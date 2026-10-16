"""Очистка и место на диске: мусор с объяснениями, анализ диска, большие файлы, дубликаты, пустые папки,
битые ярлыки, переменная PATH, старые пакеты драйверов, корзина, шредер.

Всё разовое и по кнопке. Удаление пользовательских файлов — в Корзину (можно вернуть), кроме кэшей и шредера.
"""
import ctypes
import glob
import hashlib
import heapq
import json
import os
import re
import shutil
import subprocess
import time
import winreg
import xml.etree.ElementTree as ET
from ctypes import wintypes
from datetime import datetime

import system

NO_WINDOW = 0x08000000
ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
BACKUPS = os.path.join(DATA, "backups")
WINDIR = os.environ.get("SystemRoot", r"C:\Windows")
LA, RA = os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", "")
PD = os.environ.get("ProgramData", r"C:\ProgramData")
HOME = os.path.expanduser("~")


def stamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


# ================================================================ мусор: категории с объяснениями

def _g(*pats):
    out = []
    for p in pats:
        out += [x for x in glob.glob(p) if os.path.isdir(x)]
    return out


def _steam_libs():
    libs = []
    for base in (r"C:\Program Files (x86)\Steam", r"C:\Program Files\Steam", r"D:\Steam", r"D:\SteamLibrary"):
        vdf = os.path.join(base, "steamapps", "libraryfolders.vdf")
        if os.path.exists(vdf):
            libs.append(base)
            try:
                for m in re.finditer(r'"path"\s+"([^"]+)"', open(vdf, encoding="utf-8", errors="replace").read()):
                    libs.append(m.group(1).replace("\\\\", "\\"))
            except OSError:
                pass
    return sorted({os.path.normcase(x): x for x in libs}.values())


def categories():
    """Все категории мусора. safe — можно отмечать по умолчанию; admin — нужны права администратора."""
    steam = _steam_libs()
    C = [
        # ---- Windows
        dict(id="temp", grp="Windows", label="Временные файлы программ (TEMP)", paths=[os.environ.get("TEMP", "")], safe=True,
             desc="Программы складывают сюда распакованные установщики, черновики и обрывки загрузок, а потом часто забывают удалить. "
                  "Удаляются только файлы старше суток, занятые сейчас — пропускаются."),
        dict(id="wintemp", grp="Windows", label="Временные файлы Windows", paths=[os.path.join(WINDIR, "Temp")], safe=True, admin=True,
             desc="То же самое, но для системных служб и установщиков, работающих от имени системы. Нужны права администратора."),
        dict(id="crash", grp="Windows", label="Дампы падений программ", paths=[LA + r"\CrashDumps"], safe=True,
             desc="Снимки памяти, которые Windows сохраняет, когда программа вылетает. Нужны только разработчикам для разбора ошибки."),
        dict(id="wer", grp="Windows", label="Отчёты об ошибках Windows", paths=[LA + r"\Microsoft\Windows\WER", PD + r"\Microsoft\Windows\WER\ReportArchive",
             PD + r"\Microsoft\Windows\WER\ReportQueue"], safe=True, admin=True,
             desc="Отчёты о сбоях, которые Windows готовит для отправки в Microsoft. Уже отправленные и устаревшие не нужны."),
        dict(id="inet", grp="Windows", label="Кэш интернета Windows (INetCache)", paths=[LA + r"\Microsoft\Windows\INetCache"], safe=True,
             desc="Кэш старого движка Internet Explorer, которым до сих пор пользуются некоторые программы и справка. Создастся заново при необходимости."),
        dict(id="thumbs_old", grp="Windows", label="Старые журналы установки драйверов и обновлений", paths=[os.path.join(WINDIR, "Logs", "CBS")],
             safe=False, admin=True, older_days=30,
             desc="Журналы обслуживания Windows (CBS) старше 30 дней. Нужны только для разбора неудачных обновлений."),
        dict(id="wu", grp="Windows", label="Загрузки Windows Update", paths=[os.path.join(WINDIR, r"SoftwareDistribution\Download")], safe=False, admin=True,
             # пока Windows Update не работает, его загрузки можно удалять целиком (так советует и Microsoft); если работает — только старше суток
             older_days=0 if wu_idle() else 1,
             desc="Скачанные установщики обновлений. После установки обновлений они не нужны; если обновление ещё ждёт установки, Windows скачает его заново." +
                  ("" if wu_idle() else " Сейчас Windows Update работает — удалятся только файлы старше суток.")),
        dict(id="lkr", grp="Windows", label="Диагностические снимки ядра (LiveKernelReports)", paths=[os.path.join(WINDIR, "LiveKernelReports")],
             safe=False, admin=True, always=True,
             desc="Снимки памяти, которые Windows сохраняет при сбоях драйверов (часто — видеодрайвера). Нужны только для отправки разработчикам. "
                  "Без прав администратора размер не узнать — он станет известен после очистки."),
        dict(id="do", grp="Windows", label="Кэш оптимизации доставки", paths=[os.path.join(WINDIR, r"ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache")],
             safe=False, admin=True,
             desc="Части обновлений, которые Windows раздаёт другим компьютерам в сети. Удаление безопасно, Windows просто скачает нужное снова."),
        # ---- видеокарта и игры
        dict(id="nv_shader", grp="Игры и видеокарта", label="Кэш шейдеров NVIDIA", paths=_g(LA + r"\NVIDIA\DXCache", LA + r"\NVIDIA\GLCache",
             RA + r"\NVIDIA\ComputeCache", LA + r"\NVIDIA Corporation\NV_Cache"), safe=False,
             desc="Шейдеры — маленькие программы для видеокарты, которые драйвер заранее компилирует для игр. Чистить стоит после обновления драйвера или если "
                  "в игре графические артефакты. Минус: первые запуски игр после очистки могут подтормаживать, пока кэш собирается заново."),
        dict(id="dx_shader", grp="Игры и видеокарта", label="Кэш шейдеров DirectX", paths=_g(LA + r"\D3DSCache"), safe=False,
             desc="То же, но кэш самого DirectX. Пересоздаётся автоматически; первые запуски игр могут быть медленнее."),
        dict(id="amd_intel", grp="Игры и видеокарта", label="Кэш шейдеров AMD и Intel", paths=_g(LA + r"\AMD\DxCache", LA + r"\AMD\DxcCache", LA + r"\AMD\VkCache",
             LA + r"\AMD\GLCache", LA + r"\Intel\ShaderCache"), safe=False,
             desc="Кэш шейдеров встроенной видеокарты. Пересоздаётся автоматически."),
        dict(id="steam_shader", grp="Игры и видеокарта", label="Steam: кэш шейдеров игр", paths=_g(*[os.path.join(s, "steamapps", "shadercache") for s in steam]),
             safe=False, desc="Steam заранее скачивает скомпилированные шейдеры для игр. Удаление безопасно, Steam загрузит их снова при запуске игры."),
        dict(id="steam_web", grp="Игры и видеокарта", label="Steam: кэш встроенного браузера и дампы", paths=_g(LA + r"\Steam\htmlcache",
             *[os.path.join(s, "dumps") for s in steam], *[os.path.join(s, "logs") for s in steam]), safe=True,
             desc="Кэш магазина и сообщества внутри Steam, дампы падений и журналы. Закрой Steam перед очисткой."),
        dict(id="epic", grp="Игры и видеокарта", label="Epic Games Launcher: веб-кэш", paths=_g(LA + r"\EpicGamesLauncher\Saved\webcache*"), safe=True,
             desc="Кэш страниц магазина Epic. Закрой лаунчер перед очисткой."),
        dict(id="gamecache", grp="Игры и видеокарта", label="Кэш лаунчеров Battle.net, EA, Ubisoft", paths=_g(PD + r"\Battle.net\Agent\data\cache",
             LA + r"\Battle.net\Cache", LA + r"\Electronic Arts\EA Desktop\cache", LA + r"\Ubisoft Game Launcher\cache"), safe=True,
             desc="Кэш интерфейса игровых лаунчеров. Закрой их перед очисткой."),
        # ---- программы
        dict(id="vscode", grp="Программы", label="VS Code: кэш и журналы", paths=_g(RA + r"\Code\Cache", RA + r"\Code\CachedData", RA + r"\Code\CachedExtensionVSIXs",
             RA + r"\Code\Code Cache", RA + r"\Code\logs", RA + r"\Code\GPUCache"), safe=True,
             desc="Кэш редактора и скачанные установщики расширений. Настройки и расширения не трогаются. Закрой VS Code перед очисткой."),
        dict(id="teams", grp="Программы", label="Microsoft Teams: кэш", paths=_g(LA + r"\Packages\MSTeams_*\LocalCache\Microsoft\MSTeams\EBWebView\Default\Cache",
             RA + r"\Microsoft\Teams\Cache", RA + r"\Microsoft\Teams\Service Worker\CacheStorage"), safe=True,
             desc="Кэш картинок и страниц Teams. Переписка хранится в облаке. Закрой Teams перед очисткой."),
        dict(id="spotify", grp="Программы", label="Spotify: кэш музыки", paths=_g(LA + r"\Spotify\Storage", LA + r"\Spotify\Data",
             LA + r"\Packages\SpotifyAB.SpotifyMusic_*\LocalCache\Spotify\Data"), safe=True,
             desc="Временно сохранённые треки для быстрого повтора. Скачанные для офлайна плейлисты — отдельно и не трогаются."),
        dict(id="telegram", grp="Программы", label="Telegram: кэш медиа", paths=_g(RA + r"\Telegram Desktop\tdata\user_data\cache",
             RA + r"\Telegram Desktop\tdata\user_data\media_cache",
             LA + r"\Packages\TelegramMessengerLLP.TelegramDesktop_*\LocalCache\Roaming\Telegram Desktop UWP\tdata\user_data\cache",
             LA + r"\Packages\TelegramMessengerLLP.TelegramDesktop_*\LocalCache\Roaming\Telegram Desktop UWP\tdata\user_data\media_cache"), safe=False,
             desc="Просмотренные фото, видео и стикеры. Сами сообщения хранятся в облаке Telegram, медиа подгрузятся снова при просмотре. Закрой Telegram перед очисткой."),
        dict(id="chrome_ai", grp="Программы", label="Chrome: локальная ИИ-модель Gemini Nano", older_days=0,
             paths=_g(LA + r"\Google\Chrome\User Data\OptGuideOnDeviceModel", LA + r"\Google\Chrome Beta\User Data\OptGuideOnDeviceModel",
                      LA + r"\Google\Chrome SxS\User Data\OptGuideOnDeviceModel"), safe=False,
             desc="Chrome сам скачивает ИИ-модель (файл weights.bin, до 4 ГБ) для подсказок «Помоги написать» и встроенного ИИ сайтов. Если этим "
                  "не пользуешься — удаляй. Чтобы Chrome не скачал её снова, включи «Chrome: не скачивать ИИ-модель» в «Приватность и защита → "
                  "Приватность». Закрой Chrome перед очисткой."),
        # ---- разработка
        dict(id="devcache", grp="Разработка", label="Кэш пакетов: pip, npm, NuGet, Yarn", paths=_g(LA + r"\pip\cache", LA + r"\npm-cache", RA + r"\npm-cache",
             LA + r"\NuGet\v3-cache", LA + r"\Yarn\Cache", LA + r"\pnpm-cache"), safe=False,
             desc="Скачанные когда-то пакеты библиотек. Нужны только для ускорения повторной установки; при необходимости скачаются снова."),
    ]
    for name, paths in system._browser_caches().items():
        if paths:
            C.append(dict(id="browser:" + name, grp="Браузеры", label=f"{name}: кэш", paths=paths, safe=True,
                          desc=("Временно сохранённые картинки и скрипты сайтов. Пароли, история, вкладки и вход на сайты не затрагиваются. "
                                f"Сайты первый раз откроются чуть медленнее. Закрой {'Discord' if name == 'Discord' else 'браузер'} перед очисткой.")))
    C = [c for c in C if c.get("always") or any(p and os.path.isdir(p) for p in c["paths"])]
    return C


def wu_idle():
    """Windows Update сейчас ничего не скачивает и не ставит — его загрузки можно удалять сразу, без суточной паузы."""
    try:
        import psutil
        return all(psutil.win_service_get(s).status() != "running" for s in ("wuauserv", "TrustedInstaller"))
    except Exception:
        return False


def _sizes(path, older_hours, limit_s=12):
    """Весь размер папки и та часть, которую можно удалить сейчас (файлы старше older_hours)."""
    total = ready = 0
    cutoff, t0 = time.time() - older_hours * 3600, time.time()
    for root, dirs, files in os.walk(path, onerror=lambda e: None):
        for f in files:
            try:
                st = os.lstat(os.path.join(root, f))
            except OSError:
                continue
            total += st.st_size
            if st.st_mtime < cutoff:
                ready += st.st_size
        if time.time() - t0 > limit_s:
            break
    return total, ready


def junk_scan():
    cats = categories()
    for c in cats:
        hours = c.get("older_days", 1) * 24
        sz = [_sizes(p, hours) for p in c["paths"] if p and os.path.isdir(p)]
        c["size_all"] = sum(s[0] for s in sz)
        c["size"] = sum(s[1] for s in sz)          # главное число — то, что удалится прямо сейчас
        c["fresh"] = c["size_all"] - c["size"]      # свежие файлы (моложе порога) — удалятся при следующей очистке
    cats = [c for c in cats if c["size_all"] > 0 or c["id"] in ("temp", "wu") or c.get("always")]
    rb = recycle_info()
    vol = shutil.disk_usage("C:\\")
    return {"categories": cats, "recycle": rb, "c_free": vol.free, "c_total": vol.total}


def clean_paths(paths, older_hours=24, progress=None):
    """Удалить содержимое папок (файлы старше older_hours), пустые подпапки — тоже. Занятые пропускаются.
    progress(n, freed) — раз в ~2000 файлов, чтобы окно показывало, что работа идёт (в «Загрузках Windows Update» их сотни тысяч)."""
    freed, skipped, cutoff, n = 0, 0, time.time() - older_hours * 3600, 0
    for base in paths:
        if not base or not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base, topdown=False, onerror=lambda e: None):
            for f in files:
                p = os.path.join(root, f)
                try:
                    st = os.lstat(p)
                    if st.st_mtime < cutoff:
                        os.remove(p)
                        freed += st.st_size
                        n += 1
                        if progress and n % 2000 == 0:
                            progress(n, freed)
                except OSError:
                    skipped += 1
            if root != base:
                try:
                    os.rmdir(root)
                except OSError:
                    pass
    return freed, skipped


def junk_clean(ids, run_elevated, prog=None, expect=None):
    """expect — {id: байт} из последнего junk_scan: по нему окно показывает проценты («37% · …»)."""
    prog = prog or (lambda s: None)
    cats = {c["id"]: c for c in categories()}
    freed, skipped, admin_paths, done = 0, 0, [], []
    expect = {k: v for k, v in (expect or {}).items() if k in ids and v}
    total = sum(expect.values()) or 0
    base = [0]                                          # сколько ожидаемых байт уже «закрыто» прошлыми категориями

    def pct(cid, fr):
        if not total:
            return ""
        return f"{min(99, int((base[0] + min(fr, expect.get(cid, 0))) * 100 / total))}% · "
    for cid in ids:
        c = cats.get(cid)
        if not c:
            continue
        hours = c.get("older_days", 1) * 24
        if c.get("admin"):
            admin_paths.append({"paths": c["paths"], "hours": hours, "id": cid})
            continue
        prog(f"{pct(cid, 0)}очищаю: {c['label']}")
        f, s = clean_paths(c["paths"], hours, lambda n, fr: prog(f"{pct(cid, fr)}{c['label']}: удалено файлов {n:,} · {fr / 2 ** 20:,.0f} МБ".replace(",", " ")))
        base[0] += expect.get(cid, 0)
        freed += f
        skipped += s
        done.append(cid)
    errors = []
    if admin_paths:
        ops = [{"type": "clean", "paths": a["paths"], "older_hours": a["hours"], "label": cats[a["id"]]["label"]} for a in admin_paths]
        prog("жду подтверждения администратора (окно UAC; в нём «Python» — это ScanHub) для системных папок")
        try:
            res = run_elevated(ops, timeout=1800, on_started=lambda: prog("права выданы ✓ — очищаю системные папки"), on_progress=prog)
            for a, r in zip(admin_paths, res):
                if r.get("ok"):
                    freed += r.get("freed", 0)
                    skipped += r.get("skipped", 0)
                    done.append(a["id"])
                else:
                    errors.append(f"{a['id']}: {r.get('error')}")
        except PermissionError as e:
            errors.append(f"категории с правами администратора пропущены: {e}")
    if "recycle" in ids:
        rb = recycle_info()
        if empty_recycle():
            freed += rb["size"]
            done.append("recycle")
        else:
            errors.append("Корзину очистить не удалось")
    return {"freed": freed, "skipped": skipped, "done": done, "errors": errors}


# ================================================================ корзина

class SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("i64Size", ctypes.c_longlong), ("i64NumItems", ctypes.c_longlong)]


def recycle_info():
    q = SHQUERYRBINFO()
    q.cbSize = ctypes.sizeof(q)
    if ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(q)) == 0:
        return {"size": q.i64Size, "count": q.i64NumItems}
    return {"size": 0, "count": 0}


def empty_recycle():
    # SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
    return ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x7) in (0, -2147418113)   # S_OK / E_UNEXPECTED (уже пуста)


class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [("hwnd", wintypes.HWND), ("wFunc", wintypes.UINT), ("pFrom", wintypes.LPCWSTR), ("pTo", wintypes.LPCWSTR),
                ("fFlags", ctypes.c_ushort), ("fAnyOperationsAborted", wintypes.BOOL), ("hNameMappings", ctypes.c_void_p),
                ("lpszProgressTitle", wintypes.LPCWSTR)]


def to_recycle(paths):
    """Отправить файлы/папки в Корзину. Возвращает (удалено, ошибки)."""
    ok, errors = 0, []
    for p in paths:
        if not os.path.exists(p):
            continue
        op = SHFILEOPSTRUCTW()
        op.wFunc = 3                                     # FO_DELETE
        op.pFrom = os.path.abspath(p) + "\0"
        op.fFlags = 0x40 | 0x10 | 0x4 | 0x400            # ALLOWUNDO | NOCONFIRMATION | SILENT | NOERRORUI
        r = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
        if r == 0 and not op.fAnyOperationsAborted and not os.path.exists(p):
            ok += 1
        else:
            errors.append(f"{p}: не удалось (код {r})")
    return ok, errors


# ================================================================ анализ диска

TYPES = [
    ("Видео", "🎬", {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".m4v", ".ts", ".flv", ".mpg", ".mpeg", ".3gp", ".vob", ".m2ts"}),
    ("Фото и картинки", "🖼", {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".heif", ".tif", ".tiff", ".raw", ".cr2", ".nef", ".arw",
                               ".dng", ".psd", ".svg", ".ico", ".avif", ".fig"}),
    ("Музыка и звук", "🎵", {".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a", ".wma", ".opus", ".aiff"}),
    ("Документы", "📄", {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".odt", ".ods", ".rtf", ".csv", ".md", ".epub", ".djvu", ".xps"}),
    ("Архивы и образы", "🗜", {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".zst", ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".wim", ".esd", ".cab", ".dmg"}),
    ("Программы и установщики", "⚙️", {".exe", ".msi", ".dll", ".sys", ".appx", ".msix", ".msixbundle", ".appxbundle", ".apk", ".jar", ".node"}),
    ("Игровые данные", "🎮", {".pak", ".vpk", ".bsa", ".ba2", ".forge", ".utoc", ".ucas", ".bundle", ".assets", ".big", ".rpf", ".arc", ".wad"}),
    ("Код и разработка", "💻", {".py", ".pyc", ".js", ".ts", ".tsx", ".java", ".class", ".c", ".cpp", ".h", ".cs", ".go", ".rs", ".json", ".xml", ".yml",
                                ".yaml", ".whl", ".o", ".obj", ".pdb", ".lib", ".a", ".so", ".map", ".lock", ".ipynb", ".gguf", ".safetensors",
                                ".ckpt", ".pt", ".pth", ".onnx", ".bin"}),
    ("Временное и служебное", "🧾", {".tmp", ".log", ".dmp", ".etl", ".db", ".dat", ".cache", ".bak", ".old", ".evtx", ".blf", ".regtrans-ms", ".edb", ".sqlite",
                                     ".ldb", ".mdmp", ".chk", ".ost", ".pst"}),
]
EXT_CAT = {e: i for i, (_, _, exts) in enumerate(TYPES) for e in exts}
_DA = {}          # последний анализ: дерево размеров для «провалиться в папку»


def analyze(root, progress=lambda s: None):
    """Обход диска/папки: размеры всех папок, типы файлов, самые большие файлы."""
    root = os.path.abspath(root)
    sizes, counts, children = {}, {}, {}
    types = [[0, 0] for _ in range(len(TYPES) + 1)]
    top = []                                            # куча (size, path) — 300 самых больших файлов
    nfiles, ndirs, denied, t0 = 0, 0, 0, time.time()
    seen, used = 0, 0
    if os.path.splitdrive(root)[1] in ("\\", ""):     # весь диск: проценты считаем от занятого места
        try:
            used = shutil.disk_usage(root).used
        except OSError:
            pass
    order = []                                          # папки в порядке обхода (для подсчёта снизу вверх)
    stack = [root]
    while stack:
        d = stack.pop()
        order.append(d)
        own, cnt, kids = 0, 0, []
        try:
            it = os.scandir(d)
        except OSError:
            denied += 1
            sizes[d], counts[d], children[d] = 0, 0, []
            continue
        with it:
            for e in it:
                try:
                    if e.is_symlink() or (hasattr(e, "is_junction") and e.is_junction()):
                        continue
                    if e.is_dir(follow_symlinks=False):
                        kids.append(e.path)
                        continue
                    sz = e.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
                own += sz
                cnt += 1
                ext = os.path.splitext(e.name)[1].lower()
                c = EXT_CAT.get(ext, len(TYPES))
                types[c][0] += sz
                types[c][1] += 1
                if sz >= 20 * 2 ** 20:
                    if len(top) < 300:
                        heapq.heappush(top, (sz, e.path))
                    elif sz > top[0][0]:
                        heapq.heapreplace(top, (sz, e.path))
        sizes[d], counts[d], children[d] = own, cnt, kids
        nfiles += cnt
        ndirs += 1
        seen += own
        stack.extend(kids)
        if ndirs % 2000 == 0:
            progress((f"{min(99, seen * 100 // used)}% · " if used else "") + f"просмотрено {nfiles:,} файлов в {ndirs:,} папках… сейчас: {d[:90]}".replace(",", " "))
    for d in reversed(order):                           # сложить размеры снизу вверх
        for k in children[d]:
            sizes[d] += sizes.get(k, 0)
            counts[d] += counts.get(k, 0)
    _DA.clear()
    _DA.update(root=root, sizes=sizes, counts=counts, children=children, when=time.time())
    usage = None
    try:
        u = shutil.disk_usage(root)
        usage = {"total": u.total, "used": u.used, "free": u.free}
    except OSError:
        pass
    big = sorted(top, reverse=True)
    return {"root": root, "size": sizes.get(root, 0), "files": nfiles, "dirs": ndirs, "denied": denied,
            "seconds": round(time.time() - t0), "usage": usage, "tree": children_of(root),
            "types": [{"name": TYPES[i][0] if i < len(TYPES) else "Прочее", "icon": TYPES[i][1] if i < len(TYPES) else "📦",
                       "size": s, "count": n} for i, (s, n) in enumerate(types) if s],
            "big": [{"path": p, "size": s, "kind": _kind(p)} for s, p in big]}


def _kind(p):
    ext = os.path.splitext(p)[1].lower()
    i = EXT_CAT.get(ext)
    return TYPES[i][0] if i is not None else ""


def children_of(path, limit=60):
    """Подпапки из последнего анализа (без нового обхода диска)."""
    if not _DA or path not in _DA["sizes"]:
        raise RuntimeError("нет данных — запусти анализ заново")
    S, N, K = _DA["sizes"], _DA["counts"], _DA["children"]
    kids = sorted(K.get(path, []), key=lambda k: -S.get(k, 0))
    own = S[path] - sum(S.get(k, 0) for k in K.get(path, []))
    return {"path": path, "size": S[path], "files": N[path], "own_files_size": own,
            "parent": os.path.dirname(path) if path != _DA["root"] and os.path.dirname(path) in S else None,
            "items": [{"path": k, "name": os.path.basename(k), "size": S.get(k, 0), "files": N.get(k, 0),
                       "has_kids": bool(K.get(k))} for k in kids[:limit]],
            "more": max(0, len(kids) - limit), "hint": folder_hint(path)}


HINTS = [
    (r"\\windows\\winsxs$", "Хранилище компонентов Windows. Вручную не удалять! Уменьшить можно через «Очистку диска Windows» → «Очистка обновлений Windows»."),
    (r"\\windows\\installer$", "Копии установщиков программ, нужны для их удаления и восстановления. Вручную не удалять."),
    (r"\\windows\\softwaredistribution", "Загрузки Windows Update — очищаются в «Очистка → Мусор»."),
    (r"\\appdata\\local\\temp$", "Временные файлы — очищаются в «Очистка → Мусор»."),
    (r"\\appdata\\local\\packages$", "Данные приложений из Microsoft Store. Чистить вручную не стоит — удаляй само приложение."),
    (r"\\\$recycle\.bin$", "Корзина — очищается в «Очистка → Мусор»."),
    (r"\\steamapps\\common$", "Установленные игры Steam. Ненужную игру удаляй через Steam."),
    (r"\\system volume information$", "Точки восстановления и служебные данные Windows. Управляются через «Защиту системы»."),
    (r"\\hiberfil\.sys$|^[a-z]:\\$", ""),
    (r"\\docker", "Образы и контейнеры Docker. Освободить место: docker system prune в терминале."),
    (r"\\\.ollama|ollama-models", "Модели Ollama. Ненужную модель удаляй командой ollama rm <имя>."),
    (r"\\node_modules$", "Библиотеки проекта JavaScript. Можно удалить, если проект не нужен: npm install восстановит."),
]


def folder_hint(path):
    p = path.lower()
    for rx, h in HINTS:
        if re.search(rx, p):
            return h
    return ""


# ================================================================ дубликаты и пустые папки

SYSTEM_DIRS = ("\\windows", "\\program files", "\\program files (x86)", "\\programdata", "\\$recycle.bin",
               "\\system volume information", "\\appdata", "\\recovery", "\\windowsapps", "\\node_modules", "\\.git")


def _skip_dir(path):
    p = path.lower()
    return any(s + "\\" in p + "\\" for s in SYSTEM_DIRS)


def duplicates(root, min_size=1024 * 1024, progress=lambda s: None, stopped=lambda: False):
    """Одинаковые файлы: сначала по размеру, потом по хэшу первых 64 КБ, потом по полному хэшу."""
    by_size, n = {}, 0
    for r, dirs, files in os.walk(root, onerror=lambda e: None):
        dirs[:] = [d for d in dirs if not _skip_dir(os.path.join(r, d))]
        for f in files:
            p = os.path.join(r, f)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_size >= min_size:
                by_size.setdefault(st.st_size, []).append(p)
            n += 1
        if n % 5000 < len(files):
            progress(f"просмотрено файлов: {n}")
        if stopped():
            break

    def h(p, limit=None):
        x = hashlib.blake2b(digest_size=20)
        with open(p, "rb") as fh:
            if limit:
                x.update(fh.read(limit))
            else:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    x.update(chunk)
        return x.hexdigest()

    groups, checked = [], 0
    cands = [(s, ps) for s, ps in by_size.items() if len(ps) > 1]
    for i, (size, paths) in enumerate(sorted(cands, key=lambda x: -x[0])):
        if stopped():
            break
        progress(f"{i * 100 // max(1, len(cands))}% · сравниваю содержимое: группа {i + 1} из {len(cands)}")
        head = {}
        for p in paths:
            try:
                head.setdefault(h(p, 65536), []).append(p)
            except OSError:
                pass
        for same in head.values():
            if len(same) < 2:
                continue
            full = {}
            for p in same:
                try:
                    full.setdefault(h(p) if size > 65536 else "x", []).append(p)
                except OSError:
                    pass
                checked += 1
            for ps in full.values():
                if len(ps) > 1:
                    ps.sort(key=lambda p: os.path.getmtime(p))
                    groups.append({"size": size, "paths": ps, "waste": size * (len(ps) - 1)})
        if len(groups) >= 400:
            break
    groups.sort(key=lambda g: -g["waste"])
    return {"root": root, "files": n, "groups": groups, "waste": sum(g["waste"] for g in groups), "min_size": min_size}


def empty_folders(root, progress=lambda s: None):
    """Пустые папки (в том числе содержащие только пустые папки). Системные места пропускаются."""
    empty, n = set(), 0
    for r, dirs, files in os.walk(root, topdown=False, onerror=lambda e: None):
        n += 1
        if _skip_dir(r) or r.rstrip("\\") == root.rstrip("\\"):
            continue
        if not files and all(os.path.join(r, d) in empty for d in dirs):
            try:
                attrs = os.stat(r).st_file_attributes
                if attrs & 0x4 or attrs & 0x400:            # системная или точка повторной обработки
                    continue
            except (OSError, AttributeError):
                continue
            empty.add(r)
        if n % 3000 == 0:
            progress(f"просмотрено папок: {n}")
    top = sorted(p for p in empty if os.path.dirname(p) not in empty)
    return {"root": root, "folders": [{"path": p, "nested": sum(1 for q in empty if q.startswith(p + "\\"))} for p in top][:2000],
            "total": len(empty)}


def remove_empty(paths):
    removed = 0
    for p in paths:
        for r, dirs, files in os.walk(p, topdown=False):
            if files:
                break
            try:
                os.rmdir(r)
                removed += 1
            except OSError:
                pass
    return {"removed": removed}


# ================================================================ битые ярлыки

def shortcuts_scan():
    dirs = [os.path.join(RA, r"Microsoft\Windows\Start Menu"), os.path.join(PD, r"Microsoft\Windows\Start Menu"),
            os.path.join(HOME, "Desktop"), r"C:\Users\Public\Desktop",
            os.path.join(RA, r"Microsoft\Internet Explorer\Quick Launch")]
    try:
        import winreg as wr
        k = wr.OpenKey(wr.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
        dirs.append(wr.QueryValueEx(k, "Desktop")[0])
    except OSError:
        pass
    lnks = []
    for d in dict.fromkeys(dirs):
        if os.path.isdir(d):
            lnks += glob.glob(os.path.join(d, "**", "*.lnk"), recursive=True)
    lnks = sorted(set(lnks))
    if not lnks:
        return {"broken": [], "total": 0}
    tmp = os.path.join(DATA, f"lnk_{stamp()}.json")
    json.dump(lnks, open(tmp, "w", encoding="utf-8"))
    res = system.ps("$sh = New-Object -ComObject WScript.Shell; (Get-Content -Raw -Encoding UTF8 $env:SH_LIST | ConvertFrom-Json) | "
                    "ForEach-Object { $l = $sh.CreateShortcut($_); [pscustomobject]@{p=$_; t=$l.TargetPath; a=$l.Arguments} } | ConvertTo-Json -Compress",
                    timeout=300, env={"SH_LIST": tmp})
    os.remove(tmp)
    broken = []
    for r in system.as_list(res):
        t = (r.get("t") or "").strip()
        if not t or not re.match(r"^[a-zA-Z]:\\", t):
            continue                                    # ярлыки на элементы оболочки, URL и т.п. не проверяем
        drive = t[:3]
        if not os.path.exists(drive):
            continue                                    # флешка/диск не подключён — это не «битый» ярлык
        if not os.path.exists(t):
            p = r["p"]
            broken.append({"path": p, "name": os.path.splitext(os.path.basename(p))[0], "target": t,
                           "admin": not p.lower().startswith(HOME.lower()), "where": _where(p)})
    return {"broken": broken, "total": len(lnks)}


def _where(p):
    pl = p.lower()
    if "start menu" in pl:
        return "меню «Пуск»"
    if "desktop" in pl:
        return "рабочий стол"
    if "quick launch" in pl:
        return "панель задач"
    return os.path.dirname(p)


def shortcuts_remove(paths, run_elevated):
    """Ярлыки сначала копируются в data\\backups\\shortcuts (можно вернуть), потом удаляются."""
    dst = os.path.join(BACKUPS, "shortcuts", stamp())
    os.makedirs(dst, exist_ok=True)
    mine, admin, removed, errors = [], [], 0, []
    for p in paths:
        if not p.lower().endswith(".lnk") or not os.path.exists(p):
            continue
        shutil.copy2(p, os.path.join(dst, os.path.basename(p)))
        (mine if p.lower().startswith(HOME.lower()) else admin).append(p)
    for p in mine:
        try:
            os.remove(p)
            removed += 1
        except OSError as e:
            admin.append(p)
    if admin:
        try:
            res = run_elevated([{"type": "remove", "path": p} for p in admin])
            removed += sum(1 for r in res if r.get("ok"))
        except PermissionError as e:
            errors.append(str(e))
    return {"removed": removed, "backup": dst, "errors": errors}


# ================================================================ переменная PATH

ENV_USER = r"Environment"
ENV_SYS = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"


def _read_path(hive, key):
    try:
        k = winreg.OpenKey(hive, key)
        v, t = winreg.QueryValueEx(k, "Path")
        return v, t
    except OSError:
        return "", winreg.REG_EXPAND_SZ


def path_scan():
    out = []
    for scope, hive, key in (("user", winreg.HKEY_CURRENT_USER, ENV_USER), ("system", winreg.HKEY_LOCAL_MACHINE, ENV_SYS)):
        raw, _ = _read_path(hive, key)
        seen = set()
        for i, e in enumerate([x for x in raw.split(";")]):
            if not e.strip():
                continue
            exp = os.path.expandvars(e.strip().strip('"'))
            norm = os.path.normcase(exp.rstrip("\\"))
            problem = None
            if not os.path.isdir(exp):
                problem = "папки нет" if os.path.exists(exp[:3]) else "диск не подключён"
            elif norm in seen:
                problem = "повтор"
            seen.add(norm)
            out.append({"scope": scope, "entry": e, "expanded": exp, "problem": problem, "index": i})
    return {"entries": out, "length_user": len(_read_path(winreg.HKEY_CURRENT_USER, ENV_USER)[0]),
            "length_system": len(_read_path(winreg.HKEY_LOCAL_MACHINE, ENV_SYS)[0])}


def _broadcast_env():
    HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG = 0xFFFF, 0x1A, 0x2
    res = ctypes.c_ulong()
    ctypes.windll.user32.SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment", SMTO_ABORTIFHUNG, 5000, ctypes.byref(res))


def path_fix(remove, run_elevated):
    """remove: [{"scope": "user"|"system", "entry": "..."}]. Старое значение сохраняется в data\\backups."""
    os.makedirs(BACKUPS, exist_ok=True)
    result = {}
    for scope, hive, key in (("user", winreg.HKEY_CURRENT_USER, ENV_USER), ("system", winreg.HKEY_LOCAL_MACHINE, ENV_SYS)):
        drop = {r["entry"] for r in remove if r["scope"] == scope}
        if not drop:
            continue
        raw, typ = _read_path(hive, key)
        json.dump({"scope": scope, "value": raw}, open(os.path.join(BACKUPS, f"path-{scope}-{stamp()}.json"), "w", encoding="utf-8"),
                  ensure_ascii=False)
        kept, seen = [], set()
        for e in raw.split(";"):
            if not e.strip():
                continue
            norm = os.path.normcase(os.path.expandvars(e.strip()).rstrip("\\"))
            if e in drop or (norm in seen and any(d == e for d in drop)):
                continue
            seen.add(norm)
            kept.append(e)
        new = ";".join(kept)
        if scope == "user":
            k = winreg.OpenKey(hive, key, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, "Path", 0, typ, new)
        else:
            r = run_elevated([{"type": "reg_set", "root": "HKLM", "key": key, "name": "Path",
                               "kind": "expand_sz" if typ == winreg.REG_EXPAND_SZ else "sz", "value": new}])[0]
            if not r.get("ok"):
                raise RuntimeError(r.get("error"))
        result[scope] = len(drop)
    _broadcast_env()
    return {"removed": result}


# ================================================================ старые пакеты драйверов

def _ver_key(v):
    # "05/19/2026 15.11.30.14" -> (2026, 5, 19, (15, 11, 30, 14))
    try:
        d, ver = v.split(" ", 1)
        mm, dd, yy = d.split("/")
        return (int(yy), int(mm), int(dd), tuple(int(x) for x in re.findall(r"\d+", ver)))
    except ValueError:
        return (0, 0, 0, ())


def drivers_scan():
    xml = subprocess.run(["pnputil", "/enum-drivers", "/format", "xml"], capture_output=True, timeout=120,
                         creationflags=NO_WINDOW).stdout
    root = ET.fromstring(xml.decode("utf-8", "replace").lstrip("\ufeff"))
    pkgs = []
    for d in root.iter("Driver"):
        g = lambda t: (d.findtext(t) or "").strip()
        pkgs.append({"oem": d.get("DriverName"), "orig": g("OriginalName"), "provider": g("ProviderName"), "cls": g("ClassName"),
                     "version": g("DriverVersion"), "signer": g("SignerName")})
    used = set(x.lower() for x in system.as_list(system.ps(
        "Get-CimInstance Win32_PnPSignedDriver | Where-Object InfName | Select-Object -ExpandProperty InfName -Unique | ConvertTo-Json -Compress",
        timeout=120)) if isinstance(x, str))
    groups = {}
    for p in pkgs:
        groups.setdefault((p["orig"].lower(), p["provider"].lower(), p["cls"].lower()), []).append(p)
    repo = os.path.join(WINDIR, r"System32\DriverStore\FileRepository")
    old = []
    for key, ps in groups.items():
        if len(ps) < 2:
            continue
        ps.sort(key=lambda p: _ver_key(p["version"]), reverse=True)
        for p in ps[1:]:
            if p["oem"].lower() in used:
                continue
            p["size"], p["folder"] = _pkg_size(repo, p)
            p["newest"] = ps[0]["version"]
            old.append(p)
    old.sort(key=lambda p: -(p["size"] or 0))
    return {"packages": len(pkgs), "old": old, "size": sum(p["size"] or 0 for p in old)}


def _pkg_size(repo, p):
    """Найти папку пакета в FileRepository по версии в его .inf и посчитать размер."""
    want = p["version"].replace(" ", ",")
    for d in glob.glob(os.path.join(repo, p["orig"] + "_*")):
        inf = os.path.join(d, p["orig"])
        try:
            head = open(inf, encoding="utf-16" if open(inf, "rb").read(2) in (b"\xff\xfe", b"\xfe\xff") else "latin-1",
                        errors="replace").read(20000)
        except OSError:
            continue
        m = re.search(r"^\s*DriverVer\s*=\s*([^\r\n;]+)", head, re.M | re.I)
        if m and re.sub(r"\s", "", m.group(1)).lower() == want.lower().replace(" ", ""):
            return system.dir_size(d, 5), d
    return None, None


def drivers_remove(oems, run_elevated):
    """pnputil /delete-driver без /force: пакет, который используется устройством, Windows удалить не даст."""
    oems = [o for o in oems if re.fullmatch(r"oem\d+\.inf", o, re.I)]
    if not oems:
        return {"removed": 0}
    res = run_elevated([{"type": "run", "cmd": ["pnputil", "/delete-driver", o], "timeout": 120} for o in oems], timeout=1200)
    ok = [o for o, r in zip(oems, res) if r.get("ok") and r.get("code") == 0]
    fail = [f"{o}: {(r.get('out') or r.get('error') or '').strip()[-160:]}" for o, r in zip(oems, res) if o not in ok]
    return {"removed": len(ok), "failed": fail}


# ================================================================ шредер

def media_type(path):
    """SSD или HDD для диска, на котором лежит путь."""
    letter = os.path.splitdrive(os.path.abspath(path))[0].rstrip(":")
    if not letter:
        return None
    r = system.ps(f"$d = Get-Partition -DriveLetter {letter} | Get-Disk; Get-PhysicalDisk | Where-Object DeviceId -eq \"$($d.Number)\" | "
                  "Select-Object -First 1 @{n='m';e={[string]$_.MediaType}}, @{n='b';e={[string]$_.BusType}} | ConvertTo-Json -Compress", timeout=60)
    return r


def _shred_guard(path):
    """Шредер стирает безвозвратно — не даём уничтожить диск целиком, систему или профиль пользователя по ошибке."""
    n = os.path.normcase(os.path.abspath(path)).rstrip("\\")
    if len(n) <= 3 or os.path.isjunction(path):
        raise RuntimeError(f"{path}: так нельзя — это целый диск или ссылка на другую папку")
    broad = {os.path.normcase(os.environ.get(v, "")).rstrip("\\") for v in
             ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
              "PUBLIC", "OneDrive")} - {""}
    home = os.path.normcase(os.path.expanduser("~"))
    broad |= {os.path.join(home, x) for x in ("desktop", "documents", "downloads", "pictures", "videos", "music", "appdata")}
    sysroot = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    if n in broad or n == os.path.dirname(home) or n.startswith(sysroot + "\\") or "\\program files" in n[2:16]:
        raise RuntimeError(f"{path}: системную или общую папку шредером уничтожать нельзя — выбери конкретные файлы или подпапку")


def shred(paths, progress=lambda s: None):
    """Перезаписать содержимое случайными данными, переименовать, обрезать и удалить."""
    files = []
    for p in paths:
        _shred_guard(p)
    for p in paths:
        if os.path.isfile(p) and not os.path.islink(p):
            files.append(p)
        elif os.path.isdir(p):
            for r, d, fs in os.walk(p):
                # ссылки и «переходы» (junction) ведут в другие папки — их содержимое не трогаем
                d[:] = [x for x in d if not (os.path.islink(os.path.join(r, x)) or os.path.isjunction(os.path.join(r, x)))]
                files += [os.path.join(r, f) for f in fs if not os.path.islink(os.path.join(r, f))]
    done, errors, total = 0, [], 0
    for i, f in enumerate(files):
        try:
            os.chmod(f, 0o666)
            size = os.path.getsize(f)
            with open(f, "r+b", buffering=0) as fh:
                left = size
                while left > 0:
                    n = min(left, 1 << 20)
                    fh.write(os.urandom(n))
                    left -= n
                fh.flush()
                os.fsync(fh.fileno())
                fh.truncate(0)
            tmp = os.path.join(os.path.dirname(f), os.urandom(8).hex())
            os.replace(f, tmp)
            os.remove(tmp)
            done += 1
            total += size
        except OSError as e:
            errors.append(f"{f}: {e.strerror or e}")
        if i % 20 == 0:
            progress(f"{done * 100 // max(1, len(files))}% · уничтожено {done} из {len(files)}")
    for p in paths:
        if os.path.isdir(p):
            for r, d, fs in os.walk(p, topdown=False):
                try:
                    os.rmdir(r)
                except OSError:
                    pass
    return {"shredded": done, "bytes": total, "errors": errors[:30]}
