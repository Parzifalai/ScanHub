"""Удаление программ: список из реестра, запуск штатного деинсталлятора, поиск остатков, принудительное удаление записи.

Остатки (папки, ярлыки, ключи реестра) никогда не удаляются сами: только показываются, удаление — по галочкам.
Папки уходят в Корзину, ключи реестра перед удалением сохраняются в .reg в data\\backups.
"""
import ctypes
import os
import re
import subprocess
import time
import winreg
from ctypes import wintypes

import pcclean
import system

NO_WINDOW = 0x08000000
HKLM, HKCU = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER
UNINST = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
ROOTS = [(HKLM, UNINST, winreg.KEY_WOW64_64KEY, "HKLM"), (HKLM, UNINST, winreg.KEY_WOW64_32KEY, "HKLM32"),
         (HKCU, UNINST, 0, "HKCU")]
SCOPE = {"HKLM": "для всех", "HKLM32": "для всех, 32-бит", "HKCU": "для тебя"}
# части Windows, которые Microsoft не даёт удалить (или без которых сломаются другие программы)
PROTECTED = [
    (r"^Microsoft Edge$", "Microsoft Edge встроен в Windows 11: Microsoft не даёт его удалить (это разрешено только в странах ЕС). На нём работают "
                          "виджеты, справка, поиск и многие программы — в том числе окно ScanHub. Если он не нравится, просто выбери другой "
                          "браузер по умолчанию: Параметры → Приложения → Приложения по умолчанию."),
    (r"^Microsoft Edge WebView2", "WebView2 — движок, на котором показывают своё окно многие программы (Office, Teams, клиенты игр, "
                                  "окно ScanHub). Без него они не откроются, поэтому Windows не даёт его удалить."),
    (r"^Microsoft Edge Update", "Служба обновления Edge и WebView2 — удаляется только вместе с ними."),
    (r"^Microsoft Update Health Tools$|^Windows PC Health Check$", "Служебный компонент Windows Update — Windows поставит его снова."),
]


def _resolve(exe):
    """«cmd.exe /C …», «rundll32 …» — без пути: ищем как Windows (System32, PATH), иначе такие программы казались
    программами с «потерянным деинсталлятором»."""
    if not exe or os.path.isabs(os.path.expandvars(exe)):
        return os.path.expandvars(exe or "")
    import shutil
    sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", exe)
    return shutil.which(exe) or (sys32 if os.path.exists(sys32) else exe)


def _protected(name):
    return next((why for rx, why in PROTECTED if re.search(rx, name or "", re.I)), None)


def _val(k, name):
    try:
        return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def programs():
    out, seen = [], set()
    for hive, path, view, tag in ROOTS:
        try:
            root = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(root)[0]):
            sub = winreg.EnumKey(root, i)
            try:
                k = winreg.OpenKey(root, sub)
            except OSError:
                continue
            name = _val(k, "DisplayName")
            if not name or _val(k, "SystemComponent") == 1 or _val(k, "ParentKeyName") or \
                    (_val(k, "ReleaseType") or "") in ("Update", "Hotfix", "Security Update"):
                continue
            us = _val(k, "UninstallString") or ""
            qs = _val(k, "QuietUninstallString") or ""
            if not us and not _val(k, "WindowsInstaller"):
                continue
            key = f"{tag}\\{sub}"
            # одна и та же запись видна и в 64-, и в 32-битном представлении реестра — её показываем один раз;
            # а вот записи «для всех» и «для тебя» — разные установки, их показываем обе (иначе после удаления
            # одной «программа появляется снова»)
            dedup = (name.lower(), (_val(k, "DisplayVersion") or ""), "HKCU" if tag == "HKCU" else "HKLM", sub.lower())
            if dedup in seen:
                continue
            seen.add(dedup)
            loc = (_val(k, "InstallLocation") or "").strip().strip('"')
            exe = _resolve(system.exe_from_command(us)) if us and "msiexec" not in us.lower() else ""
            msi = bool(_val(k, "WindowsInstaller")) or "msiexec" in us.lower()
            d = _val(k, "InstallDate") or ""
            out.append({"key": key, "name": name, "version": _val(k, "DisplayVersion") or "", "publisher": _val(k, "Publisher") or "",
                        "size": (_val(k, "EstimatedSize") or 0) * 1024, "date": f"{d[:4]}-{d[4:6]}-{d[6:8]}" if re.fullmatch(r"\d{8}", d) else "",
                        "location": loc if loc and os.path.isdir(loc) else "", "uninstall": us, "quiet": qs, "msi": msi,
                        "broken": bool(exe) and not os.path.exists(exe), "user": tag == "HKCU", "scope": SCOPE[tag],
                        "protected": _protected(name),
                        "icon": (_val(k, "DisplayIcon") or "").split(",")[0].strip('"')})
    out.sort(key=lambda p: (p["name"].lower(), p["scope"]))
    names = {}
    for p in out:
        names[p["name"].lower()] = names.get(p["name"].lower(), 0) + 1
    for p in out:
        p["copies"] = names[p["name"].lower()]          # >1 — у программы несколько записей (для всех / для тебя / 32-бит)
    return out


def find(key):
    return next((p for p in programs() if p["key"] == key), None)


# ---------------------------------------------------------------- запуск деинсталлятора

class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND), ("lpVerb", wintypes.LPCWSTR),
                ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]


def _split(cmd):
    cmd = cmd.strip()
    if cmd.startswith('"'):
        exe, _, rest = cmd[1:].partition('"')
        return exe, rest.strip()
    m = re.match(r"(.+?\.exe)(\s+.*)?$", cmd, re.I)
    if m:
        return m.group(1), (m.group(2) or "").strip()
    exe, _, rest = cmd.partition(" ")
    return exe, rest


def _shell_run(exe, params, admin=False):
    """ShellExecuteEx: обычные деинсталляторы сами покажут UAC, если им нужны права. Скрипты (.bat, .cmd) — нет:
    их Windows запускает без прав, и удаление «для всех» молча не срабатывает, поэтому admin=True — сразу через UAC.
    Возвращает дескриптор процесса."""
    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = 0x40 | 0x400                      # NOCLOSEPROCESS | FLAG_NO_UI
    sei.lpVerb = "runas" if admin else "open"
    sei.lpFile = exe
    sei.lpParameters = params or None
    sei.nShow = 1
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.GetLastError()
        raise RuntimeError("запуск отменён" if err == 1223 else f"не удалось запустить деинсталлятор (ошибка {err})")
    return sei.hProcess


def _wait(h, seconds, cancelled=lambda: False):
    """Ждать деинсталлятор, но по секунде — чтобы ожидание можно было прервать кнопкой «Перестать ждать»."""
    if not h:
        return
    t0 = time.time()
    while time.time() - t0 < seconds and not cancelled():
        if ctypes.windll.kernel32.WaitForSingleObject(h, 1000) == 0:        # WAIT_OBJECT_0 — процесс завершился
            break
    ctypes.windll.kernel32.CloseHandle(h)


def uninstall(key, progress=lambda s: None, elevated=False, cancelled=None):
    cancelled = cancelled or (lambda: False)
    p = find(key)
    if not p:
        raise RuntimeError("программа уже удалена")
    if p.get("protected"):
        raise RuntimeError(p["protected"])
    us = p["uninstall"]
    if p["msi"] and (m := re.search(r"\{[0-9A-F-]{36}\}", us + key, re.I)):
        exe, params = "msiexec.exe", f"/x {m.group(0)}"
    elif us:
        exe, params = _split(us)
        exe = _resolve(exe)
        if not os.path.exists(exe) and not exe.lower().endswith(("msiexec.exe", "msiexec")):
            raise RuntimeError("деинсталлятор не найден — используй «Удалить запись и остатки»")
    else:
        raise RuntimeError("у программы нет деинсталлятора")
    script = exe.lower().endswith((".bat", ".cmd"))
    admin = elevated or (script and not key.startswith("HKCU"))
    progress("Подтверди окно UAC — удаление идёт с правами администратора" if admin else
             "Идёт удаление — следуй инструкциям в окне удаления программы")
    started = time.time()
    h = _shell_run(exe, params, admin)
    _wait(h, 3600, cancelled)
    # многие деинсталляторы (NSIS, Inno) копируют себя во временную папку и сразу выходят — ждём, пока исчезнет запись,
    # но только пока работает деинсталлятор, запущенный ПОСЛЕ начала удаления (чужие «setup» в системе не в счёт)
    progress("Жду, пока деинсталлятор закончит…")
    t0 = time.time()
    while time.time() - t0 < 600 and not cancelled():
        if not find(key):
            break
        if time.time() - t0 > 8 and not _uninstaller_running(started):
            break
        time.sleep(2)
    removed = find(key) is None
    progress("Ищу остатки…")
    # не удалилось без прав администратора — окно предложит повторить с ними
    return {"name": p["name"], "removed": removed, "leftovers": leftovers(p) if removed or not cancelled() else [], "key": key,
            "cancelled": bool(cancelled()) and not removed,
            "retry_admin": not removed and not admin and not key.startswith("HKCU") and not cancelled()}


def _uninstaller_running(since=0):
    """Работает ли деинсталлятор, запущенный после начала удаления."""
    import psutil
    pat = re.compile(r"(unins\d*|uninst|uninstall|au_|un_a|setup|msiexec|_iu14d2n)", re.I)
    for pr in psutil.process_iter(["name", "create_time"]):
        n = pr.info.get("name") or ""
        if pat.search(n) and n.lower() != "msiexec.exe" and (pr.info.get("create_time") or 0) >= since - 2:
            return True
    return False


# ---------------------------------------------------------------- остатки

STOP = {"the", "for", "and", "free", "pro", "x64", "x86", "64-bit", "32-bit", "version", "edition", "update", "setup", "windows",
        "microsoft", "app", "desktop", "client", "launcher", "inc", "inc.", "ltd", "llc", "corporation", "corp", "co", "gmbh"}


# производители и общие слова: папка или ключ с таким именем принадлежит многим программам сразу
BROAD = {"adobe", "google", "microsoft", "nvidia", "amd", "intel", "apple", "mozilla", "oracle", "java", "python", "realtek", "lenovo",
         "hp", "dell", "asus", "acer", "msi", "epic", "valve", "jetbrains", "autodesk", "corel", "logitech", "razer", "ubisoft", "ea",
         "electronic", "riot", "blizzard", "battle.net", "visual", "node", "nodejs", "docker", "vmware", "oracle", "windows",
         "office", "kaspersky", "eset", "avast", "avg", "norton", "mcafee", "yandex", "mail.ru", "tencent", "wondershare", "samsung",
         "xiaomi", "huawei", "sony", "canon", "epson", "brother", "qualcomm", "broadcom", "killer", "dolby", "waves", "nahimic", "steelseries"}
# ключи реестра, которые никогда не удаляем целиком
REG_KEEP = {"microsoft", "classes", "policies", "wow6432node", "clients", "registeredapplications", "windows", "intel", "nvidia",
            "nvidiacorporation", "realtek", "amd", "ati", "google", "mozilla", "apple", "appleinc.", "oracle", "javasoft", "python",
            "pythoncore", "odbc", "khronos", "partner", "mozillaplugins", "netscape", "wow64", "dell", "lenovo", "hp", "hewlett-packard"}


def _safe_folder(path, protected, bases=None):
    """Папку-остаток предлагаем, только если она не системная, не корень и в ней нет других установленных программ."""
    n = os.path.normcase(os.path.abspath(path)).rstrip("\\")
    home = os.path.normcase(os.path.expanduser("~"))
    deny = {os.path.normcase(os.environ.get(v, "")).rstrip("\\") for v in
            ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "APPDATA", "LOCALAPPDATA", "SystemRoot", "USERPROFILE",
             "PUBLIC", "CommonProgramFiles", "CommonProgramFiles(x86)")} - {""}
    if n in deny or n == home or len(n) <= 3 or n.startswith(os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))):
        return False
    if any(n == p or p.startswith(n + "\\") for p in protected):       # это папка другой программы или её родитель
        return False
    if bases and not any(n.startswith(os.path.normcase(b).rstrip("\\") + "\\") for b in bases if b):
        return False                                                    # место установки вне обычных папок программ
    return True


def _tokens(p):
    name = re.sub(r"[\(\[].*?[\)\]]", " ", p["name"])
    name = re.sub(r"\bv?\d+(\.\d+)+\b", " ", name)
    words = [w for w in re.split(r"[\s\-_:,]+", name) if w and w.lower() not in STOP and len(w) > 1]
    full = " ".join(words).strip()
    cands = {full.lower(), "".join(words).lower()} if full else set()
    # первое слово названия («Adobe» из «Adobe Photoshop») — только если оно не общее: иначе под удаление попадёт
    # папка всего производителя (C:\Program Files\Adobe, HKCU\Software\Google) вместе с другими его программами
    if words and words[0].lower() not in BROAD:
        cands.add(words[0].lower())
    pub = re.sub(r"[,.]?\s*(inc|ltd|llc|corp(oration)?|gmbh|co|s\.a|limited)\.?$", "", (p["publisher"] or "").strip(), flags=re.I).strip()
    # короткие слова (от 3 букв) — иначе «qt» нашло бы что угодно; но если всё название — одно короткое слово
    # («Qt», «R»…), ищем папки точно с этим именем, иначе остатки таких программ не искались совсем
    short_ok = {full.lower()} if len(words) == 1 and len(full) == 2 else set()
    return {c for c in cands if (len(c) >= 3 or c in short_ok) and c.replace(" ", "") not in BROAD}, pub.lower()


def _first_word(name):
    w = [x for x in re.split(r"[\s\-_:,]+", re.sub(r"[\(\[].*?[\)\]]", " ", name or "")) if x]
    return w[0].lower() if w else ""


def leftovers(p):
    toks, pub = _tokens(p)
    others = [q for q in programs() if q["key"] != p["key"]]
    first = _first_word(p["name"])
    # первое слово, с которого начинается название ещё какой-то программы или имя производителя, — не годится
    if first in toks and len(toks) > 1 and (first == pub.replace(" ", "") or any(_first_word(q["name"]) == first for q in others)):
        toks = toks - {first}
    if not toks:
        return []
    protected = {os.path.normcase(q["location"].rstrip("\\")) for q in others if q["location"]}
    other_names = {re.sub(r"\s+", "", q["name"].lower()) for q in others}
    bases = [os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
             os.environ.get("ProgramData", r"C:\ProgramData"), os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", ""),
             os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs"),
             os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs"),
             os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs")]
    found = []

    def match(n):
        n = n.lower().replace(" ", "")
        return any(n == t.replace(" ", "") for t in toks)

    for b in bases:
        if not b or not os.path.isdir(b):
            continue
        try:
            entries = list(os.scandir(b))
        except OSError:
            continue
        for e in entries:
            if not e.is_dir():
                continue
            hit = None
            if match(e.name):
                hit = e.path
            elif pub and e.name.lower().replace(" ", "") == pub.replace(" ", ""):
                try:
                    sub = [x for x in os.scandir(e.path) if x.is_dir() and match(x.name)]
                except OSError:
                    sub = []
                hit = sub[0].path if sub else None
            if hit and _safe_folder(hit, protected) and re.sub(r"\s+", "", os.path.basename(hit).lower()) not in other_names - toks:
                found.append({"kind": "folder", "path": hit, "size": system.dir_size(hit, 5),
                              "admin": not hit.lower().startswith(os.path.expanduser("~").lower())})
    if p.get("location") and os.path.isdir(p["location"]) and _safe_folder(p["location"], protected, bases) \
            and not any(f["path"] == p["location"] for f in found):
        found.append({"kind": "folder", "path": p["location"], "size": system.dir_size(p["location"], 5),
                      "admin": not p["location"].lower().startswith(os.path.expanduser("~").lower())})
    # ключи реестра настроек программы
    for hive, tag in ((HKCU, "HKCU"), (HKLM, "HKLM")):
        for base in (r"Software", r"Software\WOW6432Node") if hive == HKLM else (r"Software",):
            for cand in _reg_candidates(hive, base, toks, pub):
                found.append({"kind": "regkey", "path": f"{tag}\\{cand}", "admin": hive == HKLM})
    # службы программы (их файл — в папке программы или в найденных остатках): после удаления они часто остаются,
    # продолжают работать и держат файлы занятыми — из-за них «остатки не удаляются»
    dirs = [os.path.normcase(f["path"].rstrip("\\")) + "\\" for f in found if f["kind"] == "folder"]
    if p.get("location"):
        dirs.append(os.path.normcase(p["location"].rstrip("\\")) + "\\")
    if dirs:
        try:
            import psutil
            for s in psutil.win_service_iter():
                try:
                    exe = system.exe_from_command(s.binpath()) or ""
                    if exe and any(os.path.normcase(exe).startswith(d) for d in dirs):
                        found.append({"kind": "service", "path": s.name(), "label": s.display_name(), "exe": exe, "admin": True})
                except Exception:
                    pass
        except Exception:
            pass
    # без повторов (C:\X и C:\X\ — одно и то же) и с пометкой, где могут лежать данные пользователя (сохранения, настройки)
    out, seen = [], set()
    roaming = os.path.normcase(os.environ.get("APPDATA", "~~")) + "\\"
    home = os.path.normcase(os.path.expanduser("~")) + "\\"
    for f in found:
        key = os.path.normcase(f["path"].rstrip("\\")) if f["kind"] == "folder" else f["path"].lower()
        if key in seen:
            continue
        seen.add(key)
        if f["kind"] == "folder":
            f["path"] = f["path"].rstrip("\\")
            n = os.path.normcase(f["path"]) + "\\"
            f["data"] = "\\start menu\\" not in n and (n.startswith(roaming) or (n.startswith(home) and "\\appdata\\local\\" not in n))
        out.append(f)
    return out


def _reg_candidates(hive, base, toks, pub):
    out = []
    try:
        root = winreg.OpenKey(hive, base)
    except OSError:
        return out
    subs = []
    for i in range(winreg.QueryInfoKey(root)[0]):
        try:
            subs.append(winreg.EnumKey(root, i))
        except OSError:
            break
    for s in subs:
        sl = s.lower().replace(" ", "")
        if sl in REG_KEEP:
            continue
        if any(sl == t.replace(" ", "") for t in toks):
            out.append(f"{base}\\{s}")
        elif pub and sl == pub.replace(" ", ""):
            try:
                k = winreg.OpenKey(root, s)
                for i in range(winreg.QueryInfoKey(k)[0]):
                    n = winreg.EnumKey(k, i)
                    if any(n.lower().replace(" ", "") == t.replace(" ", "") for t in toks):
                        out.append(f"{base}\\{s}\\{n}")
            except OSError:
                pass
    return out


def _exists(i):
    """Остаток ещё на месте?"""
    if i["kind"] == "folder":
        return os.path.exists(i["path"])
    if i["kind"] == "service":
        try:
            import psutil
            psutil.win_service_get(i["path"])
            return True
        except Exception:
            return False
    hive, _, sub = i["path"].partition("\\")
    try:
        winreg.CloseKey(winreg.OpenKey(HKCU if hive == "HKCU" else HKLM, sub))
        return True
    except OSError:
        return False


def remove_leftovers(items, run_elevated):
    """items: [{"kind": "folder"|"regkey"|"service", "path", "admin"}] (уже сверены сервером с найденными остатками).
    Сначала службы — пока служба работает, её файлы заняты и папка не удаляется. В конце — честная перепроверка:
    что осталось, возвращается в "left" с причиной (раньше такие остатки молча пропадали из списка)."""
    os.makedirs(pcclean.BACKUPS, exist_ok=True)
    ops = []
    for i in items:
        if i["kind"] == "service":
            ops.append({"type": "run", "cmd": ["sc.exe", "stop", i["path"]], "timeout": 60})
            ops.append({"type": "run", "cmd": ["sc.exe", "delete", i["path"]], "timeout": 60})
    # всё «для всех» — одним окном UAC: помощник выполняет по порядку, так что службы остановятся раньше, чем дойдёт до папок
    ok, errors = 0, []
    for i in items:
        if i["kind"] == "folder" and i.get("admin"):
            ops.append({"type": "recycle", "paths": [i["path"]]})
        elif i["kind"] == "regkey":
            path = i["path"]
            if not re.match(r"^HK(CU|LM)\\Software\\", path, re.I) or path.count("\\") < 2:
                continue
            reg = path.replace("HKCU\\", "HKEY_CURRENT_USER\\").replace("HKLM\\", "HKEY_LOCAL_MACHINE\\")
            bak = os.path.join(pcclean.BACKUPS, f"reg-{pcclean.stamp()}-{len(ops)}.reg")
            if path.upper().startswith("HKCU"):
                subprocess.run(["reg", "export", reg, bak, "/y"], capture_output=True, creationflags=NO_WINDOW)
                r = subprocess.run(["reg", "delete", reg, "/f"], capture_output=True, creationflags=NO_WINDOW)
                if r.returncode == 0:
                    ok += 1
                else:
                    errors.append(f"{path}: не удалось удалить ключ")
            else:
                ops.append({"type": "run", "cmd": ["reg", "export", reg, bak, "/y"], "timeout": 60})
                ops.append({"type": "run", "cmd": ["reg", "delete", reg, "/f"], "timeout": 60, "count": True})
    if ops:
        try:
            res = run_elevated(ops)
            for op, r in zip(ops, res):
                if op["type"] == "recycle":
                    ok += r.get("removed", 0) if r.get("ok") else 0
                elif op.get("count"):
                    ok += 1 if r.get("ok") and r.get("code") == 0 else 0
        except PermissionError as e:
            errors.append(f"элементы, требующие прав администратора, пропущены: {e}")
    n, errs = pcclean.to_recycle([i["path"] for i in items if i["kind"] == "folder" and not i.get("admin")])
    ok += n
    errors += errs
    left = []
    for i in items:
        if _exists(i):
            why = ("служба не остановилась или окно UAC было отменено" if i["kind"] == "service" else
                   "файлы заняты работающей программой или службой — удалится при перезагрузке" if i["kind"] == "folder" else
                   "ключ не удалился — нет прав или он занят")
            left.append({**i, "why": why})
    return {"removed": len(items) - len(left), "errors": errors, "left": left}


def delete_on_reboot(items, run_elevated):
    """Папки, которые держат занятые файлы, — удалить при следующей перезагрузке (MoveFileEx, как это делают установщики)."""
    folders = [i["path"] for i in items if i["kind"] == "folder" and os.path.exists(i["path"])]
    if not folders:
        return {"scheduled": 0}
    res = run_elevated([{"type": "delay_delete", "path": f} for f in folders])
    return {"scheduled": sum(1 for r in res if r.get("ok")), "files": sum(r.get("scheduled", 0) for r in res)}


def force_remove_many(keys, run_elevated):
    """Несколько записей удалённых программ сразу: HKLM — одним окном UAC, с резервной копией каждой."""
    os.makedirs(pcclean.BACKUPS, exist_ok=True)
    el, local, names = [], [], []
    for key in keys:
        p = find(key)
        if not p:
            continue
        tag, sub = key.split("\\", 1)
        hive = "HKEY_CURRENT_USER" if tag == "HKCU" else "HKEY_LOCAL_MACHINE"
        path = UNINST if tag != "HKLM32" else r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        reg = f"{hive}\\{path}\\{sub}"
        bak = os.path.join(pcclean.BACKUPS, f"uninstall-entry-{pcclean.stamp()}-{len(names)}.reg")
        cmds = [["reg", "export", reg, bak, "/y"], ["reg", "delete", reg, "/f"]]
        (local if tag == "HKCU" else el).extend(cmds)
        names.append((key, p["name"]))
    for c in local:
        subprocess.run(c, capture_output=True, creationflags=NO_WINDOW)
    if el:
        run_elevated([{"type": "run", "cmd": c, "timeout": 60} for c in el])
    removed = [n for k, n in names if find(k) is None]
    failed = [n for k, n in names if n not in removed]
    return {"removed": len(removed), "names": removed, "failed": failed, "errors": [f"{n}: запись не удалилась (окно UAC отменено?)" for n in failed]}


def force_remove(key, run_elevated):
    """Для программ со сломанным деинсталлятором: убрать запись из списка программ (с резервной копией) и найти остатки."""
    p = find(key)
    if not p:
        raise RuntimeError("запись уже удалена")
    tag, sub = key.split("\\", 1)
    hive = "HKEY_CURRENT_USER" if tag == "HKCU" else "HKEY_LOCAL_MACHINE"
    path = UNINST if tag != "HKLM32" else r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    reg = f"{hive}\\{path}\\{sub}"
    os.makedirs(pcclean.BACKUPS, exist_ok=True)
    bak = os.path.join(pcclean.BACKUPS, f"uninstall-entry-{pcclean.stamp()}.reg")
    left = leftovers(p)
    if tag == "HKCU":
        subprocess.run(["reg", "export", reg, bak, "/y"], capture_output=True, creationflags=NO_WINDOW)
        subprocess.run(["reg", "delete", reg, "/f"], capture_output=True, creationflags=NO_WINDOW)
    else:
        run_elevated([{"type": "run", "cmd": ["reg", "export", reg, bak, "/y"], "timeout": 60},
                      {"type": "run", "cmd": ["reg", "delete", reg, "/f"], "timeout": 60}])
    return {"name": p["name"], "removed": find(key) is None, "backup": bak, "leftovers": left}
