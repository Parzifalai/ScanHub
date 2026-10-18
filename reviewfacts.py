"""Факты о файлах и папках перед «✦ Есть ли тут важное?» / «✦ Что можно удалить?».

Без интернета и быстро (до ~10 с на 60 пунктов): что это, чьё, запущено ли, когда трогали, что внутри.
Помощник получает их вместе со списком — и судит по фактам, а не только по именам.
Отсюда же — проверка, что путь можно удалять вообще (SAFE_BLOCK), и само удаление для «Проверить и удалить с помощью ИИ».
"""
import os
import re
import time

import system

HOME = os.path.expanduser("~")
WIN = os.environ.get("SystemRoot", r"C:\Windows")
PF = [os.environ.get(k) for k in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432") if os.environ.get(k)]
GAME_RX = re.compile(r"(?i)\\(steamapps|epic games|riot games|genshin|hoyoplay|battle\.net|ubisoft|ea games|origin games|"
                     r"gog galaxy|xboxgames|wuthering|minecraft|\.minecraft|games)\\")
ARCH = (".zip", ".rar", ".7z", ".tar", ".gz", ".iso")
DOC = (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".psd", ".blend", ".kra", ".txt", ".md")
MEDIA = (".mp4", ".mkv", ".mov", ".avi", ".jpg", ".jpeg", ".png", ".heic", ".mp3", ".wav", ".flac")
SETUP_RX = re.compile(r"(?i)(setup|install|installer|инсталл|\.msi$|_x64|x86_64|win64|portable)")


def _norm(p):
    return os.path.normcase(os.path.abspath(p)).rstrip("\\")


# пути, которые нельзя удалять ни при каких оценках: корни дисков, Windows, Program Files целиком, профиль целиком,
# служебные файлы Windows. Внутри Program Files и профиля можно — отдельные папки (с проверкой помощника и человека).
def blocked(path):
    n = _norm(path)
    if re.fullmatch(r"[a-z]:", n):
        return "это весь диск"
    base = os.path.basename(n)
    if base in ("pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log.tmp", "bootmgr", "$recycle.bin", "system volume information",
                "$windows.~bt", "recovery", "boot", "efi"):
        return "служебный файл Windows — удаляется только через настройки Windows"
    if n == _norm(WIN) or n.startswith(_norm(WIN) + "\\"):
        return "папка Windows — вручную не удаляется"
    for p in PF:
        if n == _norm(p):
            return "папка Program Files целиком"
    if n in (_norm(HOME), _norm(os.path.dirname(HOME))):
        return "папка пользователя целиком"
    for sub in ("Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music", "AppData", r"AppData\Local", r"AppData\Roaming",
                "OneDrive"):
        if n == _norm(os.path.join(HOME, sub)):
            return "системная папка пользователя целиком — удаляй то, что внутри"
    return ""


def _when(t):
    d = (time.time() - t) / 86400
    return "сегодня" if d < 1 else f"{int(d)} дн. назад" if d < 60 else f"{int(d / 30)} мес. назад" if d < 730 else f"{d / 365:.0f} г. назад"


def _origin(path):
    try:
        with open(path + ":Zone.Identifier", encoding="utf-8", errors="replace") as f:
            m = re.search(r"(?m)^(?:HostUrl|ReferrerUrl)=(\S+)", f.read())
        if m:
            from urllib.parse import urlparse
            return urlparse(m.group(1)).hostname or ""
    except OSError:
        pass
    return ""


def _inside(path, limit=4000):
    """Коротко о содержимом папки: сколько файлов, каких типов больше, самые свежие изменения."""
    exts, n, newest, sample, dirs = {}, 0, 0, [], 0
    for root, ds, fs in os.walk(path):
        dirs += len(ds)
        for f in fs:
            n += 1
            e = os.path.splitext(f)[1].lower() or "(без расширения)"
            exts[e] = exts.get(e, 0) + 1
            if len(sample) < 6 and root == path:
                sample.append(f)
            try:
                newest = max(newest, os.path.getmtime(os.path.join(root, f)))
            except OSError:
                pass
            if n >= limit:
                break
        if n >= limit:
            break
    top = ", ".join(f"{e} ×{c}" for e, c in sorted(exts.items(), key=lambda x: -x[1])[:5])
    first = sorted(os.listdir(path))[:8] if os.path.isdir(path) else []
    return (f"внутри{' не меньше' if n >= limit else ''} {n} файлов и {dirs} папок; больше всего: {top or '—'}"
            + (f"; последнее изменение внутри {_when(newest)}" if newest else "")
            + (f"; сверху: {', '.join(first)}" if first else ""))


def collect(items, emit=lambda s: None):
    """items: [{path, …}] → {нормализованный путь: строка фактов}."""
    import uninstall
    out = {}
    paths = [i["path"] for i in items if i.get("path") and os.path.exists(i["path"])]
    if not paths:
        return out
    emit("собираю факты о файлах")
    try:
        progs = [(p["name"], _norm(p["location"])) for p in uninstall.programs() if p.get("location") and len(p["location"]) > 4]
    except Exception:
        progs = []
    try:
        import psutil
        running = {}
        for pr in psutil.process_iter(["exe", "name"]):
            if pr.info.get("exe"):
                running.setdefault(_norm(pr.info["exe"]), pr.info["name"])
    except Exception:
        running = {}
    exes = [p for p in paths if os.path.isfile(p) and p.lower().endswith((".exe", ".msi", ".dll")) and not blocked(p)][:25]
    try:
        sigs = system.signatures(exes) if exes else {}
    except Exception:
        sigs = {}
    try:
        import intel
        dl = [_norm(d) for d in intel.download_folders()]
    except Exception:
        dl = [_norm(os.path.join(HOME, "Downloads"))]
    t0 = time.time()
    for p in paths:
        n = _norm(p)
        f = []
        try:
            st = os.stat(p)
        except OSError:
            continue
        isdir = os.path.isdir(p)
        f.append("папка" if isdir else "файл")
        f.append(f"изменён {_when(st.st_mtime)}")
        if not isdir and abs(st.st_atime - st.st_mtime) > 86400:
            f.append(f"открывали {_when(st.st_atime)}")
        owner = next((name for name, loc in progs if n == loc or n.startswith(loc + "\\") or loc.startswith(n + "\\")), "")
        if owner:
            f.append(f"относится к установленной программе «{owner}»" if not _norm(next(l for nm, l in progs if nm == owner)).startswith(n + "\\")
                     else f"внутри — установленная программа «{owner}» (удалять через «Удаление программ»)")
        run = [nm for e, nm in running.items() if e == n or e.startswith(n + "\\")]
        if run:
            f.append("СЕЙЧАС ЗАПУЩЕНО отсюда: " + ", ".join(sorted(set(run))[:3]))
        if GAME_RX.search(n + "\\"):
            f.append("похоже на папку игры или лаунчера")
        if any(n.startswith(d + "\\") for d in dl):
            f.append("лежит в Загрузках")
            host = "" if isdir else _origin(p)
            if host:
                f.append(f"скачан с {host}")
        low = os.path.basename(n)
        m = re.match(r"(.+?)\s*\((\d+)\)(\.[^.]+)?$", low)
        if m and os.path.exists(os.path.join(os.path.dirname(p), m.group(1) + (m.group(3) or ""))):
            f.append("это копия: рядом лежит такой же файл без номера")
        if not isdir and low.endswith(ARCH):
            stem = re.sub(r"(\.tar)?\.[^.]+$", "", os.path.basename(p))
            if os.path.isdir(os.path.join(os.path.dirname(p), stem)):
                f.append(f"архив, рядом уже есть распакованная папка «{stem}»")
            else:
                f.append("архив")
        if not isdir and SETUP_RX.search(low) and low.endswith((".exe", ".msi")):
            f.append("похоже на установщик")
        if not isdir and low.endswith(DOC):
            f.append("документ — возможно, личный")
        if not isdir and low.endswith(MEDIA):
            f.append("фото, видео или музыка — возможно, личное")
        s = sigs.get(p)
        if s and s.get("status"):
            f.append(f"подпись: {s.get('signer') or '—'} ({'действительна' if s.get('status') == 'Valid' else s.get('status')})")
        try:
            import pcclean
            h = pcclean.folder_hint(p)
            if h:
                f.append("справка ScanHub: " + h)
        except Exception:
            pass
        b = blocked(p)
        if b:
            f.append("УДАЛЯТЬ НЕЛЬЗЯ: " + b)
        if isdir and time.time() - t0 < 8:
            try:
                f.append(_inside(p))
            except OSError:
                pass
        out[n] = "; ".join(f)
    return out


# ================================================================ удаление по одобренному списку

def _reason(e, path):
    """Почему не удалилось и что сделать — простыми словами."""
    w = getattr(e, "winerror", None)
    if w in (32, 33) or "used by another process" in str(e) or "занят" in str(e):      # занятый файл Python тоже считает PermissionError
        return "busy", "файл сейчас открыт программой", "Закрой программу, которая его использует, и попробуй снова — или нажми «Удалить при перезагрузке»."
    if isinstance(e, PermissionError) or w == 5:
        return "admin", "нужны права администратора", "Нажми «Удалить с правами администратора» — появится окно UAC."
    if isinstance(e, FileNotFoundError) or w in (2, 3):
        return "gone", "уже удалено", ""
    return "other", str(e)[:200], f"Открой папку {os.path.dirname(path)} и удали вручную; если не получится — спроси помощника."


def delete(paths, permanent=False):
    """Удалить файлы/папки: в Корзину (по умолчанию) или навсегда. Возвращает {done, failed, freed}."""
    import pcclean
    done, failed, freed = [], [], 0
    for p in paths:
        b = blocked(p)
        if b:
            failed.append({"path": p, "kind": "blocked", "why": b, "how": "Такие вещи удаляются только через настройки Windows или программу, которой они принадлежат."})
            continue
        if not os.path.exists(p):
            done.append({"path": p, "size": 0, "note": "уже не было"})
            continue
        size = _size(p)
        try:
            if permanent:
                if os.path.isdir(p) and not os.path.islink(p):
                    import shutil
                    shutil.rmtree(p)
                else:
                    os.remove(p)
            else:
                pcclean.to_recycle([p])
            if os.path.exists(p):
                # Корзина не говорит почему — пробуем переименовать: занятый файл или папка не переименуется (ошибка 32)
                probe = p + ".scanhub-probe"
                os.rename(p, probe)
                os.rename(probe, p)
                raise PermissionError(5, "не удалилось — нужны права администратора")
            done.append({"path": p, "size": size})
            freed += size
        except Exception as e:
            kind, why, how = _reason(e, p)
            if kind == "gone":
                done.append({"path": p, "size": 0, "note": why})
            else:
                failed.append({"path": p, "kind": kind, "why": why, "how": how})
    return {"done": done, "failed": failed, "freed": freed, "permanent": permanent}


def _size(p):
    if os.path.isfile(p):
        try:
            return os.path.getsize(p)
        except OSError:
            return 0
    t = 0
    for root, _, fs in os.walk(p):
        for f in fs:
            try:
                t += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return t
