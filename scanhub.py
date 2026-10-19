"""ScanHub — личный центр антивирусов и сканеров.

Запуск:  pythonw scanhub.py            (сервер + окно)
         python  scanhub.py --update-all  (проверить и поставить обновления, без окна)
"""
import ctypes
import sys

VERSION = "1.4.4"
# репозиторий на GitHub (владелец/имя), где выходят новые версии ScanHub; пусто — проверка обновлений ScanHub выключена
UPDATE_REPO = "Parzifalai/ScanHub"

if sys.version_info < (3, 14) or sys.platform != "win32":
    # pythonw не показывает ошибок — без этого окна ScanHub на старом Python просто молча не открылся бы
    msg = (f"ScanHub нужен Python 3.14 или новее для Windows, а запущен Python {sys.version.split()[0]}.\n\n"
           "Скачай его с python.org (при установке отметь «Add python.exe to PATH»), затем выполни:\n"
           "pip install -r requirements.txt")
    if sys.platform == "win32":
        ctypes.windll.user32.MessageBoxW(None, msg, "ScanHub", 0x10)
    sys.exit(msg)

import fnmatch
import glob
import hashlib
import http.server
import json
import os
import re
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import winreg
import webbrowser
import zipfile
from datetime import datetime
from email.utils import parsedate_to_datetime

# модули приложения — только из его папки (процесс администратора запускается с -I: без текущей папки и переменных PYTHON*)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import atomtraits
import hwcheck
import services

try:
    import metrics
    import system
    import deepscan
    import pcclean
    import tweaks
    import uninstall
    import diag
    import alerts
    import ultra
except ImportError:          # нет psutil — разделы «Ресурсы» и «Система» не работают
    metrics = system = deepscan = pcclean = tweaks = uninstall = diag = alerts = ultra = None
import yarascan
import intel
import assistant
import report
import ultra_report

ROOT = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(ROOT, "registry")
APPS = os.path.join(ROOT, "apps")
DATA = os.path.join(ROOT, "data")
LOGS = os.path.join(DATA, "logs")
STATE_FILE = os.path.join(DATA, "state.json")
HISTORY_FILE = os.path.join(DATA, "history.json")
CONFIG_FILE = os.path.join(DATA, "config.json")
UI_FILE = os.path.join(ROOT, "ui", "index.html")

HOST, PORT = "127.0.0.1", 8765
# токен окна — новый при каждом запуске и только в памяти: прочитать его из файла никакая программа не сможет.
# Окно после перезапуска сервера получает «bad token» и перезагружается само — с новым токеном в странице.
TOKEN = secrets.token_hex(16)
try:
    os.remove(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "token"))   # от старых версий
except OSError:
    pass
CHECK_EVERY = 6 * 3600          # как часто проверять обновления, пока приложение открыто
IDLE_EXIT = 600                 # закрыть сервер, если окно закрыто 10 минут и ничего не идёт (свёрнутое окно Edge может молчать минутами)
NO_WINDOW = 0x08000000          # CREATE_NO_WINDOW
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

for d in (APPS, DATA, LOGS):
    os.makedirs(d, exist_ok=True)

lock = threading.RLock()
jobs = {}            # id -> dict
busy = {}            # tool id -> "install"/"update" текст
last_ping = time.time()


# ---------------------------------------------------------------- хранилище

def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, value):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


SECRET_KEYS = ("virustotal_key", "filescan_key", "metadefender_key", "hybrid_key", "github_token", "gemini_key", "deepseek_key",
               "anthropic_key", "openai_key", "openrouter_key")
AI_KEYS = ("gemini_key", "deepseek_key", "anthropic_key", "openai_key", "openrouter_key")


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data, protect):
    """Шифрование Windows (DPAPI) для учётной записи: расшифровать может только этот пользователь на этом компьютере.
    Копия config.json на другом ПК или в резервной копии бесполезна."""
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    src, out = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), _Blob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(src), None if not protect else "ScanHub", None, None, None, 0x1, ctypes.byref(out))   # 0x1 — без окон
    if not ok:
        raise OSError("DPAPI: не удалось " + ("зашифровать" if protect else "расшифровать"))
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def seal(value):
    import base64
    return "dpapi:" + base64.b64encode(_dpapi(value.encode("utf-8"), True)).decode() if value else ""


def unseal(value):
    import base64
    if not (isinstance(value, str) and value.startswith("dpapi:")):
        return value or ""
    try:
        return _dpapi(base64.b64decode(value[6:]), False).decode("utf-8")
    except Exception:
        return ""                     # файл с другого ПК или другой учётной записи — ключ нужно ввести заново


def config():
    cfg = {"github_token": "", "check_every_hours": 6, "virustotal_key": "", "filescan_key": "", "metadefender_key": "", "hybrid_key": "",
           "gemini_key": "", "deepseek_key": "", "ai_provider": "", "ai_model": "", "ai_files": "meta", "report_url": "", "lang": "ru",
           "alerts_on": True,
           "vt_files": 8, "fs_files": 20, "smart_mb": 100, "folder_full": False}
    raw = load_json(CONFIG_FILE, {})
    cfg.update(raw)
    for k in SECRET_KEYS:
        cfg[k] = unseal(cfg.get(k))
    if any(raw.get(k) and not str(raw[k]).startswith("dpapi:") for k in SECRET_KEYS):
        try:                          # ключи от старых версий лежали открытым текстом — шифруем при первом чтении
            with lock:
                c = load_json(CONFIG_FILE, {})
                for k in SECRET_KEYS:
                    if c.get(k) and not str(c[k]).startswith("dpapi:"):
                        c[k] = seal(c[k])
                save_json(CONFIG_FILE, c)
        except Exception as e:                # ключ остался незашифрованным — об этом должен узнать автор
            report.record("шифрование ключей в настройках", e)
    return cfg


def state():
    return load_json(STATE_FILE, {"tools": {}, "last_check": None})


def tool_state(st, tid):
    return st["tools"].setdefault(tid, {})


def registry():
    tools = []
    for path in sorted(glob.glob(os.path.join(REGISTRY, "*.json"))):
        m = load_json(path, None)
        if m and m.get("id"):
            tools.append(m)
    return tools


def manifest(tid):
    for m in registry():
        if m["id"] == tid:
            return m
    raise KeyError(f"нет инструмента {tid}")


def now():
    return datetime.now().isoformat(timespec="seconds")


# ---------------------------------------------------------------- GitHub

def http_get(url, accept="application/vnd.github+json"):
    headers = {"User-Agent": "ScanHub", "Accept": accept}
    tok = config().get("github_token")
    if tok and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {tok}"
    req = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(req, timeout=60)


def gh_json(path):
    with http_get("https://api.github.com" + path) as r:
        return json.load(r)


def latest_release(m, skip=()):
    """Самый свежий релиз (не pre-release), кроме версий из skip — их придержала проверка VirusTotal."""
    src = m["source"]
    pattern = re.compile(src["asset"], re.I)
    rel = asset = None
    for r in gh_json(f"/repos/{m['repo']}/releases?per_page=10"):
        if r.get("draft") or r.get("prerelease") or r["tag_name"] in skip:
            continue
        a = next((a for a in r.get("assets", []) if pattern.search(a["name"])), None)
        if a:
            rel, asset = r, a
            break
    if not asset:
        raise RuntimeError(f"в релизах нет файла под шаблон {src['asset']}")
    sums = None
    if src.get("checksums"):
        # имя файла сумм — точное или шаблон (у TruffleHog в нём есть версия: trufflehog_3.99.2_checksums.txt)
        sums = next((a for a in rel["assets"] if a["name"] == src["checksums"] or re.fullmatch(src["checksums"], a["name"])), None)
    return {"version": rel["tag_name"], "date": rel.get("published_at"), "asset": asset, "sums": sums,
            "notes": (rel.get("body") or "")[:4000], "url": rel.get("html_url")}


def latest_commit(m):
    src = m["source"]
    branch = src.get("branch") or gh_json(f"/repos/{m['repo']}")["default_branch"]
    c = gh_json(f"/repos/{m['repo']}/commits/{branch}")
    return {"version": c["sha"][:7], "date": c["commit"]["committer"]["date"], "branch": branch,
            "sha": c["sha"], "notes": c["commit"]["message"][:2000],
            "url": f"https://github.com/{m['repo']}/commit/{c['sha']}"}


def latest_direct(m):
    """Файл по прямой ссылке: версия = дата Last-Modified на сервере."""
    url = m["source"]["url"]
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0 ScanHub"})
    with urllib.request.urlopen(req, timeout=60) as r:
        lm = r.headers.get("Last-Modified")
        size = int(r.headers.get("Content-Length") or 0)
    when = parsedate_to_datetime(lm).astimezone() if lm else datetime.now()
    return {"version": when.strftime("%Y-%m-%d %H:%M"), "date": when.isoformat(timespec="seconds"),
            "size": size, "url": m.get("homepage") or url, "notes": ""}


def latest(m):
    t = m["source"]["type"]
    if t == "github-release":
        return latest_release(m)
    if t == "github-source":
        return latest_commit(m)
    if t == "direct":
        return latest_direct(m)
    return None


def authenticode(path):
    """Цифровая подпись exe: (статус, владелец сертификата)."""
    ps = ("$s = Get-AuthenticodeSignature -LiteralPath $env:SCANHUB_ARG; "
          "[pscustomobject]@{status=[string]$s.Status; signer=[string]$s.SignerCertificate.Subject} "
          "| ConvertTo-Json -Compress")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                             env={**os.environ, "SCANHUB_ARG": path}, timeout=60, creationflags=NO_WINDOW).stdout
        d = json.loads(out)
        return d.get("status") or "Unknown", d.get("signer") or ""
    except Exception:
        return "Unknown", ""


def check_signer(m, path):
    """Сверить подписанта с манифестом. Valid — хорошо; UnknownError (цепочка не проверена) — с пометкой."""
    want = m["source"].get("signer")
    if not want:
        return None
    status, signer = authenticode(path)
    if want.lower() not in signer.lower():
        raise RuntimeError(f"файл подписан не тем, кем нужно: «{signer or 'без подписи'}» ({status})")
    if status not in ("Valid", "UnknownError"):
        raise RuntimeError(f"подпись {want} недействительна: {status}")
    return f"подпись {want}: {'действительна' if status == 'Valid' else 'есть, цепочку Windows не проверила'}"


def locate(tid):
    """Для антивирусов, которые скачиваются вручную: найти свежий файл по подписи в папках загрузок."""
    m = manifest(tid)
    f = m["source"]
    dirs = [os.path.expandvars(os.path.expanduser(d)) for d in f["search"]]
    dirs += [d for d in intel.download_folders() if d not in dirs]     # папки загрузок, выбранные в браузерах
    best = None
    for d in dirs:
        for p in glob.glob(os.path.join(d, "*.exe")):
            try:
                if os.path.getsize(p) < f.get("min_mb", 0) * 1024 * 1024:
                    continue
                mt = os.path.getmtime(p)
            except OSError:
                continue
            if best and mt <= best[0]:
                continue
            status, signer = authenticode(p)
            if f["signer"].lower() in signer.lower() and status in ("Valid", "UnknownError"):
                best = (mt, p, status)
    if not best:
        raise RuntimeError("не нашёл скачанный файл в " + ", ".join(dirs))
    mt, p, status = best
    with lock:
        st = state()
        ts = tool_state(st, tid)
        ts.update(installed=datetime.fromtimestamp(mt).strftime("%Y-%m-%d %H:%M"), exe=p, path=os.path.dirname(p),
                  installed_at=datetime.fromtimestamp(mt).isoformat(timespec="seconds"), error=None,
                  verified=f"подпись {f['signer']}: " + ("действительна" if status == "Valid"
                                                         else "есть, цепочку Windows не проверила"))
        save_json(STATE_FILE, st)
    return p


# ---------------------------------------------------------------- Defender

def defender_block(path):
    """Если Defender заблокировал файл — вернуть имя угрозы."""
    ps = ("$p=$env:SCANHUB_ARG; Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | "
          "Where-Object { ($_.Resources -join ';') -match [regex]::Escape($p) } | "
          "Select-Object -First 1 | ForEach-Object { (Get-MpThreat -ThreatID $_.ThreatID).ThreatName }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True,
                             env={**os.environ, "SCANHUB_ARG": path},
                             text=True, timeout=60, creationflags=NO_WINDOW).stdout.strip()
        return out or None
    except Exception:
        return None


class DefenderBlocked(Exception):
    pass


# ---------------------------------------------------------------- установка

def download(url, dest, progress):
    with http_get(url, accept="application/octet-stream") as r, open(dest, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while chunk := r.read(1 << 16):
            f.write(chunk)
            done += len(chunk)
            if total:
                progress(f"скачиваю {done * 100 // total}%")


def is_av_block(e):
    # 225 ERROR_VIRUS_INFECTED, 226 ERROR_VIRUS_DELETED; Python показывает их как Errno 22 / PermissionError
    return isinstance(e, PermissionError) or getattr(e, "winerror", None) in (225, 226)


def av_blocked(path):
    time.sleep(3)
    threat = defender_block(os.path.basename(path))
    return DefenderBlocked(f"{threat} — {os.path.basename(path)}" if threat
                           else f"файл {os.path.basename(path)} заблокирован (вероятно, антивирусом)")


def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError as e:
        if is_av_block(e):
            raise av_blocked(path)
        raise
    return h.hexdigest()


def extract(archive, name, dest):
    low = name.lower()
    if low.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            z.extractall(dest)
    elif low.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar")):
        with tarfile.open(archive) as t:
            t.extractall(dest, filter="data")
    else:
        shutil.copy2(archive, os.path.join(dest, name))
    # архив с одной папкой внутри — поднимаем содержимое на уровень выше
    items = os.listdir(dest)
    if len(items) == 1 and os.path.isdir(os.path.join(dest, items[0])):
        inner = os.path.join(dest, items[0])
        for x in os.listdir(inner):
            shutil.move(os.path.join(inner, x), dest)
        os.rmdir(inner)


class HeldBack(Exception):
    pass


VT_GATE = 5      # столько и больше срабатываний на VirusTotal — версию не ставим


def vt_gate(m, info, archive, exes, progress):
    """Перед установкой релиза с GitHub: спросить VirusTotal (если есть ключ) про архив и главный exe."""
    key = config().get("virustotal_key")
    if not key:
        return
    progress("сверяю с VirusTotal")
    files = [archive] + sorted(exes, key=lambda p: not fnmatch.fnmatch(os.path.basename(p).lower(),
                                                                       (m.get("exe") or "").lower()))[:1]
    vt = services.VirusTotal(key, lambda s: None, lambda: False)
    worst = 0
    for f in files:
        code, body = vt.call(f"/files/{services.sha256(f)}")
        if code == 200:
            stats = body["data"]["attributes"].get("last_analysis_stats", {})
            worst = max(worst, stats.get("malicious", 0))
    if worst >= VT_GATE:
        raise HeldBack(f"{info['version']}: {worst} антивирусов на VirusTotal считают файл вредоносным")


def install(tid, progress=lambda s: None, force=False):
    m = manifest(tid)
    t = m["source"]["type"]
    if t in ("system", "service"):
        raise RuntimeError("этот инструмент ставить не нужно")
    if t == "manual":
        return locate(tid)
    held = tool_state(state(), tid).get("held", {}) if not force else {}
    info = latest_release(m, skip=set(held)) if t == "github-release" else latest(m)
    version = info["version"]
    target = os.path.join(APPS, tid, re.sub(r"[^\w.\-]", "_", version))
    tmp = tempfile.mkdtemp(prefix=f"{tid}-", dir=os.path.join(APPS))
    try:
        stage = os.path.join(tmp, "stage")
        os.makedirs(stage)
        if t == "github-release":
            a = info["asset"]
            file = os.path.join(tmp, a["name"])
            progress("скачиваю")
            download(a["browser_download_url"], file, progress)
            progress("проверяю контрольную сумму")
            got = sha256(file)
            want = (a.get("digest") or "").removeprefix("sha256:")
            if info["sums"]:
                sums_file = os.path.join(tmp, "SUMS")
                download(info["sums"]["browser_download_url"], sums_file, lambda s: None)
                for line in open(sums_file, encoding="utf-8", errors="replace"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[-1].lstrip("*") == a["name"]:
                        if want and want != parts[0].lower():
                            raise RuntimeError("SHA256SUMS и GitHub дают разные суммы")
                        want = parts[0].lower()
            if want and got != want:
                raise RuntimeError(f"контрольная сумма не совпала: {got} ≠ {want}")
            checked = "SHA-256 сверена с GitHub" if want else None
            progress("распаковываю")
            extract(file, a["name"], stage)
        elif t == "direct":
            name = m["source"].get("filename") or os.path.basename(urllib.parse.urlparse(m["source"]["url"]).path)
            file = os.path.join(tmp if name.lower().endswith(".zip") else stage, name)
            progress("скачиваю")
            download(m["source"]["url"], file, progress)
            sha256(file)
            if name.lower().endswith(".zip"):
                progress("распаковываю")
                extract(file, name, stage)
                file = next((p for p in glob.glob(os.path.join(stage, "**", "*.exe"), recursive=True)
                             if fnmatch.fnmatch(os.path.basename(p).lower(), (m.get("exe") or "*.exe").lower())), file)
            progress("проверяю подпись (Defender сканирует новый файл — бывает несколько минут)")
            checked = check_signer(m, file)
        else:  # github-source
            file = os.path.join(tmp, "src.zip")
            progress("скачиваю исходники")
            download(f"https://api.github.com/repos/{m['repo']}/zipball/{info['sha']}", file, progress)
            checked = None
            progress("распаковываю")
            extract(file, "src.zip", stage)
        # проверить, что Defender не съел распакованное
        exes = glob.glob(os.path.join(stage, "**", "*.exe"), recursive=True)
        for exe in exes:
            sha256(exe)
        if t == "github-release" and not force:
            vt_gate(m, info, file, exes, progress)
        if os.path.exists(target):
            shutil.rmtree(target)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.move(stage, target)
        if m.get("setup"):
            progress("подготовка")
            try:
                run_setup(m, target)
            except Exception:
                shutil.rmtree(target, ignore_errors=True)
                raise
    except OSError as e:
        if is_av_block(e) or (e.errno == 22 and e.filename):
            blocked = av_blocked(e.filename or tid)
            if is_av_block(e) or "заблокирован (вероятно" not in str(blocked):
                raise blocked
        raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    with lock:
        st = state()
        ts = tool_state(st, tid)
        prev = ts.get("path")
        ts.update(installed=version, path=target, installed_at=now(), latest=version,
                  verified=checked, blocked=None, error=None, exe=None)
        save_json(STATE_FILE, st)
    # оставить одну предыдущую версию для отката, остальные удалить
    keep = {target, prev}
    for d in glob.glob(os.path.join(APPS, tid, "*")):
        if d not in keep:
            shutil.rmtree(d, ignore_errors=True)
    return version


def run_setup(m, d):
    for cmd in m["setup"]:
        cmd = [os.path.expandvars(c.replace("{dir}", d).replace("{python}", sys.executable.replace("pythonw", "python"))) for c in cmd]
        r = subprocess.run(cmd, cwd=d, capture_output=True, text=True, creationflags=NO_WINDOW)
        if r.returncode:
            raise RuntimeError(f"подготовка упала: {' '.join(cmd)}\n{r.stdout[-1500:]}{r.stderr[-1500:]}")


def install_async(tid, verb="установка", force=False):
    def work():
        try:
            for attempt in range(4):
                try:
                    install(tid, lambda s: busy.__setitem__(tid, f"{verb}: {s}"), force=force)
                    break
                except (HeldBack, DefenderBlocked) as e:
                    m = manifest(tid)
                    if isinstance(e, DefenderBlocked):
                        # Defender заблокировал этот релиз — пробуем предыдущий (он тоже пройдёт Defender и VirusTotal)
                        if m["source"]["type"] != "github-release" or force:
                            raise
                        ver = latest_release(m, skip=set(tool_state(state(), tid).get("held", {})))["version"]
                        reason = f"{ver}: Defender — {e}"
                    else:
                        ver, reason = str(e).split(":")[0], str(e)
                    with lock:
                        st = state()
                        tool_state(st, tid).setdefault("held", {})[ver] = reason
                        save_json(STATE_FILE, st)
                    if attempt == 3:
                        if isinstance(e, DefenderBlocked):
                            raise
                        raise RuntimeError("все свежие версии подозрительны на VirusTotal") from e
        except DefenderBlocked as e:
            with lock:
                st = state()
                tool_state(st, tid).update(blocked=str(e), error=None)
                save_json(STATE_FILE, st)
        except Exception as e:
            with lock:
                st = state()
                tool_state(st, tid)["error"] = f"{verb}: {e}"
                save_json(STATE_FILE, st)
        finally:
            busy.pop(tid, None)
    if tid in busy:
        return False
    busy[tid] = verb
    threading.Thread(target=work, daemon=True).start()
    return True


def check_updates(auto=True):
    """Проверить все инструменты; при auto ставить обновления тем, у кого включено автообновление."""
    results = {}
    for m in registry():
        tid = m["id"]
        if m["source"].get("builtin") == "yara" and yarascan.installed():
            try:
                tag = yarascan.latest_forge(config().get("github_token") or None)[0]
                with lock:
                    st = state()
                    tool_state(st, tid).update(latest=tag, checked_at=now())
                    save_json(STATE_FILE, st)
                old = (yarascan.meta() or {}).get("version")
                if auto and tag != old and auto_on(m, tool_state(state(), tid)) and tid not in busy:
                    busy[tid] = "обновление правил"
                    def upd():
                        try:
                            yarascan.update_rules(lambda x: None, token=config().get("github_token") or None)
                        except Exception as e:
                            with lock:
                                st = state()
                                tool_state(st, tid)["error"] = f"обновление правил: {e}"
                                save_json(STATE_FILE, st)
                        finally:
                            busy.pop(tid, None)
                    threading.Thread(target=upd, daemon=True).start()
                results[tid] = tag
            except Exception as e:
                with lock:
                    st = state()
                    tool_state(st, tid)["check_error"] = str(e)
                    save_json(STATE_FILE, st)
            continue
        if m["source"]["type"] in ("system", "service", "manual", "builtin"):
            continue
        try:
            held = tool_state(state(), tid).get("held", {})
            info = latest_release(m, skip=set(held)) if m["source"]["type"] == "github-release" else latest(m)
            with lock:
                st = state()
                ts = tool_state(st, tid)
                ts.update(latest=info["version"], latest_date=info["date"], latest_url=info["url"],
                          latest_notes=info["notes"], checked_at=now())
                ts.pop("check_error", None)
                save_json(STATE_FILE, st)
            results[tid] = info["version"]
            if auto and ts.get("installed") and ts["installed"] != info["version"] and auto_on(m, ts):
                install_async(tid, "автообновление")
        except Exception as e:
            with lock:
                st = state()
                tool_state(st, tid)["check_error"] = str(e)
                save_json(STATE_FILE, st)
    with lock:
        st = state()
        st["last_check"] = now()
        save_json(STATE_FILE, st)
    return results


def updater_loop():
    while True:
        st = state()
        last = st.get("last_check")
        every = config().get("check_every_hours", 6) * 3600
        due = not last or (datetime.now() - datetime.fromisoformat(last)).total_seconds() > every
        if due:
            check_updates(auto=True)
        time.sleep(300)


# ---------------------------------------------------------------- запуск сканов

def auto_on(m, ts):
    return ts.get("auto_update", m.get("auto_update", True))


def exe_path(m, ts):
    if m["source"]["type"] == "builtin":
        return "builtin" if system else None
    if m["source"]["type"] == "service":
        return "service" if m["source"].get("nokey") or config().get(m["source"]["key"]) else None
    if ts.get("exe"):
        return ts["exe"] if os.path.isfile(ts["exe"]) else None
    if m["source"]["type"] == "system":
        p = os.path.expandvars(m["source"]["path"])
        return p if os.path.exists(p) else None
    d = ts.get("path")
    if not d or not os.path.isdir(d):
        return None
    if not m.get("exe"):
        return d
    for p in glob.glob(os.path.join(d, "**", "*"), recursive=True):
        if fnmatch.fnmatch(os.path.basename(p).lower(), m["exe"].lower()):
            return p
    return None


def build_cmd(m, mode, exe, target, install_dir):
    def sub(a):
        return (a.replace("{target}", target or "").replace("{exe}", exe)
                 .replace("{dir}", install_dir or "").replace("{data}", DATA).replace("{registry}", REGISTRY)
                 .replace("{python}", sys.executable.replace("pythonw", "python")))
    cmd = [sub(a) for a in mode.get("cmd", ["{exe}"] + mode.get("args", []))]
    return [c for c in cmd if c != ""]


def decode(b):
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            pass
    return b.decode("utf-8", "replace")


ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def verdict(m, mode, code, lines=()):
    if mode.get("count_regex"):
        found = [int(x) for l in lines for x in re.findall(mode["count_regex"], l)]
        if found:
            n = max(found)
            v = mode["count_verdict"] if n else mode.get("zero_verdict", ["clean", "Чисто"])
            return [v[0], v[1].replace("{n}", str(n))]
    table = {**m.get("exit_codes", {}), **mode.get("exit_codes", {})}
    v = table.get(str(code))
    if v:
        return v
    return ["clean", "Готово"] if code == 0 else ["error", f"Код выхода {code}"]


def start_job(tid, mode_id, target, batch=None):
    m = manifest(tid)
    mode = next(x for x in m["modes"] if x["id"] == mode_id)
    st = state()
    ts = tool_state(st, tid)
    exe = exe_path(m, ts)
    if not exe:
        raise RuntimeError("нужен API-ключ (Настройки)" if m["source"]["type"] == "service"
                           else "инструмент не установлен")
    kind = mode.get("target")
    if kind in ("path", "folder") and not (target and os.path.exists(target)):
        raise RuntimeError("укажи существующий файл или папку")
    if kind == "file" and not (target and os.path.isfile(target)):
        raise RuntimeError("укажи файл (не папку)")
    if kind == "url" and not re.match(r"^https?://\S+$", target or ""):
        raise RuntimeError("укажи ссылку, начинающуюся с http:// или https://")
    is_service = m["source"]["type"] == "service"
    install_dir = None if is_service else (ts.get("path") or os.path.dirname(exe))
    cmd = [m["name"], mode["action"], target or ""] if is_service else build_cmd(m, mode, exe, target, install_dir)
    smart_note, listfile = None, None
    cfg_ = config()
    dropped = bool(target) and os.path.normpath(target).lower().startswith(DROP.lower())   # перетащенные файлы — все, без отбора
    if batch and kind == "path" and target and os.path.isdir(target) and tid in ("clamav", "atomscan") and not cfg_["folder_full"] and not dropped:
        files, n_ok, n_all = smart_files(target, 3000 if tid == "clamav" else 200, cfg_["smart_mb"])
        smart_note = (f"[ScanHub] быстрая проверка папки: {len(files)} файлов из {n_all} — программы, библиотеки, скрипты, архивы и документы "
                      f"с макросами до {cfg_['smart_mb']} МБ" + (f" (самые важные из {n_ok} подходящих)" if n_ok > len(files) else "") +
                      ". Всю папку целиком проверяет режим в карточке сканера.")
        if tid == "clamav":
            listfile = os.path.join(DATA, f"list_{uuid.uuid4().hex[:8]}.txt")
            with open(listfile, "w", encoding="utf-8") as f:
                f.write("\n".join(files))
            cmd = [exe, f"--database={install_dir}\\database", "--infected", "--max-filesize=4000M", "--max-scansize=4000M",
                   "--max-recursion=6", f"--file-list={listfile}"]
        else:
            cmd = [exe, "--no-update", "path"] + files
        if not files:
            cmd = None
    if tid == "atomscan" and cmd and mode_id != "version" and "--no-update" not in cmd:
        cmd = [cmd[0], "--no-update"] + list(cmd[1:])        # правила обновляет atomtraits — без образцов вирусов
    jid = uuid.uuid4().hex[:10]
    job = {"id": jid, "tool": tid, "tool_name": m["name"], "mode": mode_id, "mode_label": mode["label"],
           "target": target, "cmd": cmd, "started": now(), "finished": None, "status": "running",
           "code": None, "verdict": None, "lines": [], "batch": batch, "gui": bool(mode.get("gui")),
           "log": os.path.join(LOGS, f"{jid}.log"), "progress": None, "listfile": listfile}
    jobs[jid] = job
    if smart_note:
        job["lines"].append(smart_note)
        if cmd is None:
            job["lines"].append("В папке нет файлов, которые стоит проверять этим сканером.")
            job.update(code=0, verdict=["clean", "Нечего проверять"], status="done", finished=now())
            finish_job(job)
            return job
        job["cmd"] = cmd[:8] + (["…"] if len(cmd) > 8 else [])

    if m["source"]["type"] == "builtin":
        def work_builtin():
            emit = job["lines"].append
            try:
                if m["source"]["builtin"] == "yara" and mode_id == "update":
                    meta = yarascan.update_rules(emit, token=config().get("github_token") or None)
                    code, v = 0, ["clean", f"Правила обновлены: {meta['rules']}"]
                elif m["source"]["builtin"] in intel.BUILTINS:
                    code, v = intel.run(m["source"]["builtin"], mode_id, target, emit, lambda: job.get("stop"), job.setdefault("details", []))
                elif m["source"]["builtin"] == "yara":
                    code, v, found = yarascan.scan_target(target, emit, lambda: job.get("stop"), config(),
                                                          smart=(lambda t: smart_files(t, 3000, config()["smart_mb"]))
                                                          if batch and not config()["folder_full"] and not dropped else None,
                                                          progress=lambda x: job.__setitem__("progress", x))
                    job["found"] = [f for f in found if f["real"]]
                else:
                    code, v = system.signature_check(target, emit, job.setdefault("details", []))
            except Exception as e:
                emit(f"[ScanHub] ошибка: {e}")
                code, v = 3, ["error", "Ошибка"]
            job.update(code=code, verdict=v, status="stopped" if job.get("stop") else "done", finished=now())
            finish_job(job)
        job["cmd"] = [m["name"], mode["label"], target or ""]
        threading.Thread(target=work_builtin, daemon=True).start()
        return job

    if is_service:
        def work_service():
            def emit(line):
                job["lines"].append(line)
                mm = re.match(r"^\[(\d+)/(\d+)\]", line)
                if mm:
                    job["progress"] = f"файл {mm.group(1)} из {mm.group(2)}"
            try:
                code, v = services.run(m["source"]["service"], mode["action"], config().get(m["source"].get("key") or "", ""),
                                       target, emit, lambda: job.get("stop"),
                                       limit=config()["vt_files" if m["source"]["service"] == "virustotal" else "fs_files"],
                                       details=job.setdefault("details", []))
            except Exception as e:
                job["lines"].append(f"[ScanHub] ошибка: {e}")
                code, v = 3, ["error", "Ошибка"]
            job.update(code=code, verdict=v, status="stopped" if job.get("stop") else "done", finished=now())
            finish_job(job)
        threading.Thread(target=work_service, daemon=True).start()
        return job

    if mode.get("console"):
        # интерактивные консольные программы — в своём окне терминала (при необходимости — от администратора)
        if mode.get("admin"):
            ps = ("$a = $env:SCANHUB_ARG | ConvertFrom-Json; "
                  "Start-Process cmd.exe -Verb RunAs -WorkingDirectory $a.dir -ArgumentList ('/k ' + $a.line)")
            line = subprocess.list2cmdline(cmd)
            r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                               env={**os.environ, "SCANHUB_ARG": json.dumps({"dir": install_dir, "line": line})},
                               creationflags=NO_WINDOW)
            ok = r.returncode == 0
            job["lines"].append("Открыто в окне консоли администратора." if ok else "Запуск отменён (UAC).")
        else:
            subprocess.Popen(["cmd", "/k", *cmd], cwd=install_dir, creationflags=subprocess.CREATE_NEW_CONSOLE)
            ok = True
            job["lines"].append("Открыто в отдельном окне консоли.")
        job.update(status="done", finished=now(), code=0 if ok else -1,
                   verdict=["launched", "Открыто"] if ok else ["error", "Отменено"])
        finish_job(job)
        return job

    if mode.get("handler"):
        # вывод разбирает сам ScanHub (Sigcheck → корневые сертификаты)
        def work_handler():
            try:
                code, v = intel.handle(mode["handler"], exe, target, job["lines"].append, lambda: job.get("stop"), job.setdefault("details", []))
            except Exception as e:
                job["lines"].append(f"[ScanHub] ошибка: {e}")
                code, v = 3, ["error", "Ошибка"]
            job.update(code=code, verdict=v, status="stopped" if job.get("stop") else "done", finished=now())
            finish_job(job)
        threading.Thread(target=work_handler, daemon=True).start()
        return job

    if mode.get("elevated_log") or mode.get("elevated"):
        # одно окно UAC, ждём конца и показываем результат здесь: либо отчёт, который программа пишет в файл (HiJackThis),
        # либо вывод консольного сканера (Emsisoft a2cmd: сначала обновление баз — "pre", потом проверка)
        def work_elev():
            t0 = time.time()
            job["lines"].append("Жду подтверждения администратора (окно UAC)…")
            try:
                pre = [build_cmd(m, {"args": a}, exe, target, install_dir) for a in mode.get("pre", [])]
                ops = [{"type": "run", "cmd": c, "cwd": os.path.dirname(exe), "timeout": 1800, "label": "обновление баз"} for c in pre]
                # raw_cmdline: аргументы передаются как написаны (a2cmd ждёт /f="путь с пробелами", а не "/f=путь с пробелами")
                main = (subprocess.list2cmdline(cmd[:1]) + " " + " ".join(cmd[1:])) if mode.get("raw_cmdline") else cmd
                ops.append({"type": "run", "cmd": main, "cwd": os.path.dirname(exe), "timeout": int(mode.get("timeout", 900)), "label": "проверка"})
                rep_dir = os.path.join(DATA, "reports", job["id"])
                if mode.get("elevated_log"):
                    ops.append({"type": "copy_glob", "src_dir": os.path.dirname(exe), "pattern": mode["elevated_log"], "dst_dir": rep_dir,
                                "newer_than": t0 - 5, "timeout": 60})
                try:
                    res = deepscan.run_elevated(ops, timeout=sum(o["timeout"] for o in ops) + 60,
                                                on_started=lambda: job["lines"].append("права выданы ✓ — " + mode.get("started_text", "идёт проверка, обычно 1–3 минуты…")),
                                                on_progress=lambda s: job.__setitem__("progress", s))
                except PermissionError:
                    job["lines"].append("Права администратора не выданы (UAC отменён).")
                    job.update(code=-1, verdict=["error", "Отменено"], status="done", finished=now())
                    finish_job(job)
                    return
                if mode.get("elevated"):
                    for o, r in zip(ops, res):
                        if o is not ops[-1]:
                            job["lines"].append(f"[{o['label']}: код {r.get('code')}]")
                        job["lines"] += [ANSI.sub("", l) for l in (r.get("out") or r.get("error") or "").splitlines() if l.strip()]
                    code = res[-1].get("code") if res and res[-1].get("ok") else -1
                    v = verdict(m, mode, code, job["lines"])
                    job.update(code=code, verdict=v, status="stopped" if job.get("stop") else "done", finished=now())
                    finish_job(job)
                    return
                logs = sorted(glob.glob(os.path.join(rep_dir, mode["elevated_log"])), key=os.path.getmtime)
                if not logs:
                    out = (res[0].get("out") or res[0].get("error") or "") if res else ""
                    job["lines"].append("Отчёт не появился." + (f" Вывод: {out[-500:]}" if out else ""))
                    code, v = 3, ["error", "Нет отчёта"]
                else:
                    raw = open(logs[-1], "rb").read()
                    text = (raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else decode(raw)).lstrip("﻿")
                    job["lines"] += ["", f"Отчёт: {logs[-1]}", ""] + text.splitlines()
                    n = sum(1 for l in text.splitlines() if re.match(mode.get("item_regex", r"^[A-Z]\d+(-\w+)?\s+-\s"), l))
                    job["report"] = logs[-1]
                    code, v = 0, ["launched", f"Отчёт готов: записей {n} — разбирать вручную"]
            except Exception as e:
                job["lines"].append(f"[ScanHub] ошибка: {e}")
                code, v = 3, ["error", "Ошибка"]
                report.record(f"{m['id']}: {mode['id']}", e)
            job.update(code=code, verdict=v, status="stopped" if job.get("stop") else "done", finished=now())
            finish_job(job)
        threading.Thread(target=work_elev, daemon=True).start()
        return job

    if mode.get("gui"):
        # GUI-программы: просто запускаем (при необходимости — с правами администратора)
        if mode.get("admin") or m.get("admin"):
            ps = ("$a = $env:SCANHUB_ARG | ConvertFrom-Json; "
                  "$p = @{FilePath=$a.exe; WorkingDirectory=$a.dir; Verb='RunAs'}; "
                  "if ($a.args.Count) { $p.ArgumentList = $a.args }; Start-Process @p")
            arg = json.dumps({"exe": cmd[0], "dir": os.path.dirname(exe), "args": cmd[1:]})
            r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                               env={**os.environ, "SCANHUB_ARG": arg}, creationflags=NO_WINDOW)
            ok = r.returncode == 0
            job["lines"].append("Запущено с правами администратора." if ok else
                                "Запуск отменён или не удался: " + (r.stderr.strip() or r.stdout.strip()))
        else:
            subprocess.Popen(cmd, cwd=os.path.dirname(exe))
            ok = True
            job["lines"].append("Программа открыта в отдельном окне.")
        job.update(status="done", finished=now(), code=0 if ok else -1,
                   verdict=["launched", "Открыто"] if ok else ["error", "Не запущено"])
        finish_job(job)
        return job

    def run_once(c):
        p = subprocess.Popen(c, cwd=install_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, creationflags=NO_WINDOW,
                             env={**os.environ, "NO_COLOR": "1", "PYTHONIOENCODING": "utf-8"})
        job["pid"] = p.pid
        for raw in p.stdout:
            line = ANSI.sub("", decode(raw).rstrip("\r\n"))
            job["lines"].append(line)
        return p.wait()

    def work():
        try:
            if tid == "atomscan" and mode_id != "version":
                try:
                    atomtraits.update(job["lines"].append, exe)
                except Exception as e:
                    job["lines"].append(f"[ScanHub] правила Atomdrift не обновились ({e}) — проверяю с уже скачанными")
            start = len(job["lines"])
            code = run_once(cmd)
            if tid == "atomscan":
                atomtraits.purge_testdata()
            v = verdict(m, mode, code, job["lines"])
            if tid == "trufflehog":
                v = secrets_report(job["lines"], start)
            if tid == "clamav" and code == 1 and deepscan:
                found = {}
                for l in job["lines"]:
                    if l.strip().endswith(" FOUND") and ": " in l:
                        path, name = l.strip()[:-6].rsplit(": ", 1)
                        found[path] = name
                if found:
                    job["lines"].append("\n[ScanHub] перепроверяю находки: цифровые подписи и VirusTotal…")
                    vv, real, fp, sus = deepscan.verify(found, "ClamAV", config(), lambda: job.get("stop"))
                    job["lines"] += ["  ✗ " + x for x in real] + ["  ✓ " + x for x in fp]
                    job["found"] = [{"path": x, "name": found[x], "engine": "ClamAV", "real": True} for x in sus if os.path.isfile(x)]
                    if not real:
                        v = ["clean", f"Ложные тревоги ClamAV: {len(fp)}"]
            job.update(code=code, verdict=v,
                       status="stopped" if job.get("stop") else "done")
        except Exception as e:
            job["lines"].append(f"[ScanHub] ошибка запуска: {e}")
            job.update(code=-1, verdict=["error", "Ошибка запуска"], status="done")
        job["finished"] = now()
        finish_job(job)
    threading.Thread(target=work, daemon=True).start()
    return job


SMART_EXT = {".exe": 0, ".msi": 0, ".scr": 0, ".com": 0, ".pif": 0, ".bat": 1, ".cmd": 1, ".ps1": 1, ".vbs": 1, ".vbe": 1,
             ".js": 1, ".jse": 1, ".wsf": 1, ".hta": 1, ".jar": 1, ".lnk": 1, ".py": 2, ".dll": 2, ".sys": 2, ".cpl": 2, ".ocx": 2,
             ".zip": 3, ".rar": 3, ".7z": 3, ".iso": 3, ".msix": 3, ".appx": 3, ".apk": 3, ".docm": 3, ".xlsm": 3, ".pptm": 3,
             ".doc": 4, ".xls": 4, ".pdf": 4}


def smart_files(target, limit=3000, max_mb=100):
    """Быстрая проверка папки: только то, что может быть опасным (программы, библиотеки, скрипты, архивы, документы с макросами),
    до max_mb МБ; сначала исполняемые. Возвращает (файлы, всего подходящих, всего файлов)."""
    found, total = [], 0
    for root, dirs, names in os.walk(target, onerror=lambda e: None):
        dirs[:] = [d for d in dirs if d.lower() not in ("$recycle.bin", "system volume information", "node_modules", ".git")]
        for n in names:
            total += 1
            pr = SMART_EXT.get(os.path.splitext(n)[1].lower())
            if pr is None:
                continue
            f = os.path.join(root, n)
            try:
                # программы и скрипты — любого размера: вредонос иногда специально «раздувают», чтобы антивирусы его пропустили
                if pr <= 1 or os.path.getsize(f) <= max_mb * 2 ** 20:
                    found.append((pr, f))
            except OSError:
                pass
    found.sort()
    return [f for _, f in found[:limit]], len(found), total


def _mask(secret):
    s = str(secret or "").strip()
    return (s[:4] + "…" + s[-2:]) if len(s) > 10 else "…" if s else "?"


def secrets_report(lines, start):
    """TruffleHog выдаёт находки в JSON вместе с самим секретом. В журнал ScanHub секреты не попадают: оставляем
    тип ключа, файл, строку и маску (первые 4 и последние 2 символа)."""
    found, summary, other = [], None, []
    for l in lines[start:]:
        if not l.startswith("{"):
            other.append(l)
            continue
        try:
            d = json.loads(l)
        except ValueError:
            continue
        if "DetectorName" in d:
            fs = ((d.get("SourceMetadata") or {}).get("Data") or {})
            loc = fs.get("Filesystem") or fs.get("Git") or {}
            found.append({"type": d.get("DetectorName"), "file": loc.get("file") or "?", "line": loc.get("line"),
                          "commit": (loc.get("commit") or "")[:8], "verified": bool(d.get("Verified")), "mask": _mask(d.get("Raw"))})
        elif d.get("msg") == "finished scanning":
            summary = d
        elif str(d.get("level", "")).startswith("error"):
            other.append("ошибка: " + str(d.get("msg") or "") + (f" ({d.get('error')})" if d.get("error") else ""))
    out = [x for x in other if x.strip()][:30]
    by_file = {}
    for f in found:
        by_file.setdefault(f["file"], []).append(f)
    for file, items in sorted(by_file.items()):
        out.append(f"{file}")
        for f in items:
            out.append(f"  {'✕ ДЕЙСТВУЕТ' if f['verified'] else '!'} {f['type']}" + (f", строка {f['line']}" if f["line"] else "")
                       + (f", коммит {f['commit']}" if f["commit"] else "") + f" · {f['mask']}")
    if summary:
        mb = int(summary.get("bytes", 0)) / 2 ** 20
        out.append(f"\nПросмотрено: {mb:.1f} МБ (фрагментов: {summary.get('chunks', 0)}).")
    ver = sum(f["verified"] for f in found)
    in_env = [f for f in found if os.path.basename(str(f["file"])).lower().startswith(".env") and not f["commit"]]
    if found:
        if in_env:
            out.append(f"\nВ файлах .env: {len(in_env)}. Ключам там и место, если .env указан в .gitignore и никогда не попадал на GitHub "
                       "или к другим людям — тогда ничего делать не нужно.")
        if len(in_env) < len(found):
            out.append("\nКлюч прямо в коде или в истории git — удали его оттуда и перевыпусти в кабинете сервиса: старый считай утёкшим, "
                       "если код уходил на GitHub или к другим людям. Храни ключи в .env, а .env — в .gitignore.")
    lines[start:] = out
    if ver:
        return ["threat", f"Действующие ключи: {ver}"]
    if found and len(in_env) == len(found):
        return ["unknown", f"Ключи в .env: {len(found)} — проверь, что .env в .gitignore"]
    if found:
        return ["suspicious", f"Ключи и пароли в коде: {len(found) - len(in_env)}"]
    return ["clean", "Ключей и паролей не найдено"]


_LINK_HOSTS = {}


UPDATE_KEEP = {"data", "apps", "python", "_backup", "dev", ".git"}     # это при обновлении не трогаем


UPD_PROG = {}          # ход обновления ScanHub для окна: stage, pct, text, error


def _upd(stage, pct, text):
    UPD_PROG.update(stage=stage, pct=round(pct, 1), text=text, error=None)


def self_update_start():
    """Обновление в фоне — окно спрашивает ход через /api/self_update/progress и рисует проценты."""
    if UPD_PROG.get("stage") not in (None, "error", "done"):
        return dict(UPD_PROG)
    _upd("check", 1, "проверяю, какая версия последняя")

    def work():
        try:
            self_update_apply()
        except Exception as e:
            UPD_PROG.update(stage="error", error=str(e))
    threading.Thread(target=work, daemon=True).start()
    return dict(UPD_PROG)


def self_update_apply():
    """Обновление в одну кнопку: скачать архив выпуска с GitHub, сверить SHA-256, поставить поверх и перезапуститься."""
    import hashlib
    import zipfile
    _upd("check", 2, "проверяю, какая версия последняя")
    info = self_update(force=True)
    if not info.get("newer"):
        raise RuntimeError("новой версии нет — у тебя последняя")
    a, repo = info.get("asset") or {}, info["repo"]
    url = a.get("url") or ""
    if not url.startswith(f"https://github.com/{repo}/releases/download/"):
        raise RuntimeError("в выпуске нет архива ScanHub — скачай его со страницы выпуска")
    if (a.get("size") or 0) > 300 * 2 ** 20:
        raise RuntimeError("архив выпуска слишком большой")
    up = os.path.join(DATA, "update")
    shutil.rmtree(up, ignore_errors=True)
    os.makedirs(up, exist_ok=True)
    zpath = os.path.join(up, "update.zip")
    req = urllib.request.Request(url, headers={"User-Agent": f"ScanHub/{VERSION}"})
    h = hashlib.sha256()
    total, got = a.get("size") or 0, 0
    _upd("download", 3, f"скачиваю ScanHub {info.get('latest')}")
    with urllib.request.urlopen(req, timeout=120) as r, open(zpath, "wb") as f:
        total = total or int(r.headers.get("Content-Length") or 0)
        while chunk := r.read(1 << 16):
            h.update(chunk)
            f.write(chunk)
            got += len(chunk)
            if total:
                _upd("download", 3 + 77 * got / total, f"скачиваю: {got / 2 ** 20:.1f} из {total / 2 ** 20:.1f} МБ")
    _upd("verify", 81, "сверяю контрольную сумму с GitHub")
    want = (a.get("digest") or "").lower()
    if want.startswith("sha256:") and want[7:] != h.hexdigest():
        raise RuntimeError("архив не совпал с контрольной суммой GitHub — не ставлю")
    with zipfile.ZipFile(zpath) as z:
        names = [n for n in z.namelist() if not n.endswith("/")]
        _upd("install", 84, "ставлю новые файлы")
        top = {n.split("/", 1)[0] for n in names}
        strip = top.pop() + "/" if len(top) == 1 and all("/" in n for n in names) else ""
        if not any(n == strip + "scanhub.py" for n in names):
            raise RuntimeError("в архиве нет ScanHub — не ставлю")
        copied = 0
        for n in names:
            rel = n[len(strip):]
            parts = rel.replace("\\", "/").split("/")
            if not rel or ".." in parts or parts[0] in UPDATE_KEEP or ":" in rel:
                continue
            dst = os.path.join(ROOT, *parts)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            data = z.read(n)
            try:
                with open(dst, "wb") as f:
                    f.write(data)
            except PermissionError:                     # ScanHub.exe может быть занят — старый откладываем в сторону
                old = dst + ".old"
                try:
                    os.remove(old)
                except OSError:
                    pass
                os.replace(dst, old)
                with open(dst, "wb") as f:
                    f.write(data)
            copied += 1
            if copied % 10 == 0:
                _upd("install", 84 + 14 * copied / max(1, len(names)), f"ставлю новые файлы: {copied} из {len(names)}")
    shutil.rmtree(up, ignore_errors=True)
    _upd("restart", 100, "перезапускаю ScanHub")
    # новая копия сервера ждёт, пока освободится порт, и поднимается сама; окно увидит новую версию и перезагрузится
    py = sys.executable.replace("python.exe", "pythonw.exe")
    subprocess.Popen([py, os.path.join(ROOT, "scanhub.py"), "--no-open", "--after-update"], cwd=ROOT,
                     close_fds=True, creationflags=NO_WINDOW | 0x00000200)
    threading.Timer(1.5, os._exit, [0]).start()
    return {"ok": True, "version": info.get("latest"), "files": copied}


def self_update(force=False):
    """Вышла ли новая версия ScanHub: последний выпуск в GitHub Releases. Раз в 6 часов, только номер версии и ссылка."""
    repo = (config().get("update_repo") or UPDATE_REPO).strip()
    if not re.fullmatch(r"[\w.\-]+/[\w.\-]+", repo):
        return {"enabled": False, "current": VERSION}
    st = state()
    c = st.get("self_update") or {}
    age = time.time() - c.get("checked", 0)
    # после неудачи (нет сети, обрыв SSL) — снова через 10 минут, а не через 6 часов
    if force or c.get("repo") != repo or not c.get("checked") or age > 6 * 3600 or (c.get("error") and age > 600):
        try:
            req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest",
                                         headers={"User-Agent": f"ScanHub/{VERSION}", "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=15) as r:
                d = json.load(r)
            assets = [{"name": a.get("name"), "url": a.get("browser_download_url"), "size": a.get("size"), "digest": a.get("digest")}
                      for a in d.get("assets") or []]
            # для обновления берём архив с кодом (ScanHub-1.2.3.zip); полный с Python — только если другого нет
            asset = next((a for a in assets if re.fullmatch(r"ScanHub-[\d.]+\.zip", a["name"] or "")), None) or \
                next((a for a in assets if a["name"] == "ScanHub-Windows.zip"), None)
            c = {"repo": repo, "checked": time.time(), "latest": str(d.get("tag_name") or "").lstrip("vV"), "url": d.get("html_url"),
                 "notes": str(d.get("body") or "")[:1500], "published": d.get("published_at"), "asset": asset}
        except Exception as e:
            c = {**c, "repo": repo, "checked": time.time(), "error": str(e)[:200]}
        with lock:
            st = state()
            st["self_update"] = c
            save_json(STATE_FILE, st)
    ver = lambda v: [int(x) for x in re.findall(r"\d+", v or "0")[:3]]
    return {"enabled": True, "current": VERSION, "repo": repo, **c,
            "newer": bool(c.get("latest")) and ver(c.get("latest")) > ver(VERSION)}


def link_hosts():
    """Сайты, которые окно может открыть в браузере: все, что упомянуты в реестре сканеров и в файлах окна.
    Чужая программа, узнавшая токен, не сможет открыть через ScanHub произвольный (фишинговый) адрес."""
    files = glob.glob(os.path.join(REGISTRY, "*.json")) + glob.glob(os.path.join(ROOT, "ui", "*.js")) + [UI_FILE] +         glob.glob(os.path.join(ROOT, "*.py"))
    stamp = tuple(sorted((f, os.path.getmtime(f)) for f in files if os.path.exists(f)))
    if _LINK_HOSTS.get("stamp") != stamp:
        hosts = {"github.com", "www.virustotal.com", "www.filescan.io", "metadefender.com", "hybrid-analysis.com", "osv.dev",
                 "hashlookup.circl.lu", "www.loldrivers.io"}
        for f in files:
            try:
                hosts |= {h.lower() for h in re.findall(r"https://([A-Za-z0-9.\-]+)", open(f, encoding="utf-8", errors="replace").read())}
            except OSError:
                pass
        _LINK_HOSTS.update(stamp=stamp, hosts=hosts)
    return _LINK_HOSTS["hosts"]


def finish_job(job):
    if job.get("listfile"):
        try:
            os.remove(job["listfile"])
        except OSError:
            pass
    with open(job["log"], "w", encoding="utf-8") as f:
        f.write(f"# {job['tool_name']} — {job['mode_label']}\n# {' '.join(job['cmd'])}\n\n")
        f.write("\n".join(job["lines"]))
    with lock:
        h = load_json(HISTORY_FILE, [])
        h.insert(0, {k: job[k] for k in ("id", "tool", "tool_name", "mode_label", "target", "started",
                                          "finished", "code", "verdict", "batch", "log")})
        save_json(HISTORY_FILE, h[:300])


def stop_job(jid):
    if jid in UPDATERS:
        UPDATERS[jid].stop()
    job = jobs.get(jid)
    if job and job["status"] == "running":
        job["stop"] = True
    if job and job.get("pid") and job["status"] == "running":
        subprocess.run(["taskkill", "/PID", str(job["pid"]), "/T", "/F"], capture_output=True,
                       creationflags=NO_WINDOW)


# ---------------------------------------------------------------- системная информация

_sys_cache = {}


def system_info(m):
    if not m["source"].get("status_ps"):
        return None
    hit = _sys_cache.get(m["id"])
    if hit and time.time() - hit[0] < 120:
        return hit[1]
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", m["source"]["status_ps"]],
                             capture_output=True, text=True, timeout=30, creationflags=NO_WINDOW).stdout
        info = json.loads(out)
    except Exception:
        info = None
    _sys_cache[m["id"]] = (time.time(), info)
    return info


def _tool_item(m, st):
    """Карточка одного инструмента для окна."""
    ts = st["tools"].get(m["id"], {})
    exe = exe_path(m, ts)
    item = {**m, "state": ts, "ready": bool(exe), "exe_path": exe, "busy": busy.get(m["id"]),
            "auto_update": auto_on(m, ts), "section": m.get("section", "scanners")}
    if m["source"]["type"] == "system":
        item["system"] = system_info(m)
    sv = item.get("state") or ts
    item["update_available"] = bool(exe and sv.get("installed") and ts.get("latest")
                                    and sv["installed"] != ts["latest"])
    # антивирусы со встроенными базами (KVRT, CureIt) устаревают за пару дней
    if exe and ts.get("installed_at") and m.get("max_age_days"):
        age = (datetime.now() - datetime.fromisoformat(ts["installed_at"])).days
        item["age_days"] = age
        item["stale"] = age >= m["max_age_days"]
    nd = m.get("needs_data")
    if m["source"]["type"] == "builtin" and m["source"].get("builtin") in intel.BUILTINS:
        iv = intel.view(m["source"]["builtin"])
        if iv:
            item["state"] = {**ts, **iv}
            item["age_days"] = (datetime.now() - datetime.fromisoformat(iv["installed_at"])).days
    if exe and nd and nd.get("builtin") == "yara":
        item["data_missing"] = not yarascan.installed()
        ym = yarascan.meta()
        if ym:
            item["state"] = {**ts, "installed": ym["version"], "installed_at": ym["updated"], "rules": ym["rules"],
                             "verified": "SHA-256 сверена с GitHub"}
            age = (datetime.now() - datetime.fromisoformat(ym["updated"])).days
            item["age_days"] = age
            item["stale"] = age >= m.get("max_age_days", 14)
        try:
            import yara_x  # noqa: F401
        except ImportError:
            item["missing"] = [{"label": "модуль yara-x (pip install yara-x)", "url": "https://pypi.org/project/yara-x/", "path": ""}]
            item["ready"] = False
    elif exe and nd and not glob.glob(os.path.join(ts.get("path") or "", nd["glob"])):
        item["data_missing"] = True
    missing = [r for r in m.get("requires", []) if not os.path.exists(os.path.expandvars(r["path"]))]
    if item.get("missing") and not missing:
        missing = item["missing"]
    if missing:
        item["missing"] = missing
        item["ready"] = False
    return item


def tools_view():
    st = state()
    out = []
    for m in registry():
        try:
            out.append(_tool_item(m, st))
        except Exception as e:            # одна сломанная карточка не должна оставлять окно без всех инструментов
            out.append({**m, "state": {"error": f"карточка не загрузилась: {e}"}, "ready": False, "exe_path": None, "busy": None,
                        "auto_update": False, "section": m.get("section", "scanners")})
    return out


assistant.HOOKS["tools"] = tools_view      # помощник видит список сканеров, не импортируя сервер
assistant.HOOKS["act"] = lambda action, arg: agent_action(action, arg)   # «Сделай сам»: действия из одобренного плана
assistant.HOOKS["url"] = lambda: f"http://{HOST}:{PORT}"                  # адрес для инструментов агента (mcp_server.py)


def pick(kind):
    """Нативный диалог выбора файла/папки (в отдельном процессе, чтобы Tk не мешал серверу)."""
    code = ("import tkinter as tk, tkinter.filedialog as fd, sys\n"
            "r=tk.Tk(); r.withdraw(); r.attributes('-topmost', True)\n"
            f"p = fd.askdirectory(title='Папка для проверки') if {kind == 'folder'!r} "
            "else fd.askopenfilename(title='Файл для проверки')\n"
            "sys.stdout.write(p or '')")
    py = sys.executable.replace("pythonw.exe", "python.exe")
    out = subprocess.run([py, "-I", "-c", code], capture_output=True, text=True, encoding="utf-8",
                         creationflags=NO_WINDOW).stdout.strip()
    if out:
        PICKED.add(os.path.normpath(out))
    return os.path.normpath(out) if out else ""


PICKED = set()       # что человек сам выбрал в окне выбора файла/папки — только это можно уничтожить шредером

# ---------------------------------------------------------------- перетаскивание файлов в окно
# Браузер не сообщает странице путь перетащенного файла — только имя, размер и дату. Поэтому сначала ищем файл там,
# откуда его обычно тащат: выделенное в открытых окнах Проводника, их папки, Рабочий стол и Загрузки. Нашли — проверяем
# сам файл (тогда работает и карантин). Не нашли (тащили из браузера, архива…) — окно присылает содержимое, проверяем копию.
DROP = os.path.join(DATA, "drop")
DROP_MAX = 2 * 2 ** 30
_LOCATE_PS = r"""$ErrorActionPreference = 'SilentlyContinue'
$sh = New-Object -ComObject Shell.Application
$sel = @(); $dirs = @()
foreach ($w in @($sh.Windows())) { try { $d = $w.Document; foreach ($i in @($d.SelectedItems())) { $sel += $i.Path }; $dirs += $d.Folder.Self.Path } catch {} }
$dirs += [Environment]::GetFolderPath('Desktop'); $dirs += [Environment]::GetFolderPath('CommonDesktopDirectory')
$dirs += $sh.NameSpace('shell:Downloads').Self.Path
(@{sel = @($sel); dirs = @($dirs)} | ConvertTo-Json -Compress)"""


def drop_locate(files):
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", _LOCATE_PS], capture_output=True, timeout=20,
                           creationflags=NO_WINDOW)
        found = json.loads(r.stdout.decode("utf-8", "replace").strip() or "{}")
    except Exception:
        found = {}
    sel = [p for p in found.get("sel") or [] if p]
    dirs = [d for d in found.get("dirs") or [] if d] + intel.download_folders()
    out = []
    for f in files:
        name, size, is_dir = str(f.get("name") or ""), int(f.get("size") or 0), bool(f.get("dir"))
        mtime = (f.get("mtime") or 0) / 1000
        if not name or name != os.path.basename(name):
            out.append(None)
            continue
        cands = [p for p in sel if os.path.basename(p).lower() == name.lower()] + [os.path.join(d, name) for d in dirs]
        best = None
        for p in dict.fromkeys(os.path.normpath(c) for c in cands):
            if is_dir:
                if os.path.isdir(p):
                    best = p
                    break
                continue
            try:
                st = os.stat(p)
            except OSError:
                continue
            if os.path.isfile(p) and st.st_size == size:
                if not mtime or abs(st.st_mtime - mtime) < 3:
                    best = p
                    break
                best = best or p          # размер совпал, а дата нет — запасной вариант
        if best:
            PICKED.add(best)
        out.append(best)
    return out


def _drop_dir(did):
    if not re.fullmatch(r"[a-z0-9]{6,16}", did or ""):
        raise RuntimeError("неверный id")
    now_ = time.time()
    if os.path.isdir(DROP):
        for x in os.listdir(DROP):                       # копии старше суток больше не нужны
            p = os.path.join(DROP, x)
            try:
                if now_ - os.path.getmtime(p) > 86400:
                    shutil.rmtree(p, ignore_errors=True)
            except OSError:
                pass
    d = os.path.join(DROP, did)
    os.makedirs(d, exist_ok=True)
    return d


def _safe_name(name):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", os.path.basename(name or "")).strip(" .")
    return name[:180] or "file"


def drop_upload(did, name, size, rfile):
    if size > DROP_MAX:
        raise RuntimeError("файл больше 2 ГБ — выбери его кнопкой «Проверить файл»")
    path = os.path.join(_drop_dir(did), _safe_name(name))
    left = size
    with open(path, "wb") as f:
        while left > 0:
            chunk = rfile.read(min(left, 2 ** 20))
            if not chunk:
                break
            f.write(chunk)
            left -= len(chunk)
    time.sleep(0.5)
    if not os.path.isfile(path):
        raise RuntimeError("Microsoft Defender удалил файл сразу при сохранении — он считает его вирусом. Не запускай оригинал")
    return path


def drop_collect(did, paths):
    d, total = _drop_dir(did), 0
    for p in paths:
        p = os.path.normpath(p)
        if p not in PICKED or not os.path.isfile(p):        # копируем только то, что сами нашли для этого перетаскивания
            continue
        total += os.path.getsize(p)
        if total > DROP_MAX:
            raise RuntimeError("файлов больше чем на 2 ГБ — проверь их папку кнопкой «Проверить папку»")
        shutil.copy2(p, os.path.join(d, _safe_name(os.path.basename(p))))
    return d


# ---------------------------------------------------------------- фоновые задачи (системные проверки)

TASKS = {}
_last_notify = 0


def _hosts_set(enable):
    new = system.hosts_prepare(enable)
    deepscan.run_elevated([{"type": "copy", "src": new, "dst": system.HOSTS},
                           {"type": "run", "cmd": ["ipconfig", "/flushdns"], "timeout": 60}])
    os.remove(new)
    return system.hosts_status()


def _sensors_set(enable):
    pf_dir = os.path.dirname(metrics.SENSORS_SCRIPT)
    if enable:
        tr = ('conhost.exe --headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File '
              f'"{metrics.SENSORS_SCRIPT}"')
        # завершить уже запущенного агента (иначе продолжит работать старая версия скрипта)
        kill_old = ("Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | Where-Object { $_.CommandLine -like "
                    "'*ScanHub\\sensors.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }")
        ops = [{"type": "run", "cmd": ["powershell", "-NoProfile", "-Command", kill_old], "timeout": 30},
               {"type": "mkdir", "path": pf_dir},
               {"type": "copy", "src": os.path.join(ROOT, "agent", "sensors.ps1"), "dst": metrics.SENSORS_SCRIPT},
               {"type": "mkdir", "path": metrics.SENSORS_DIR},
               # папка данных: пользователь может писать (файл «want»), скрипт агента лежит отдельно в Program Files
               {"type": "run", "cmd": ["icacls", metrics.SENSORS_DIR, "/grant", "*S-1-5-32-545:(OI)(CI)M"], "timeout": 30},
               {"type": "run", "cmd": ["schtasks", "/End", "/TN", metrics.SENSORS_TASK], "timeout": 30},
               {"type": "run", "cmd": ["schtasks", "/Create", "/TN", metrics.SENSORS_TASK, "/TR", tr, "/SC", "ONCE",
                                       "/ST", "00:00", "/RL", "HIGHEST", "/F"], "timeout": 60},
               # по умолчанию Windows не запускает задачи от батареи — для ноутбука это не годится
               {"type": "run", "cmd": ["powershell", "-NoProfile", "-Command",
                                       "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
                                       "-ExecutionTimeLimit (New-TimeSpan -Hours 12) -MultipleInstances IgnoreNew; "
                                       "Set-ScheduledTask -TaskPath '\\ScanHub\\' -TaskName 'Sensors' -Settings $s | Out-Null"],
                "timeout": 60}]
    else:
        ops = [{"type": "run", "cmd": ["schtasks", "/End", "/TN", metrics.SENSORS_TASK], "timeout": 30},
               {"type": "run", "cmd": ["schtasks", "/Delete", "/TN", metrics.SENSORS_TASK, "/F"], "timeout": 30},
               {"type": "rmtree", "path": pf_dir}]
    res = deepscan.run_elevated(ops, timeout=300)
    metrics.METRICS.sensors_on = None          # перепроверить при следующем такте
    if enable:
        subprocess.run(["schtasks", "/Run", "/TN", metrics.SENSORS_TASK], capture_output=True, creationflags=NO_WINDOW)
    return {"enabled": metrics.sensors_installed(), "steps": [{"ok": r.get("ok"), "code": r.get("code"),
                                                               "out": (r.get("out") or r.get("error") or "")[-300:]} for r in res]}


def _hardware(refresh=False):
    path = os.path.join(DATA, "hardware.json")
    if not refresh:
        cached = load_json(path, None)
        if cached:
            return cached
    d = system.hardware()
    d["collected"] = now()
    save_json(path, d)
    return d


def _memclean_set(enable):
    """Полная очистка памяти: скрипт в Program Files (меняет только администратор) + задача с наивысшими правами."""
    pf_dir = os.path.dirname(system.MEMCLEAN_SCRIPT)
    if enable:
        tr = ('conhost.exe --headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File '
              f'"{system.MEMCLEAN_SCRIPT}"')
        ops = [{"type": "mkdir", "path": pf_dir},
               {"type": "copy", "src": os.path.join(ROOT, "agent", "memclean.ps1"), "dst": system.MEMCLEAN_SCRIPT},
               {"type": "mkdir", "path": os.path.dirname(system.MEMCLEAN_JSON)},
               {"type": "run", "cmd": ["icacls", os.path.dirname(system.MEMCLEAN_JSON), "/grant", "*S-1-5-32-545:(OI)(CI)M"],
                "timeout": 30},
               {"type": "run", "cmd": ["schtasks", "/Create", "/TN", system.MEMCLEAN_TASK, "/TR", tr, "/SC", "ONCE",
                                       "/ST", "00:00", "/RL", "HIGHEST", "/F"], "timeout": 60},
               {"type": "run", "cmd": ["powershell", "-NoProfile", "-Command",
                                       "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
                                       "-ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew; "
                                       "Set-ScheduledTask -TaskPath '\\ScanHub\\' -TaskName 'MemClean' -Settings $s | Out-Null"],
                "timeout": 60}]
    else:
        ops = [{"type": "run", "cmd": ["schtasks", "/Delete", "/TN", system.MEMCLEAN_TASK, "/F"], "timeout": 30},
               {"type": "remove", "path": system.MEMCLEAN_SCRIPT}]
    deepscan.run_elevated(ops, timeout=300)
    if metrics:
        metrics.METRICS.memclean_on = None
    return {"enabled": system.memclean_installed()}


def _with_rp(desc, fn, args):
    """Перед изменением системы — точка восстановления (если пользователь не снял галочку и защита системы включена)."""
    def run():
        rp = None
        if args.get("restore_point"):
            st = tweaks.restore_status()
            if st["enabled"]:
                try:
                    rp = tweaks.restore_create(deepscan.run_elevated, desc)
                except PermissionError:
                    rp = {"status": "error", "text": "UAC отменён — точка восстановления не создана"}
            else:
                rp = {"status": "off", "text": "защита системы выключена — точка восстановления не создана"}
        res = fn()
        if isinstance(res, dict):
            res["restore_point"] = rp
        return res
    return run


def _last(name):
    t = TASKS.get(name) or {}
    return t.get("result") if t.get("status") == "done" else None


def _only_found(name, args):
    """Удаляющие и меняющие действия — только над тем, что ScanHub сам нашёл последней проверкой.

    Защищает и от ошибки в окне, и от запроса к серверу в обход окна: иначе «остатком программы» можно было бы
    передать C:\\Windows, а ScanHub удалил бы его с правами администратора. Флаги (нужны ли права, тип) берём
    с сервера, а не из запроса."""
    def keep(values, allowed, what):
        allowed = set(allowed)
        if any(v not in allowed for v in values):
            raise RuntimeError(f"{what}: этого нет в результатах последней проверки — обнови список и попробуй снова")

    a = dict(args)
    if name in ("leftovers_remove", "leftovers_delay"):
        known = {(i["kind"], i["path"]): i for src in ("uninstall", "force_remove")
                 for i in (_last(src) or {}).get("leftovers", [])}
        keep([(i.get("kind"), i.get("path")) for i in a.get("items", [])], known, "остаток программы")
        a["items"] = [known[(i["kind"], i["path"])] for i in a.get("items", [])]
    elif name == "shortcuts_remove":
        keep(a.get("paths", []), [b["path"] for b in (_last("shortcuts") or {}).get("broken", [])], "ярлык")
    elif name == "drvstore_remove":
        keep(a.get("oems", []), [p["oem"] for p in (_last("drvstore") or {}).get("old", [])], "пакет драйвера")
    elif name == "empty_remove":
        keep(a.get("paths", []), [f["path"] for f in (_last("empty") or {}).get("folders", [])], "пустая папка")
    elif name == "recycle":
        keep(a.get("paths", []), [f["path"] for f in (_last("disk_analyze") or {}).get("big", [])] +
             [p for g in (_last("dups") or {}).get("groups", []) for p in g["paths"]], "файл")
    elif name == "appx_remove":
        keep(a.get("fulls", []), [x["full"] for x in (_last("appx") or [])], "приложение")
    elif name == "firewall_set":
        ids = a.get("ids") or a.get("id")
        keep(ids if isinstance(ids, list) else [ids], [r["id"] for r in (_last("firewall") or {}).get("rules", [])], "правило брандмауэра")
    elif name == "firewall_remove":            # удалять — только правила, у которых проверка не нашла программу
        keep(a.get("ids") or [], [r["id"] for r in (_last("firewall") or {}).get("rules", []) if tweaks.ORPHAN_FLAG in r.get("flags", [])],
             "правило от удалённой программы")
    elif name == "ctx_set" and not str(a.get("id", "")).startswith("classic|"):
        keep([a.get("id")], [i["id"] for i in (_last("ctx") or {}).get("items", [])], "пункт меню")
    elif name == "startup_set":
        keep([a.get("id")], [i["id"] for i in (_last("startup") or {}).get("items", [])], "запись автозагрузки")
    elif name == "envpath_fix":
        keep([(x.get("scope"), x.get("entry")) for x in a.get("remove", [])],
             [(e["scope"], e["entry"]) for e in (_last("envpath") or {}).get("entries", []) if e.get("problem")], "запись PATH")
    elif name == "shred":
        if any(os.path.normpath(p) not in PICKED for p in a.get("paths", [])):
            raise RuntimeError("шредер уничтожает только то, что ты сам выбрал в окне выбора файла или папки")
    elif name == "quarantine":
        found = {f["path"] for j in list(jobs.values()) for f in (j.get("found") or [])}
        found |= {f["path"] for j in list(jobs.values()) for s in (j.get("steps") or []) for f in (s.get("files") or [])}
        found |= {f["path"] for i in (load_json(ULTRA_FILE, None) or {}).get("todo", []) for f in (i.get("files") or [])}
        keep([f.get("path") for f in a.get("files", [])], found, "файл для карантина")
    return a


def _task_fn(name, args):
    args = _only_found(name, args)
    run_el = deepscan.run_elevated
    prog = args.get("_prog") or (lambda s: None)
    path = args.get("path") or ""
    lazy = {
        # ---- очистка и место на диске
        "prepare": lambda: prepare(prog, args.get("_cancel") or (lambda: False), bool(args.get("trails"))),
        "junk_scan": lambda: pcclean.junk_scan(),
        "junk_clean": lambda: pcclean.junk_clean(list(args.get("ids", [])), run_el, prog,
                                                 {c["id"]: c.get("size", 0) for c in (_last("junk_scan") or {}).get("categories", [])}),
        "disk_analyze": lambda: pcclean.analyze(path or "C:\\", prog),
        "dups": lambda: pcclean.duplicates(path, int(args.get("min_mb", 1)) * 2 ** 20, prog),
        "empty": lambda: pcclean.empty_folders(path, prog),
        "empty_remove": lambda: pcclean.remove_empty(list(args.get("paths", []))),
        "recycle": lambda: dict(zip(("removed", "errors"), pcclean.to_recycle(list(args.get("paths", []))))),
        "shortcuts": pcclean.shortcuts_scan,
        "shortcuts_remove": lambda: pcclean.shortcuts_remove(list(args.get("paths", [])), run_el),
        "envpath": pcclean.path_scan,
        "envpath_fix": _with_rp("очистка PATH", lambda: pcclean.path_fix(list(args.get("remove", [])), run_el), args),
        "drvstore": pcclean.drivers_scan,
        "drvstore_remove": _with_rp("удаление старых драйверов", lambda: pcclean.drivers_remove(list(args.get("oems", [])), run_el), args),
        "shred": lambda: pcclean.shred(list(args.get("paths", [])), prog),
        "media": lambda: pcclean.media_type(path) or {},
        # ---- программы
        "programs": uninstall.programs,
        "uninstall": lambda: uninstall.uninstall(args["key"], prog, bool(args.get("elevated")), args.get("_cancel")),
        "leftovers_remove": _with_rp("удаление остатков программы", lambda: uninstall.remove_leftovers(list(args.get("items", [])), run_el), args),
        "force_remove": lambda: uninstall.force_remove(args["key"], run_el),
        "force_remove_many": lambda: uninstall.force_remove_many([str(k) for k in args.get("keys", [])][:50], run_el),
        "file_why": lambda: assistant.t_file_info(str(args.get("path", "")), True, {**config(), "ai_files": "meta"}),
        "leftovers_delay": lambda: uninstall.delete_on_reboot(list(args.get("items", [])), run_el),
        "appx": tweaks.appx_list,
        "appx_remove": lambda: tweaks.appx_remove(list(args.get("fulls", []))),
        "winget": lambda: _winget_list(),
        "upd_ignore": lambda: _upd_ignore(str(args.get("id", ""))),
        # ---- приватность и система
        "privacy": tweaks.privacy_status,
        "privacy_apply": _with_rp("настройки приватности", lambda: {"items": tweaks.privacy_apply(list(args.get("ids", [])), run_el)}, args),
        "privacy_revert": lambda: {"items": tweaks.privacy_revert(list(args.get("ids", [])), run_el)},
        "security": tweaks.security_status,
        "security_apply": _with_rp("настройки защиты Windows", lambda: {"items": tweaks.security_apply(list(args.get("ids", [])), run_el)}, args),
        "security_revert": lambda: {"items": tweaks.security_revert(list(args.get("ids", [])), run_el)},
        "ctx": tweaks.ctx_scan,
        "ctx_set": _with_rp("контекстное меню", lambda: {"ok": tweaks.ctx_set(args["id"], bool(args.get("enable")), run_el)}, args),
        "explorer_restart": lambda: {"ok": tweaks.restart_explorer()},
        "game": tweaks.game_status,
        "game_on": lambda: tweaks.game_on(list(args.get("opts", [])), run_el,
                                         lambda: system.mem_full() if system.memclean_installed() else system.mem_quick()),
        "game_off": lambda: tweaks.game_off(run_el),
        "firewall": tweaks.firewall_audit,
        "firewall_set": lambda: {"ok": tweaks.firewall_set(args.get("ids") or args["id"], bool(args.get("enable")), run_el)},
        "firewall_remove": lambda: tweaks.firewall_remove(args.get("ids") or [], run_el),
        "ext_open": lambda: __import__("browsers").open_extension(_find_ext(args)),
        "ai_delete": lambda: assistant.review_delete(str(args.get("job", "")), [str(x) for x in args.get("paths") or []][:200],
                                                     bool(args.get("permanent")), bool(args.get("admin")), run_el, bool(args.get("later"))),
        "startup": tweaks.startup_list,
        "startup_set": lambda: {"ok": tweaks.startup_set(args["id"], bool(args.get("enable")), run_el)},
        "boot_trace": lambda: tweaks.boot_trace(run_el),
        "restore": tweaks.restore_status,
        "restore_create": lambda: tweaks.restore_create(run_el),
        "restore_enable": lambda: tweaks.restore_enable(run_el),
        "trim": lambda: tweaks.trim_now(run_el),
        # ---- сбои и ошибки
        "diag": lambda: _diag(int(args.get("days", 30))),
        "runtimes": lambda: {"items": diag.runtimes()},
        "driver_disable": lambda: _driver_toggle(str(args.get("service", "")), True, run_el),
        "driver_restore": lambda: _driver_toggle(str(args.get("service", "")), False, run_el),
        "net_diag": lambda: __import__("netdiag").run(prog, speed=args.get("speed", True) is not False),
        "app_links": lambda: app_links(False),
        "app_links_create": lambda: app_links(True),
        "health_history": lambda: (__import__("health_history").snapshot(bool(args.get("force"))), __import__("health_history").view())[1],
        "crash_fix": lambda: __import__("fixhelp").crash_fix(str(args.get("app", "")), str(args.get("path", "")), system.installed_apps(),
                                                             (_last("winget") or {}).get("apps") or system.winget_upgrades()),
        "browsers": lambda: __import__("browsers").audit(),
        "fixplan": lambda: __import__("fixes").build(_task_wait, _last, load_json(ULTRA_FILE, None), prog),
        # ---- карантин
        "quarantine_list": lambda: {"items": yarascan.q_list()},
        "quarantine": lambda: _quarantine(list(args.get("files", []))),
        "q_restore": lambda: {"path": yarascan.q_restore(args["id"]), "items": yarascan.q_list()},
        "q_delete": lambda: {"ok": yarascan.q_delete(args["id"]), "items": yarascan.q_list()},
    }
    if name in lazy:
        return lazy[name]
    return {
        "autoruns": system.autoruns,
        "network": system.network,
        "drivers": system.drivers,
        "driver_updates": system.driver_updates,
        "health": system.health,
        "cleanup_scan": system.cleanup_scan,
        "cleanup_run": lambda: system.cleanup_run(args.get("ids", [])),
        "apps": system.installed_apps,
        "hosts": system.hosts_status,
        "hosts_set": lambda: _hosts_set(bool(args.get("enable"))),
        "watch": system.watch_status,
        "watch_set": lambda: system.watch_set(bool(args.get("enable"))),
        "sysfiles": lambda: deepscan.sysfiles_check(sfc=args.get("sfc", True), disk=bool(args.get("disk"))),
        "noise": lambda: metrics.METRICS.noise_report(),
        "hardware": lambda: _hardware(bool(args.get("refresh"))),
        "devices": lambda: __import__("devices").check(),
        "phone_status": lambda: __import__("phone").status(),
        "phone_last": lambda: __import__("phone").last() or {},
        "phone_install": lambda: __import__("phone").install(prog),
        "phone_scan": lambda: __import__("phone").scan(args.get("serial"), prog, config().get("virustotal_key")),
        "phone_open": lambda: __import__("phone").open_app(str(args.get("pkg", ""))),
        "phone_uninstall": lambda: __import__("phone").uninstall(str(args.get("pkg", ""))),
        "phone_a11y_off": lambda: __import__("phone").a11y_off(str(args.get("pkg", ""))),
        "device_fix": lambda: __import__("devices").fix(str(args.get("kind", ""))),
        "hwcheck": lambda: hwcheck.check(metrics.METRICS.snapshot() if metrics else None, load_json(os.path.join(DATA, "diag.json"), None)),
        "mem_quick": system.mem_quick,
        "mem_full": system.mem_full,
        "memclean_set": lambda: _memclean_set(bool(args.get("enable"))),
        "changes": lambda: journal_view(),
        "change_undo": lambda: journal_undo(str(args.get("id", "")), run_el),
        "sensors_set": lambda: _sensors_set(bool(args.get("enable"))),
    }[name]


def _winget_list():
    """Устаревшие программы; версии, которые ScanHub или человек решили не ставить, помечены ignored (окно прячет их в «Скрытые»)."""
    import updates
    apps = system.winget_upgrades()
    for a in apps or []:
        if updates.ignored(a):
            a["ignored"] = (updates.ignore_list().get(a["id"]) or {}).get("why") or "ты попросил не предлагать"
    return {"apps": apps}


def _upd_ignore(pid):
    """«Больше не предлагать» / «Вернуть»: только для программы из последнего списка winget."""
    import updates
    a = next((x for x in (_last("winget") or {}).get("apps") or [] if x["id"] == pid), None)
    if not a:
        raise RuntimeError("этой программы нет в списке — нажми «Проверить снова»")
    d = updates.ignore_list()
    if updates.ignored(a):
        d.pop(pid, None)
        json.dump(d, open(updates.IGNORE, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        a.pop("ignored", None)
    else:
        updates.ignore_add(pid, a["available"], "ты попросил не предлагать это обновление")
        a["ignored"] = "ты попросил не предлагать это обновление"
    return {"apps": (_last("winget") or {}).get("apps")}


def _find_ext(a):
    """Открыть можно только расширение из последней проверки браузеров."""
    for e in (_last("browsers") or {}).get("extensions", []):
        if e.get("browser") == a.get("browser") and e.get("id") == a.get("id") and (e.get("profile_dir") or "") == (a.get("profile_dir") or ""):
            return e
    raise RuntimeError("этого расширения нет в последней проверке — нажми «Проверить снова»")


def _driver_toggle(service, disable, run_el):
    """Отключить/вернуть только тот драйвер, который проверка нашла уязвимым (LOLDrivers), — не любую службу."""
    if not re.fullmatch(r"[\w.\-]{1,64}", service):
        raise RuntimeError("неверное имя службы")
    if disable:
        hits = intel.check_drivers(lambda s: None, update=False)["hits"]
        if not any((h.get("service") or "").lower() == service.lower() for h in hits):
            raise RuntimeError("этот драйвер не найден среди уязвимых — отключать его ScanHub не будет")
        return tweaks.driver_disable(service, run_el)
    return tweaks.driver_restore(service, run_el)


_LIVE = {}


def _live_activity(job):
    """Доказательство, что проверка не зависла: когда журнал последний раз пополнялся и что делает процесс сканера
    (процессор, сколько прочитано с диска). Процесс psutil держим между запросами — иначе загрузку процессора не посчитать."""
    n, t = len(job.get("lines") or []), time.time()
    last = _LIVE.setdefault(("lines", job["id"]), [n, t])
    if n != last[0]:
        last[:] = [n, t]
    out = {"quiet_s": round(t - last[1])}
    pid = job.get("pid")
    if pid and metrics:
        try:
            import psutil
            pr = _LIVE.get(("proc", pid))
            if not pr:
                pr = _LIVE[("proc", pid)] = psutil.Process(pid)
                pr.cpu_percent(None)
            kids = pr.children(recursive=True)
            procs = [pr] + kids
            cpu = 0.0
            for q in procs:
                key = ("proc", q.pid)
                if key not in _LIVE:
                    _LIVE[key] = q
                    q.cpu_percent(None)
                cpu += _LIVE[key].cpu_percent(None)
            busy = max(procs, key=lambda q: q.memory_info().rss)      # сам сканер обычно самый «тяжёлый» из дерева процессов
            io = sum((q.io_counters().read_bytes for q in procs), 0)
            out.update(name=busy.name(), cpu=round(cpu / (psutil.cpu_count() or 1), 1), read=io,
                       mem=sum(q.memory_info().rss for q in procs), since=pr.create_time())
        except Exception:
            pass
    if len(_LIVE) > 200:
        _LIVE.clear()
    return out


def _diag(days):
    r = diag.analyze(max(1, min(days, 365)))
    try:
        import appinfo
        appinfo.annotate(r)                       # «что это за программа» у вылетов, зависаний и утечек
    except Exception as e:
        report.record("appinfo", e)
    save_json(os.path.join(DATA, "diag.json"), r)
    return r


def _quarantine(files):
    done, errors = [], []
    for f in files:
        try:
            done.append(yarascan.quarantine(f["path"], f.get("name", ""), f.get("engine", "")))
        except PermissionError:
            errors.append(f"{os.path.basename(f['path'])}: нет доступа (файл используется или нужен администратор)")
        except Exception as e:
            errors.append(f"{os.path.basename(f['path'])}: {e}")
    return {"moved": len(done), "errors": errors, "items": yarascan.q_list()}



# ---------------------------------------------------------------- журнал изменений: что ScanHub поменял и как вернуть

CHANGES_FILE = os.path.join(DATA, "changes.json")
_changes_lock = threading.Lock()
# задача → (заголовок, как отменить: (обратная задача, её аргументы, список, по которому сервер проверяет id) | особая отмена | None)
CHANGE_TASKS = {
    "privacy_apply": "Приватность: выключено", "privacy_revert": "Приватность: возвращено как было",
    "security_apply": "Защита Windows: включено", "security_revert": "Защита Windows: возвращено как было",
    "ctx_set": "Меню правой кнопки", "game_on": "Игровой режим включён", "game_off": "Игровой режим выключен",
    "firewall_set": "Брандмауэр", "firewall_remove": "Брандмауэр: удалены правила от удалённых программ", "startup_set": "Автозагрузка", "driver_disable": "Отключён уязвимый драйвер",
    "driver_restore": "Драйвер включён обратно", "hosts_set": "Блокировка майнинг-сайтов (файл hosts)",
    "watch_set": "Сторож (проверка раз в 15 минут)", "memclean_set": "Полная очистка памяти", "sensors_set": "Датчики Lenovo",
    "device_fix": "Устройства: настройка Windows",
    "phone_uninstall": "Телефон: удалено приложение", "phone_a11y_off": "Телефон: снят доступ к спец. возможностям",
    "envpath_fix": "PATH: убраны лишние записи", "shortcuts_remove": "Удалены битые ярлыки",
    "force_remove": "Удалена запись программы из списка установленных", "force_remove_many": "Удалены записи удалённых программ",
    "uninstall": "Удалена программа", "leftovers_remove": "Удалены остатки программы", "leftovers_delay": "Остатки удалятся при перезагрузке",
    "appx_remove": "Удалены встроенные приложения Windows", "junk_clean": "Очистка мусора и кэшей", "cleanup_run": "Очистка",
    "empty_remove": "Удалены пустые папки", "recycle": "Файлы перемещены в Корзину", "ai_delete": "Удалено по проверке помощника", "drvstore_remove": "Удалены старые драйверы",
    "shred": "Файлы уничтожены шредером", "restore_enable": "Включена защита системы", "restore_create": "Создана точка восстановления",
    "quarantine": "Файлы перемещены в карантин", "q_restore": "Файл возвращён из карантина", "q_delete": "Файл удалён из карантина навсегда",
    "app_links_create": "Созданы ярлыки ScanHub",
}
_flip = lambda a: not a.get("enable")
UNDO = {
    "privacy_apply": ("privacy_revert", lambda a, r: {"ids": a.get("ids", [])}, None),
    "security_apply": ("security_revert", lambda a, r: {"ids": a.get("ids", [])}, None),
    "ctx_set": ("ctx_set", lambda a, r: {"id": a.get("id"), "enable": _flip(a)}, "ctx"),
    "game_on": ("game_off", lambda a, r: {}, None),
    "firewall_set": ("firewall_set", lambda a, r: {**({"ids": a["ids"]} if a.get("ids") else {"id": a.get("id")}), "enable": _flip(a)}, "firewall"),
    "startup_set": ("startup_set", lambda a, r: {"id": a.get("id"), "enable": _flip(a)}, "startup"),
    "driver_disable": ("driver_restore", lambda a, r: {"service": a.get("service")}, None),
    "hosts_set": ("hosts_set", lambda a, r: {"enable": _flip(a)}, None),
    "watch_set": ("watch_set", lambda a, r: {"enable": _flip(a)}, None),
    "memclean_set": ("memclean_set", lambda a, r: {"enable": _flip(a)}, None),
    "sensors_set": ("sensors_set", lambda a, r: {"enable": _flip(a)}, None),
    "envpath_fix": ("@path", None, None), "shortcuts_remove": ("@shortcuts", None, None),
    "force_remove": ("@reg", None, None), "force_remove_many": ("@reg", None, None), "leftovers_remove": ("@reg", None, None),
}
HOW = {
    "uninstall": "Вернуть: поставь программу заново с её официального сайта.",
    "appx_remove": "Вернуть: найди приложение в Microsoft Store и установи снова.",
    "recycle": "Вернуть: открой Корзину Windows → правой кнопкой по файлу → «Восстановить».",
    "ai_delete": "Если удалялось в Корзину — открой Корзину Windows → правой кнопкой по файлу → «Восстановить». Удалённое навсегда вернуть нельзя.",
    "quarantine": "Вернуть: «Проверка на вирусы → Карантин» → «Вернуть».",
    "restore_create": "", "restore_enable": "Выключить: «Приватность и защита → Точки восстановления».", "app_links_create": "",
    "q_restore": "", "game_off": "", "driver_restore": "", "privacy_revert": "", "security_revert": "",
    "phone_uninstall": "Вернуть: поставь приложение заново из магазина на телефоне.",
    "phone_a11y_off": "Вернуть: на телефоне «Настройки → Спец. возможности» → приложение → включить.",
    "device_fix": "Вернуть: «Параметры Windows → Специальные возможности → Клавиатура» (залипание, фильтрация), «Bluetooth и устройства → Мышь» "
                  "(повышенная точность) или «Конфиденциальность → Микрофон/Камера».",
}
IRREVERSIBLE = "Это не отменяется: удалённое стёрто."


def _change_keys(name, a):
    """Что именно изменилось — по этим ключам новое изменение «перекрывает» старое (отменять старое уже нельзя)."""
    base = {"privacy_apply": "privacy", "privacy_revert": "privacy", "security_apply": "security", "security_revert": "security"}.get(name)
    if base:
        return [f"{base}:{i}" for i in a.get("ids", [])]
    if name in ("ctx_set", "startup_set"):
        return [f"{name}:{a.get('id')}"]
    if name == "firewall_set":
        return [f"fw:{i}" for i in (a.get("ids") or [a.get("id")])]
    if name in ("game_on", "game_off"):
        return ["game"]
    if name in ("driver_disable", "driver_restore"):
        return [f"drv:{a.get('service')}"]
    if name in ("hosts_set", "watch_set", "memclean_set", "sensors_set"):
        return [name]
    return []


def _change_items(name, a, r):
    """Человеческие названия того, что изменилось (для списка)."""
    def find(src, ids, *fields):
        rows = _last(src) or {}
        rows = rows if isinstance(rows, list) else next((v for v in rows.values() if isinstance(v, list)), [])
        out = []
        for i in ids:
            row = next((x for x in rows if isinstance(x, dict) and x.get("id") == i), None)
            out.append(next((row.get(f) for f in fields if row and row.get(f)), str(i)))
        return out
    try:
        if name in ("privacy_apply", "privacy_revert"):
            t = {x["id"]: x["title"] for x in tweaks.PRIVACY}
            return [t.get(i, i) for i in a.get("ids", [])]
        if name in ("security_apply", "security_revert"):
            t = {x["id"]: x["title"] for x in tweaks.SECURITY}
            return [t.get(i, i) for i in a.get("ids", [])]
        if name == "ctx_set":
            return [("включён: " if a.get("enable") else "скрыт: ") + find("ctx", [a.get("id")], "name", "title", "text")[0]]
        if name == "startup_set":
            return [("включено: " if a.get("enable") else "выключено: ") + find("startup", [a.get("id")], "name", "title")[0]]
        if name == "firewall_set":
            return [("включено: " if a.get("enable") else "выключено: ") + x for x in find("firewall", a.get("ids") or [a.get("id")], "name", "title", "display")]
        if name in ("driver_disable", "driver_restore"):
            return [str(a.get("service"))]
        if name in ("phone_uninstall", "phone_a11y_off"):
            return [str(a.get("pkg", ""))]
        if name == "device_fix":
            return [{"filterkeys": "выключена фильтрация ввода", "stickykeys": "выключено залипание клавиш", "mouseaccel": "выключена повышенная точность указателя",
                     "privacy_microphone": "программам разрешён микрофон", "privacy_webcam": "программам разрешена камера"}.get(a.get("kind"), str(a.get("kind")))]
        if name in ("hosts_set", "watch_set", "memclean_set", "sensors_set"):
            return ["включено" if a.get("enable") else "выключено"]
        if name == "envpath_fix":
            return [x.get("entry", "") for x in a.get("remove", [])]
        if name in ("shortcuts_remove", "empty_remove", "recycle", "shred"):
            return [os.path.basename(p) or p for p in a.get("paths", [])]
        if name == "force_remove_many":
            return list((r or {}).get("names") or [])
        if name in ("force_remove", "uninstall"):
            return [(r or {}).get("name") or str(a.get("key", ""))]
        if name == "appx_remove":
            return [f.split("_")[0] for f in a.get("fulls", [])]
        if name == "junk_clean":
            return find("junk_scan", a.get("ids", []), "title", "name")
        if name in ("leftovers_remove", "leftovers_delay"):
            return [i.get("path", "") for i in a.get("items", [])]
        if name in ("quarantine",):
            return [os.path.basename(f.get("path", "")) for f in a.get("files", [])]
        if name == "ai_delete":
            return [d.get("path", "") for d in (r or {}).get("done", [])]
    except Exception:
        pass
    return []


def journal_record(name, args, result, started):
    """Записать успешное изменение. Резервные копии, сделанные задачей, запоминаются для отмены."""
    if name not in CHANGE_TASKS:
        return
    t0 = time.mktime(time.strptime(started[:19], "%Y-%m-%dT%H:%M:%S")) - 2 if started else time.time() - 600
    backups = [p for p in glob.glob(os.path.join(DATA, "backups", "**", "*"), recursive=True)
               if os.path.isfile(p) and os.path.getmtime(p) >= t0]
    undo = UNDO.get(name)
    e = {"id": uuid.uuid4().hex[:10], "t": now(), "task": name, "title": CHANGE_TASKS[name], "items": _change_items(name, args, result)[:40],
         "keys": _change_keys(name, args), "args": args, "backups": backups[:60],
         "result": {k: v for k, v in (result or {}).items() if k in ("backup", "names", "removed", "freed")} if isinstance(result, dict) else {},
         "undo": bool(undo), "how": HOW.get(name, "" if undo else IRREVERSIBLE)}
    if name == "shortcuts_remove" and not (result or {}).get("backup"):
        e["undo"] = False
    if name == "leftovers_remove":                 # вернуть можно только записи реестра: папки уже удалены
        e["undo"] = any(p.lower().endswith(".reg") for p in backups)
        e["how"] = "«Отменить» вернёт удалённые записи реестра; удалённые папки не вернутся." if e["undo"] else IRREVERSIBLE
    with _changes_lock:
        rows = load_json(CHANGES_FILE, [])
        for old in rows:                           # то же самое поменяли ещё раз — старую отмену больше не предлагаем
            if e["keys"] and set(old.get("keys") or []) & set(e["keys"]) and not old.get("undone"):
                old["superseded"] = True
        rows.insert(0, e)
        save_json(CHANGES_FILE, rows[:400])


def _reg_title(path):
    """Название программы или раздел реестра из резервной копии .reg (она в UTF-16)."""
    try:
        text = open(path, encoding="utf-16", errors="replace").read()
    except (OSError, UnicodeError):
        return os.path.basename(path)
    m = re.search(r'"DisplayName"="([^"]+)"', text) or re.search(r"^\[([^\]]+)\]", text, re.M)
    return m.group(1) if m else os.path.basename(path)


def journal_backfill():
    """Первый запуск журнала: изменения, сделанные раньше, восстанавливаются по резервным копиям в data\backups."""
    bak = os.path.join(DATA, "backups")
    stamp_t = lambda f: (lambda m: f"{m[1]}-{m[2]}-{m[3]}T{m[4]}:{m[5]}:{m[6]}" if m else now())(
        re.search(r"(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)(\d\d)", os.path.basename(f)))
    rows = []
    add = lambda task, t, items, backups, undo, how="", args=None, keys=None: rows.append(
        {"id": uuid.uuid4().hex[:10], "t": t, "task": task, "title": CHANGE_TASKS.get(task, task), "items": items[:40], "keys": keys or [],
         "args": args or {}, "backups": backups, "result": {}, "undo": undo, "how": how, "old": True})
    tw = load_json(os.path.join(bak, "tweaks.json"), {})
    t_tw = datetime.fromtimestamp(os.path.getmtime(os.path.join(bak, "tweaks.json"))).isoformat(timespec="seconds") if tw else now()
    for prefix, task in (("privacy", "privacy_apply"), ("security", "security_apply")):
        ids = [k.split(":", 1)[1] for k in tw if k.startswith(prefix + ":")]
        if ids:
            names = {x["id"]: x["title"] for x in (tweaks.PRIVACY if prefix == "privacy" else tweaks.SECURITY)}
            add(task, t_tw, [names.get(i, i) for i in ids], [], True, args={"ids": ids}, keys=[f"{prefix}:{i}" for i in ids])
    for k in tw:
        if k.startswith("drv:"):
            add("driver_disable", t_tw, [k[4:]], [], True, args={"service": k[4:]}, keys=[k])
    for f in sorted(glob.glob(os.path.join(bak, "uninstall-entry-*.reg"))):
        add("force_remove", stamp_t(f), [_reg_title(f)], [f], True)
    for f in sorted(glob.glob(os.path.join(bak, "reg-*.reg"))):
        add("leftovers_remove", stamp_t(f), [_reg_title(f)], [f], True, "«Отменить» вернёт удалённые записи реестра; удалённые папки не вернутся.")
    for f in sorted(glob.glob(os.path.join(bak, "path-*.json"))):
        add("envpath_fix", stamp_t(f), ["прежнее значение PATH (" + ("для тебя" if "-user-" in f else "для всех") + ")"], [f], True)
    for d in sorted(glob.glob(os.path.join(bak, "shortcuts", "*"))):
        names = os.listdir(d) if os.path.isdir(d) else []
        if names:
            add("shortcuts_remove", stamp_t(d + "-000000") if not re.search(r"\d{6}$", d) else stamp_t(d), names, [], False,
                f"Копии ярлыков лежат в {d} — перетащи нужный обратно на рабочий стол или в меню «Пуск».")
    rows.sort(key=lambda r: r["t"], reverse=True)
    return rows


def journal_view():
    with _changes_lock:
        if not os.path.exists(CHANGES_FILE):
            try:
                save_json(CHANGES_FILE, journal_backfill())
            except Exception as e:
                report.record("журнал изменений: прошлые изменения", e)
    rows = load_json(CHANGES_FILE, [])
    return {"items": [{k: v for k, v in r.items() if k not in ("args", "backups", "keys")} for r in rows]}


def journal_undo(cid, run_el):
    """Отменить изменение из журнала. Что и как отменять, сервер берёт из своей записи, а не из запроса окна."""
    with _changes_lock:
        rows = load_json(CHANGES_FILE, [])
    e = next((r for r in rows if r.get("id") == cid), None)
    if not e or not e.get("undo") or e.get("undone") or e.get("superseded"):
        raise RuntimeError("это изменение уже нельзя отменить из журнала")
    kind, mk, scan = UNDO[e["task"]]
    a = e.get("args") or {}
    if kind == "@reg":                              # записи программ: импорт сохранённой копии реестра
        regs = [p for p in e.get("backups", []) if p.lower().endswith(".reg") and os.path.exists(p)]
        if not regs:
            raise RuntimeError("копия записи реестра не найдена")
        res = run_el([{"type": "run", "cmd": ["reg", "import", p], "timeout": 60} for p in regs])
        if not all(x.get("ok") for x in res):
            raise RuntimeError("не всё вернулось — окно UAC отменено или файл повреждён")
        out = {"restored": len(regs)}
    elif kind == "@path":                           # PATH: прежнее значение из резервной копии
        restored = 0
        # возвращаем только удалённые записи — то, что программы добавили в PATH позже, не трогаем
        norm = lambda x: os.path.normcase(os.path.expandvars(x.strip()).rstrip("\\"))
        for p in [p for p in e.get("backups", []) if os.path.basename(p).startswith("path-") and os.path.exists(p)]:
            b = load_json(p, {})
            scope = b.get("scope")
            hive, key = (winreg.HKEY_CURRENT_USER, pcclean.ENV_USER) if scope == "user" else (winreg.HKEY_LOCAL_MACHINE, pcclean.ENV_SYS)
            cur, _typ = pcclean._read_path(hive, key)
            have = {norm(x) for x in cur.split(";") if x.strip()}
            back = [x for x in (b.get("value") or "").split(";") if x.strip() and norm(x) not in have]
            if not back:
                continue
            new = ";".join([x for x in cur.split(";") if x.strip()] + back)
            if scope == "user":
                with winreg.OpenKey(hive, key, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.SetValueEx(k, "Path", 0, winreg.REG_EXPAND_SZ, new)
            else:
                r = run_el([{"type": "reg_set", "root": "HKLM", "key": key, "name": "Path", "kind": "expand_sz", "value": new}])[0]
                if not r.get("ok"):
                    raise RuntimeError(r.get("error") or "окно UAC отменено")
            restored += len(back)
        if not restored and not any(os.path.basename(p).startswith("path-") for p in e.get("backups", [])):
            raise RuntimeError("резервная копия PATH не найдена")
        pcclean._broadcast_env()
        out = {"restored": restored}
    elif kind == "@shortcuts":                      # ярлыки: копии лежат в data\backups\shortcuts\<время>
        bak = (e.get("result") or {}).get("backup") or ""
        mine, admin = [], []
        for p in a.get("paths", []):
            src = os.path.join(bak, os.path.basename(p))
            if os.path.exists(src) and not os.path.exists(p):
                (mine if p.lower().startswith(os.path.expanduser("~").lower()) else admin).append((src, p))
        for src, dst in mine:
            shutil.copy2(src, dst)
        if admin:
            run_el([{"type": "copy", "src": s_, "dst": d} for s_, d in admin])
        out = {"restored": len(mine) + len(admin)}
    else:
        if scan:                                    # сервер сверяет id со своим последним списком — обновим его
            TASKS[scan] = {"name": scan, "status": "done", "result": _task_fn(scan, {})(), "finished": now()}
        out = _task_fn(kind, {**mk(a, e.get("result")), "_prog": lambda s: None, "_cancel": lambda: False})()
    with _changes_lock:
        rows = load_json(CHANGES_FILE, [])
        for r in rows:
            if r.get("id") == cid:
                r["undone"] = now()
        save_json(CHANGES_FILE, rows)
    return {"ok": True, "result": out}


def admin_console(what):
    """Восстановление системных файлов или очистка хранилища компонентов — в видимом окне администратора (UAC)."""
    hint = ("echo. & echo DISM не нашёл исправных файлов, код 0x800f0915 или 0x800f081f. На тестовых сборках Windows Insider так бывает: "
            "у Microsoft нет файлов именно для этой сборки. Ничего не испортилось. Попробуй в ScanHub "
            "«Очистить старые версии компонентов» — или дождись следующей сборки Windows, она заменит хранилище целиком.")
    line = ("echo Восстановление системных файлов: сначала DISM, затем SFC. Не закрывай окно. & "
            "DISM /Online /Cleanup-Image /RestoreHealth & (if errorlevel 1 (" + hint + ")) & "
            "echo. & echo Теперь SFC проверит и починит системные файлы… & sfc /scannow & "
            "echo. & echo Готово. Перезагрузи компьютер.") if what == "sfc_repair" else \
        ("echo Очистка хранилища компонентов: Windows удалит старые версии компонентов, которые уже заменены обновлениями. & "
         "echo Это безопасно и освобождает место; минус — эти обновления нельзя будет удалить. 5–20 минут, не закрывай окно. & echo. & "
         "DISM /Online /Cleanup-Image /StartComponentCleanup & echo. & "
         "echo Перепроверяю хранилище (ещё 5–15 минут)… & DISM /Online /Cleanup-Image /ScanHealth & echo. & "
         "echo Готово. Если выше «Хранилище компонентов подлежит восстановлению» — повреждение в версии, которая ещё используется; "
         "её починит следующая сборка Windows.")
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    "Start-Process cmd.exe -Verb RunAs -ArgumentList ('/k chcp 65001 >nul & ' + $env:SH_LINE)"],
                   env={**os.environ, "SH_LINE": line}, creationflags=NO_WINDOW)


# ---------------------------------------------------------------- «Сделай сам»: действия ИИ-агента
# Агент (или модель по API) вызывает только действия из плана, который человек одобрил кнопкой. Здесь они идут через те же
# задачи, что и кнопки окна: с проверкой «только найденное ScanHub», окном UAC, точкой отката и записью в журнал изменений.

def _wait_task(name, args, timeout=900):
    t = start_task(name, args)
    t0 = time.time()
    while t.get("status") == "running" and time.time() - t0 < timeout:
        time.sleep(1)
        t = TASKS.get(name) or t
    if t.get("status") == "error":
        return {"ok": False, "ошибка": t.get("error")}
    if t.get("status") == "running":
        return {"ok": None, "итог": "ещё выполняется — ход видно в окне ScanHub"}
    res = json.dumps(t.get("result"), ensure_ascii=False, default=str)
    return {"ok": True, "итог": res[:1500]}


def agent_action(action, arg):
    if action == "update_program":
        try:
            start_updates([arg])
        except RuntimeError as e:
            return {"ok": False, "ошибка": str(e)}
        return {"ok": True, "итог": "обновление запущено: ScanHub скачает установщик, проверит его на вирусы и поставит. "
                                    "Ход — «Программы → Обновления программ»."}
    if action == "disable_driver":
        return _wait_task("driver_disable", {"service": arg})
    if action == "quarantine":
        return _wait_task("quarantine", {"files": [{"path": arg, "name": "по решению помощника", "engine": "помощник"}]})
    if action == "startup_off":
        TASKS["startup"] = {"name": "startup", "status": "done", "result": tweaks.startup_list(), "finished": now()}
        items = TASKS["startup"]["result"].get("items", [])
        it = next((i for i in items if i["name"].lower() == arg.lower()), None) or \
            next((i for i in items if arg.lower() in i["name"].lower()), None)
        if not it:
            return {"ok": False, "ошибка": f"в автозагрузке нет записи «{arg}»"}
        return _wait_task("startup_set", {"id": it["id"], "enable": False})
    if action == "security_on":
        return _wait_task("security_apply", {"ids": [arg]})
    if action == "restore_on":
        return _wait_task("restore_enable", {})
    if action == "free_ram":
        return _wait_task("mem_quick", {})
    if action == "sfc":
        admin_console("sfc_repair")
        return {"ok": True, "итог": "открыто окно администратора с восстановлением системных файлов: 10–30 минут, потом перезагрузка. "
                                    "Человеку нужно подтвердить UAC и дождаться конца."}
    if action == "wu_drivers":
        os.startfile("ms-settings:windowsupdate-optionalupdates")
        return {"ok": True, "итог": "открыт Windows Update → необязательные обновления (драйверы) — выбрать и установить там"}
    return {"ok": False, "ошибка": "неизвестное действие"}


def start_task(name, args):
    if not system:
        raise RuntimeError("нужен пакет psutil: pip install psutil")
    t = TASKS.get(name)
    if t and t["status"] == "running":
        return t
    t = TASKS[name] = {"name": name, "status": "running", "started": now(), "result": t["result"] if t else None,
                       "error": None, "progress": None, "args": {k: v for k, v in args.items() if not k.startswith("_")}}
    args = {**args, "_prog": lambda s: t.__setitem__("progress", s), "_cancel": lambda: bool(t.get("cancel"))}
    try:
        fn = _task_fn(name, args)
    except KeyError:
        TASKS.pop(name, None)
        raise RuntimeError(f"неизвестная задача {name}")
    except Exception as e:                      # отказ проверки аргументов — задача не начинается
        t.update(status="error", error=str(e), finished=now())
        return t

    def work():
        try:
            t["result"] = fn()
            t["status"] = "done"
            try:
                journal_record(name, t["args"], t["result"], t["started"])
            except Exception as e:
                report.record("журнал изменений", e)
        except PermissionError as e:
            t["error"] = str(e) if "UAC" in str(e) else f"нет доступа: {e}"
            t["status"] = "error"
        except Exception as e:
            t["error"] = str(e)
            t["status"] = "error"
            if not isinstance(e, RuntimeError):            # RuntimeError — понятные сообщения для человека, остальное — ошибки кода
                report.record(f"задача {name}", e)
        t["progress"] = None
        t["finished"] = now()
    threading.Thread(target=work, daemon=True).start()
    return t


def start_deep(skip=None):
    """Глубокая проверка всеми сканерами по очереди. skip — {id шага: почему пропущен}."""
    running = next((j for j in list(jobs.values()) if j["tool"] == "deep" and j["status"] == "running"), None)
    if running:
        return running
    jid = uuid.uuid4().hex[:10]
    job = {"id": jid, "tool": "deep", "tool_name": "Глубокая проверка", "mode": "deep", "mode_label": "все сканеры",
           "target": None, "cmd": ["ScanHub", "глубокая проверка"], "started": now(), "finished": None,
           "status": "running", "code": None, "verdict": None, "lines": [], "steps": [], "batch": None, "gui": False,
           "log": os.path.join(LOGS, f"{jid}.log")}
    jobs[jid] = job
    ctx = {"manifest": manifest, "state": state, "exe_path": exe_path, "config": config,
           "metrics": metrics.METRICS if metrics else None, "skip": skip, "install": _install_wait}

    def work():
        try:
            code, v = deepscan.DeepScan(job, ctx).run()
        except Exception as e:
            job["lines"].append(f"[ScanHub] ошибка: {e}")
            code, v = 3, ["error", "Ошибка"]
        job.update(code=code, verdict=v, status="stopped" if job.get("stop") else "done", finished=now())
        finish_job(job)
    threading.Thread(target=work, daemon=True).start()
    return job


ULTRA_FILE = os.path.join(DATA, "ultra.json")


def _task_wait(name, args):
    t = start_task(name, args)
    while t["status"] == "running":
        time.sleep(1)
    return t


def _job_wait(tid, mode):
    job = start_job(tid, mode, None)
    job["parent"] = "ultra"          # окно не показывает отдельные уведомления о шагах ультра проверки
    return job


def _deep_wait(skip):
    job = start_deep(skip)
    job["parent"] = "ultra"
    return job


# «Подготовить ScanHub»: всё, без чего проверка файла и глубокая проверка неполные. Один раз, ~1 ГБ.
PREPARE = [("clamav", "антивирус ClamAV"), ("atomscan", "ИИ-сканер Atomdrift"), ("hollowshunter", "проверку процессов HollowsHunter"),
           ("rootcerts", "Sigcheck для проверки сертификатов"), ("minersearch", "поиск майнеров MinerSearch")]
# списки угроз, которые проверки качают сами при первом запуске, — подготовка берёт их заранее
PREPARE_INTEL = [("update_loldrivers", "база уязвимых драйверов (LOLDrivers)"), ("update_fmhy", "списки опасных сайтов (FMHY)"),
                 ("update_malext", "база вредоносных расширений браузеров")]


def prepare(prog=lambda s: None, cancel=lambda: False, trails=False):
    """Поставить недостающие рекомендуемые сканеры и скачать их базы. Уже готовое пропускается — можно нажимать повторно.
    trails — человек согласился с лицензией баз Maltrail (мастер первого запуска): скачать и их."""
    done, errors = [], []
    step, total = [0], len(PREPARE) + 4
    _prog = prog

    def prog(text):                                     # «37% · …» — окно рисует полосу и сколько осталось
        sub = re.search(r"(\d{1,3})%", str(text))
        frac = (step[0] + (int(sub.group(1)) / 100 if sub else 0)) / total
        _prog(f"{min(99, int(frac * 100))}% · {text}")

    def wait_job(job, label):
        while job["status"] == "running":
            if cancel():
                stop_job(job["id"])
            last = next((l for l in reversed(job["lines"]) if l.strip()), "")
            prog(f"{label}: {job.get('progress') or last.strip()[:80]}")
            time.sleep(1)
        return job.get("verdict") or ["error", "ошибка"]

    for tid, label in PREPARE:
        step[0] += 1 if tid != PREPARE[0][0] else 0
        if cancel():
            break
        m = manifest(tid)
        if exe_path(m, tool_state(state(), tid)):
            continue
        prog(f"ставлю {label}…")
        install_async(tid)
        while tid in busy:
            prog(f"{label}: {busy[tid]}")
            time.sleep(1)
        ts = tool_state(state(), tid)
        if exe_path(m, ts):
            done.append(label)
        else:
            errors.append(f"{label}: {ts.get('blocked') or ts.get('error') or 'не установилось'}")
    # базы ClamAV
    step[0] = len(PREPARE)
    cm, cts = manifest("clamav"), tool_state(state(), "clamav")
    if not cancel() and exe_path(cm, cts) and not glob.glob(os.path.join(cts.get("path") or "", cm["needs_data"]["glob"])):
        v = wait_job(start_job("clamav", "update", None), "базы ClamAV (~250 МБ)")
        (done if v[0] != "error" else errors).append("базы ClamAV" if v[0] != "error" else f"базы ClamAV: {v[1]}")
    # правила YARA
    step[0] += 1
    if not cancel() and not yarascan.installed():
        v = wait_job(start_job("yara", "update", None), "правила YARA")
        (done if v[0] != "error" else errors).append("правила YARA" if v[0] != "error" else f"правила YARA: {v[1]}")
    # правила Atomdrift: скачать сейчас и разобрать заранее, чтобы первая проверка не ждала 1–3 минуты
    step[0] += 1
    ats = tool_state(state(), "atomscan")
    aexe = exe_path(manifest("atomscan"), ats)
    if not cancel() and aexe:
        try:
            prog("правила Atomdrift (~170 МБ)…")
            atomtraits.update(lambda s: prog(f"правила Atomdrift: {str(s).strip()[:80]}"), aexe)
            atomtraits.warm(aexe)
            done.append("правила Atomdrift")
        except Exception as e:
            errors.append(f"правила Atomdrift: {e}")
    # списки угроз и базы опасных адресов (Maltrail — только с согласия: лицензия разрешает их для своего компьютера)
    step[0] += 1
    try:
        import intel
        if trails:
            intel._save_meta("trails_accepted", datetime.now().isoformat(timespec="seconds"))
        jobs_i = list(PREPARE_INTEL) + ([("ensure_trails", "базы опасных адресов (Maltrail, ~12 МБ)")] if intel.trails_accepted() else [])
        for i, (fn, label) in enumerate(jobs_i):
            if cancel():
                break
            part = fn.replace("update_", "").replace("ensure_", "")
            if fn != "ensure_trails" and intel._fresh(part, 7 * 24 if part == "loldrivers" else 24):
                continue                                   # уже свежие — второй раз не качаем
            prog(f"{label}… ({i + 1} из {len(jobs_i)})")
            try:
                r = getattr(intel, fn)(lambda s: None)
                if r is False:
                    raise RuntimeError("не скачалось")
                done.append(label)
            except Exception as e:
                errors.append(f"{label}: {e}")
    except Exception as e:
        errors.append(f"списки угроз: {e}")
    return {"done": done, "errors": errors, "stopped": cancel()}


def _install_wait(tid):
    install_async(tid)
    while tid in busy:
        time.sleep(1)
    m = manifest(tid)
    return bool(exe_path(m, tool_state(state(), tid)))


def _set_task(name, result):
    TASKS[name] = {"name": name, "status": "done", "started": now(), "finished": now(), "result": result,
                   "error": None, "progress": None, "args": {}}


def _drop_tasks(names):
    for n in names:
        if TASKS.get(n, {}).get("status") != "running":
            TASKS.pop(n, None)


def _notify(title, text):
    if system:
        threading.Thread(target=system.toast, args=("ScanHub: " + title, text), daemon=True).start()


def _winget_upgrade():
    subprocess.Popen(["cmd", "/k", "winget", "upgrade", "--all"], creationflags=subprocess.CREATE_NEW_CONSOLE)


UPDATERS = {}         # id задачи -> updates.Updater (для «Пропустить» и «Остановить»)


def start_updates(ids=None, force=()):
    """Безопасное обновление программ: скачать → проверить → тихо поставить. ids=None — все устаревшие."""
    import updates
    running = next((j for j in list(jobs.values()) if j["tool"] == "updates" and j["status"] == "running"), None)
    if running:
        return running
    known = (_last("winget") or {}).get("apps")
    if known is None:
        known = system.winget_upgrades() or []
        _set_task("winget", {"apps": known})
    want = set(ids) if ids is not None else {a["id"] for a in known if not a.get("ignored")}
    apps = [a for a in known if a["id"] in want and not a.get("ghost")]   # только то, что winget сам показал устаревшим; удалённые — не ставим
    if not apps:
        raise RuntimeError("нечего обновлять — обнови список программ и выбери снова")
    jid = uuid.uuid4().hex[:10]
    job = {"id": jid, "tool": "updates", "tool_name": "Обновление программ", "mode": "updates", "mode_label": f"программ: {len(apps)}",
           "target": None, "cmd": ["ScanHub", "обновление программ"], "started": now(), "finished": None, "status": "running",
           "code": None, "verdict": None, "lines": [], "batch": None, "gui": False, "log": os.path.join(LOGS, f"{jid}.log"), "progress": None}
    jobs[jid] = job
    u = UPDATERS[jid] = updates.Updater(job, apps, {"config": config, "notify": _notify}, force)

    def work():
        try:
            code, v = u.run()
        except Exception as e:
            job["lines"].append(f"[ScanHub] ошибка: {e}")
            code, v = 3, ["error", "Ошибка"]
        job.update(code=code, verdict=v, status="stopped" if job.get("stop") else "done", finished=now(), progress=None)
        finish_job(job)
        UPDATERS.pop(jid, None)
        _drop_tasks(["winget"])                              # список устаревших программ пересчитается
        _notify("Обновление программ", v[1])
    threading.Thread(target=work, daemon=True).start()
    return job


def _alive_files(view):
    """Найденные файлы, которых уже нет на месте (убраны в карантин или удалены), из итогов убираем — иначе после
    перезагрузки окна кнопка «В карантин» появлялась снова. Пометка files_done — «файлы обезврежены»."""
    def fix(item):
        if item.get("files"):
            left = [f for f in item["files"] if os.path.isfile(f.get("path", ""))]
            if len(left) != len(item["files"]):
                item["files"] = left
                if not left:
                    item["files_done"] = True
    for i in view.get("todo") or []:
        fix(i)
    for s in view.get("steps") or []:
        for i in s.get("items") or []:
            fix(i)
        fix(s)
    if view.get("found"):
        view["found"] = [f for f in view["found"] if os.path.isfile(f.get("path", ""))]
    return view


def ultra_view(job):
    return {k: v for k, v in job.items() if k not in ("lines", "log", "cmd")}


def start_ultra(sel):
    """Ультра проверка: все проверки приложения подряд по выбранным пунктам."""
    if not ultra:
        raise RuntimeError("нужен пакет psutil: pip install psutil")
    running = next((j for j in list(jobs.values()) if j["tool"] == "ultra" and j["status"] == "running"), None)
    if running:
        return running
    jid = uuid.uuid4().hex[:10]
    job = {"id": jid, "tool": "ultra", "tool_name": "Ультра проверка", "mode": "ultra", "mode_label": "все проверки",
           "target": None, "cmd": ["ScanHub", "ультра проверка"], "started": now(), "finished": None,
           "status": "running", "code": None, "verdict": None, "lines": [], "steps": [], "batch": None, "gui": False,
           "log": os.path.join(LOGS, f"{jid}.log")}
    jobs[jid] = job
    ctx = {"task": _task_wait, "job": _job_wait, "deep": _deep_wait, "install": _install_wait, "tools": tools_view,
           "set_task": _set_task, "drop_tasks": _drop_tasks, "notify": _notify, "stop_job": stop_job,
           "metrics": lambda: metrics.METRICS.snapshot() if metrics else None,
           "save": lambda: save_json(ULTRA_FILE, ultra_view(job))}

    def work():
        u = ultra.Ultra(job, ctx, sel)
        try:
            code, v = u.run()
        except Exception as e:
            job["lines"].append(f"[ScanHub] ошибка: {e}")
            code, v = 3, ["error", "Ошибка"]
        job["mode_label"] = f"шагов: {len(job['steps'])}"
        job.update(code=code, verdict=v, status="stopped" if job.get("stop") else "done", finished=now())
        save_json(ULTRA_FILE, ultra_view(job))
        try:
            ultra_report.archive(ultra_view(job))           # для «что изменилось с прошлой проверки»
        except Exception as e:
            report.record("архив ультра проверки", e)
        finish_job(job)
        _notify(v[1], "Итоги и что стоит сделать — в разделе «Ультра проверка».")
        if "winget_upgrade" in u.after and not job.get("stop"):
            try:                                             # скачать → проверить на вирусы → тихо поставить
                start_updates(None)
            except Exception as e:
                job["lines"].append(f"[ScanHub] обновление программ не началось: {e}")
    threading.Thread(target=work, daemon=True).start()
    return job


# ---------------------------------------------------------------- HTTP

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if ctype.startswith("text/html"):
            # окно грузит только свои файлы и обращается только к своему серверу: чужой скрипт или картинку-«маячок» вставить нельзя
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                             "img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
                             "frame-ancestors 'none'")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def guard(self):
        # защита от DNS-rebinding и запросов с чужих сайтов
        if self.headers.get("Host") not in (f"{HOST}:{PORT}", f"localhost:{PORT}"):
            self.send(403, {"error": "bad host"})
            return False
        if self.path.startswith("/api/agent/"):
            return True                                # ключ ответа агента проверяется в самом обработчике
        if self.path.startswith("/api/") and self.path not in ("/api/hello", "/api/version") \
                and self.headers.get("X-Token") != TOKEN:
            self.send(403, {"error": "bad token"})
            return False
        return True

    def do_GET(self):
        try:
            return self._get()
        except (ConnectionError, BrokenPipeError):
            pass
        except Exception as e:
            report.record(f"GET {urllib.parse.urlparse(self.path).path}", e)
            try:
                self.send(500, {"error": f"ошибка ScanHub: {e}"})
            except Exception:
                pass

    def _get(self):
        global last_ping
        if not self.guard():
            return
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path in ("/", "/index.html"):
            html = open(UI_FILE, encoding="utf-8").read().replace("__TOKEN__", TOKEN).replace("__VERSION__", VERSION)
            return self.send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        if u.path in STATIC:
            data = open(os.path.join(ROOT, "ui", u.path.lstrip("/")), "rb").read()
            return self.send(200, data, STATIC[u.path])
        if u.path == "/api/hello":
            # window — открыто ли окно (опрашивает сервер последние 20 с); нужно запуску из меню «Проверить в ScanHub»
            return self.send(200, {"app": "scanhub", "version": VERSION, "window": time.time() - last_ping < 20})
        if u.path == "/api/ai/config":
            return self.send(200, assistant.cfg_view(config()))
        if u.path == "/api/setup":
            # мастер первого запуска: пройден ли, согласие на базы Maltrail, какие ключи уже есть
            import intel
            c = config()
            return self.send(200, {"done": bool(c.get("setup_done")), "trails": intel.trails_accepted(),
                                   "keys": {k: bool(c.get(k)) for k in ("virustotal_key", "filescan_key", "metadefender_key", "hybrid_key")}})
        if u.path == "/api/fps":
            import fps
            fps.S.setdefault("minimal", bool(config().get("fps_minimal", True)))
            fps.S.setdefault("corner", str(config().get("fps_corner") or "tl")[:2])
            return self.send(200, fps.view())
        if u.path == "/api/usage":
            return self.send(200, {"on": config().get("usage_ping")})
        if u.path == "/api/ai/job":
            j = assistant.view(q.get("id"))
            return self.send(200, j) if j else self.send(404, {"error": "нет такого запроса"})
        if u.path == "/api/version":
            return self.send(200, {"ui": ui_version()})
        if u.path == "/api/pending":                 # файл из меню «Проверить в ScanHub»
            last_ping = time.time()
            return self.send(200, take_pending())
        if u.path == "/api/self_update":
            return self.send(200, self_update(q.get("force") == "1"))
        if u.path == "/api/errors":                  # сколько ошибок ScanHub записано с запуска (окно предлагает отчёт)
            return self.send(200, dict(report.NEW))
        last_ping = time.time()
        if WATCHER:
            WATCHER.keep_alive()
        if u.path == "/api/tools":
            return self.send(200, {"tools": tools_view(), "last_check": state().get("last_check")})
        if u.path == "/api/job":
            j = jobs.get(q.get("id"))
            if not j:
                return self.send(404, {"error": "нет задачи"})
            since = int(q.get("since", 0))
            view = _alive_files(json.loads(json.dumps({k: v for k, v in j.copy().items() if k != "lines"}, default=str)))
            return self.send(200, {**view, "lines": j["lines"][since:], "total": len(j["lines"])})
        if u.path == "/api/jobs":
            return self.send(200, {"jobs": [{k: v for k, v in j.copy().items() if k != "lines"}
                                            for j in list(jobs.values()) if j["status"] == "running"]})
        if u.path == "/api/metrics":
            if not metrics:
                return self.send(500, {"error": "нужен пакет psutil: pip install psutil"})
            return self.send(200, metrics.METRICS.snapshot())
        if u.path == "/api/task":
            t = TASKS.get(q.get("name"))
            if not t and q.get("name") == "diag":          # последний разбор сбоев хранится на диске
                cached = load_json(os.path.join(DATA, "diag.json"), None)
                if cached:
                    if any("about" not in x for k in ("crashes", "hangs", "leaks") for x in cached.get(k) or []):    # разбор старой версии — дописываем
                        try:
                            import appinfo
                            save_json(os.path.join(DATA, "diag.json"), appinfo.annotate(cached))
                        except Exception as e:
                            report.record("appinfo", e)
                    t = {"name": "diag", "status": "done", "result": cached, "finished": cached.get("collected"), "error": None}
            return self.send(200, t or {"status": "none"})
        if u.path == "/api/ultra":
            j = next((j for j in list(jobs.values()) if j["tool"] == "ultra" and j["status"] == "running"), None)
            saved = None if j else load_json(ULTRA_FILE, None)
            if saved and saved.get("status") == "running":      # ScanHub закрыли посреди проверки — показываем, что успели
                saved.update(status="stopped", verdict=["error", "Прервана: ScanHub закрыли или перезапустили посреди проверки"])
                for st in saved.get("steps", []):
                    if st["status"] in ("running", "pending"):
                        st.update(status="skipped", verdict="skipped", label="не выполнено", progress=None)
            view = _alive_files(json.loads(json.dumps(ultra_view(j) if j else saved))) if (j or saved) else None
            if j:                                    # последние строки журнала — «Что сейчас происходит» на экране проверки
                deep = next((jobs.get(s.get("job")) for s in j["steps"] if s["id"] == "deep" and s["status"] == "running"), None)
                view["tail"] = (deep or j)["lines"][-40:]
                view["tail_of"] = "глубокая проверка" if deep else "ультра проверка"
                view["live"] = _live_activity(deep or j)
            if view and not j:
                try:
                    view["compare"] = ultra_report.compare(view)
                except Exception as e:
                    report.record("ультра: сравнение с прошлой проверкой", e)
            return self.send(200, {"plan": ultra.PLAN if ultra else [], "job": view})
        if u.path == "/api/alerts":
            if not WATCHER:
                return self.send(200, {"items": [], "on": False, "rules": []})
            return self.send(200, WATCHER.view(int(q.get("since", 0) or 0)))
        if u.path == "/api/disk":
            try:
                return self.send(200, pcclean.children_of(q.get("path", "")))
            except Exception as e:
                return self.send(400, {"error": str(e)})
        if u.path == "/api/self_update/progress":
            return self.send(200, dict(UPD_PROG))
        if u.path == "/api/replies":
            return self.send(200, report.replies_view())
        if u.path == "/api/history":
            return self.send(200, {"history": load_json(HISTORY_FILE, [])})
        if u.path == "/api/config":
            c = config()   # сами ключи наружу не отдаём
            return self.send(200, {"virustotal_key": bool(c["virustotal_key"]), "filescan_key": bool(c["filescan_key"]),
                                   "metadefender_key": bool(c["metadefender_key"]), "hybrid_key": bool(c["hybrid_key"]),
                                   "github_token": bool(c["github_token"]), "alerts_on": bool(c.get("alerts_on", True)),
                                   "check_every_hours": c["check_every_hours"], "vt_files": c["vt_files"], "fs_files": c["fs_files"],
                                   "smart_mb": c["smart_mb"], "folder_full": bool(c["folder_full"]), "ctx_menu": ctxmenu_on()})
        if u.path == "/api/log":
            h = next((x for x in load_json(HISTORY_FILE, []) if x["id"] == q.get("id")), None)
            if not h or not os.path.exists(h["log"]):
                return self.send(404, {"error": "лог не найден"})
            return self.send(200, {"text": open(h["log"], encoding="utf-8", errors="replace").read()})
        self.send(404, {"error": "not found"})

    def do_POST(self):
        global last_ping
        if not self.guard():
            return
        last_ping = time.time()
        n = int(self.headers.get("Content-Length") or 0)
        u = urllib.parse.urlparse(self.path)
        if u.path == "/api/drop/upload":            # содержимое перетащенного файла — пишется на диск кусками, не в память
            q = dict(urllib.parse.parse_qsl(u.query))
            try:
                return self.send(200, {"path": drop_upload(q.get("id"), q.get("name"), n, self.rfile)})
            except Exception as e:
                self.close_connection = True
                return self.send(500, {"error": str(e)})
        if n > (3 if u.path.startswith("/api/report/") else 2) * 2 ** 20:   # окну хватает килобайтов (отчёту со снимками — до 3 МБ)
            return self.send(413, {"error": "слишком большой запрос"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self.send(400, {"error": "неверный JSON"})
        p = urllib.parse.urlparse(self.path).path
        try:
            if p == "/api/clientlog":
                # ошибки окна (JavaScript) — в общий журнал ошибок ScanHub
                global CLIENT_ERRS
                CLIENT_ERRS += 1
                if CLIENT_ERRS <= 200:
                    report.record(f"окно: {str(body.get('src') or '')[:120]}:{body.get('line') or ''}",
                                  str(body.get("msg") or "")[:800], str(body.get("stack") or "")[:1500])
                return self.send(200, {"ok": True})
            if p == "/api/ultra/pdf":
                import intel
                out = ultra_report.make_pdf(load_json(ULTRA_FILE, None), VERSION, config(), EDGE, (intel.download_folders() or [DATA])[0])
                subprocess.Popen(["explorer", "/select,", out])
                return self.send(200, {"path": out})
            if p == "/api/self_update/apply":
                try:
                    if body.get("async"):                     # новое окно: обновление в фоне, ход — через /api/self_update/progress
                        return self.send(200, self_update_start())
                    return self.send(200, self_update_apply())
                except Exception as e:
                    return self.send(400, {"error": str(e)})
            if p == "/api/uninstall_self":
                if body.get("preview"):
                    return self.send(200, self_traces())
                return self.send(200, uninstall_self(bool(body.get("folder"))))
            if p == "/api/ctxmenu":
                on = ctxmenu_set(bool(body.get("enable")))
                with lock:                        # выбор человека запоминаем: при следующем запуске не включаем заново
                    c = load_json(CONFIG_FILE, {})
                    c["ctx_menu_set"] = True
                    save_json(CONFIG_FILE, c)
                return self.send(200, {"on": on})
            if p == "/api/report/preview":
                r = report.build(body, VERSION, config())
                return self.send(200, {"text": report.preview_text(r), "ready": bool(config().get("report_url") or report.REPORT_URL),
                                       "log": report.log_info()})
            if p == "/api/replies":
                if body.get("action") == "check":
                    try:
                        report.check_replies(config())
                    except Exception as e:
                        return self.send(200, {**report.replies_view(), "error": f"не получилось проверить: {e}"})
                if body.get("action") == "read":
                    return self.send(200, report.replies_read())
                return self.send(200, report.replies_view())
            if p == "/api/report/send":
                report.send(report.build(body, VERSION, config()), config())
                return self.send(200, {"ok": True})
            if p == "/api/fps":
                # счётчик FPS для игр: PresentMon с правами администратора + окошко поверх игры
                import fps
                if body.get("action") == "stop":
                    return self.send(200, fps.stop())
                if body.get("action") == "style":
                    fps.S["minimal"] = bool(body.get("minimal", True))
                    _cfg_update({"fps_minimal": fps.S["minimal"]})
                    return self.send(200, fps.view())
                if body.get("action") == "corner":
                    fps.S["corner"] = str(body.get("corner") or "tl")[:2]
                    _cfg_update({"fps_corner": fps.S["corner"]})
                    return self.send(200, fps.view())
                m = manifest("presentmon")
                exe = exe_path(m, tool_state(state(), "presentmon"))
                if not exe and not _install_wait("presentmon"):
                    ts = tool_state(state(), "presentmon")
                    return self.send(400, {"error": "не получилось скачать счётчик FPS: " + str(ts.get("blocked") or ts.get("error") or "нет связи")})
                exe = exe or exe_path(m, tool_state(state(), "presentmon"))
                corner = str(body.get("corner") or config().get("fps_corner") or "tl")[:2]
                fps.S["minimal"] = bool(config().get("fps_minimal", True))
                return self.send(200, fps.start(exe, deepscan.run_elevated, metrics.METRICS if metrics else None, corner, body.get("overlay", True) is not False))
            if p == "/api/setup/done":
                _cfg_update({"setup_done": now()})
                return self.send(200, {"ok": True})
            if p == "/api/setup/testkey":
                return self.send(200, test_key(str(body.get("key", "")), str(body.get("value", "")).strip()))
            if p == "/api/usage":
                # анонимный счётчик запусков: только с согласия (спрашиваем один раз на главной, меняется в ⚙)
                on = bool(body.get("on"))
                _cfg_update({"usage_ping": on, **({} if on else {"usage_last": ""})})
                if on:
                    threading.Thread(target=lambda: __import__("usage").ping(config(), _cfg_update, VERSION), daemon=True).start()
                return self.send(200, {"on": on})
            if p == "/api/quit":
                # «Выйти»: выключить сервер сразу, а не через 2 минуты после закрытия окна.
                # Если что-то идёт — без force только сообщаем, что именно (окно спросит, останавливать ли)
                run = [j for j in list(jobs.values()) if j["status"] == "running"]
                tasks = [n for n, t in list(TASKS.items()) if t.get("status") == "running"]
                if (run or tasks) and not body.get("force"):
                    return self.send(409, {"error": "busy", "jobs": [j.get("tool_name") or j["tool"] for j in run], "tasks": tasks})
                for j in run:
                    stop_job(j["id"])
                _stop_helpers()
                threading.Timer(1.5, os._exit, [0]).start()
                return self.send(200, {"ok": True})
            if p == "/api/ping":
                return self.send(200, {"ok": True})
            if p == "/api/install":
                verb = "поиск" if manifest(body["tool"])["source"]["type"] == "manual" else \
                    "обновление" if body.get("update") else "установка"
                return self.send(200, {"ok": install_async(body["tool"], verb, bool(body.get("force")))})
            if p == "/api/config":
                with lock:
                    c = load_json(CONFIG_FILE, {})
                    for k in SECRET_KEYS:
                        if k in body:
                            c[k] = seal(str(body[k]).strip())     # на диске — только в зашифрованном виде
                    if "alerts_on" in body:
                        c["alerts_on"] = bool(body["alerts_on"])
                    for k, (lo, hi, dflt) in {"vt_files": (1, 100, 8), "fs_files": (1, 200, 20), "smart_mb": (10, 4000, 100)}.items():
                        if k in body:
                            c[k] = max(lo, min(hi, int(body[k] or dflt)))
                    if "folder_full" in body:
                        c["folder_full"] = bool(body["folder_full"])
                    if "check_every_hours" in body:
                        c["check_every_hours"] = max(1, min(168, int(body["check_every_hours"])))
                    if body.get("lang") in ("ru", "en"):
                        c["lang"] = body["lang"]
                    save_json(CONFIG_FILE, c)
                return self.send(200, {"ok": True})
            if p == "/api/check":
                threading.Thread(target=check_updates, kwargs={"auto": True}, daemon=True).start()
                return self.send(200, {"ok": True})
            if p == "/api/auto":
                with lock:
                    st = state()
                    tool_state(st, body["tool"])["auto_update"] = bool(body["value"])
                    save_json(STATE_FILE, st)
                return self.send(200, {"ok": True})
            if p == "/api/dismiss":
                with lock:
                    st = state()
                    ts = tool_state(st, body["tool"])
                    ts["error"] = ts["blocked"] = None
                    save_json(STATE_FILE, st)
                return self.send(200, {"ok": True})
            if p == "/api/run":
                job = start_job(body["tool"], body["mode"], body.get("target"), body.get("batch"))
                return self.send(200, {"id": job["id"]})
            if p == "/api/task":
                return self.send(200, start_task(body["name"], body.get("args") or {}))
            if p == "/api/task/cancel":                 # «Перестать ждать» — задача заканчивает ожидание и отчитывается
                t = TASKS.get(body.get("name"))
                if t and t.get("status") == "running":
                    t["cancel"] = True
                return self.send(200, {"ok": bool(t)})
            if p == "/api/notify":
                # системное уведомление Windows, если окно ScanHub свёрнуто (не чаще раза в 3 секунды)
                global _last_notify
                if system and time.time() - _last_notify > 3:
                    _last_notify = time.time()
                    title, text = str(body.get("title", ""))[:120], str(body.get("text", ""))[:200]
                    threading.Thread(target=system.toast, args=("ScanHub: " + title, text or " "), daemon=True).start()
                return self.send(200, {"ok": True})
            if p == "/api/launch":
                # только фиксированный список системных окон, никаких произвольных команд
                what = body.get("what")
                uris = {"storagesense": "ms-settings:storagesense", "wu": "ms-settings:windowsupdate",
                        "wu_optional": "ms-settings:windowsupdate-optionalupdates", "defender": "windowsdefender:",
                        "startup": "ms-settings:startupapps", "privacy": "ms-settings:privacy", "gaming": "ms-settings:gaming-gamemode",
                        "storage": "ms-settings:storagesense", "apps": "ms-settings:appsfeatures", "recovery": "ms-settings:recovery",
                        "sysprotect": "SystemPropertiesProtection.exe", "rstrui": "rstrui.exe", "firewall": "wf.msc",
                        "proxy": "ms-settings:network-proxy", "coreisolation": "windowsdefender://coreisolation",
                        "threatsettings": "windowsdefender://threatsettings", "bitlocker": "control.exe /name Microsoft.BitLockerDriveEncryption",
                        "sound": "ms-settings:sound", "mic_privacy": "ms-settings:privacy-microphone", "cam_privacy": "ms-settings:privacy-webcam",
                        "bluetooth": "ms-settings:bluetooth", "mouse": "ms-settings:mousetouchpad", "typing": "ms-settings:typing",
                        "ease_keyboard": "ms-settings:easeofaccess-keyboard", "devmgmt": "devmgmt.msc", "mmsys": "control.exe mmsys.cpl"}
                if what in uris:
                    if " " in uris[what]:            # программа с параметрами (control.exe /name …)
                        subprocess.Popen(uris[what].split())
                    else:
                        os.startfile(uris[what])
                elif what and what.startswith("store:") and re.fullmatch(r"[\w.\-]+_[a-z0-9]+", what[6:]):
                    os.startfile(f"ms-windows-store://pdp/?PFN={what[6:]}")
                elif what == "cleanmgr":
                    subprocess.Popen(["cleanmgr.exe", "/d", "C"])
                elif what == "winget_upgrade":
                    _winget_upgrade()
                elif what in ("perfmon_rel", "eventvwr", "mdsched", "optionalfeatures"):
                    if what == "perfmon_rel":
                        # perfmon.exe в новых сборках требует прав администратора (WinError 740) — монитор стабильности
                        # открываем через Панель управления, там права не нужны
                        subprocess.Popen(["control.exe", "/name", "Microsoft.ActionCenter", "/page", "pageReliabilityView"])
                    else:
                        os.startfile({"eventvwr": "eventvwr.msc", "mdsched": "mdsched.exe", "optionalfeatures": "optionalfeatures.exe"}[what])
                elif what and what.startswith("winget_install:") and re.fullmatch(r"[\w.\-+]+", what[15:]):
                    subprocess.Popen(["cmd", "/k", "winget", "install", "--id", what[15:], "-e"], creationflags=subprocess.CREATE_NEW_CONSOLE)
                elif what and what.startswith("winget_one:") and re.fullmatch(r"[\w.\-+]+", what[11:]):
                    subprocess.Popen(["cmd", "/k", "winget", "upgrade", "--id", what[11:], "-e"], creationflags=subprocess.CREATE_NEW_CONSOLE)
                elif what in ("sfc_repair", "component_cleanup"):
                    admin_console(what)
                else:
                    return self.send(400, {"error": "неизвестное действие"})
                return self.send(200, {"ok": True})
            if p == "/api/ultra":
                return self.send(200, {"id": start_ultra(body.get("sel"))["id"]})
            if p == "/api/updates":
                ids = body.get("ids")
                return self.send(200, {"id": start_updates(list(ids) if ids is not None else None,
                                                           list(ids or []) if body.get("force") else ())["id"]})
            if p == "/api/updates/skip":
                u = UPDATERS.get(body.get("id"))
                if u:
                    u.skip_current()
                return self.send(200, {"ok": bool(u)})
            if p == "/api/deep":
                return self.send(200, {"id": start_deep()["id"]})
            if p == "/api/kill":
                return self.send(200, {"name": metrics.kill(int(body["pid"]))})
            if p == "/api/stop":
                stop_job(body["id"])
                return self.send(200, {"ok": True})
            if p == "/api/pick":
                return self.send(200, {"path": pick(body.get("kind", "folder"))})
            if p == "/api/drop/locate":
                return self.send(200, {"paths": drop_locate(body.get("files") or [])})
            if p == "/api/drop/collect":
                return self.send(200, {"path": drop_collect(body.get("id"), body.get("paths") or [])})
            if p == "/api/open":
                path = body["path"]
                if os.path.exists(path):
                    subprocess.Popen(["explorer", "/select,", path] if os.path.isfile(path) else ["explorer", path])
                return self.send(200, {"ok": True})
            if p == "/api/ai/config":
                # провайдер, модель и ключи помощника; ключи на диске — только зашифрованными
                prov = str(body.get("provider", ""))
                if prov and prov not in assistant.PROVIDERS:
                    return self.send(400, {"error": "неизвестный провайдер"})
                with lock:
                    c = load_json(CONFIG_FILE, {})
                    if "provider" in body:
                        c["ai_provider"] = prov
                    if "model" in body:
                        c["ai_model"] = str(body["model"])[:120]
                    if body.get("files") in assistant.FILE_MODES:
                        c["ai_files"] = body["files"]
                    if "web" in body:
                        c["ai_web"] = bool(body["web"])
                    for k in AI_KEYS:
                        if k in body:
                            v = str(body[k]).strip()
                            c[k] = "" if v == "-" else seal(v)
                    save_json(CONFIG_FILE, c)
                return self.send(200, assistant.cfg_view(config()))
            if p == "/api/ai/models":
                prov = str(body.get("provider") or config().get("ai_provider") or "")
                if prov not in assistant.PROVIDERS:
                    return self.send(400, {"error": "выбери провайдера"})
                try:
                    models = assistant.list_models(config(), prov)
                except assistant.AIError as e:
                    return self.send(200, {"models": [], "error": str(e)})
                return self.send(200, {"models": models, "default": assistant.default_model(prov, models)})
            if p == "/api/ai/test":
                try:
                    old = config().get("ai_model")
                    text, switched = assistant.test(config())
                    if switched:                     # выбранная модель перегружена — запоминаем ту, что ответила
                        with lock:
                            c = load_json(CONFIG_FILE, {})
                            c["ai_model"] = switched
                            save_json(CONFIG_FILE, c)
                    return self.send(200, {"ok": True, "text": text, "switched": switched, "was": old,
                                           "cfg": assistant.cfg_view(config())})
                except assistant.AIError as e:
                    return self.send(200, {"ok": False, "error": str(e)})
            if p == "/api/ai/ask":
                kind = body.get("kind") if body.get("kind") in ("explain", "solve", "act", "review") else "chat"
                cfg_ = config()
                if not cfg_.get("ai_provider"):
                    return self.send(400, {"error": "помощник не настроен"})
                return self.send(200, {"id": assistant.start(kind, body, cfg_)["id"]})
            if p in ("/api/agent/tools", "/api/agent/call"):
                # инструменты ИИ-агента (mcp_server.py): только пока идёт его ответ и только с его одноразовым ключом
                import hmac
                job = assistant.JOBS.get(str(body.get("job", "")))
                key = self.headers.get("X-Agent-Key") or ""
                if not job or job.get("status") != "running" or not job.get("agent_key") or not hmac.compare_digest(key, job["agent_key"]):
                    return self.send(403, {"error": "нет доступа"})
                cfg_ = config()
                if p == "/api/agent/tools":
                    return self.send(200, {"tools": assistant.agent_tools(job, cfg_)})
                text = assistant.agent_call(job, cfg_, str(body.get("name", "")), body.get("args") or {})
                return self.send(200, {"text": text})
            if p == "/api/ai/cli":
                import agents
                prov = str(body.get("provider", ""))
                if prov not in agents.CLI:
                    return self.send(400, {"error": "неизвестная программа"})
                try:
                    if body.get("action") == "login":
                        agents.login(prov)
                    return self.send(200, agents.status(prov))
                except agents.AgentError as e:
                    return self.send(200, {"installed": False, "connected": False, "message": str(e)})
            if p == "/api/ai/stop":
                j = assistant.JOBS.get(body.get("id"))
                if j:
                    j["stop"] = True
                return self.send(200, {"ok": bool(j)})
            if p == "/api/wipe":
                # история проверок, журналы, перетащенные копии файлов, итоги ультра проверки и разбора сбоев.
                # Не трогаем: ключи (удаляются в Настройках), резервные копии для «вернуть как было» и карантин
                n = 0
                with lock:
                    for f in [HISTORY_FILE, ULTRA_FILE, os.path.join(DATA, "diag.json"), assistant.CACHE] + glob.glob(os.path.join(LOGS, "*")):
                        try:
                            os.remove(f)
                            n += 1
                        except OSError:
                            pass
                    shutil.rmtree(DROP, ignore_errors=True)
                    shutil.rmtree(os.path.join(DATA, "reports"), ignore_errors=True)     # копии отчётов HiJackThis и т. п.
                return self.send(200, {"removed": n})
            if p == "/api/link":
                url = str(body["url"])
                if urllib.parse.urlsplit(url).scheme == "https" and ((urllib.parse.urlsplit(url).hostname or "").lower() in link_hosts()
                                                                     or (body.get("ai") and url in assistant.ANSWER_LINKS)):
                    webbrowser.open(url)
                else:
                    return self.send(400, {"error": "эту ссылку ScanHub не открывает"})
                return self.send(200, {"ok": True})
        except Exception as e:
            if isinstance(e, (ConnectionError, BrokenPipeError)):    # окно закрыли или перезагрузили посреди ответа — не ошибка ScanHub
                return
            if not isinstance(e, (RuntimeError, PermissionError, FileNotFoundError)):
                report.record(f"POST {p}", e)
            return self.send(400, {"error": str(e)})
        self.send(404, {"error": "not found"})


CLIENT_ERRS = 0
WATCHER = alerts.Watcher(metrics.METRICS, lambda: config().get("alerts_on", True)) if alerts else None

STATIC = {"/logo.svg": "image/svg+xml", "/logo-small.svg": "image/svg+xml", "/icon-32.png": "image/png",
          "/icon-256.png": "image/png", "/scanhub.ico": "image/x-icon",
          "/app.css": "text/css; charset=utf-8", "/core.js": "text/javascript; charset=utf-8",
          "/res.js": "text/javascript; charset=utf-8", "/panels.js": "text/javascript; charset=utf-8",
          "/pages.js": "text/javascript; charset=utf-8", "/ultra.js": "text/javascript; charset=utf-8", "/fix.js": "text/javascript; charset=utf-8",
          "/ai.js": "text/javascript; charset=utf-8", "/bug.js": "text/javascript; charset=utf-8",
          "/history.js": "text/javascript; charset=utf-8", "/i18n.js": "text/javascript; charset=utf-8",
          "/devices.js": "text/javascript; charset=utf-8", "/phone.js": "text/javascript; charset=utf-8", "/setup.js": "text/javascript; charset=utf-8", "/game.js": "text/javascript; charset=utf-8",
          "/en.json": "application/json; charset=utf-8"}


def ui_version():
    # все модули и файлы окна — раньше список был ручным, и новые файлы (i18n.js, history.js…) не обновляли окно
    files = [UI_FILE] + glob.glob(os.path.join(ROOT, "*.py")) + glob.glob(os.path.join(ROOT, "ui", "*.*"))
    return int(max(os.path.getmtime(f) for f in files if os.path.exists(f)))


# что Edge сам докачивает в профиль окна (сотни МБ) — окну ScanHub это не нужно
WINDOW_JUNK = ("component_crx_cache", "ProvenanceData", "Edge Wallet", "Edge Entity Extraction", "extensions_crx_cache", "Crashpad",
               "OnDeviceHeadSuggestModel", "Subresource Filter", "WidevineCdm", "edge_shopping", "Edge Shopping", "BrowserMetrics",
               "optimization_guide_model_store", "OptimizationHints", "Speech Recognition", "TrustTokenKeyCommitments",
               "MEIPreload", "hyphen-data", "Edge Travel", "EdgeWallet", "Edge Copilot", "SmartScreen")


def prune_window_profile():
    """Чистит профиль окна от компонентов Edge: без этого он вырастает до ~450 МБ. Занятое (окно открыто) пропускается."""
    base = os.path.join(DATA, "window")
    for name in WINDOW_JUNK:
        shutil.rmtree(os.path.join(base, name), ignore_errors=True)
    for sub in ("Cache", "Code Cache", "GPUCache", "DawnGraphiteCache", "DawnWebGPUCache", "Service Worker"):
        shutil.rmtree(os.path.join(base, "Default", sub), ignore_errors=True)


def open_window():
    url = f"http://{HOST}:{PORT}/"
    if os.path.exists(EDGE):
        prune_window_profile()
        # отдельный чистый профиль: расширения обычного браузера с доступом «ко всем сайтам» не видят окно ScanHub
        # и не могут прочитать его ключ доступа, чтобы управлять приложением
        subprocess.Popen([EDGE, f"--app={url}", "--window-size=1280,860", f"--user-data-dir={os.path.join(DATA, 'window')}",
                          "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-sync",
                          "--disable-component-update", "--disable-background-networking", "--disable-domain-reliability",
                          "--disk-cache-size=20000000", "--disable-breakpad",
                          # свёрнутое окно не «засыпает»: иначе оно перестаёт подавать сигнал «я открыто» и сервер закрывается
                          "--disable-background-timer-throttling", "--disable-renderer-backgrounding",
                          "--disable-backgrounding-occluded-windows",
                          "--disable-features=msEdgeSidebarV2,msUndersideButton,msShoppingExp,msEdgeWallet,EdgeEntityExtraction,"
                          "msEdgeCopilot,OptimizationGuideModelDownloading,OptimizationHints,IntensiveWakeUpThrottling"])
    else:
        webbrowser.open(url)


def protect_folder():
    """Код ScanHub запускается и с правами администратора, поэтому менять его должны только владелец, система и администраторы.
    На диске D: по умолчанию любой вошедший пользователь может менять файлы — убираем унаследованные права (один раз).
    Вернуть как было: icacls D:\\ScanHub /reset /T"""
    mark = os.path.join(DATA, "acl.ok")
    if os.path.exists(mark):
        return
    try:
        out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, creationflags=NO_WINDOW).stdout
        sid = out.strip().split(",")[-1].strip('"')
        if not sid.startswith("S-1-5-21-"):
            return
        grant = ["icacls", ROOT, "/grant:r", f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/Q"]
        # сначала явные права, и только потом — отключить унаследованные: при сбое на втором шаге доступ не теряется
        if subprocess.run(grant, capture_output=True, creationflags=NO_WINDOW).returncode == 0 and \
                subprocess.run(["icacls", ROOT, "/inheritance:r", "/Q"], capture_output=True, creationflags=NO_WINDOW).returncode == 0:
            open(mark, "w").write(now())
    except Exception:
        pass


# ---------------------------------------------------------------- «Проверить в ScanHub» в меню правой кнопки
# Только HKCU (без прав администратора) и только для этой учётной записи. Файл передаётся окну через data\pending_check.json:
# туда может писать только сам пользователь, а сайт в браузере не может ни создать файл, ни вызвать ScanHub без ключа.
PENDING = os.path.join(DATA, "pending_check.json")
CTX_KEYS = (r"Software\Classes\*\shell\ScanHubCheck", r"Software\Classes\Directory\shell\ScanHubCheck")


def ctxmenu_on():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, CTX_KEYS[0] + r"\command"):
            return True
    except OSError:
        return False


def launch_cmd():
    """Чем запускать ScanHub: ScanHub.exe рядом (у него своя иконка) или pythonw + scanhub.py."""
    exe = os.path.join(ROOT, "ScanHub.exe")
    if os.path.exists(exe):
        return exe, "", exe
    return sys.executable.replace("python.exe", "pythonw.exe"), f'"{os.path.join(ROOT, "scanhub.py")}"', os.path.join(ROOT, "ui", "scanhub.ico")


def ctxmenu_set(enable):
    import winreg
    exe, script, icon = launch_cmd()
    for i, key in enumerate(CTX_KEYS):
        if enable:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as k:
                winreg.SetValueEx(k, "MUIVerb", 0, winreg.REG_SZ, "Проверить в ScanHub" if i == 0 else "Проверить папку в ScanHub")
                winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, icon)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key + r"\command") as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f'"{exe}" {script + " " if script else ""}--check "%1"')
        else:
            for sub in (key + r"\command", key):
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
                except OSError:
                    pass
    return ctxmenu_on()


def ctxmenu_startup():
    """«Проверить в ScanHub» включён по умолчанию: при первом запуске добавляем пункт; если человек потом выключил его
    в Настройках — больше не трогаем. Если пункт есть — обновляем пути (папку ScanHub могли перенести)."""
    try:
        c = load_json(CONFIG_FILE, {})
        if not c.get("ctx_menu_set"):
            ctxmenu_set(True)
            with lock:
                c = load_json(CONFIG_FILE, {})
                c["ctx_menu_set"] = True
                save_json(CONFIG_FILE, c)
        elif ctxmenu_on():
            ctxmenu_set(True)
    except Exception as e:
        report.record("меню «Проверить в ScanHub»", e)


APP_LINKS_PS = r"""$a = $env:SH_ARGS | ConvertFrom-Json
$sh = New-Object -ComObject WScript.Shell
$places = @([Environment]::GetFolderPath('Desktop'), (Join-Path ([Environment]::GetFolderPath('Programs')) ''))
$out = @()
foreach ($d in $places) {
  $p = Join-Path $d 'ScanHub.lnk'
  if ($a.create) { $l = $sh.CreateShortcut($p); $l.TargetPath = $a.exe; $l.Arguments = $a.args; $l.WorkingDirectory = $a.root
    $l.IconLocation = $a.icon + ',0'; $l.Description = 'ScanHub — проверка и обслуживание Windows'; $l.Save() }
  $ok = $false
  if (Test-Path $p) { $l = $sh.CreateShortcut($p); $ok = ($l.TargetPath -like ($a.root + '*')) -or ($l.Arguments -like ('*' + $a.root + '*')) }
  $out += [pscustomobject]@{ where = $d; ok = $ok }
}
@($out) | ConvertTo-Json -Compress"""


# ---------------------------------------------------------------- удаление ScanHub с компьютера

LINKS_DEL_PS = r"""$a = $env:SH_ARGS | ConvertFrom-Json
$sh = New-Object -ComObject WScript.Shell
$n = 0
foreach ($d in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) {
  Get-ChildItem -LiteralPath $d -Filter '*.lnk' -ErrorAction SilentlyContinue | ForEach-Object {
    $l = $sh.CreateShortcut($_.FullName)
    if (($l.TargetPath -like ($a.root + '*')) -or ($l.Arguments -like ('*' + $a.root + '*'))) { Remove-Item -LiteralPath $_.FullName -Force; $n++ } } }
$n"""


def self_traces():
    """Что ScanHub оставил в системе вне своей папки — для окна «Удалить ScanHub»."""
    pf_dir = os.path.dirname(metrics.SENSORS_SCRIPT) if metrics else ""
    q = os.path.join(DATA, "quarantine")
    try:
        links = [i for i in app_links(False).get("items", []) if i.get("ok")]
    except Exception:
        links = []
    hosts = system.hosts_status() if system else {}
    rows = load_json(CHANGES_FILE, [])
    T = [
        {"id": "ctx", "title": "Пункт «Проверить в ScanHub» в меню правой кнопки", "found": ctxmenu_on(), "admin": False},
        {"id": "links", "title": "Ярлыки ScanHub на рабочем столе и в «Пуске»", "found": bool(links), "admin": False},
        {"id": "watch", "title": "Сторож — задача планировщика (проверка раз в 15 минут)", "found": bool(system and system.watch_status().get("enabled")), "admin": False},
        {"id": "sensors", "title": "Датчики Lenovo — задача планировщика и скрипт в Program Files", "found": bool(metrics and metrics.sensors_installed()), "admin": True},
        {"id": "memclean", "title": "Полная очистка памяти — задача планировщика и скрипт", "found": bool(system and system.memclean_installed()), "admin": True},
        {"id": "hosts", "title": "Блокировка майнинг-сайтов в файле hosts", "found": bool(hosts.get("enabled")), "admin": True},
        {"id": "pf", "title": "Папки ScanHub в Program Files и ProgramData",
         "found": bool(pf_dir and os.path.isdir(pf_dir)) or os.path.isdir(os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "ScanHub")), "admin": True},
    ]
    return {"traces": T, "root": ROOT, "quarantine": len(os.listdir(q)) if os.path.isdir(q) else 0,
            "undo": sum(1 for r in rows if r.get("undo") and not r.get("undone") and not r.get("superseded"))}


def uninstall_self(delete_folder):
    """Убрать всё, что ScanHub оставил в системе; по желанию — и саму папку (после выхода, отдельным процессом)."""
    info = self_traces()
    found = {t["id"] for t in info["traces"] if t["found"]}
    done, errors = [], []
    if "ctx" in found:
        ctxmenu_set(False)
        done.append("ctx")
    if "links" in found:
        system.ps(LINKS_DEL_PS, env={"SH_ARGS": json.dumps({"root": ROOT})}, timeout=60)
        done.append("links")
    if "watch" in found:
        system.watch_set(False)
        done.append("watch")
    ops = []
    if "sensors" in found:
        ops += [{"type": "run", "cmd": ["schtasks", "/End", "/TN", metrics.SENSORS_TASK], "timeout": 30},
                {"type": "run", "cmd": ["schtasks", "/Delete", "/TN", metrics.SENSORS_TASK, "/F"], "timeout": 30}]
    if "memclean" in found:
        ops += [{"type": "run", "cmd": ["schtasks", "/Delete", "/TN", system.MEMCLEAN_TASK, "/F"], "timeout": 30}]
    if "hosts" in found:
        ops += [{"type": "copy", "src": system.hosts_prepare(False), "dst": system.HOSTS},
                {"type": "run", "cmd": ["ipconfig", "/flushdns"], "timeout": 60}]
    if found & {"sensors", "memclean", "pf"}:
        ops += [{"type": "rmtree", "path": os.path.dirname(metrics.SENSORS_SCRIPT)},
                {"type": "rmtree", "path": os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "ScanHub")}]
    if delete_folder:
        # часть отчётов сканеров создана от администратора — отдаём их своей учётной записи, иначе папка удалится не целиком
        sid = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True,
                             creationflags=NO_WINDOW).stdout.strip().split(",")[-1].strip('"')
        if sid.startswith("S-1-5-21-"):
            ops += [{"type": "run", "cmd": ["icacls", ROOT, "/grant", f"*{sid}:(OI)(CI)F", "/T", "/C", "/Q"], "timeout": 300}]
    if ops:
        try:
            res = deepscan.run_elevated(ops, timeout=600)
            done += [x for x in ("sensors", "memclean", "hosts", "pf") if x in found]
            if not all(r.get("ok") for r in res):
                errors.append("часть системных шагов не выполнилась")
        except PermissionError:
            errors.append("окно администратора отменено — системные задачи и hosts остались")
            if delete_folder:
                return {"done": done, "errors": errors, "folder": False}
    if delete_folder:
        # отдельный процесс ждёт, пока ScanHub и его окно закроются, и удаляет папку (до минуты попыток)
        cmd = (f'cmd /d /c "for /l %i in (1,1,30) do @(ping -n 3 127.0.0.1 >nul & rmdir /s /q "{ROOT}" 2>nul & '
               f'if not exist "{ROOT}" exit)"')
        for flags in (NO_WINDOW | 0x00000200 | 0x01000000, NO_WINDOW | 0x00000200):   # вне задания (job) ScanHub, если Windows разрешает
            try:
                subprocess.Popen(cmd, cwd=os.environ.get("SystemRoot", r"C:\Windows"), close_fds=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
                break
            except PermissionError:
                continue
    threading.Timer(2.5, os._exit, [0]).start()        # ScanHub больше не нужен — выключаемся
    return {"done": done, "errors": errors, "folder": bool(delete_folder)}


def app_links(create=False):
    """Ярлыки ScanHub на рабочем столе и в «Пуске» (для портативной версии — её не нужно устанавливать)."""
    exe, script, icon = launch_cmd()
    res = system.ps(APP_LINKS_PS, env={"SH_ARGS": json.dumps({"create": create, "exe": exe, "args": script, "icon": icon, "root": ROOT})}, timeout=60)
    items = system.as_list(res)
    return {"ok": bool(items) and all(i.get("ok") for i in items), "items": items}


def check_from_menu(path):
    """Запуск из меню «Проверить в ScanHub»: передать файл окну (открыть его, если окна нет)."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return
    os.makedirs(DATA, exist_ok=True)
    with open(PENDING + ".tmp", "w", encoding="utf-8") as f:
        json.dump({"path": path, "kind": "folder" if os.path.isdir(path) else "file", "t": time.time()}, f, ensure_ascii=False)
    os.replace(PENDING + ".tmp", PENDING)
    if already_running():
        try:
            with urllib.request.urlopen(f"http://{HOST}:{PORT}/api/hello", timeout=2) as r:
                alive = json.load(r).get("window")
        except Exception:
            alive = False
        if not alive:
            open_window()
        return True
    return False


def take_pending():
    try:
        p = json.load(open(PENDING, encoding="utf-8"))
        os.remove(PENDING)
    except (OSError, ValueError):
        return {}
    if time.time() - p.get("t", 0) > 300 or not os.path.exists(p.get("path", "")):
        return {}
    PICKED.add(os.path.normpath(p["path"]))          # выбрал сам человек — как в окне выбора файла
    return {"path": p["path"], "kind": p.get("kind", "file")}


class Server(http.server.ThreadingHTTPServer):
    # окно при открытии раздела шлёт десяток запросов разом; со стандартной очередью на 5 подключений
    # Windows отбрасывает лишние — в окне «Failed to fetch» / ERR_CONNECTION_REFUSED
    request_queue_size = 128
    daemon_threads = True
    # порт только наш: по умолчанию Python разрешает другим программам сесть на тот же порт, и Windows
    # раздаёт подключения как попало (окно открывало чужой сервер, а ScanHub запускался по второму разу)
    allow_reuse_address = False

    def server_bind(self):
        import socket
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


PORT_FILE = os.path.join(DATA, "port")
PORTS = tuple(range(8765, 8776))          # 8765 занят чужой программой — берём следующий свободный


def _is_scanhub(port):
    try:
        with urllib.request.urlopen(f"http://{HOST}:{port}/api/hello", timeout=2) as r:
            return json.load(r).get("app") == "scanhub"
    except Exception:
        return False


def already_running():
    """Уже запущен ли ScanHub: на порту из прошлого запуска или на 8765. Найденный порт становится текущим."""
    global PORT
    ports = []
    try:
        ports.append(int(open(PORT_FILE, encoding="utf-8").read().strip()))
    except (OSError, ValueError):
        pass
    for p in dict.fromkeys(ports + [8765]):
        if p in PORTS and _is_scanhub(p):
            PORT = p
            return True
    return False


def bind_server(prefer=None, wait=0):
    """Занять порт ScanHub (по возможности prefer, иначе первый свободный из PORTS) и запомнить его."""
    global PORT
    t0 = time.time()
    while True:
        for p in ([prefer] if prefer else []) + [x for x in PORTS if x != prefer]:
            try:
                srv = Server((HOST, p), Handler)
            except OSError:
                if prefer and p == prefer and time.time() - t0 < wait:
                    break                          # ждём, пока старый ScanHub освободит свой порт
                continue
            PORT = p
            try:
                os.makedirs(DATA, exist_ok=True)
                with open(PORT_FILE, "w", encoding="utf-8") as f:
                    f.write(str(p))
            except OSError:
                pass
            return srv
        else:
            return None
        time.sleep(0.5)


def _stop_helpers():
    """Выход: погасить то, что ScanHub запускал сам и что живёт отдельным процессом (сервер adb, счётчик FPS)."""
    if "fps" in sys.modules:
        try:
            sys.modules["fps"].stop()
        except Exception:
            pass
    if "phone" in sys.modules:
        try:
            sys.modules["phone"].stop_server()
        except Exception:
            pass


def idle_watch():
    while True:
        time.sleep(15)
        running = any(j["status"] == "running" for j in list(jobs.values())) or \
            any(t.get("status") == "running" for t in list(TASKS.values())) or \
            ("fps" in sys.modules and sys.modules["fps"].S.get("on"))       # идёт игра с показом FPS — окно ScanHub можно закрыть
        if not running and not busy and time.time() - last_ping > IDLE_EXIT:
            _stop_helpers()
            os._exit(0)


KEY_TESTS = {   # безопасный запрос с ключом: отпечаток тестового файла EICAR — его знают все сервисы
    "virustotal_key": ("https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "x-apikey", {}),
    "filescan_key": ("https://www.filescan.io/api/reputation/hash?sha256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "X-Api-Key", {}),
    "metadefender_key": ("https://api.metadefender.com/v4/apikey/", "apikey", {}),
    "hybrid_key": ("https://hybrid-analysis.com/api/v2/key/current", "api-key", {"User-Agent": "Falcon Sandbox"}),
}


def test_key(name, value):
    """Проверить ключ сервиса одним запросом: {ok, text}. Ключ никуда, кроме самого сервиса, не уходит."""
    if name not in KEY_TESTS or not value:
        return {"ok": False, "text": "пустой ключ"}
    url, header, extra = KEY_TESTS[name]
    try:
        code, body = services.request(url, {header: value, "accept": "application/json", **extra}, timeout=20)
    except Exception as e:
        return {"ok": None, "text": f"сервис не ответил: {getattr(e, 'reason', e)} — ключ сохраню, проверю позже"}
    if code in (200, 404):
        return {"ok": True, "text": "ключ работает"}
    if code in (401, 403):
        return {"ok": False, "text": "сервис не принял ключ — проверь, что скопирован целиком"}
    if code == 429:
        return {"ok": True, "text": "ключ верный, но сейчас лимит запросов — это нормально"}
    return {"ok": None, "text": f"сервис ответил {code} — ключ сохраню, проверю при первой проверке"}


def _cfg_update(d):
    with lock:
        c = load_json(CONFIG_FILE, {})
        c.update(d)
        save_json(CONFIG_FILE, c)


def _health_snapshot_later():
    """Снимок истории здоровья раз в сутки — через минуту после запуска, чтобы не мешать открытию окна."""
    time.sleep(60)
    try:
        __import__("health_history").snapshot()
    except Exception as e:
        report.record("история здоровья", e)


def _replies_loop():
    """Ответы автора на мои сообщения: через 20 с после запуска и раз в 30 минут, пока ScanHub открыт."""
    time.sleep(20)
    while True:
        try:
            n = report.check_replies(config())
            if n:
                _notify("автор ответил на твоё сообщение", "Открой ScanHub → «Написать автору» → «Мои сообщения»")
        except Exception:
            pass                               # нет интернета или посредник старый — попробуем позже
        time.sleep(1800)


def main():
    if "--elevated-b64" in sys.argv:
        deepscan.elevated_main(sys.argv[sys.argv.index("--elevated-b64") + 1])
        return
    if "--check" in sys.argv:                  # «Проверить в ScanHub» из меню правой кнопки
        i = sys.argv.index("--check")
        if i + 1 < len(sys.argv) and check_from_menu(sys.argv[i + 1]):
            return                             # ScanHub уже запущен — окно подхватит файл само
    if "--watch-once" in sys.argv:
        system.watch_once()
        return
    if "--update-all" in sys.argv:
        res = check_updates(auto=False)
        st = state()
        for tid, ver in res.items():
            ts = st["tools"].get(tid, {})
            if ts.get("installed") and ts["installed"] != ver and auto_on(manifest(tid), ts):
                print(f"{tid}: {ts['installed']} -> {ver}")
                try:
                    install(tid, lambda s: None)
                except Exception as e:
                    print(f"  ошибка: {e}")
        return
    if "--after-update" in sys.argv:            # перезапуск после обновления: ждём, пока старый сервер освободит порт
        try:
            prev = int(open(PORT_FILE, encoding="utf-8").read().strip())
        except (OSError, ValueError):
            prev = PORT
        server = bind_server(prefer=prev, wait=20)
    else:
        if already_running():
            open_window()
            return
        server = bind_server(prefer=PORT)
    if not server:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, "Все порты ScanHub (8765–8775) заняты другими программами. Перезагрузи компьютер "
                                               "и открой ScanHub снова.", "ScanHub", 0x10)
        return
    threading.Thread(target=protect_folder, daemon=True).start()
    threading.Thread(target=updater_loop, daemon=True).start()
    threading.Thread(target=_health_snapshot_later, daemon=True).start()
    threading.Thread(target=_replies_loop, daemon=True).start()
    threading.Thread(target=lambda: __import__("usage").loop(config, _cfg_update, VERSION), daemon=True).start()
    threading.Thread(target=ctxmenu_startup, daemon=True).start()
    threading.Thread(target=lambda: ultra_report.seed(load_json(ULTRA_FILE, None)), daemon=True).start()
    if "--no-window" not in sys.argv:
        threading.Thread(target=idle_watch, daemon=True).start()
        if "--no-open" not in sys.argv:          # перезапуск сервера: открытое окно подхватит новую версию само
            open_window()
    server.serve_forever()


if __name__ == "__main__":
    main()
