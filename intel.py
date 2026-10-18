"""Сверка с открытыми базами угроз — разово, без постоянно работающих служб.

* Опасные адреса — базы Maltrail (github.com/stamparm/trails, 1,7 млн доменов и IP вредоносов): текущие соединения,
  кэш DNS (куда компьютер недавно обращался) и файл hosts. Лицензия баз разрешает защищать свои компьютеры.
* Откуда скачаны файлы — Windows помечает скачанное «зоной» с адресом сайта (поток Zone.Identifier). Сайты сверяются
  со списком FMHY (поддельные сайты репаков, торрентов и программ) и с базами Maltrail.
* Пакеты разработчика — установленные пакеты npm и pip и lock-файлы проекта сверяются с базой OSV.dev (Google):
  известные вредоносные пакеты (MAL-…) и уязвимости. Отправляются только названия и версии пакетов.

Базы Maltrail лежат на диске закодированными XOR (как правила YARA): в них есть адреса и пути вредоносов, и антивирусы
иначе могут принять сам файл базы за угрозу.
"""
import gzip
import hashlib
import io
import ipaddress
import json
import os
import re
import time
import urllib.parse
import urllib.request
import winreg
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
IDIR = os.path.join(DATA, "intel")
META = os.path.join(IDIR, "meta.json")
TRAILS = os.path.join(IDIR, "trails.bin")
FMHY = os.path.join(IDIR, "fmhy.json")
TRAILS_URL = "https://github.com/stamparm/trails/releases/latest/download/trails.csv.gz"
TRAILS_SHA = "https://github.com/stamparm/trails/releases/latest/download/trails.csv.sha256"
FMHY_RAW = "https://raw.githubusercontent.com/fmhy/FMHYFilterlist/main/"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
MAX_AGE_H = 24                       # базы старше суток обновляются перед проверкой
BUILTINS = ("netintel", "origin", "osv", "byovd", "malext")
_XOR = bytes(i ^ 0xA7 for i in range(256))
# в базах есть и «подозрительное» (парковки доменов, динамический DNS, рекламные SDK) — это слишком шумно, берём только вредоносы
BAD_CLASSES = ("(malware)", "(malicious)")
RISKY_DL = {".exe", ".msi", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".jar", ".lnk", ".zip", ".rar",
            ".7z", ".iso", ".img", ".apk", ".dll", ".msix", ".appx", ".reg", ".docm", ".xlsm", ".torrent"}


class IntelError(Exception):
    pass


# ================================================================ общее

def _get(url, timeout=120):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "ScanHub"}), timeout=timeout)


def meta():
    try:
        return json.load(open(META, encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_meta(part, value):
    m = meta()
    m[part] = value
    os.makedirs(IDIR, exist_ok=True)
    tmp = META + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(m, f, ensure_ascii=False, indent=1)
    os.replace(tmp, META)


def _fresh(part, hours=MAX_AGE_H):
    m = meta().get(part)
    if not m:
        return False
    try:
        return (datetime.now() - datetime.fromisoformat(m["checked"])).total_seconds() < hours * 3600
    except (KeyError, ValueError):
        return False


def view(builtin):
    """Состояние баз для карточки инструмента: версия, когда обновлены, сколько записей."""
    m = meta()
    if builtin == "netintel" and m.get("trails") and os.path.exists(TRAILS):
        t = m["trails"]
        return {"installed": t["version"], "installed_at": t["updated"], "rules": t["count"], "verified": "SHA-256 сверена с GitHub"}
    if builtin == "origin" and m.get("fmhy") and os.path.exists(FMHY):
        f = m["fmhy"]
        rules = f["count"] + (m.get("trails", {}).get("count", 0) if os.path.exists(TRAILS) else 0)
        return {"installed": f["version"], "installed_at": f["updated"], "rules": rules, "verified": "списки FMHY и Maltrail"}
    if builtin == "byovd" and m.get("loldrivers") and os.path.exists(LOL):
        x = m["loldrivers"]
        return {"installed": x["version"], "installed_at": x["updated"], "rules": x["count"], "verified": "база loldrivers.io"}
    if builtin == "malext" and m.get("malext") and os.path.exists(MALEXT):
        x = m["malext"]
        return {"installed": x["version"], "installed_at": x["updated"], "rules": x["count"], "verified": "база MalExt Sentry"}
    return None


# ================================================================ Maltrail

def update_trails(emit=print, force=False):
    """Скачать свежие базы Maltrail (~12 МБ). Сначала сверяет опубликованную сумму — если не изменилась, ничего не качает."""
    old = meta().get("trails") or {}
    with _get(TRAILS_SHA, 60) as r:
        published = r.read().decode("ascii", "replace").split()[0].strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", published):
        raise IntelError("не удалось получить контрольную сумму баз Maltrail")
    if not force and old.get("sha") == published and os.path.exists(TRAILS):
        _save_meta("trails", {**old, "checked": datetime.now().isoformat(timespec="seconds")})
        emit(f"  базы Maltrail свежие ({old['version']}, адресов: {old['count']:,})".replace(",", " "))
        return old
    emit("  скачиваю базы Maltrail (~12 МБ)…")
    with _get(TRAILS_URL, 300) as r:
        version = re.search(r"/download/([^/]+)/", r.geturl())
        blob = r.read()
    h, count = hashlib.sha256(), 0
    with gzip.GzipFile(fileobj=io.BytesIO(blob)) as g:
        for line in g:
            h.update(line)
            if line[:1] != b"#" and (b"(malware)" in line or b"(malicious)" in line):
                count += 1
    if h.hexdigest() != published:
        raise IntelError("базы Maltrail не совпали с опубликованной контрольной суммой — оставляю прежние")
    os.makedirs(IDIR, exist_ok=True)
    tmp = TRAILS + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob.translate(_XOR))
    os.replace(tmp, TRAILS)
    now = datetime.now().isoformat(timespec="seconds")
    info = {"version": _tag(version.group(1)) if version else now[:16].replace("T", " "), "sha": published, "count": count,
            "updated": now, "checked": now, "size": len(blob)}
    _save_meta("trails", info)
    emit(f"  базы Maltrail обновлены: {info['version']}, адресов вредоносов: {count:,}".replace(",", " "))
    return info


def _tag(t):
    """content-20261012-0238 → 2026-10-12 02:38"""
    m = re.fullmatch(r"content-(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)", t)
    return f"{m[1]}-{m[2]}-{m[3]} {m[4]}:{m[5]}" if m else t


TRAILS_LICENSE = ("Базы Maltrail (лицензия Maltrail Trails Community Data License 1.0) бесплатны для защиты компьютеров, которыми "
                  "ты пользуешься сам, но не для встраивания в продукт для других. Поэтому ScanHub не качает их сам: нажми "
                  "«Скачать базы» в карточке «Опасные адреса» — этим ты соглашаешься с лицензией для своего компьютера.")


def trails_accepted():
    """Каждый человек сам один раз соглашается с лицензией баз Maltrail (кнопкой «Скачать базы»). Уже скачанные — согласие было."""
    return os.path.exists(TRAILS) or bool(meta().get("trails_accepted"))


def ensure_trails(emit=print):
    """Базы есть и не старше суток — иначе обновить. Без интернета — работать со старыми, если они есть."""
    if not trails_accepted():
        emit("  " + TRAILS_LICENSE)
        return False
    if os.path.exists(TRAILS) and _fresh("trails"):
        return True
    try:
        update_trails(emit)
        return True
    except Exception as e:
        if os.path.exists(TRAILS):
            emit(f"  базы Maltrail не обновились ({e}) — проверяю по прежним от {meta().get('trails', {}).get('version', '?')}")
            return True
        emit(f"  базы Maltrail не скачались: {e}")
        return False


def _keys_for_domain(d):
    """example.sub.domain.com → сам домен и все родительские (минимум 2 уровня): базы часто содержат только «корень» вредоноса."""
    d = d.strip().strip(".").lower()
    parts = d.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)] if len(parts) >= 2 else [d]


def match_trails(domains=(), ips=()):
    """Найти домены и IP (можно «ip:port») в базах. Возвращает {индикатор: (что это, совпавшая запись)}."""
    want = {}
    for d in domains:
        for k in _keys_for_domain(d):
            want.setdefault(k, set()).add(d.lower())
    for ip in ips:
        want.setdefault(ip, set()).add(ip)
    if not want or not os.path.exists(TRAILS):
        return {}
    hits = {}
    raw = open(TRAILS, "rb").read().translate(_XOR)
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as g:
        for line in io.TextIOWrapper(g, encoding="utf-8", errors="replace"):
            if line[:1] == "#":
                continue
            trail, _, rest = line.partition(",")
            if trail not in want:
                continue
            info = rest.split(",")[0].strip()
            if not info.endswith(BAD_CLASSES):
                continue
            for orig in want[trail]:
                hits.setdefault(orig, (info, trail))
    return hits


def _public_ip(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


def _family(info):
    """«emotet (malware)» → «emotet, вредонос»; «ek clearfake (malicious)» → «заражённый сайт clearfake»."""
    name, _, cls = info.rpartition(" (")
    cls = cls.rstrip(")")
    name = re.sub(r"-\d+$", "", name.strip())
    if name.startswith("ek "):
        return f"заражённый сайт ({name[3:]})"
    if cls == "malicious":
        return f"вредоносный адрес ({name})" if name else "вредоносный адрес"
    return f"вредонос {name}" if name else "вредонос"


def check_network(emit=print, update=True):
    """Соединения, кэш DNS и hosts против баз Maltrail. Возвращает {"hits": [...], "conns", "dns", "hosts", "ok"}."""
    import psutil
    import system
    if update and not ensure_trails(emit):
        return {"ok": False, "hits": [], "conns": 0, "dns": 0, "hosts": 0}
    if not os.path.exists(TRAILS):
        return {"ok": False, "hits": [], "conns": 0, "dns": 0, "hosts": 0}
    conns, procs = [], {}
    for c in psutil.net_connections(kind="inet"):
        if not c.raddr or not _public_ip(c.raddr.ip) or c.status not in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"):
            continue
        if c.pid not in procs:
            try:
                p = psutil.Process(c.pid)
                procs[c.pid] = (p.name(), p.exe())
            except (psutil.Error, OSError):
                procs[c.pid] = ("?", "")
        conns.append((c.raddr.ip, c.raddr.port, c.pid, *procs[c.pid]))
    dns = system.as_list(system.ps("Get-DnsClientCache | Select-Object Entry, Data, Type | ConvertTo-Json -Compress")) or []
    names, dns_ips = set(), {}
    for d in dns:
        if not isinstance(d, dict):
            continue
        e = str(d.get("Entry") or "").lower()
        if e and "." in e and not e.endswith((".local", ".lan", ".arpa", ".home")):
            names.add(e)
        data = str(d.get("Data") or "")
        if d.get("Type") in (1, 28) and _public_ip(data):
            dns_ips[data] = e
    hosts_ips = {}
    try:
        for line in open(system.HOSTS, encoding="utf-8", errors="replace"):
            parts = line.split("#")[0].split()
            if len(parts) >= 2 and _public_ip(parts[0]):
                hosts_ips[parts[0]] = parts[1:]
    except OSError:
        pass
    ips = {ip for ip, *_ in conns} | {f"{ip}:{port}" for ip, port, *_ in conns} | set(dns_ips) | set(hosts_ips)
    emit(f"  сверяю с базами Maltrail: соединений {len(conns)}, адресов в кэше DNS {len(names) + len(dns_ips)}, переадресаций в hosts {len(hosts_ips)}…")
    t0 = time.time()
    found = match_trails(names, ips)
    emit(f"  сверено за {time.time() - t0:.1f} с")
    hits, seen = [], set()
    for ip, port, pid, name, exe in conns:
        for key in (f"{ip}:{port}", ip):
            if key in found and (pid, key) not in seen:
                seen.add((pid, key))
                info, trail = found[key]
                hits.append({"kind": "conn", "level": "bad", "indicator": key, "info": info, "what": _family(info),
                             "process": name, "pid": pid, "exe": exe,
                             "text": f"{name} (PID {pid}) сейчас соединён с {key} — {_family(info)}"})
                break
    for ip, hostnames in hosts_ips.items():
        if ip in found:
            info, _ = found[ip]
            hits.append({"kind": "hosts", "level": "bad", "indicator": ip, "info": info, "what": _family(info),
                         "text": f"файл hosts перенаправляет {', '.join(hostnames[:3])} на {ip} — {_family(info)}"})
    for n in sorted(names):
        if n in found:
            info, trail = found[n]
            hits.append({"kind": "dns", "level": "warn", "indicator": n, "info": info, "what": _family(info),
                         "text": f"компьютер недавно обращался к {n} — {_family(info)}" + (f" (в базе: {trail})" if trail != n else "")})
    for ip, host in dns_ips.items():
        if ip in found and not any(h["indicator"] in (ip, host) for h in hits):
            info, _ = found[ip]
            hits.append({"kind": "dns", "level": "warn", "indicator": ip, "info": info, "what": _family(info),
                         "text": f"{host or 'адрес'} → {ip} — {_family(info)}"})
    return {"ok": True, "hits": hits, "conns": len(conns), "dns": len(names) + len(dns_ips), "hosts": len(hosts_ips)}


# ================================================================ FMHY: откуда скачаны файлы

def update_fmhy(emit=print):
    basic = _domains(FMHY_RAW + "filterlist-basic-domains.txt")
    plus = _domains(FMHY_RAW + "filterlist-domains.txt")
    with _get(FMHY_RAW + "filterlists-reasons.json", 60) as r:
        reasons = json.load(r)
    if len(basic) < 20:
        raise IntelError("список FMHY пришёл пустым")
    now = datetime.now().isoformat(timespec="seconds")
    os.makedirs(IDIR, exist_ok=True)
    with open(FMHY, "w", encoding="utf-8") as f:
        json.dump({"basic": sorted(basic), "plus": sorted(plus - basic), "reasons": reasons}, f, ensure_ascii=False)
    info = {"version": now[:10], "count": len(basic | plus), "updated": now, "checked": now}
    _save_meta("fmhy", info)
    emit(f"  список FMHY обновлён: опасных сайтов {len(basic)}, не рекомендуемых {len(plus - basic)}")
    return info


def _site(host):
    """Имя сайта без поддомена и зоны: dw53.softmany.net → softmany (для сравнения «тот же владелец или нет»)."""
    parts = (host or "").lower().split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu") and len(parts[-1]) == 2:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else host


def _domains(url):
    with _get(url, 60) as r:
        text = r.read().decode("utf-8", "replace")
    return {l.strip().lower() for l in text.splitlines() if l.strip() and not l.startswith(("#", "!"))}


def _known_folder(guid, fallback):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as k:
            return os.path.expandvars(winreg.QueryValueEx(k, guid)[0])
    except OSError:
        return fallback


def _browser_download_dirs():
    """Папки загрузок, выбранные в настройках браузеров на движке Chromium (Chrome, Edge, Яндекс, Opera, Brave)."""
    import glob
    la, ra = os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", "")
    prefs = []
    for pat in (r"Google\Chrome\User Data\*\Preferences", r"Microsoft\Edge\User Data\*\Preferences",
                r"Yandex\YandexBrowser\User Data\*\Preferences", r"BraveSoftware\Brave-Browser\User Data\*\Preferences"):
        prefs += glob.glob(os.path.join(la, pat))
    prefs += glob.glob(os.path.join(ra, "Opera Software", "*", "Preferences"))
    out = []
    for p in prefs:
        try:
            d = json.load(open(p, encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        for sect in ("download", "savefile"):
            v = (d.get(sect) or {}).get("default_directory")
            if v:
                out.append(v)
    return out


def download_folders():
    home = os.path.expanduser("~")
    dl = _known_folder("{374DE290-123F-4565-9164-39C4925E467B}", os.path.join(home, "Downloads"))
    desk = _known_folder("Desktop", os.path.join(home, "Desktop"))
    out = []
    for p in (dl, *_browser_download_dirs(), desk, os.path.join(home, "Downloads"), os.path.join(home, "Desktop")):
        if p and os.path.isdir(p) and os.path.normcase(p) not in {os.path.normcase(x) for x in out}:
            out.append(p)
    return out


def zone_of(path):
    """Пометка «скачано из интернета»: {"zone": 3, "host": "…", "url": "…", "ref": "…"} или None."""
    try:
        with open(path + ":Zone.Identifier", encoding="utf-8", errors="replace") as f:
            text = f.read(4096)
    except OSError:
        return None
    v = dict(re.findall(r"^(\w+)=(.*)$", text, re.M))
    out = {"zone": int(v["ZoneId"]) if v.get("ZoneId", "").strip().isdigit() else None}
    for k, name in (("HostUrl", "url"), ("ReferrerUrl", "ref")):
        u = v.get(k, "").strip()
        if u.lower().startswith(("http://", "https://")):
            out[name] = u
    host = urllib.parse.urlsplit(out.get("url") or out.get("ref") or "").hostname
    out["host"] = host.lower() if host else None
    ref_host = urllib.parse.urlsplit(out.get("ref") or "").hostname
    out["ref_host"] = ref_host.lower() if ref_host else None
    return out


def check_downloads(emit=print, folders=None, limit=20000, update=True):
    """Сайты, с которых скачаны программы и архивы в Загрузках и на Рабочем столе, против FMHY и Maltrail."""
    if update and not (os.path.exists(FMHY) and _fresh("fmhy")):
        try:
            update_fmhy(emit)
        except Exception as e:
            if not os.path.exists(FMHY):
                raise IntelError(f"список FMHY не скачался: {e}")
            emit(f"  список FMHY не обновился ({e}) — проверяю по прежнему")
    trails_ok = ensure_trails(emit) if update else os.path.exists(TRAILS)
    fm = json.load(open(FMHY, encoding="utf-8"))
    basic, plus, reasons = set(fm["basic"]), set(fm["plus"]), fm.get("reasons", {})
    folders = folders or download_folders()
    files, n_all, t0 = [], 0, time.time()
    for base in folders:
        for root, dirs, names in os.walk(base, onerror=lambda e: None):
            dirs[:] = [d for d in dirs if d.lower() not in ("node_modules", ".git", "$recycle.bin", "__pycache__", ".venv", "venv")]
            for n in names:
                n_all += 1
                if os.path.splitext(n)[1].lower() not in RISKY_DL:
                    continue
                p = os.path.join(root, n)
                z = zone_of(p)
                if z and (z.get("host") or z.get("ref_host")):
                    files.append((p, z))
                if len(files) >= limit:
                    break
            if len(files) >= limit or time.time() - t0 > 120:
                break
    emit(f"  папки: {', '.join(folders)}")
    emit(f"  программ и архивов с пометкой «скачано из интернета»: {len(files)} (всего файлов просмотрено: {n_all})")
    hosts = {h for _, z in files for h in (z.get("host"), z.get("ref_host")) if h}
    trail_hits = match_trails(hosts) if trails_ok and hosts else {}

    def fmhy_hit(h):
        for k in _keys_for_domain(h):
            if k in basic:
                return "bad", k
            if k in plus:
                return "warn", k
        return None, None

    items, by_host = [], {}
    for p, z in files:
        if z.get("host"):
            by_host[z["host"]] = by_host.get(z["host"], 0) + 1
        for h in dict.fromkeys(x for x in (z.get("host"), z.get("ref_host")) if x):
            lvl, key = fmhy_hit(h)
            th = trail_hits.get(h)
            if not (lvl or th):
                continue
            why = []
            if th:
                why.append(f"Maltrail: {_family(th[0])}")
            if lvl:
                r = reasons.get(key) or ""
                r = re.sub(r"\s*-\s*https?://\S+$", "", r).strip()
                why.append(("FMHY: опасный сайт" if lvl == "bad" else "FMHY: не рекомендуется") + (f" — {r}" if r else ""))
            # опасна только страница, с которой был переход, а сам файл — с другого сайта (softmany.com → softmany.net — это один и тот же)
            page_only = h != z.get("host") and _site(h) != _site(z.get("host"))
            level = "bad" if (th or lvl == "bad") and not page_only else "warn"
            if page_only and z.get("host"):
                why.append(f"сам файл пришёл с {z['host']} — если это официальный сайт программы, файл скорее всего в порядке")
            items.append({"path": p, "host": h, "via": "переход со страницы" if page_only else "файл скачан с" if h == z.get("host") else "скачан через страницу",
                          "level": level, "why": "; ".join(why), "url": z.get("url") or z.get("ref")})
            break
    top = sorted(((n, h) for h, n in by_host.items() if n), reverse=True)[:8]
    if top:
        emit("  чаще всего скачано с: " + ", ".join(f"{h} ({n})" for n, h in top))
    return {"files": len(files), "scanned": n_all, "items": items, "folders": folders, "top": top, "trails": trails_ok}


# ================================================================ OSV: пакеты разработчика

def _site_packages():
    """Папки site-packages всех найденных Python: текущий, установленные для пользователя и для всех."""
    import sys
    import glob
    la, ad = os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", "")
    pats = [os.path.join(sys.base_prefix, "Lib", "site-packages"), os.path.join(la, "Programs", "Python", "*", "Lib", "site-packages"),
            os.path.join(ad, "Python", "*", "site-packages"), r"C:\Python*\Lib\site-packages",
            os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Python*", "Lib", "site-packages")]
    out = {}
    for p in pats:
        for d in glob.glob(p):
            if os.path.isdir(d):
                out[os.path.normcase(d)] = d
    return list(out.values())


def _pip_dir(d, add, where):
    try:
        names = os.listdir(d)
    except OSError:
        return
    for n in names:
        if not n.endswith((".dist-info", ".egg-info")):
            continue
        md = os.path.join(d, n, "METADATA" if n.endswith(".dist-info") else "PKG-INFO")
        try:
            head = open(md, encoding="utf-8", errors="replace").read(4000)
        except OSError:
            continue
        name = re.search(r"^Name:\s*(.+)$", head, re.M)
        ver = re.search(r"^Version:\s*(.+)$", head, re.M)
        if name and ver:
            add("PyPI", name.group(1).strip(), ver.group(1).strip(), where)


def _npm_tree(nm, add, where, depth=0):
    """Установленные пакеты npm: node_modules/<пакет>/package.json и вложенные node_modules (до 6 уровней)."""
    if depth > 6:
        return
    try:
        names = os.listdir(nm)
    except OSError:
        return
    for n in names:
        if n.startswith("."):
            continue
        p = os.path.join(nm, n)
        subs = [os.path.join(p, x) for x in os.listdir(p)] if n.startswith("@") and os.path.isdir(p) else [p]
        for s in subs:
            try:
                pj = json.load(open(os.path.join(s, "package.json"), encoding="utf-8", errors="replace"))
                if pj.get("name") and pj.get("version"):
                    add("npm", pj["name"], pj["version"], where)
            except (OSError, ValueError):
                pass
            inner = os.path.join(s, "node_modules")
            if os.path.isdir(inner):
                _npm_tree(inner, add, where, depth + 1)


def _npm_lock(path, add):
    try:
        lock = json.load(open(path, encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return
    for key, v in (lock.get("packages") or {}).items():
        if key and isinstance(v, dict) and v.get("version") and not v.get("link"):
            add("npm", v.get("name") or key.split("node_modules/")[-1], v["version"], path)

    def walk(deps):
        for name, v in (deps or {}).items():
            if isinstance(v, dict) and v.get("version"):
                add("npm", name, v["version"], path)
                walk(v.get("dependencies"))
    if not lock.get("packages"):
        walk(lock.get("dependencies"))


def _requirements(path, add):
    try:
        for line in open(path, encoding="utf-8", errors="replace"):
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)", line)
            if m:
                add("PyPI", m.group(1), m.group(2), path)
    except OSError:
        pass


def inventory(target=None, emit=print):
    """Пакеты: глобальные npm и pip; если задана папка — ещё её lock-файлы, node_modules и виртуальные окружения."""
    pk = {}

    def add(eco, name, ver, where):
        ver = str(ver).strip()
        if not name or not ver or ver.startswith(("file:", "link:", "git", "http", "workspace:")):
            return
        k = (eco, name.lower() if eco == "PyPI" else name, ver)
        pk.setdefault(k, set()).add(where)

    if target:
        n = 0
        for root, dirs, names in os.walk(target, onerror=lambda e: None):
            low = root.lower()
            if os.path.basename(low) == "site-packages":
                _pip_dir(root, add, root)
                dirs[:] = []
                continue
            if "node_modules" in dirs:
                nm = os.path.join(root, "node_modules")
                if "package-lock.json" not in names and os.path.exists(os.path.join(nm, ".package-lock.json")):
                    _npm_lock(os.path.join(nm, ".package-lock.json"), add)
                elif "package-lock.json" not in names:
                    _npm_tree(nm, add, nm)
            dirs[:] = [d for d in dirs if d.lower() not in ("node_modules", ".git", "__pycache__", "$recycle.bin")]
            if "package-lock.json" in names:
                _npm_lock(os.path.join(root, "package-lock.json"), add)
            if "npm-shrinkwrap.json" in names:
                _npm_lock(os.path.join(root, "npm-shrinkwrap.json"), add)
            for f in names:
                if re.fullmatch(r"requirements[\w.\-]*\.txt", f.lower()):
                    _requirements(os.path.join(root, f), add)
            n += 1
            if n > 20000:
                emit("  папка очень большая — просмотрены первые 20 000 подпапок")
                break
    else:
        gnm = os.path.join(os.environ.get("APPDATA", ""), "npm", "node_modules")
        if os.path.isdir(gnm):
            _npm_tree(gnm, add, "npm (глобальные пакеты)")
        for sp in _site_packages():
            _pip_dir(sp, add, sp)
    return pk


def _osv_post(queries):
    req = urllib.request.Request(OSV_BATCH, data=json.dumps({"queries": queries}).encode(),
                                 headers={"User-Agent": "ScanHub", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r).get("results") or []


# не просто «malicious» — так пишут и об обычных уязвимостях («malicious input»); только про вредоносный сам пакет
_MAL_TEXT = re.compile(r"(embedded malicious code|malicious (code|package|version|release|dependency)|\bmalware\b|\bbackdoor|typosquat|"
                       r"compromised (package|version|release|account)|\bstealer\b)", re.I)


def _vuln_details(ids, limit=300):
    """Подробности уязвимостей (параллельно): нужно, чтобы узнать вредоносный код, записанный не как MAL-…, а как обычный GHSA
    с CWE-506 «встроенный вредоносный код» (так помечены старые случаи — event-stream, ctx и др.)."""
    from concurrent.futures import ThreadPoolExecutor

    def one(i):
        try:
            with _get(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(i)}", 30) as r:
                d = json.load(r)
            cwe = (d.get("database_specific") or {}).get("cwe_ids") or []
            sev = (d.get("database_specific") or {}).get("severity")
            return i, {"summary": d.get("summary") or "", "malicious": "CWE-506" in cwe or bool(_MAL_TEXT.search(d.get("summary") or "")),
                       "severity": sev}
        except Exception:
            return i, None
    ids = [i for i in dict.fromkeys(ids) if not i.startswith("MAL-")][:limit]
    with ThreadPoolExecutor(8) as ex:
        return {i: d for i, d in ex.map(one, ids) if d}


def check_packages(emit=print, target=None, stopped=lambda: False):
    pk = inventory(target, emit)
    if not pk:
        emit("  пакетов npm и pip не найдено" + (" в этой папке" if target else ""))
        return {"packages": 0, "malicious": [], "vulnerable": []}
    eco_n = {}
    for eco, _, _ in pk:
        eco_n[eco] = eco_n.get(eco, 0) + 1
    emit("  найдено пакетов: " + ", ".join(f"{e} — {n}" for e, n in sorted(eco_n.items())) +
         ". В OSV.dev уходят только названия и версии.")
    keys = sorted(pk)
    rows = []
    for i in range(0, len(keys), 1000):
        if stopped():
            break
        part = keys[i:i + 1000]
        res = _osv_post([{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in part])
        for (e, n, v), r in zip(part, res):
            ids = [x.get("id") for x in (r or {}).get("vulns") or [] if x.get("id")]
            if ids:
                rows.append({"ecosystem": e, "name": n, "version": v, "ids": ids, "where": sorted(pk[(e, n, v)])[:3],
                             "link": f"https://osv.dev/vulnerability/{ids[0]}"})
        emit(f"  сверено с OSV: {min(i + 1000, len(keys))} из {len(keys)}")
    det = _vuln_details([i for r in rows for i in r["ids"]]) if rows and not stopped() else {}
    mal, vul = [], []
    for r in rows:
        bad = [i for i in r["ids"] if i.startswith("MAL-") or det.get(i, {}).get("malicious")]
        if bad:
            r.update(link=f"https://osv.dev/vulnerability/{bad[0]}", summary=next((det[i]["summary"] for i in bad if i in det), ""))
            mal.append(r)
        else:
            sev = [det.get(i, {}).get("severity") for i in r["ids"]]
            r["severity"] = next((x for x in ("CRITICAL", "HIGH", "MODERATE", "LOW") if x in sev), None)
            vul.append(r)
    vul.sort(key=lambda r: ["CRITICAL", "HIGH", "MODERATE", "LOW", None].index(r["severity"]))
    return {"packages": len(keys), "malicious": mal, "vulnerable": vul}


# ================================================================ LOLDrivers: уязвимые и вредоносные драйверы

LOL_URL = "https://www.loldrivers.io/api/drivers.json"
LOL = os.path.join(IDIR, "loldrivers.json")
DRV_CACHE = os.path.join(IDIR, "drvhash.json")


def update_loldrivers(emit=print):
    """База LOLDrivers (~33 МБ JSON) → компактный список хэшей: sha256 → [категория, имя, продукт, компания, грузится при HVCI]."""
    emit("  скачиваю базу LOLDrivers (~33 МБ)…")
    with _get(LOL_URL, 300) as r:
        data = json.load(r)
    db = {}
    for d in data:
        cat = "malicious" if str(d.get("Category", "")).lower().startswith("malicious") else "vulnerable"
        tag = (d.get("Tags") or [""])[0]
        for s in d.get("KnownVulnerableSamples") or []:
            for h in (s.get("SHA256"), (s.get("Authentihash") or {}).get("SHA256")):
                if h and re.fullmatch(r"[0-9a-fA-F]{64}", h):
                    db[h.lower()] = [cat, s.get("Filename") or s.get("OriginalFilename") or tag, s.get("Product") or "", s.get("Company") or "",
                                     str(s.get("LoadsDespiteHVCI", "")).upper() == "TRUE", d.get("Id")]
    if len(db) < 500:
        raise IntelError("база LOLDrivers пришла неполной")
    now = datetime.now().isoformat(timespec="seconds")
    os.makedirs(IDIR, exist_ok=True)
    with open(LOL + ".tmp", "w", encoding="utf-8") as f:
        json.dump(db, f)
    os.replace(LOL + ".tmp", LOL)
    info = {"version": now[:10], "count": len(data), "hashes": len(db), "updated": now, "checked": now}
    _save_meta("loldrivers", info)
    emit(f"  база LOLDrivers обновлена: драйверов {len(data)}, отпечатков {len(db)}")
    return info


def _loaded_drivers():
    """Драйверы, загруженные в ядро прямо сейчас (EnumDeviceDrivers) → полные пути."""
    import ctypes
    from ctypes import wintypes
    psapi = ctypes.WinDLL("psapi")
    arr = (ctypes.c_void_p * 4096)()
    need = wintypes.DWORD()
    if not psapi.EnumDeviceDrivers(arr, ctypes.sizeof(arr), ctypes.byref(need)):
        return set()
    out, buf = set(), ctypes.create_unicode_buffer(1024)
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    psapi.GetDeviceDriverFileNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    for i in range(min(need.value // ctypes.sizeof(ctypes.c_void_p), 4096)):
        if arr[i] and psapi.GetDeviceDriverFileNameW(arr[i], buf, 1024):
            p = buf.value
            p = re.sub(r"^\\SystemRoot\\", sysroot.replace("\\", "\\\\") + "\\\\", p, flags=re.I)
            p = re.sub(r"^\\\?\?\\", "", p)
            if p.lower().startswith("\\windows\\"):
                p = os.path.splitdrive(sysroot)[0] + p
            out.add(os.path.normcase(p))
    if not out:
        # без прав администратора новые сборки Windows скрывают адреса драйверов — берём работающие службы-драйверы
        import system
        paths = system.as_list(system.ps("Get-CimInstance Win32_SystemDriver -Filter \"State='Running'\" | "
                                         "Select-Object -ExpandProperty PathName | ConvertTo-Json -Compress", timeout=90)) or []
        for p in paths:
            p = re.sub(r"^\\\?\?\\", "", str(p).strip('"'))
            out.add(os.path.normcase(os.path.expandvars(p)))
    return out


def _driver_services():
    """Службы-драйверы (тип 1/2) и путь к их файлу: так находятся драйверы вне System32 (утилиты вентиляторов, античиты, «чистильщики»)."""
    out = {}
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    except OSError:
        return out
    i = 0
    while True:
        try:
            name = winreg.EnumKey(root, i)
        except OSError:
            break
        i += 1
        try:
            with winreg.OpenKey(root, name) as k:
                typ = winreg.QueryValueEx(k, "Type")[0]
                if typ not in (1, 2):
                    continue
                img = str(winreg.QueryValueEx(k, "ImagePath")[0])
                start = winreg.QueryValueEx(k, "Start")[0]
        except OSError:
            continue
        img = os.path.expandvars(img.strip('"'))
        img = re.sub(r"^\\SystemRoot\\", sysroot.replace("\\", "\\\\") + "\\\\", img, flags=re.I)
        img = re.sub(r"^\\\?\?\\", "", img)
        if img.lower().startswith("system32\\"):
            img = os.path.join(sysroot, img)
        out[os.path.normcase(img)] = {"service": name, "start": start}
    return out


def check_drivers(emit=print, update=True, deep=False):
    """Драйверы на ПК против LOLDrivers: загруженные, зарегистрированные службы, System32\\drivers (+ DriverStore при deep)."""
    import glob
    if update and not (os.path.exists(LOL) and _fresh("loldrivers", 7 * 24)):   # база меняется медленно, а сервер отдаёт её минутами
        try:
            update_loldrivers(emit)
        except Exception as e:
            if not os.path.exists(LOL):
                raise IntelError(f"база LOLDrivers не скачалась: {e}")
            emit(f"  база LOLDrivers не обновилась ({e}) — проверяю по прежней")
    db = json.load(open(LOL, encoding="utf-8"))
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    loaded, services = _loaded_drivers(), _driver_services()
    paths = set(loaded) | set(services)
    paths |= {os.path.normcase(p) for p in glob.glob(os.path.join(sysroot, "System32", "drivers", "*.sys"))}
    if deep:
        paths |= {os.path.normcase(p) for p in glob.glob(os.path.join(sysroot, "System32", "DriverStore", "FileRepository", "*", "*.sys"))}
    try:
        cache = json.load(open(DRV_CACHE, encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    new_cache, hits, n = {}, [], 0
    t0 = time.time()
    for p in sorted(paths):
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_size > 64 * 2 ** 20:
            continue
        key = f"{st.st_size}:{int(st.st_mtime)}"
        h = cache.get(p, {}).get(key) if isinstance(cache.get(p), dict) else None
        if not h:
            try:
                hh = hashlib.sha256()
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        hh.update(chunk)
                h = hh.hexdigest()
            except OSError:
                continue
        new_cache[p] = {key: h}
        n += 1
        if h in db:
            cat, name, product, company, hvci_ok, lid = db[h]
            svc = services.get(p)
            hits.append({"path": p, "sha256": h, "category": cat, "name": name, "product": product, "company": company,
                         "loads_despite_hvci": hvci_ok, "loaded": p in loaded, "service": svc["service"] if svc else None,
                         "start": svc["start"] if svc else None, "link": f"https://www.loldrivers.io/drivers/{lid}/" if lid else LOL_URL})
    try:
        with open(DRV_CACHE + ".tmp", "w", encoding="utf-8") as f:
            json.dump(new_cache, f)
        os.replace(DRV_CACHE + ".tmp", DRV_CACHE)
    except OSError:
        pass
    emit(f"  проверено драйверов: {n} (загружено сейчас: {len(loaded)}, служб-драйверов: {len(services)}) за {time.time() - t0:.1f} с")
    import tweaks
    bl = tweaks._rv("HKLM", r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable")
    hvci = tweaks._rv("HKLM", tweaks.CI_HVCI, "Enabled") == 1
    return {"checked": n, "hits": hits, "blocklist": bl != 0, "hvci": hvci}


# частые уязвимые драйверы без сведений о версии — чья это программа
DRV_OWNERS = {"pwdrvio.sys": "MiniTool Partition Wizard", "pwdspio.sys": "MiniTool Partition Wizard", "rtcore64.sys": "MSI Afterburner",
              "rtcore32.sys": "MSI Afterburner", "gdrv.sys": "Gigabyte App Center / утилиты Gigabyte", "winring0x64.sys": "утилита мониторинга "
              "(FanControl, OpenHardwareMonitor, Libre Hardware Monitor и др.)", "winring0.sys": "утилита мониторинга", "dbutil_2_3.sys": "Dell BIOS/Update",
              "asio.sys": "ASUS AI Suite", "asio64.sys": "ASUS AI Suite", "atszio64.sys": "ASUS", "aswarpot.sys": "Avast/AVG",
              "inpoutx64.sys": "утилита работы с портами (InpOut)", "ene.sys": "подсветка RGB (ENE)", "cpuz141_x64.sys": "CPU-Z",
              "procexp152.sys": "Process Explorer", "speedfan.sys": "SpeedFan", "hwinfo64a.sys": "HWiNFO (старая версия)"}


def driver_owner(h):
    """Чей драйвер: подпись (издатель), программа из списка установленных и папка в Program Files с тем же названием."""
    import system
    name = os.path.basename(h["path"]).lower()
    sig = system.signatures([h["path"]]).get(h["path"]) or {}
    m = re.search(r'CN="?([^",]+)', sig.get("signer") or "")
    sig["signer"] = m.group(1).strip() if m else (sig.get("signer") or "")
    signer = re.sub(r"\s*(Ltd|LLC|Inc|Co\.?|Corporation|Corp|GmbH|Limited|Solution|Software|Technology|Technologies)\.?$", "",
                    sig.get("signer") or "", flags=re.I).strip()
    word = (signer.split() or [""])[0].lower() if signer else ""
    guess = DRV_OWNERS.get(name, "")
    keys = {k for k in (word, (guess.split() or [""])[0].lower()) if len(k) >= 3}
    apps = [a for a in system.installed_apps() if keys and any(k in (a["name"] + " " + a.get("publisher", "")).lower() for k in keys)]
    dirs = []
    for root in (os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
        try:
            dirs += [os.path.join(root, d) for d in os.listdir(root) if keys and any(k in d.lower() for k in keys)]
        except OSError:
            pass
    return {"signer": sig.get("signer") or "", "signed": sig.get("status") == "Valid", "program": guess or (apps[0]["name"] if apps else ""),
            "apps": [a["name"] for a in apps][:3], "dirs": dirs[:3]}


def live_driver(h, r):
    """Уязвимый драйвер реально опасен, если он работает или стартует с Windows и его не блокирует целостность памяти.
    Загруженный сейчас — опасен всегда: раз загрузился, значит, защита его не остановила."""
    if h["loaded"]:
        return h["start"] != 4                  # отключён (Start=4), но ещё в памяти — исчезнет после перезагрузки
    return bool(h["service"] and h["start"] != 4) and not (r["hvci"] and not h["loads_despite_hvci"])


def pending_driver(h):
    """Отключён ScanHub или вручную, но ещё загружен: уйдёт после перезагрузки."""
    return bool(h["loaded"] and h["start"] == 4 and h["category"] != "malicious")


def _drv_text(h, r):
    where = "уже отключён, работает до перезагрузки" if h["loaded"] and h["start"] == 4 else "загружен сейчас" if h["loaded"] else f"служба {h['service']}" + (" (выключена)" if h["start"] == 4 else "") if h["service"] else "лежит на диске, не загружен"
    who = " · ".join(x for x in (h["product"], h["company"]) if x)
    if h["category"] == "malicious":
        return f"ВРЕДОНОСНЫЙ драйвер {h['name'] or os.path.basename(h['path'])} — {where}" + (f" · {who}" if who else "")
    blocked = r["hvci"] and not h["loads_despite_hvci"] and not h["loaded"]
    return (f"уязвимый драйвер {h['name'] or os.path.basename(h['path'])} — {where}" + (f" · {who}" if who else "") +
            (" · целостность памяти не даст его загрузить" if blocked else " · его можно использовать для отключения антивируса"))


# ================================================================ MalExt Sentry: вредоносные расширения браузеров

MALEXT_URL = "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/malicious_extensions_detailed.csv"
MALEXT = os.path.join(IDIR, "malext.json")
MALEXT_BAD = ("malware", "spyware", "adware", "search hijacking", "bundling unwanted software", "potentially unwanted software",
              "critical vulnerability")
MALEXT_RU = {"malware": "вредонос", "spyware": "шпион", "adware": "рекламное ПО", "search hijacking": "угонщик поиска",
             "bundling unwanted software": "ставит нежелательные программы", "policy violation": "нарушение правил магазина",
             "removal reason unknown": "причина удаления неизвестна", "in store but suspicious": "подозрительное (ещё в магазине)",
             "potentially unwanted software": "нежелательная программа", "critical vulnerability": "критическая уязвимость"}
_malext_cache = {}


def malext_reason(r):
    return MALEXT_RU.get(str(r).lower(), r)


def update_malext(emit=print):
    import csv
    with _get(MALEXT_URL, 120) as r:
        text = r.read().decode("utf-8", "replace").lstrip("﻿")
    db = {}
    for row in csv.DictReader(io.StringIO(text)):
        i = (row.get("extension_id") or "").strip().lower()
        if re.fullmatch(r"[a-p]{32}", i):
            reason = (row.get("reason") or "").strip()
            db[i] = {"name": row.get("name") or "", "reason": reason, "store": row.get("store") or "",
                     "date": row.get("insert_date_fmt") or "", "bad": reason.lower() in MALEXT_BAD}
    if len(db) < 1000:
        raise IntelError("база MalExt пришла неполной")
    os.makedirs(IDIR, exist_ok=True)
    with open(MALEXT + ".tmp", "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False)
    os.replace(MALEXT + ".tmp", MALEXT)
    now = datetime.now().isoformat(timespec="seconds")
    info = {"version": now[:10], "count": len(db), "updated": now, "checked": now}
    _save_meta("malext", info)
    _malext_cache.clear()
    emit(f"  база вредоносных расширений обновлена: {len(db)}")
    return info


def malext_db(update=True):
    """{id расширения: {...}}; обновляется не чаще раза в сутки, без интернета — прежняя."""
    if update and not (os.path.exists(MALEXT) and _fresh("malext")):
        try:
            update_malext(lambda s: None)
        except Exception:
            pass
    if not os.path.exists(MALEXT):
        return {}
    mt = os.path.getmtime(MALEXT)
    if _malext_cache.get("mt") != mt:
        _malext_cache.update(db=json.load(open(MALEXT, encoding="utf-8")), mt=mt)
    return _malext_cache["db"]


# ================================================================ корневые сертификаты (Sysinternals Sigcheck)

# (шаблон по имени/издателю, уровень, пояснение). bad — известные перехватчики HTTPS; info — законные, но стоит знать; dev — ставил сам?
CERT_KNOWN = [
    (r"superfish|edellroot|dsdtestprovider|privdog|komodia|qaznet trust|qaznet", "bad",
     "известный перехватчик HTTPS (реклама или слежка) — удали"),
    (r"куәландырушы орталық|қуәландырушы|national certification authority|нуц рк|гос.*казахстан", "info",
     "Национальный удостоверяющий центр Казахстана — нужен для ЭЦП и eGov. Если не пользуешься ЭЦП на этом ПК, можно удалить"),
    (r"russian trusted (root|sub) ca|минцифры", "info",
     "сертификат Минцифры России — ставится для госсайтов и банков РФ. Технически позволяет перехватывать HTTPS; удали, если не нужен"),
    (r"eset ssl filter|kaspersky|adguard|avast|avg web|bitdefender|dr\.?web|norton|mcafee|sophos|zscaler|netfilter|glasswire|comodo",
     "info", "фильтрация HTTPS антивирусом или блокировщиком рекламы — нормально, если эта программа у тебя установлена"),
    (r"fiddler|charles|mitmproxy|burp|portswigger|httptoolkit|proxyman|mkcert|development ca|localhost|docker|asp\.net core https",
     "dev", "сертификат инструмента разработчика (прокси-отладчик или локальный HTTPS) — нормально, если ты ставил его сам"),
    (r"cloudflare|warp|nordvpn|proton|expressvpn|surfshark|windscribe|hotspot shield|psiphon|outline|amnezia|kaspersky vpn", "info",
     "сертификат VPN или защищённого DNS — нормально, если этот VPN у тебя стоит"),
    (r"lenovo|hewlett|\bhp\b|\bdell\b|\basus|\bacer\b|\bmsi\b|gigabyte|\bintel\b|nvidia|\bamd\b|realtek|logitech|razer|steelseries", "info",
     "сертификат производителя ПК или устройства — ставится его фирменными программами, обычно безвреден"),
    (r"faceit|vanguard|riot|esea|battleye|easy ?anti|xigncode|nprotect", "info", "сертификат античита игры — нормально, если ты играешь в эту игру"),
    (r"fortinet|fortigate|palo alto|check ?point|cisco|umbrella|forcepoint|netskope|websense|bluecoat|symantec web", "info",
     "корпоративная фильтрация HTTPS — нормально на рабочем или учебном компьютере, странно на домашнем"),
    (r"microsoft|windows", "info", "сертификат Microsoft, которого нет в публичном списке (тестовый или для разработки)"),
]
# что такое корневой сертификат — одной строкой для итогов проверки
CERT_EXPLAIN = ("Что это: корневой сертификат — «доверенная печать» для защищённых сайтов (HTTPS). Неизвестные чаще всего ставят VPN, "
                "антивирусы, программы банков и госуслуг, фирменные утилиты ноутбука или инструменты разработчика — это не вирус. "
                "Опасен только перехватчик HTTPS (помечен ⚠): через него можно подсматривать пароли на сайтах.")


def _sigcheck_rows(exe, args):
    import subprocess
    r = subprocess.run([exe, "-accepteula", "-nobanner", *args, "-c", "*"], capture_output=True, timeout=180, creationflags=0x08000000)
    raw = r.stdout
    text = raw.decode("utf-16", "replace") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or raw[1:2] == b"\x00" else raw.decode("utf-8", "replace")
    import csv
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith("Store,Subject")), None)
    if start is None:
        return [], text
    rows = []
    # в данных у Sigcheck на одно поле больше, чем в заголовке (пустое перед серийным номером), — разбираем по смыслу, а не по колонкам
    for r in csv.reader(io.StringIO("\n".join(lines[start + 1:]))):
        if len(r) < 8:
            continue                                     # «No certificates found.» и пустые строки
        thumb = next((x for x in reversed(r) if re.fullmatch(r"[0-9A-Fa-f]{40}", x.replace(" ", ""))), "")
        rows.append({"Store": r[0], "Subject": r[1], "Issuer": r[4], "Thumbprint": thumb.replace(" ", ""),
                     "Valid from": r[-2], "Valid to": r[-1]})
    return rows, text


def check_rootcerts(exe, emit=print):
    rows = []
    for args, where in ((["-tv"], "компьютер"), (["-tuv"], "пользователь")):
        r, text = _sigcheck_rows(exe, args)
        if not r and "No certificates found" not in text and "certificates" not in text.lower():
            emit(f"  sigcheck ({where}): {text.strip()[-300:]}")
        rows += r
    out = []
    for row in rows:
        subj, issuer = row.get("Subject", ""), row.get("Issuer", "")
        lvl, why = "warn", ("неизвестный: его нет в списке доверенных Microsoft. Скорее всего его поставила какая-то программа (VPN, банк, "
                            "утилита ноутбука). Если ни одна такая программа у тебя не стоит — удали его")
        for rx, l, w in CERT_KNOWN:
            if re.search(rx, f"{subj} {issuer}", re.I):
                lvl, why = l, w
                break
        out.append({"store": row.get("Store", ""), "subject": subj, "issuer": issuer, "thumb": row.get("Thumbprint", ""),
                    "from": row.get("Valid from", ""), "to": row.get("Valid to", ""), "level": lvl, "why": why})
    return out


# ================================================================ запуск из карточки ScanHub

def handle(name, exe, target, emit, stopped, details):
    """Скачиваемый инструмент, вывод которого ScanHub разбирает сам (mode "handler")."""
    if name == "rootcerts":
        emit("  сверяю корневые сертификаты компьютера и пользователя со списком доверенных Microsoft (нужен интернет)…")
        certs = check_rootcerts(exe, emit)
        for c in certs:
            mark = {"bad": "  ✕ ", "warn": "  ! ", "dev": "  · ", "info": "  · "}[c["level"]]
            emit(f"{mark}{c['subject']} [{c['store']}] — {c['why']}")
            emit(f"      отпечаток {c['thumb']}, действует {c['from']} — {c['to']}")
            details.append(c)
        if any(c["level"] in ("bad", "warn") for c in certs):
            emit("\nУдалить: «Сертификаты пользователя» (certmgr.msc) или «Сертификаты компьютера» (certlm.msc) → Доверенные корневые центры → "
                 "найди по имени или отпечатку → Удалить. Кнопки «Открыть» — в карточке.")
        bad = [c for c in certs if c["level"] == "bad"]
        warn = [c for c in certs if c["level"] == "warn"]
        if bad:
            return 1, ["threat", f"Перехватчики HTTPS: {len(bad)}"]
        if warn:
            return 2, ["suspicious", f"Неизвестные корневые сертификаты: {len(warn)}"]
        return 0, ["clean", f"Посторонних нет" + (f" (известных: {len(certs)})" if certs else "")]
    raise IntelError(f"неизвестный обработчик {name}")

def run(builtin, mode_id, target, emit, stopped, details):
    """Встроенная проверка: вернуть (код, [вердикт, подпись])."""
    target = os.path.normpath(target) if target else None
    if mode_id == "update":
        if builtin == "netintel":
            _save_meta("trails_accepted", datetime.now().isoformat(timespec="seconds"))   # человек сам нажал «Скачать базы»
            i = update_trails(emit, force=True)
            return 0, ["clean", f"Базы обновлены: {i['count']:,} адресов".replace(",", " ")]
        if builtin == "origin":
            update_fmhy(emit)
            ensure_trails(emit)
            return 0, ["clean", "Списки обновлены"]
    if builtin == "byovd":
        if mode_id == "update":
            i = update_loldrivers(emit)
            return 0, ["clean", f"База обновлена: {i['count']} драйверов"]
        r = check_drivers(emit, deep=(mode_id == "deep"))
        for h in r["hits"]:
            emit(("  ✕ " if h["category"] == "malicious" else "  ! ") + _drv_text(h, r))
            emit(f"      {h['path']} · {h['link']}")
            details.append(h)
        emit("  блок-лист уязвимых драйверов Microsoft: " + ("включён" if r["blocklist"] else "ВЫКЛЮЧЕН — включи в «Приватность и защита → Защита Windows»")
             + "; целостность памяти: " + ("включена" if r["hvci"] else "выключена"))
        mal = [h for h in r["hits"] if h["category"] == "malicious"]
        live = [h for h in r["hits"] if h["category"] != "malicious" and live_driver(h, r)]
        if r["hits"]:
            emit("\nУязвимый драйвер — не вирус: его ставит обычная программа (мониторинг, вентиляторы, RGB, античит). Но вирус может загрузить "
                 "его и выключить антивирус. Если программа, которая его поставила, не нужна — удали её; если нужна — обнови до новой версии.")
        if mal:
            return 1, ["threat", f"Вредоносные драйверы: {len(mal)}"]
        if live:
            return 2, ["suspicious", f"Уязвимые драйверы в работе: {len(live)}"]
        if any(pending_driver(h) for h in r["hits"]):
            return 0, ["unknown", "Уязвимый драйвер отключён — перезагрузи компьютер, чтобы он выгрузился"]
        if r["hits"]:
            return 0, ["unknown", f"Уязвимые драйверы на диске (не работают): {len(r['hits'])}"]
        return 0, ["clean", f"Проверено драйверов: {r['checked']}, известных уязвимых нет"]
    if builtin == "malext":
        if mode_id == "update":
            i = update_malext(emit)
            return 0, ["clean", f"База обновлена: {i['count']} расширений"]
        import browsers
        db = malext_db()
        emit(f"  база вредоносных расширений: {len(db)} (MalExt Sentry)")
        r = browsers.audit()
        emit(f"  браузеры: {', '.join(r['browsers']) or 'не найдены'}; расширений: {len(r['extensions'])}")
        hits = [e for e in r["extensions"] if e.get("malext")]
        for e in hits:
            mx = e["malext"]
            emit(("  ✕ " if mx["bad"] else "  ! ") + f"{e['browser']}: «{e['name']}» ({e['id']}) — {malext_reason(mx['reason'])}, удалено из магазина"
                 + (f" {mx['date']}" if mx.get("date") else ""))
            details.append({"browser": e["browser"], "name": e["name"], "id": e["id"], **mx})
        if hits:
            emit("\nУдали эти расширения в самом браузере (меню → Расширения). Если среди них было вредоносное — смени пароли от важных сайтов: "
                 "такие расширения часто крадут вход и куки.")
        bad = [e for e in hits if e["malext"]["bad"]]
        if bad:
            return 1, ["threat", f"Вредоносные расширения: {len(bad)}"]
        if hits:
            return 2, ["suspicious", f"Удалённые из магазина расширения: {len(hits)}"]
        return 0, ["clean", f"Проверено расширений: {len(r['extensions'])}, в базе нет ни одного"]
    if builtin == "netintel":
        r = check_network(emit)
        if not r["ok"]:
            return 3, ["error", "Нет баз Maltrail"]
        for h in r["hits"]:
            emit(("  ✕ " if h["level"] == "bad" else "  ! ") + h["text"])
            details.append(h)
        bad = [h for h in r["hits"] if h["level"] == "bad"]
        if bad:
            emit("\nПроцесс, который соединяется с адресом вредоноса, стоит проверить на вирусы (кнопка в «Ресурсах» или «Проверить программу»).")
            return 1, ["threat", f"Соединения с вредоносами: {len(bad)}"]
        if r["hits"]:
            emit("\nОбращения из кэша DNS — это адреса, которые компьютер недавно открывал: часто это реклама или заражённые сайты в браузере, "
                 "а не вирус на ПК. Насторожиться стоит, если адрес повторяется и браузер был закрыт.")
            return 2, ["suspicious", f"Обращения к опасным адресам: {len(r['hits'])}"]
        emit("  совпадений с базами вредоносов нет")
        return 0, ["clean", "Опасных адресов нет"]
    if builtin == "origin":
        folders = [target] if target and os.path.isdir(target) else None
        r = check_downloads(emit, folders)
        for it in r["items"]:
            emit(("  ✕ " if it["level"] == "bad" else "  ! ") + f"{os.path.basename(it['path'])} — {it['via']} {it['host']}: {it['why']}")
            emit(f"      {it['path']}")
            details.append(it)
        bad = [i for i in r["items"] if i["level"] == "bad"]
        if bad:
            emit("\nФайлы с опасных сайтов лучше удалить или проверить на вирусы (перетащи их в окно ScanHub). Программу скачай заново с официального сайта.")
            return 2, ["suspicious", f"Скачано с опасных сайтов: {len(bad)}"]
        if r["items"]:
            return 0, ["clean", f"С не рекомендуемых сайтов: {len(r['items'])}"]
        return 0, ["clean", f"Проверено файлов: {r['files']}, всё с обычных сайтов" if r["files"] else "Скачанных программ нет"]
    if builtin == "osv":
        if target and not os.path.isdir(target):
            raise IntelError("укажи папку проекта")
        r = check_packages(emit, target if target else None, stopped)
        for row in r["malicious"]:
            emit(f"  ✕ {row['ecosystem']} {row['name']}@{row['version']} — ВРЕДОНОСНЫЙ ПАКЕТ ({', '.join(row['ids'][:3])}) · {row['link']}"
                 + (f"\n      {row['summary']}" if row.get("summary") else ""))
            emit(f"      где: {'; '.join(row['where'])}")
            details.append({**row, "level": "bad"})
        for row in r["vulnerable"][:60]:
            sev = {"CRITICAL": "критично", "HIGH": "высокая опасность", "MODERATE": "средняя", "LOW": "низкая"}.get(row.get("severity"), "")
            emit(f"  · {row['ecosystem']} {row['name']}@{row['version']} — уязвимостей: {len(row['ids'])}{', ' + sev if sev else ''} "
                 f"({', '.join(row['ids'][:3])}{'…' if len(row['ids']) > 3 else ''}) · {row['link']}")
            details.append({**row, "level": "warn"})
        if len(r["vulnerable"]) > 60:
            emit(f"  …и ещё {len(r['vulnerable']) - 60} пакетов с уязвимостями")
        if r["malicious"]:
            emit("\nВредоносный пакет крадёт ключи и пароли при установке. Удали его, смени токены и пароли, которые были на этом ПК, "
                 "и проверь компьютер глубокой проверкой.")
            return 1, ["threat", f"Вредоносные пакеты: {len(r['malicious'])}"]
        if r["vulnerable"]:
            emit("\nУязвимости — не вирусы: это известные ошибки в старых версиях. Обнови пакеты (npm update / pip install -U), когда будет время.")
            return 0, ["unknown", f"Пакетов с уязвимостями: {len(r['vulnerable'])} из {r['packages']}"]
        return 0, ["clean", f"Проверено пакетов: {r['packages']}, всё чисто" if r["packages"] else "Пакетов не найдено"]
    raise IntelError(f"неизвестная проверка {builtin}")
