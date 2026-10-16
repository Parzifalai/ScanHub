"""История здоровья ПК: раз в день снимок (батарея, место на дисках, индекс стабильности, сбои) — видно, что деградирует.

* Снимок делается при запуске ScanHub и Сторожем (если включён), не чаще раза в сутки. Без постоянных фоновых процессов.
* Батарея: Windows сама хранит историю ёмкости (отчёт powercfg) — её видно сразу, на годы назад.
* Сбои за прошлые 30 дней берутся из уже собранного разбора сбоев (data\\diag.json), дальше копятся по дням.
* Место на дисках копится с первого снимка: тренд появится через неделю.
Всё хранится только на этом компьютере: data\\health_history.json.
"""
import json
import os
import shutil
import subprocess
import tempfile
import time
from datetime import date, datetime, timedelta

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
FILE = os.path.join(DATA, "health_history.json")
NO_WINDOW = 0x08000000
KEEP_DAYS = 800

EVENTS_PS = r"""$since = (Get-Date).AddDays(-1)
$q = @(
 @{LogName='Application'; ProviderName='Application Error'; Id=1000; StartTime=$since},
 @{LogName='Application'; ProviderName='Application Hang'; Id=1002; StartTime=$since},
 @{LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'; Id=1001; StartTime=$since},
 @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41; StartTime=$since},
 @{LogName='System'; ProviderName='Display'; Id=4101; StartTime=$since})
$n = @{}
foreach ($f in $q) { $n[$f.ProviderName] = @(Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue).Count }
$s = Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction SilentlyContinue | Sort-Object TimeGenerated | Select-Object -Last 1
[pscustomobject]@{ crashes = $n['Application Error']; hangs = $n['Application Hang']; bsod = $n['Microsoft-Windows-WER-SystemErrorReporting'];
  shutdowns = $n['Microsoft-Windows-Kernel-Power']; gpu = $n['Display']; stability = $(if ($s) { [math]::Round($s.SystemStabilityIndex, 2) }) } | ConvertTo-Json -Compress"""


def _ps(script, timeout=120):
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, timeout=timeout,
                           creationflags=NO_WINDOW)
        out = r.stdout.decode("utf-8", "replace").strip()
        return json.loads(out) if out else None
    except Exception:
        return None


def _load():
    try:
        return json.load(open(FILE, encoding="utf-8"))
    except (OSError, ValueError):
        return {"days": [], "battery": [], "created": date.today().isoformat()}


def _save(h):
    os.makedirs(DATA, exist_ok=True)
    with open(FILE + ".tmp", "w", encoding="utf-8") as f:
        json.dump(h, f, ensure_ascii=False)
    os.replace(FILE + ".tmp", FILE)


def battery():
    """Текущая ёмкость и вся история ёмкости из отчёта Windows (без прав администратора)."""
    tmp = os.path.join(tempfile.gettempdir(), f"scanhub-bat-{os.getpid()}.xml")
    try:
        subprocess.run(["powercfg", "/batteryreport", "/xml", "/output", tmp], capture_output=True, timeout=60, creationflags=NO_WINDOW)
        import xml.etree.ElementTree as ET
        root = ET.parse(tmp).getroot()
    except Exception:
        return None, []
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    strip = lambda t: t.split("}", 1)[-1]
    find = lambda el, name: next((c for c in el.iter() if strip(c.tag) == name), None)
    bats = find(root, "Batteries")
    b = next((c for c in bats if strip(c.tag) == "Battery"), None) if bats is not None else None
    if b is None:
        return None, []
    val = lambda el, n: (find(el, n).text if find(el, n) is not None else None)
    num = lambda x: int(x) if x and str(x).isdigit() else None
    now = {"design": num(val(b, "DesignCapacity")), "full": num(val(b, "FullChargeCapacity")), "cycles": num(val(b, "CycleCount"))}
    hist = []
    histel = find(root, "History")
    for e in (histel if histel is not None else []):
        if strip(e.tag) != "HistoryEntry":
            continue
        full, design = num(e.get("FullChargeCapacity")), num(e.get("DesignCapacity"))
        end = (e.get("EndDate") or "")[:10]
        if full and design and end:
            hist.append({"d": end, "pct": round(full * 100 / design, 1)})
    return now, hist


def _disks():
    out = {}
    try:
        import psutil
        for p in psutil.disk_partitions():
            if "fixed" not in (p.opts or "") and p.fstype not in ("NTFS", "ReFS", "exFAT", "FAT32"):
                continue
            try:
                u = shutil.disk_usage(p.mountpoint)
            except OSError:
                continue
            out[p.mountpoint.rstrip("\\")] = {"free": round(u.free / 2 ** 30, 1), "total": round(u.total / 2 ** 30, 1)}
    except Exception:
        pass
    return out


def _backfill_crashes(h):
    """Сбои по дням за прошлый месяц из разбора сбоев — чтобы график был не пустым с первого дня."""
    try:
        d = json.load(open(os.path.join(DATA, "diag.json"), encoding="utf-8"))
    except (OSError, ValueError):
        return
    per = {}
    add = lambda t, k: per.setdefault(str(t)[:10], {}).__setitem__(k, per.get(str(t)[:10], {}).get(k, 0) + 1)
    for c in d.get("crashes") or []:
        for i in c.get("items") or []:
            add(i["t"], "crashes")
    for x in d.get("hangs") or []:
        for i in x.get("items") or []:
            add(i["t"], "hangs")
    for b in d.get("bsod") or []:
        add(b["t"], "bsod")
    for s in d.get("shutdowns") or []:
        add(s["t"], "shutdowns")
    for g in d.get("gpu") or []:
        add(g["t"], "gpu")
    stab = {x["d"]: x["v"] for x in d.get("stability") or []}
    known = {x["d"] for x in h["days"]}
    for day in sorted(set(per) | set(stab)):
        if day not in known and day < date.today().isoformat():
            h["days"].append({"d": day, "events": per.get(day, {}), "stability": stab.get(day), "backfill": True})
    h["days"].sort(key=lambda x: x["d"])


def snapshot(force=False):
    """Снимок за сегодня (если ещё не было). Возвращает True, если записал."""
    h = _load()
    today = date.today().isoformat()
    if not force and any(x["d"] == today and not x.get("backfill") for x in h["days"]):
        return False
    if not h.get("backfilled"):
        _backfill_crashes(h)
        h["backfilled"] = True
    now, hist = battery()
    ev = _ps(EVENTS_PS) or {}
    entry = {"d": today, "t": datetime.now().isoformat(timespec="minutes"), "disks": _disks(),
             "events": {k: ev.get(k) or 0 for k in ("crashes", "hangs", "bsod", "shutdowns", "gpu")}, "stability": ev.get("stability")}
    if now and now.get("design"):
        entry["battery"] = {**now, "pct": round(now["full"] * 100 / now["design"], 1) if now.get("full") else None}
    h["days"] = [x for x in h["days"] if x["d"] != today] + [entry]
    cut = (date.today() - timedelta(days=KEEP_DAYS)).isoformat()
    h["days"] = sorted((x for x in h["days"] if x["d"] >= cut), key=lambda x: x["d"])
    if hist:
        h["battery"] = hist
    _save(h)
    return True


def _slope(points):
    """Наклон прямой (в единицах за 30 дней) по точкам (дата, значение)."""
    pts = [(datetime.fromisoformat(d).timestamp() / 86400, v) for d, v in points if v is not None]
    if len(pts) < 2 or pts[-1][0] - pts[0][0] < 6:
        return None
    n = len(pts)
    mx, my = sum(p[0] for p in pts) / n, sum(p[1] for p in pts) / n
    den = sum((p[0] - mx) ** 2 for p in pts)
    return (sum((p[0] - mx) * (p[1] - my) for p in pts) / den) * 30 if den else None


def view():
    h = _load()
    days, trends = h.get("days", []), []
    since = (date.today() - timedelta(days=180)).isoformat()
    bat = h.get("battery") or []
    if bat:
        last = bat[-1]["pct"]
        s = _slope([(x["d"], x["pct"]) for x in bat if x["d"] >= since])
        s_all = _slope([(x["d"], x["pct"]) for x in bat])
        t = {"what": "battery", "now": last, "per_month": round(s, 2) if s is not None else None,
             "first": bat[0]["pct"], "first_d": bat[0]["d"], "per_month_all": round(s_all, 2) if s_all is not None else None}
        s = s if s is not None and s < 0 else s_all if s_all is not None and s_all < 0 else s
        if s is not None and s < -0.05 and last > 70:
            t["months_to_70"] = round((last - 70) / -s)
        trends.append(t)
    for disk in sorted({k for x in days for k in (x.get("disks") or {})}):
        pts = [(x["d"], x["disks"][disk]["free"]) for x in days if disk in (x.get("disks") or {}) and x["d"] >= since]
        s = _slope(pts)
        total = next((x["disks"][disk]["total"] for x in reversed(days) if disk in (x.get("disks") or {})), None)
        t = {"what": "disk", "disk": disk, "now": pts[-1][1] if pts else None, "total": total,
             "per_month": round(s, 1) if s is not None else None, "days": len(pts)}
        if s is not None and s < -0.3 and pts:
            t["months_left"] = round(max(0, pts[-1][1] - (total or 0) * 0.05) / -s, 1)
        trends.append(t)
    return {"days": days, "battery": bat, "trends": trends, "since": days[0]["d"] if days else None}
