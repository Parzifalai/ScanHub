"""FPS в играх: счётчик PresentMon (Intel, открытый код) + окошко поверх игры (overlay.py) + итог после игры.

* PresentMon нужны права администратора (Windows отдаёт сведения о кадрах только им), поэтому он идёт через тот же
  run_elevated с ctl-файлом, что и долгие операции: «Выключить» пишет в ctl слово stop, и процесс администратора его гасит.
  Ничего не остаётся работать: PresentMon живёт, только пока включён показ FPS, и сам выключается через 6 часов.
* PresentMon пишет CSV в data\\fps\\live.csv; ScanHub дочитывает новые строки, считает FPS игры, которая сейчас на экране
  (окно на переднем плане), и раз в полсекунды кладёт данные для окошка в data\\fps\\overlay.json.
* После выключения — итог по каждой игре: средний FPS, «1% худших» (насколько сильные просадки), заметные подлагивания,
  температура и мощность видеокарты. Хранятся последние 30 в data\\fps\\sessions.json.
"""
import csv
import ctypes
import ctypes.wintypes as wt
import json
import os
import statistics
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
DIR = os.path.join(ROOT, "data", "fps")
# процесс администратора принимает файлы только прямо из папки data (защита от подмены) — поэтому они не в data\fps
LIVE = os.path.join(ROOT, "data", "fps_live.csv")
CTL = os.path.join(ROOT, "data", "fps_ctl")
ALIVE = os.path.join(ROOT, "data", "fps_alive")
OVERLAY = os.path.join(DIR, "overlay.json")
SESSIONS = os.path.join(DIR, "sessions.json")
NO_WINDOW = 0x08000000
MAX_HOURS = 6
# то, что рисует кадры, но игрой не является
NOT_GAMES = {"dwm.exe", "msedge.exe", "chrome.exe", "firefox.exe", "opera.exe", "browser.exe", "explorer.exe", "msedgewebview2.exe",
             "searchhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe", "textinputhost.exe", "applicationframehost.exe",
             "discord.exe", "telegram.exe", "code.exe", "steamwebhelper.exe", "nvidia overlay.exe", "nvcontainer.exe", "claude.exe",
             "python.exe", "pythonw.exe", "widgets.exe", "<unknown>", "lockapp.exe", "spotify.exe", "obs64.exe"}

S = {"on": False, "status": "off", "error": None, "started": None, "app": None, "fps": None, "low1": None, "ft": None,
     "apps": {}, "thread": None, "elev": None}
_lock = threading.Lock()


def _fg_pid():
    u = ctypes.windll.user32
    h = u.GetForegroundWindow()
    pid = wt.DWORD()
    u.GetWindowThreadProcessId(h, ctypes.byref(pid))
    return pid.value


def _title(pid):
    """Заголовок главного окна процесса: «Prominence II» понятнее, чем java.exe."""
    u = ctypes.windll.user32
    found = []
    PROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    def cb(h, _):
        p = wt.DWORD()
        u.GetWindowThreadProcessId(h, ctypes.byref(p))
        if p.value == pid and u.IsWindowVisible(h):
            n = u.GetWindowTextLengthW(h)
            if n:
                b = ctypes.create_unicode_buffer(n + 1)
                u.GetWindowTextW(h, b, n + 1)
                found.append(b.value)
                return False
        return True
    try:
        u.EnumWindows(PROC(cb), 0)
    except Exception:
        pass
    t = (found[0] if found else "").strip()
    return t[:40] if t and len(t) > 2 else ""


def _pct(vals, p):
    if not vals:
        return None
    v = sorted(vals)
    return v[min(len(v) - 1, int(len(v) * p))]


class App:
    """Кадры одной игры за сеанс: все времена кадров (мс) и что было с видеокартой."""
    def __init__(self, name):
        self.name, self.ft, self.recent, self.first, self.last = name, [], [], time.time(), time.time()
        self.gpu_t, self.gpu_w, self.cpu_t = [], [], []

    def add(self, ms, now):
        if 0 < ms < 2000:
            self.ft.append(ms)
            self.recent.append((now, ms))
            self.last = now

    def window(self, now, sec=1.5):
        self.recent = [x for x in self.recent if now - x[0] <= sec]
        return [x[1] for x in self.recent]

    def summary(self):
        if len(self.ft) < 120:
            return None
        ft = self.ft
        avg = 1000 / statistics.fmean(ft)
        worst = sorted(ft, reverse=True)[:max(1, len(ft) // 100)]          # 1% самых долгих кадров
        low1 = 1000 / statistics.fmean(worst)
        med = statistics.median(ft)
        stutter = sum(1 for x in ft if x > max(2.5 * med, med + 20))         # заметное подлагивание: кадр в 2,5 раза дольше обычного
        dur = self.last - self.first
        r = {"app": self.name, "start": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.first)), "minutes": round(dur / 60, 1),
             "frames": len(ft), "avg": round(avg), "low1": round(low1), "max_ft": round(max(ft), 1), "stutters": stutter,
             "stutter_per_min": round(stutter / max(dur / 60, 0.1), 1)}
        if self.gpu_t:
            r.update(gpu_temp_max=max(self.gpu_t), gpu_temp_avg=round(statistics.fmean(self.gpu_t)))
        if self.gpu_w:
            r["gpu_w_avg"] = round(statistics.fmean(self.gpu_w))
        if self.cpu_t:
            r["cpu_temp_max"] = max(self.cpu_t)
        r["verdict"] = verdict(r)
        return r


def verdict(r):
    """Итог игры простыми словами: [уровень, коротко, что делать]."""
    avg, low = r["avg"], r["low1"]
    tips = []
    if r.get("gpu_temp_max") and r["gpu_temp_max"] >= 87:
        tips.append("видеокарта грелась до %d°C — почисти охлаждение или поставь ноутбук на подставку" % r["gpu_temp_max"])
    if r.get("cpu_temp_max") and r["cpu_temp_max"] >= 95:
        tips.append("процессор грелся до %d°C — возможен перегрев" % r["cpu_temp_max"])
    if avg >= 55 and low >= avg * 0.5 and r["stutter_per_min"] < 3:
        return ["ok", "Шла плавно", "; ".join(tips) or ""]
    if avg >= 45 and (low < avg * 0.5 or r["stutter_per_min"] >= 3):
        return ["warn", "FPS высокий, но есть подлагивания",
                "; ".join(tips) or "Обычно виноваты фоновые программы (браузер, обновления) или подгрузка игры с диска. Закрой лишнее и включи игровой режим ScanHub."]
    return ["warn", "Мало кадров" if avg < 30 else "Не всегда плавно",
            "; ".join(tips) or "Понизь качество графики или разрешение в игре; на ноутбуке играй от зарядки в режиме «Производительность»."]


def _sessions():
    try:
        return json.load(open(SESSIONS, encoding="utf-8"))
    except (OSError, ValueError):
        return []


def view():
    return {"on": S["on"], "status": S["status"], "error": S["error"], "started": S["started"], "app": S["app"], "fps": S["fps"],
            "low1": S["low1"], "ft": S["ft"], "sessions": _sessions()[:10], "corner": S.get("corner", "tl"), "minimal": S.get("minimal", True)}


def start(exe, run_elevated, metrics, corner="tl", overlay=True):
    with _lock:
        if S["on"]:
            return view()
        os.makedirs(DIR, exist_ok=True)
        open(ALIVE, "w").close()
        for f in (LIVE, CTL, OVERLAY):
            try:
                os.remove(f)
            except OSError:
                pass
        S.update(on=True, status="uac", error=None, started=time.strftime("%Y-%m-%dT%H:%M:%S"), app=None, fps=None, low1=None, ft=None,
                 apps={}, corner=corner)
    # вывод — в stdout, а его процесс администратора пишет в файл сам: свой файл PresentMon держит закрытым для чтения
    cmd = [exe, "--output_stdout", "--no_console_stats", "--v2_metrics", "--stop_existing_session", "--session_name", "ScanHubFPS",
           "--exclude", "dwm.exe", "--timed", str(MAX_HOURS * 3600), "--terminate_after_timed"]

    def elev():
        try:
            run_elevated([{"type": "run", "cmd": cmd, "cwd": os.path.dirname(exe), "timeout": MAX_HOURS * 3600 + 60,
                           "stdout_file": LIVE, "alive": ALIVE}],
                         timeout=MAX_HOURS * 3600 + 120, ctl=CTL, on_started=lambda: S.update(status="on"))
        except PermissionError:
            S.update(error="права администратора не выданы — без них Windows не показывает кадры", status="off")
        except Exception as e:
            S.update(error=str(e), status="off")
        finally:
            _finish()

    S["elev"] = threading.Thread(target=elev, daemon=True)
    S["elev"].start()
    S["thread"] = threading.Thread(target=_reader, args=(metrics,), daemon=True)
    S["thread"].start()
    if overlay:
        _overlay_start()
    return view()


def stop():
    if not S["on"]:
        return view()
    try:
        open(CTL, "w", encoding="utf-8").write("stop")
    except OSError:
        pass
    for _ in range(30):                              # процесс администратора видит ctl раз в полсекунды
        if not S["on"]:
            break
        time.sleep(0.2)
    if S["on"]:
        _finish()
    return view()


def _finish():
    with _lock:
        if not S["on"]:
            return
        S["on"] = False
        if S["status"] != "off" or not S["error"]:
            S["status"] = "off"
        new = [x for x in (a.summary() for a in S["apps"].values()) if x]
        if new:
            old = _sessions()
            json.dump((sorted(new, key=lambda x: -x["frames"]) + old)[:30], open(SESSIONS, "w", encoding="utf-8"), ensure_ascii=False)
        S["last_new"] = new
        try:
            json.dump({"stop": True}, open(OVERLAY, "w", encoding="utf-8"))
        except OSError:
            pass


def _reader(metrics):
    """Дочитывает CSV PresentMon по мере записи и обновляет FPS игры на переднем плане.
    Кодировку берём по первым байтам: в stdout PresentMon пишет UTF-16, в файл — UTF-8. Сбой в одной строке не останавливает подсчёт."""
    import codecs
    pos, cols, buf, dec = 0, None, "", None
    while S["on"]:
        time.sleep(0.5)
        try:
            with open(LIVE, "rb") as f:
                f.seek(pos)
                raw = f.read()
                pos += len(raw)
        except OSError:
            raw = b""
        try:
            if dec is None and raw:
                enc = "utf-16-le" if raw[:2] == b"\xff\xfe" else "utf-16-be" if raw[:2] == b"\xfe\xff" else "utf-8"
                dec = codecs.getincrementaldecoder(enc)("replace")
            buf += dec.decode(raw) if dec and raw else ""
            lines = buf.split("\n")
            buf = lines.pop()                          # неполная последняя строка — дочитаем в следующий раз
            now = time.time()
            for line in lines:
                line = line.replace("\x00", "").strip("\r﻿ ")
                if not line:
                    continue
                try:
                    row = next(csv.reader([line]))
                except csv.Error:
                    continue
                if cols is None:
                    cols = {n.strip().lstrip("﻿"): i for i, n in enumerate(row)}
                    continue
                try:
                    name = row[cols["Application"]]
                    pid = int(row[cols["ProcessID"]])
                    ms = float(row[cols.get("FrameTime", cols.get("MsBetweenPresents", -1))])
                except (KeyError, ValueError, IndexError):
                    continue
                if name.lower() in NOT_GAMES:
                    continue
                key = (name, pid)
                a = S["apps"].get(key)
                if a is None:
                    a = S["apps"][key] = App(_title(pid) or name.removesuffix(".exe"))
                a.add(ms, now)
        except Exception:
            pass
        _update(time.time(), metrics)


def _update(now, metrics):
    try:
        os.utime(ALIVE)                                # «ScanHub жив» — иначе процесс администратора сам остановит PresentMon
    except OSError:
        pass
    if metrics:
        metrics.touch()                                # датчики должны работать, даже если окно ScanHub закрыто во время игры
    fg = _fg_pid()
    apps = S["apps"]
    cur = next((a for (n, pid), a in apps.items() if pid == fg and a.window(now)), None)
    if not cur:                                        # на переднем плане не игра — берём ту, что сейчас рисует больше всего
        live = [(len(a.window(now)), a) for a in apps.values()]
        live = [x for x in live if x[0] >= 10]
        cur = max(live, key=lambda x: x[0])[1] if live else None
    g = (getattr(metrics, "gpu", None) or {}) if metrics else {}
    cpu_t = ((getattr(metrics, "sensors", None) or {}).get("cpu_temp")) if metrics else None   # датчики Lenovo, если включены
    if cur:
        w = cur.window(now)
        fps = round(1000 / statistics.fmean(w)) if w else None
        lw = sorted(w, reverse=True)[:max(1, len(w) // 20)]
        S.update(app=cur.name, fps=fps, low1=round(1000 / statistics.fmean(lw)) if lw else None, ft=round(statistics.fmean(w), 1) if w else None)
        if g.get("temp") is not None:
            cur.gpu_t.append(g["temp"])
        if g.get("power") is not None:
            cur.gpu_w.append(g["power"])
        if cpu_t:
            cur.cpu_t.append(cpu_t)
    else:
        S.update(app=None, fps=None, low1=None, ft=None)
    data = {"t": now, "app": S["app"], "fps": S["fps"], "low": S["low1"], "ft": S["ft"], "gpu_temp": g.get("temp"), "gpu_w": g.get("power"),
            "gpu_util": g.get("util"), "cpu_temp": cpu_t, "corner": S.get("corner", "tl"), "status": S["status"],
            "minimal": S.get("minimal", True)}
    try:
        tmp = OVERLAY + ".tmp"
        json.dump(data, open(tmp, "w", encoding="utf-8"))
        os.replace(tmp, OVERLAY)
    except OSError:
        pass


def _overlay_start():
    py = sys.executable.replace("python.exe", "pythonw.exe")
    if not os.path.exists(py):
        py = sys.executable
    try:
        subprocess.Popen([py, "-I", os.path.join(ROOT, "overlay.py"), OVERLAY], cwd=ROOT, creationflags=NO_WINDOW)
    except OSError:
        pass
