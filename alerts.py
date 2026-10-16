"""Предупреждения: пока открыт ScanHub, он сам замечает странное в работе устройства и сообщает об этом.

Работает только при открытом окне ScanHub (в фоне — только «Сторож», если пользователь сам его включил).
Каждое правило срабатывает не чаще, чем раз в N минут, чтобы не надоедать.
"""
import shutil
import threading
import time
from collections import deque
from datetime import datetime

import psutil

RULES = [
    ("idle_cpu", "Нагрузка, когда ты не за компьютером", "Процессор загружен больше чем на 60% дольше 2 минут, а ты 3+ минуты не трогал мышь и клавиатуру — так ведут себя майнеры и зависшие фоновые задачи."),
    ("idle_gpu", "Видеокарта работает в простое", "Видеокарта загружена больше чем на 40% дольше 2 минут, пока тебя нет. Бывает от обоев Wallpaper Engine, видео в фоне — или от скрытого майнера."),
    ("cpu_hot", "Перегрев процессора", "Температура процессора выше 95°C дольше 30 секунд (нужны датчики Lenovo)."),
    ("gpu_hot", "Перегрев видеокарты", "Видеокарта выше 87°C или сбрасывает частоты из-за перегрева."),
    ("ram_full", "Заканчивается оперативная память", "Занято больше 92% памяти дольше минуты — программы начнут тормозить и вылетать."),
    ("disk_low", "Заканчивается место на диске", "На любом диске меньше 5 ГБ свободно."),
    ("miner", "Подозрение на скрытый майнер", "Процесс с именем майнера, системным именем не из Windows или долгой нагрузкой из папки пользователя без подписи."),
    ("events", "Новые сбои", "Вылет программы, синий экран, аппаратная ошибка, сбой видеодрайвера или диска — сразу с объяснением причины."),
]
COOLDOWN = {"idle_cpu": 1800, "idle_gpu": 1800, "cpu_hot": 900, "gpu_hot": 900, "ram_full": 1800, "disk_low": 6 * 3600, "miner": 3600}


class Watcher:
    def __init__(self, metrics, enabled):
        self.metrics, self.enabled = metrics, enabled
        self.items = deque(maxlen=200)
        self.seq = 0
        self.last_fired = {}
        self.since = {}                # условие -> с какого момента выполняется
        self.events_from = datetime.now().astimezone().isoformat()
        self.events_at = 0
        self.checked = None
        self.active_until = 0
        self.thread = None

    def keep_alive(self):
        """Вызывается на каждый запрос окна ScanHub: пока окно открыто — наблюдаем."""
        self.active_until = time.time() + 90
        if not self.thread or not self.thread.is_alive():
            self.thread = threading.Thread(target=self._loop, daemon=True)
            self.thread.start()

    def push(self, kind, level, title, text, action=None):
        self.seq += 1
        self.items.append({"id": self.seq, "t": datetime.now().isoformat(timespec="seconds"), "kind": kind, "level": level,
                           "title": title, "text": text, "action": action})

    def _fire(self, key, kind, level, title, text, action=None):
        if time.time() - self.last_fired.get(key, 0) < COOLDOWN.get(kind, 1800):
            return
        self.last_fired[key] = time.time()
        self.push(kind, level, title, text, action)

    def _held(self, key, cond, seconds):
        """Условие выполняется непрерывно не меньше seconds секунд."""
        if not cond:
            self.since.pop(key, None)
            return False
        start = self.since.setdefault(key, time.time())
        return time.time() - start >= seconds

    def _loop(self):
        while time.time() < self.active_until:
            if self.enabled():
                try:
                    self.check()
                except Exception as e:
                    self.checked = f"ошибка проверки: {e}"
            time.sleep(10)

    def check(self):
        import metrics as mt
        m = self.metrics
        m.touch()
        snap = m.snapshot()
        S = snap["series"]
        now_t = time.time()
        recent = lambda key, sec: [v for t, v in zip(S["t"], S.get(key, [])) if v is not None and t >= now_t - sec]
        idle = mt.idle_seconds()
        cpu2 = recent("cpu", 120)
        if cpu2 and self._held("idle_cpu", idle is not None and idle >= 180 and sum(cpu2) / len(cpu2) >= 60, 5):
            why = snap.get("cpu_why") or {}
            c = (why.get("culprits") or [{}])[0]
            self._fire("idle_cpu", "idle_cpu", "warn", f"Компьютер загружен на {sum(cpu2) / len(cpu2):.0f}%, хотя ты им не пользуешься",
                       (f"Больше всего грузит {c.get('name')}" + (f" — {c['title']}" if c.get("title") else " — если не знаешь, что это, проверь файл")) if c else
                       "Это фоновые задачи.", {"page": "res"})
        gpu2 = recent("gpu", 120)
        if gpu2 and self._held("idle_gpu", idle is not None and idle >= 180 and sum(gpu2) / len(gpu2) >= 40, 5):
            c = ((snap.get("heat") or {}).get("culprits") or [{}])[0]
            self._fire("idle_gpu", "idle_gpu", "warn", f"Видеокарта загружена на {sum(gpu2) / len(gpu2):.0f}% в простое",
                       f"Грузит {c.get('name')}." if c.get("name") else "Источник не определён — открой «Ресурсы».", {"page": "res"})
        sn = snap.get("sensors") or {}
        ct = sn.get("cpu_temp")
        if self._held("cpu_hot", ct is not None and ct >= 95, 30):
            self._fire("cpu_hot", "cpu_hot", "bad", f"Процессор перегревается: {ct:.0f}°C",
                       "Проверь, не закрыты ли решётки охлаждения; поставь ноутбук на твёрдую поверхность. Если так в простое — нужна чистка от пыли.", {"page": "res"})
        g = snap.get("gpu") or {}
        if self._held("gpu_hot", (g.get("temp") or 0) >= 87 or bool(g.get("throttle")), 20):
            self._fire("gpu_hot", "gpu_hot", "bad", f"Видеокарта перегревается: {g.get('temp', 0):.0f}°C",
                       "Видеокарта сбрасывает частоты — игры будут тормозить. Проверь охлаждение и пыль.", {"page": "res"})
        vm = psutil.virtual_memory()
        if self._held("ram_full", vm.percent >= 92, 60):
            top = (snap.get("top_mem") or [{}])[0]
            self._fire("ram_full", "ram_full", "warn", f"Память почти закончилась: занято {vm.percent:.0f}%",
                       f"Больше всего занимает {top.get('name')} ({(top.get('mem') or 0) / 2 ** 30:.1f} ГБ). Закрой лишнее или нажми «Очистить память»."
                       if top.get("name") else "Закрой лишние программы.", {"page": "speed:memory"})
        for d in (snap.get("now") or {}).get("disks") or []:
            free = d["total"] - d["used"]
            if free < 5 * 2 ** 30:
                self._fire("disk_low:" + d["mount"], "disk_low", "warn", f"На диске {d['mount']} осталось {free / 2 ** 30:.1f} ГБ",
                           "Когда место кончается, Windows тормозит и не ставит обновления. Освободи место в «Очистке».", {"page": "clean:junk"})
        for p in snap.get("suspicious") or []:
            self._fire(f"miner:{p['pid']}", "miner", "bad", f"Подозрительный процесс: {p['name']}", "; ".join(p["flags"]),
                       {"scan": p.get("exe")} if p.get("exe") else {"page": "res"})
        if now_t - self.events_at >= 180:
            self.events_at = now_t
            import diag
            for e in diag.new_events_since(self.events_from):
                self.events_from = max(self.events_from, e["t"])
                lvl = "bad" if e["kind"] in ("bsod", "whea", "disk") else "warn"
                self.push("events", lvl, e["title"], e["text"], {"page": "health:crash"})
        self.checked = datetime.now().isoformat(timespec="seconds")

    def view(self, since=0):
        return {"items": [i for i in self.items if i["id"] > since], "last": self.seq, "checked": self.checked,
                "on": bool(self.enabled()), "rules": [{"id": r[0], "title": r[1], "desc": r[2]} for r in RULES]}
