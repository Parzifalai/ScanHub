"""Ультра проверка устройства: все проверки ScanHub подряд по выбранным пунктам и одна сводка в конце.

Шаги переиспользуют те же задачи, что и разделы приложения (результаты сразу видны и там). Всё, что требует прав
администратора после глубокой проверки (системные папки, старые драйверы, битые ярлыки «для всех», DISM + SFC, диски),
идёт одним запросом UAC.
"""
import os
import shutil
import time
from datetime import datetime

import deepscan
import pcclean
import system
import tweaks
import yarascan

# on — включено по умолчанию; admin — попросит подтверждение администратора; mins — примерная длительность
PLAN = [
    {"id": "prep", "title": "Подготовка", "mins": 2,
     "hint": "свежие базы Defender, ClamAV и правил YARA и недостающие сканеры — без них новые вирусы не найти"},
    {"id": "quick", "title": "Быстрая проверка", "mins": 4,
     "hint": "Microsoft Defender: память, автозагрузка и системные папки"},
    {"id": "deep", "title": "Глубокая проверка", "mins": 25, "admin": True,
     "hint": "все сканеры по очереди: внедрённый код в процессах, майнеры, сеть, автозагрузка, исключения Defender, браузеры, файлы в опасных местах, онлайн-сверка"},
    {"id": "clean", "title": "Очистка", "mins": 3,
     "hint": "мусор, кэши, оперативная память, битые ярлыки и старые драйверы",
     "opts": [
         {"id": "junk", "t": "Мусор и кэши", "on": True, "admin": True,
          "d": "временные файлы, кэши браузеров, программ и игр, отчёты об ошибках — только то, что безопасно удалять"},
         {"id": "junk_more", "t": "Необязательные кэши", "on": False, "admin": True,
          "d": "кэши шейдеров видеокарты, загрузки Windows Update, диагностические снимки ядра, кэши разработки и медиа Telegram. "
               "Создадутся заново, но первый запуск игр и программ будет медленнее"},
         {"id": "recycle", "t": "Корзина", "on": False, "d": "файлы удаляются навсегда — сначала загляни, нет ли там нужного"},
         {"id": "mem", "t": "Оперативная память", "on": True, "d": "сжать память неактивных программ"},
         {"id": "lnk", "t": "Битые ярлыки", "on": True, "d": "ярлыки на удалённые программы; копии сохраняются"},
         {"id": "drv", "t": "Старые драйверы", "on": True, "admin": True,
          "d": "старые версии, которые уже заменены новыми и не используются; откатить драйвер на них потом будет нельзя"},
     ]},
    {"id": "health", "title": "Полная проверка ПК", "mins": 2,
     "hint": "защита, обновления Windows, диски, батарея, память, устройства",
     "opts": [
         {"id": "sfc", "t": "Системные файлы Windows (DISM + SFC)", "on": True, "admin": True, "mins": 12,
          "d": "ещё 10–15 минут, только проверка — ничего не меняет"},
         {"id": "disk", "t": "Диски подробно", "on": True, "admin": True, "mins": 3,
          "d": "файловая система, износ и температура SSD, TRIM"},
     ]},
    {"id": "disk", "title": "Что занимает место", "mins": 2,
     "hint": "самые большие папки и файлы на диске C: — если места мало",
     "opts": [{"id": "always", "t": "Даже если места хватает", "on": False, "d": "без галочки — только когда диск C: занят больше чем на 80%"}]},
    {"id": "updates", "title": "Обновления", "mins": 3,
     "hint": "устаревшие программы (winget) и новые драйверы в Windows Update",
     "opts": [{"id": "install", "t": "Сразу обновить программы", "on": True,
               "d": "в конце: скачаю установщики, проверю на вирусы (Defender, подпись, VirusTotal) и тихо поставлю; «для всех» — одним окном UAC"}]},
    {"id": "startup", "title": "Автозагрузка", "mins": 1,
     "hint": "что запускается вместе с Windows, что замедляет загрузку, подозрительные записи"},
    {"id": "privacy", "title": "Приватность и защита", "mins": 2,
     "hint": "слежка Windows, брандмауэр, расширения браузеров, меню правой кнопки, точки восстановления, защита от майнеров, встроенные приложения, PATH"},
    {"id": "errors", "title": "Сбои и ошибки", "mins": 1,
     "hint": "вылеты программ, синие экраны, аппаратные ошибки, устройства и драйверы с ошибками, нехватка компонентов, перегрев"},
]
STEP = {p["id"]: p for p in PLAN}
LVL = ["threat", "bad", "warn", "info", "ok"]

# сканеры, которые запускаются только своим окном — в конце советуем их
EXTERNAL = ["cureit", "kvrt", "eset", "emsisoft", "msert", "malwarebytes", "adwcleaner"]     # MinerSearch идёт внутри глубокой проверки


def fmt(b):
    b = float(b or 0)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if b < 1024 or unit == "ТБ":
            return (f"{b:.0f}" if unit in ("Б", "КБ") or b >= 100 else f"{b:.1f}".replace(".", ",")) + " " + unit
        b /= 1024


def plural(n, one, few, many):
    n = abs(int(n))
    if n % 10 == 1 and n % 100 != 11:
        return one
    return few if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14 else many


def defaults():
    return {"steps": [p["id"] for p in PLAN], "opts": {p["id"]: [o["id"] for o in p.get("opts", []) if o["on"]] for p in PLAN}}


class Ultra:
    """job — словарь задачи ScanHub; ctx — функции сервера: task, job, deep, install, tools, set_task, drop_tasks, notify, stop_job."""

    def __init__(self, job, ctx, sel):
        self.job, self.ctx = job, ctx
        d = defaults()
        want = set((sel or {}).get("steps", d["steps"]))
        steps = [p["id"] for p in PLAN if p["id"] in want]          # всегда в порядке плана
        opts = (sel or {}).get("opts") or {}
        self.sel = {"steps": steps, "opts": {k: [o for o in opts.get(k, d["opts"][k])] for k in STEP}}
        job["sel"] = self.sel
        self.emit = job["lines"].append
        self.steps = job["steps"] = []
        job["recs"], job["todo"], job["stats"] = [], [], {}
        self.freed = 0
        self.quick_ok = False
        self.health = None
        self.sysfiles = None             # результат DISM + SFC, если выполнен в общем окне UAC очистки
        self.after = []                  # действия после итогов (окно winget)
        self.sub = None                  # id текущей вложенной проверки — чтобы остановить её

    # ------------------------------------------------------------ общее
    def stopped(self):
        return bool(self.job.get("stop"))

    def on(self, step, opt):
        return opt in self.sel["opts"].get(step, [])

    @staticmethod
    def add(s, lvl, title, text="", action=None, todo=None):
        s["items"].append({"lvl": lvl, "t": title, "s": text, "a": action,
                           "todo": lvl in ("threat", "bad", "warn") if todo is None else todo})

    def task(self, s, name, args=None, text=None):
        """Задача приложения (та же, что в разделах) — ждём её окончания."""
        if text:
            s["progress"] = text
        t = self.ctx["task"](name, args or {})
        if t.get("status") == "error":
            raise RuntimeError(t.get("error") or "ошибка")
        return t.get("result")

    def tool_job(self, s, tid, mode):
        """Запуск сканера ScanHub и ожидание."""
        j = self.ctx["job"](tid, mode)
        self.sub = j["id"]
        while j["status"] == "running":
            if self.stopped():
                self.ctx["stop_job"](j["id"])
            if j.get("progress"):
                s["progress"] = j["progress"]
            time.sleep(1)
        self.sub = None
        return j

    def run(self):
        for sid in self.sel["steps"]:
            p = STEP[sid]
            self.steps.append({"id": sid, "title": p["title"], "hint": p["hint"], "status": "pending", "verdict": None,
                               "label": "", "items": [], "progress": None, "started": None, "finished": None,
                               "opts": self.sel["opts"].get(sid, [])})
        def narrate():                            # каждый новый этап — строкой в журнал (видно в консоли и в «Что сейчас происходит»)
            last = None
            while self.job.get("status") == "running":
                cur = next((x for x in self.steps if x["status"] == "running"), None)
                p = cur and cur.get("progress")
                if p and p != last:
                    last = p
                    self.emit(f"  · {p}")
                time.sleep(1)
        import threading
        threading.Thread(target=narrate, daemon=True).start()
        for s in self.steps:
            if self.stopped():
                s.update(status="skipped", verdict="skipped", label="остановлено")
                continue
            s.update(status="running", started=datetime.now().isoformat(timespec="seconds"))
            self.emit(f"\n━━ {s['title']} ━━")
            try:
                getattr(self, "s_" + s["id"])(s)
            except Exception as e:
                s.update(verdict="error", label="не получилось")
                self.add(s, "warn", f"{s['title']}: шаг не выполнился", str(e)[:300])
            if self.stopped() and not s["label"]:
                s.update(verdict="skipped", label="остановлено")
            if not s["verdict"]:
                worst = min((LVL.index(i["lvl"]) for i in s["items"]), default=LVL.index("ok"))
                s["verdict"] = LVL[worst] if LVL[worst] != "info" else "ok"
            for i in s["items"]:
                self.emit(f"  {'✓' if i['lvl'] == 'ok' else '•' if i['lvl'] == 'info' else '!'} {i['t']}" + (f" — {i['s']}" if i["s"] else ""))
            self.emit(f"  итог шага: {s['label']}")
            s.update(status="skipped" if s["verdict"] == "skipped" else "done", progress=None,
                     finished=datetime.now().isoformat(timespec="seconds"))
            self.ctx.get("save", lambda: None)()        # если ScanHub закроют посреди проверки, сделанное не пропадёт
        return self.finish()

    def finish(self):
        todo = [dict(i, step=s["title"]) for s in self.steps for i in s["items"] if i["todo"]]
        todo.sort(key=lambda i: LVL.index(i["lvl"]))
        self.job["todo"] = todo
        self.job["recs"] = self.recs()
        threats = [s for s in self.steps if s["verdict"] == "threat"]
        bad = sum(1 for i in todo if i["lvl"] in ("threat", "bad"))
        warn = sum(1 for i in todo if i["lvl"] == "warn")
        self.job["stats"] = {"threats": len(threats), "bad": bad, "warn": warn, "freed": self.freed,
                             "steps": len(self.steps), "done": sum(1 for s in self.steps if s["status"] == "done")}
        if self.stopped():
            head, v, code = "Ультра проверка остановлена", "error", 3
        elif threats:
            head, v, code = "Найдены угрозы", "threat", 1
        elif bad:
            head, v, code = "Угроз нет, но есть что исправить", "suspicious", 2
        else:
            head, v, code = "Угроз не найдено", "clean", 0
        parts = [head]
        if not threats and not self.stopped():
            if bad:
                parts.append(f"важного: {bad}")
            if warn:
                parts.append(f"замечаний: {warn}")
        if self.freed:
            parts.append(f"освобождено {fmt(self.freed)}")
        return code, [v, " · ".join(parts)]

    # ------------------------------------------------------------ шаги
    def s_prep(self, s):
        tv = {t["id"]: t for t in self.ctx["tools"]()}
        done = []
        s["progress"] = "обновляю базы Microsoft Defender"
        j = self.tool_job(s, "defender", "sigupdate")
        if (j.get("verdict") or [""])[0] == "clean":
            done.append("Defender")
        else:
            self.add(s, "warn", "Базы Defender не обновились", (j.get("verdict") or ["", ""])[1] +
                     ". Проверь интернет или обнови вручную в «Безопасность Windows».", {"launch": "defender", "label": "Открыть"})
        deep = "deep" in self.sel["steps"]
        # сканеры, без которых шаги глубокой проверки пропустятся
        for tid in (["hollowshunter", "clamav", "minersearch", "rootcerts"] if deep else []):
            t = tv.get(tid)
            if t and not t["ready"] and not t.get("missing") and t["source"]["type"] not in ("manual", "service") and not self.stopped():
                s["progress"] = f"устанавливаю {t['name']}"
                ok = self.ctx["install"](tid)
                if ok:
                    done.append(f"{t['name']} установлен")
                else:
                    self.add(s, "warn", f"{t['name']} не установился", "Без него один шаг глубокой проверки пропустится.",
                             {"page": "tools", "label": "Подробнее"})
        tv = {t["id"]: t for t in self.ctx["tools"]()}
        c = tv.get("clamav")
        if c and c["ready"] and not self.stopped():
            s["progress"] = "скачиваю базы ClamAV (в первый раз ~250 МБ)" if c.get("data_missing") else "обновляю базы ClamAV"
            j = self.tool_job(s, "clamav", "update")
            if (j.get("verdict") or [""])[0] in ("clean", "unknown"):
                done.append("ClamAV")
            else:
                self.add(s, "warn", "Базы ClamAV не обновились", (j.get("verdict") or ["", ""])[1], {"run": ["clamav", "update"], "label": "Повторить"})
        y = tv.get("yara")
        if y and y["ready"] and (y.get("stale") or y.get("data_missing")) and not self.stopped():
            s["progress"] = "обновляю правила YARA"
            j = self.tool_job(s, "yara", "update")
            if (j.get("verdict") or [""])[0] == "clean":
                done.append("YARA")
            else:
                self.add(s, "warn", "Правила YARA не обновились", (j.get("verdict") or ["", ""])[1], {"run": ["yara", "update"], "label": "Повторить"})
        elif y and y["ready"]:
            done.append("YARA (свежие)")
        if done:
            self.add(s, "ok", "Обновлено: " + ", ".join(done))
        s["label"] = "базы свежие" if not any(i["lvl"] == "warn" for i in s["items"]) else "не всё обновилось"

    def s_quick(self, s):
        s["progress"] = "Defender проверяет память, автозагрузку и системные папки"
        j = self.tool_job(s, "defender", "quick")
        s["job"] = j["id"]
        v, label = (j.get("verdict") or ["error", "ошибка"])
        if j["status"] == "stopped":
            s.update(verdict="skipped", label="остановлено")
            return
        if v == "threat":
            self.add(s, "threat", "Defender нашёл угрозы",
                     "Обычно он обезвреживает их сам. Что именно найдено и что с этим сделано — в «Безопасность Windows» → «Журнал защиты».",
                     {"launch": "defender", "label": "Журнал защиты"})
            s.update(verdict="threat", label="найдены угрозы")
        elif v == "clean":
            self.quick_ok = True
            s["label"] = "угроз нет"
        else:
            s.update(verdict="warn", label=label.lower())
            self.add(s, "warn", "Defender не выполнил быструю проверку", f"{label}. Возможно, Defender выключен или его заменил другой антивирус.",
                     {"launch": "defender", "label": "Открыть"})

    def s_deep(self, s):
        skip = {"defender": "уже проверено в «Быстрой проверке» ультра проверки"} if self.quick_ok else None
        j = self.ctx["deep"](skip)
        self.sub = s["job"] = j["id"]
        while j["status"] == "running":
            if self.stopped():
                self.ctx["stop_job"](j["id"])
            st = j.get("steps") or []
            cur = next((x for x in st if x["status"] == "running"), None)
            n = sum(1 for x in st if x["status"] in ("done", "skipped"))
            if cur:
                s["progress"] = f"{n + 1} из {len(st)}: {cur['title']}"
            time.sleep(1)
        self.sub = None
        if j["status"] == "stopped":
            s.update(verdict="skipped", label="остановлено")
            return
        v, label = j.get("verdict") or ["error", "ошибка"]
        act = {"deep": j["id"], "label": "Подробнее"}
        for x in j.get("steps") or []:
            if x.get("verdict") in ("threat", "suspicious"):
                self.add(s, "threat" if x["verdict"] == "threat" else "warn", f"{x['title']}: {x['label']}",
                         "; ".join(x["findings"][:3]) + (f" …и ещё {len(x['findings']) - 3}" if len(x["findings"]) > 3 else ""), act)
                s["items"][-1]["key"] = "deep:" + x["id"]
                if x.get("files"):                            # найденные файлы — сразу с кнопкой «В карантин»
                    s["items"][-1]["files"] = [f for f in x["files"] if os.path.isfile(f["path"])]
            elif x.get("status") == "done" and not x.get("problem"):
                self.add(s, "ok", f"{x['title']}: {x['label']}")
        for p in j.get("problems") or []:
            f = p.get("fix") or {}
            a = {"install": f["install"], "label": "Установить"} if f.get("install") else \
                {"run": f["run"], "label": "Запустить"} if f.get("run") else \
                {"launch": f["open"], "label": "Открыть"} if f.get("open") else act
            self.add(s, "warn", f"Не сработало: {p['step']}", p["text"], a)
        s.update(verdict="threat" if v == "threat" else "warn" if v in ("suspicious", "error") else "ok", label=label.lower())

    def s_clean(self, s):
        o = lambda x: self.on("clean", x)
        elev, handlers = [], []          # операции с правами администратора и разбор их результатов
        report, errors = [], []
        cats = pcclean.categories()
        pick = [c for c in cats if (c["safe"] and o("junk")) or (not c["safe"] and o("junk_more"))]
        freed = skipped = 0
        if pick:
            s["progress"] = "удаляю мусор и кэши"
            for c in pick:
                if c.get("admin"):
                    elev.append({"type": "clean", "paths": c["paths"], "older_hours": c.get("older_days", 1) * 24})
                    handlers.append(("junk", c))
                    continue
                f, sk = pcclean.clean_paths(c["paths"], c.get("older_days", 1) * 24)
                freed += f
                skipped += sk
        rb_freed = 0
        if o("recycle"):
            rb = pcclean.recycle_info()
            if rb["count"] and pcclean.empty_recycle():
                rb_freed = rb["size"]
                report.append(f"Корзина очищена: {fmt(rb['size'])}")
        elif not self.stopped():
            rb = pcclean.recycle_info()
            if rb["size"] > 500 * 2 ** 20:
                self.add(s, "info", f"В Корзине {fmt(rb['size'])} ({rb['count']} {plural(rb['count'], 'файл', 'файла', 'файлов')})",
                         "Корзину ультра проверка не трогала. Загляни в неё и очисти, если там нет нужного.",
                         {"page": "clean:junk", "label": "Очистка"}, todo=True)
        lnk_n, lnk_backup = 0, None
        if o("lnk") and not self.stopped():
            s["progress"] = "ищу битые ярлыки"
            broken = pcclean.shortcuts_scan()["broken"]
            mine = [b["path"] for b in broken if not b.get("admin")]
            if mine:
                r = pcclean.shortcuts_remove(mine, self._no_elevation)
                lnk_n, lnk_backup = r["removed"], r["backup"]
                errors += r["errors"]
            adm = [b["path"] for b in broken if b.get("admin")]
            if adm:
                lnk_backup = lnk_backup or os.path.join(pcclean.BACKUPS, "shortcuts", pcclean.stamp())
                os.makedirs(lnk_backup, exist_ok=True)
                for p in adm:
                    shutil.copy2(p, os.path.join(lnk_backup, os.path.basename(p)))
                    elev.append({"type": "remove", "path": p})
                    handlers.append(("lnk", p))
        drv = []
        if o("drv") and not self.stopped():
            s["progress"] = "ищу старые драйверы"
            drv = pcclean.drivers_scan()["old"]
            if drv:
                if tweaks.restore_status()["enabled"]:
                    elev.append(tweaks.restore_ops("ультра проверка: удаление старых драйверов"))
                    handlers.append(("rp", None))
                for p in drv:
                    elev.append({"type": "run", "cmd": ["pnputil", "/delete-driver", p["oem"]], "timeout": 120})
                    handlers.append(("drv", p))
        # DISM + SFC и диски из «Полной проверки ПК» — в то же окно UAC, чтобы не спрашивать дважды
        hs = "health" in self.sel["steps"] and (self.on("health", "sfc") or self.on("health", "disk"))
        sf_ops = deepscan.sysfiles_ops(self.on("health", "sfc"), self.on("health", "disk")) if hs and elev else []
        if elev and not self.stopped():
            s["progress"] = "жду подтверждения администратора (окно UAC; в нём «Python» — это ScanHub)" + \
                (" · затем проверка системных файлов, до 15 минут" if sf_ops else "")
            self.ctx["notify"]("Нужно подтверждение", "Ультра проверка просит права администратора для очистки системных папок и драйверов.")
            try:
                res = deepscan.run_elevated(elev + sf_ops, timeout=3600, on_started=lambda: s.update(
                    progress="права выданы ✓ · очищаю системные папки и старые драйверы" +
                             (", затем проверка системных файлов (DISM + SFC) и дисков — до 15 минут" if sf_ops else "")))
            except PermissionError:
                res = None
                self.add(s, "warn", "Права администратора не выданы (UAC отменён)",
                         "Системные временные файлы, старые драйверы и ярлыки «для всех» не очищены. Их можно очистить в разделе «Очистка».",
                         {"page": "clean:junk", "label": "Очистка"})
            if res:
                drv_ok, drv_size, junk_failed = 0, 0, []
                for (kind, x), r in zip(handlers, res):
                    if kind == "junk":
                        if r.get("ok"):
                            freed += r.get("freed", 0)
                            skipped += r.get("skipped", 0)
                        else:
                            junk_failed.append(x["label"])
                    elif kind == "lnk" and r.get("ok"):
                        lnk_n += 1
                    elif kind == "drv" and r.get("ok") and r.get("code") == 0:
                        drv_ok += 1
                        drv_size += x.get("size") or 0
                    elif kind == "rp":
                        rp = tweaks.restore_result(r)
                        if rp["status"] == "ok":
                            report.append("Точка восстановления создана")
                if junk_failed:
                    errors.append("не очистилось: " + ", ".join(junk_failed))
                if drv:
                    report.append(f"Удалено старых драйверов: {drv_ok} из {len(drv)}" + (f" ({fmt(drv_size)})" if drv_size else ""))
                    if drv_ok < len(drv):
                        errors.append(f"старых драйверов не удалилось: {len(drv) - drv_ok} — Windows не даёт удалить те, что ещё используются")
                if sf_ops:
                    self.sysfiles = deepscan.sysfiles_parse(res[len(elev):], self.on("health", "sfc"), self.on("health", "disk"))
        elif drv:
            report.append(f"Старых драйверов: {len(drv)} — не удалены (проверка остановлена)")
        if lnk_n:
            report.append(f"Удалено битых ярлыков: {lnk_n} (копии — в {lnk_backup})")
        elif o("lnk"):
            report.append("Битых ярлыков нет")
        if o("mem") and not self.stopped():
            s["progress"] = "очищаю оперативную память"
            m = system.mem_full() if system.memclean_installed() else system.mem_quick()
            report.append(f"Оперативная память: освобождено {fmt(m.get('freed', 0))}, занято "
                          f"{round(m['before']['percent'])}% → {round(m['after']['percent'])}%")
        self.freed += freed + rb_freed
        if pick:
            report.insert(0, f"Мусор и кэши: освобождено {fmt(freed)}" + (f", пропущено занятых файлов: {skipped}" if skipped else ""))
        for r in report:
            self.add(s, "ok", r)
        for e in errors:
            self.add(s, "info", e, todo=False)
        self.ctx["drop_tasks"](["junk_scan", "shortcuts", "drvstore"])   # разделы «Очистки» пересчитают заново
        s["label"] = f"освобождено {fmt(freed + rb_freed)}" if freed + rb_freed else "готово"

    @staticmethod
    def _no_elevation(ops, timeout=None):
        raise PermissionError("без прав администратора")

    def s_health(self, s):
        h = self.health = self.task(s, "health", text="проверяю защиту, обновления, диски, батарею и устройства — 1–2 минуты") or {}
        add = lambda lvl, t, x="", a=None: self.add(s, lvl, t, x, a)
        df = h.get("defender") or {}
        if df.get("realtime"):
            add("ok", "Microsoft Defender защищает в реальном времени")
        if df.get("realtime") is False:
            add("bad", "Защита в реальном времени выключена", "Microsoft Defender не следит за файлами — включи её в «Безопасность Windows».",
                {"launch": "defender", "label": "Открыть"})
        if (df.get("sig_age") or 0) > 2:
            add("warn", f"Базам Defender {df['sig_age']} дн.", "Обнови их в «Безопасность Windows».", {"run": ["defender", "sigupdate"], "label": "Обновить"})
        if df.get("tamper") is False:
            add("warn", "Защита от подделки выключена", "Вредонос может отключить Defender. Включи её в «Безопасность Windows» → «Защита от вирусов и угроз».",
                {"launch": "defender", "label": "Открыть"})
        off = [f["name"] for f in h.get("firewall") or [] if not f.get("on")]
        if h.get("firewall") and not off:
            add("ok", "Брандмауэр включён во всех профилях")
        if off:
            add("bad", "Брандмауэр выключен: " + ", ".join(off), "Компьютер открыт для подключений из сети.", {"launch": "firewall", "label": "Открыть"})
        uac = h.get("uac") or {}
        if uac.get("lua") == 0:
            add("bad", "Контроль учётных записей (UAC) выключен", "Программы получают права администратора без спроса.")
        elif uac.get("prompt") == 0:
            add("warn", "UAC не спрашивает подтверждения", "Программы повышают права молча.")
        if h.get("secureboot") != 1:
            add("info", "Secure Boot выключен", "Защищает от буткитов. Включается в BIOS/UEFI.", None)
        if h.get("last_update"):
            days = (datetime.now() - datetime.fromisoformat(h["last_update"])).days
            if days > 45:
                add("warn", f"Windows не обновлялась {days} дн.", "Проверь Центр обновления.", {"launch": "wu", "label": "Windows Update"})
            else:
                add("ok", f"Последнее обновление Windows — {days} дн. назад")
        if h.get("reboot_pending"):
            add("warn", "Нужна перезагрузка", "Обновления Windows ждут перезагрузки, чтобы установиться.")
        for v in h.get("volumes") or []:
            free = 100 - v["percent"]
            if free < 20:
                add("bad" if free < 10 else "warn", f"Диск {v['mount']} — свободно {fmt(v['free'])} ({round(free)}%)",
                    "Когда место кончается, Windows тормозит и не может поставить обновления.", {"page": "disk:disk", "label": "Что занимает"})
        for d in h.get("disks") or []:
            if d.get("health") not in (None, "Healthy"):
                add("bad", f"{d['name']}: {d['health']}", "Срочно сделай резервную копию важных файлов.")
        b = h.get("battery") or {}
        if b.get("design"):
            wear = max(0, round((1 - b["full"] / b["design"]) * 100))
            self.add(s, "warn" if wear > 40 else "ok", f"Износ батареи: {wear}%",
                     f"циклов зарядки: {b['cycles']}" if b.get("cycles") else "", todo=wear > 40)
        if (h.get("uptime_days") or 0) > 7:
            add("warn", f"Без перезагрузки {h['uptime_days']} дн.", "Перезагрузи компьютер — освободится память и доставятся обновления.")
        if (h.get("ram") or {}).get("percent", 0) > 85:
            add("warn", f"Память занята на {round(h['ram']['percent'])}%", "Закрой лишние программы.", {"page": "res", "label": "Ресурсы"})
        # комплектующие: память, видеокарта, экран, питание, BIOS, устройства, сеть (сбои и диски — в своих шагах)
        try:
            hw = self.task(s, "hwcheck", text="проверяю комплектующие: память, видеокарту, экран, питание, сеть — несколько секунд") or {}
        except Exception:
            hw = None
        if hw is not None:
            found = 0
            for x in hw.get("items") or []:
                if x["comp"] in ("Сбои", "Диски") or x["lvl"] == "ok":
                    continue
                found += x["lvl"] in ("bad", "warn")
                add(x["lvl"], x["title"], " ".join(t for t in (x.get("text"), x.get("how")) if t), {"page": x.get("page") or "health:hw", "label": "Подробнее"})
                s["items"][-1]["src"] = "hwcheck"                  # по этой метке итоги перепроверяют пункт заново
            if not found:
                add("ok", "Комплектующие работают как надо: память, видеокарта, экран, питание, устройства")
        elif h.get("problem_devices"):
            add("warn", f"Устройства с ошибками: {h['problem_devices']}", "Какие именно и что с ними делать — в разделе «Драйверы».", {"page": "health:drivers", "label": "Драйверы"})
        else:
            add("ok", "Все устройства работают")
        # системные файлы и диски: уже проверены в общем окне UAC очистки или проверяются сейчас
        sf, disk = self.on("health", "sfc"), self.on("health", "disk")
        if (sf or disk) and self.sysfiles is None and not self.stopped():
            s["progress"] = ("жду подтверждения администратора (окно UAC; в нём «Python» — это ScanHub) · " +
                             ("проверка системных файлов, 10–15 минут" if sf else "проверка дисков"))
            self.ctx["notify"]("Нужно подтверждение", "Ультра проверка просит права администратора для проверки системных файлов и дисков.")
            try:
                self.sysfiles = self.task(s, "sysfiles", {"sfc": sf, "disk": disk})
            except Exception as e:
                add("warn", "Системные файлы и диски не проверены", str(e), {"page": "health:health", "label": "Проверить"})
        if self.sysfiles is not None:
            self.ctx["set_task"]("sysfiles", self.sysfiles)
            self._sysfiles(s, self.sysfiles)
        self.ctx["set_task"]("winget", {"apps": h.get("winget")})
        n = sum(1 for i in s["items"] if i["lvl"] in ("bad", "warn") and i["todo"])
        s["label"] = f"замечаний: {n}" if n else "всё в порядке"

    def _sysfiles(self, s, r):
        # карточки с понятным выводом считает deepscan.sysfiles_cards — одинаково для ультра, «Полной проверки» и мастера
        repair = {"launch": "sfc_repair", "label": "Восстановить"}
        for c in r.get("cards") or deepscan.sysfiles_cards(r):
            self.add(s, c["lvl"], c["title"], c["text"], repair if c["action"] == "repair" else None)
        d = r.get("disk")
        if d and not d.get("error"):
            for x in d.get("scan") or []:
                if x.get("r") and "noerrorsfound" not in x["r"].lower():
                    self.add(s, "bad", f"Файловая система {x['d']}: найдены ошибки", f"Нужна проверка с исправлением: chkdsk {x['d']}: /f",
                             {"page": "health:health", "label": "Подробнее"})
            for x in d.get("smart") or []:
                errs = (x.get("rerr") or 0) + (x.get("werr") or 0)
                wear = x.get("wear")
                if errs:
                    self.add(s, "bad", f"{x['name']}: неисправленных ошибок {errs}", "Сделай резервную копию важных файлов!")
                elif wear is not None and float(wear) >= 80:
                    self.add(s, "warn", f"{x['name']}: износ {wear}%", "Диск скоро выработает ресурс — подумай о замене и резервной копии.")
                else:
                    self.add(s, "ok", f"{x['name']}: " + (f"износ {wear}%" if wear is not None else "исправен") +
                             (f", {x['temp']}°C" if x.get("temp") else ""))
            if d.get("trim_on") is False:
                self.add(s, "warn", "TRIM выключен", "Без TRIM SSD со временем замедляется.",
                         {"task": "trim", "label": "Выполнить TRIM", "confirm": "Выполнить TRIM для всех дисков? Попросит права администратора."})

    def s_disk(self, s):
        u = shutil.disk_usage("C:\\")
        pct = u.used / u.total * 100
        if pct < 80 and not self.on("disk", "always"):
            s.update(verdict="ok", label=f"места хватает: свободно {fmt(u.free)}")
            self.add(s, "ok", f"На C: свободно {fmt(u.free)} из {fmt(u.total)} — разбирать не нужно")
            return
        r = self.task(s, "disk_analyze", {"path": "C:\\"}, "считаю размеры папок на C: — 1–3 минуты") or {}
        items = sorted((r.get("tree") or {}).get("items") or [], key=lambda x: -x["size"])[:6]
        big = (r.get("big") or [])[:5]
        types = sorted(r.get("types") or [], key=lambda x: -x["size"])[:4]
        lvl = "bad" if pct >= 92 else "warn" if pct >= 85 else "info"
        said = any(i["todo"] and i["t"].startswith("Диск C:") for x in self.steps for i in x["items"])
        self.add(s, lvl, f"На C: свободно {fmt(u.free)} из {fmt(u.total)} ({100 - round(pct)}%)",
                 "Посмотри, что можно удалить или перенести на другой диск.", {"page": "disk:disk", "label": "Что занимает"},
                 todo=lvl != "info" and not said)
        if items:
            self.add(s, "info", "Больше всего занимают папки", ", ".join(f"{x['name']} — {fmt(x['size'])}" for x in items), todo=False)
        if types:
            self.add(s, "info", "По типам файлов", ", ".join(f"{x['name'].lower()} — {fmt(x['size'])}" for x in types), todo=False)
        if big:
            self.add(s, "info", "Самые большие файлы", ", ".join(f"{os.path.basename(x['path'])} — {fmt(x['size'])}" for x in big), todo=False)
        s["label"] = f"свободно {fmt(u.free)}"

    def s_updates(self, s):
        apps = (self.health or {}).get("winget", "?") if self.health else "?"
        if apps == "?":
            apps = (self.task(s, "winget", text="спрашиваю winget, какие программы устарели — до минуты") or {}).get("apps")
        drv = self.task(s, "driver_updates", text="ищу новые драйверы в Windows Update — до 2 минут") or []
        install = self.on("updates", "install")
        ghosts = [a for a in apps if a.get("ghost")] if isinstance(apps, list) else []
        if ghosts:
            apps = [a for a in apps if not a.get("ghost")]
            self.add(s, "warn", f"Удалённые программы в списке Windows: {len(ghosts)}",
                     "Файлов уже нет, а запись осталась, поэтому winget предлагает их обновить: " + ", ".join(a["name"] for a in ghosts) +
                     ". Обновлять не нужно — убери запись.", {"page": "apps:winget", "label": "Убрать записи"})
        if apps is None:
            self.add(s, "info", "winget не найден — устаревшие программы не проверить",
                     "Установи «Установщик приложений» из Microsoft Store.", todo=False)
        elif apps:
            names = ", ".join(f"{a['name']} {a['version']} → {a['available']}" for a in apps[:8]) + (f" …и ещё {len(apps) - 8}" if len(apps) > 8 else "")
            if install:
                self.after.append("winget_upgrade")
                self.add(s, "info", f"Устарело программ: {len(apps)} — обновлю в конце, после проверки на вирусы",
                         names, {"page": "apps:winget", "label": "Обновления"}, todo=False)
            else:
                self.add(s, "warn", f"Устарело программ: {len(apps)}", "В старых версиях находят уязвимости. " + names,
                         {"page": "apps:winget", "label": "Выбрать и обновить"})
        else:
            self.add(s, "ok", "Все программы обновлены")
        if drv:
            self.add(s, "warn", f"Windows Update нашёл драйверы: {len(drv)}", ", ".join(x["title"] for x in drv[:5]),
                     {"launch": "wu_optional", "label": "Установить"})
        else:
            self.add(s, "ok", "Новых драйверов в Windows Update нет")
        n = len(apps or [])
        s["label"] = (f"устарело программ: {n}" if n else "программы свежие") + (f", драйверов: {len(drv)}" if drv else "")

    def s_startup(self, s):
        st = self.task(s, "startup", text="собираю программы автозагрузки") or {}
        ar = self.task(s, "autoruns", text="проверяю записи автозапуска и их подписи — до минуты") or []
        items = st.get("items") or []
        en = [i for i in items if i.get("enabled")]
        miss = [i for i in en if i.get("missing")]
        slow = sorted([i for i in en if i.get("delay_ms")], key=lambda i: -i["delay_ms"])
        bad = [i for i in ar if i.get("level") == "bad"]
        self.startup_on = en
        if bad:
            self.add(s, "bad", f"Подозрительные записи автозапуска: {len(bad)}",
                     "; ".join(f"{i['name']} — {', '.join(i['flags'])}" for i in bad[:4]), {"page": "speed:boot", "label": "Автозагрузка"})
        if miss:
            self.add(s, "warn", f"Записи автозагрузки без файла: {len(miss)}", ", ".join(i["name"] for i in miss[:6]) +
                     " — программы удалены, а запись осталась. Её можно выключить.", {"page": "speed:boot", "label": "Автозагрузка"})
        if slow:
            self.add(s, "warn", "Замедляют загрузку Windows", ", ".join(f"{i['name']} (+{i['delay_ms'] / 1000:.1f} с)".replace(".", ",") for i in slow[:5]),
                     {"page": "speed:boot", "label": "Автозагрузка"})
        boot = self.boot = st.get("boot")
        if boot and boot.get("last", {}).get("total"):
            self.add(s, "info", f"Последняя загрузка Windows: {boot['last']['total'] / 1000:.1f} с".replace(".", ","), todo=False)
        self.add(s, "ok" if len(en) <= 12 else "info", f"Вместе с Windows запускается: {len(en)} {plural(len(en), 'программа', 'программы', 'программ')}",
                 ", ".join(i["name"] for i in en[:12]) + (" …" if len(en) > 12 else ""), todo=False)
        s["label"] = f"включено {len(en)}" + (f", подозрительных {len(bad)}" if bad else "")

    def s_privacy(self, s):
        pv = self.task(s, "privacy", text="проверяю настройки приватности") or []
        pv = pv.get("items", []) if isinstance(pv, dict) else pv
        off = [i for i in pv if i.get("rec") and not i.get("applied")]
        if off:
            self.add(s, "info", f"Не выключено рекомендуемых настроек приватности: {len(off)}", ", ".join(i["title"] for i in off[:6]),
                     {"page": "privacy:privacy", "label": "Настроить"}, todo=True)
        else:
            self.add(s, "ok", "Рекомендуемые настройки приватности уже выключены")
        sc = self.task(s, "security", text="проверяю защиту Windows") or []
        sc = sc.get("items", []) if isinstance(sc, dict) else sc
        weak = [i for i in sc if i.get("ok") is False and i.get("rec")]
        if weak:
            self.add(s, "warn", f"Выключены защиты Windows: {len(weak)}", ", ".join(i["title"] for i in weak[:6]),
                     {"page": "privacy:security", "label": "Включить"}, todo=True)
        elif sc:
            self.add(s, "ok", "Встроенные защиты Windows включены")
        fw = self.task(s, "firewall", text="читаю правила брандмауэра") or {}
        if fw.get("warn"):
            self.add(s, "warn", f"Правила брандмауэра с замечаниями: {fw['warn']}",
                     "Например, разрешения для удалённых программ или для программ из временных папок.", {"page": "privacy:firewall", "label": "Посмотреть"})
        cx = self.task(s, "ctx", text="проверяю меню правой кнопки") or {}
        dead = [i for i in cx.get("items") or [] if i.get("exists") is False and i.get("enabled")]
        if dead:
            self.add(s, "info", f"В меню правой кнопки — пункты от удалённых программ: {len(dead)}", ", ".join(i["label"] for i in dead[:5]),
                     {"page": "privacy:ctx", "label": "Убрать"}, todo=True)
        rs = tweaks.restore_status()
        self.ctx["set_task"]("restore", rs)
        if not rs["enabled"]:
            self.add(s, "warn", "Точки восстановления выключены", "Если обновление или драйвер что-то сломает, откатить Windows будет нельзя.",
                     {"page": "privacy:restore", "label": "Включить"})
        hs = system.hosts_status()
        if not hs.get("enabled") and not hs.get("error"):
            self.add(s, "info", "Блокировка майнинг-доменов выключена", "Браузерные майнеры и часть вредоносов смогут связаться со своими серверами.",
                     {"page": "privacy:miners", "label": "Включить"}, todo=True)
        if "deep" not in self.sel["steps"]:                 # иначе браузеры уже проверила глубокая проверка
            import browsers
            br = self.task(s, "browsers", text="проверяю расширения и настройки браузеров") or {}
            for lvl, t in browsers.findings(br) if br else []:
                self.add(s, lvl if lvl != "bad" else "bad", t, "", {"page": "privacy:browsers", "label": "Браузеры"}, todo=lvl in ("bad", "warn"))
        ax = self.task(s, "appx", text="смотрю встроенные приложения") or []
        self.ads = [a for a in ax if a.get("grp") == "ad"]
        pth = self.task(s, "envpath", text="проверяю переменную PATH") or {}
        bad_path = [e for e in pth.get("entries") or [] if e.get("problem") in ("повтор", "папки нет")]
        if bad_path:
            self.add(s, "info", f"Лишние записи в PATH: {len(bad_path)}", "Папки удалённых программ и повторы — замедляют запуск команд в терминале.",
                     {"page": "clean:envpath", "label": "Убрать"}, todo=True)
        n = sum(1 for i in s["items"] if i["todo"])
        s["label"] = f"замечаний: {n}" if n else "всё в порядке"

    def s_errors(self, s):
        r = self.task(s, "diag", {"days": 30}, "читаю журналы Windows за 30 дней — 10–30 секунд") or {}
        self.diag = r
        crash = {"page": "health:crash", "label": "Почему"}
        for x in r.get("summary") or []:
            if x["text"].startswith("Устройств с ошибками") and (self.health or {}).get("problem_devices"):
                continue
            self.add(s, {"bad": "bad", "warn": "warn"}.get(x["lvl"], "info"), x["text"], "", crash, todo=x["lvl"] in ("bad", "warn"))
        for c in sorted(r.get("crashes") or [], key=lambda c: -c["count"])[:3]:
            self.add(s, "info", f"{c['app']}: вылетов {c['count']}", f"Почему: {c['what']}. Что делать: {c['advice']}", crash, todo=False)
        miss = [x for x in r.get("runtimes") or [] if not x.get("ok") and x.get("need")]
        if miss:
            self.add(s, "warn", "Не хватает компонентов: " + ", ".join(x["name"] for x in miss), "Из-за этого программы и игры могут не запускаться.",
                     {"page": "health:runtimes", "label": "Установить"})
        stab = r.get("stability") or []
        if stab:
            v = stab[-1]["v"]
            self.add(s, "warn" if v < 5 else "ok", f"Индекс стабильности Windows: {v:g} из 10".replace(".", ","), "", None, todo=False)
        snap = self.ctx["metrics"]()
        if snap:
            g = (snap.get("gpu") or {}).get("temp")
            c = (snap.get("sensors") or {}).get("cpu_temp")
            for name, t in (("видеокарты", g), ("процессора", c)):
                if t is not None:
                    self.add(s, "warn" if t >= 85 else "ok", f"Температура {name} сейчас: {round(t)}°C",
                             "Почисти систему охлаждения и проверь, что грузит компьютер." if t >= 85 else "", {"page": "res", "label": "Ресурсы"} if t >= 85 else None)
        if not r.get("summary"):
            self.add(s, "ok", "За 30 дней серьёзных сбоев нет")
        n = sum(1 for i in s["items"] if i["todo"])
        s["label"] = f"замечаний: {n}" if n else "серьёзных сбоев нет"

    # ------------------------------------------------------------ что сделать ещё (вручную)
    def recs(self):
        R = []
        threat = any(s["verdict"] in ("threat", "warn") and s["id"] in ("quick", "deep") for s in self.steps)
        R.append({"kind": "tools", "t": "Проверь ещё отдельными антивирусами" + (" — обязательно, раз есть находки" if threat else ""),
                  "s": "Они запускаются своим окном и сами ведут проверку, поэтому ультра проверка не может пройти их за тебя.",
                  "tools": EXTERNAL, "threat": threat})
        if threat:
            R.append({"t": "Офлайн-проверка Defender", "s": "Раз есть находки — проверь диск до запуска Windows: так Defender находит руткиты, "
                      "которые прячутся от обычной проверки. Компьютер перезагрузится, проверка займёт около 15 минут.",
                      "a": {"run": ["defender", "offline"], "label": "Перезагрузить и проверить"}})
        ads = getattr(self, "ads", None)
        R.append({"t": "Удалить лишние встроенные приложения", "s": (f"Рекламных и пробных приложений Windows: {len(ads)}. " if ads else "") +
                  "Удаляются только для тебя и ничего не ломают — вернуть можно из Microsoft Store.",
                  "a": {"page": "apps:debloat", "label": "Выбрать"}})
        en = getattr(self, "startup_on", None)
        R.append({"t": "Проверить автозагрузку вручную",
                  "s": (f"Вместе с Windows запускается {len(en)} {plural(len(en), 'программа', 'программы', 'программ')}. " if en else "") +
                       "Выключи то, чем пользуешься не каждый день: лаунчеры игр, мессенджеры, «помощники» обновлений. Антивирус и драйверы оставь.",
                  "a": {"page": "speed:boot", "label": "Автозагрузка"}})
        if "startup" in self.sel["steps"] and not getattr(self, "boot", None):
            R.append({"t": "Узнать, что замедляет загрузку Windows", "s": "Журнал загрузки читается с правами администратора — один раз подтверди окно UAC.",
                      "a": {"task": "boot_trace", "label": "Узнать", "page": "speed:boot"}})
        dg = getattr(self, "diag", None) or {}
        if dg.get("whea") or dg.get("bsod"):
            R.append({"t": "Проверить оперативную память", "s": "Были синие экраны или аппаратные ошибки — проверка памяти Windows покажет, не в ней ли дело. "
                                                                   "Нужна перезагрузка, 10–20 минут.",
                      "a": {"launch": "mdsched", "label": "Проверка памяти", "confirm": "Проверка памяти попросит перезагрузить компьютер. Открыть?"}})
        if not self.on("clean", "junk_more") and "clean" in self.sel["steps"]:
            R.append({"t": "Необязательные кэши", "s": "Кэши шейдеров, загрузки Windows Update и снимки ядра ультра проверка не трогала. Их можно удалить в «Очистке», если не хватает места.",
                      "a": {"page": "clean:junk", "label": "Очистка"}})
        R.append({"t": "Поискать дубликаты и пустые папки", "s": "Одинаковые файлы в разных местах — обычно фото, видео и установщики в «Загрузках».",
                  "a": {"page": "disk:dups", "label": "Дубликаты"}})
        return R
