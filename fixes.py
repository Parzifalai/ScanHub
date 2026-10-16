"""Мастер исправлений после ультра проверки: всё найденное — по шагам.

Что ScanHub может сделать сам — кнопкой (или галочками, если вариантов несколько). Чего не может — инструкцией «сделай сам».
Последний шаг — сторонние сканеры. Перед составлением списка всё, что можно исправить, проверяется заново: с момента ультра
проверки что-то могло поменяться, а сервер разрешает изменения только по свежим результатам (scanhub._only_found).
"""
import os
import re
import shutil

import system
import tweaks

GROUPS = ["Угрозы", "Система", "Место на диске", "Обновления", "Автозагрузка", "Приватность и защита", "Браузеры", "Сбои и устройства",
          "Сделай сам", "Сторонние сканеры"]
EXTERNAL = ["cureit", "kvrt", "eset", "emsisoft", "msert", "malwarebytes", "adwcleaner"]     # MinerSearch идёт внутри глубокой проверки
# необязательные кэши, которые по умолчанию отмечены (создаются заново сами); медиа Telegram и кэши разработки — нет
DEFAULT_GROUPS = ("Windows", "Браузеры", "Игры и видеокарта")


def fmt(b):
    b = float(b or 0)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if b < 1024 or unit == "ТБ":
            return (f"{b:.0f}" if unit in ("Б", "КБ") or b >= 100 else f"{b:.1f}".replace(".", ",")) + " " + unit
        b /= 1024


class Plan:
    def __init__(self, task, ultra_job, progress):
        self.task, self.prog = task, progress
        self.job = ultra_job or {}
        self.todo = self.job.get("todo") or []
        self.covered = set()
        self.cards = []

    def run_task(self, name, args=None, text=""):
        self.prog(text or name)
        t = self.task(name, args or {})
        return t.get("result") if t.get("status") == "done" else None

    def cover(self, rx):
        for i, t in enumerate(self.todo):
            if re.search(rx, t["t"], re.I):
                self.covered.add(i)

    def card(self, cid, group, lvl, title, text, kind, **kw):
        self.cards.append({"id": cid, "group": group, "lvl": lvl, "title": title, "text": text, "kind": kind, **kw})

    # ------------------------------------------------------------ сборка
    def build(self):
        for step in (self.threats, self.system_files, self.space, self.updates, self.startup, self.privacy, self.browsers):
            try:
                step()
            except Exception as e:                       # один сломанный шаг не должен ломать весь мастер
                self.card(f"err-{step.__name__}", "Сделай сам", "info", f"Не удалось подготовить: {step.__name__}", str(e)[:200], "manual",
                          how=["Открой соответствующий раздел ScanHub и проверь вручную."])
        self.leftover_manual()
        self.restart()
        self.card("scanners", "Сторонние сканеры", "info", "Проверь компьютер ещё сторонними антивирусами",
                  "Это последний этап. Эти сканеры работают только своим окном и сами ведут проверку — ScanHub не может пройти их за тебя. "
                  "Два-три разных антивируса находят больше, чем один. Начни с Dr.Web CureIt! и KVRT, они самые сильные из бесплатных.",
                  "scanners", tools=EXTERNAL,
                  note="Malwarebytes ставится как программа: после проверки его можно удалить, пробный Premium выключится сам через 14 дней.")
        order = {g: i for i, g in enumerate(GROUPS)}
        self.cards.sort(key=lambda c: order.get(c["group"], 99))
        return {"source": self.job.get("id"), "finished": self.job.get("finished"), "cards": self.cards}

    def threats(self):
        files, seen = [], set()
        for i, t in enumerate(self.todo):
            for f in t.get("files") or []:
                if f["path"] not in seen and os.path.isfile(f["path"]):
                    seen.add(f["path"])
                    files.append({**f, "lvl": t["lvl"], "why": t["t"]})
                    self.covered.add(i)
        if files:
            hard = any(f["lvl"] == "threat" for f in files)
            self.card("quarantine", "Угрозы", "threat" if hard else "warn", f"Подозрительные файлы: {len(files)}",
                      "Карантин переносит файл в папку ScanHub и кодирует его — запуститься он больше не сможет, а если это ложная тревога, "
                      "его можно вернуть в «Проверка на вирусы → Карантин». Если файл знаком и на него ругаются 1–2 антивируса из 70 — "
                      "скорее всего, это ложная тревога: пропусти этот шаг.",
                      "choice", items=[{"id": f["path"], "label": os.path.basename(f["path"]), "sub": f"{f['path']} · {f.get('name') or f['why']}",
                                        "on": f["lvl"] == "threat", "value": {"path": f["path"], "name": f.get("name", ""), "engine": f.get("engine", "")}}
                                       for f in files],
                      apply={"task": "quarantine", "arg": "files", "label": "В карантин выбранные",
                             "confirm": "Убрать выбранные файлы в карантин? Программы, которым они нужны, перестанут работать."})
        for i, t in enumerate(self.todo):
            if t["t"].startswith("Defender нашёл угрозы"):
                self.covered.add(i)
                self.card("defender-threats", "Угрозы", "threat", "Defender нашёл угрозы",
                          "Обычно он обезвреживает их сам, но стоит посмотреть, что именно найдено и всё ли удалено.", "manual",
                          how=["Открой «Безопасность Windows» → «Защита от вирусов и угроз» → «Журнал защиты».",
                               "У каждой угрозы проверь состояние: «Удалено» или «Помещено в карантин». Если «Разрешено» или «Активно» — нажми «Действия» → «Удалить»."],
                          open={"launch": "defender", "label": "Открыть журнал защиты"})

    def system_files(self):
        sf = self.last("sysfiles")
        if sf and not sf.get("cards"):
            import deepscan
            sf = {**sf, "cards": deepscan.sysfiles_cards(sf)}
        # «Восстановить» — только если оно может помочь (не после ошибки «нет исправных копий» и не при одной лишь перезагрузке)
        broken = any(c["action"] == "repair" for c in (sf or {}).get("cards") or []) if sf else \
            any(re.search(r"Хранилище компонентов|повреждённые системные|Повреждены системные", t["t"]) for t in self.todo)
        self.cover(r"Хранилище компонентов|Хранилище системных|повреждённые системные|Повреждены системные|Системные файлы|повреждение в хранилище|Повреждение в хранилище")
        if broken:
            self.card("sfc", "Система", "bad", "Восстановить системные файлы Windows",
                      "Повреждено хранилище компонентов — «склад» исправных копий системных файлов. Через него ставятся обновления и чинятся "
                      "испорченные файлы. ScanHub откроет окно администратора: DISM скачает исправные файлы из Windows Update, потом SFC "
                      "перепроверит систему. 15–30 минут, нужен интернет, потом перезагрузка.",
                      "auto", do={"launch": "sfc_repair", "label": "Восстановить", "uac": True,
                                  "confirm": "Запустить восстановление системных файлов? Откроется окно администратора на 15–30 минут. Не закрывай его до надписи «Готово»."},
                      open={"launch": "component_cleanup", "label": "Очистить старые версии компонентов 🛡",
                            "confirm": "Очистить хранилище компонентов? Windows удалит старые версии компонентов, уже заменённые обновлениями: "
                                       "освободится место, а если повреждены именно старые копии — пропадёт и повреждение. Минус: эти обновления "
                                       "нельзя будет удалить. Откроется окно администратора на 10–30 минут."},
                      note="На тестовых сборках Windows (Insider) DISM часто не находит исправных файлов (ошибка 0x800f0915 или 0x800f081f): "
                           "у Microsoft нет файлов именно для этой сборки. Тогда помогает «Очистить старые версии компонентов» — если повреждены "
                           "старые копии, они просто удалятся. Иначе починит следующая сборка Windows.")
        d = (sf or {}).get("disk") or {}
        if d.get("trim_on") is False:
            self.cover(r"TRIM")
            self.card("trim", "Система", "warn", "Включить TRIM для SSD",
                      "Без TRIM SSD со временем замедляется. ScanHub выполнит TRIM для всех дисков сейчас.", "auto",
                      do={"task": "trim", "label": "Выполнить TRIM", "uac": True})

    def space(self):
        u = shutil.disk_usage("C:\\")
        free = u.free / u.total * 100
        js = self.run_task("junk_scan", text="считаю, сколько ещё можно освободить") or {}
        cats = [c for c in js.get("categories", []) if (c.get("size") or 0) >= 20 * 2 ** 20]
        rb = js.get("recycle") or {}
        items = [{"id": c["id"], "label": c["label"], "sub": f"{fmt(c['size'])} · {c.get('desc', '')}", "on": bool(c.get("safe") or c["grp"] in DEFAULT_GROUPS),
                  "value": c["id"], "size": c["size"], "admin": bool(c.get("admin"))} for c in cats]
        if rb.get("size"):
            items.append({"id": "recycle", "label": f"Корзина ({rb['count']} файлов)", "sub": f"{fmt(rb['size'])} · удаляется навсегда — сначала загляни в неё",
                          "on": False, "value": "recycle", "size": rb["size"]})
        self.cover(r"Диск C:|На C:|Корзине")
        if items and (free < 20 or sum(i["size"] for i in items) > 2 ** 30):
            self.card("junk", "Место на диске", "bad" if free < 10 else "warn",
                      f"Освободить место на C: (сейчас свободно {fmt(u.free)}, {round(free)}%)",
                      "Это то, что ультра проверка не удаляла по умолчанию: кэши шейдеров, загрузки обновлений, диагностические снимки, Корзина. "
                      "Кэши создадутся заново сами. Медиа Telegram и кэши разработки не отмечены — они тоже восстановятся, но скачиваются снова.",
                      "choice", items=items, apply={"task": "junk_clean", "arg": "ids", "label": "Удалить выбранное", "uac_if": True},
                      open={"page": "disk:disk", "label": "Большие файлы — посмотреть самому"},
                      note="Самое большое на диске обычно — твои файлы, игры и программы. Их ScanHub сам не удаляет: открой «Что занимает место», "
                           "там видно, какие папки и файлы больше всего, и их можно отправить в Корзину.")

    def updates(self):
        apps = (self.last("winget") or {}).get("apps")
        if apps is None:
            apps = (self.run_task("winget", text="спрашиваю winget, какие программы устарели — до минуты") or {}).get("apps")
        self.cover(r"Устарело|Удалённые программы в списке")
        ghosts = [a for a in apps or [] if a.get("ghost")]
        apps = [a for a in apps or [] if not a.get("ghost")]
        if ghosts:
            self.card("winget_ghosts", "Обновления", "info", f"Удалённые программы в списке Windows: {len(ghosts)}",
                      "Программ уже нет — ни папки, ни деинсталлятора, — но запись в списке установленных осталась, поэтому winget предлагает "
                      "их «обновить». Обновлять не нужно: ScanHub уберёт лишние записи (сначала сохранит их копию). Если программа нужна — "
                      "просто поставь её заново.",
                      "choice", items=[{"id": a["ghost"]["key"], "label": a["name"], "sub": f"версия {a.get('version')} · деинсталлятора и папки программы нет",
                                        "on": True, "value": a["ghost"]["key"], "admin": not a["ghost"]["key"].startswith("HKCU")} for a in ghosts],
                      apply={"task": "force_remove_many", "arg": "keys", "label": "Убрать записи", "uac_if": True})
        if apps:
            self.card("winget", "Обновления", "warn", f"Обновить программы: {len(apps)}",
                      "В старых версиях программ находят уязвимости. ScanHub скачает установщики, проверит каждый на вирусы (подпись, Defender, "
                      "VirusTotal) и поставит тихо. Если на файл ругаются антивирусы — программа придерживается и не ставится.",
                      "choice", items=[{"id": a["id"], "label": a["name"], "sub": f"{a['version']} → {a['available']}", "on": True, "value": a["id"]} for a in apps],
                      apply={"updates": True, "label": "Проверить и обновить выбранные"},
                      open={"page": "apps:winget", "label": "Ход обновления"},
                      note="Программы «для всех пользователей» попросят одно окно UAC на все сразу. Открытые программы лучше закрыть — "
                           "иначе они обновятся после перезапуска или пропустятся.")
        if any(t["t"].startswith("Windows Update нашёл драйверы") for t in self.todo):
            self.cover(r"Windows Update нашёл драйверы")
            t = next(t for t in self.todo if t["t"].startswith("Windows Update нашёл драйверы"))
            self.card("wu_drivers", "Обновления", "warn", "Установить новые драйверы", t["s"], "manual",
                      how=["ScanHub откроет Windows Update → «Необязательные обновления» → «Обновления драйверов».",
                           "Отметь найденные драйверы и нажми «Скачать и установить». Потом перезагрузи компьютер."],
                      open={"launch": "wu_optional", "label": "Открыть Windows Update"},
                      why="Сам ScanHub драйверы не ставит: это делает Windows Update — так безопаснее, и откат всегда возможен.")
        rt = self.run_task("runtimes", text="проверяю компоненты для программ") or {}
        miss = [x for x in rt.get("items") or [] if not x.get("ok") and x.get("need") and x.get("winget")]
        self.cover(r"Не хватает компонентов")
        if miss:
            self.card("runtimes", "Обновления", "warn", "Установить недостающие компоненты",
                      "Без них программы и игры не запускаются с ошибкой «не найден …dll». Установка — через winget, каждая в своём окне.",
                      "choice", items=[{"id": x["winget"], "label": x["name"], "sub": x.get("desc", ""), "on": True, "value": x["winget"]} for x in miss],
                      apply={"launch_each": "winget_install:", "label": "Установить выбранные"})

    def startup(self):
        st = self.run_task("startup", text="собираю автозагрузку") or {}
        en = [i for i in st.get("items") or [] if i.get("enabled")]
        core = [i for i in en if _essential(i)]          # антивирус, звук, тачпад, видеодрайвер — выключать не стоит
        en = [i for i in en if not _essential(i)]
        self.cover(r"автозагрузки без файла|Замедляют загрузку")
        if en:
            sec = lambda ms: f"{ms / 1000:.1f}".replace(".", ",") + " с"
            items = [{"id": i["id"], "label": i["name"],
                      "sub": " · ".join(x for x in [i.get("where", ""), "файла нет — программа удалена" if i.get("missing") else "",
                                                    f"замедляет загрузку на {sec(i['delay_ms'])}" if i.get("delay_ms") else "",
                                                    ("✓ " + i["signer"]) if i.get("signer") else "без подписи"] if x),
                      "on": bool(i.get("missing")), "value": i["id"], "admin": bool(i.get("admin"))} for i in en]
            self.card("startup", "Автозагрузка", "warn" if any(i.get("missing") for i in en) else "info",
                      f"Что запускается вместе с Windows: {len(en)}",
                      "Выключение работает как в Диспетчере задач: программа остаётся установленной, просто не стартует сама. Включить обратно можно "
                      "в «Скорость → Автозагрузка». Обычно смело выключают лаунчеры игр, мессенджеры и «помощники» обновлений; антивирус и драйверы "
                      "(звук, тачпад, Lenovo) лучше оставить. Отмечены только записи удалённых программ — остальное решай сам.",
                      "choice", items=items, apply={"task": "startup_set", "each": "id", "args": {"enable": False}, "label": "Выключить выбранные"},
                      note=(f"Не показано системных записей: {len(core)} ({', '.join(i['name'] for i in core[:4])}{'…' if len(core) > 4 else ''}): "
                            "защита Windows, драйверы звука, тачпада и видеокарты — без них что-то перестанет работать. "
                            "Они есть в «Скорость → Автозагрузка».") if core else None)

    def privacy(self):
        pv = self.run_task("privacy", text="проверяю приватность") or []
        pv = pv.get("items", []) if isinstance(pv, dict) else pv
        off = [i for i in pv if not i.get("applied")]
        self.cover(r"настроек приватности")
        if any(i.get("rec") for i in off):
            self.card("privacy", "Приватность и защита", "info", "Выключить слежку и рекламу Windows",
                      "Только безопасные настройки: они не ломают обновления, Microsoft Store, вход в аккаунт и антивирус. Исходные значения "
                      "сохраняются — «Приватность → вернуть как было» восстановит их точно.", "choice",
                      items=[{"id": i["id"], "label": i["title"], "sub": i.get("desc", ""), "on": bool(i.get("rec")), "value": i["id"],
                              "admin": bool(i.get("admin"))} for i in off],
                      apply={"task": "privacy_apply", "arg": "ids", "args": {"restore_point": True}, "label": "Применить выбранное", "uac_if": True})
        sc = self.run_task("security", text="проверяю защиту Windows") or []
        sc = sc.get("items", []) if isinstance(sc, dict) else sc
        self.cover(r"защиты Windows")
        weak = [i for i in sc if i.get("ok") is False and i.get("kind") == "fix"]
        if weak:
            self.card("security", "Защита Windows", "warn", "Включить выключенные защиты Windows",
                      "Встроенные защиты от вирусов и взлома. Исходные значения сохраняются — «Приватность и защита → Защита Windows → вернуть как было» "
                      "восстановит их. Часть заработает после перезагрузки.", "choice",
                      items=[{"id": i["id"], "label": i["title"], "sub": i.get("desc", ""), "on": bool(i.get("rec")), "value": i["id"],
                              "admin": bool(i.get("admin"))} for i in weak],
                      apply={"task": "security_apply", "arg": "ids", "args": {"restore_point": True}, "label": "Включить выбранное", "uac_if": True})
        manual = [i for i in sc if i.get("ok") is False and i.get("kind") == "manual" and i.get("rec")]
        for i in manual:
            self.card("security_" + i["id"], "Защита Windows", "warn", f"Включить: {i['title']}", i.get("desc", ""), "manual",
                      open={"launch": i["launch"], "label": "Открыть"})
        fw = self.run_task("firewall", text="читаю правила брандмауэра") or {}
        groups = {}
        for r in fw.get("rules") or []:
            if r.get("enabled") and r.get("level") == "warn":
                groups.setdefault(r["name"] + "|" + (r.get("prog") or ""), {**r, "ids": []})["ids"].append(r["id"])
        dead = [g for g in groups.values() if any("программы больше нет" in f for f in g["flags"])]
        other = [g for g in groups.values() if g not in dead]
        self.cover(r"брандмауэра")
        if dead or other:
            self.card("firewall", "Приватность и защита", "warn", f"Правила брандмауэра с замечаниями: {len(groups)}",
                      "Правило брандмауэра разрешает программе принимать подключения из сети. Правила удалённых программ больше не нужны — "
                      "они отмечены, их можно смело выключить (не удаляются, включаются обратно в «Приватность → Брандмауэр»). "
                      "Остальные правила с замечаниями (программы из временных папок, открытые для публичных сетей) — реши сам.",
                      "choice", items=[{"id": g["ids"][0], "label": g["name"], "sub": f"{'; '.join(g['flags'])} · {g.get('prog') or ''}",
                                        "on": g in dead, "value": g["ids"]} for g in dead + other],
                      apply={"task": "firewall_set", "arg": "ids", "flatten": True, "args": {"enable": False}, "label": "Выключить выбранные", "uac": True})
        rs = tweaks.restore_status()
        self.cover(r"Точки восстановления")
        if not rs["enabled"] and not rs.get("policy_off"):
            u = shutil.disk_usage("C:\\")
            self.card("restore", "Приватность и защита", "warn", "Включить точки восстановления",
                      "Точка восстановления — снимок системы. Если обновление или драйвер что-то сломает, Windows можно откатить, не трогая "
                      "личные файлы. ScanHub включит защиту системы для C: и сразу создаст первую точку.", "auto",
                      do={"task": "restore_enable", "label": "Включить и создать точку", "uac": True},
                      note=f"Займёт до 5% диска C: (≈{fmt(u.total * 0.05)}), старые точки Windows удаляет сама." +
                           (" Сейчас на C: мало места — лучше сначала освободить его (шаг «Место на диске»)." if u.free < u.total * 0.1 else ""))
        hs = system.hosts_status()
        self.cover(r"майнинг-доменов")
        if not hs.get("enabled") and not hs.get("error"):
            self.card("hosts", "Приватность и защита", "info", "Заблокировать майнинг-домены",
                      "В файл hosts добавится список NoCoin (~1000 адресов): браузерные майнеры и часть вредоносов не смогут связаться со своими "
                      "серверами. Ничего не работает постоянно — это просто строчки в файле. Выключить можно в «Приватность → Защита от майнеров».",
                      "auto", do={"task": "hosts_set", "args": {"enable": True}, "label": "Включить блокировку", "uac": True})
        cx = self.run_task("ctx", text="проверяю меню правой кнопки") or {}
        dead_ctx = [i for i in cx.get("items") or [] if i.get("exists") is False and i.get("enabled")]
        self.cover(r"меню правой кнопки")
        if dead_ctx:
            self.card("ctx", "Приватность и защита", "info", f"Убрать из меню правой кнопки пункты удалённых программ: {len(dead_ctx)}",
                      "Программы удалены, а их пункты остались и только загромождают меню. Выключение обратимо — «Приватность → Контекстное меню».",
                      "choice", items=[{"id": i["id"], "label": i["label"], "sub": i.get("where", ""), "on": True, "value": i["id"], "admin": bool(i.get("admin"))}
                                       for i in dead_ctx],
                      apply={"task": "ctx_set", "each": "id", "args": {"enable": False, "restore_point": False}, "label": "Убрать выбранные", "uac_if": True})
        pth = self.run_task("envpath", text="проверяю PATH") or {}
        bad = [e for e in pth.get("entries") or [] if e.get("problem") in ("повтор", "папки нет")]
        self.cover(r"PATH")
        if bad:
            self.card("path", "Приватность и защита", "info", f"Убрать лишние записи из PATH: {len(bad)}",
                      "PATH — список папок, где Windows ищет программы для команд в терминале. Записи на удалённые папки и повторы не нужны. "
                      "Старое значение сохраняется в D:\\ScanHub\\data\\backups.", "choice",
                      items=[{"id": e["scope"] + "|" + e["entry"], "label": e["entry"], "sub": ("повтор записи выше" if e["problem"] == "повтор" else "этой папки нет") +
                              (" · для всех пользователей" if e["scope"] == "system" else " · для тебя"), "on": True,
                              "value": {"scope": e["scope"], "entry": e["entry"]}, "admin": e["scope"] == "system"} for e in bad],
                      apply={"task": "envpath_fix", "arg": "remove", "args": {"restore_point": False}, "label": "Убрать выбранные", "uac_if": True})
        ax = self.run_task("appx", text="смотрю встроенные приложения") or []
        ads = [a for a in ax if a.get("grp") == "ad"]
        if ads:
            self.card("debloat", "Приватность и защита", "info", f"Удалить рекламные приложения Windows: {len(ads)}",
                      "Windows ставит их, чтобы рекламировать сервисы Microsoft и партнёров. Удаляются только для тебя и ничего не ломают; "
                      "вернуть любое можно из Microsoft Store.", "choice",
                      items=[{"id": a["full"], "label": a["title"], "sub": a.get("desc", ""), "on": True, "value": a["full"]} for a in ads],
                      apply={"task": "appx_remove", "arg": "fulls", "label": "Удалить выбранные"},
                      open={"page": "apps:debloat", "label": "Все встроенные приложения"})

    def browsers(self):
        import browsers as B
        br = self.run_task("browsers", text="проверяю браузеры") or {}
        self.cover(r"расширение «|политики|прокси")
        ext = [e for e in br.get("extensions") or [] if e["level"] in ("bad", "warn")]
        if ext:
            self.card("extensions", "Браузеры", "bad" if any(e["level"] == "bad" for e in ext) else "warn",
                      f"Проверить расширения браузера: {len(ext)}",
                      "Расширения удаляются только в самом браузере — ScanHub не может сделать это за тебя.", "manual",
                      list=[f"{e['browser']}: «{e['name']}» — {'; '.join(e['flags'])}" for e in ext],
                      how=["Открой браузер → меню ⋮ → «Расширения» → «Управление расширениями».",
                           "У расширений из списка выше, которые ты не ставил сам, нажми «Удалить».",
                           "Если расширение возвращается после удаления — его ставит политика или программа: запусти AdwCleaner (шаг «Сторонние сканеры»)."],
                      open={"page": "privacy:browsers", "label": "Подробнее о расширениях"})
        for p in br.get("policies") or []:
            self.card("policy-" + p["browser"], "Браузеры", "warn", f"{p['browser']}: браузером управляют политики",
                      ", ".join(i["what"] for i in p["items"]) + f". Ключ реестра: {p['key']}.", "manual",
                      how=["На домашнем компьютере политики обычно ставит угонщик браузера или «оптимизатор».",
                           "Запусти Malwarebytes AdwCleaner (шаг «Сторонние сканеры») — он удаляет такие политики.",
                           "Если это рабочий компьютер организации — ничего не делай, политики ставит администратор."],
                      open={"run": ["adwcleaner", "run"], "label": "Запустить AdwCleaner"})
        px = br.get("proxy") or {}
        if px.get("proxy") or px.get("pac"):
            self.card("proxy", "Браузеры", "warn", "Трафик идёт через прокси", f"{px.get('proxy') or ''} {px.get('pac') or ''}".strip(), "manual",
                      how=["Если это твой VPN, Fiddler или другая знакомая программа — всё в порядке.",
                           "Если нет — открой «Параметры → Сеть и Интернет → Прокси» и выключи прокси, затем запусти AdwCleaner и KVRT."],
                      open={"launch": "proxy", "label": "Настройки прокси"})

    def leftover_manual(self):
        """Всё, что ультра проверка нашла, но исправить можно только самому."""
        how = [
            (r"Устройств\w* с ошибками", ["Открой «Здоровье ПК → Драйверы» — там видно, какое устройство и почему не работает.",
                                         "Чаще всего помогает драйвер из Windows Update («Необязательные обновления») или с сайта производителя ноутбука."],
             {"page": "health:drivers", "label": "Драйверы"}),
            (r"видеодрайвер", ["Обнови драйвер видеокарты: для NVIDIA — через приложение NVIDIA App или сайт nvidia.com.",
                               "Если сбои повторяются — проверь температуру видеокарты под нагрузкой и отключи разгон."],
             {"page": "health:crash", "label": "Подробнее о сбое"}),
            (r"Вылетов программ|вылет", ["Открой «Здоровье ПК → Сбои и ошибки» — у каждой программы написано, почему она вылетала и что делать.",
                                        "Обычно помогает обновить или переустановить программу."], {"page": "health:crash", "label": "Почему вылетали"}),
            (r"Синих экранов|Аппаратных ошибок|Ошибок диска", ["Открой «Здоровье ПК → Сбои и ошибки» — там причина по коду ошибки и что делать.",
                                                               "Сделай резервную копию важных файлов."], {"page": "health:crash", "label": "Сбои"}),
            (r"^Диск [A-Z]:", ["Открой «Место на диске → Что занимает место» и выбери этот диск.",
                               "Удали или перенеси ненужные большие файлы и игры; удалённое уходит в Корзину."], {"page": "disk:disk", "label": "Что занимает место"}),
            (r"перезагрузк|Без перезагрузки", ["Сохрани файлы, закрой программы и перезагрузи компьютер (Пуск → Выключение → Перезагрузка)."], None),
            (r"Защита в реальном времени|Защита от подделки|Брандмауэр выключен|UAC",
             ["Открой «Безопасность Windows» и включи выключенную защиту.", "Если она снова выключается сама — запусти KVRT и Dr.Web CureIt!."],
             {"launch": "defender", "label": "Безопасность Windows"}),
            (r"Уязвимые драйверы", ["Открой «Проверка на вирусы → Глубокая проверка», шаг «Уязвимые драйверы»: там написано, какой программе принадлежит драйвер.",
                                    "Не пользуешься этой программой — удали её. Пользуешься — нажми «Отключить драйвер» (вернуть можно там же кнопкой «Включить обратно»).",
                                    "Перезагрузи компьютер: драйвер перестанет загружаться."], {"page": "scan:deep", "label": "Глубокая проверка"}),
            (r"Онлайн-сверка", ["Открой «Проверка на вирусы → Глубокая проверка», шаг «Онлайн-сверка»: у каждого файла есть кнопка «Почему?» — она покажет, какие антивирусы и что нашли.",
                               "1–2 тревоги из 70 эвристикой — обычно ложные. Если файл скачан не с официального сайта или ты его не знаешь — убери в карантин."],
             {"page": "scan:deep", "label": "Глубокая проверка"}),
            (r"Откуда скачаны", ["Открой «Проверка на вирусы → Глубокая проверка», шаг «Откуда скачаны программы»: там видно, с какого сайта каждый файл.",
                                 "Файл с опасного сайта лучше удалить и скачать заново с официального сайта программы."], {"page": "scan:deep", "label": "Глубокая проверка"}),
            (r"Браузеры: на что посмотреть", ["Открой «Приватность и защита → Браузеры»: у каждого расширения написано, что с ним не так.",
                                              "Расширение из базы вредоносных или которое ты не ставил — удали в настройках браузера (Расширения → Удалить)."],
             {"page": "privacy:browsers", "label": "Браузеры"}),
            (r"Обновление BIOS не устанавливается", ["Подключи родную зарядку и убедись, что ноутбук заряжается.",
                                                     "Сохрани файлы и нажми Пуск → Выключение → «Перезагрузка» (не выключение).",
                                                     "Не отключай зарядку и не закрывай крышку, пока Windows не загрузится сама — обновление займёт несколько минут."], None),
            (r"Подозрительные записи автозапуска|Не сработало", ["Открой подробности и реши по каждой записи; при сомнениях — проверь файл."], None),
        ]
        for i, t in enumerate(self.todo):
            if i in self.covered:
                continue
            steps, act = next(((h, a) for rx, h, a in how if re.search(rx, t["t"], re.I)), (None, None))
            a = act or (t.get("a") if t.get("a") and not t["a"].get("task") else None)
            self.card(f"todo-{i}", "Сбои и устройства" if steps and act and act.get("page", "").startswith("health") else "Сделай сам",
                      t["lvl"] if t["lvl"] in ("threat", "bad", "warn") else "info", t["t"], t.get("s") or "", "manual",
                      how=steps or ["ScanHub не может исправить это сам — открой раздел и посмотри подробности."], open=a, todo=t["t"])

    def restart(self):
        if any(c["id"] in ("sfc",) for c in self.cards) or any(re.search(r"перезагрузк", t["t"], re.I) for t in self.todo):
            self.card("reboot", "Сделай сам", "info", "Перезагрузи компьютер в конце",
                      "После восстановления системных файлов, драйверов и обновлений Windows нужна перезагрузка, чтобы всё применилось.", "manual",
                      how=["Дождись, пока закончатся окна восстановления системы и обновления программ.",
                           "Сохрани файлы и перезагрузи компьютер: Пуск → Выключение → Перезагрузка."])


ESSENTIAL_RX = re.compile(r"securityhealth|windows defender|realtek|rtkaud|rthdvcpl|waves|maxxaudio|dolby|nahimic|synaptics|elan|"
                          r"touchpad|igfx|intel.*graphics|nvidia|nvbackend|amd.*(radeon|software)|radeonsoftware|lenovo|vantage|"
                          r"bluetooth|onedrive.*setup|ctfmon|smartscreen", re.I)


def _essential(i):
    """Запись автозагрузки, без которой что-то перестанет работать: защита Windows и драйверы устройств."""
    text = " ".join(str(i.get(k) or "") for k in ("name", "cmd", "exe", "where"))
    return bool(ESSENTIAL_RX.search(text)) or (i.get("signer") or "").startswith("Microsoft Windows")


def build(task, last, ultra_job, progress=lambda s: None):
    p = Plan(task, ultra_job, progress)
    p.last = last
    return p.build()
