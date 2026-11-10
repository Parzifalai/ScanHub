"""Сводки для второго мнения ИИ (Claude, ChatGPT, Gemini…): человек копирует текст и вставляет в чат.

check_summary — всё об одной проверке файла или папки: что за объект (подпись, хэши, откуда скачан, прошлые проверки),
итог ScanHub, каждый сканер с вердиктом, подробностями (VirusTotal — по каждому движку) и концом журнала, список проверенных файлов.
pc_summary — всё, что ScanHub знает о компьютере: защита, находки, сбои, железо, диски, программы, автозагрузка, драйверы,
приватность, браузеры, сеть, угрозы, история проверок, здоровье.

Обе возвращают два текста: обычный и с личным, скрытым как у помощника (имя учётной записи и ПК, почта); ключи и пароли скрыты всегда.
Последняя сводка лежит в data\\summaries — «Сохранить файлом» копирует её в Загрузки.
"""
import hashlib
import json
import os
import platform
import re
import shutil
import time
from datetime import datetime

import assistant

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
OUT_DIR = os.path.join(DATA, "summaries")
FULL_CFG = {"ai_files": "read"}          # сводку человек заказывает сам — файл и папку смотрим полностью


def _win():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            g = lambda n: winreg.QueryValueEx(k, n)[0]
            return f"{g('ProductName')} {g('DisplayVersion')} (сборка {g('CurrentBuild')}.{g('UBR')})"
    except OSError:
        return platform.platform()


def _head(title, version):
    return (f"# {title}\n\nСформировано ScanHub {version} — {datetime.now():%Y-%m-%d %H:%M} · {_win()}\n"
            "ScanHub — набор разовых сканеров для Windows; ниже — сырые данные его проверок.\n")


def _block(obj):
    text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, indent=1, default=str)
    return "```\n" + text.strip() + "\n```\n"


def _secrets_only(text):
    """Ключи сервисов и пароли скрыты всегда, даже в «полном» тексте."""
    cfg = _cfg()
    for k in ("virustotal_key", "filescan_key", "metadefender_key", "hybrid_key", "gemini_key", "deepseek_key", "github_token",
              "anthropic_key", "openai_key", "openrouter_key"):
        v = cfg.get(k)
        if v and len(v) >= 8:
            text = text.replace(v, "<ключ>")
    for rx in assistant.SECRET_RE:
        text = rx.sub("<скрыто>", text)
    return text


def _cfg():
    try:
        import scanhub
        return scanhub.config()
    except Exception:
        return {}


def _finish(kind, text):
    full = _secrets_only(text)
    private = assistant.redact(full, _cfg())
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, t in ((f"{kind}.md", full), (f"{kind}-private.md", private)):
        with open(os.path.join(OUT_DIR, name), "w", encoding="utf-8") as f:
            f.write(t)
    return {"text": private, "text_full": full, "chars": len(full), "kind": kind}


def save_copy(kind, private=True):
    """Копия последней сводки в «Загрузки»; возвращает путь."""
    src = os.path.join(OUT_DIR, f"{kind}{'-private' if private else ''}.md")
    if not os.path.exists(src):
        raise RuntimeError("сводка ещё не собрана — нажми «Скопировать сводку» ещё раз")
    try:
        import intel
        dl = intel.download_folders()[0]
    except Exception:
        dl = os.path.join(os.path.expanduser("~"), "Downloads")
    name = {"check": "проверка", "pc": "компьютер"}.get(kind, kind)
    dst = os.path.join(dl, f"ScanHub — сводка ({name}) {datetime.now():%Y-%m-%d %H-%M}.md")
    shutil.copyfile(src, dst)
    return dst


# ---------------------------------------------------------------- одна проверка файла или папки

ASK_CHECK = """## Что я прошу

Это сводка проверки файла/папки программой ScanHub на моём компьютере. Дай независимое второе мнение:
1. Насколько вероятно, что объект вредоносный: «безопасно / скорее безопасно / подозрительно / опасно» — и почему.
2. Какие сигналы весомые, а какие — типичные ложные срабатывания (эвристики ML/Generic у 1–3 движков, отсутствие в базах для редких файлов, подпись издателя).
3. Сходится ли источник (откуда скачан) с подписью и названием программы.
4. Что мне сделать: запускать, удалить, проверить ещё чем-то (чем именно и как).
Отвечай по-русски, коротко и по делу.
"""


def _hashes(p):
    hs = {n: hashlib.new(n) for n in ("md5", "sha1", "sha256")}
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            for h in hs.values():
                h.update(chunk)
    return {n.upper().replace("SHA", "SHA-"): h.hexdigest() for n, h in hs.items()}


def _log_tail(job, n=80):
    lines = list(job.get("lines") or [])
    if not lines and job.get("log") and os.path.exists(job["log"]):
        try:
            lines = open(job["log"], encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            pass
    lines = [l for l in lines if l.strip()]
    return lines[-n:]


def _files_of(job, limit=600):
    lf = job.get("listfile")
    if lf and os.path.exists(lf):
        try:
            names = [l.strip() for l in open(lf, encoding="utf-8", errors="replace") if l.strip()]
            return names[:limit], len(names)
        except OSError:
            pass
    return [], 0


def _compact_details(details):
    """Ответы VirusTotal/MetaDefender: каждый движок — одной строкой «движок: категория — название угрозы», сработавшие первыми."""
    if not isinstance(details, list):
        return details
    out = []
    for d in details:
        if not isinstance(d, dict) or not isinstance(d.get("engines"), list):
            out.append(d)
            continue
        eng = sorted(d["engines"], key=lambda e: e.get("c") not in ("malicious", "suspicious"))
        d = {k: v for k, v in d.items() if k != "engines"}
        d["движки"] = [f"{e.get('e')}: {e.get('c')}" + (f" — {e.get('r')}" if e.get("r") else "") for e in eng]
        out.append(d)
    return out


def check_summary(jobs, job_ids, verdict=None, target="", excluded=None, version=""):
    rows = [jobs[j] for j in job_ids if j in jobs]
    if not rows:
        raise RuntimeError("этой проверки уже нет в памяти ScanHub — проверь файл ещё раз")
    target = target or next((r.get("target") for r in rows if r.get("target")), "")
    out = [_head("Сводка проверки ScanHub — для второго мнения", version)]

    out.append("## Что проверяли\n")
    if target and os.path.exists(target):
        info = assistant.t_file_info(target, online=False, cfg=FULL_CFG)
        if isinstance(info.get("прошлые_проверки_ScanHub"), list):         # эта проверка описана ниже — в «прошлых» только старые
            info["прошлые_проверки_ScanHub"] = [x for x in info["прошлые_проверки_ScanHub"] if x.get("id") not in job_ids] or "раньше этот путь не проверялся"
        if os.path.isfile(target) and os.path.getsize(target) <= 2 * 2 ** 30:
            try:
                info["хэши"] = _hashes(target)
            except OSError as e:
                info["хэши"] = f"не прочитать: {e}"
        out.append(_block(info))
    else:
        out.append(f"Путь: {target or '—'}" + (" (файла уже нет на диске)" if target else "") + "\n")

    if verdict:
        out.append("## Итог ScanHub\n")
        out.append(f"**{verdict.get('title', '')}** — {verdict.get('text', '')}\n")
        for k, name in (("why", "Почему так"), ("notes", "Заметки")):
            if verdict.get(k):
                out.append(f"{name}:\n" + "\n".join(f"- {x}" for x in verdict[k]) + "\n")

    out.append(f"## Сканеры ({len(rows)})\n")
    for r in rows:
        v = r.get("verdict") or ["", ""]
        dur = ""
        try:
            if r.get("finished"):
                dur = f" · {round((datetime.fromisoformat(r['finished']) - datetime.fromisoformat(r['started'])).total_seconds())} с"
        except (TypeError, ValueError):
            pass
        out.append(f"### {r.get('tool_name')} — {v[1] or v[0] or r.get('status')}\n")
        code = f" · код выхода {r['code']}" if r.get("code") is not None else ""
        out.append(f"Вердикт: `{v[0] or '—'}` · режим: {r.get('mode_label', '')} · состояние: {r.get('status')}{code}{dur}\n")
        if r.get("found"):
            out.append("Найдено:\n" + _block(r["found"]))
        if r.get("details"):
            out.append("Подробности сервиса:\n" + _block(_compact_details(r["details"])))
        tail = _log_tail(r)
        if tail:
            out.append(f"Журнал сканера (последние {len(tail)} строк):\n" + _block("\n".join(tail)))

    files, total = [], 0
    for r in rows:
        f, n = _files_of(r)
        if n > total:
            files, total = f, n
    if total:
        out.append(f"## Проверенные файлы ({total})\n" + _block("\n".join(files) + (f"\n… и ещё {total - len(files)}" if total > len(files) else "")))
    if excluded:
        out.append("## Не участвовали в проверке\n" + "\n".join(f"- {e.get('name')}: {e.get('reason')}" for e in excluded) + "\n")
    out.append(ASK_CHECK)
    return _finish("check", "\n".join(out))


# ---------------------------------------------------------------- весь компьютер

ASK_PC = """## Что я прошу

Это полная сводка моего компьютера, собранная программой ScanHub. Оцени систему как опытный специалист:
1. Общая оценка: безопасность, стабильность, производительность, место, приватность — по шкале «хорошо / есть замечания / плохо», с причинами.
2. Самые важные проблемы — по порядку, с объяснением простыми словами.
3. Что сделать — конкретные шаги (в ScanHub или в Windows), начиная с самого важного.
4. Что выглядит подозрительно (программы, автозагрузка, драйверы, расширения, соединения) и что, наоборот, нормально и трогать не надо.
Отвечай по-русски, без воды.
"""

PC_SECTIONS = [
    ("Система и комплектующие", "system_info", {}),
    ("Что ScanHub нашёл (главная и последние проверки)", "scanhub_findings", {}),
    ("Ультра проверка — последний итог", "ultra_results", {}),
    ("Защита Windows и приватность", "security", {}),
    ("Угрозы: откуда скачаны файлы в «Загрузках»", "threat_intel", {"kind": "downloads"}),
    ("Угрозы: уязвимые драйверы (LOLDrivers)", "threat_intel", {"kind": "drivers"}),
    ("Угрозы: сетевые соединения (Maltrail)", "threat_intel", {"kind": "network"}),
    ("Карантин ScanHub", "quarantine", {}),
    ("История проверок", "scan_history", {"limit": 40}),
    ("Отчёт HiJackThis+", "hjt_report", {}),
    ("Браузеры и расширения", "browsers", {}),
    ("Сбои, вылеты, синие экраны, индекс стабильности (30 дней)", "crashes", {"kind": "all"}),
    ("Комплектующие: проверка", "hardware", {}),
    ("Датчики: температура и вентиляторы", "sensors", {}),
    ("Питание и батарея", "power", {}),
    ("Драйверы и устройства с ошибками", "drivers", {}),
    ("Устройства: клавиатура, мышь, звук, камера, Bluetooth", "devices", {}),
    ("Нагрузка сейчас: процессы", "processes", {}),
    ("Место на дисках", "disk_space", {}),
    ("Автозагрузка", "startup", {}),
    ("Установленные программы", "programs", {}),
    ("Доступные обновления программ", "updates", {}),
    ("Компоненты для программ (VC++, .NET, DirectX, WebView2)", "runtimes", {}),
    ("Сеть: порты, DNS, hosts, Wi-Fi", "network", {}),
    ("История здоровья (батарея, диски, стабильность по дням)", "health_history", {}),
    ("Телефон (последняя проверка)", "phone", {}),
    ("Сканеры ScanHub: что установлено", "scanhub_tools", {}),
]


def pc_summary(progress=None, version=""):
    prog = progress or (lambda s: None)
    out = [_head("Полная сводка компьютера от ScanHub — для оценки системы", version)]
    toc = []
    n = len(PC_SECTIONS)
    for i, (title, tool, args) in enumerate(PC_SECTIONS):
        prog(f"{round(i / n * 100)}% · {title.lower()}")
        t0 = time.time()
        fn = assistant.TOOLS.get(tool, (None,))[0]
        try:
            kw = dict(args)
            if tool in assistant.FILE_TOOLS:
                kw["cfg"] = FULL_CFG
            res = fn(**kw) if fn else {"ошибка": "нет такого инструмента"}
        except Exception as e:
            res = {"ошибка": str(e)[:300]}
        toc.append(title)
        out.append(f"## {title}\n")
        out.append(_block(res))
        if time.time() - t0 > 30:
            out.append(f"_(раздел собирался {round(time.time() - t0)} с)_\n")
    out.insert(1, "## Содержание\n" + "\n".join(f"{i + 1}. {t}" for i, t in enumerate(toc)) + "\n"
               "\nНе вошло в сводку: замер скорости интернета (≈60 МБ трафика) и «почему шумит» (замер 25 с) — их запускают отдельно.\n")
    out.append(ASK_PC)
    prog("100% · готово")
    return _finish("pc", "\n".join(out))
