"""«Нашёл ошибку?» — отчёт об ошибке автору ScanHub.

* Журнал ошибок самого ScanHub (data\\errors.log): падения задач и запросов на сервере и ошибки окна (JS). Это не находки
  сканеров, а ошибки в коде ScanHub — по ним видно, где чинить.
* Отчёт собирается на компьютере, человек видит его целиком до отправки. Имя пользователя, имя компьютера, личные пути,
  почта и ключи вычищаются (как для ИИ-помощника).
* Отправка — на посредник Cloudflare Worker (support/cloudflare-worker.js), он пересылает отчёт автору в Telegram.
  Ключ Telegram-бота хранится только в Worker: в открытом коде ScanHub его нет, достать и злоупотребить им нельзя.
"""
import base64
import hashlib
import json
import os
import platform
import re
import secrets
import sys
import threading
import traceback
import urllib.error
import urllib.request
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
ERRLOG = os.path.join(DATA, "errors.log")
# адрес посредника (Cloudflare Worker); его можно поменять в data\config.json → report_url
REPORT_URL = "https://scanhub-reports.parzifaal2.workers.dev/report"
MAX_LOG = 256 * 1024
_lock = threading.Lock()
_seen = {}
NEW = {"n": 0, "last": ""}          # сколько ошибок записано с запуска — окно предлагает отправить отчёт, когда число растёт


def record(where, err, tb=None):
    """Записать ошибку ScanHub. Одинаковые ошибки подряд не дублируются (счётчик в памяти, раз в 10 минут — снова строка)."""
    try:
        msg = str(err) if not isinstance(err, BaseException) else f"{type(err).__name__}: {err}"
        if isinstance(err, BaseException) and tb is None:
            tb = "".join(traceback.format_exception(type(err), err, err.__traceback__))
        key = (where, msg[:200])
        now = datetime.now()
        last = _seen.get(key)
        if last and (now - last).total_seconds() < 600:
            return
        _seen[key] = now
        tb = _short_tb(tb or "")
        line = json.dumps({"t": now.isoformat(timespec="seconds"), "where": str(where)[:200], "msg": msg[:1500], "tb": tb},
                          ensure_ascii=False)
        with _lock:
            os.makedirs(DATA, exist_ok=True)
            with open(ERRLOG, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            NEW["n"] += 1
            NEW["last"] = f"{where}: {msg}"[:300]
            if os.path.getsize(ERRLOG) > MAX_LOG:          # держим только свежую половину
                lines = open(ERRLOG, encoding="utf-8", errors="replace").read().splitlines()
                open(ERRLOG, "w", encoding="utf-8").write("\n".join(lines[len(lines) // 2:]) + "\n")
    except Exception:
        pass                                               # журнал ошибок сам не должен ронять ScanHub


def _short_tb(tb):
    """Из трассировки — только строки кода ScanHub (файл:строка: функция), без путей стандартной библиотеки."""
    out = []
    for m in re.finditer(r'File "([^"]+)", line (\d+), in (\S+)', tb):
        path, line, fn = m.groups()
        if os.path.normcase(path).startswith(os.path.normcase(ROOT)):
            out.append(f"{os.path.relpath(path, ROOT)}:{line} {fn}")
    if not out:                                            # стек ошибки окна (JavaScript): «at render (/pages.js:120:5)»
        out = [re.sub(r"\s+", " ", m.group(1)) for m in re.finditer(r"at ([^\n]+?/\w+\.js:\d+:\d+\)?)", tb)][:6]
        return " ← ".join(out)
    return " ← ".join(reversed(out[-6:]))


def log_info():
    """Сколько записей в журнале ошибок и за какой срок — для галочки «Приложить журнал ошибок»."""
    items = recent(LOG_SEND)
    return {"n": len(items), "since": items[0].get("t", "") if items else ""}


LOG_SEND = 60                    # сколько последних записей журнала уходит по галочке
MAX_PHOTOS, MAX_PHOTO = 3, 600 * 1024   # снимки экрана: окно сжимает их в JPEG до ~400 КБ


def _photos(items):
    """Снимки из окна: только JPEG/PNG, не больше трёх и не больше 600 КБ каждый. Возвращает base64 без заголовка data:."""
    out = []
    for it in (items or [])[:MAX_PHOTOS]:
        s = str(it or "")
        s = s.split(",", 1)[1] if s.startswith("data:") else s
        try:
            raw = base64.b64decode(s, validate=True)
        except (ValueError, TypeError):
            continue
        if len(raw) > MAX_PHOTO or not (raw[:3] == b"\xff\xd8\xff" or raw[:8] == b"\x89PNG\r\n\x1a\n"):
            continue
        out.append(base64.b64encode(raw).decode())
    return out


def recent(n=15):
    try:
        lines = open(ERRLOG, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return []
    out = []
    for l in lines[-n:]:
        try:
            out.append(json.loads(l))
        except ValueError:
            pass
    return out


def _windows():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            name = winreg.QueryValueEx(k, "ProductName")[0]
            build = winreg.QueryValueEx(k, "CurrentBuildNumber")[0]
            try:
                disp = winreg.QueryValueEx(k, "DisplayVersion")[0]
            except OSError:
                disp = ""
        if int(build) >= 22000:
            name = name.replace("Windows 10", "Windows 11")
        return f"{name} {disp} (сборка {build})".replace("  ", " ")
    except Exception:
        return platform.platform()


def build(body, version, cfg):
    """Отчёт из того, что человек написал в окне, плюс (по галочкам) технические сведения и журнал ошибок ScanHub.
    kind: "bug" — ошибка, "idea" — предложение улучшения. Возвращает dict для отправки и показа."""
    from assistant import redact
    kind = "idea" if body.get("kind") == "idea" else "bug"
    text = str(body.get("text") or "").strip()[:3000]
    steps = str(body.get("steps") or "").strip()[:2000] if kind == "bug" else ""
    contact = str(body.get("contact") or "").strip()[:120]
    rep = {"app": "scanhub", "kind": kind, "version": version, "text": redact(text, cfg), "steps": redact(steps, cfg), "contact": contact}
    tech = {}
    if body.get("tech", True):
        tech.update({
            "windows": _windows(),
            "python": sys.version.split()[0],
            "где": str(body.get("page") or "")[:80],
            "ошибка_на_экране": redact(str(body.get("error") or "")[:1500], cfg),
        })
    if body.get("logs", kind == "bug"):
        errs = []
        for e in recent(LOG_SEND):
            errs.append(f"{e.get('t', '')} · {e.get('where', '')} · {e.get('msg', '')}" + (f"\n    {e['tb']}" if e.get("tb") else ""))
        tech["последние_ошибки_ScanHub"] = redact("\n".join(errs), cfg) if errs else "журнал ошибок пуст"
    if tech:
        rep["tech"] = tech
    photos = _photos(body.get("photos"))
    if photos:
        rep["photos"] = photos
    return rep


def preview_text(rep):
    """То, что человек видит в окне «Что уйдёт автору»."""
    idea = rep.get("kind") == "idea"
    parts = [f"ScanHub {rep['version']}" + (" · предложение" if idea else ""), "", "Что предлагаешь:" if idea else "Что случилось:", rep["text"] or "—"]
    if rep.get("steps"):
        parts += ["", "Что делал перед этим:", rep["steps"]]
    if rep.get("contact"):
        parts += ["", f"Контакт для ответа: {rep['contact']}"]
    t = rep.get("tech")
    if t and t.get("windows"):
        parts += ["", "Технические сведения:", f"Windows: {t['windows']}", f"Python: {t['python']}"]
        if t.get("где"):
            parts.append(f"Раздел: {t['где']}")
        if t.get("ошибка_на_экране"):
            parts.append(f"Ошибка на экране: {t['ошибка_на_экране']}")
    if t and t.get("последние_ошибки_ScanHub"):
        parts += ["", "Журнал ошибок ScanHub:", t["последние_ошибки_ScanHub"]]
    if rep.get("photos"):
        parts += ["", f"Снимков экрана: {len(rep['photos'])} (уйдут картинками, как ты их видишь в окне)"]
    return "\n".join(parts)


TICKETS = os.path.join(DATA, "tickets.json")      # мои сообщения автору: номер, секрет для ответа, начало текста, ответы


def _tickets():
    try:
        return json.load(open(TICKETS, encoding="utf-8"))
    except (OSError, ValueError):
        return []


def _save_tickets(t):
    os.makedirs(DATA, exist_ok=True)
    with open(TICKETS + ".tmp", "w", encoding="utf-8") as f:
        json.dump(t[-50:], f, ensure_ascii=False, indent=1)
    os.replace(TICKETS + ".tmp", TICKETS)


def replies_view():
    """Мои сообщения автору и его ответы (без секретов) — для окна."""
    out = [{k: v for k, v in t.items() if k != "key"} for t in reversed(_tickets())]
    return {"tickets": out, "unread": sum(t.get("unread", 0) for t in out)}


def replies_read():
    with _lock:
        t = _tickets()
        for x in t:
            x["unread"] = 0
        _save_tickets(t)
    return replies_view()


def check_replies(cfg):
    """Спросить посредника, ответил ли автор. Отправляются только номера своих сообщений и секреты к ним. Возвращает число новых ответов."""
    url = (cfg.get("report_url") or REPORT_URL).strip()
    t = _tickets()
    live = [x for x in t if (datetime.now() - datetime.fromisoformat(x["sent"])).days < 180]
    if not url or not live:
        return 0
    data = json.dumps({"tickets": [{"id": x["id"], "key": x["key"]} for x in live[-30:]]}).encode()
    req = urllib.request.Request(re.sub(r"/report$", "/replies", url), data=data, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "ScanHub"})
    with urllib.request.urlopen(req, timeout=20) as r:
        ans = json.load(r)
    new = 0
    with _lock:
        t = _tickets()
        for x in t:
            got = (ans.get("replies") or {}).get(x["id"]) or []
            have = {(a.get("t"), a.get("text")) for a in x.get("replies", [])}
            fresh = [a for a in got if (a.get("t"), a.get("text")) not in have]
            if fresh:
                x["replies"] = x.get("replies", []) + fresh
                x["unread"] = x.get("unread", 0) + len(fresh)
                new += len(fresh)
        if new:
            _save_tickets(t)
    return new


def send(rep, cfg):
    url = (cfg.get("report_url") or REPORT_URL).strip()
    if not url:
        raise RuntimeError("отправка отчётов ещё не настроена в этой копии ScanHub")
    if len(rep.get("text", "")) < 5:
        raise RuntimeError("напиши хотя бы пару слов" + ("" if rep.get("kind") == "idea" else " о том, что случилось"))
    tid, key = secrets.token_hex(8), secrets.token_hex(16)      # по ним этот компьютер (и только он) заберёт ответ автора
    rep = {**rep, "ticket": tid, "ticket_h": hashlib.sha256(key.encode()).hexdigest()}
    data = json.dumps(rep, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": f"ScanHub/{rep.get('version')}"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            ans = json.load(r)
    except urllib.error.HTTPError as e:
        try:
            msg = json.load(e).get("error")
        except Exception:
            msg = None
        if e.code == 429:
            raise RuntimeError("слишком много отчётов подряд — попробуй через 10 минут")
        if e.code == 413 and rep.get("photos"):
            raise RuntimeError("сервер отчётов пока не принимает снимки — убери их и отправь ещё раз")
        raise RuntimeError(msg or f"сервер отчётов ответил {e.code}")
    except (urllib.error.URLError, TimeoutError) as e:
        raise RuntimeError(f"нет связи с сервером отчётов: {getattr(e, 'reason', e)}")
    if not ans.get("ok"):
        raise RuntimeError(ans.get("error") or "отчёт не принят")
    if ans.get("ticket") == tid:                                 # старый посредник ответы не поддерживает — тогда и ждать нечего
        with _lock:
            t = _tickets()
            t.append({"id": tid, "key": key, "kind": rep.get("kind"), "text": rep.get("text", "")[:300],
                      "sent": datetime.now().isoformat(timespec="seconds"), "replies": [], "unread": 0})
            _save_tickets(t)
    return ans
