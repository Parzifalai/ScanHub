"""Анонимный счётчик запусков — чтобы автор знал, сколько людей пользуется ScanHub. Только с согласия.

* Спрашиваем один раз (карточка на главной); ответ — config usage_ping: true/false. Пока не ответил — ничего не уходит.
* Раз в сутки, пока ScanHub открыт, уходит одна строка: случайный номер этой копии (uuid4, не связан ни с человеком,
  ни с компьютером), версия ScanHub, язык окна и номер сборки Windows. Никаких имён, путей, находок и IP-адресов
  (адрес видит Cloudflare как у любого запроса, посредник его не сохраняет).
* Принимает тот же посредник, что и «Нашёл ошибку?» (support/cloudflare-worker.js, /ping), автор видит итог на /stats.
"""
import json
import time
import urllib.request
import uuid

import report

PING_URL = report.REPORT_URL.rsplit("/", 1)[0] + "/ping"


def _build():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            return str(winreg.QueryValueEx(k, "CurrentBuildNumber")[0])
    except OSError:
        return ""


def ping(cfg, save, version):
    """Отправить отметку «запущен сегодня», если человек согласился и сегодня ещё не отправляли. save(dict) — дописать в config."""
    if cfg.get("usage_ping") is not True:
        return False
    today = time.strftime("%Y-%m-%d")                       # местная дата: «сегодня» у человека, а не по UTC
    lang = cfg.get("lang") or "ru"
    mark = f"{today}|{version}|{lang}"                       # обновился или сменил язык в тот же день — отметимся ещё раз
    if cfg.get("usage_last") == mark:
        return False
    iid = cfg.get("install_id") or uuid.uuid4().hex
    body = json.dumps({"app": "scanhub", "id": iid, "v": version, "lang": lang, "win": _build(), "day": today}).encode()
    url = (cfg.get("report_url") or report.REPORT_URL).rsplit("/", 1)[0] + "/ping"
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json", "User-Agent": f"ScanHub/{version}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            ok = json.load(r).get("ok")
    except Exception:
        return False                        # нет сети или посредник ещё не умеет /ping — попробуем завтра, без записи в журнал ошибок
    if ok:
        save({"install_id": iid, "usage_last": mark})
    return bool(ok)


def loop(get_cfg, save, version):
    time.sleep(90)                          # не мешать открытию окна
    while True:
        try:
            ping(get_cfg(), save, version)
        except Exception:
            pass
        time.sleep(6 * 3600)
