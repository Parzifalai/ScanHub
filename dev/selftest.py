"""Самопроверка ScanHub: запускает копию сервера на порту 8797, открывает в Edge (без окна) каждый раздел и вкладку
в обоих режимах и ловит ошибки окна, ошибки сервера и подозрительный текст («undefined», «NaN», «[object Object]»).
Ничего не нажимает, кроме переходов между разделами, — на компьютере ничего не меняется.

Запуск: python -X utf8 selftest.py        (--en — то же в английском режиме + список непереведённых строк в i18n_left.txt)
"""
import http.server
import json
import os
import re
import sys
import threading
import time

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # папка ScanHub (dev лежит внутри)
sys.path.insert(0, ROOT_DIR)
os.chdir(ROOT_DIR)
import scanhub  # noqa: E402
import report  # noqa: E402

PORT = 8797
EN = "--en" in sys.argv
CYR = re.compile("[А-Яа-яЁё]")
BAD_TEXT = re.compile(r"\bundefined\b|\bNaN\b|\[object Object\]|null null")


def serve():
    scanhub.PORT = PORT
    scanhub.Server((scanhub.HOST, PORT), scanhub.Handler).serve_forever()


def main():
    threading.Thread(target=serve, daemon=True).start()
    time.sleep(1.5)
    errs_before = report.NEW["n"]
    from playwright.sync_api import sync_playwright
    problems, visited = [], 0
    with sync_playwright() as p:
        b = p.chromium.launch(channel="msedge", headless=True)
        pg = b.new_page(viewport={"width": 1360, "height": 860})
        js_errors = []
        pg.on("pageerror", lambda e: js_errors.append(str(e)))
        pg.on("console", lambda m: js_errors.append(m.text) if m.type == "error" else None)
        pg.goto(f"http://127.0.0.1:{PORT}/")
        pg.wait_for_timeout(1500)
        pg.evaluate(f"localStorage.setItem('lang', '{'en' if EN else 'ru'}')")
        pg.reload()
        pg.wait_for_timeout(3000)
        left = {}
        pages = pg.evaluate("PAGES.map(p => [p.id, (p.tabs || []).map(t => t[0])])")
        for mode in ("simple", "dev"):
            pg.evaluate(f"MODE = '{mode}'; store.set('mode', MODE); render()")
            pg.wait_for_timeout(500)
            for pid, tabs in pages:
                for sub in (tabs or [None]):
                    js_errors.clear()
                    pg.evaluate(f"go({json.dumps(pid)}, {json.dumps(sub)})")
                    pg.wait_for_timeout(1800)
                    visited += 1
                    where = f"{mode}: {pid}" + (f":{sub}" if sub else "")
                    text = pg.evaluate("document.querySelector('main, #main, .layout')?.innerText || document.body.innerText")
                    bad = BAD_TEXT.findall(text)
                    if bad:
                        line = next((l for l in text.splitlines() if BAD_TEXT.search(l)), "")
                        problems.append(f"{where}: на экране «{bad[0]}» — {line.strip()[:120]}")
                    if EN:
                        for l in text.splitlines():
                            l = l.strip()
                            if CYR.search(l) and l != "Русский · English":
                                left.setdefault(l, where)
                    if len(text.strip()) < 40:
                        problems.append(f"{where}: раздел почти пустой")
                    for e in js_errors:
                        if "Failed to load resource" in e and "404" in e:
                            continue
                        problems.append(f"{where}: ошибка окна — {e[:200]}")
        b.close()
    if EN:
        open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "i18n_left.txt"), "w", encoding="utf-8").write(
            "".join(f"{w}\t{l}\n" for l, w in left.items()))
        print(f"Непереведённых строк: {len(left)} (i18n_left.txt)")
    new = report.NEW["n"] - errs_before
    if new:
        problems.append(f"сервер записал ошибок: {new}, последняя — {report.NEW['last']}")
    print(f"Открыто разделов и вкладок: {visited}")
    print("Всё в порядке" if not problems else f"Проблем: {len(problems)}")
    for x in problems:
        print("  · " + x)
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
