"""Ультра проверка: архив итогов, сравнение с прошлой проверкой и отчёт в PDF.

* Архив — data\\ultra_history (последние 12 проверок), нужен для «что изменилось с прошлого раза».
* Сравнение — по пунктам «что стоит сделать»: числа в названиях не учитываются («Диск C: свободно 13 ГБ» и «… 21 ГБ» — один пункт).
* PDF — HTML-отчёт печатается встроенным Edge (без лишних программ). Имя пользователя, имя компьютера, почта и ключи
  заменяются ещё до записи файла — отчёт можно отправить другу или на форум помощи.
"""
import glob
import html
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
HIST = os.path.join(DATA, "ultra_history")
KEEP = 12
LVL = {"threat": ("Угроза", "#c0392b"), "bad": ("Важно", "#c0392b"), "warn": ("Замечание", "#b9770e"), "info": ("Совет", "#2e6da4"),
       "ok": ("В порядке", "#1e8449")}


def archive(view):
    if not view or view.get("status") == "running" or not view.get("id"):
        return
    os.makedirs(HIST, exist_ok=True)
    stamp = (view.get("finished") or view.get("started") or "").replace(":", "-")[:16]
    with open(os.path.join(HIST, f"{stamp}-{view['id']}.json"), "w", encoding="utf-8") as f:
        json.dump(view, f, ensure_ascii=False)
    for old in sorted(glob.glob(os.path.join(HIST, "*.json")))[:-KEEP]:
        try:
            os.remove(old)
        except OSError:
            pass


def seed(view):
    """Первый запуск новой версии: уже сохранённые итоги — первая запись архива."""
    if view and not glob.glob(os.path.join(HIST, "*.json")):
        archive(view)


def _key(t):
    t = re.sub(r"\(.*?\)", "", str(t or ""))
    return re.sub(r"\s+", " ", re.sub(r"[\d.,%]+", "#", t)).strip().lower()


def previous(cur):
    for f in sorted(glob.glob(os.path.join(HIST, "*.json")), reverse=True):
        try:
            v = json.load(open(f, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if v.get("id") != (cur or {}).get("id"):
            return v
    return None


def compare(cur):
    prev = previous(cur)
    if not cur or not prev:
        return None
    imp = lambda v: {_key(i.get("t")): i for i in v.get("todo") or [] if i.get("lvl") in ("threat", "bad", "warn")}
    a, b = imp(prev), imp(cur)
    pick = lambda d, keys: [{"t": d[k].get("t"), "lvl": d[k].get("lvl")} for k in keys]
    return {"prev_when": prev.get("finished") or prev.get("started"), "prev_verdict": (prev.get("verdict") or [None, None])[1],
            "fixed": pick(a, [k for k in a if k not in b]), "new": pick(b, [k for k in b if k not in a]),
            "still": pick(b, [k for k in b if k in a])}


def _system_line():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            build = winreg.QueryValueEx(k, "CurrentBuildNumber")[0]
            disp = winreg.QueryValueEx(k, "DisplayVersion")[0]
        win = f"Windows {'11' if int(build) >= 22000 else '10'} {disp} (сборка {build})"
    except Exception:
        win = "Windows"
    try:
        hw = json.load(open(os.path.join(DATA, "hardware.json"), encoding="utf-8"))
        sy = hw.get("system") or {}
        model = " ".join(x for x in (str(sy.get("maker") or "").title(), sy.get("family") or "", f"({sy['model']})" if sy.get("model") else "") if x)
    except Exception:
        model = ""
    return " · ".join(x for x in (model, win) if x)


def build_html(view, version, cfg):
    from assistant import redact
    e = html.escape
    st = view.get("stats") or {}
    when = (view.get("finished") or view.get("started") or "").replace("T", " ")[:16]
    cmp = compare(view)
    row = lambda i: (f'<tr><td class="lvl" style="color:{LVL.get(i.get("lvl"), LVL["info"])[1]}">{LVL.get(i.get("lvl"), LVL["info"])[0]}</td>'
                     f'<td><b>{e(str(i.get("t") or ""))}</b>{"<div class=s>" + e(str(i["s"])) + "</div>" if i.get("s") else ""}</td></tr>')
    todo = [i for i in view.get("todo") or []]
    parts = [f"""<h1>ScanHub — отчёт ультра проверки</h1>
<div class="meta">{e(when)} · ScanHub {e(version)} · {e(_system_line())}</div>
<div class="verdict">{e((view.get("verdict") or ["", ""])[1])}</div>
<div class="stats">угроз: <b>{st.get("threats", 0)}</b> · важного: <b>{st.get("bad", 0)}</b> · замечаний: <b>{st.get("warn", 0)}</b>
 · освобождено: <b>{round((st.get("freed") or 0) / 2 ** 30, 1)} ГБ</b> · шагов: <b>{st.get("done", 0)} из {st.get("steps", 0)}</b></div>"""]
    if cmp:
        parts.append(f"""<h2>С прошлой проверки ({e((cmp["prev_when"] or "").replace("T", " ")[:16])})</h2>
<p>Исправлено: <b>{len(cmp["fixed"])}</b> · новое: <b>{len(cmp["new"])}</b> · осталось: <b>{len(cmp["still"])}</b></p>"""
                     + (f"<h3>Исправлено</h3><ul>{''.join('<li>' + e(str(i['t'])) + '</li>' for i in cmp['fixed'])}</ul>" if cmp["fixed"] else "")
                     + (f"<h3>Новое</h3><ul>{''.join('<li>' + e(str(i['t'])) + '</li>' for i in cmp['new'])}</ul>" if cmp["new"] else ""))
    if todo:
        parts.append("<h2>Что стоит сделать</h2><table>" + "".join(row(i) for i in todo) + "</table>")
    parts.append("<h2>Шаги проверки</h2>")
    for s in view.get("steps") or []:
        items = [i for i in s.get("items") or [] if i.get("lvl") != "ok"]
        oks = len([i for i in s.get("items") or [] if i.get("lvl") == "ok"])
        parts.append(f'<h3>{e(s.get("title") or "")} — <span class="lab">{e(s.get("label") or s.get("status") or "")}</span></h3>'
                     + ("<table>" + "".join(row(i) for i in items) + "</table>" if items else "")
                     + (f'<div class="s">в порядке: {oks}</div>' if oks else ""))
    parts.append('<div class="foot">Отчёт создан ScanHub. Имя пользователя, имя компьютера, почта и ключи заменены. '
                 'ScanHub не заменяет антивирус: это разовая проверка многими сканерами и подсказки, что исправить.</div>')
    body = "\n".join(parts)
    doc = f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>ScanHub — отчёт ультра проверки</title><style>
@page {{ size: A4; margin: 16mm 14mm; }}
body {{ font: 10.5pt "Segoe UI", Arial, sans-serif; color: #1b1f24; }}
h1 {{ font: 600 19pt Bahnschrift, "Segoe UI", sans-serif; margin: 0 0 4px; color: #1f4fbf; }}
h2 {{ font: 600 13pt Bahnschrift, "Segoe UI", sans-serif; margin: 18px 0 6px; border-bottom: 2px solid #1f4fbf; padding-bottom: 3px; }}
h3 {{ font: 600 11pt "Segoe UI", sans-serif; margin: 12px 0 4px; }}
.meta, .s, .foot {{ color: #5b6470; }} .meta {{ margin-bottom: 10px; }}
.verdict {{ font-size: 13pt; font-weight: 600; margin: 6px 0; }}
.stats {{ margin-bottom: 6px; }} .lab {{ font-weight: 400; color: #5b6470; }}
table {{ width: 100%; border-collapse: collapse; margin: 4px 0; }}
td {{ padding: 4px 6px; vertical-align: top; border-bottom: 1px solid #e3e6ea; }}
td.lvl {{ width: 78px; font-weight: 600; font-size: 9pt; }}
.s {{ font-size: 9.5pt; }} ul {{ margin: 2px 0 6px 18px; padding: 0; }}
.foot {{ margin-top: 20px; font-size: 9pt; border-top: 1px solid #e3e6ea; padding-top: 6px; }}
</style></head><body>{body}</body></html>"""
    if cfg.get("lang") == "en":
        import i18n
        doc = i18n.tr_html(doc).replace('<html lang="ru">', '<html lang="en">')
    return redact(doc, cfg)


def make_pdf(view, version, cfg, edge, out_dir):
    if not view:
        raise RuntimeError("итогов ультра проверки ещё нет — сначала запусти её")
    if not os.path.exists(edge):
        raise RuntimeError("не найден Microsoft Edge — он нужен, чтобы сохранить PDF")
    rep = os.path.join(DATA, "reports")
    os.makedirs(rep, exist_ok=True)
    src = os.path.join(rep, "ultra-report.html")
    with open(src, "w", encoding="utf-8") as f:
        f.write(build_html(view, version, cfg))
    day = (view.get("finished") or view.get("started") or datetime.now().isoformat())[:10]
    out = os.path.join(out_dir, f"ScanHub — report {day}.pdf" if cfg.get("lang") == "en" else f"ScanHub — отчёт {day}.pdf")
    prof = os.path.join(tempfile.gettempdir(), "scanhub-pdf-profile")
    r = subprocess.run([edge, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--no-first-run",
                        f"--user-data-dir={prof}", f"--print-to-pdf={out}", "file:///" + src.replace("\\", "/")],
                       capture_output=True, timeout=120, creationflags=0x08000000)
    if not os.path.exists(out):
        raise RuntimeError(f"Edge не сохранил PDF (код {r.returncode})")
    return out
