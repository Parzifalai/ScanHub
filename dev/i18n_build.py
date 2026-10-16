"""Собирает ui\\en.json из переводов i18n\\*.tsv («Русский<TAB>English», «Русский<TAB>-» — не переводить).

Новые фразы после правок кода:
  python -X utf8 i18n_extract.py && python -X utf8 i18n_batch.py keys
  python -X utf8 i18n_build.py --todo  → i18n_todo.tsv (фразы без перевода), перевести и положить в i18n\\<любое имя>.tsv
"""
import glob, json, os, re, sys
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # папка ScanHub (dev лежит внутри)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT_DIR, "ui", "en.json")
CYR = re.compile("[А-Яа-яЁё]")

tr, skip, bad = {}, set(), []
for f in sorted(glob.glob(os.path.join(HERE, "i18n", "*.tsv"))):
    for n, line in enumerate(open(f, encoding="utf-8").read().splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            bad.append(f"{os.path.basename(f)}:{n}"); continue
        ru, en = parts[0].strip(), parts[1].strip()
        if en == "-":
            skip.add(ru)
        elif en:
            tr[ru] = en

keys = json.load(open(os.path.join(HERE, "i18n_keys.json"), encoding="utf-8"))
todo = [k for k in keys if k not in tr and k not in skip]
if "--todo" in sys.argv:
    open(os.path.join(HERE, "i18n_todo.tsv"), "w", encoding="utf-8").write("".join(f"{k}\t\n" for k in todo))
    print("без перевода:", len(todo), "→ i18n_todo.tsv")
    sys.exit()

cyr = [k for k, v in tr.items() if CYR.search(v) and k != "Русский"]
# одна и та же фраза встречается и с большой буквы (в начале строки), и с маленькой (после «—», в списках)
def _up(s): return s[:1].upper() + s[1:]
def _low(s): return s[:1].lower() + s[1:] if s[1:2].islower() else s   # «NVIDIA…», «PDF…» не трогаем
out = dict(tr)
for ru, en in tr.items():
    if re.match("[а-яё]", ru) and len(ru) >= 4:
        out.setdefault(_up(ru), _up(en))
    elif re.match("[А-ЯЁ]", ru) and len(ru.split()) <= 4 and ru[1:2].islower():
        out.setdefault(_low(ru), _low(en))
# ключи из 1–2 букв («ЦП», «ПК») окно применяет только к целой строке, не по кускам (см. ui\i18n.js)
json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=0, sort_keys=True)
print(f"переводов {len(tr)}, с вариантами {len(out)}, без перевода {len(todo)} (--todo), не переводить {len(skip)}")
if bad: print("плохие строки:", bad[:40])
if cyr: print("кириллица в переводе:", cyr[:20])
sys.exit(1 if bad else 0)
