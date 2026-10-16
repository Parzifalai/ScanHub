"""Список чистых фраз для перевода и пачки по номерам.
python i18n_batch.py keys            — пересобрать i18n_keys.json (чистые фразы, без обрывков кода по краям)
python i18n_batch.py <номер> [размер] — напечатать пачку «номер<TAB>фраза»"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LEAD = re.compile(r"^[^А-Яа-яЁёA-Za-z0-9%(«\[✦⚡]+")
TAIL = re.compile(r"[^А-Яа-яЁёA-Za-z0-9.!?…)»%:\]]+$")


def clean(k):
    k = LEAD.sub("", TAIL.sub("", k)).strip()
    return k


if sys.argv[1] == "keys":
    src = json.load(open(os.path.join(HERE, "i18n_todo.json"), encoding="utf-8"))
    keys = sorted({c for c in (clean(k) for k in src) if len(c) >= 3 and re.search(r"[А-Яа-яЁё]", c) and not c.startswith("(?")})
    json.dump(keys, open(os.path.join(HERE, "i18n_keys.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=0)
    print("чистых фраз:", len(keys), "символов:", sum(map(len, keys)))
    sys.exit()
keys = json.load(open(os.path.join(HERE, "i18n_keys.json"), encoding="utf-8"))
k, size = int(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 400
for i in range(k * size, min(len(keys), (k + 1) * size)):
    print(f"{i}\t{keys[i]}")
