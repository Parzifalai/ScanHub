"""Перевод на английский для того, что ScanHub собирает без окна (PDF-отчёт): тот же словарь ui\\en.json
и те же правила, что в ui\\i18n.js — целая фраза, затем куски фраз, затем единицы измерения."""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
CYR = re.compile("[А-Яа-яЁё]")
_D, _RX = None, None
UNITS = [
    (r"(\d),(\d+)(?=\s?(?:[ГМКТ]Б|с|мс|Вт|%)(?![А-Яа-яЁё]))", r"\1.\2"),
    (r"(?i)(\d)\s?ГБ(?![А-Яа-яЁё])", r"\1 GB"), (r"(?i)(\d)\s?МБ(?![А-Яа-яЁё])", r"\1 MB"), (r"(?i)(\d)\s?КБ(?![А-Яа-яЁё])", r"\1 KB"),
    (r"(\d)\s?ТБ(?![А-Яа-яЁё])", r"\1 TB"), (r"(\d)\s?Вт(?![А-Яа-яЁё])", r"\1 W"), (r"(\d)\s?мс(?![А-Яа-яЁё])", r"\1 ms"),
    (r"(\d)\s?мин\.?(?![А-Яа-яЁё])", r"\1 min"), (r"(\d)\s?ч(?![А-Яа-яЁё])", r"\1 h"), (r"(\d)\s?с(?![А-Яа-яЁё])", r"\1 s"),
    (r"(\d)\s?(?:дн\.?|дней|дня|день)(?![А-Яа-яЁё])", r"\1 days"),
    (r"(\d)из(?=\s)", r"\1 of"), (r"(^|[\s(])из(?=\s+[\d~]|\s*$)", r"\1of"),
    (r"(min|h|s|days)\s+назад", r"\1 ago"), (r"(^|[\s(·])за\s+(?=\d)", r"\1over "),
    (r"(^|[\s(])код\s+(?=0x|\d)", r"\1code "),
]


def _load():
    global _D, _RX
    if _D is None:
        try:
            with open(os.path.join(HERE, "ui", "en.json"), encoding="utf-8") as f:
                _D = json.load(f)
        except (OSError, ValueError):
            _D = {}
        keys = sorted((k for k in _D if _D[k] and len(k.strip()) > 2), key=len, reverse=True)
        _RX = re.compile("(?<![А-Яа-яЁё])(?:" + "|".join(map(re.escape, keys)) + ")(?![А-Яа-яЁё])") if keys else None
    return _D


def tr(s):
    """Русская строка → английская (что не нашлось в словаре, остаётся как есть)."""
    d = _load()
    if not s or not d or not CYR.search(s):
        return s
    t = s.strip()
    if t in d:
        return s.replace(t, d[t])

    def one(m):
        k = m.group(0)
        if not re.search(r"\s|:$", k.strip()):        # одиночное слово рядом с другими русскими словами не трогаем — иначе каша
            before, after = s[:m.start()].rstrip(' «»"'), s[m.end():].lstrip(' «»"')
            if (before and CYR.match(before[-1])) or (after and CYR.match(after[0])):
                return k
        return d.get(k, k)
    r = _RX.sub(one, s) if _RX else s
    if CYR.search(r):
        for rx, to in UNITS:
            r = re.sub(rx, to, r)
    return re.sub(r"(?<![\d.,])1 (day|hour|minute|file|folder|program|threat|item|step|time|driver|app)s\b", r"1 \1", r)


def tr_html(doc):
    """Переводит текст между тегами HTML-документа (стили и разметку не трогает)."""
    head, sep, body = doc.partition("<body>")
    if not sep:
        head, body = "", doc
    body = re.sub(r">([^<]+)<", lambda m: ">" + tr(m.group(1)) + "<", body)
    head = re.sub(r"<title>([^<]*)</title>", lambda m: "<title>" + tr(m.group(1)) + "</title>", head)
    return head + sep + body
