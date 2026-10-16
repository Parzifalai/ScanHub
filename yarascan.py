"""YARA-сканер ScanHub (движок yara-x от VirusTotal) и карантин.

Правила — два открытых набора, те же, что использует Kudu:
  • YARA Forge (github.com/YARAHQ/yara-forge) — ~5 тыс. проверенных правил из 40+ источников (signature-base, Malpedia, ESET…);
  • Elastic (github.com/elastic/protections-artifacts) — ~500 правил Elastic Security под Windows.
Скачиваются по кнопке, сверяются по SHA-256 от GitHub, компилируются один раз и хранятся в data\\yara.
"""
import hashlib
import io
import json
import os
import re
import time
import urllib.request
import uuid
import zipfile
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
YDIR = os.path.join(DATA, "yara")
META = os.path.join(YDIR, "meta.json")
COMPILED = os.path.join(YDIR, "rules.bin")
QDIR = os.path.join(DATA, "quarantine")
QINDEX = os.path.join(QDIR, "index.json")
FORGE_REPO = "YARAHQ/yara-forge"
ELASTIC_ZIP = "https://codeload.github.com/elastic/protections-artifacts/zip/refs/heads/main"
MAX_FILE = 150 * 1024 * 1024
# правила-«индикаторы» и поисковые: срабатывают и на легитимные утилиты — считаем подозрением, а не угрозой
SOFT = re.compile(r"(SUSP|HKTL|HACKTOOL|PUA|INDICATOR|HUNT|INFO|GEN_|GENERIC|CAPABILITY|TOOL|LOLBIN|EXPL_|VULN|_DEV_|TEST)", re.I)


def _get(url, accept="application/octet-stream", token=None):
    h = {"User-Agent": "ScanHub", "Accept": accept}
    if token and "api.github.com" in url:
        h["Authorization"] = f"Bearer {token}"
    return urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=120)


def meta():
    try:
        return json.load(open(META, encoding="utf-8"))
    except (OSError, ValueError):
        return None


def installed():
    return os.path.exists(COMPILED) and meta() is not None


def latest_forge(token=None):
    with _get(f"https://api.github.com/repos/{FORGE_REPO}/releases/latest", "application/vnd.github+json", token) as r:
        rel = json.load(r)
    return rel["tag_name"], rel.get("published_at"), {a["name"]: a for a in rel.get("assets", [])}


def update_rules(emit=print, package="core", token=None):
    """Скачать свежие наборы правил, проверить, скомпилировать. Возвращает meta."""
    import yara_x
    os.makedirs(YDIR, exist_ok=True)
    tag, date, assets = latest_forge(token)
    name = f"yara-forge-rules-{package}.zip"
    a = assets.get(name)
    if not a:
        raise RuntimeError(f"в релизе YARA Forge {tag} нет {name}")
    emit(f"YARA Forge {tag} ({package}): скачиваю {a['size'] // 1024} КБ…")
    data = _get(a["browser_download_url"]).read()
    want = (a.get("digest") or "").removeprefix("sha256:")
    got = hashlib.sha256(data).hexdigest()
    if want and want != got:
        raise RuntimeError(f"контрольная сумма YARA Forge не совпала: {got} ≠ {want}")
    emit("  SHA-256 сверена с GitHub ✓" if want else "  GitHub не сообщил сумму — сверить нечем")
    z = zipfile.ZipFile(io.BytesIO(data))
    yar = next(n for n in z.namelist() if n.endswith(".yar"))
    forge_src = z.read(yar).decode("utf-8", "replace")

    emit("Elastic protections-artifacts: скачиваю правила для Windows…")
    elastic, el_files = {}, 0
    try:
        raw = _get(ELASTIC_ZIP).read()
        ez = zipfile.ZipFile(io.BytesIO(raw))
        for n in ez.namelist():
            base = n.rsplit("/", 1)[-1]
            if "/yara/rules/" in n and base.startswith(("Windows_", "Multi_")) and base.endswith(".yar"):
                elastic[base] = ez.read(n).decode("utf-8", "replace")
        el_files = len(elastic)
        emit(f"  файлов правил: {el_files}")
    except Exception as e:
        emit(f"  не удалось скачать Elastic: {e} — продолжаю только с YARA Forge")

    emit("Компилирую правила…")
    t0 = time.time()
    c = yara_x.Compiler(relaxed_re_syntax=True)
    for v in ("filename", "filepath", "extension", "filetype", "owner"):
        c.define_global(v, "")
    c.new_namespace("forge")
    c.add_source(forge_src)
    skipped = []
    c.new_namespace("elastic")
    for fname, src in sorted(elastic.items()):
        try:
            c.add_source(src)
        except Exception as e:          # редкие правила с неподдерживаемым синтаксисом — пропускаем по одному
            skipped.append(f"{fname}: {str(e).splitlines()[0][:120]}")
    rules = c.build()
    count = sum(1 for _ in rules)
    buf = io.BytesIO()
    rules.serialize_into(buf)
    # на диске — только в закодированном виде: внутри правил строки из настоящих вирусов, и Defender считает файл вредоносом
    with open(COMPILED + ".tmp", "wb") as f:
        f.write(_xor(buf.getvalue()))
    os.replace(COMPILED + ".tmp", COMPILED)
    m = {"version": tag, "date": date, "package": package, "sha256": got, "rules": count,
         "elastic_files": el_files, "skipped": skipped[:30], "updated": datetime.now().isoformat(timespec="seconds")}
    json.dump(m, open(META, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    _cache.clear()
    emit(f"Готово: {count} правил за {time.time() - t0:.1f} с" + (f", пропущено файлов Elastic: {len(skipped)}" if skipped else ""))
    return m


_cache = {}
_XOR = bytes(i ^ 0xA7 for i in range(256))


def _xor(b):
    """Обратимое кодирование (XOR 0xA7): файл перестаёт совпадать с сигнатурами и не запускается."""
    return b.translate(_XOR)


def load():
    import yara_x
    mt = os.path.getmtime(COMPILED)
    if _cache.get("mt") != mt:
        with open(COMPILED, "rb") as f:
            _cache.update(rules=yara_x.Rules.deserialize_from(io.BytesIO(_xor(f.read()))), mt=mt)
    return _cache["rules"]


def severity(rule_id):
    return "suspicious" if SOFT.search(rule_id) else "threat"


def iter_files(target, max_depth=12):
    if os.path.isfile(target):
        yield target
        return
    base = target.rstrip("\\").count("\\")
    for root, dirs, files in os.walk(target, onerror=lambda e: None):
        if root.count("\\") - base >= max_depth:
            dirs[:] = []
        dirs[:] = [d for d in dirs if d.lower() not in ("$recycle.bin", "system volume information", "winsxs")]
        for f in files:
            yield os.path.join(root, f)


def scan(files, emit=print, stopped=lambda: False, progress=None, time_limit=None, max_size=MAX_FILE):
    """Проверить файлы. Возвращает (найдено {путь: [правила]}, проверено, ошибок)."""
    import yara_x
    rules = load()
    sc = yara_x.Scanner(rules)
    sc.set_timeout(8)
    found, n, errs, t0 = {}, 0, 0, time.time()
    skipped_big = []
    for path in files:
        if stopped() or (time_limit and time.time() - t0 > time_limit):
            break
        try:
            size = os.path.getsize(path)
            if max_size and size > max_size:
                skipped_big.append(path)
                continue
            sc.set_global("filename", os.path.basename(path))
            sc.set_global("filepath", path)
            sc.set_global("extension", os.path.splitext(path)[1].lower())
            res = sc.scan_file(path)
        except Exception:
            errs += 1
            continue
        n += 1
        if progress and n % 50 == 0:
            progress(n)
        hits = [r for r in res.matching_rules]
        if hits:
            found[path] = [{"id": r.identifier, "ns": r.namespace,
                            "desc": dict(r.metadata).get("description", ""), "sev": severity(r.identifier)} for r in hits]
            emit(f"  ⚠ {path}\n      " + "\n      ".join(f"{h['id']}" + (f" — {h['desc']}" if h["desc"] else "") for h in found[path][:4]))
    if skipped_big:
        emit(f"  пропущено больших файлов (больше {max_size // 2 ** 20} МБ): {len(skipped_big)}")
    return found, n, errs


def scan_target(target, emit, stopped, cfg, smart=None, progress=None):
    """Режим «Проверить файл или папку»: (код, вердикт, находки для карантина).
    smart — функция быстрого отбора файлов папки (в общей проверке): только потенциально опасные типы."""
    if not installed():
        emit("Правила YARA не скачаны — нажми «Скачать правила».")
        return 3, ["error", "Нет правил"], []
    m = meta()
    emit(f"Правила: YARA Forge {m['version']} + Elastic · всего {m['rules']}")
    if smart and os.path.isdir(target):
        files, n_ok, n_all = smart(target)
        emit(f"Быстрая проверка папки: {len(files)} файлов из {n_all} — программы, библиотеки, скрипты, архивы и документы с макросами до 100 МБ.")
    else:
        files = list(iter_files(target))
        emit(f"Файлов: {len(files)}")
    total = len(files)
    found, n, errs = scan(files, emit, stopped, progress=(lambda k: progress(f"{k} из {total} файлов")) if progress else None,
                          max_size=None)
    emit(f"\nПроверено: {n}" + (f", не удалось прочитать: {errs}" if errs else ""))
    if not found:
        return 0, ["clean", "Чисто"], []
    return judge(found, emit, cfg, stopped)


def judge(found, emit, cfg, stopped):
    """Перепроверить находки (подпись + VirusTotal) и вынести вердикт."""
    import deepscan
    hard = {p: ", ".join(h["id"] for h in hs[:2]) for p, hs in found.items() if any(h["sev"] == "threat" for h in hs)}
    soft = {p: ", ".join(h["id"] for h in hs[:2]) for p, hs in found.items() if p not in hard}
    items, real_any, susp_any = [], False, False
    for group, names in (("threat", hard), ("suspicious", soft)):
        if not names:
            continue
        v, real, fp, suspects = deepscan.verify(names, "YARA", cfg, stopped)
        for p in names:
            ok = p in suspects
            items.append({"path": p, "name": names[p], "engine": "YARA", "real": ok, "sev": group})
        for x in real:
            emit(("  ✗ " if group == "threat" else "  ? ") + x)
        for x in fp:
            emit("  ✓ " + x)
        real_any |= group == "threat" and bool(real)
        susp_any |= bool(real)
    if real_any:
        return 1, ["threat", f"Найдено: {sum(1 for i in items if i['real'] and i['sev'] == 'threat')}"], items
    if susp_any:
        return 2, ["suspicious", f"Подозрительно: {sum(1 for i in items if i['real'])}"], items
    return 0, ["clean", f"Ложные срабатывания: {len(items)}"], items


# ================================================================ карантин
# Файл переносится в data\\quarantine с побайтовым XOR — так он не запустится и не будет повторно пойман антивирусами.



def q_list():
    try:
        return json.load(open(QINDEX, encoding="utf-8"))
    except (OSError, ValueError):
        return []


def _q_save(items):
    os.makedirs(QDIR, exist_ok=True)
    json.dump(items, open(QINDEX + ".tmp", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    os.replace(QINDEX + ".tmp", QINDEX)


def quarantine(path, threat="", engine=""):
    if not os.path.isfile(path):
        raise RuntimeError("файл не найден")
    os.makedirs(QDIR, exist_ok=True)
    data = open(path, "rb").read()
    qid = uuid.uuid4().hex[:12]
    with open(os.path.join(QDIR, qid + ".bin"), "wb") as f:
        f.write(_xor(data))
    try:
        os.remove(path)
    except OSError:
        os.remove(os.path.join(QDIR, qid + ".bin"))
        raise
    items = q_list()
    items.insert(0, {"id": qid, "path": path, "name": threat, "engine": engine, "size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest(), "date": datetime.now().isoformat(timespec="seconds")})
    _q_save(items)
    return items[0]


def q_restore(qid):
    items = q_list()
    it = next((i for i in items if i["id"] == qid), None)
    if not it:
        raise RuntimeError("нет такого файла в карантине")
    dst = it["path"]
    if os.path.exists(dst):
        root, ext = os.path.splitext(dst)
        dst = f"{root} (восстановлен){ext}"
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as f:
        f.write(_xor(open(os.path.join(QDIR, qid + ".bin"), "rb").read()))
    os.remove(os.path.join(QDIR, qid + ".bin"))
    _q_save([i for i in items if i["id"] != qid])
    return dst


def q_delete(qid):
    items = q_list()
    try:
        os.remove(os.path.join(QDIR, qid + ".bin"))
    except OSError:
        pass
    _q_save([i for i in items if i["id"] != qid])
    return True
