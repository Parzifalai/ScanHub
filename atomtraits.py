"""Правила (traits) Atomdrift Scan — без папки testdata.

Atomdrift сам обновляет правила раз в сутки: скачивает архив ~170 МБ и распаковывает его целиком, вместе с testdata —
там ~6 000 файлов для его собственных тестов, из них ~1 400 настоящих образцов вредоносов (DOS-вирусы, веб-шеллы,
кейлоггеры). Defender и Malwarebytes находят их и поднимают тревогу «Virus:DOS/…». Поэтому ScanHub обновляет правила
сам: сверяет SHA-256 архива с манифестом, распаковывает его из памяти и пропускает testdata, а Atomdrift запускает
только с --no-update. Модели ИИ (без образцов) обновляет сам Atomdrift: update-rules --models-only.
"""
import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import time
import tomllib
import urllib.request

BASE = "https://updates.atomdrift.org/cleave/"
UA = {"User-Agent": "ScanHub/1.0 (atomscan traits updater)"}     # без своей подписи сервер отвечает 403
SKIP = {"testdata"}
# отдельные файлы правил, в которых антивирусы видят вредонос (в правиле — пример вредоносной команды). Их не распаковываем:
# иначе Defender удаляет файл и показывает тревогу при каждом обновлении. Список пополняется сам (см. _learn).
KNOWN_FLAGGED = {"objectives/command-and-control/dropper/delivery/url-shortcut/windows.yaml"}
ROOT = os.path.join(os.environ.get("APPDATA") or os.path.expanduser(r"~\AppData\Roaming"), "atomdrift", "cleave")
TRAITS = os.path.join(ROOT, "traits")
MARK = ".cleave-rules.toml"
STAMP = os.path.join(ROOT, ".scanhub-checked")
FLAGGED = os.path.join(ROOT, ".scanhub-flagged.txt")
STALE = 24 * 3600
NO_WINDOW = 0x08000000


def local():
    try:
        with open(os.path.join(TRAITS, MARK), "rb") as f:
            return tomllib.load(f)
    except (OSError, ValueError):
        return {}


def purge_testdata():
    """Убрать образцы, если они уже на диске (их распаковал сам Atomdrift). True — что-то удалили."""
    p = os.path.join(TRAITS, "testdata")
    if not os.path.isdir(p):
        return False
    shutil.rmtree(p, ignore_errors=True)
    return True


def flagged():
    try:
        with open(FLAGGED, encoding="utf-8") as f:
            return KNOWN_FLAGGED | {l.strip() for l in f if l.strip()}
    except OSError:
        return set(KNOWN_FLAGGED)


def _learn(tmp, written):
    """Файлы, которые антивирус удалил сразу после распаковки, — запомнить и больше не распаковывать."""
    time.sleep(3)
    gone = [n for n in written if not os.path.exists(os.path.join(tmp, *n.split("/")))]
    if gone:
        with open(FLAGGED, "a", encoding="utf-8") as f:
            f.writelines(n + "\n" for n in gone)
    return gone


def _get(url, timeout):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()


def _touch(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%dT%H:%M:%S"))


def due():
    return not local() or not os.path.exists(STAMP) or time.time() - os.path.getmtime(STAMP) > STALE


def update(emit=lambda s: None, exe=None, version="", force=False):
    """Обновить правила и модели, если пора (не чаще раза в сутки). Возвращает коммит установленных правил."""
    if purge_testdata():
        emit("[ScanHub] убрал образцы вирусов из правил Atomdrift (testdata) — они нужны только для его тестов")
    cur = local()
    if not force and not due():
        return cur.get("commit")
    if exe:
        try:                                                  # модели ИИ и фильтры известных файлов — образцов в них нет
            subprocess.run([exe, "update-rules", "--models-only"], capture_output=True, timeout=300,
                           creationflags=NO_WINDOW, env={**os.environ, "NO_COLOR": "1"})
        except (OSError, subprocess.SubprocessError):
            pass
    man = tomllib.loads(_get(BASE + "versions.toml", 30).decode("utf-8"))
    key = man["latest"]
    art = man["artifacts"][key]
    if cur.get("commit") == art["commit"]:
        _touch(STAMP)
        return cur["commit"]
    emit(f"[ScanHub] скачиваю правила Atomdrift {key} от {art['date']} (~170 МБ, без образцов вирусов)…")
    data = _get(BASE + art["file"], 900)
    if hashlib.sha256(data).hexdigest() != art["sha256"]:
        raise RuntimeError("контрольная сумма архива правил Atomdrift не совпала — не устанавливаю")
    tmp, old = TRAITS + ".new", TRAITS + ".old"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    skip_files, written = flagged(), []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:zst") as tf:
        for m in tf:
            name = m.name.lstrip("./")
            if name.split("/")[0] in SKIP or name in skip_files:
                continue
            tf.extract(m, tmp, filter="data")
            if m.isfile():
                written.append(name)
    gone = _learn(tmp, written)
    if gone:
        emit(f"[ScanHub] антивирус удалил файлов правил: {len(gone)} — при следующих обновлениях они пропускаются")
    with open(os.path.join(tmp, MARK), "w", encoding="utf-8") as f:
        f.write(f'commit = "{art["commit"]}"\ndate = "{art["date"]}"\nsource = "latest"\n'
                f'version = "{version or cur.get("version") or ""}"\n')
    shutil.rmtree(old, ignore_errors=True)
    if os.path.isdir(TRAITS):
        os.replace(TRAITS, old)
    try:
        os.replace(tmp, TRAITS)
    except OSError:
        if os.path.isdir(old) and not os.path.isdir(TRAITS):
            os.replace(old, TRAITS)                           # прежние правила остаются рабочими
        raise
    shutil.rmtree(old, ignore_errors=True)
    _touch(STAMP)
    emit(f"[ScanHub] правила Atomdrift обновлены: {key}")
    if exe:
        warm(exe)
    return art["commit"]


def warm(exe):
    """Первый запуск после обновления правил разбирает их ~1–3 минуты (дальше — из кэша, ~6 с). Делаем это сразу в фоне,
    чтобы задержка не выпала на проверку, которую ждёт человек."""
    probe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe")
    try:
        subprocess.Popen([exe, "--no-update", probe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=NO_WINDOW, env={**os.environ, "NO_COLOR": "1"})
    except OSError:
        pass
