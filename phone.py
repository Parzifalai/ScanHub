"""Проверка Android-телефона через отладку по USB (adb). Разово: ничего не ставится на телефон и не остаётся работать на ПК.

* adb — официальные Google Platform Tools. Берём уже установленный (PATH, winget, Android SDK), иначе скачиваем с dl.google.com
  в apps\\platform-tools и проверяем подпись Google. Сервер adb, который запустил сам ScanHub, гасится через 90 с без дела —
  требование «ничего постоянно работающего». Чужой (уже работавший) сервер adb не трогаем.
* Только чтение: свойства системы, список приложений и откуда они установлены, кто получил опасные права
  (спец. возможности, администратор устройства, доступ к уведомлениям, SMS по умолчанию, установка других приложений),
  root и разблокированный загрузчик, патч безопасности, Play Защита, блокировка экрана, батарея, память.
* Приложения сверяются со списком следилок (stalkerware-indicators, AssoEchap — github.com/AssoEchap/stalkerware-indicators),
  установленные не из магазина — с VirusTotal по SHA-256 (если есть ключ; сам файл никуда не отправляется).
* Изменения — только по кнопке и только для того, что нашла последняя проверка: открыть настройки приложения на телефоне,
  удалить приложение, снять у него доступ к спец. возможностям.
"""
import glob
import io
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
APPS = os.path.join(ROOT, "apps")
OWN_ADB = os.path.join(APPS, "platform-tools", "adb.exe")
PT_URL = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
IOC_URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
IOC_FILE = os.path.join(DATA, "intel", "stalkerware.json")
NO_WINDOW = 0x08000000
IDLE_KILL = 90

# магазины приложений: установленное оттуда прошло хоть какую-то проверку
STORES = {
    "com.android.vending": "Google Play", "com.xiaomi.market": "Xiaomi GetApps", "com.xiaomi.mipicks": "Xiaomi GetApps",
    "com.huawei.appmarket": "Huawei AppGallery", "com.sec.android.app.samsungapps": "Galaxy Store", "com.heytap.market": "OPPO App Market",
    "com.oppo.market": "OPPO App Market", "com.bbk.appstore": "vivo App Store", "ru.vk.store": "RuStore", "com.amazon.venezia": "Amazon Appstore",
    "com.aurora.store": "Aurora Store (Google Play)", "org.fdroid.fdroid": "F-Droid", "com.google.android.feedback": "Google Play",
    "com.transsion.phonemaster": "магазин Transsion", "com.oneplus.market": "OnePlus Store", "com.nothing.appstore": "Nothing Store",
}
# установщики производителя: ими система ставит и обновляет свои же приложения
VENDOR = {"android": "предустановлено производителем", "com.xiaomi.discover": "обновление Xiaomi", "com.miui.system": "обновление Xiaomi",
          "com.facebook.system": "менеджер приложений Facebook (предустановлен)", "com.android.chrome": "веб-приложение из Chrome",
          "com.google.android.apps.chrome": "веб-приложение из Chrome", "com.sec.android.app.chromecustomizations": "веб-приложение из Chrome",
          "com.samsung.android.app.updatecenter": "обновление Samsung", "com.huawei.appgallery": "Huawei AppGallery"}
# «установщики пакетов»: так ставятся APK-файлы, скачанные вручную
SIDELOAD = {"com.google.android.packageinstaller", "com.android.packageinstaller", "com.miui.packageinstaller", "com.samsung.android.packageinstaller",
            "com.android.shell", "adb", "com.google.android.apps.nbu.files", "com.android.documentsui", "com.mi.android.globalFileexplorer",
            "com.android.fileexplorer", "com.android.chrome", "org.telegram.messenger", "com.whatsapp"}
# известные приложения, которым спец. возможности и права администратора нужны по делу — не тревожим, а поясняем
A11Y_OK = re.compile(r"^(com\.google\.android\.marvin\.talkback|com\.google\.android\.accessibility|com\.samsung\.accessibility|"
                     r"com\.miui\.|com\.xiaomi\.|com\.android\.|com\.google\.android\.apps\.|com\.lastpass\.|com\.x8bit\.bitwarden|"
                     r"com\.onepassword\.|com\.kaspersky\.|com\.eset\.|com\.avast\.|com\.bitdefender\.|com\.drweb|com\.wssyncmldm|"
                     r"net\.dinglisch\.android\.tasker|com\.joaomgcd\.|com\.microsoft\.|com\.samsung\.android\.)")
PERM_WORDS = {
    "READ_SMS": "читает SMS", "RECEIVE_SMS": "получает SMS", "SEND_SMS": "отправляет SMS", "READ_CALL_LOG": "видит журнал звонков",
    "RECORD_AUDIO": "микрофон", "CAMERA": "камера", "ACCESS_FINE_LOCATION": "точное местоположение", "ACCESS_BACKGROUND_LOCATION": "местоположение в фоне",
    "READ_CONTACTS": "контакты", "READ_PHONE_STATE": "сведения о телефоне и звонках", "READ_EXTERNAL_STORAGE": "файлы",
    "MANAGE_EXTERNAL_STORAGE": "все файлы", "READ_MEDIA_IMAGES": "фото", "POST_NOTIFICATIONS": "",
}

_state = {"adb": None, "started_by_us": False, "last": 0.0, "killer": None}
_lock = threading.Lock()


# ---------------------------------------------------------------- adb: найти, поставить, запустить
def find_adb():
    cands = [OWN_ADB, shutil.which("adb") or ""]
    la = os.environ.get("LOCALAPPDATA", "")
    cands += glob.glob(os.path.join(la, "Microsoft", "WinGet", "Packages", "Google.PlatformTools*", "platform-tools", "adb.exe"))
    cands += [os.path.join(la, "Android", "Sdk", "platform-tools", "adb.exe")]
    # уже стоящий в системе adb лучше своего: два разных adb выключают сервер друг друга
    for p in cands[1:] + cands[:1]:
        if p and os.path.isfile(p):
            return p
    return None


def _signer(path):
    ps = ("$s = Get-AuthenticodeSignature -LiteralPath $env:SCANHUB_ARG; "
          "[pscustomobject]@{status=[string]$s.Status; signer=[string]$s.SignerCertificate.Subject} | ConvertTo-Json -Compress")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=60,
                             env={**os.environ, "SCANHUB_ARG": path}, creationflags=NO_WINDOW).stdout
        d = json.loads(out)
        return d.get("status") or "", d.get("signer") or ""
    except Exception:
        return "", ""


def install(prog=lambda s: None):
    """Скачать Google Platform Tools (~7 МБ) в apps\\platform-tools и проверить подпись adb.exe."""
    prog("10% · скачиваю Google Platform Tools (~7 МБ) с dl.google.com")
    req = urllib.request.Request(PT_URL, headers={"User-Agent": "ScanHub"})
    with urllib.request.urlopen(req, timeout=120) as r:
        blob = r.read()
    prog("60% · распаковываю")
    tmp = os.path.join(APPS, "platform-tools.new")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for n in z.namelist():
            if ".." in n or n.startswith(("/", "\\")):
                raise RuntimeError("в архиве Platform Tools странные пути — не распаковываю")
        z.extractall(tmp)
    exe = os.path.join(tmp, "platform-tools", "adb.exe")
    prog("85% · проверяю подпись Google")
    st, who = _signer(exe)
    if st != "Valid" or "Google" not in who:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"подпись adb.exe не подтвердилась ({st or 'нет подписи'}) — не ставлю")
    dst = os.path.join(APPS, "platform-tools")
    shutil.rmtree(dst, ignore_errors=True)
    shutil.move(os.path.join(tmp, "platform-tools"), dst)
    shutil.rmtree(tmp, ignore_errors=True)
    return {"adb": OWN_ADB, "signer": who}


def _adb(*args, serial=None, timeout=30, check=False):
    exe = _state["adb"] or find_adb()
    if not exe:
        raise RuntimeError("adb не установлен")
    _state["adb"] = exe
    cmd = [exe] + (["-s", serial] if serial else []) + list(args)
    with _lock:
        _state["last"] = time.time()
    r = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
    out = r.stdout.decode("utf-8", "replace")
    err = r.stderr.decode("utf-8", "replace")
    if "daemon not running" in err and "started successfully" in err:
        _state["started_by_us"] = True
        _start_killer()
    if check and r.returncode:
        raise RuntimeError((err or out).strip()[:300] or f"adb вернул {r.returncode}")
    return out


def sh(serial, cmd, timeout=30):
    return _adb("shell", cmd, serial=serial, timeout=timeout).replace("\r\n", "\n")


def _start_killer():
    if _state["killer"] and _state["killer"].is_alive():
        return

    def loop():
        while True:
            time.sleep(15)
            if time.time() - _state["last"] > IDLE_KILL:
                stop_server()
                return
    _state["killer"] = threading.Thread(target=loop, daemon=True)
    _state["killer"].start()


def stop_server():
    """Погасить сервер adb, если его запустил ScanHub (чужой не трогаем)."""
    if not _state["started_by_us"] or not _state["adb"]:
        return False
    try:
        subprocess.run([_state["adb"], "kill-server"], capture_output=True, timeout=15, creationflags=NO_WINDOW)
    except Exception:
        pass
    _state["started_by_us"] = False
    return True


def status():
    """Есть ли adb и какой телефон подключён: device / unauthorized (не подтвердил на телефоне) / offline."""
    exe = find_adb()
    if not exe:
        return {"adb": None, "devices": []}
    out = _adb("devices", "-l", timeout=20)
    devs = []
    for line in out.splitlines()[1:]:
        m = re.match(r"(\S+)\s+(device|unauthorized|offline|no permissions|recovery|sideload|bootloader)\b(.*)", line.strip())
        if not m:
            continue
        info = dict(re.findall(r"(\w+):(\S+)", m.group(3)))
        devs.append({"serial": m.group(1), "state": m.group(2), "model": info.get("model", "").replace("_", " "), "usb": "usb" in info})
    return {"adb": exe, "own": os.path.normcase(exe) == os.path.normcase(OWN_ADB), "devices": devs}


# ---------------------------------------------------------------- база следилок
def stalkerware(update=False):
    """{пакет: название} из stalkerware-indicators. Скачивается раз в 7 дней в data\\intel\\stalkerware.json."""
    try:
        if not update and os.path.exists(IOC_FILE) and time.time() - os.path.getmtime(IOC_FILE) < 7 * 86400:
            return json.load(open(IOC_FILE, encoding="utf-8"))
    except (OSError, ValueError):
        pass
    try:
        req = urllib.request.Request(IOC_URL, headers={"User-Agent": "ScanHub"})
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode("utf-8", "replace")
    except Exception:
        try:
            return json.load(open(IOC_FILE, encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    db, name, sect = {}, None, None
    for line in text.splitlines():
        m = re.match(r"- name:\s*(.+)", line)
        if m:
            name, sect = m.group(1).strip().strip("'\""), None
            continue
        m = re.match(r"  (\w+):\s*$", line)
        if m:
            sect = m.group(1)
            continue
        m = re.match(r"  - (\S+)", line)
        if m and sect == "packages" and name:
            db[m.group(1).strip("'\"")] = name
    if db:
        os.makedirs(os.path.dirname(IOC_FILE), exist_ok=True)
        json.dump(db, open(IOC_FILE, "w", encoding="utf-8"), ensure_ascii=False)
    return db


# ---------------------------------------------------------------- проверка
def _props(serial):
    out = sh(serial, "getprop")
    return dict(re.findall(r"^\[([^\]]+)\]: \[([^\]]*)\]", out, re.M))


def _setting(serial, ns, key):
    v = sh(serial, f"settings get {ns} {key}").strip()
    return None if v in ("null", "") else v


def _comp_pkgs(v):
    return sorted({c.split("/")[0] for c in re.split(r"[:,]", v or "") if "/" in c})


def cap(s):
    return s[:1].upper() + s[1:]


def _patch_age(patch):
    try:
        t = time.mktime(time.strptime(patch[:10], "%Y-%m-%d"))
        return int((time.time() - t) / 86400)
    except (ValueError, TypeError):
        return None


def _vt(sha, key):
    from services import request
    code, body = request(f"https://www.virustotal.com/api/v3/files/{sha}", {"x-apikey": key, "accept": "application/json"}, timeout=30)
    if code == 404:
        return {"known": False}
    if code != 200:
        return {"error": f"VirusTotal ответил {code}"}
    a = (body.get("data") or {}).get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    return {"known": True, "mal": st.get("malicious", 0), "sus": st.get("suspicious", 0),
            "total": sum(v for k, v in st.items() if k in ("malicious", "suspicious", "undetected", "harmless")),
            "label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label"),
            "link": f"https://www.virustotal.com/gui/file/{sha}"}


def scan(serial=None, prog=lambda s: None, vt_key=None):
    st = status()
    ready = [d for d in st["devices"] if d["state"] == "device" and (not serial or d["serial"] == serial)]
    if not ready:
        if any(d["state"] == "unauthorized" for d in st["devices"]):
            raise RuntimeError("телефон не разрешил отладку: разблокируй его и нажми «Разрешить» в окне «Разрешить отладку по USB?»")
        raise RuntimeError("телефон не подключён по отладке USB")
    serial = ready[0]["serial"]
    R = {"when": time.strftime("%Y-%m-%dT%H:%M:%S"), "serial": serial, "findings": [], "apps": [], "special": []}
    add = lambda lvl, t, s="", **k: R["findings"].append({"lvl": lvl, "t": t, "s": s, **k})

    prog("5% · читаю сведения о телефоне")
    p = _props(serial)
    brand = (p.get("ro.product.brand") or "").capitalize()
    model = p.get("ro.product.marketname") or p.get("ro.product.model") or ""
    skin = p.get("ro.mi.os.version.name") and f"HyperOS {p['ro.mi.os.version.name'].removeprefix('OS')}" \
        or (p.get("ro.miui.ui.version.name") and f"MIUI {p['ro.miui.ui.version.name'].lstrip('V')}") \
        or (p.get("ro.build.version.oneui") and "One UI") or ""
    R["device"] = {"name": f"{brand} {model}".strip() if brand.lower() not in model.lower() else model, "android": p.get("ro.build.version.release", ""),
                   "sdk": int(p.get("ro.build.version.sdk") or 0), "skin": skin, "patch": p.get("ro.build.version.security_patch", ""),
                   "build": p.get("ro.build.display.id", "")}
    sdk = R["device"]["sdk"]

    # --- система
    age = _patch_age(R["device"]["patch"])
    R["device"]["patch_age"] = age
    if age is not None:
        if age > 365:
            add("bad", "Обновления безопасности старше года", f"Последний патч — {R['device']['patch']}. Известные дыры в Android не закрыты. "
                "Проверь «Настройки → О телефоне → Обновление системы»; если обновлений больше не выходит — телефон перестал поддерживаться.")
        elif age > 180:
            add("warn", "Обновления безопасности давно не ставились", f"Последний патч — {R['device']['patch']} (≈{age // 30} мес. назад). Проверь обновления системы.")
        else:
            add("ok", "Обновления безопасности свежие", f"патч от {R['device']['patch']}")
    if sdk and sdk < 31:
        add("warn", f"Старая версия Android ({R['device']['android']})", "Для неё почти не выходят исправления, а новые приложения перестают поддерживать.")
    vbs = p.get("ro.boot.verifiedbootstate", "")
    if vbs == "orange" or p.get("ro.boot.flash.locked") == "0":
        add("warn", "Загрузчик разблокирован", "Телефон загрузит изменённую систему — так ставят прошивки и root. Если ты этого не делал, это повод насторожиться: "
            "так бывает у телефонов, перепроданных с изменённой прошивкой.")
    prog("12% · проверяю root")
    su = sh(serial, "command -v su || ls /system/xbin/su /system/bin/su /sbin/su 2>/dev/null").strip()
    if su:
        add("warn", "На телефоне есть root", "Права суперпользователя: любое приложение, получившее их, может всё. Если ставил не ты — это серьёзно.")
    if p.get("ro.build.tags") == "test-keys":
        add("warn", "Прошивка подписана тестовыми ключами", "Это не заводская прошивка (или изменённая).")
    lock = sh(serial, "locksettings get-disabled 2>/dev/null").strip().lower()
    if lock == "true":
        add("bad", "Нет блокировки экрана", "Кто угодно, взяв телефон, увидит всё. Поставь PIN, пароль или отпечаток: «Настройки → Пароли и безопасность».")
    elif lock == "false":
        add("ok", "Блокировка экрана включена")
    pp = _setting(serial, "global", "package_verifier_user_consent")
    pe = _setting(serial, "global", "package_verifier_enable")
    if pp == "-1" or pe == "0":
        add("warn", "Google Play Защита выключена", "Она проверяет приложения на вирусы. Включи: Play Маркет → аватар → «Play Защита» → «Проверять приложения».")
    if (p.get("ro.crypto.state") or "") == "unencrypted":
        add("warn", "Память телефона не зашифрована", "При краже данные можно прочитать, подключив память напрямую.")

    # --- приложения
    prog("25% · получаю список приложений")
    lst = sh(serial, "pm list packages -3 -f -i", timeout=60)
    apps = {}
    for line in lst.splitlines():
        m = re.match(r"package:(\S+)=([\w.]+)(?:\s+installer=(\S+))?", line.strip())
        if m:
            inst = m.group(3) if m.group(3) not in (None, "null") else ""
            apps[m.group(2)] = {"pkg": m.group(2), "installer": inst, "path": m.group(1)}
    disabled = set(re.findall(r"package:(\S+)", sh(serial, "pm list packages -d")))
    for a in apps.values():
        i = a["installer"]
        pre = not a["path"].startswith("/data/")             # лежит в /product, /cust, /system… — поставил производитель
        a["store"] = STORES.get(i, "") or VENDOR.get(i, "") or ("предустановлено производителем" if pre else "")
        a["source"] = a["store"] or ("файл APK (установлен вручную)" if i in SIDELOAD else "файл APK или с компьютера" if not i else f"установщик {i}")
        a["sideload"] = not a["store"]
        a["disabled"] = a["pkg"] in disabled
    R["counts"] = {"apps": len(apps), "sideload": sum(1 for a in apps.values() if a["sideload"])}

    prog("40% · смотрю, у кого особые права")
    a11y = _comp_pkgs(_setting(serial, "secure", "enabled_accessibility_services"))
    notif = _comp_pkgs(_setting(serial, "secure", "enabled_notification_listeners"))
    dp = sh(serial, "dumpsys device_policy", timeout=40)
    admins = sorted(set(re.findall(r"ComponentInfo\{([^/}]+)/", dp)))
    sms = _setting(serial, "secure", "sms_default_application") or ""
    install_ok = re.findall(r"^\s*(\S+)$", sh(serial, "cmd appops query-op REQUEST_INSTALL_PACKAGES allow 2>/dev/null"), re.M) if sdk >= 26 else []
    install_ok = [x for x in install_ok if re.match(r"^[\w.]+$", x) and "." in x]
    overlay = re.findall(r"^\s*(\S+)$", sh(serial, "cmd appops query-op SYSTEM_ALERT_WINDOW allow 2>/dev/null"), re.M) if sdk >= 26 else []
    overlay = {x for x in overlay if re.match(r"^[\w.]+$", x) and "." in x}

    special = []
    for pkg in a11y:
        special.append({"pkg": pkg, "what": "a11y", "t": "Спец. возможности", "s": "видит всё, что на экране, и может нажимать за тебя"})
    for pkg in admins:
        special.append({"pkg": pkg, "what": "admin", "t": "Администратор устройства", "s": "может блокировать экран, стирать данные и мешать своему удалению"})
    for pkg in notif:
        special.append({"pkg": pkg, "what": "notif", "t": "Доступ к уведомлениям", "s": "читает все уведомления, включая сообщения и коды из SMS"})
    if sms and not sms.startswith(("com.google.android.apps.messaging", "com.android.mms", "com.samsung.android.messaging")):
        special.append({"pkg": sms, "what": "sms", "t": "SMS по умолчанию", "s": "получает и отправляет все SMS, включая коды банков"})
    for pkg in install_ok:
        special.append({"pkg": pkg, "what": "install", "t": "Может ставить другие приложения", "s": "через него на телефон попадают APK-файлы"})
    for x in special:
        a = apps.get(x["pkg"])
        x["sideload"] = bool(a and a["sideload"])
        x["system"] = a is None
        x["known_ok"] = bool(A11Y_OK.match(x["pkg"])) or x["system"]
        x["lvl"] = "bad" if x["sideload"] and x["what"] in ("a11y", "admin", "notif", "sms") else \
                   "warn" if x["sideload"] and x["what"] == "install" else \
                   "warn" if not x["known_ok"] and x["what"] in ("a11y", "admin", "notif", "sms") else "info"
    R["special"] = special

    prog("50% · сверяю со списком приложений-следилок")
    ioc = stalkerware()
    for pkg, a in apps.items():
        hit = ioc.get(pkg)
        if hit:
            a["stalker"] = hit
            add("bad", f"Приложение-следилка: {hit}", f"{pkg} — известная программа для слежки (stalkerware). Она читает переписку, звонки и местоположение "
                "и отправляет их тому, кто её поставил. Перед удалением подумай о безопасности: тот, кто её поставил, узнает об удалении.", pkg=pkg)
    R["ioc_n"] = len(ioc)

    # подробности по подозрительным: не из магазина или с особыми правами
    focus = [a for a in apps.values() if a["sideload"] or a.get("stalker")] + \
            [apps[x["pkg"]] for x in special if x["pkg"] in apps and x["lvl"] != "info"]
    seen = set()
    focus = [a for a in focus if not (a["pkg"] in seen or seen.add(a["pkg"]))][:30]
    for i, a in enumerate(focus):
        prog(f"{55 + int(i / max(1, len(focus)) * 25)}% · разбираю {a['pkg']}")
        d = sh(serial, f"dumpsys package {a['pkg']}", timeout=30)
        m = re.search(r"versionName=(\S+)", d)
        a["version"] = m.group(1) if m else ""
        m = re.search(r"firstInstallTime=(\S+ \S+)", d)
        a["installed"] = m.group(1) if m else ""
        m = re.search(r"packageSource=(\d)", d)                # Android 13+: 1 — прочее (adb), 2 — магазин, 3 — файл, 4 — скачанный файл
        if m and a["sideload"]:
            a["source"] = {"1": "с компьютера (adb) или другим способом", "2": "из магазина приложений", "3": "файл APK (установлен вручную)",
                           "4": "скачанный файл APK"}.get(m.group(1), a["source"])
            if m.group(1) == "1" and re.search(r"pkgFlags=\[[^\]]*DEBUGGABLE", d):
                a["source"] = "с компьютера — отладочная сборка (так ставят свои приложения разработчики)"
                a["dev"] = True
        granted = set(re.findall(r"android\.permission\.(\w+): granted=true", d))
        a["perms"] = [w for k, w in PERM_WORDS.items() if k in granted and w]
        a["overlay"] = a["pkg"] in overlay
    # VirusTotal по хэшу для установленных не из магазина (файл не отправляется)
    if vt_key:
        side = sorted([a for a in focus if a["sideload"] and not a.get("dev")], key=lambda a: a["installer"] not in SIDELOAD)[:12]
        for i, a in enumerate(side):
            prog(f"{80 + int(i / max(1, len(side)) * 15)}% · VirusTotal: {a['pkg']}")
            path = sh(serial, f"pm path {a['pkg']}").strip().splitlines()
            base = next((x[8:] for x in path if x.startswith("package:") and x.endswith("base.apk")), path[0][8:] if path else "")
            if not base:
                continue
            h = sh(serial, f"sha256sum '{base}' 2>/dev/null").split()
            if h and re.fullmatch(r"[0-9a-f]{64}", h[0]):
                a["sha256"] = h[0]
                try:
                    a["vt"] = _vt(h[0], vt_key)
                except Exception as e:
                    a["vt"] = {"error": str(e)[:120]}
                if a["vt"].get("mal", 0) >= 3:
                    add("bad", f"VirusTotal: {a['pkg']} — вредоносное", f"{a['vt']['mal']} из {a['vt']['total']} антивирусов"
                        + (f" ({a['vt']['label']})" if a['vt'].get("label") else "") + ". Удали это приложение.", pkg=a["pkg"])
                elif a["vt"].get("mal", 0) + a["vt"].get("sus", 0) >= 2:
                    add("warn", f"VirusTotal: {a['pkg']} — есть подозрения", f"{a['vt'].get('mal', 0) + a['vt'].get('sus', 0)} из {a['vt']['total']} антивирусов"
                        + (f" ({a['vt']['label']})" if a['vt'].get("label") else "") + ". Так бывает у взломанных игр и программ: в них часто встраивают рекламу "
                        "или хуже. Если скачивал не с официального сайта — лучше удали.", pkg=a["pkg"])
                elif a["vt"].get("mal") or a["vt"].get("sus"):
                    add("info", f"VirusTotal: {a['pkg']} — один антивирус из {a['vt']['total']}", "Одна тревога при всех остальных «чисто» — обычно ложная.", pkg=a["pkg"])
    R["vt"] = bool(vt_key)
    R["apps"] = sorted(apps.values(), key=lambda a: (not a.get("stalker"), not a["sideload"], a["pkg"]))

    by_pkg = {}
    for x in special:
        if x["lvl"] in ("bad", "warn") and not (apps.get(x["pkg"]) or {}).get("stalker"):
            by_pkg.setdefault(x["pkg"], []).append(x)
    for pkg, xs in by_pkg.items():
        rights = "; ".join(f"{x['t'].lower()} — {x['s']}" for x in xs)
        if any(x["lvl"] == "bad" for x in xs):
            add("bad", f"Приложение не из магазина с опасным доступом: {pkg}", f"{cap(rights)}. Если ставил не ты или не знаешь, что это, — сними доступ и удали.", pkg=pkg)
        else:
            add("warn", f"Особый доступ у {pkg}", f"{cap(rights)}. Если ты сам включал это для приложения — всё нормально.", pkg=pkg)
    R["counts"]["sideload"] = n_side = sum(1 for a in apps.values() if a["sideload"] and not a.get("dev"))
    if n_side:
        add("info", f"Установлено не из магазина: {n_side}", "Такие приложения никто не проверял. Если среди них есть незнакомые — посмотри их в списке ниже.")

    # --- батарея и память
    prog("96% · батарея и память")
    b = sh(serial, "dumpsys battery")
    bat = {k: v for k, v in re.findall(r"^\s*(level|health|temperature|status|Charge counter|cycle count|Cycle count):\s*(\S+)", b, re.M)}
    R["battery"] = {"level": int(bat["level"]) if bat.get("level", "").isdigit() else None,
                    "health": {"2": "хорошее", "3": "перегрев", "4": "износ", "5": "перенапряжение", "7": "холод"}.get(bat.get("health", ""), ""),
                    "temp": int(bat["temperature"]) / 10 if bat.get("temperature", "").lstrip("-").isdigit() else None,
                    "cycles": int(bat.get("cycle count") or bat.get("Cycle count") or 0) or None}
    if R["battery"]["health"] in ("износ", "перегрев"):
        add("warn", f"Батарея: {R['battery']['health']}", "Android сам сообщает о проблеме с батареей — её стоит проверить в сервисе.")
    df = sh(serial, "df /data 2>/dev/null").splitlines()
    m = re.search(r"\s(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%", df[-1] if df else "")
    if m:
        total, used = int(m.group(1)) * 1024, int(m.group(2)) * 1024
        R["storage"] = {"total": total, "used": used, "pct": int(m.group(4))}
        if int(m.group(4)) >= 92:
            add("warn", "Память телефона почти заполнена", f"Занято {m.group(4)}% — телефон начинает тормозить, обновления не ставятся.")
    if _setting(serial, "global", "adb_enabled") == "1":
        add("info", "Отладка по USB включена", "Она нужна для этой проверки. Когда закончишь — выключи: «Настройки → Для разработчиков → Отладка по USB».")

    lv = [f["lvl"] for f in R["findings"]]
    R["verdict"] = "bad" if "bad" in lv else "warn" if "warn" in lv else "ok"
    try:
        os.makedirs(DATA, exist_ok=True)
        json.dump(R, open(os.path.join(DATA, "phone.json"), "w", encoding="utf-8"), ensure_ascii=False)
    except OSError:
        pass
    return R


def last():
    try:
        return json.load(open(os.path.join(DATA, "phone.json"), encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------- действия (только над найденным последней проверкой)
def _known(pkg):
    r = last() or {}
    if not re.fullmatch(r"[\w.]+", pkg or "") or not any(a["pkg"] == pkg for a in r.get("apps", [])) and not any(x["pkg"] == pkg for x in r.get("special", [])):
        raise RuntimeError("это приложение не из последней проверки телефона — сначала проверь телефон заново")
    return r["serial"]


def open_app(pkg):
    serial = _known(pkg)
    sh(serial, "input keyevent KEYCODE_WAKEUP")
    out = sh(serial, f"am start -a android.settings.APPLICATION_DETAILS_SETTINGS -d package:{pkg}")
    if "Error" in out:
        raise RuntimeError(out.strip()[:200])
    return {"ok": True}


def uninstall(pkg):
    serial = _known(pkg)
    out = _adb("uninstall", pkg, serial=serial, timeout=60).strip()
    if "Success" not in out:
        if "DELETE_FAILED_DEVICE_POLICY_MANAGER" in out:
            raise RuntimeError("приложение — администратор устройства и мешает удалению. Открой его настройки на телефоне и сними права "
                               "администратора («Настройки → Пароли и безопасность → Приложения администратора»), затем удали снова")
        raise RuntimeError(out[:200] or "не удалилось")
    return {"ok": True, "pkg": pkg}


def a11y_off(pkg):
    serial = _known(pkg)
    cur = _setting(serial, "secure", "enabled_accessibility_services") or ""
    keep = [c for c in cur.split(":") if c and not c.startswith(pkg + "/")]
    sh(serial, "settings put secure enabled_accessibility_services " + (":".join(keep) if keep else "''"))
    if not keep:
        sh(serial, "settings put secure accessibility_enabled 0")
    return {"ok": True, "pkg": pkg}
