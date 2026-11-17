"""2.5: драйвер для устройства с ошибкой и службы Windows — то, что агент делает по «Сделай сам».

Почему так (случай с ноутбука без бренда, сканер отпечатка FocalTech с кодом 28): модель искала драйвер по названию,
советовала «самый верхний в каталоге», путалась в распаковке .cab (expand пишет «требуется указать папку назначения», если
папки ещё нет) и в путях. Здесь ScanHub сам:
- берёт номер оборудования (VID_xxxx&PID_xxxx …) и даёт ссылку на поиск именно по нему в каталоге Microsoft Update;
- распаковывает скачанный .cab / .zip в свою папку, находит .inf;
- ставит драйвер, только если в .inf есть номер одного из устройств с ошибкой (чужой драйвер не ставится);
- ставит одним окном UAC (pnputil /add-driver … /install) и проверяет, пропала ли ошибка у устройства.
"""
import ctypes
import hashlib
import os
import re
import subprocess
import time
import urllib.parse
import zipfile
from ctypes import wintypes as wt

import hwcheck

NO_WINDOW = 0x08000000
ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
DRV_DIR = os.path.join(DATA, "drivers")
SYS32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
CATALOG = "https://www.catalog.update.microsoft.com/Search.aspx?q="
CM_DRP_HARDWAREID, CM_DRP_COMPATIBLEIDS = 0x02, 0x03
# коды Диспетчера устройств, которые лечатся драйвером
DRIVER_CODES = {1, 10, 18, 28, 31, 32, 37, 39, 40, 41, 48, 52}
CODE_TEXT = {28: "драйвер не установлен", 1: "устройство настроено неправильно — нужен другой драйвер", 10: "устройство не запускается",
             18: "драйвер нужно переустановить", 31: "Windows не может загрузить драйвер", 37: "драйвер не запустился",
             39: "драйвер повреждён или отсутствует", 52: "у драйвера нет действительной подписи", 43: "устройство сообщило об ошибке",
             22: "устройство отключено", 45: "устройство не подключено"}


def _multi(dn, prop):
    """Строки из свойства-списка (REG_MULTI_SZ) узла устройства."""
    size = wt.ULONG(0)
    typ = wt.ULONG()
    hwcheck.cfg.CM_Get_DevNode_Registry_PropertyW(dn, prop, ctypes.byref(typ), None, ctypes.byref(size), 0)
    if not size.value:
        return []
    buf = ctypes.create_unicode_buffer(size.value // 2 + 2)
    if hwcheck.cfg.CM_Get_DevNode_Registry_PropertyW(dn, prop, ctypes.byref(typ), buf, ctypes.byref(size), 0) != hwcheck.CR_SUCCESS:
        return []
    return [x for x in ctypes.wstring_at(buf, size.value // 2).split("\0") if x]


def hardware_ids(instance_id):
    dn = wt.DWORD()
    if hwcheck.cfg.CM_Locate_DevNodeW(ctypes.byref(dn), instance_id, 0) != hwcheck.CR_SUCCESS:
        return [], []
    return _multi(dn, CM_DRP_HARDWAREID), _multi(dn, CM_DRP_COMPATIBLEIDS)


def search_term(ids, instance_id=""):
    """Короткий номер для поиска драйвера: VID_xxxx&PID_xxxx, VEN_xxxx&DEV_xxxx или ACPI-имя (FTE3600)."""
    for rx in (r"VID_[0-9A-F]{4}&PID_[0-9A-F]{4}", r"VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}", r"^ACPI\\([A-Z0-9]{4,8})$", r"^HID\\([A-Z0-9]{4,8})$"):
        for s in list(ids) + [instance_id]:
            m = re.search(rx, s or "", re.I)
            if m:
                return (m.group(1) if m.groups() else m.group(0)).upper()
    return (ids[0] if ids else instance_id.rsplit("\\", 1)[0]).upper()


def problem_devices():
    """Устройства с ошибкой + всё, что нужно для поиска драйвера."""
    out = []
    for d in hwcheck.problem_devices():
        hw, compat = hardware_ids(d["id"])
        term = search_term(hw, d["id"])
        out.append({"имя": d["name"], "класс": d.get("cls"), "код": d["code"],
                    "что_значит": CODE_TEXT.get(d["code"], "ошибка устройства"), "id": d["id"],
                    "номера_оборудования": hw[:6], "совместимые": compat[:4], "номер_для_поиска": term,
                    "каталог_microsoft": CATALOG + urllib.parse.quote(term),
                    "лечится_драйвером": d["code"] in DRIVER_CODES})
    return out


# ---------------------------------------------------------------- распаковка скачанного

def _safe_name(path):
    base = re.sub(r"[^\w.-]+", "_", os.path.splitext(os.path.basename(path.rstrip("\\/")))[0])[:40] or "driver"
    return f"{base}_{hashlib.sha1(os.path.abspath(path).lower().encode()).hexdigest()[:8]}"


def _expand_cab(src, dest):
    os.makedirs(dest, exist_ok=True)              # папка назначения должна уже быть — иначе «требуется указать папку назначения»
    r = subprocess.run([os.path.join(SYS32, "expand.exe"), src, "-F:*", dest], capture_output=True, timeout=600, creationflags=NO_WINDOW)
    if r.returncode != 0 or not any(os.scandir(dest)):
        msg = (r.stdout or b"").decode("cp866", "replace").strip().splitlines()
        raise RuntimeError("не получилось распаковать .cab: " + (msg[-1] if msg else "файл повреждён или это не архив")[:200])
    return r.returncode


def _unzip(src, dest):
    os.makedirs(dest, exist_ok=True)
    root = os.path.abspath(dest)
    with zipfile.ZipFile(src) as z:
        if sum(i.file_size for i in z.infolist()) > 3 * 2 ** 30:
            raise RuntimeError("архив больше 3 ГБ — на драйвер не похоже")
        for i in z.infolist():
            to = os.path.abspath(os.path.join(root, i.filename))
            if not to.startswith(root + os.sep) and to != root:     # «../» в архиве — мимо папки не распаковываем
                continue
            z.extract(i, root)


def _infs(folder):
    out = []
    for dp, _, fs in os.walk(folder):
        out += [os.path.join(dp, f) for f in fs if f.lower().endswith(".inf")]
    return out[:200]


def prepare(path):
    """Скачанный файл → папка с .inf. Возвращает (папка, [inf])."""
    p = os.path.abspath(path)
    low = p.lower()
    if os.path.isdir(p):
        return p, _infs(p)
    if low.endswith(".inf"):
        return os.path.dirname(p), [p]
    dest = os.path.join(DRV_DIR, _safe_name(p))
    if low.endswith(".cab"):
        _expand_cab(p, dest)
    elif low.endswith(".zip"):
        _unzip(p, dest)
    elif low.endswith((".exe", ".msi")):
        raise RuntimeError("это установщик (.exe/.msi), а не файл драйвера — его запускают двойным щелчком; "
                           "перед запуском его можно проверить в ScanHub («Проверить файл»)")
    else:
        raise RuntimeError("ScanHub ставит драйвер из .cab, .zip, .inf или папки с .inf")
    infs = _infs(dest)
    if not infs:                                   # в каталоге Microsoft бывает .cab внутри .cab
        for dp, _, fs in os.walk(dest):
            for f in fs:
                if f.lower().endswith(".cab"):
                    _expand_cab(os.path.join(dp, f), os.path.join(dp, os.path.splitext(f)[0]))
        infs = _infs(dest)
    return dest, infs


def _read_inf(path):
    raw = open(path, "rb").read(4 * 2 ** 20)
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or raw[1:2] == b"\x00":
        return raw.decode("utf-16", "replace").lower()
    return raw.decode("cp1252", "replace").lower()


def match(infs, devs):
    """Какие .inf подходят каким устройствам с ошибкой: по полному номеру оборудования или по VID/PID (VEN/DEV)."""
    hits = {}
    for inf in infs:
        try:
            text = _read_inf(inf)
        except OSError:
            continue
        for d in devs:
            keys = [x.lower() for x in d["номера_оборудования"]] + [d["номер_для_поиска"].lower()]
            if any(k and k in text for k in keys):
                hits.setdefault(inf, []).append(d)
    return hits


# ---------------------------------------------------------------- установка

def install(path, run_el):
    path = os.path.expandvars(str(path or "").strip().strip('"«»'))
    if not path or not os.path.exists(path):
        return {"ok": False, "ошибка": f"файла или папки нет: {path}",
                "что_делать": "проверь путь (инструменты find_files / file_info) — в Загрузках или в «Новая папка»"}
    devs = [d for d in problem_devices() if d["лечится_драйвером"]]
    if not devs:
        return {"ok": False, "ошибка": "сейчас нет устройств с ошибкой драйвера — ставить нечего",
                "что_делать": "если устройство не работает без ошибки в Диспетчере — дело не в драйвере"}
    try:
        folder, infs = prepare(path)
    except Exception as e:
        return {"ok": False, "ошибка": str(e)[:300]}
    if not infs:
        return {"ok": False, "ошибка": "в этом файле нет драйвера (.inf) — это другой тип файла или архив неполный", "папка": folder}
    hits = match(infs, devs)
    if not hits:
        return {"ok": False, "подходит": False, "ошибка": "этот драйвер не для твоих устройств с ошибкой — ставить его ScanHub не будет",
                "в_файле_драйверы_для": sorted({os.path.basename(i) for i in infs})[:10],
                "устройства_с_ошибкой": [{"имя": d["имя"], "номер": d["номер_для_поиска"], "искать_тут": d["каталог_microsoft"]} for d in devs],
                "что_делать": "найди драйвер по номеру устройства (ссылка «искать_тут») и скачай версию для Windows 11 / 10, x64"}
    pnp = os.path.join(SYS32, "pnputil.exe")
    ops = [{"type": "run", "cmd": [pnp, "/add-driver", inf, "/install"], "timeout": 600, "label": "ставлю драйвер"} for inf in hits]
    ops.append({"type": "run", "cmd": [pnp, "/scan-devices"], "timeout": 120, "label": "ищу устройства заново"})
    try:
        res = run_el(ops)
    except PermissionError:
        return {"ok": False, "ошибка": "окно UAC отменено — без прав администратора драйвер не поставить"}
    time.sleep(3)
    after = {d["id"]: d for d in problem_devices()}
    fixed, still = [], []
    for d in {d["id"]: d for ds in hits.values() for d in ds}.values():
        (still if d["id"] in after else fixed).append(d)
    codes = [r.get("code") for r in res[:-1]] if isinstance(res, list) else []
    reboot = 3010 in codes
    out = "\n".join(str(r.get("out") or "").strip() for r in (res if isinstance(res, list) else []))[-1500:]
    ok = bool(fixed) or reboot
    return {"ok": ok, "драйверы": [os.path.basename(i) for i in hits],
            "заработало": [d["имя"] for d in fixed],
            "ещё_с_ошибкой": [{"имя": d["имя"], "код": after[d["id"]]["код"], "что_значит": after[d["id"]]["что_значит"]} for d in still],
            "нужна_перезагрузка": reboot,
            "итог": ("драйвер поставлен, устройство заработало" if fixed and not still else
                     "драйвер поставлен, нужна перезагрузка — после неё проверь устройство" if reboot else
                     "драйвер добавлен, но устройство всё ещё с ошибкой — скорее всего нужна другая версия драйвера" if not fixed else
                     "часть устройств заработала"),
            "pnputil": out, "папка": folder}


# ---------------------------------------------------------------- службы Windows

# только службы обычных функций (отпечаток, звук, печать, Bluetooth, Wi-Fi…): удалённый доступ, RDP, WinRM и т. п. ScanHub не включает
SAFE_SERVICES = {"wbiosrvc": "Биометрическая служба (отпечаток, Windows Hello)", "audiosrv": "Звук Windows",
                 "audioendpointbuilder": "Звук: устройства воспроизведения", "spooler": "Печать", "bthserv": "Bluetooth",
                 "btagservice": "Bluetooth: звук", "wlansvc": "Wi-Fi", "wcmsvc": "Подключения к сетям", "dhcp": "Сеть: DHCP",
                 "dnscache": "Сеть: DNS", "nlasvc": "Сеть: определение сети", "netprofm": "Сеть: профили", "wuauserv": "Windows Update",
                 "bits": "Фоновая загрузка (Windows Update)", "themes": "Темы оформления", "wsearch": "Поиск Windows",
                 "frameserver": "Камера: Frame Server", "camsvc": "Доступ к камере и микрофону", "tabletinputservice": "Сенсорная клавиатура и перо",
                 "hidserv": "Кнопки клавиатуры и мультимедиа", "shellhwdetection": "Автозапуск носителей", "w32time": "Время Windows",
                 "stisvc": "Сканеры и камеры (WIA)", "lfsvc": "Геолокация", "sensorservice": "Датчики", "sensrsvc": "Датчики (наблюдение)",
                 "deviceassociationservice": "Сопряжение устройств", "usosvc": "Обновления Windows (оркестратор)",
                 "wpdbusenum": "Телефоны и плееры по USB", "fdrespub": "Сеть: обнаружение устройств", "fdphost": "Сеть: обнаружение"}
MODES = {"auto": "auto", "demand": "demand", "manual": "demand", "disabled": "disabled", "delayed-auto": "delayed-auto"}


def service_state(name):
    import system
    rows = system.as_list(system.ps(f"Get-CimInstance Win32_Service -Filter \"Name='{name}'\" | Select-Object Name, DisplayName, State, StartMode "
                                    "| ConvertTo-Json -Compress", timeout=30))
    return rows[0] if rows and isinstance(rows[0], dict) else None


def service_set(name, run_el, mode="", stop=False):
    """Включить и запустить службу из списка SAFE_SERVICES (или вернуть прежний режим). Возвращает, что было и что стало."""
    key = str(name or "").strip().lower()
    if key not in SAFE_SERVICES:
        raise RuntimeError(f"службу «{name}» ScanHub не включает — только службы обычных функций (звук, печать, Bluetooth, отпечаток…)")
    before = service_state(key)
    if not before:
        raise RuntimeError(f"службы «{name}» нет на этом компьютере")
    was = {"auto": "auto", "manual": "demand", "disabled": "disabled"}.get(str(before.get("StartMode", "")).lower(), "demand")
    sc = os.path.join(SYS32, "sc.exe")
    ops = []
    if stop:                                       # отмена: вернуть режим как было и остановить
        ops.append({"type": "run", "cmd": [sc, "config", before["Name"], "start=", MODES.get(mode, "demand")], "timeout": 60})
        if MODES.get(mode) == "disabled":
            ops.append({"type": "run", "cmd": [sc, "stop", before["Name"]], "timeout": 60})
    else:
        if was == "disabled":
            ops.append({"type": "run", "cmd": [sc, "config", before["Name"], "start=", "demand"], "timeout": 60})
        ops.append({"type": "run", "cmd": [sc, "start", before["Name"]], "timeout": 90})
    res = run_el(ops)
    time.sleep(2)
    after = service_state(key) or {}
    running = str(after.get("State", "")).lower() == "running"
    return {"служба": before.get("DisplayName") or before["Name"], "имя": before["Name"], "было": was,
            "было_состояние": before.get("State"), "стало": after.get("StartMode"), "состояние": after.get("State"),
            "работает": running, "sc": "\n".join(str(r.get("out") or "").strip() for r in res if isinstance(r, dict))[-600:]}
