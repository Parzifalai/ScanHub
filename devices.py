"""Подключённые устройства: клавиатуры, мыши и тачпады, микрофоны, динамики, камеры, Bluetooth, телефоны и флешки.

* Список — напрямую из Windows (cfgmgr32, как hwcheck.problem_devices): доли секунды вместо 20 с у Win32_PnPEntity.
* У каждого — понятное состояние: работает / выключено / не работает (код Диспетчера устройств с объяснением).
* Настройки, из-за которых «не работает», хотя устройство исправно: микрофон и камера запрещены в параметрах
  конфиденциальности, включены залипание и фильтрация ввода (клавиши «тормозят»), ускорение указателя мыши.
* Кто недавно пользовался микрофоном и камерой — Windows помнит это сама (ConsentStore → LastUsedTimeStart/Stop).
Живые проверки (уровень микрофона, нажатия клавиш, кнопки мыши, тон в динамиках, картинка с камеры) делает окно.
"""
import ctypes
import ctypes.wintypes as wt
import os
import re
import time
import winreg

import hwcheck
from hwcheck import cfg, CR_SUCCESS, DN_HAS_PROBLEM, CM_GETIDLIST_FILTER_PRESENT, CM_DRP_CLASS, CM_DRP_DEVICEDESC, CM_DRP_FRIENDLYNAME, _prop, _bus_name

DN_STARTED = 0x00000008
DEVPKEY_BT_BATTERY = hwcheck._devpkey("104ea319-6ee2-4701-bd47-8ddbf425bbe5", 2)
DEVPKEY_BT_COD = hwcheck._devpkey("2bd67d8b-8beb-48d5-87e0-6cda3428040a", 4)            # класс устройства (наушники, телефон…)
DEVPKEY_BT_LAST = hwcheck._devpkey("2bd67d8b-8beb-48d5-87e0-6cda3428040a", 11)          # когда подключалось последний раз
BT_MAJOR = {1: "компьютер", 2: "телефон", 4: "наушники или колонка", 5: "клавиатура, мышь или геймпад", 6: "принтер или камера", 7: "часы или браслет"}

GROUPS = [
    ("keyboard", "Клавиатуры"),
    ("mouse", "Мыши и тачпады"),
    ("mic", "Микрофоны"),
    ("speaker", "Динамики и наушники"),
    ("camera", "Камеры"),
    ("bluetooth", "Bluetooth"),
    ("portable", "Телефоны, флешки и другие подключённые"),
]
# служебное, что человеку ничего не говорит
SKIP_NAME = re.compile(r"enumerator|перечислител|Microsoft Bluetooth LE|Bluetooth Device \(RFCOMM|Bluetooth Device \(Personal Area|"
                       r"Avrcp|Hands-Free Audio Gateway|Audio Gateway|Device Identification Service|Generic Attribute Profile|"
                       r"Generic Access Profile|vendor-defined|определяемое поставщиком|System Controller|Consumer Control|"
                       r"Устройство управления|Radio Management|Wireless Radio Controls|Portable Device Control|"
                       r"Converted Portable Device|Virtual|виртуальн|Универсальный профиль доступа|Служба сведений об устройств|"
                       r"Универсальная служба атрибутов|профиль атрибутов", re.I)
TOUCHPAD = re.compile(r"touch ?pad|сенсорн\w* панел|precision", re.I)

CODE_TEXT = {
    1: "настроено неправильно", 3: "драйвер повреждён", 10: "не запускается", 12: "не хватает ресурсов", 14: "ждёт перезагрузки",
    18: "драйвер нужно переустановить", 19: "сведения в реестре повреждены", 21: "Windows удаляет устройство", 22: "выключено",
    24: "отключено или не найдено", 28: "драйвер не установлен", 29: "выключено в BIOS", 31: "работает неправильно",
    32: "драйвер выключен", 37: "драйвер не смог запуститься", 38: "драйвер уже загружен с ошибкой — нужна перезагрузка",
    39: "драйвер повреждён или отсутствует", 43: "Windows остановила устройство: оно сообщило об ошибке", 45: "сейчас не подключено",
    47: "подготовлено к безопасному извлечению", 48: "драйвер заблокирован: известна несовместимость", 52: "подпись драйвера не проверена",
}


def _ids():
    size = wt.ULONG()
    if cfg.CM_Get_Device_ID_List_SizeW(ctypes.byref(size), None, CM_GETIDLIST_FILTER_PRESENT) != CR_SUCCESS:
        return []
    buf = ctypes.create_unicode_buffer(size.value)
    if cfg.CM_Get_Device_ID_ListW(None, buf, size, CM_GETIDLIST_FILTER_PRESENT) != CR_SUCCESS:
        return []
    return [x for x in ctypes.wstring_at(buf, size.value).split("\0") if x]


def _battery(dn):
    v = ctypes.c_ubyte()
    size, typ = wt.ULONG(1), wt.ULONG()
    try:
        if cfg.CM_Get_DevNode_PropertyW(dn, ctypes.byref(DEVPKEY_BT_BATTERY), ctypes.byref(typ), ctypes.byref(v), ctypes.byref(size), 0) == CR_SUCCESS:
            return int(v.value) if 0 <= v.value <= 100 else None
    except (OSError, AttributeError):
        pass
    return None


def _devprop_raw(dn, key, n=8):
    buf = ctypes.create_string_buffer(n)
    size, typ = wt.ULONG(n), wt.ULONG()
    try:
        if cfg.CM_Get_DevNode_PropertyW(dn, ctypes.byref(key), ctypes.byref(typ), buf, ctypes.byref(size), 0) == CR_SUCCESS:
            return buf.raw[:size.value]
    except (OSError, AttributeError):
        pass
    return b""


def _link(did):
    u = did.upper()
    if u.startswith(("BTHENUM\\", "BTHLE", "BTHLEDEVICE\\", "BTHHFENUM\\")) or "{00001124-0000-1000-8000-00805F9B34FB}" in u or "{00001812-0000-1000-8000-00805F9B34FB}" in u:
        return "Bluetooth"
    if u.startswith(("USB\\", "USBSTOR\\")) or (u.startswith("HID\\VID_")):
        return "USB"
    if u.startswith(("ACPI\\", "HID\\ELAN", "HID\\SYNA", "HID\\MSFT", "I2C", "HID\\CONVERTEDDEVICE")) or "PNP0303" in u or "PNP0F13" in u:
        return "встроенное"
    if u.startswith("SWD\\MMDEVAPI"):
        return ""
    return ""


def _group(cls, did, name):
    c, u = (cls or "").lower(), did.upper()
    if c == "keyboard":
        return "keyboard"
    if c == "mouse" or (c == "hidclass" and TOUCHPAD.search(name or "")):
        return "mouse"
    if c == "audioendpoint":
        return "mic" if "{0.0.1." in u else "speaker"
    if c in ("camera", "image") and not re.search(r"scanner|сканер|ir camera|инфракрасн", name or "", re.I):
        return "camera"
    if c == "bluetooth" and (u.startswith(("BTHENUM\\DEV_", "BTHLE\\DEV_")) or "DEV_" in u):
        return "bluetooth"
    if c in ("wpd", "androidusbdeviceclass", "diskdrive") and ("USB" in u or "WPDBUSENUM" in u or "USBSTOR" in u):
        return "portable"
    return None


def list_devices():
    out = []
    for did in _ids():
        dn = wt.DWORD()
        if cfg.CM_Locate_DevNodeW(ctypes.byref(dn), did, 0) != CR_SUCCESS:
            continue
        cls = _prop(dn, CM_DRP_CLASS)
        name = _prop(dn, CM_DRP_FRIENDLYNAME) or _prop(dn, CM_DRP_DEVICEDESC)
        g = _group(cls, did, name)
        if not g or not name or SKIP_NAME.search(name):
            continue
        st, pr = wt.ULONG(), wt.ULONG()
        if cfg.CM_Get_DevNode_Status(ctypes.byref(st), ctypes.byref(pr), dn, 0) != CR_SUCCESS:
            continue
        code = pr.value if st.value & DN_HAS_PROBLEM else 0
        if code == 45:                      # «сейчас не подключено» — у «присутствующих» почти не бывает, но пропустим
            continue
        bus = _bus_name(dn)
        try:
            import system
            nice = system.device_name(name, bus)
        except Exception:
            nice = name
        d = {"group": g, "name": nice, "cls": cls, "id": did, "code": code, "link": _link(did)}
        if code == 0:
            d.update(state="ok", text="работает")
        elif code == 22:
            d.update(state="off", text="выключено в Диспетчере устройств")
        elif code == 14:
            d.update(state="info", text="ждёт перезагрузки, чтобы закончить установку")
        else:
            d.update(state="bad", text=f"{CODE_TEXT.get(code, 'ошибка')} (код {code})")
            try:
                import system
                h = system.device_hint(cls, code, did)
                if h:
                    d["hint"] = h
            except Exception:
                pass
        if g == "bluetooth":
            b = _battery(dn)
            if b is not None:
                d["battery"] = b
            cod = _devprop_raw(dn, DEVPKEY_BT_COD, 4)
            if len(cod) == 4:
                d["kind"] = BT_MAJOR.get((int.from_bytes(cod, "little") >> 8) & 0x1F, "")
            last = _devprop_raw(dn, DEVPKEY_BT_LAST, 8)
            if len(last) == 8:
                t = _ft(int.from_bytes(last, "little"))
                if t:
                    d["last"] = t
            if d["state"] == "ok":
                d["text"] = "сопряжено" + (f" · подключалось {_ago(d['last'])}" if d.get("last") else "")
        out.append(d)
    # одинаковые интерфейсы одного устройства — одной строкой (у Bluetooth остаётся самая свежая запись)
    out.sort(key=lambda d: -(d.get("last") or 0))
    seen, uniq = {}, []
    for d in out:
        k = (d["group"], d["name"], d["state"])
        if k in seen:
            seen[k]["n"] = seen[k].get("n", 1) + 1
            continue
        seen[k] = d
        uniq.append(d)
    return uniq


# ---------------------------------------------------------------- микрофон и камера: разрешения и кто пользовался
CS = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"


def _rv(root, path, name):
    try:
        with winreg.OpenKey(root, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def _ago(t):
    s = time.time() - t
    if s < 3600:
        return "только что"
    if s < 86400:
        return f"{int(s // 3600)} ч назад"
    d = int(s // 86400)
    return "вчера" if d == 1 else f"{d} дн. назад"


def _ft(v):
    try:
        v = int(v)
        return None if v <= 0 else (v - 116444736000000000) / 1e7
    except (TypeError, ValueError):
        return None


def _app_name(key, packaged):
    if not packaged:                                    # «C:#Program Files#Discord#…#Discord.exe»
        path = key.replace("#", "\\")
        return os.path.basename(path), path
    m = re.match(r"([^_]+)_", key)                      # «Microsoft.WindowsCamera_8wekyb3d8bbwe»
    n = (m.group(1) if m else key)
    n = re.sub(r"^Microsoft\.(Windows)?", "", n) or n
    return n, key


def privacy(cap):
    """cap: 'microphone' | 'webcam'. Разрешено ли всем / приложениям Store / обычным программам и кто пользовался за 30 дней."""
    base = CS + "\\" + cap
    sys_v = _rv(winreg.HKEY_LOCAL_MACHINE, base, "Value")
    user_v = _rv(winreg.HKEY_CURRENT_USER, base, "Value")
    np_v = _rv(winreg.HKEY_CURRENT_USER, base + "\\NonPackaged", "Value")
    used, now, cutoff = [], time.time(), time.time() - 30 * 86400
    for packaged, sub in ((True, base), (False, base + "\\NonPackaged")):
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub)
        except OSError:
            continue
        with k:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                if name == "NonPackaged":
                    continue
                start = _ft(_rv(winreg.HKEY_CURRENT_USER, sub + "\\" + name, "LastUsedTimeStart"))
                stop = _rv(winreg.HKEY_CURRENT_USER, sub + "\\" + name, "LastUsedTimeStop")
                if not start or start < cutoff:
                    continue
                app, path = _app_name(name, packaged)
                used.append({"app": app, "path": path, "start": start, "now": stop == 0, "ago": int(now - start)})
    used.sort(key=lambda x: -x["start"])
    return {"system": sys_v != "Deny", "user": user_v != "Deny", "desktop": np_v != "Deny", "used": used[:15]}


def _flag(path, name="Flags"):
    v = _rv(winreg.HKEY_CURRENT_USER, path, name)
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def settings_issues(devs):
    """Настройки Windows, из-за которых устройство «не работает» или работает странно, хотя оно исправно."""
    F = []
    add = lambda group, lvl, t, s, fix=None: F.append({"group": group, "lvl": lvl, "t": t, "s": s, "fix": fix})
    if _flag(r"Control Panel\Accessibility\Keyboard Response") & 1:
        add("keyboard", "warn", "Включена фильтрация ввода", "Windows пропускает короткие и повторные нажатия — кажется, что клавиатура «тормозит» или "
            "не нажимаются клавиши. Обычно включается случайно, если долго держать правый Shift.", "filterkeys")
    if _flag(r"Control Panel\Accessibility\StickyKeys") & 1:
        add("keyboard", "warn", "Включено залипание клавиш", "Shift, Ctrl и Alt «залипают» после одного нажатия. Включается, если пять раз подряд нажать Shift.", "stickykeys")
    if _flag(r"Control Panel\Accessibility\ToggleKeys") & 1:
        add("keyboard", "info", "Включено озвучивание Caps Lock и Num Lock", "При нажатии этих клавиш звучит сигнал — это не поломка.", None)
    ms = _rv(winreg.HKEY_CURRENT_USER, r"Control Panel\Mouse", "MouseSpeed")
    if str(ms) not in ("0", "None"):
        add("mouse", "info", "Включено «Повышенная точность указателя»", "Указатель ускоряется при быстром движении. Для работы удобно, в играх "
            "прицеливаться точнее без него.", "mouseaccel")
    for cap, grp, word in (("microphone", "mic", "микрофон"), ("webcam", "camera", "камеру")):
        p = privacy(cap)
        has = any(d["group"] == grp for d in devs)
        if not p["system"] or not p["user"]:
            add(grp, "bad" if has else "info", f"Windows запрещает приложениям использовать {word}",
                f"В «Параметры → Конфиденциальность → {'Микрофон' if grp == 'mic' else 'Камера'}» доступ выключен — устройство исправно, "
                f"но ни одна программа его не получит.", "privacy_" + cap)
        elif not p["desktop"]:
            add(grp, "warn", f"Обычным программам запрещено использовать {word}",
                "Discord, Zoom, Telegram и браузеры его не получат — разрешено только приложениям из Microsoft Store.", "privacy_" + cap)
    return F


def check():
    t0 = time.time()
    devs = list_devices()
    issues = settings_issues(devs)
    mic, cam = privacy("microphone"), privacy("webcam")
    groups = []
    for gid, title in GROUPS:
        items = [d for d in devs if d["group"] == gid]
        iss = [x for x in issues if x["group"] == gid]
        if not items and gid in ("portable", "bluetooth", "camera"):
            continue
        worst = "bad" if any(d["state"] == "bad" for d in items) or any(x["lvl"] == "bad" for x in iss) else \
                "warn" if any(x["lvl"] == "warn" for x in iss) or (gid in ("keyboard", "mouse", "mic", "speaker") and not [d for d in items if d["state"] == "ok"]) else "ok"
        groups.append({"id": gid, "title": title, "items": items, "issues": iss, "lvl": worst})
    bad = sum(1 for g in groups if g["lvl"] == "bad")
    warn = sum(1 for g in groups if g["lvl"] == "warn")
    return {"groups": groups, "mic_used": mic["used"], "cam_used": cam["used"], "bad": bad, "warn": warn,
            "seconds": round(time.time() - t0, 2), "when": time.strftime("%Y-%m-%dT%H:%M:%S")}


# ---------------------------------------------------------------- исправления (только HKCU — без UAC)
def fix(kind):
    def setv(path, name, val, typ=winreg.REG_SZ):
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as k:
            winreg.SetValueEx(k, name, 0, typ, val)

    def clear_bit(path):
        v = _flag(path)
        setv(path, "Flags", str(v & ~1))

    if kind == "filterkeys":
        clear_bit(r"Control Panel\Accessibility\Keyboard Response")
    elif kind == "stickykeys":
        clear_bit(r"Control Panel\Accessibility\StickyKeys")
    elif kind == "mouseaccel":
        for n, v in (("MouseSpeed", "0"), ("MouseThreshold1", "0"), ("MouseThreshold2", "0")):
            setv(r"Control Panel\Mouse", n, v)
    elif kind in ("privacy_microphone", "privacy_webcam"):
        cap = kind.split("_", 1)[1]
        setv(CS + "\\" + cap, "Value", "Allow")
        setv(CS + "\\" + cap + "\\NonPackaged", "Value", "Allow")
    else:
        raise RuntimeError("неизвестное исправление")
    _apply_now(kind)
    return {"ok": True, "kind": kind}


def _apply_now(kind):
    """Фильтрация, залипание и ускорение мыши читаются из реестра только при входе — сообщаем Windows сразу через SystemParametersInfo."""
    u = ctypes.windll.user32
    try:
        if kind == "filterkeys":
            class FILTERKEYS(ctypes.Structure):
                _fields_ = [("cbSize", wt.UINT), ("dwFlags", wt.DWORD), ("iWaitMSec", wt.DWORD), ("iDelayMSec", wt.DWORD),
                            ("iRepeatMSec", wt.DWORD), ("iBounceMSec", wt.DWORD)]
            fk = FILTERKEYS(); fk.cbSize = ctypes.sizeof(fk)
            if u.SystemParametersInfoW(0x0032, fk.cbSize, ctypes.byref(fk), 0):        # SPI_GETFILTERKEYS
                fk.dwFlags &= ~1
                u.SystemParametersInfoW(0x0033, fk.cbSize, ctypes.byref(fk), 3)        # SPI_SETFILTERKEYS
        elif kind == "stickykeys":
            class STICKYKEYS(ctypes.Structure):
                _fields_ = [("cbSize", wt.UINT), ("dwFlags", wt.DWORD)]
            sk = STICKYKEYS(); sk.cbSize = ctypes.sizeof(sk)
            if u.SystemParametersInfoW(0x003A, sk.cbSize, ctypes.byref(sk), 0):        # SPI_GETSTICKYKEYS
                sk.dwFlags &= ~1
                u.SystemParametersInfoW(0x003B, sk.cbSize, ctypes.byref(sk), 3)
        elif kind == "mouseaccel":
            arr = (ctypes.c_int * 3)(0, 0, 0)
            u.SystemParametersInfoW(0x0004, 0, arr, 3)                                 # SPI_SETMOUSE
    except Exception:
        pass
