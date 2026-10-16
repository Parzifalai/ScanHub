"""Проверка комплектующих: что работает не в полную силу, неправильно подключено или конфликтует.

Только чтение, без прав администратора: WMI/CIM, nvidia-smi, powercfg, netsh, журнал сбоев (кэш diag.json).
Каждая находка: comp (группа), lvl (bad / warn / info / ok), title (без меняющихся чисел — по нему сверяет ультра
проверка), text (что видно), how (что сделать).
"""
import os
import re
import shutil
import subprocess
from datetime import datetime, date

import system

NO_WINDOW = 0x08000000

_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = @{}
$arr = Get-CimInstance Win32_PhysicalMemoryArray | Select-Object -First 1
$o.ram = @{slots=[int]$arr.MemoryDevices; modules=@(Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
  @{slot=$_.DeviceLocator; bank=$_.BankLabel; size=[long]$_.Capacity; speed=[int]$_.Speed; cfg=[int]$_.ConfiguredClockSpeed; type=[int]$_.SMBIOSMemoryType; part=([string]$_.PartNumber).Trim()} })}
$b = Get-CimInstance -Namespace root\wmi BatteryStatus | Select-Object -First 1
$w = Get-CimInstance Win32_Battery | Select-Object -First 1
if ($b) { $o.battery = @{online=[bool]$b.PowerOnline; charging=[bool]$b.Charging; discharging=[bool]$b.Discharging; rate=[int]$b.DischargeRate; pct=[int]$w.EstimatedChargeRemaining} }
$bios = Get-CimInstance Win32_BIOS
$o.bios = @{ver=$bios.SMBIOSBIOSVersion; date=$(if($bios.ReleaseDate){$bios.ReleaseDate.ToString('yyyy-MM-dd')})}
$cs = Get-CimInstance Win32_ComputerSystem
$o.sys = @{maker=$cs.Manufacturer; model=$cs.Model; family=$cs.SystemFamily; laptop=[bool](Get-CimInstance Win32_Battery)}
$o.disks = @(Get-PhysicalDisk | ForEach-Object { @{name=$_.FriendlyName; media=[string]$_.MediaType; bus=[string]$_.BusType; health=[string]$_.HealthStatus; op=[string]($_.OperationalStatus -join ', ')} })
$o.net = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object { @{name=$_.InterfaceDescription; alias=$_.Name;
  media=[string]$_.PhysicalMediaType; bps=[long]$_.ReceiveLinkSpeed; speed=$_.LinkSpeed} })
$o.scheme = (powercfg /getactivescheme) -join ' '
$o | ConvertTo-Json -Compress -Depth 5
"""

# коды ошибок «Диспетчера устройств»: что значит и что делать
DEV = {
    1: ("устройство настроено неправильно", "Переустанови драйвер: «Диспетчер устройств» → устройство → «Удалить устройство» → перезагрузка.", "warn"),
    3: ("драйвер повреждён или не хватает памяти", "Переустанови драйвер с сайта производителя ноутбука.", "warn"),
    10: ("устройство не запускается", "Обычно помогает свежий драйвер с сайта производителя. Если это USB-устройство — подключи его в другой порт.", "warn"),
    12: ("конфликт ресурсов: два устройства претендуют на одно и то же", "Обнови BIOS и драйвер чипсета. На ПК — переставь плату расширения в другой слот.", "bad"),
    14: ("ждёт перезагрузки компьютера", "Перезагрузи компьютер.", "info"),
    18: ("драйвер нужно переустановить", "Переустанови драйвер с сайта производителя.", "warn"),
    19: ("запись в реестре повреждена", "Удали устройство в «Диспетчере устройств» и перезагрузись — Windows поставит его заново.", "warn"),
    21: ("Windows удаляет это устройство", "Перезагрузи компьютер.", "info"),
    22: ("устройство отключено вручную", "Если оно нужно — «Диспетчер устройств» → правой кнопкой → «Включить устройство».", "warn"),
    24: ("устройство не найдено или подключено не полностью", "Проверь подключение: кабель, разъём, переподключи устройство.", "warn"),
    28: ("драйвер не установлен", "Поставь драйвер: Windows Update → «Дополнительные обновления» или сайт производителя.", "warn"),
    31: ("Windows не может загрузить драйвер", "Поставь свежий драйвер с сайта производителя.", "warn"),
    32: ("драйвер отключён", "Включи устройство или переустанови драйвер.", "warn"),
    37: ("драйвер вернул ошибку при запуске", "Переустанови драйвер; если не помогает — откати на предыдущую версию.", "warn"),
    39: ("драйвер повреждён или отсутствует", "Переустанови драйвер с сайта производителя.", "warn"),
    41: ("драйвер загружен, но устройство не найдено", "Переподключи устройство; для внутренних устройств — обнови BIOS и драйвер чипсета.", "warn"),
    43: ("устройство сообщило о сбое и остановлено", "Для USB: другой кабель или порт, без разветвителя. Для видеокарты: свежий драйвер, проверь перегрев и питание.", "bad"),
    48: ("драйвер заблокирован как несовместимый", "Поставь новую версию драйвера с сайта производителя.", "warn"),
    52: ("подпись драйвера не прошла проверку", "Поставь драйвер с официального сайта; не используй «сборки драйверов».", "warn"),
}

# ---------------------------------------------------------------- быстрые сведения напрямую из Windows (без WMI)
import ctypes
import ctypes.wintypes as wt
import winreg

cfg = ctypes.WinDLL("cfgmgr32")
CR_SUCCESS = 0
DN_HAS_PROBLEM = 0x00000400
CM_GETIDLIST_FILTER_PRESENT = 0x00000100
CM_DRP_DEVICEDESC, CM_DRP_CLASS, CM_DRP_FRIENDLYNAME = 0x01, 0x08, 0x0D


def _prop(dn, prop):
    buf = ctypes.create_unicode_buffer(512)
    size = wt.ULONG(ctypes.sizeof(buf))
    typ = wt.ULONG()
    if cfg.CM_Get_DevNode_Registry_PropertyW(dn, prop, ctypes.byref(typ), buf, ctypes.byref(size), 0) == CR_SUCCESS:
        return buf.value
    return ""


class DEVPROPKEY(ctypes.Structure):
    _fields_ = [("fmtid", ctypes.c_byte * 16), ("pid", wt.ULONG)]


def _devpkey(guid, pid):
    import uuid
    k = DEVPROPKEY()
    ctypes.memmove(k.fmtid, uuid.UUID(guid).bytes_le, 16)
    k.pid = pid
    return k


# имя, которое сообщило само устройство: «Gaming Mouse» вместо «USB Input Device»
DEVPKEY_BUS_DESC = _devpkey("540b947e-8b40-45bc-a8a2-6a0b894cbda2", 4)


def _bus_name(dn):
    buf = ctypes.create_string_buffer(1024)
    size, typ = wt.ULONG(ctypes.sizeof(buf)), wt.ULONG()
    try:
        if cfg.CM_Get_DevNode_PropertyW(dn, ctypes.byref(DEVPKEY_BUS_DESC), ctypes.byref(typ), buf, ctypes.byref(size), 0) == CR_SUCCESS:
            return ctypes.wstring_at(buf).strip()
    except (OSError, AttributeError):
        pass
    return ""


def problem_devices():
    size = wt.ULONG()
    if cfg.CM_Get_Device_ID_List_SizeW(ctypes.byref(size), None, CM_GETIDLIST_FILTER_PRESENT) != CR_SUCCESS:
        return []
    buf = ctypes.create_unicode_buffer(size.value)
    if cfg.CM_Get_Device_ID_ListW(None, buf, size, CM_GETIDLIST_FILTER_PRESENT) != CR_SUCCESS:
        return []
    ids = [x for x in ctypes.wstring_at(buf, size.value).split("\0") if x]
    out = []
    for did in ids:
        dn = wt.DWORD()
        if cfg.CM_Locate_DevNodeW(ctypes.byref(dn), did, 0) != CR_SUCCESS:
            continue
        st, pr = wt.ULONG(), wt.ULONG()
        if cfg.CM_Get_DevNode_Status(ctypes.byref(st), ctypes.byref(pr), dn, 0) != CR_SUCCESS:
            continue
        if st.value & DN_HAS_PROBLEM and pr.value not in (0, 45):
            out.append({"name": _prop(dn, CM_DRP_FRIENDLYNAME) or _prop(dn, CM_DRP_DEVICEDESC), "cls": _prop(dn, CM_DRP_CLASS),
                        "code": pr.value, "id": did, "bus": _bus_name(dn)})
    return out


class DEVMODE(ctypes.Structure):
    _fields_ = [("dmDeviceName", wt.WCHAR * 32), ("dmSpecVersion", wt.WORD), ("dmDriverVersion", wt.WORD), ("dmSize", wt.WORD),
                ("dmDriverExtra", wt.WORD), ("dmFields", wt.DWORD), ("dmPositionX", wt.LONG), ("dmPositionY", wt.LONG),
                ("dmDisplayOrientation", wt.DWORD), ("dmDisplayFixedOutput", wt.DWORD), ("dmColor", ctypes.c_short),
                ("dmDuplex", ctypes.c_short), ("dmYResolution", ctypes.c_short), ("dmTTOption", ctypes.c_short),
                ("dmCollate", ctypes.c_short), ("dmFormName", wt.WCHAR * 32), ("dmLogPixels", wt.WORD), ("dmBitsPerPel", wt.DWORD),
                ("dmPelsWidth", wt.DWORD), ("dmPelsHeight", wt.DWORD), ("dmDisplayFlags", wt.DWORD), ("dmDisplayFrequency", wt.DWORD),
                ("dmICMMethod", wt.DWORD), ("dmICMIntent", wt.DWORD), ("dmMediaType", wt.DWORD), ("dmDitherType", wt.DWORD),
                ("dmReserved1", wt.DWORD), ("dmReserved2", wt.DWORD), ("dmPanningWidth", wt.DWORD), ("dmPanningHeight", wt.DWORD)]


class DISPLAY_DEVICE(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("DeviceName", wt.WCHAR * 32), ("DeviceString", wt.WCHAR * 128), ("StateFlags", wt.DWORD),
                ("DeviceID", wt.WCHAR * 128), ("DeviceKey", wt.WCHAR * 128)]


def displays():
    """Активные экраны: адаптер, текущее разрешение и частота, максимум частоты при том же разрешении."""
    u = ctypes.windll.user32
    out, i = [], 0
    while True:
        dd = DISPLAY_DEVICE(); dd.cb = ctypes.sizeof(dd)
        if not u.EnumDisplayDevicesW(None, i, ctypes.byref(dd), 0):
            break
        i += 1
        if not dd.StateFlags & 0x1:                                  # DISPLAY_DEVICE_ATTACHED_TO_DESKTOP
            continue
        cur = DEVMODE(); cur.dmSize = ctypes.sizeof(cur)
        if not u.EnumDisplaySettingsW(dd.DeviceName, -1, ctypes.byref(cur)):   # ENUM_CURRENT_SETTINGS
            continue
        best, k = cur.dmDisplayFrequency, 0
        while True:
            m = DEVMODE(); m.dmSize = ctypes.sizeof(m)
            if not u.EnumDisplaySettingsW(dd.DeviceName, k, ctypes.byref(m)):
                break
            k += 1
            if m.dmPelsWidth == cur.dmPelsWidth and m.dmPelsHeight == cur.dmPelsHeight:
                best = max(best, m.dmDisplayFrequency)
        out.append({"adapter": dd.DeviceString, "w": cur.dmPelsWidth, "h": cur.dmPelsHeight, "hz": cur.dmDisplayFrequency, "hz_max": best,
                    "primary": bool(dd.StateFlags & 0x4)})
    return out


def gpu_drivers():
    """Видеоадаптеры из реестра класса Display: название, версия и дата драйвера."""
    out = []
    base = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
    except OSError:
        return out
    for i in range(winreg.QueryInfoKey(k)[0]):
        sub = winreg.EnumKey(k, i)
        if not sub.isdigit():
            continue
        try:
            s = winreg.OpenKey(k, sub)
            get = lambda n: winreg.QueryValueEx(s, n)[0]
            desc = get("DriverDesc")
        except OSError:
            continue
        try:
            ver = get("DriverVersion")
        except OSError:
            ver = ""
        try:
            d = get("DriverDate")                                     # «12-19-2025»
            mm, dd_, yy = d.split("-")
            dt = f"{yy}-{mm.zfill(2)}-{dd_.zfill(2)}"
        except (OSError, ValueError):
            dt = ""
        if "basic" not in desc.lower() or len(out) == 0:
            out.append({"name": desc, "driver": ver, "driver_date": dt})
    return out


GBIT = re.compile(r"(?i)gigabit|\bgbe\b|2\.5g|5g?base|10g|i21\d|i22\d|rtl81(1|6)[18]|killer e\d|ethernet controller|aqtion")


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else r.stdout.decode("cp866", "replace")
    except (OSError, subprocess.SubprocessError):
        return ""


def _nvidia():
    exe = shutil.which("nvidia-smi")
    if not exe:
        return []
    out = _run([exe, "--query-gpu=name,pcie.link.gen.current,pcie.link.gen.max,pcie.link.width.current,pcie.link.width.max,"
                     "enforced.power.limit,power.max_limit,power.default_limit,temperature.gpu,driver_version",
                "--format=csv,noheader,nounits"])
    res = []
    for line in out.splitlines():
        p = [x.strip() for x in line.split(",")]
        if len(p) < 10:
            continue
        num = lambda x: float(x) if re.fullmatch(r"[\d.]+", x or "") else None
        res.append({"name": p[0], "gen": num(p[1]), "gen_max": num(p[2]), "width": num(p[3]), "width_max": num(p[4]),
                    "power": num(p[5]), "power_max": num(p[6]), "power_default": num(p[7]), "temp": num(p[8]), "driver": p[9]})
    return res


def _cpu_max():
    """«Максимальное состояние процессора» в текущей схеме питания: (от сети, от батареи) в процентах."""
    out = _run(["powercfg", "/query", "SCHEME_CURRENT", "SUB_PROCESSOR", "PROCTHROTTLEMAX"])
    vals = [int(x, 16) for x in re.findall(r":\s*0x([0-9a-fA-F]{8})\s*$", out, re.M)]
    return (vals[-2], vals[-1]) if len(vals) >= 2 else (None, None)


def _wifi():
    out = _run(["netsh", "wlan", "show", "interfaces"])
    m = re.search(r"(?im)^\s*(?:Signal|Сигнал)\s*:\s*(\d+)\s*%", out)
    if not m:
        return None
    rx = re.search(r"(?im)^\s*(?:Receive rate \(Mbps\)|Скорость приема \(Мбит/с\)|Скорость приёма \(Мбит/с\))\s*:\s*([\d.]+)", out)
    radio = re.search(r"(?im)^\s*(?:Radio type|Тип радио)\s*:\s*(\S+)", out)
    band = re.search(r"(?im)^\s*(?:Band|Диапазон)\s*:\s*(.+)$", out)
    return {"signal": int(m.group(1)), "rx": float(rx.group(1)) if rx else None, "radio": radio.group(1) if radio else "",
            "band": band.group(1).strip() if band else ""}


# Итог попытки обновить прошивку через Windows Update (капсула UEFI). Windows хранит код прошивки (ESRT LastAttemptStatus)
# в виде NTSTATUS: 1→C0000001, 2→C000009A, 3→C0000059, 4→C000007B, 5→C0000022, 6→C00002D3, 7→C00002DE.
FW_STATUS = {
    0xC00002DE: ("не хватило питания — прошивка не обновляется без зарядки",
                 "Подключи родную зарядку (заряд лучше выше 30%) и перезагрузи компьютер — именно «Перезагрузка», не выключение. "
                 "Обновление займёт несколько минут: не отключай зарядку, не закрывай крышку и не нажимай кнопку питания.", "warn"),
    0xC00002D3: ("не подключена зарядка — прошивка обновляется только от сети",
                 "Подключи зарядку и перезагрузи компьютер. Не отключай её и не выключай ноутбук, пока идёт обновление.", "warn"),
    0xC0000059: ("прошивка отказалась ставить эту версию — она старее текущей или не подходит к модели",
                 "Обычно ничего делать не нужно. Если надпись при загрузке мешает — поставь свежий BIOS с сайта производителя "
                 "(у Lenovo — Lenovo Vantage → «Обновления системы»).", "info"),
    0xC000007B: ("файл прошивки повреждён",
                 "Поставь обновление вручную с сайта производителя (у Lenovo — Lenovo Vantage → «Обновления системы»).", "warn"),
    0xC0000022: ("файл прошивки не прошёл проверку подписи",
                 "Не ставь прошивки из неизвестных источников. Скачай обновление с сайта производителя или через его утилиту.", "warn"),
    0xC000009A: ("прошивке не хватило ресурсов для установки",
                 "Перезагрузи компьютер с подключённой зарядкой. Если повторяется — поставь обновление вручную с сайта производителя.", "warn"),
    0xC0000001: ("установка прошивки не удалась",
                 "Перезагрузи компьютер с подключённой зарядкой. Если повторяется — поставь обновление вручную с сайта производителя.", "warn"),
}


def firmware_updates():
    """Обновления прошивок, которые Windows ставит при загрузке: что за устройство, какая версия и чем кончилась последняя попытка.
    Данные — HKLM\\SYSTEM\\CurrentControlSet\\Control\\FirmwareResources (читается без прав администратора)."""
    out = []
    base = r"SYSTEM\CurrentControlSet\Control\FirmwareResources"
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
    except OSError:
        return out
    i = 0
    while True:
        try:
            guid = winreg.EnumKey(root, i)
        except OSError:
            break
        i += 1
        vals = {}
        try:
            with winreg.OpenKey(root, guid) as k:
                for name in ("Version", "LastAttemptVersion", "LastAttemptStatus", "Filename"):
                    try:
                        vals[name] = winreg.QueryValueEx(k, name)[0]
                    except OSError:
                        pass
        except OSError:
            continue
        name = ""
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Enum\UEFI\RES_{guid}\0") as k:
                for v in ("FriendlyName", "DeviceDesc"):
                    try:
                        name = str(winreg.QueryValueEx(k, v)[0]).split(";")[-1]
                        break
                    except OSError:
                        pass
        except OSError:
            pass
        st = int(vals.get("LastAttemptStatus") or 0) & 0xFFFFFFFF
        fn = os.path.splitext(os.path.basename(str(vals.get("Filename") or "")))[0]
        ver = re.search(r"(\d+(?:\.\d+)+)\s*$", name)
        out.append({"guid": guid, "name": name or "Прошивка устройства", "status": st, "code": f"0x{st:08X}",
                    "target": fn if re.fullmatch(r"[A-Z0-9]{6,12}", fn or "") else (ver.group(1) if ver else ""),
                    "bios": bool(re.search(r"(?i)system firmware|bios", name))})
    return out


def _days(d):
    try:
        return (date.today() - date.fromisoformat(d[:10])).days
    except (TypeError, ValueError):
        return None


def check(metrics_snapshot=None, diag_cache=None):
    raw = system.ps(_PS, timeout=90) or {}
    gpus, disp, devs = gpu_drivers(), displays(), problem_devices()
    items = []

    def add(comp, lvl, title, text="", how="", page=None):
        items.append({"comp": comp, "lvl": lvl, "title": title, "text": text, "how": how, "page": page})

    # ---------------- оперативная память
    ram = raw.get("ram") or {}
    mods = [m for m in system.as_list(ram.get("modules")) if m.get("size")]
    if mods:
        total = sum(m["size"] for m in mods) / 2 ** 30
        speeds = {m.get("speed") for m in mods if m.get("speed")}
        cfgs = [m.get("cfg") for m in mods if m.get("cfg")]
        rated = max(speeds) if speeds else 0
        cur = min(cfgs) if cfgs else 0
        kind = {26: "DDR4", 34: "DDR5", 30: "LPDDR4", 35: "LPDDR5", 24: "DDR3"}.get(mods[0].get("type"), "")
        desc = f"{len(mods)} × {round(mods[0]['size'] / 2 ** 30)} ГБ {kind}".strip() if len({m['size'] for m in mods}) == 1 else \
            " + ".join(f"{round(m['size'] / 2 ** 30)} ГБ" for m in mods)
        if rated and cur and cur < rated * 0.92:
            add("Память", "warn", "Память работает медленнее, чем умеет",
                f"Планки рассчитаны на {rated} МТ/с, а работают на {cur} МТ/с.",
                "На ПК включи в BIOS профиль XMP (Intel) или EXPO/DOCP (AMD). На ноутбуках частоту обычно задаёт производитель — "
                "если планку меняли, поставь пару одинаковых на родной частоте.")
        channels = {re.sub(r"(?i).*channel\s*([A-Z]).*", r"\1", (m.get("bank") or "") + " " + (m.get("slot") or "")) for m in mods}
        if len(mods) == 1:
            add("Память", "warn", "Память работает в одноканальном режиме",
                f"Установлена одна планка ({desc}).",
                "Вторая такая же планка в свободный слот удвоит пропускную способность памяти: +10–30% в играх, особенно на встроенной графике."
                if (ram.get("slots") or 0) > 1 else "Свободных слотов нет — так задумано производителем.")
        elif len(channels) == 1 and len(mods) > 1 and all("channel" in ((m.get("bank") or "") + (m.get("slot") or "")).lower() for m in mods):
            add("Память", "warn", "Обе планки в одном канале",
                f"{desc}: все планки стоят в канале {next(iter(channels))}.",
                "Переставь планки в слоты разных каналов (обычно A2 и B2 — смотри инструкцию к плате), чтобы включился двухканальный режим.")
        if len({m["size"] for m in mods}) > 1 or len(speeds) > 1 or len({m.get("part") for m in mods}) > 1:
            add("Память", "info", "Планки памяти разные",
                f"{desc}; частоты: {', '.join(str(s) for s in sorted(speeds))} МТ/с.",
                "Разные планки работают на скорости самой медленной и иногда дают редкие сбои. Если бывают синие экраны — поставь одинаковую пару.")
        if total < 7.5:
            add("Память", "warn", "Мало оперативной памяти", f"Всего {total:.0f} ГБ.", "Для Windows 11 и браузера комфортно от 16 ГБ.")
        if not any(i["comp"] == "Память" and i["lvl"] in ("warn", "bad") for i in items):
            add("Память", "ok", f"Память: {desc}, {cur or rated} МТ/с" + (", двухканальный режим" if len(channels) > 1 else ""))

    # ---------------- видеокарта
    nv = _nvidia()
    for d in devs:
        if (d.get("cls") or "").lower() != "display":
            continue
        if d["code"] == 22:
            add("Видеокарта", "bad", "Видеокарта отключена", d["name"], "«Диспетчер устройств» → «Видеоадаптеры» → правой кнопкой → «Включить устройство».")
        else:
            add("Видеокарта", "bad", "Видеокарта работает с ошибкой", f"{d['name']}: код {d['code']} — {DEV.get(d['code'], ('ошибка',))[0]}.",
                "Поставь свежий драйвер с сайта производителя видеокарты или ноутбука. Если не помогает — проверь перегрев и питание.")
    for g in gpus:
        age = _days(g.get("driver_date"))
        if age is not None and age > 365 and re.search(r"(?i)nvidia|radeon|amd|intel\(r\) arc", g.get("name") or ""):
            add("Видеокарта", "info", "Драйвер видеокарты старше года", f"{g['name']}: драйвер от {g['driver_date']}.",
                "Свежий драйвер исправляет вылеты в играх: NVIDIA App / AMD Adrenalin или сайт производителя ноутбука.")
    for n in nv:
        if n.get("width") and n.get("width_max") and n["width"] < n["width_max"]:
            add("Видеокарта", "bad", "Видеокарта работает на неполной ширине шины PCIe",
                f"{n['name']}: x{n['width']:.0f} из x{n['width_max']:.0f}.",
                "На ПК: видеокарта не до конца вставлена или стоит не в том слоте (нужен верхний x16), загрязнён разъём. "
                "Выключи ПК, вынь и плотно вставь карту в верхний слот.")
        if n.get("gen_max") and n["gen_max"] < 3:
            add("Видеокарта", "warn", "Шина PCIe ограничена старым поколением",
                f"{n['name']}: максимум PCIe {n['gen_max']:.0f}.0.", "В BIOS переключи слот видеокарты в режим Auto / Gen4.")
        if n.get("power") and n.get("power_max") and n["power"] < n["power_max"] * 0.85:
            add("Видеокарта", "info", "Видеокарта получает не всю мощность",
                f"{n['name']}: сейчас лимит {n['power']:.0f} Вт из {n['power_max']:.0f} Вт возможных.",
                "Это режим питания ноутбука. Для игр включи режим «Производительность» (у Lenovo — Fn+Q или Lenovo Vantage / Legion Space) "
                "и играй от зарядки — тогда лимит поднимется.")
        if n.get("temp") and n["temp"] >= 87:
            add("Видеокарта", "warn", "Видеокарта горячая", f"{n['name']}: {n['temp']:.0f} °C.", "Почисти систему охлаждения, не ставь ноутбук на мягкое.")
        if not any(i["comp"] == "Видеокарта" and i["lvl"] in ("warn", "bad") for i in items):
            add("Видеокарта", "ok", f"{n['name']}: PCIe x{(n.get('width') or 0):.0f}, драйвер {n.get('driver')}")

    # ---------------- экран
    for g in disp:
        if g.get("hz") and g.get("hz_max") and g["hz"] < g["hz_max"] and g["hz_max"] >= 75:
            add("Экран", "warn", "Экран работает не на полной частоте",
                f"Сейчас {g['hz']} Гц, а экран умеет {g['hz_max']} Гц ({g['adapter']}).",
                "«Параметры» → «Дисплей» → «Расширенные параметры дисплея» → «Частота обновления» — выбери максимальную. "
                "Для внешнего монитора нужен кабель DisplayPort или HDMI 2.0+, старый HDMI-кабель ограничивает частоту.")
        elif g.get("hz") and g["hz"] >= 60:
            add("Экран", "ok", f"Экран: {g.get('w')}×{g.get('h')}, {g['hz']} Гц")
    if len(disp) > 1 and len(gpus) > 1 and any(re.search(r"(?i)nvidia|radeon rx", g.get("name") or "") for g in gpus):
        add("Экран", "info", "Подключён внешний монитор", "В ноутбуке две видеокарты.",
            "Для игр подключай монитор к разъёму, который идёт от дискретной видеокарты (обычно HDMI или USB-C с DisplayPort на задней панели), "
            "и проверь в «Панели управления NVIDIA», что игра запускается на ней.")

    # ---------------- питание
    b = raw.get("battery") or {}
    if b.get("online") and b.get("discharging") and (b.get("rate") or 0) > 0:
        add("Питание", "bad", "Батарея разряжается от зарядки",
            f"Зарядка подключена, но батарея тратит {b['rate'] / 1000:.0f} Вт.",
            "Зарядка слабее, чем нужно ноутбуку (часто — USB-C на 65 Вт вместо родной), или плохо вставлен штекер. "
            "Используй родной блок питания нужной мощности.")
    cpu_ac, cpu_dc = _cpu_max()
    if cpu_ac is not None and cpu_ac < 100:
        add("Питание", "warn", "Процессор ограничен в настройках питания",
            f"«Максимальное состояние процессора» от сети — {cpu_ac}%.",
            "«Панель управления» → «Электропитание» → «Изменить параметры схемы» → «Дополнительные» → «Управление питанием процессора» → 100%.")
    if re.search(r"(?i)power saver|экономия энергии", raw.get("scheme") or "") and b.get("online") is not False:
        add("Питание", "info", "Включена схема «Экономия энергии»", "Компьютер работает медленнее, чтобы беречь заряд.",
            "От сети выбери «Сбалансированная» или «Высокая производительность».")

    # ---------------- BIOS
    bios = raw.get("bios") or {}
    pending = any(d.get("code") == 14 and re.search(r"(?i)firmware|uefi|bios", d.get("name") or "") for d in devs)
    failed = [f for f in firmware_updates() if f["status"]]
    for f in failed:
        reason, fix, lvl = FW_STATUS.get(f["status"], (f"прошивка вернула код ошибки {f['code']}",
                                                        "Перезагрузи компьютер с подключённой зарядкой. Если ошибка повторяется — поставь обновление "
                                                        "вручную с сайта производителя.", "warn"))
        what = "BIOS" if f["bios"] else f["name"]
        target = f" {f['target']}" if f["target"] else ""
        now = f" (сейчас {bios.get('ver')})" if f["bios"] and bios.get("ver") else ""
        add("BIOS", lvl, f"Обновление {what} не устанавливается: {reason.split(' — ')[0]}",
            f"Windows пытается поставить {what}{target}{now} при каждом включении — отсюда надпись «Устройство обновляется» "
            f"на несколько секунд при загрузке. Последняя попытка не удалась: {reason} (код {f['code']}).", fix)
    if failed:
        pending = True                                     # подробная причина уже показана выше
    elif pending:
        add("BIOS", "warn", "Обновление BIOS ждёт перезагрузки",
            "Windows уже скачала новую прошивку, она установится при следующей перезагрузке.",
            "Подключи зарядку и перезагрузи компьютер. Не выключай его, пока идёт обновление (экран может быть чёрным пару минут).")
    age = _days(bios.get("date"))
    if age is not None and age > 540 and not pending:
        add("BIOS", "info", "BIOS давно не обновлялся", f"Версия {bios.get('ver')} от {bios.get('date')}.",
            "Новые версии BIOS исправляют перегрев, сон и совместимость. У Lenovo — через Lenovo Vantage → «Обновления системы».")

    # ---------------- накопители
    for d in system.as_list(raw.get("disks")):
        if d.get("health") and d["health"] != "Healthy":
            add("Диски", "bad", "Диск сообщает о проблеме", f"{d['name']}: {d['health']} ({d.get('op')}).",
                "Срочно сделай резервную копию важных файлов и замени диск.")
        else:
            add("Диски", "ok", f"{d['name']}: исправен ({d.get('bus')})")

    # ---------------- устройства (у одной мыши бывает несколько «интерфейсов» с одной ошибкой — показываем один раз)
    seen_dev = set()
    for d in devs:
        shown = system.device_name(d.get("name"), d.get("bus"))
        if (shown, d.get("code")) in seen_dev:
            continue
        seen_dev.add((shown, d.get("code")))
        if (d.get("cls") or "").lower() == "display":
            continue                                              # уже выше, в «Видеокарте»
        if d.get("code") == 14 and re.search(r"(?i)firmware|uefi|bios", d.get("name") or ""):
            continue                                              # уже выше, как обновление BIOS
        what, how, lvl = DEV.get(d.get("code"), (f"ошибка {d.get('code')}", "Переустанови драйвер или переподключи устройство.", "warn"))
        usb = "usb" in (d.get("id") or "").lower() or "usb" in (d.get("name") or "").lower()
        if usb and d.get("code") in (43, 10, 28):
            how = "Скорее всего, плохой контакт: подключи устройство в другой порт напрямую (без разветвителя), попробуй другой кабель."
        how = system.device_hint(d.get("cls"), d.get("code"), d.get("id")) or how
        add("Устройства", lvl, f"Устройство с ошибкой: {shown}", f"Код {d.get('code')}: {what}.", how, "health:drivers")

    # ---------------- сеть
    for a in system.as_list(raw.get("net")):
        mbps = (a.get("bps") or 0) / 1e6
        media = (a.get("media") or "").lower()
        if "802.3" in media or "ethernet" in (a.get("name") or "").lower() and "wi" not in media:
            if mbps and mbps <= 10:
                add("Сеть", "bad", "Кабель интернета работает на 10 Мбит/с", f"{a['name']}: {a.get('speed')}.",
                    "Почти всегда повреждён кабель или разъём. Замени патч-корд, проверь, что штекер защёлкнулся.")
            elif mbps and mbps <= 100 and GBIT.search(a.get("name") or ""):
                add("Сеть", "warn", "Сетевой кабель работает на 100 Мбит/с вместо 1 Гбит/с", f"{a['name']}: {a.get('speed')}.",
                    "Гигабиту нужны все 4 пары проводов: обычно виноват старый или пережатый кабель, плохой разъём или порт роутера на 100 Мбит/с. "
                    "Поменяй кабель (Cat 5e или Cat 6) и порт роутера.")
            elif mbps:
                add("Сеть", "ok", f"Сетевой кабель: {a.get('speed')}")
    wf = _wifi()
    if wf:
        if wf["signal"] < 45:
            add("Сеть", "warn", "Слабый сигнал Wi-Fi", f"Сигнал {wf['signal']}%" + (f", скорость {wf['rx']:.0f} Мбит/с" if wf.get("rx") else "") + ".",
                "Подойди ближе к роутеру или убери преграды; если роутер двухдиапазонный — 5 ГГц быстрее, 2,4 ГГц дальше.")
        else:
            add("Сеть", "ok", f"Wi-Fi: сигнал {wf['signal']}%" + (f", {wf['band']}" if wf.get("band") else "") + (f", {wf['rx']:.0f} Мбит/с" if wf.get("rx") else ""))

    # ---------------- температура (из текущих показаний ScanHub)
    m = metrics_snapshot or {}
    temp = (m.get("now") or {}).get("cpu_temp") or (m.get("sensors") or {}).get("cpu_temp")
    if isinstance(temp, (int, float)) and temp >= 92:
        add("Температура", "warn", "Процессор очень горячий", f"Сейчас {temp:.0f} °C.",
            "Почисти вентиляторы и решётки от пыли, ставь ноутбук на твёрдую поверхность. Если так и в простое — пора менять термопасту.")
    if ((m.get("gpu") or {}).get("throttle")):
        add("Температура", "warn", "Видеокарта сбрасывает частоты из-за перегрева", "Прямо сейчас видеокарта перегрета.",
            "Почисти охлаждение; в играх включи режим «Производительность» — вентиляторы будут крутиться быстрее.")

    # ---------------- аппаратные сбои (последний разбор журналов)
    dg = diag_cache or {}
    if dg:
        n_whea = len(system.as_list(dg.get("whea")))
        if n_whea:
            add("Сбои", "bad" if n_whea > 3 else "warn", "Аппаратные ошибки WHEA",
                f"За {dg.get('days', 30)} дн.: {n_whea}. Их пишет сам процессор, когда сталкивается с ошибкой железа.",
                "Отключи разгон (CPU, память, видеокарта), обнови BIOS, проверь память (mdsched.exe). Если повторяется — диагностика в сервисе.",
                "health:diag")
        gpu_resets = system.as_list(dg.get("gpu"))
        if len(gpu_resets) >= 3:
            add("Сбои", "warn", "Видеодрайвер часто перезапускается", f"За {dg.get('days', 30)} дн.: {len(gpu_resets)} сбросов.",
                "Обнови драйвер видеокарты начисто, убери разгон, проверь температуру видеокарты в играх.", "health:diag")
        if dg.get("throttle"):
            add("Сбои", "info", "Процессор сбрасывал частоты", f"Событий: {dg['throttle']}.",
                "Причина — перегрев или ограничение по питанию. Почисти охлаждение и проверь зарядку.", "health:diag")
        if len(system.as_list(dg.get("memtest"))):
            for t in system.as_list(dg.get("memtest"))[-1:]:
                if re.search(r"(?i)error|ошиб", t.get("text") or "") and not re.search(r"(?i)no errors|не обнаруж", t.get("text") or ""):
                    add("Память", "bad", "Проверка памяти нашла ошибки", (t.get("text") or "")[:160],
                        "Проверь планки по одной; неисправную замени.", "health:diag")

    order = {"bad": 0, "warn": 1, "info": 2, "ok": 3}
    items.sort(key=lambda i: order.get(i["lvl"], 9))
    return {"items": items, "collected": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "model": " ".join(x for x in ((raw.get("sys") or {}).get("maker"), (raw.get("sys") or {}).get("family")) if x)}
