"""Сбои и ошибки: почему вылетела программа, синие экраны, аппаратные ошибки, сбои драйверов и дисков,
что установлено неправильно. Источник — журналы Windows (читаются без прав администратора) и монитор стабильности.

ScanHub не «угадывает» по ощущениям: каждое объяснение опирается на код ошибки или модуль, на котором упала программа.
Точную причину знает только разработчик программы — здесь самая вероятная и что с ней делать.
"""
import json
import os
import re
import threading
import winreg
from collections import Counter
from datetime import date, datetime, timedelta

import system

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")

EVENTS_PS = r"""
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$since = (Get-Date).AddDays(-[int]$env:SH_DAYS)
if ($env:SH_SINCE) { $since = [datetime]::Parse($env:SH_SINCE) }
$specs = @(
 @{LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'; Id=1001},
 @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41},
 @{LogName='System'; ProviderName='EventLog'; Id=6008},
 @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; Level=1,2,3},
 @{LogName='System'; ProviderName='Display'; Id=4101},
 @{LogName='System'; ProviderName='nvlddmkm'; Level=1,2,3},
 @{LogName='System'; ProviderName='amdkmdag'; Level=1,2},
 @{LogName='System'; ProviderName='disk'; Level=1,2,3},
 @{LogName='System'; ProviderName='Ntfs'; Level=1,2,3},
 @{LogName='System'; ProviderName='stornvme','storahci','iaStorAC','iaStorVD','volmgr'; Level=1,2},
 @{LogName='System'; ProviderName='Service Control Manager'; Id=7000,7001,7009,7011,7023,7024,7026,7031,7034},
 @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-PnP'; Id=219},
 @{LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; Id=20},
 @{LogName='System'; ProviderName='Microsoft-Windows-Resource-Exhaustion-Detector'; Id=2004},
 @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Processor-Power'; Id=37},
 @{LogName='System'; ProviderName='Microsoft-Windows-MemoryDiagnostics-Results'},
 @{LogName='Application'; ProviderName='Application Error'; Id=1000},
 @{LogName='Application'; ProviderName='Application Hang'; Id=1002},
 @{LogName='Application'; ProviderName='Windows Error Reporting'; Id=1001},
 @{LogName='Application'; ProviderName='.NET Runtime'; Id=1026}
)
$out = foreach ($s in $specs) { $s.StartTime = $since; try { Get-WinEvent -FilterHashtable $s -MaxEvents 800 -ErrorAction Stop } catch {} }
@($out | ForEach-Object {
  $m = [string]$_.Message; if ($m.Length -gt 500) { $m = $m.Substring(0, 500) }
  [pscustomobject]@{prov=$_.ProviderName; id=$_.Id; lvl=[int]$_.Level; t=$_.TimeCreated.ToString('o');
    p=@($_.Properties | Select-Object -First 16 | ForEach-Object { [string]$_.Value }); m=($m -replace '\s+', ' ')} }) | ConvertTo-Json -Depth 4 -Compress
"""

STATE_PS = r"""
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$o = [ordered]@{}
$o.services = @(Get-CimInstance Win32_Service | Where-Object { $_.StartMode -ne 'Disabled' } | ForEach-Object { @{name=$_.Name; title=$_.DisplayName; path=[string]$_.PathName; mode=[string]$_.StartMode} })
$since = (Get-Date).AddDays(-[int]$env:SH_DAYS)
$o.stability = @(Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction SilentlyContinue | Where-Object { $_.TimeGenerated -ge $since } | ForEach-Object { @{t=$_.TimeGenerated.ToString('o'); v=[double]$_.SystemStabilityIndex} })
# записи монитора стабильности — из них Windows и считает индекс (успешные установки отсеиваем уже в Python)
$o.reliab = @(Get-CimInstance Win32_ReliabilityRecords -ErrorAction SilentlyContinue | Where-Object { $_.TimeGenerated -ge $since } | ForEach-Object {
  $m = [string]$_.Message; if ($m.Length -gt 400) { $m = $m.Substring(0, 400) }
  @{t=$_.TimeGenerated.ToString('o'); s=[string]$_.SourceName; id=[int]$_.EventIdentifier; p=[string]$_.ProductName; m=($m -replace '\s+', ' ')} })
$o | ConvertTo-Json -Depth 4 -Compress
"""

# ---------------------------------------------------------------- справочники

BUGCHECK = {
    0x0A: ("IRQL_NOT_LESS_OR_EQUAL", "драйвер обратился к памяти в неподходящий момент", "driver"),
    0x19: ("BAD_POOL_HEADER", "повреждена системная память — драйвер или ОЗУ", "driver"),
    0x1A: ("MEMORY_MANAGEMENT", "ошибка управления памятью — чаще всего неисправная или разогнанная ОЗУ, реже драйвер", "ram"),
    0x1E: ("KMODE_EXCEPTION_NOT_HANDLED", "драйвер выполнил недопустимую операцию", "driver"),
    0x3B: ("SYSTEM_SERVICE_EXCEPTION", "сбой в драйвере или системном компоненте — часто видеодрайвер или антивирус", "driver"),
    0x4E: ("PFN_LIST_CORRUPT", "повреждена таблица памяти — ОЗУ или драйвер", "ram"),
    0x50: ("PAGE_FAULT_IN_NONPAGED_AREA", "обращение к несуществующей памяти — драйвер, ОЗУ или диск", "driver"),
    0x77: ("KERNEL_STACK_INPAGE_ERROR", "не удалось прочитать данные с диска — проблема с диском или кабелем", "disk"),
    0x7A: ("KERNEL_DATA_INPAGE_ERROR", "не удалось прочитать данные с диска — проблема с диском или файлом подкачки", "disk"),
    0x7E: ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "сбой в драйвере", "driver"),
    0x7F: ("UNEXPECTED_KERNEL_MODE_TRAP", "аппаратная проблема: ОЗУ, перегрев или разгон", "hardware"),
    0x9F: ("DRIVER_POWER_STATE_FAILURE", "драйвер не справился со сном или пробуждением — часто Wi‑Fi, видео или USB", "driver"),
    0xBE: ("ATTEMPTED_WRITE_TO_READONLY_MEMORY", "драйвер попытался записать в защищённую память", "driver"),
    0xC2: ("BAD_POOL_CALLER", "драйвер неправильно работает с памятью", "driver"),
    0xD1: ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "сбой драйвера — очень часто сетевого (Wi‑Fi, LAN)", "driver"),
    0xEF: ("CRITICAL_PROCESS_DIED", "завершился важный процесс Windows — повреждение системных файлов или диск", "system"),
    0xF4: ("CRITICAL_OBJECT_TERMINATION", "завершился важный процесс — часто проблема с диском", "disk"),
    0xFC: ("ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY", "драйвер попытался выполнить данные как код", "driver"),
    0x101: ("CLOCK_WATCHDOG_TIMEOUT", "ядро процессора перестало отвечать — разгон, BIOS или перегрев", "hardware"),
    0x109: ("CRITICAL_STRUCTURE_CORRUPTION", "повреждены данные ядра — драйвер или ОЗУ", "ram"),
    0x116: ("VIDEO_TDR_FAILURE", "видеокарта зависла и не смогла перезапуститься — драйвер, перегрев или разгон видеокарты", "gpu"),
    0x119: ("VIDEO_SCHEDULER_INTERNAL_ERROR", "внутренняя ошибка видеодрайвера", "gpu"),
    0x124: ("WHEA_UNCORRECTABLE_ERROR", "аппаратная ошибка: процессор, ОЗУ, питание или разгон", "hardware"),
    0x12B: ("FAULTY_HARDWARE_CORRUPTED_PAGE", "неисправная ОЗУ", "ram"),
    0x133: ("DPC_WATCHDOG_VIOLATION", "драйвер слишком долго не отвечал — часто драйвер SSD или устаревшая прошивка", "driver"),
    0x139: ("KERNEL_SECURITY_CHECK_FAILURE", "драйвер повредил память ядра", "driver"),
    0x13A: ("KERNEL_MODE_HEAP_CORRUPTION", "драйвер повредил память", "driver"),
    0x144: ("BUGCODE_USB3_DRIVER", "сбой драйвера USB 3", "driver"),
    0x154: ("UNEXPECTED_STORE_EXCEPTION", "сбой при работе с памятью и диском — часто SSD", "disk"),
}
# события Service Control Manager: что значит каждое
SVC_IDS = {7000: "служба не смогла запуститься", 7001: "не запустилась, потому что не запустилась нужная ей другая служба",
           7009: "не ответила вовремя при запуске (30 секунд)", 7011: "не ответила вовремя на команду Windows",
           7023: "запустилась, но сразу завершилась с ошибкой", 7024: "завершилась с ошибкой самой службы",
           7026: "не загрузились драйверы, нужные при старте", 7031: "неожиданно завершилась (упала), Windows её перезапустила",
           7034: "неожиданно завершилась (упала)"}

# Application Hang 1002, параметр «тип зависания»
HANG_TYPES = {
    "unknown": "окно программы перестало отвечать: она долго что-то делала (считала, ждала диск или интернет) и не успевала "
               "обновлять окно, поэтому Windows или ты её закрыли",
    "quiesce": "приложение из Microsoft Store не успело «уснуть», когда его свернули или закрыли, и Windows закрыла его сама. "
               "Обычно безвредно и незаметно",
    "cross-process": "программа ждала ответа от другой программы (например, от антивируса, драйвера или своей службы) и не дождалась",
    "top level window is idle": "окно программы перестало обрабатывать нажатия и сообщения — программа зависла",
    "synchronous": "программа ждала завершения долгой операции и перестала отвечать",
}
# процессы ScanHub и его сканеров: во время проверки им по делу нужно много памяти
OWN_TOOLS = {"clamscan.exe", "atomscan.exe", "python.exe", "pythonw.exe", "hollows_hunter.exe", "hollows_hunter64.exe", "capa.exe",
             "chainsaw.exe", "hayabusa.exe", "trufflehog.exe", "yara.exe", "freshclam.exe", "sigcheck.exe", "sigcheck64.exe"}

LIVE = {0x117: "видеокарта перестала отвечать, Windows перезапустила драйвер (экран мигнул)",
        0x141: "видеокарта зависла и была перезапущена — драйвер, перегрев или разгон",
        0x193: "графическая подсистема Windows сохранила диагностический снимок, работа продолжилась. Обычно безвредно; "
               "часто бывает на ноутбуках с двумя видеокартами при переключении между ними",
        0x1A1: "окно или программа надолго заблокировали графическую подсистему",
        0x15E: "сетевой драйвер долго не отвечал", 0x15F: "устройство не дало компьютеру уснуть"}
EXC = {
    "c0000005": ("нарушение доступа к памяти", "программа обратилась к памяти, которая ей не принадлежит"),
    "c0000409": ("аварийное завершение", "программа сама экстренно закрылась, обнаружив внутреннюю ошибку (часто — защита от читов или повреждённые файлы)"),
    "c0000374": ("повреждение памяти (кучи)", "программа испортила свою память — ошибка в ней самой, в моде или в оверлее; если так падают разные программы — проверь ОЗУ"),
    "e0434352": ("необработанная ошибка .NET", "ошибка внутри программы на .NET"),
    "e06d7363": ("необработанная ошибка C++", "ошибка внутри программы"),
    "c000001d": ("недопустимая инструкция", "программа использует инструкции, которых нет у процессора, или файл повреждён"),
    "c00000fd": ("переполнение стека", "ошибка в программе (бесконечная рекурсия)"),
    "c0000135": ("не найдена библиотека DLL", "не хватает системной библиотеки — обычно Visual C++ или DirectX"),
    "c000007b": ("неподходящая библиотека", "подсунута 32-битная DLL вместо 64-битной или наоборот — переустанови Visual C++/DirectX и программу"),
    "c0000142": ("ошибка запуска библиотеки", "библиотека не смогла инициализироваться"),
    "c06d007e": ("не найден модуль", "не хватает DLL — переустанови программу и Visual C++"),
    "c06d007f": ("не найдена функция в DLL", "версия библиотеки не подходит программе"),
    "c0000417": ("неверный параметр", "программа передала неверные данные системной библиотеке"),
    "80000003": ("точка останова", "программа остановилась на отладочной проверке"),
    "40000015": ("аварийный выход (abort)", "программа сама прервала работу"),
    "c0000602": ("быстрое завершение", "программа сама экстренно закрылась"),
}
# модуль, на котором упала программа -> (что это, категория)
MODULES = [
    (r"^(nvwgf2umx?|nvoglv(32|64)|nvldumdx?|nvd3dumx?|nvcuda|nvlddmkm|nvwgf2um|nvapi64|nvumdshimx?)\.(dll|sys)$", "видеодрайвер NVIDIA", "gpu"),
    (r"^(atidxx(32|64)|atiumd(64|ag)|amdxc(32|64)|amdvlk(32|64)|atio6axx|atiumdag|amdenc|amdihk64)\.dll$", "видеодрайвер AMD", "gpu"),
    (r"^(igd10iumd(32|64)|igdumdim(32|64)|igxel\w+|ig\d+icd(32|64)|igd12umd64|igc64)\.dll$", "видеодрайвер Intel", "gpu"),
    (r"^(d3d11|d3d12|d3d12core|dxgi|d3d9|d3d10warp|vulkan-1|opengl32|dxcore)\.dll$", "графика DirectX/Vulkan", "graphics"),
    (r"^(discordhook(64)?|discord_overlay\w*)\.dll$", "оверлей Discord", "overlay"),
    (r"^gameoverlayrenderer(64)?\.dll$", "оверлей Steam", "overlay"),
    (r"^rtsshooks(64)?\.dll$", "RivaTuner / MSI Afterburner (счётчик FPS)", "overlay"),
    (r"^(nvspcap(64)?|nvcamera\w*|nvshadowplay\w*)\.dll$", "оверлей NVIDIA (запись, фильтры)", "overlay"),
    (r"^(graphics-hook(32|64)|obs-vulkan(32|64))\.dll$", "захват OBS", "overlay"),
    (r"^(eosovh-win(32|64)-shipping|igo(32|64)|uplay_overlay\w*|overlay64)\.dll$", "оверлей лаунчера (Epic, EA, Ubisoft)", "overlay"),
    (r"^(reshade(32|64)?|dinput8|enbseries|scripthookv|xinput1_3)\.dll$", "мод или перехватчик (ReShade, ENB, ScriptHook)", "mods"),
    (r"^(mbae(64)?|mbae-api)\.dll$", "защита от эксплойтов Malwarebytes", "av"),
    (r"^(aswhook|aswhooka|avghook\w*)\.dll$", "защита Avast/AVG", "av"),
    (r"^(sbiedll|bdhkm64|atcuf64|kasperskylab\w*|klhkum)\.dll$", "антивирус или песочница", "av"),
    (r"^(easyanticheat\w*|beclient\w*|vgk|faceit\w*)\.(dll|sys)$", "античит", "anticheat"),
    (r"^(vcruntime140(_1)?|msvcp140(_\w+)?|msvcr\d+|msvcp\d+|concrt140)\.dll$", "библиотека Visual C++", "runtime"),
    (r"^ucrtbase\.dll$", "библиотека C (программа сама вызвала аварийный выход)", "app"),
    (r"^(clr|coreclr|clrjit|mscorwks|kernelbase)\.dll$", "среда выполнения .NET / системная обработка исключений", "dotnet"),
    (r"^jvm\.dll$", "Java (Minecraft и его лаунчеры)", "java"),
    (r"^(unityplayer|gameassembly|mono-2\.0-bdwgc|mono)\.dll$", "движок Unity", "engine"),
    (r"^ntdll\.dll$", "ядро Windows для программ (ntdll)", "memory"),
    (r"^(libcef|chrome_elf|electron|msedge_elf|qt\dcore)\.dll$", "встроенный браузер или Qt внутри программы", "app"),
    (r"^(xaudio2_\d|audioses|mmdevapi|rtkapo\w*|nahimic\w*|sonicstudio\w*)\.dll$", "звук (аудиодрайвер или эффекты)", "audio"),
    (r"^(rpcrt4|combase|ole32)\.dll$", "системная связь между программами (RPC/COM)", "system"),
]
ADVICE = {
    "gpu": "Обнови драйвер видеокарты (если вылеты начались после обновления — откати на прошлую версию). Проверь температуру видеокарты под нагрузкой и отключи разгон, если он есть.",
    "graphics": "Падение в графике DirectX/Vulkan почти всегда из-за видеодрайвера, оверлея или разгона видеокарты: обнови драйвер, отключи оверлеи.",
    "overlay": "Отключи этот оверлей для программы или игры: оверлеи встраиваются в чужой процесс и часто роняют его.",
    "mods": "В папке программы лежит мод-перехватчик. Обнови или удали его и проверь целостность файлов игры.",
    "av": "В программу встраивается защита антивируса. Добавь программу в исключения этой защиты или временно её отключи и проверь.",
    "anticheat": "Сбой античита: перезапусти лаунчер, проверь целостность файлов игры, переустанови античит.",
    "runtime": "Переустанови Visual C++ 2015–2022 (x64 и x86) — кнопка в разделе «Компоненты для программ».",
    "dotnet": "Ошибка внутри программы (.NET или исключение C++). Обнови программу; подробности — в тексте события.",
    "java": "Сбой Java: обнови лаунчер и Java, не выделяй игре больше половины ОЗУ, обнови видеодрайвер, отключи моды по одному.",
    "engine": "Сбой в движке игры: проверь целостность файлов (Steam → Свойства → Установленные файлы → Проверить), обнови игру и видеодрайвер.",
    "memory": "Программа повредила свою память: обнови её, отключи моды и оверлеи. Если так падают разные программы — проверь ОЗУ (кнопка «Проверка памяти»).",
    "audio": "Сбой в звуке: обнови аудиодрайвер (Realtek) и отключи звуковые эффекты вроде Nahimic.",
    "system": "Падение внутри системной библиотеки обычно вызвано самой программой. Обнови её; если повторяется — проверь системные файлы (Здоровье ПК → галочка DISM + SFC).",
    "app": "Ошибка в самой программе. Обнови или переустанови её; для игр — проверь целостность файлов.",
}


def _hex(v):
    try:
        n = int(v, 0) if isinstance(v, str) else int(v)
        return f"{n & 0xFFFFFFFF:08x}"
    except (TypeError, ValueError):
        return (v or "").lower().removeprefix("0x")


def explain_module(module, app_name, module_path=""):
    m = (module or "").lower()
    if m and app_name and m == app_name.lower():
        return "сама программа", "app"
    for rx, what, cat in MODULES:
        if re.match(rx, m):
            # d3d11.dll или dxgi.dll из папки игры — это не система, а ReShade/ENB
            if cat == "graphics" and module_path and "\\windows\\" not in module_path.lower():
                return "мод-перехватчик в папке программы (ReShade/ENB) под видом " + module, "mods"
            return what, cat
    if module_path and "\\windows\\" not in module_path.lower() and module_path.lower().rsplit("\\", 1)[0] != "":
        return f"сторонний модуль {module}", "app"
    return module or "неизвестный модуль", "app"


def explain_crash(app, module, code, module_path=""):
    what, cat = explain_module(module, app, module_path)
    c = _hex(code)
    ename, edesc = EXC.get(c, (f"код 0x{c}", ""))
    if c in ("c0000135", "c000007b", "c06d007e", "c06d007f"):
        cat = "runtime"
    if c == "e0434352" and cat in ("dotnet", "app"):
        cat = "dotnet"
    cause = f"Упала на модуле {module} — {what}" if module else "Модуль сбоя неизвестен"
    return {"what": what, "cat": cat, "code": f"0x{c}", "code_name": ename, "code_desc": edesc, "cause": cause, "advice": ADVICE.get(cat, ADVICE["app"])}


# ---------------------------------------------------------------- сбор

def _events(days=None, since=None):
    env = {"SH_DAYS": str(days or 30)}
    if since:
        env["SH_SINCE"] = since
    return system.as_list(system.ps(EVENTS_PS, timeout=240, env=env))


def _bug(s):
    m = re.search(r"0x([0-9a-fA-F]+)", s or "")
    return int(m.group(1), 16) if m else None


def analyze(days=30):
    box = {}
    th = threading.Thread(target=lambda: box.update(st=system.ps(STATE_PS, timeout=180, env={"SH_DAYS": str(days)})), daemon=True)
    th.start()                                     # состояние и записи стабильности читаются параллельно с журналами
    ev = _events(days)
    th.join(200)
    st = box.get("st") or {}
    R = {"days": days, "collected": datetime.now().isoformat(timespec="seconds"), "bsod": [], "shutdowns": [], "whea": [], "gpu": [],
         "live": {}, "disk": [], "crashes": {}, "hangs": {}, "leaks": [], "services": {}, "drivers": {}, "updates": [], "lowmem": [],
         "throttle": 0, "memtest": [], "dotnet": [], "store_crash": {}}
    for e in ev:
        prov, eid, p, t, msg = e.get("prov"), e.get("id"), e.get("p") or [], e.get("t"), e.get("m") or ""
        g = lambda i: p[i] if len(p) > i else ""
        if prov == "Microsoft-Windows-WER-SystemErrorReporting":
            code = _bug(g(0))
            name, desc, cat = BUGCHECK.get(code, (f"0x{code:X}" if code is not None else "?", "причина не распознана", "driver"))
            R["bsod"].append({"t": t, "code": f"0x{code:X}" if code is not None else "", "name": name, "desc": desc, "cat": cat, "dump": g(1)})
        elif prov == "Microsoft-Windows-Kernel-Power" and eid == 41:
            bc = int(g(0) or 0) if str(g(0)).isdigit() else 0
            R["shutdowns"].append({"t": t, "bugcheck": bc, "button": g(5) not in ("", "0")})
        elif prov == "EventLog" and eid == 6008:
            R["shutdowns"].append({"t": t, "bugcheck": 0, "button": False, "dirty": True})
        elif prov == "Microsoft-Windows-WHEA-Logger":
            R["whea"].append({"t": t, "id": eid, "lvl": e.get("lvl"), "text": msg[:260]})
        elif prov in ("Display", "nvlddmkm", "amdkmdag"):
            R["gpu"].append({"t": t, "prov": prov, "id": eid, "text": msg[:200]})
        elif prov in ("disk", "Ntfs", "stornvme", "storahci", "iaStorAC", "iaStorVD", "volmgr"):
            R["disk"].append({"t": t, "prov": prov, "id": eid, "lvl": e.get("lvl"), "text": msg[:220]})
        elif prov == "Service Control Manager":
            name = g(1) if eid == 7009 else g(0)
            x = R["services"].setdefault(name, {"name": name, "count": 0, "last": t, "ids": Counter()})
            x["count"] += 1
            x["ids"][eid] += 1
            x["last"] = max(x["last"], t)
        elif prov == "Microsoft-Windows-Kernel-PnP":
            drv = g(4) or g(1)
            x = R["drivers"].setdefault(drv, {"name": drv, "device": g(1), "status": _hex(g(2)), "count": 0, "last": t, "lvl": e.get("lvl")})
            x["count"] += 1
            x["last"] = max(x["last"], t)
        elif prov == "Microsoft-Windows-WindowsUpdateClient":
            R["updates"].append({"t": t, "code": "0x" + _hex(g(0)), "title": g(1)})
        elif prov == "Microsoft-Windows-Resource-Exhaustion-Detector":
            R["lowmem"].append({"t": t, "text": msg[:300]})
        elif prov == "Microsoft-Windows-Kernel-Processor-Power":
            R["throttle"] += 1
        elif prov == "Microsoft-Windows-MemoryDiagnostics-Results":
            R["memtest"].append({"t": t, "id": eid, "text": msg[:200]})
        elif prov == "Application Error":
            app = g(0)
            info = explain_crash(app, g(3), g(6), g(11))
            x = R["crashes"].setdefault(app.lower(), {"app": app, "path": g(10), "count": 0, "last": t, "items": [], "modules": Counter(), "cats": Counter()})
            x["count"] += 1
            x["last"] = max(x["last"], t)
            x["modules"][g(3)] += 1
            x["cats"][info["cat"]] += 1
            if len(x["items"]) < 6:
                x["items"].append({"t": t, "version": g(1), "module": g(3), "module_path": g(11), **info})
        elif prov == "Application Hang":
            app = g(0)
            x = R["hangs"].setdefault(app.lower(), {"app": app, "path": g(5), "count": 0, "last": t, "items": []})
            x["count"] += 1
            x["last"] = max(x["last"], t)
            if len(x["items"]) < 6:
                ms = int(g(4)) if str(g(4)).isdigit() and int(g(4)) < 0xFFFFFFFF else None
                kind = g(9) or "Unknown"
                x["items"].append({"t": t, "version": g(1), "seconds": round(ms / 1000) if ms else None, "type": kind,
                                   "why": HANG_TYPES.get(kind.lower(), HANG_TYPES["unknown"])})
        elif prov == ".NET Runtime":
            R["dotnet"].append({"t": t, "text": msg[:400]})
        elif prov == "Windows Error Reporting":
            kind = g(2)
            if kind == "LiveKernelEvent":
                try:
                    code = int(g(5), 16)
                except ValueError:
                    code = None
                x = R["live"].setdefault(code, {"code": f"0x{code:X}" if code is not None else "?", "desc": LIVE.get(code, "диагностический снимок ядра Windows"),
                                                "count": 0, "last": t, "serious": code in (0x117, 0x141)})
                x["count"] += 1
                x["last"] = max(x["last"], t)
            elif kind.startswith("RADAR_PRE_LEAK"):
                R["leaks"].append({"t": t, "app": g(5), "version": g(6)})
            elif kind in ("MoAppCrash", "MoBEX"):
                pkg = g(5).split("_")[0]
                x = R["store_crash"].setdefault(pkg, {"app": pkg, "count": 0, "last": t})
                x["count"] += 1
                x["last"] = max(x["last"], t)
            elif kind in ("MoAppHang", "AppHangB1"):
                app = g(5).split("_")[0]
                x = R["hangs"].setdefault(app.lower(), {"app": app, "path": "", "count": 0, "last": t, "items": []})
                x["count"] += 1
                x["last"] = max(x["last"], t)
    # вылеты: главная причина по самой частой категории модуля
    crashes = []
    for x in R["crashes"].values():
        top_mod = x["modules"].most_common(1)[0][0] if x["modules"] else ""
        top_cat = x["cats"].most_common(1)[0][0] if x["cats"] else "app"
        main = next((i for i in x["items"] if i["module"] == top_mod), x["items"][0] if x["items"] else {})
        crashes.append({"app": x["app"], "path": x["path"], "count": x["count"], "last": x["last"], "module": top_mod, "cat": top_cat,
                        "what": main.get("what", ""), "code": main.get("code", ""), "code_name": main.get("code_name", ""),
                        "code_desc": main.get("code_desc", ""), "advice": ADVICE.get(top_cat, ADVICE["app"]),
                        "modules": [f"{m} ×{n}" for m, n in x["modules"].most_common(4)], "items": x["items"]})
    crashes.sort(key=lambda c: c["last"], reverse=True)
    R["crashes"] = crashes
    R["hangs"] = sorted(R["hangs"].values(), key=lambda h: h["last"], reverse=True)
    for h in R["hangs"]:                   # главное объяснение — по самому частому типу зависания
        kinds = Counter(i["type"].lower() for i in h.get("items", []))
        h["type"] = kinds.most_common(1)[0][0] if kinds else "unknown"
        h["why"] = HANG_TYPES.get(h["type"], HANG_TYPES["unknown"])
        h["benign"] = h["type"] == "quiesce"
        secs = [i["seconds"] for i in h.get("items", []) if i.get("seconds")]
        h["seconds"] = max(secs) if secs else None
    # утечки: по программам, сколько раз и когда последний; свои сканеры ScanHub отмечаем — им память нужна по делу
    lk = {}
    for l in R["leaks"]:
        x = lk.setdefault(l["app"].lower(), {"app": l["app"], "count": 0, "last": l["t"], "version": l.get("version", "")})
        x["count"] += 1
        x["last"] = max(x["last"], l["t"])
    for x in lk.values():
        x["scanhub"] = x["app"].lower() in OWN_TOOLS
    R["leaks"] = sorted(lk.values(), key=lambda x: x["last"], reverse=True)
    R["store_crash"] = sorted(R["store_crash"].values(), key=lambda h: h["last"], reverse=True)
    R["live"] = sorted(R["live"].values(), key=lambda h: -h["count"])
    for x in R["services"].values():
        x["ids"] = dict(x["ids"])
        x["why"] = ("завершалась аварийно" if x["ids"].get(7031) or x["ids"].get(7034) else
                    "не запустилась вовремя" if x["ids"].get(7009) or x["ids"].get(7011) else "не смогла запуститься")
        crashed = x["ids"].get(7031, 0) + x["ids"].get(7034, 0)
        x["events"] = [{"id": int(i), "count": n, "what": SVC_IDS.get(int(i), "ошибка службы")} for i, n in x["ids"].items()]
        x["sev"] = (["warn", "Стоит посмотреть: служба падает снова и снова — программа, которой она принадлежит, работает с ошибками"]
                    if crashed >= 3 else
                    ["info", "Скорее всего, не опасно: служба один-два раза упала, Windows её перезапустила"] if crashed else
                    ["info", "Не опасно: такое бывает при загрузке, когда служба не успевает стартовать или ждёт сеть. "
                             "Повод разбираться — только если перестало работать то, за что она отвечает"])
    R["services"] = sorted(R["services"].values(), key=lambda s: -s["count"])
    R["drivers"] = sorted(R["drivers"].values(), key=lambda d: -d["count"])
    for d in R["drivers"]:
        d["benign"] = d["name"].lower().endswith("wudfrd")       # WUDFRd: частое безвредное предупреждение
    # что-то установлено неправильно
    R["devices"] = [{**d, "why": DEV_CODES.get(d.get("code"), f"ошибка {d.get('code')}"), "name": system.device_name(d.get("name"), d.get("bus")),
                     "hint": system.device_hint(d.get("cls"), d.get("code"), d.get("id"))} for d in _devices()]
    broken_svc = []
    for s in system.as_list(st.get("services")):
        exe = system.exe_from_command(s.get("path") or "")
        if exe and os.path.isabs(exe) and not os.path.exists(exe) and not exe.lower().endswith("svchost.exe"):
            broken_svc.append({"name": s["name"], "title": s.get("title"), "exe": exe, "mode": s.get("mode")})
    R["broken_services"] = broken_svc
    R["stability"] = _stability(system.as_list(st.get("stability")))
    R["reliability"] = _reliability(system.as_list(st.get("reliab")))
    R["runtimes"] = runtimes()
    R["summary"] = _summary(R)
    return R


DEV_CODES = {1: "неправильно настроено", 3: "драйвер повреждён", 10: "не запускается", 12: "КОНФЛИКТ РЕСУРСОВ с другим устройством",
             14: "нужна перезагрузка", 18: "нужно переустановить драйвер", 19: "ошибка в реестре", 22: "отключено вручную",
             24: "не подключено или нет драйвера", 28: "драйвер не установлен", 31: "работает неправильно", 32: "служба драйвера отключена",
             39: "драйвер повреждён или отсутствует", 43: "Windows остановила устройство из-за сбоя", 45: "не подключено", 52: "драйвер без подписи"}


def _stability(rows):
    by_day = {}
    for r in rows:
        d = (r.get("t") or "")[:10]
        if d:
            by_day[d] = min(by_day.get(d, 10), r.get("v") or 10)
    return [{"d": d, "v": round(v, 1)} for d, v in sorted(by_day.items())][-60:]


def _devices():
    """Устройства с ошибками — напрямую из Windows (cfgmgr32): WMI на некоторых ПК отвечает по 20 с."""
    try:
        import hwcheck
        return hwcheck.problem_devices()
    except Exception:
        return []


def _rel_status(m):
    """Код завершения установки из сообщения MsiInstaller (на английской и русской Windows)."""
    x = re.findall(r"(?:status|состояни[ея][^:]{0,60}):\s*(\d+)", m or "", re.I)
    return int(x[-1]) if x else None


def _reliability(rows):
    """Сбои из монитора стабильности — то, что снижает индекс. Успешные установки индекс не снижают — их только считаем."""
    out, ok = [], 0
    for r in rows:
        src, eid, prod, msg = r.get("s") or "", r.get("id"), (r.get("p") or "").strip(), r.get("m") or ""
        t = r.get("t") or ""
        name, cat = prod, None
        if src == "Microsoft-Windows-WindowsUpdateClient":
            if eid == 20:
                cat = "update"
                if not name:
                    mm = re.search(r":\s*([^:]+?)\.?\s*$", msg)
                    name = mm.group(1) if mm else "обновление Windows"
                if re.match(r"[0-9A-Z]{12}-", name):          # приложение Store: «9NKSQGP7F2NH-5319275A.WhatsAppDesktop»
                    name = re.sub(r"^[0-9A-Z]{12}-", "", name).split(".")[-1] + " (Microsoft Store)"
            else:
                ok += 1
        elif src == "MsiInstaller":
            code = _rel_status(msg)
            if eid in (1033, 1034, 1035, 1036) and code not in (None, 0, 3010):
                cat = "install"
            else:
                ok += 1
        elif src == "Application Error" or (src == "Windows Error Reporting" and re.search(r"APPCRASH|BEX|CLR20", msg)):
            cat = "crash"
        elif src == "Application Hang" or (src == "Windows Error Reporting" and "AppHang" in msg):
            cat = "hang"
        elif src in ("EventLog",) and eid == 6008 or src == "Microsoft-Windows-Kernel-Power" and eid == 41:
            cat, name = "shutdown", name or "Windows"
        elif "BugCheck" in src or "SystemErrorReporting" in src or re.search(r"BlueScreen|LiveKernelEvent", msg):
            cat, name = "windows", name or "Windows"
        elif src == "Windows Error Reporting":
            continue                                   # повтор вылета/зависания, уже посчитан выше
        else:
            cat = "other"
        if cat:
            if cat in ("crash", "hang") and not name:
                mm = re.search(r"(?:application|приложени[ея])[^:]*:\s*([\w .\-]+\.exe)", msg, re.I)
                name = mm.group(1) if mm else "программа"
            out.append({"t": t, "d": t[:10], "cat": cat, "name": (name or src)[:120], "src": src, "id": eid,
                        "code": (re.search(r"0x[0-9a-fA-F]{8}", msg) or [""])[0]})
    out.sort(key=lambda x: x["t"], reverse=True)
    return {"events": out[:600], "ok": ok}


def _summary(R):
    S = []
    add = lambda lvl, text: S.append({"lvl": lvl, "text": text})
    if R["bsod"]:
        add("bad", f"Синих экранов: {len(R['bsod'])}")
    hard = [s for s in R["shutdowns"] if not s.get("bugcheck")]
    if hard:
        add("warn", f"Внезапных выключений: {len(hard)}")
    if R["whea"]:
        add("bad" if any(w["lvl"] in (1, 2) for w in R["whea"]) else "warn", f"Аппаратных ошибок: {len(R['whea'])}")
    # разовый старый сбой — норма, делать с ним нечего: «warn» (в «Что стоит сделать») только если повторяется или был недавно
    serious_live = sum(x["count"] for x in R["live"] if x["serious"])
    n_gpu = len(R["gpu"]) + serious_live
    recent = lambda items, days: any((x.get("t") or x.get("last") or "")[:10] >= (date.today() - timedelta(days=days)).isoformat() for x in items)
    if n_gpu:
        if n_gpu >= 2 or recent(R["gpu"] + [x for x in R["live"] if x["serious"]], 7):
            add("warn", f"Сбоев видеодрайвера: {n_gpu}")
        else:
            add("info", f"Был единичный сбой видеодрайвера — давно и больше не повторялся")
    if R["disk"]:
        add("bad" if any(d["lvl"] in (1, 2) for d in R["disk"]) else "warn", f"Ошибок диска: {len(R['disk'])}")
    if R["crashes"]:
        n = sum(c["count"] for c in R["crashes"])
        if any(c["count"] >= 2 for c in R["crashes"]) or recent(R["crashes"], 3):
            add("warn", f"Вылетов программ: {n}")
        else:
            add("info", f"Разовых вылетов программ: {n} — каждая упала по одному разу, это бывает")
    if R["hangs"]:
        add("info", f"Зависаний программ: {sum(h['count'] for h in R['hangs'])}")
    bad_dev = [d for d in R["devices"] if d.get("code") not in (22, 14)]      # 22 — отключено вручную, 14 — ждёт перезагрузки
    if bad_dev:
        add("warn", f"Устройств с ошибками: {len(bad_dev)}")
    if R["broken_services"]:
        add("info", f"Служб от удалённых программ: {len(R['broken_services'])}")
    if R["updates"]:
        add("info", f"Неудачных установок обновлений: {len(R['updates'])}")
    missing = [r for r in R["runtimes"] if not r["ok"] and r.get("need")]
    if missing:
        add("warn", f"Не хватает компонентов: {len(missing)}")
    return S


# ---------------------------------------------------------------- компоненты для программ и игр

def _reg(root, path, name, view=0):
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def runtimes():
    HKLM = winreg.HKEY_LOCAL_MACHINE
    win = os.environ.get("SystemRoot", r"C:\Windows")
    vc64 = _reg(HKLM, r"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64", "Installed", winreg.KEY_WOW64_64KEY)
    vc86 = _reg(HKLM, r"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x86", "Installed", winreg.KEY_WOW64_32KEY)
    v64 = _reg(HKLM, r"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64", "Version", winreg.KEY_WOW64_64KEY)
    net35 = _reg(HKLM, r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5", "Install")
    net4 = _reg(HKLM, r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full", "Release") or 0
    wv2 = _reg(HKLM, r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", "pv", winreg.KEY_WOW64_32KEY) or \
        _reg(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", "pv")
    dx9 = os.path.exists(os.path.join(win, r"System32\d3dx9_43.dll")) and os.path.exists(os.path.join(win, r"SysWOW64\d3dx9_43.dll"))
    names = " | ".join(p["name"] for p in __import__("uninstall").programs()).lower()
    old_vc = {y: (f"visual c++ {y}" in names) for y in ("2005", "2008", "2010", "2012", "2013")}
    dotnet_desktop = sorted(os.listdir(r"C:\Program Files\dotnet\shared\Microsoft.WindowsDesktop.App")) if os.path.isdir(r"C:\Program Files\dotnet\shared\Microsoft.WindowsDesktop.App") else []
    R = [
        {"id": "vc64", "name": "Visual C++ 2015–2022 (64-бит)", "ok": vc64 == 1, "ver": (v64 or "").lstrip("v"), "need": True, "winget": "Microsoft.VCRedist.2015+.x64",
         "desc": "Без неё не запускается большинство современных программ и игр («отсутствует VCRUNTIME140.dll»)."},
        {"id": "vc86", "name": "Visual C++ 2015–2022 (32-бит)", "ok": vc86 == 1, "need": True, "winget": "Microsoft.VCRedist.2015+.x86",
         "desc": "Нужна 32-битным программам и многим лаунчерам — ставят обе версии."},
        {"id": "dx9", "name": "DirectX 9 (старые библиотеки d3dx9)", "ok": dx9, "need": True, "winget": "Microsoft.DirectX",
         "desc": "Старым играм (до ~2015 года) нужны библиотеки DirectX 9, которых нет в Windows 10/11 по умолчанию («d3dx9_43.dll не найден»)."},
        {"id": "net35", "name": ".NET Framework 3.5", "ok": net35 == 1, "need": False, "launch": "optionalfeatures",
         "desc": "Нужен старым программам и играм. Включается в «Компонентах Windows»."},
        {"id": "net48", "name": ".NET Framework 4.8", "ok": net4 >= 528040, "need": True, "ver": str(net4),
         "desc": "Встроен в Windows 10/11; если его нет — Windows сильно устарела."},
        {"id": "webview2", "name": "Microsoft Edge WebView2", "ok": bool(wv2), "ver": wv2 or "", "need": True, "winget": "Microsoft.EdgeWebView2Runtime",
         "desc": "Встроенный браузер, на котором работают Teams, новый Outlook, виджеты и многие программы."},
        {"id": "oldvc", "name": "Старые Visual C++ 2005–2013", "ok": all(old_vc.values()), "need": False,
         "ver": ", ".join(y for y, v in old_vc.items() if v) or "нет", "winget": "Microsoft.VCRedist.2013.x64",
         "desc": "Нужны только старым играм и программам. Установлены: " + (", ".join(y for y, v in old_vc.items() if v) or "ни одной") + "."},
        {"id": "dotnet", "name": ".NET Desktop Runtime (новый .NET)", "ok": bool(dotnet_desktop), "need": False, "ver": ", ".join(dotnet_desktop[-3:]),
         "winget": "Microsoft.DotNet.DesktopRuntime.8", "desc": "Нужен программам на современном .NET; без него они при запуске просят его скачать."},
    ]
    return R


# ---------------------------------------------------------------- новые сбои (для предупреждений)

def new_events_since(iso):
    """Сбои с момента iso — коротко, для уведомлений. Только важное: вылеты, синие экраны, железо, диск, видеодрайвер."""
    out = []
    for e in _events(since=iso):
        prov, eid, p, t = e.get("prov"), e.get("id"), e.get("p") or [], e.get("t")
        g = lambda i: p[i] if len(p) > i else ""
        if t <= iso:
            continue
        if prov == "Application Error":
            info = explain_crash(g(0), g(3), g(6), g(11))
            out.append({"t": t, "kind": "crash", "title": f"{g(0)} аварийно завершилась", "text": f"{info['cause']}. {info['advice']}"})
        elif prov == "Microsoft-Windows-WER-SystemErrorReporting":
            code = _bug(g(0))
            name, desc, _ = BUGCHECK.get(code, ("?", "причина не распознана", ""))
            out.append({"t": t, "kind": "bsod", "title": f"Был синий экран: {name}", "text": desc})
        elif prov == "Microsoft-Windows-WHEA-Logger":
            out.append({"t": t, "kind": "whea", "title": "Аппаратная ошибка (WHEA)", "text": (e.get("m") or "")[:160]})
        elif prov in ("Display", "nvlddmkm"):
            out.append({"t": t, "kind": "gpu", "title": "Видеодрайвер перестал отвечать и был перезапущен", "text": "Если повторяется — обнови драйвер и проверь температуру."})
        elif prov in ("disk", "Ntfs", "stornvme") and e.get("lvl") in (1, 2):
            out.append({"t": t, "kind": "disk", "title": "Ошибка диска", "text": (e.get("m") or "")[:160]})
        elif prov == "Microsoft-Windows-Kernel-Power" and eid == 41:
            out.append({"t": t, "kind": "power", "title": "Компьютер был выключен некорректно", "text": "Питание пропало, компьютер завис или его выключили кнопкой."})
    return out
