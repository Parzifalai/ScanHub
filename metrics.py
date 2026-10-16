"""Ресурсы ПК для ScanHub: история загрузки и детектор процессов, похожих на скрытые майнеры.

Сбор идёт только пока окно ScanHub открыто и спрашивает метрики (после 30 с тишины — пауза).
"""
import json
import os
import platform
import subprocess
import threading
import time
from collections import deque

import psutil

NO_WINDOW = 0x08000000
ENGINES = {"3d": "3D, игры и графика", "videoencode": "кодирование видео", "videodecode": "декодирование видео",
           "compute": "вычисления: CUDA, ИИ, майнинг", "compute_0": "вычисления: CUDA, ИИ, майнинг",
           "compute_1": "вычисления: CUDA, ИИ, майнинг", "copy": "копирование данных", "cuda": "вычисления: CUDA, ИИ, майнинг",
           "graphics_1": "3D, игры и графика", "graphics": "3D, игры и графика", "videoprocessing": "обработка видео", "security": "защищённое видео"}
HISTORY = 300            # точек = секунд истории (5 минут)
STEP = 1.0

# известные майнеры (по имени процесса)
MINER_NAMES = {"xmrig", "xmr-stak", "nicehashminer", "excavator", "t-rex", "lolminer", "nbminer", "phoenixminer",
               "gminer", "miner", "ethminer", "cpuminer", "minerd", "ccminer", "teamredminer", "nanominer",
               "srbminer-multi", "bzminer", "rigel", "onezerominer", "wildrig", "xmrigdaemon", "cgminer", "bfgminer"}
# системные имена, под которые маскируется вредонос: настоящие живут только в Windows
SYSTEM_NAMES = {"svchost.exe", "explorer.exe", "csrss.exe", "conhost.exe", "dllhost.exe", "rundll32.exe",
                "lsass.exe", "services.exe", "winlogon.exe", "smss.exe", "wininit.exe", "taskhostw.exe",
                "spoolsv.exe", "audiodg.exe", "sihost.exe", "wmiprvse.exe", "searchindexer.exe", "runtimebroker.exe"}
WINDIR = os.environ.get("SystemRoot", r"C:\Windows").lower()
SELF_DIR = os.path.dirname(os.path.abspath(__file__)).lower()

_UPD = ("Windows Update устанавливает обновления", "Закончится само. Не выключай компьютер — посмотреть прогресс можно в Windows Update.")
_DEF = ("Microsoft Defender проверяет компьютер", "Плановая проверка, обычно 5–20 минут. Если повторяется часто — добавь в исключения папки с играми и проектами.")
_IDX = ("Windows индексирует файлы для поиска", "Обычно после копирования большого числа файлов. Закончится само.")
_BRW = ("браузер", "Много вкладок, видео или тяжёлые сайты. Закрой лишние вкладки — Shift+Esc покажет, какая грузит.")
KNOWN_LOAD = {
    "tiworker.exe": _UPD, "trustedinstaller.exe": _UPD, "mousocoreworker.exe": _UPD, "usoclient.exe": _UPD,
    "wuauclt.exe": _UPD, "musnotificationux.exe": _UPD, "setuphost.exe": ("Windows готовит крупное обновление", _UPD[1]),
    "msmpeng.exe": _DEF, "mpdefendercoreservice.exe": _DEF, "nissrv.exe": _DEF, "mpcmdrun.exe": _DEF,
    "searchindexer.exe": _IDX, "searchprotocolhost.exe": _IDX, "searchfilterhost.exe": _IDX,
    "compattelrunner.exe": ("Windows собирает данные совместимости (телеметрия)", "Фоновая задача, обычно 5–15 минут."),
    "devicecensus.exe": ("Windows собирает сведения об устройстве", "Короткая фоновая задача."),
    "sdiagnhost.exe": ("Средство диагностики Windows", "Закончится само."),
    "msiexec.exe": ("Идёт установка или удаление программы", "Дождись окончания."),
    "memory compression": ("Windows сжимает память — оперативки не хватает", "Закрой лишние программы и вкладки."),
    "system": ("Ядро Windows: драйверы, диск, сеть", "Если долго держится высокая нагрузка — проверь драйверы во вкладке «Драйверы»."),
    "mbamservice.exe": ("Malwarebytes проверяет компьютер", "Это твой постоянный антивирус Malwarebytes — он работает в фоне."),
    "onedrive.exe": ("OneDrive синхронизирует файлы", "Закончится, когда файлы загрузятся."),
    "steam.exe": ("Steam (обновление игр)", "Можно поставить загрузки на паузу в Steam."),
    "steamwebhelper.exe": ("Steam (интерфейс)", "Закрой Steam, если он не нужен."),
    "steamservice.exe": ("Steam обновляет игры", "Можно поставить загрузки на паузу в Steam."),
    "epicgameslauncher.exe": ("Epic Games Launcher", "Закрой лаунчер, если он не нужен."),
    "wallpaper64.exe": ("Wallpaper Engine — живые обои", "Включи в Wallpaper Engine паузу при работе от батареи и при развёрнутых окнах, или поставь статичные обои."),
    "wallpaper32.exe": ("Wallpaper Engine — живые обои", "Включи паузу в настройках Wallpaper Engine."),
    "chrome.exe": ("Google Chrome — " + _BRW[0], _BRW[1]), "msedge.exe": ("Microsoft Edge — " + _BRW[0], _BRW[1]),
    "firefox.exe": ("Firefox — " + _BRW[0], _BRW[1]), "browser.exe": ("Яндекс Браузер", _BRW[1]), "opera.exe": ("Opera", _BRW[1]),
    "discord.exe": ("Discord", "Отключи в Discord аппаратное ускорение или закрой, если не нужен."),
    "telegram.exe": ("Telegram", "Обычно не грузит; если грузит — обнови Telegram."),
    "ollama.exe": ("Ollama — локальная нейросеть", "Пока модель загружена, она держит видеокарту и память. Останови модель, если не нужна."),
    "ollama_llama_server.exe": ("Ollama — модель отвечает на запрос", "Шум пропадёт после окончания генерации."),
    "vmmem": ("WSL или Docker", "Виртуальная машина в фоне. Останови Docker/WSL, если не нужны: wsl --shutdown."),
    "vmmemwsl": ("WSL", "Останови командой wsl --shutdown, если не нужен."),
    "com.docker.backend.exe": ("Docker Desktop", "Закрой Docker Desktop, если не нужен."),
    "node.exe": ("Node.js — твой проект или сборка", ""), "python.exe": ("Python-скрипт", ""),
    "pythonw.exe": ("Python-программа в фоне (в т.ч. ScanHub)", ""),
    "code.exe": ("VS Code", ""), "cursor.exe": ("Cursor", ""),
    "nahimicsvc64.exe": ("Nahimic — звуковые эффекты Lenovo", "Известен тем, что иногда грузит процессор. Можно отключить службу Nahimic, если эффекты не нужны."),
    "nahimicsvc32.exe": ("Nahimic — звуковые эффекты Lenovo", "Можно отключить службу Nahimic, если эффекты не нужны."),
    "audiodg.exe": ("Обработка звука Windows", "Высокая нагрузка — обычно из-за звуковых эффектов (Nahimic, улучшения звука)."),
    "dwm.exe": ("Отрисовка окон Windows", "Нагрузка растёт от анимаций, живых обоев и видео на весь экран."),
    "explorer.exe": ("Проводник Windows", "Если долго грузит — перезапусти проводник через Диспетчер задач."),
    "nvcontainer.exe": ("NVIDIA App / GeForce Experience", "Можно отключить оверлей и запись в NVIDIA App."),
    "lenovovantageservice.exe": ("Lenovo Vantage", ""), "obs64.exe": ("OBS — запись/стрим", ""),
}
_MODES = {"961cc777-2547-4f9d-8174-7d86181b8a7a": ("efficiency", "Лучшая энергоэффективность"),
          "00000000-0000-0000-0000-000000000000": ("balanced", "Сбалансированный"),
          "ded574b5-45a0-4f42-8737-46345c09c238": ("performance", "Максимальная производительность")}


SENSORS_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "ScanHub")
SENSORS_JSON = os.path.join(SENSORS_DIR, "sensors.json")
SENSORS_WANT = os.path.join(SENSORS_DIR, "want")
SENSORS_TASK = r"ScanHub\Sensors"
SENSORS_SCRIPT = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "ScanHub", "sensors.ps1")
FAN_MODES = {1: "Тихий", 2: "Баланс", 3: "Производительность", 224: "Свой", 255: "Свой"}


_JOB = None


def bind_to_server(popen):
    """Привязать дочерний процесс к жизни сервера (Job Object с KILL_ON_JOB_CLOSE)."""
    global _JOB
    try:
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
        if _JOB is None:
            class IO(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rb", "wb", "ob")]

            class BASIC(ctypes.Structure):
                _fields_ = [("a", ctypes.c_int64), ("b", ctypes.c_int64), ("LimitFlags", wintypes.DWORD),
                            ("c", ctypes.c_size_t), ("d", ctypes.c_size_t), ("e", wintypes.DWORD),
                            ("f", ctypes.c_size_t), ("g", wintypes.DWORD), ("h", wintypes.DWORD)]

            class EXT(ctypes.Structure):
                _fields_ = [("Basic", BASIC), ("Io", IO), ("i", ctypes.c_size_t), ("j", ctypes.c_size_t),
                            ("k", ctypes.c_size_t), ("l", ctypes.c_size_t)]
            k32.CreateJobObjectW.restype = wintypes.HANDLE
            job = k32.CreateJobObjectW(None, None)
            info = EXT()
            info.Basic.LimitFlags = 0x2000            # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            k32.SetInformationJobObject(wintypes.HANDLE(job), 9, ctypes.byref(info), ctypes.sizeof(info))
            _JOB = job
        k32.AssignProcessToJobObject(wintypes.HANDLE(_JOB), wintypes.HANDLE(int(popen._handle)))
    except Exception:
        pass
    return popen


def sensors_installed():
    if not os.path.exists(SENSORS_SCRIPT):
        return False
    r = subprocess.run(["schtasks", "/Query", "/TN", SENSORS_TASK], capture_output=True, creationflags=NO_WINDOW)
    return r.returncode == 0


def sensors_outdated():
    import hashlib
    try:
        a = hashlib.sha256(open(SENSORS_SCRIPT, "rb").read()).digest()
        b = hashlib.sha256(open(os.path.join(SELF_DIR, "agent", "sensors.ps1"), "rb").read()).digest()
        return a != b
    except OSError:
        return False


def _num(v, lo, hi):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


def sensors_read(max_age=10):
    """Показания агента: температура процессора, вентиляторы, режим. None — агент не работает."""
    try:
        with open(SENSORS_JSON, encoding="utf-8-sig") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    if time.time() - (d.get("t") or 0) > max_age:
        return None
    raw_acpi = d.get("acpi")
    raw_acpi = raw_acpi if isinstance(raw_acpi, list) else [raw_acpi] if raw_acpi is not None else []
    acpi = [x for x in raw_acpi if _num(x, 15, 115)]
    cpu = _num(d.get("om_cpu"), 15, 115) or _num(d.get("gz_cpu"), 15, 115) or _num(d.get("fm_cpu"), 15, 115)         or (max(acpi) if acpi else None)
    def pick(*keys):
        vals = [_num(d.get(k), 0, 12000) for k in keys]
        good = [v for v in vals if v]                 # первое ненулевое
        return good[0] if good else next((v for v in vals if v is not None), None)
    fans = [f for f in (pick("om_fan1", "gz_fan1", "fm_fan1"), pick("om_fan2", "gz_fan2", "fm_fan2")) if f is not None]
    # GameZone на некоторых моделях всегда отдаёт 0 — если процессор горячий, а все вентиляторы «стоят», данных нет
    if fans and not any(fans) and (cpu or 0) >= 70:
        fans = []
    mode = d.get("gz_mode")
    return {"cpu_temp": cpu, "gpu_temp_ec": _num(d.get("om_gpu"), 15, 115) or _num(d.get("gz_gpu"), 15, 115),
            "fans": fans, "fan_max": _num(d.get("gz_fanmax"), 1000, 12000),
            "fan_mode": FAN_MODES.get(int(mode)) if isinstance(mode, (int, float)) and mode else None,
            "source": "Lenovo" if d.get("has_gz") or d.get("has_fm") else "ACPI", "raw": d}


def fan_tip(st):
    """Совет «что проверить», если шумит без нагрузки — под производителя и тип устройства."""
    maker = (st.get("maker") or "").lower()
    if not st.get("laptop"):
        return ("проверь кривые вентиляторов в BIOS или утилите материнской платы, почисти корпус и радиаторы от пыли "
                "и убедись, что вентиляторы не задевают провода")
    utils = [("lenovo", "режим вентиляторов Lenovo (Fn+Q — «Тихий»)"),
             ("asus", "режим в Armoury Crate (Fn+F5 — «Тихий»)"),
             ("micro-star", "режим в MSI Center (User Scenario — «Silent»)"), ("msi", "режим в MSI Center (Silent)"),
             ("hp", "режим в OMEN Gaming Hub / HP Command Center"),
             ("acer", "режим в NitroSense / PredatorSense"),
             ("dell", "режим в Alienware Command Center / Dell Power Manager"),
             ("gigabyte", "режим в Gigabyte Control Center"), ("razer", "режим в Razer Synapse"),
             ("huawei", "режим производительности в PC Manager"), ("xiaomi", "режим в Xiaomi PC Manager")]
    util = next((u for k, u in utils if k in maker), "режим вентиляторов в фирменной утилите производителя")
    return f"проверь {util}, не стоит ли ноутбук на мягком (закрывает решётки) и когда его последний раз чистили от пыли"


def power_mode():
    """Режим питания Windows (Параметры → Питание): для сети и для батареи."""
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes")
        b = psutil.sensors_battery()
        name = "ActiveOverlayDcPowerScheme" if b and not b.power_plugged else "ActiveOverlayAcPowerScheme"
        guid = winreg.QueryValueEx(k, name)[0].lower()
        key, label = _MODES.get(guid, ("unknown", "особый"))
        return {"key": key, "label": label}
    except OSError:
        return None


def idle_seconds():
    """Сколько секунд не было ввода с клавиатуры и мыши."""
    try:
        import ctypes

        class LII(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
        li = LII()
        li.cbSize = ctypes.sizeof(LII)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(li)):
            return (ctypes.windll.kernel32.GetTickCount() - li.dwTime) / 1000.0
    except Exception:
        pass
    return None
USER_DIRS = [p.lower() for p in filter(None, [os.environ.get("TEMP"), os.environ.get("APPDATA"),
                                              os.environ.get("LOCALAPPDATA"), os.environ.get("ProgramData"),
                                              r"C:\Users\Public"])]
TRUSTED_SIGNERS = ("Microsoft", "Google", "Mozilla", "NVIDIA", "Advanced Micro Devices", "Intel", "Valve",
                   "Discord", "Telegram", "JetBrains", "Lenovo", "Python Software Foundation", "OpenJS",
                   "GitHub", "Anthropic", "Spotify", "Zoom", "Opera", "Yandex", "Brave", "Epic Games")


# ---------------------------------------------------------------- все процессы одним запросом
# psutil читает данные каждого процесса отдельно, а для защищённых системных процессов (без прав администратора их больше
# сотни) каждый раз запрашивает ВСЮ таблицу процессов — ~1 с процессора на показатель за проход. Здесь одна таблица на всех,
# как в Диспетчере задач: NtQuerySystemInformation(SystemProcessInformation).
import ctypes as _ct


class _UNICODE_STRING(_ct.Structure):
    _fields_ = [("Length", _ct.c_ushort), ("MaximumLength", _ct.c_ushort), ("Buffer", _ct.c_void_p)]


class _SPI(_ct.Structure):
    _fields_ = [("NextEntryOffset", _ct.c_ulong), ("NumberOfThreads", _ct.c_ulong), ("WorkingSetPrivateSize", _ct.c_longlong),
                ("HardFaultCount", _ct.c_ulong), ("NumberOfThreadsHighWatermark", _ct.c_ulong), ("CycleTime", _ct.c_ulonglong),
                ("CreateTime", _ct.c_longlong), ("UserTime", _ct.c_longlong), ("KernelTime", _ct.c_longlong),
                ("ImageName", _UNICODE_STRING), ("BasePriority", _ct.c_long), ("UniqueProcessId", _ct.c_void_p),
                ("InheritedFromUniqueProcessId", _ct.c_void_p), ("HandleCount", _ct.c_ulong), ("SessionId", _ct.c_ulong),
                ("UniqueProcessKey", _ct.c_size_t), ("PeakVirtualSize", _ct.c_size_t), ("VirtualSize", _ct.c_size_t),
                ("PageFaultCount", _ct.c_ulong), ("PeakWorkingSetSize", _ct.c_size_t), ("WorkingSetSize", _ct.c_size_t),
                ("QuotaPeakPagedPoolUsage", _ct.c_size_t), ("QuotaPagedPoolUsage", _ct.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", _ct.c_size_t), ("QuotaNonPagedPoolUsage", _ct.c_size_t),
                ("PagefileUsage", _ct.c_size_t), ("PeakPagefileUsage", _ct.c_size_t), ("PrivatePageCount", _ct.c_size_t),
                ("ReadOperationCount", _ct.c_longlong), ("WriteOperationCount", _ct.c_longlong), ("OtherOperationCount", _ct.c_longlong),
                ("ReadTransferCount", _ct.c_longlong), ("WriteTransferCount", _ct.c_longlong), ("OtherTransferCount", _ct.c_longlong)]


def proc_table():
    """{pid: {name, cpu (секунды), rss, create (unix), io (байт прочитано+записано)}} — за один системный вызов."""
    ntdll = _ct.windll.ntdll
    size = _ct.c_ulong(1 << 20)
    for _ in range(8):
        buf = _ct.create_string_buffer(size.value)
        st = ntdll.NtQuerySystemInformation(5, buf, size, _ct.byref(size))
        if st == -1073741820:                       # STATUS_INFO_LENGTH_MISMATCH — процессов прибавилось, буфер побольше
            size = _ct.c_ulong(size.value + (1 << 17))
            continue
        if st != 0:
            raise OSError(f"NtQuerySystemInformation: {st & 0xFFFFFFFF:#x}")
        break
    out, off, base = {}, 0, _ct.addressof(buf)
    while True:
        e = _SPI.from_address(base + off)
        pid = e.UniqueProcessId or 0
        name = _ct.wstring_at(e.ImageName.Buffer, e.ImageName.Length // 2) if e.ImageName.Buffer and e.ImageName.Length else ""
        out[pid] = {"name": name or ("System Idle Process" if pid == 0 else ""), "cpu": (e.UserTime + e.KernelTime) / 1e7,
                    "rss": e.WorkingSetSize, "create": e.CreateTime / 1e7 - 11644473600 if e.CreateTime else 0,
                    "io": e.ReadTransferCount + e.WriteTransferCount}
        if not e.NextEntryOffset:
            break
        off += e.NextEntryOffset
    return out


def _sig(path):
    ps = ("$s = Get-AuthenticodeSignature -LiteralPath $env:SCANHUB_ARG; "
          "[pscustomobject]@{status=[string]$s.Status; signer=[string]$s.SignerCertificate.Subject} | ConvertTo-Json -Compress")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=60,
                             env={**os.environ, "SCANHUB_ARG": path}, creationflags=NO_WINDOW).stdout
        d = json.loads(out)
        cn = next((x.split("=", 1)[1].strip('"') for x in d.get("signer", "").split(", ") if x.startswith("CN=")), "")
        return {"status": d.get("status"), "signer": cn}
    except Exception:
        return {"status": "Unknown", "signer": ""}


class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.series = {k: deque(maxlen=HISTORY) for k in
                       ("t", "cpu", "ram", "gpu", "gpu_temp", "gpu_power", "gpu_top", "net_down", "net_up",
                        "disk_read", "disk_write", "cpu_temp", "fan1", "fan2", "cpu_top")}
        self.gpu_procs = []      # [{pid, name, exe, util, mem}] — нагрузка на видеокарту по процессам
        self.cpu_hist = {}       # pid -> deque[(t, cpu%)] за 5 минут
        self.io_prev = {}        # pid -> (t, байт прочитано+записано)
        self.io_hist = {}        # pid -> deque[(t, байт/с)]
        self.pid_names = {}      # pid -> (имя, путь)
        self.services = {}       # pid -> [службы] (для svchost)
        self.services_at = 0
        self.sensors = None      # последние показания агента датчиков
        self.sensors_on = None   # агент установлен?
        self.sensors_checked = 0
        self.sensors_started = 0
        self.sensors_wait = None # с какого момента ждём первые показания
        self.memclean_on = None  # полная очистка памяти включена?
        self.memclean_checked = 0
        self.gpu_hist = {}       # pid -> deque[(t, util)] за 5 минут
        self.cpu_leader = None   # [имя, %] — кто больше всех грузит процессор (для подсказки на графике)
        self.percpu = []
        self.now = {}
        self.procs = []
        self.flags = {}          # pid -> список причин
        self.cpu_avg = {}        # pid -> скользящее среднее CPU
        self.sigs = {}           # путь exe -> подпись (кэш)
        self.sig_queue = []
        self.gpu = None
        self.gpu_apps = {}
        self.static = self._static()
        self.last_request = 0
        self.running = False

    # ------------------------------------------------------------ статика
    def _static(self):
        vm = psutil.virtual_memory()
        cpu = platform.processor()
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            cpu = winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
        except OSError:
            pass
        maker = model = family = ""
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS")
            q = lambda n: str(winreg.QueryValueEx(k, n)[0]).strip()
            maker, model = q("SystemManufacturer"), q("SystemProductName")
            try:
                family = q("SystemFamily")
            except OSError:
                pass
        except OSError:
            pass
        lenovo_wmi = False
        if "lenovo" in maker.lower():
            r = subprocess.run(["powershell", "-NoProfile", "-Command",
                                "[bool](Get-CimClass -Namespace root\\WMI -ClassName LENOVO_GAMEZONE_DATA -ErrorAction SilentlyContinue)"],
                               capture_output=True, text=True, timeout=30, creationflags=NO_WINDOW)
            lenovo_wmi = "True" in r.stdout
        return {"maker": maker, "model": model, "family": family, "laptop": psutil.sensors_battery() is not None,
                "lenovo_wmi": lenovo_wmi,
                "cpu_name": cpu, "cores": psutil.cpu_count(logical=False), "threads": psutil.cpu_count(),
                "ram_total": vm.total, "boot": psutil.boot_time(), "host": platform.node(),
                "os": f"{platform.system()} {platform.release()} ({platform.version()})"}

    # ------------------------------------------------------------ жизненный цикл
    light = False          # лёгкий режим для «Сторожа»: без постоянного опроса видеокарты по процессам (Get-Counter — дорогой)

    def touch(self):
        self.last_request = time.time()
        if not self.running:
            self.running = True
            threading.Thread(target=self._loop, daemon=True).start()
            threading.Thread(target=self._gpu_loop, daemon=True).start()
            threading.Thread(target=self._sig_loop, daemon=True).start()
            threading.Thread(target=self._proc_loop, daemon=True).start()
            if not self.light:
                self._start_gpu_procs()

    def _start_gpu_procs(self):
        if not getattr(self, "_gpu_procs_on", False):
            self._gpu_procs_on = True
            threading.Thread(target=self._gpu_proc_loop, daemon=True).start()

    def _active(self):
        return time.time() - self.last_request < 30

    # ------------------------------------------------------------ основной цикл
    def _loop(self):
        psutil.cpu_percent(percpu=True)
        net0, disk0, t0 = psutil.net_io_counters(), psutil.disk_io_counters(), time.time()
        while True:
            time.sleep(STEP)
            if not self._active():
                self.running = False
                return
            t = time.time()
            dt = max(t - t0, 0.001)
            per = psutil.cpu_percent(percpu=True)
            vm = psutil.virtual_memory()
            net, disk = psutil.net_io_counters(), psutil.disk_io_counters()
            g = self.gpu or {}
            with self.lock:
                s = self.series
                s["t"].append(round(t))
                s["cpu"].append(round(sum(per) / len(per), 1))
                s["ram"].append(round(vm.percent, 1))
                s["gpu"].append(g.get("util"))
                s["gpu_temp"].append(g.get("temp"))
                sn = self.sensors or {}
                fans = sn.get("fans") or []
                s["cpu_temp"].append(sn.get("cpu_temp"))
                s["fan1"].append(fans[0] if len(fans) > 0 else None)
                s["fan2"].append(fans[1] if len(fans) > 1 else None)
                s["gpu_power"].append(g.get("power"))
                top = self.gpu_procs[0] if self.gpu_procs and self.gpu_procs[0]["util"] >= 3 else None
                s["gpu_top"].append([top["name"], top["util"]] if top else None)
                ctop = self.cpu_leader
                s["cpu_top"].append(ctop if ctop and ctop[1] >= 3 else None)
                s["net_down"].append(round((net.bytes_recv - net0.bytes_recv) / dt))
                s["net_up"].append(round((net.bytes_sent - net0.bytes_sent) / dt))
                if disk and disk0:
                    s["disk_read"].append(round((disk.read_bytes - disk0.read_bytes) / dt))
                    s["disk_write"].append(round((disk.write_bytes - disk0.write_bytes) / dt))
                self.percpu = per
                self.now.update(ram_used=vm.total - vm.available, ram_total=vm.total,
                                swap=psutil.swap_memory().percent)
            net0, disk0, t0 = net, disk, t

    def _sensors_tick(self):
        now = time.time()
        if self.memclean_on is None or now - self.memclean_checked > 60:
            import system
            self.memclean_on = system.memclean_installed()
            self.memclean_checked = now
        if self.sensors_on is None or now - self.sensors_checked > 60:
            self.sensors_on = sensors_installed()
            self.sensors_checked = now
        if not self.sensors_on:
            self.sensors = None
            return
        try:
            os.makedirs(SENSORS_DIR, exist_ok=True)
            with open(SENSORS_WANT, "w") as f:
                f.write(str(int(now)))
        except OSError:
            pass
        self.sensors = sensors_read()
        if self.sensors is not None:
            self.sensors_wait = None
        elif self.sensors_wait is None:
            self.sensors_wait = now
        if self.sensors is None and now - self.sensors_started > 20:
            # агент не работает — запустить задачу (без UAC: права выданы при включении датчиков)
            subprocess.run(["schtasks", "/Run", "/TN", SENSORS_TASK], capture_output=True, creationflags=NO_WINDOW)
            self.sensors_started = now

    def _proc_loop(self):
        tick = 0
        while self.running:
            try:
                self._sensors_tick()
            except Exception as e:                  # журнал сам не повторяет одну ошибку чаще раза в 10 минут
                __import__("report").record("датчики", e)
            if tick % 5 == 0:
                self._disks()
            self._scan_procs()
            tick += 1
            time.sleep(3)

    def _disks(self):
        out = []
        for p in psutil.disk_partitions(all=False):
            if "cdrom" in p.opts or not p.fstype:
                continue
            try:
                u = psutil.disk_usage(p.mountpoint)
            except OSError:
                continue
            out.append({"mount": p.mountpoint.rstrip("\\"), "fs": p.fstype, "total": u.total, "used": u.used,
                        "percent": u.percent})
        b = psutil.sensors_battery()
        with self.lock:
            self.now["disks"] = out
            self.now["battery"] = {"percent": round(b.percent), "plugged": b.power_plugged} if b else None

    # ------------------------------------------------------------ процессы и подозрения
    def _scan_procs(self):
        ncpu = psutil.cpu_count() or 1
        rows = []
        alive = set()
        tnow = time.time()
        try:
            table = proc_table()
        except OSError:
            table = {}
        if not hasattr(self, "cpu_prev"):
            self.cpu_prev, self.exe_cache = {}, {}
        for pid, t in table.items():
            # загрузка процессора = прирост процессорного времени за проход; новый процесс с тем же PID — по времени запуска
            prev = self.cpu_prev.get(pid)
            cpu = 0.0
            if prev and prev[2] == t["create"] and tnow > prev[0]:
                cpu = max(0.0, (t["cpu"] - prev[1]) / (tnow - prev[0]) * 100 / ncpu)
            self.cpu_prev[pid] = (tnow, t["cpu"], t["create"])
            io_rate = 0
            prev_io = self.io_prev.get(pid)
            if prev_io and tnow > prev_io[0] and prev_io[2] == t["create"]:
                io_rate = max(0, (t["io"] - prev_io[1]) / (tnow - prev_io[0]))
            self.io_prev[pid] = (tnow, t["io"], t["create"])
            key = (pid, t["create"])
            if key not in self.exe_cache:            # путь к программе — один раз на процесс (это дёшево)
                try:
                    self.exe_cache[key] = psutil.Process(pid).exe()
                except (psutil.Error, OSError):
                    self.exe_cache[key] = ""
            info = {"pid": pid, "name": t["name"], "exe": self.exe_cache[key], "create_time": t["create"],
                    "memory_info": type("M", (), {"rss": t["rss"]})}
            if pid == 4:                      # «System»: ядро и драйверы — в таблицу процессов не выводим, но учитываем в «Почему нагружен процессор»
                self.pid_names[pid] = ("System", "")
                self.cpu_hist.setdefault(pid, deque(maxlen=110)).append((tnow, cpu))
                alive.add(pid)
                continue
            if pid == 0 or not info["name"]:
                continue
            alive.add(pid)
            self.pid_names[pid] = (info["name"], info["exe"] or "")
            self.cpu_hist.setdefault(pid, deque(maxlen=110)).append((tnow, cpu))
            if io_rate:
                self.io_hist.setdefault(pid, deque(maxlen=110)).append((tnow, io_rate))
            avg = self.cpu_avg.get(pid, cpu)
            avg = avg * 0.9 + cpu * 0.1          # ~30 с сглаживания при шаге 3 с
            self.cpu_avg[pid] = avg
            rows.append({"pid": pid, "name": info["name"], "exe": info["exe"] or "",
                         "cpu": round(cpu, 1), "cpu_avg": round(avg, 1),
                         "mem": info["memory_info"].rss if info["memory_info"] else 0,
                         "started": info["create_time"], "gpu_mem": self.gpu_apps.get(pid)})
        for pid in list(self.cpu_avg):
            if pid not in alive:
                self.cpu_avg.pop(pid, None)
                self.flags.pop(pid, None)
                self.io_prev.pop(pid, None)
        for pid in [p for p in self.cpu_prev if p not in table]:
            self.cpu_prev.pop(pid, None)
        if len(self.exe_cache) > 2000:
            self.exe_cache = {k: v for k, v in self.exe_cache.items() if k[0] in table and table[k[0]]["create"] == k[1]}
        for hist in (self.cpu_hist, self.io_hist):
            for pid in [k for k, v in hist.items() if not v or v[-1][0] < tnow - 330]:
                hist.pop(pid, None)
        if tnow - self.services_at > 60:
            svc = {}
            try:
                for sv in psutil.win_service_iter():
                    try:
                        d = sv.as_dict()
                        if d.get("pid"):
                            svc.setdefault(d["pid"], []).append(d.get("display_name") or d["name"])
                    except (psutil.Error, OSError):
                        pass
            except (psutil.Error, OSError):
                pass
            self.services, self.services_at = svc, tnow
        for r in rows:
            r["flags"] = self._judge(r)
            r["sig"] = self.sigs.get(r["exe"].lower()) if r["exe"] else None
        # лидер по процессору: одинаковые процессы (браузер, svchost) складываем
        agg = {}
        for r in rows:
            agg[r["name"]] = agg.get(r["name"], 0) + r["cpu"]
        lead = max(agg.items(), key=lambda kv: kv[1]) if agg else None
        self.cpu_leader = [lead[0], round(lead[1], 1)] if lead else None
        with self.lock:
            self.procs = rows

    def _judge(self, r):
        name, exe = r["name"].lower(), r["exe"].lower()
        stem = name.rsplit(".", 1)[0]
        reasons = []
        if exe.startswith(SELF_DIR):          # сами сканеры ScanHub (MinerSearch и т.п.)
            return reasons
        if stem in MINER_NAMES or "xmrig" in name or "miner" in stem:
            reasons.append("имя известного майнера")
        if name in SYSTEM_NAMES and exe and not exe.startswith(WINDIR):
            reasons.append("системное имя, но запущен не из Windows")
        heavy = r["cpu_avg"] >= 20 or (r["gpu_mem"] or 0) >= 1500
        if heavy and exe:
            if any(exe.startswith(d) for d in USER_DIRS):
                sig = self.sigs.get(exe)
                if sig is None:
                    if exe not in self.sig_queue:
                        self.sig_queue.append(exe)
                elif not (sig["status"] == "Valid" and any(t.lower() in sig["signer"].lower() for t in TRUSTED_SIGNERS)):
                    reasons.append("долго грузит " + ("видеокарту" if r["cpu_avg"] < 20 else "процессор")
                                   + " из папки пользователя, " + ("без подписи" if sig["status"] != "Valid"
                                                                   else f"подпись: {sig['signer']}"))
        return reasons

    def _sig_loop(self):
        while self.running:
            if self.sig_queue:
                path = self.sig_queue.pop(0)
                self.sigs[path] = _sig(path)
            else:
                time.sleep(1)

    # ------------------------------------------------------------ NVIDIA
    def _gpu_loop(self):
        q = ("utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,name,clocks.gr,clocks.max.gr,pstate,"
             "clocks_event_reasons.sw_thermal_slowdown,clocks_event_reasons.hw_thermal_slowdown,temperature.gpu.tlimit,"
             "clocks_event_reasons.sw_power_cap")
        try:
            p = bind_to_server(subprocess.Popen(["nvidia-smi", f"--query-gpu={q}", "--format=csv,noheader,nounits",
                                                 "-lms", "1000"], stdout=subprocess.PIPE, text=True, creationflags=NO_WINDOW))
        except OSError:
            return
        tick = 0
        for line in p.stdout:
            if not self.running:
                p.kill()
                return
            parts = [x.strip() for x in line.split(",")]
            if len(parts) >= 6:
                num = lambda x: float(x) if x.replace(".", "", 1).isdigit() else None
                self.gpu = {"util": num(parts[0]), "mem_used": num(parts[1]), "mem_total": num(parts[2]),
                            "temp": num(parts[3]), "power": num(parts[4]), "name": parts[5]}
                if self.light and (self.gpu["util"] or 0) >= 40:     # видеокарта занята — тогда уже выясняем, кем
                    self._start_gpu_procs()
                if len(parts) >= 12:
                    self.gpu.update(clock=num(parts[6]), clock_max=num(parts[7]), pstate=parts[8], tlimit=num(parts[11]))
                    self.gpu.update(sw_thermal=parts[9].strip() == "Active", hw_thermal=parts[10].strip() == "Active",
                                    power_cap=len(parts) > 12 and parts[12].strip() == "Active")
                    tl = self.gpu.get("tlimit")
                    # настоящий перегрев — аппаратный флаг или запас до порога меньше 10°C
                    self.gpu["throttle"] = self.gpu["hw_thermal"] or (self.gpu["sw_thermal"] and tl is not None and tl <= 10)
            if tick % 5 == 0:
                self._gpu_apps()
            tick += 1

    GPU_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$parent = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID").ParentProcessId
while ($true) {
  if (-not (Get-Process -Id $parent -ErrorAction SilentlyContinue)) { exit }
  $s = (Get-Counter '\GPU Engine(*)\Utilization Percentage','\GPU Process Memory(*)\Dedicated Usage').CounterSamples
  $u = @{}; $m = @{}
  foreach ($x in $s) {
    if ($x.InstanceName -match 'pid_(\d+)_') {
      $p = $matches[1]
      if ($x.Path -like '*utilization percentage') {
        $e = if ($x.InstanceName -match 'engtype_([a-z0-9]+)') { $matches[1] } else { 'x' }
        $k = "$p|$e"; $u[$k] = [double]$u[$k] + $x.CookedValue
      } else { $m[$p] = [double]$m[$p] + $x.CookedValue }
    }
  }
  $o = @{}
  $eo = @{}
  foreach ($k in $u.Keys) { $p, $e = $k.Split('|'); if (-not $o.ContainsKey($p) -or $u[$k] -gt $o[$p]) { $o[$p] = [math]::Round($u[$k], 1); $eo[$p] = $e } }
  $mm = @{}; foreach ($k in $m.Keys) { $mm[$k] = [math]::Round($m[$k] / 1MB) }
  [Console]::Out.WriteLine((@{u = $o; m = $mm; e = $eo} | ConvertTo-Json -Compress))
  [Console]::Out.Flush()
  Start-Sleep -Milliseconds 2000
}
"""

    def _gpu_proc_loop(self):
        """Постоянный PowerShell отдаёт JSON раз в ~3 с: загрузка видеокарты и видеопамять по каждому PID."""
        try:
            p = bind_to_server(subprocess.Popen(["powershell", "-NoProfile", "-Command", self.GPU_PS], stdout=subprocess.PIPE,
                                                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", creationflags=NO_WINDOW))
        except OSError:
            return
        names = {}
        for line in p.stdout:
            if not self.running:
                p.kill()
                return
            try:
                d = json.loads(line)
            except ValueError:
                continue
            now, rows = time.time(), []
            util, mem, eng = d.get("u") or {}, d.get("m") or {}, d.get("e") or {}
            for spid in set(util) | set(mem):
                pid = int(spid)
                if pid not in names:
                    try:
                        pr = psutil.Process(pid)
                        names[pid] = (pr.name(), pr.exe())
                    except (psutil.Error, OSError):
                        names[pid] = (f"PID {pid}", "")
                u = min(float(util.get(spid) or 0), 100.0)
                h = self.gpu_hist.setdefault(pid, deque(maxlen=120))
                h.append((now, u))
                rows.append({"pid": pid, "name": names[pid][0], "exe": names[pid][1], "util": round(u, 1),
                             "mem": mem.get(spid) or 0, "engine": ENGINES.get(str(eng.get(spid, "")).lower(), "")})
            rows.sort(key=lambda r: (r["util"], r["mem"]), reverse=True)
            self.gpu_procs = rows

    def noise_report(self, observe=25):
        """Почему шумит ноутбук: наблюдаем ~25 с, плюс история за 5 минут. Вентиляторы крутятся от нагрузки и тепла."""
        self.touch()
        t_end = time.time() + observe
        while time.time() < t_end:
            time.sleep(1)
            self.touch()
        now = time.time()
        ncpu = psutil.cpu_count() or 1

        def avg_hist(hist, since, until=None):
            out = {}
            for pid, h in list(hist.items()):
                vals = [v for t, v in list(h) if t >= since and (until is None or t <= until)]
                if vals:
                    out[pid] = (sum(vals) / len(vals), max(vals))
            return out

        def who(pid):
            name, exe = self.pid_names.get(pid, (f"PID {pid}", ""))
            low = name.lower()
            known = KNOWN_LOAD.get(low)
            svcs = self.services.get(pid) or []
            if low == "svchost.exe" and svcs:
                known = known or ("Системная служба Windows", "")
                known = (f"Служба Windows: {', '.join(svcs[:2])}", known[1])
            return {"pid": pid, "name": name, "exe": exe, "title": known[0] if known else "",
                    "advice": known[1] if known else "", "services": svcs[:3]}

        cpu_now = avg_hist(self.cpu_hist, now - observe - 3)
        cpu_5m = avg_hist(self.cpu_hist, now - 300)
        io_now = avg_hist(self.io_hist, now - observe - 3)
        with self.lock:
            S = {k: list(v) for k, v in self.series.items()}
        recent = [v for t, v in zip(S["t"], S["cpu"]) if t >= now - observe and v is not None]
        cpu_total = sum(recent) / len(recent) if recent else 0
        cpu_peak5 = max([v for v in S["cpu"] if v is not None] or [0])
        peak_at = next((t for t, v in zip(S["t"], S["cpu"]) if v == cpu_peak5), now)
        gpu_vals = [v for t, v in zip(S["t"], S["gpu"]) if t >= now - observe and v is not None]
        gpu_now = sum(gpu_vals) / len(gpu_vals) if gpu_vals else None
        disk_vals = [a + b for t, a, b in zip(S["t"], S["disk_read"], S["disk_write"]) if t >= now - observe]
        disk_now = sum(disk_vals) / len(disk_vals) if disk_vals else 0
        heat = self.heat_report()
        idle = idle_seconds()
        bat = self.now.get("battery")
        mode = power_mode()

        def grouped(data, minimum):
            g = {}
            for pid, (a, m) in data.items():
                name = self.pid_names.get(pid, (f"PID {pid}",))[0]
                if name.lower() in ("system idle process",):
                    continue
                w = who(pid)
                key = name.lower() if name.lower() != "svchost.exe" else f"svchost:{w['title']}"
                cur = g.setdefault(key, {**w, "avg": 0.0, "peak": 0.0, "count": 0, "pids": []})
                cur["avg"] += a
                cur["peak"] = max(cur["peak"], m)
                cur["count"] += 1
                cur["pids"].append(pid)
            rows = [{**v, "avg": round(v["avg"], 1), "peak": round(v["peak"], 1)} for v in g.values() if v["avg"] >= minimum]
            return sorted(rows, key=lambda r: r["avg"], reverse=True)

        top_cpu = grouped(cpu_now, 1)[:8]
        top_5m = grouped(cpu_5m, 2)[:6]
        top_io = sorted(io_now.items(), key=lambda kv: kv[1][0], reverse=True)
        top_io = [{**who(pid), "rate": round(a), "peak": round(m), "pids": [pid]} for pid, (a, m) in top_io if a >= 512 * 1024][:5]
        # кто давал пик: средняя нагрузка процессов в окне вокруг самой высокой точки за 5 минут
        peak_rows = grouped(avg_hist(self.cpu_hist, peak_at - 8, peak_at + 4), 1)[:8] if cpu_peak5 >= 30 else []
        self._safety(top_cpu + top_5m + top_io + peak_rows)

        causes = []
        sus = [r for r in self.procs if r.get("flags")]
        for r in sus:
            causes.append({"level": "bad", "title": f"Подозрение на скрытый майнер: {r['name']}",
                           "text": "; ".join(r["flags"]), "action": "scan", "path": r["exe"]})
        for c in top_cpu:
            if c["avg"] >= 8 or (cpu_total >= 20 and c["avg"] >= cpu_total * 0.3):
                many = f" (процессов: {c['count']})" if c["count"] > 1 else ""
                causes.append({"level": "warn" if c["avg"] >= 20 else "info",
                               "title": f"{c['name']}{many} грузит процессор на {c['avg']:.0f}%" + (f" — {c['title']}" if c["title"] else ""),
                               "text": c["advice"] or ("" if c["title"] else "Если не знаешь, что это за программа, — проверь её кнопкой справа."),
                               "action": "proc", "proc": c, "path": c["exe"]})
        if heat and heat.get("culprits"):
            g = heat["culprits"][0]
            if g["avg"] >= 15:
                causes.append({"level": "warn" if g["avg"] >= 40 else "info",
                               "title": f"{g['name']} нагружает видеокарту на {g['avg']:.0f}%" + (f" ({g['engine']})" if g.get("engine") else ""),
                               "text": KNOWN_LOAD.get(g["name"].lower(), ("", "Видеокарта греется и раскручивает вентиляторы."))[1]
                               or "Видеокарта греется и раскручивает вентиляторы."})
        for d in top_io[:2]:
            if d["rate"] >= 10 * 1024 * 1024:
                causes.append({"level": "info", "title": f"{d['name']} активно работает с диском ({d['rate'] / 2**20:.0f} МБ/с)"
                                                          + (f" — {d['title']}" if d["title"] else ""),
                               "text": d["advice"] or "Активная работа с диском тоже нагружает систему."})
        if idle is not None and idle >= 120 and cpu_total >= 20:
            causes.append({"level": "info", "title": f"Ты не пользуешься компьютером {int(idle // 60)} мин, а он загружен на {cpu_total:.0f}%",
                           "text": "Значит, работают фоновые задачи — они перечислены выше. Обычно это обновления и проверки, которые Windows запускает, пока ты не за компьютером."})
        loaded = any(c["level"] in ("bad", "warn") for c in causes) or cpu_total >= 25 or (gpu_now or 0) >= 30
        if loaded and not causes:
            names = ", ".join(f"{c['name']} {c['avg']:.0f}%" for c in top_cpu[:4])
            causes.append({"level": "warn" if cpu_total >= 40 else "info",
                           "title": f"Процессор загружен на {cpu_total:.0f}% — нагрузку дают сразу несколько программ",
                           "text": f"Больше всего: {names}." if names else "Нагрузку дают системные процессы."})
        if not loaded:
            if cpu_peak5 >= 50 and now - peak_at < 300:
                who_peak = ", ".join(f"{r['name']} {r['avg']:.0f}%" for r in peak_rows[:3])
                causes.append({"level": "info", "title": f"Сейчас нагрузки нет, но {int((now - peak_at) // 60) or 1} мин назад процессор был загружен на {cpu_peak5:.0f}%",
                               "text": (f"Тогда больше всего грузили: {who_peak}. " if who_peak else "") +
                                       "Вентиляторы ещё какое-то время крутятся, чтобы остудить систему. Если шум не стихает за 2–3 минуты — смотри советы ниже.",
                               "action": "peak" if peak_rows else ""})
            else:
                causes.append({"level": "ok", "title": "Сейчас устройство почти не нагружено",
                               "text": "Если вентиляторы всё равно шумят: " + fan_tip(self.static) + "."})
        if mode and mode.get("key") == "performance":
            causes.append({"level": "info", "title": "В Windows включён режим питания «Максимальная производительность»",
                           "text": "В нём вентиляторы раскручиваются быстрее. Для тишины выбери «Сбалансированный» или «Энергоэффективность»."})
        if bat and bat.get("plugged") and loaded and self.static.get("laptop"):
            causes.append({"level": "info", "title": "Ноутбук от сети — система может работать на полную мощность",
                           "text": "От сети процессор и видеокарта получают больше энергии и сильнее греются под нагрузкой."})
        sn = self.sensors or {}
        fans = sn.get("fans") or []
        if fans:
            fan = max(fans)
            fmax = sn.get("fan_max") or 5500
            share = fan / fmax
            ct = sn.get("cpu_temp")
            temp_txt = f" при температуре процессора {ct:.0f}°C" if ct else ""
            if share >= 0.6:
                causes.insert(0, {"level": "warn", "title": f"Вентиляторы крутятся на {fan:.0f} об/мин — это {share:.0%} от максимума{temp_txt}",
                                  "text": "Причину нагрева смотри в пунктах ниже."})
            elif fan > 0:
                causes.append({"level": "info", "title": f"Вентиляторы: {', '.join(f'{x:.0f}' for x in fans)} об/мин{temp_txt}",
                               "text": ("Это минимальные обороты: вентиляторы почти не слышно, так что шум, скорее всего, не от них "
                                        "(может быть дроссель, жёсткий диск или блок питания)." if fan <= 2300 else
                                        "Вентиляторы на средних оборотах — их слышно в тишине." if fan <= 3500 else
                                        "Вентиляторы на высоких оборотах.")})
            else:
                causes.append({"level": "ok", "title": "Вентиляторы сейчас остановлены", "text": "Если что-то шумит — это не вентиляторы (например, жёсткий диск или дроссели)."})
            if ct and ct >= 90:
                causes.insert(0, {"level": "bad", "title": f"Процессор очень горячий: {ct:.0f}°C",
                                  "text": "Проверь, не закрыты ли решётки, и почисти ноутбук от пыли. Под нагрузкой до 95°C у Ryzen — норма, но в простое — нет."})
        if sn.get("fan_mode") == "Производительность":
            causes.append({"level": "info", "title": "Режим вентиляторов Lenovo: «Производительность»",
                           "text": "В нём вентиляторы крутятся быстрее. Fn+Q переключает режим: «Тихий» (синий индикатор) — самый тихий."})
        elif sn.get("fan_mode") and fans and max(fans) > 0:
            causes.append({"level": "info", "title": f"Режим вентиляторов Lenovo: «{sn['fan_mode']}»",
                           "text": "Fn+Q переключает режим; «Тихий» — самый тихий, но под нагрузкой ноутбук будет горячее." if sn["fan_mode"] != "Тихий" else ""})
        order = {"bad": 0, "warn": 1, "info": 2, "ok": 3}
        causes.sort(key=lambda c: order[c["level"]])
        return {"cpu_total": round(cpu_total, 1), "cpu_peak5": round(cpu_peak5, 1), "gpu_now": round(gpu_now, 1) if gpu_now is not None else None,
                "gpu_temp": (self.gpu or {}).get("temp"), "disk_now": round(disk_now), "idle_s": idle, "battery": bat,
                "power_mode": mode, "top_cpu": top_cpu, "top_5m": top_5m, "top_io": top_io,
                "peak": {"cpu": round(cpu_peak5, 1), "ago_s": int(now - peak_at), "at": time.strftime("%H:%M:%S", time.localtime(peak_at)),
                         "procs": peak_rows},
                "gpu_culprits": (heat or {}).get("culprits", [])[:4], "causes": causes, "observed_s": observe,
                "sensors": {k: v for k, v in sn.items() if k != "raw"} if sn else None,
                "device": {"maker": self.static.get("maker"), "model": self.static.get("family") or self.static.get("model"),
                           "laptop": self.static.get("laptop")},
                "note": "" if sn else ("Скорость вентиляторов и температуру процессора можно добавить: «Ресурсы» → «Включить датчики» "
                                       "(один раз попросит права администратора)." if self.static.get("lenovo_wmi") else
                                       "Температура процессора и обороты вентиляторов на этом устройстве недоступны без датчиков "
                                       "производителя — оцениваю по нагрузке и фоновым задачам.")}

    INTERPRETERS = {"python.exe", "pythonw.exe", "node.exe", "java.exe", "javaw.exe", "powershell.exe", "pwsh.exe", "cmd.exe",
                    "wscript.exe", "cscript.exe", "rundll32.exe", "mshta.exe", "dllhost.exe", "conhost.exe"}

    def _safety(self, rows):
        """Что за процесс и можно ли ему доверять: подпись издателя, где лежит файл, команда запуска (у Python/Node/PowerShell —
        какой скрипт), знакомая ли это программа. Итог: safe — подписан и в системной папке / Program Files;
        check — без подписи в пользовательской или временной папке; likely — остальное."""
        import system                                          # здесь: system импортирует metrics
        exes = {r.get("exe") for r in rows if r.get("exe")}
        try:
            sigs = system.signatures(list(exes)) if exes else {}
        except Exception:
            sigs = {}
        win = os.environ.get("SystemRoot", r"C:\Windows").lower()
        pf = [os.environ.get(k, "").lower() for k in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432") if os.environ.get(k)]
        for r in rows:
            exe = r.get("exe") or ""
            low = exe.lower()
            sg = sigs.get(exe) or {}
            signed = sg.get("status") == "Valid"
            place = ("system" if low.startswith(win + "\\") else "programs" if any(low.startswith(x + "\\") for x in pf)
                     else "temp" if "\\temp\\" in low or "\\tmp\\" in low else "user" if "\\users\\" in low else "other" if exe else "unknown")
            cmds = []
            if r.get("name", "").lower() in self.INTERPRETERS:
                for pid in (r.get("pids") or [r.get("pid")])[:5]:
                    try:
                        c = " ".join(psutil.Process(pid).cmdline())
                    except (psutil.Error, OSError, TypeError):
                        continue
                    if c and c not in cmds:
                        cmds.append(c[:300])
            mine = (bool(cmds) and all("scanhub" in c.lower() for c in cmds)) or "\\scanhub\\" in low   # только если все — ScanHub
            r.update(signed=signed, signer=sg.get("signer") if signed else "", sig_status=sg.get("status") or "", place=place, cmds=cmds,
                     mine=mine, safety="safe" if mine or (signed and place in ("system", "programs")) else
                     "check" if not signed and place in ("temp", "user", "other") else "likely")
        return rows

    def cpu_report(self):
        """Почему нагружен процессор: нагрузка и температура за 5 минут, кто её создавал, что это за процессы."""
        with self.lock:
            pts = [(t, v) for t, v in zip(self.series["t"], self.series["cpu"]) if v is not None]
            temps = [v for v in self.series["cpu_temp"] if v is not None]
        if len(pts) < 5:
            return None
        now_v = sum(v for _, v in pts[-5:]) / 5
        avg = sum(v for _, v in pts) / len(pts)
        peak = max(v for _, v in pts)
        peak_at = next(t for t, v in pts if v == peak)
        since = pts[0][0]
        # сколько раз за окно опрашивались процессы (у самого «долгоживущего» процесса больше всего отсчётов)
        ticks = max([sum(1 for t, _ in list(h) if t >= since) for h in list(self.cpu_hist.values())] or [1])
        groups = {}
        for pid, h in list(self.cpu_hist.items()):
            vals = [v for t, v in list(h) if t >= since]
            if not vals:
                continue
            name, exe = self.pid_names.get(pid, (f"PID {pid}", ""))
            if name.lower() == "system idle process":
                continue
            low = name.lower()
            svcs = self.services.get(pid) or []
            known = KNOWN_LOAD.get(low)
            if low == "svchost.exe" and svcs:
                known = (f"Служба Windows: {', '.join(svcs[:2])}", known[1] if known else "")
            key = low if low != "svchost.exe" else f"svchost:{','.join(svcs[:2])}"
            # среднее за окно, считая отсутствующие отсчёты нулём, — чтобы короткий всплеск не выглядел постоянной нагрузкой
            share = len(vals) / ticks
            g = groups.setdefault(key, {"name": name, "exe": exe, "title": known[0] if known else "", "advice": known[1] if known else "",
                                        "avg": 0.0, "peak": 0.0, "count": 0})
            g["avg"] += sum(vals) / len(vals) * min(1.0, share)
            g["peak"] = max(g["peak"], max(vals))
            g["count"] += 1
        culprits = sorted(({**g, "avg": round(g["avg"], 1), "peak": round(g["peak"], 1)} for g in groups.values() if g["avg"] >= 0.5 or g["peak"] >= 10),
                          key=lambda g: g["avg"], reverse=True)[:8]
        reasons = []
        idle = idle_seconds()
        if culprits and culprits[0]["avg"] >= 5:
            c = culprits[0]
            many = f" (процессов: {c['count']})" if c["count"] > 1 else ""
            reasons.append(["warn" if c["avg"] >= 25 else "info", f"Больше всего нагружает {c['name']}{many}: в среднем {c['avg']:.0f}%, пик {c['peak']:.0f}%"
                            + (f" — {c['title']}" if c["title"] else "")])
            if c["advice"]:
                reasons.append(["info", c["advice"]])
        if peak >= 60 and now_v < 30:
            reasons.append(["info", f"Всплеск до {peak:.0f}% был {max(1, int((time.time() - peak_at) // 60))} мин назад, сейчас нагрузка спала"])
        if idle is not None and idle >= 120 and avg >= 20:
            reasons.append(["warn", f"Ты не пользуешься компьютером {int(idle // 60)} мин, а процессор загружен в среднем на {avg:.0f}% — работают фоновые задачи"])
        ct = temps[-1] if temps else None
        if ct is not None:
            if ct >= 95:
                reasons.append(["bad", f"Процессор очень горячий: {ct:.0f}°C — он может сбрасывать частоты"])
            elif ct >= 85 and now_v < 30:
                reasons.append(["warn", f"Процессор горячий ({ct:.0f}°C) при небольшой нагрузке — проверь охлаждение и пыль"])
        if any(r["flags"] for r in self.procs):
            reasons.append(["bad", "Есть подозрительный процесс — смотри предупреждение о майнере выше"])
        if not reasons:
            reasons.append(["ok", "Процессор почти не нагружен" if avg < 10 else "Нагрузка распределена между несколькими программами"])
        return {"now": round(now_v, 1), "avg": round(avg, 1), "peak": round(peak, 1), "temp": ct,
                "temp_min": min(temps) if temps else None, "temp_max": max(temps) if temps else None,
                "culprits": culprits, "reasons": reasons, "window_s": round(pts[-1][0] - since), "idle_s": idle}

    def heat_report(self):
        """Почему греется видеокарта: температура за 5 минут, кто нагружал её, когда температура росла."""
        g = self.gpu or {}
        with self.lock:
            temps = [(t, v) for t, v in zip(self.series["t"], self.series["gpu_temp"]) if v is not None]
            powers = [v for v in self.series["gpu_power"] if v is not None]
        if not temps:
            return None
        now_t = temps[-1][1]
        tmin, tmax = min(v for _, v in temps), max(v for _, v in temps)
        # окно роста: от минимума до сейчас (или последние 2 минуты)
        t_min_at = next(t for t, v in temps if v == tmin)
        since = min(t_min_at, temps[-1][0] - 120)
        culprits = []
        for pid, h in self.gpu_hist.items():
            vals = [u for t, u in h if t >= since]
            if vals:
                avg = sum(vals) / len(vals)
                if avg >= 2:
                    row = next((r for r in self.gpu_procs if r["pid"] == pid), None)
                    if row:
                        culprits.append({"pid": pid, "name": row["name"], "engine": row.get("engine", ""),
                                         "avg": round(avg, 1), "peak": round(max(vals), 1)})
        culprits.sort(key=lambda c: c["avg"], reverse=True)
        util = g.get("util") or 0
        reasons = []
        if g.get("throttle"):
            reasons.append(["bad", "Видеокарта перегревается и сбрасывает частоты (троттлинг)"])
        elif g.get("sw_thermal") or g.get("power_cap"):
            bat = (self.now.get("battery") or {})
            on_battery = bat and not bat.get("plugged")
            reasons.append(["info", "Частоты ограничены настройками питания ноутбука, а не перегревом"
                                    + (" — он работает от батареи" if on_battery else " (тихий/сбалансированный режим)")])
        if g.get("tlimit") is not None and g["tlimit"] <= 10:
            reasons.append(["bad", f"До порога троттлинга осталось {g['tlimit']:.0f}°C"])
        if culprits and culprits[0]["avg"] >= 15:
            c = culprits[0]
            kind = f" ({c['engine']})" if c.get("engine") else ""
            reasons.append(["info", f"Основная нагрузка — {c['name']}{kind}: в среднем {c['avg']}% (пик {c['peak']}%)"])
        if now_t >= 70 and util < 15:
            reasons.append(["warn", "Температура высокая при низкой нагрузке — похоже на плохое охлаждение: пыль, "
                                    "засохшая термопаста или ноутбук стоит на мягкой поверхности"])
        if powers and max(powers) >= 60:
            reasons.append(["info", f"Потребление доходило до {max(powers):.0f} Вт — карта работала в полную силу"])
        if g.get("pstate") == "P0" and util >= 50:
            reasons.append(["info", "Карта в режиме максимальной производительности (P0)"])
        if not reasons:
            reasons.append(["ok", "Нагрев в норме" if now_t < 70 else "Нагрев объясняется нагрузкой"])
        return {"now": now_t, "min": tmin, "max": tmax, "rise": round(now_t - tmin, 1), "tlimit": g.get("tlimit"),
                "throttle": bool(g.get("throttle")), "clock": g.get("clock"), "clock_max": g.get("clock_max"),
                "pstate": g.get("pstate"), "power": g.get("power"), "culprits": culprits[:6], "reasons": reasons,
                "window_s": round(temps[-1][0] - since)}

    def _gpu_apps(self):
        try:
            out = subprocess.run(["nvidia-smi", "--query-compute-apps=pid,used_memory", "--format=csv,noheader,nounits"],
                                 capture_output=True, text=True, timeout=10, creationflags=NO_WINDOW).stdout
            apps = {}
            for line in out.splitlines():
                a, b = [x.strip() for x in line.split(",")[:2]]
                if a.isdigit() and b.isdigit():
                    apps[int(a)] = int(b)
            self.gpu_apps = apps
        except Exception:
            pass

    # ------------------------------------------------------------ выдача
    def snapshot(self):
        self.touch()
        heat = self.heat_report()
        cpu_why = self.cpu_report()
        with self.lock:
            procs = sorted(self.procs, key=lambda r: r["cpu"], reverse=True)
            by_mem = sorted(self.procs, key=lambda r: r["mem"], reverse=True)
            sus = [r for r in self.procs if r["flags"]]
            return {"static": self.static, "now": dict(self.now), "gpu": self.gpu, "percpu": self.percpu,
                    "series": {k: list(v) for k, v in self.series.items()},
                    "top_cpu": procs[:12], "top_mem": by_mem[:12], "suspicious": sus,
                    "count": len(self.procs), "uptime": time.time() - self.static["boot"],
                    "gpu_procs": self.gpu_procs[:10], "heat": heat, "cpu_why": cpu_why,
                    "sensors": {k: v for k, v in (self.sensors or {}).items() if k != "raw"} if self.sensors else None,
                    "sensors_on": self.sensors_on,
                    "memclean_on": self.memclean_on,
                    "sensors_outdated": bool(self.sensors_on and sensors_outdated()),
                    "sensors_stuck": bool(self.sensors_on and self.sensors is None and self.sensors_wait
                                          and time.time() - self.sensors_wait > 25)}


METRICS = Metrics()


def kill(pid):
    p = psutil.Process(pid)
    name = p.name()
    p.terminate()
    try:
        p.wait(5)
    except psutil.TimeoutExpired:
        p.kill()
    return name
