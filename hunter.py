"""Охотник ScanHub: скрытые майнеры, следы стилеров/ClickFix и закрепление в системе — без загрузок и без базы вирусов.

Это детектив, а не антивирус: ничего не удаляет и не меняет. Возвращает находки с объяснением простыми словами
и *предложенными* безопасными действиями (выполняет их сервер ScanHub после согласия человека).

Главное правило — взвешивание улик. У каждой улики есть вес и роль:
  decisive — решающая (одной достаточно для «угрозы»);
  core     — самостоятельная улика;
  mod      — усилитель: считается только рядом с core/decisive и суммарно не больше 2× суммы core
             (поэтому «без подписи», «в папке пользователя», «порт 4444» сами по себе не дают ничего);
  neg      — оправдание (целая подпись).
Уровни: threat ≥ 100, suspicious ≥ 50, info ≥ 20, ниже — не показываем.
«Угроза» только когда: есть decisive, или ≥ 2 core, или ≥ 3 положительных улик. Дополнительно:
  * только содержимое файла (строки майнера, конфиг, скрипт) без «активности» (запущен, автозапуск, скрытность,
    подделка имени, сеть) — не выше suspicious: лежащий без дела набор майнера — ещё не заражение;
  * целая цифровая подпись + улики майнера без подделки имени — не выше suspicious («если ставил сам — всё в порядке»);
  * подпись системных оболочек (powershell, cmd, mshta…) ничего не оправдывает.

ТАБЛИЦА ВЕСОВ (она же — словарь W ниже)
  Команда запуска процесса
    CMD_STRATUM 100 decisive  адрес пула stratum+tcp/ssl:// в команде
    CMD_DONATE   50 core      --donate-level (есть только у майнеров)
    CMD_WALLET   45 core      кошелёк Monero / кошелёк после -u
    CMD_POOL     45 core      -o хост:порт пула вместе с -u или известным пулом
    CMD_ALGO     40 core      --algo/--coin rx/0, randomx, kawpow, ethash…
    CMD_FLAGS    15×n (≤45) core  --rig-id, --cpu-max-threads-hint, --cuda, --opencl, --nicehash…
    CMD_MENTION  40 core      то же, но в команде оболочки/интерпретатора (а не самой программы)
    CMD_BACKGROUND 10 mod     --background
  Содержимое файла
    FP_STRONG    70 core      несколько «отпечатков» майнера внутри exe (переживают переименование)
    FP_WEAK      25 core      одиночное упоминание
    VI_MISMATCH  15 mod       настоящее имя файла (в свойствах) не совпадает с именем на диске
    UPX          10 mod       упакован UPX
    CFG_MINER    45 core      настройки майнера (pools + randomx/cpu/donate-level/autosave)
    CFG_WALLET   25 mod       в настройках кошелёк или адрес пула
    SCR_STRATUM  60 core      скрипт с адресом пула stratum
    SCR_DONATE   50 core      скрипт с --donate-level
    SCR_WALLET   35 core      скрипт с кошельком
    SCR_POOL     35 core      скрипт с адресом пула
    SCR_ALGO     20 core      скрипт с алгоритмом добычи
    SCR_CRADLE   45 core      скрипт скачивает и сразу запускает код
    SCR_DEFENDER 45 core      скрипт отключает Defender / добавляет исключения
    SCR_HIDDEN   15 mod       скрипт прячет окно
    NEAR_KIT     30 mod       рядом лежат настройки/скрипт запуска майнера
  Обстоятельства
    RUNNING 20 mod · HIGH_CPU 15 mod · AUTORUN 30 mod · USER_DIR 10 mod · UNSIGNED 10 mod · BAD_SIG 25 mod
    POOL_PORT 5 mod · DEF_EXCLUDED 30 mod · SIG_TRUSTED −60 neg · SIG_VALID −15 neg
  Подделка под систему
    MASQ_PATH    70 core      имя системной программы, а лежит не в папке Windows
    MASQ_LOOKALIKE 45 core    имя, похожее на системное (svch0st, scvhost…)
  Скрытый запуск (процессы и автозагрузка)
    L_MSHTA_URL 70 · L_REGSVR_URL 70 · L_CRADLE 60 · L_DEFENDER 50 · L_OFFICE_PARENT 50 · L_LOLBIN_DL 45
    L_DOWNLOAD 35 · L_ENC 30 (все core) · L_SCRIPT_USERDIR 15 · L_DLL_USERDIR 15 · L_HIDDEN 15 · L_HEADLESS 15 (mod)
  Закрепление
    P_ACCESS 100 decisive · P_WINLOGON 70 · P_IFEO 60 · P_SPE 60 · P_WMI 55 · P_APPINIT 55 · P_IFEO_SEC 50
    P_LOGONSCRIPT 50 · P_FAKE_MS_TASK 50 · P_POLICYRUN 40 · P_SPE_ARMED 40 · P_TEMP_AUTORUN 35 · P_SVC_USERDIR 30 (core)
  «Физика майнера» — поведение, которое не спрятать упаковкой и переименованием (слой physics)
    B_OBSERVER_SHY 70 core    нагрузка пропадает, пока запущена программа с именем Диспетчера задач, и возвращается после
                              (глубокая проверка: безвредная «приманка» — копия ping.exe под именем Taskmgr.exe; два прогона подряд)
    L_SVCHOST_NOK  50 core    svchost.exe запущен без параметра -k (так выглядит подмена процесса)
    B_RANDOMX_MEM  30 core    скрытая программа под нагрузкой держит 2,05–2,75 ГБ своей памяти (набор данных RandomX)
    B_GPU_HIDDEN   30 core    скрытая программа без окна сильно нагружает видеокарту
    B_IDLE_RAMP    30 core    грузит компьютер, только когда человек отошёл (история наблюдений между проверками)
    B_FLAT_LOAD    18 core    скрытая программа ровно и без пауз грузит процессор (разброс ≤ 15 %)
    B_LOCK_PAGES   25 mod     у процесса есть право «Блокировка страниц в памяти» (обычным программам оно не выдаётся)
    B_WINRING0     25 mod     рядом лежит драйвер WinRing0 (майнеры разгоняют им добычу)
    B_SINGLE_REMOTE 20 mod    одно-единственное постоянное соединение с интернетом
    B_NO_IO        15 mod     при такой нагрузке почти не читает и не пишет на диск
    B_BUSY_THREADS 10 mod     почти все потоки программы — «рабочие» (нет обычных простаивающих)
    SYS_BIN       −30 neg     это программа из папки Windows (для неё нужны улики сильнее)
    P_HIDDEN_SCRIPT 30 core   скрипт из папки пользователя запускается скрытно
  ClickFix / стилеры (Win+R и история PowerShell)
    C_MSHTA 100 decisive · C_PIPE_SHELL 55 · C_CRADLE 45 · C_ENC 45 · C_LOLBIN_DL 40 (core)
    C_CAPTCHA 45 mod · C_RUNMRU 30 mod · C_RAWIP 20 mod · C_HIDDEN 15 mod · C_KNOWN_GOOD −70 neg (только история)
  Защита
    D_HOSTS_AV 60 · D_DEF_BAD 60 · D_POLICY_OFF 60 · D_RTP_OFF 55 · D_DEF_INFO 20 (core)
  Сеть
    N_POOL_CONN 60 · N_MALTRAIL_CONN 60 · N_POOL_DNS 30 · N_MALTRAIL_DNS 25 (core)

Запуск для проверки:  python -X utf8 hunter.py [--deep] [--json]
"""
import base64
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
from collections import deque

try:
    import psutil
except ImportError:                      # без psutil процессы читаем через PowerShell
    psutil = None
try:
    import winreg
except ImportError:
    winreg = None

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
CACHE_FILE = os.path.join(DATA, "hunter_cache.json")
ENV = os.environ
WINDIR = ENV.get("SystemRoot", r"C:\Windows").lower().rstrip("\\")
PF_DIRS = [p.lower().rstrip("\\") for p in filter(None, [ENV.get("ProgramFiles"), ENV.get("ProgramFiles(x86)"), ENV.get("ProgramW6432")])]
USER_DIRS = [p.lower().rstrip("\\") for p in filter(None, [ENV.get("TEMP"), ENV.get("APPDATA"), ENV.get("LOCALAPPDATA"),
                                                             ENV.get("ProgramData"), r"C:\Users\Public"])]
TEMP_DIRS = [p.lower().rstrip("\\") for p in filter(None, [ENV.get("TEMP"), WINDIR + r"\temp", r"C:\Users\Public"])]
# Своё: папка ScanHub, скрипты датчиков и очистки памяти в Program Files, данные в ProgramData
OWN_ROOTS = [p.lower().rstrip("\\") for p in (ROOT, os.path.join(ENV.get("ProgramFiles", r"C:\Program Files"), "ScanHub"),
                                               os.path.join(ENV.get("ProgramData", r"C:\ProgramData"), "ScanHub"))]

T_THREAT, T_SUSP, T_INFO = 100, 50, 20

# код: (вес, роль, категория, объяснение простыми словами)
W = {
    "CMD_STRATUM": (100, "decisive", "miner", "в команде запуска указан адрес майнинг-пула"),
    "CMD_DONATE": (50, "core", "miner", "в команде параметр --donate-level — он есть только у майнеров"),
    "CMD_WALLET": (45, "core", "miner", "в команде запуска указан кошелёк криптовалюты"),
    "CMD_POOL": (45, "core", "miner", "программа подключается к серверу добычи криптовалюты"),
    "CMD_ALGO": (40, "core", "miner", "в команде выбран алгоритм добычи криптовалюты"),
    "CMD_FLAGS": (15, "core", "miner", "в команде настройки, характерные для майнеров"),
    "CMD_MENTION": (40, "core", "miner", "в команде оболочки упоминается запуск майнера"),
    "CMD_BACKGROUND": (10, "mod", "miner", "запущена в фоне, без окна"),
    "FP_STRONG": (70, "core", "miner", "внутри файла — код майнера (его не скрыть переименованием)"),
    "FP_WEAK": (25, "core", "miner", "внутри файла упоминается майнинг"),
    "VI_MISMATCH": (15, "mod", "masquerade", "файл переименован: в его свойствах записано другое имя"),
    "UPX": (10, "mod", "miner", "файл сжат упаковщиком UPX — так часто прячут содержимое"),
    "CFG_MINER": (45, "core", "miner", "это файл настроек майнера"),
    "CFG_WALLET": (25, "mod", "miner", "в настройках указан кошелёк или адрес пула"),
    "SCR_STRATUM": (60, "core", "miner", "скрипт запускает добычу криптовалюты (в нём адрес пула)"),
    "SCR_DONATE": (50, "core", "miner", "в скрипте параметр --donate-level — он есть только у майнеров"),
    "SCR_WALLET": (35, "core", "miner", "в скрипте указан кошелёк криптовалюты"),
    "SCR_POOL": (35, "core", "miner", "в скрипте адрес сервера добычи криптовалюты"),
    "SCR_ALGO": (20, "core", "miner", "в скрипте выбран алгоритм добычи"),
    "SCR_CRADLE": (45, "core", "clickfix", "скрипт скачивает код из интернета и сразу его запускает"),
    "SCR_DEFENDER": (45, "core", "defense", "скрипт отключает защиту Windows или добавляет исключения"),
    "SCR_HIDDEN": (15, "mod", "miner", "скрипт прячет своё окно"),
    "NEAR_KIT": (30, "mod", "miner", "рядом лежат настройки или скрипт запуска майнера"),
    "RUNNING": (20, "mod", "miner", "программа сейчас запущена"),
    "HIGH_CPU": (15, "mod", "miner", "сейчас сильно нагружает процессор"),
    "AUTORUN": (30, "mod", "persistence", "запускается сама вместе с Windows"),
    "USER_DIR": (10, "mod", "persistence", "лежит в папке пользователя, а не там, куда ставятся программы"),
    "UNSIGNED": (10, "mod", "persistence", "нет цифровой подписи издателя"),
    "BAD_SIG": (25, "mod", "persistence", "цифровая подпись повреждена или недействительна"),
    "POOL_PORT": (5, "mod", "network", "соединение по порту, которым часто пользуются майнинг-пулы"),
    "DEF_EXCLUDED": (30, "mod", "defense", "файл спрятан от Защитника Windows (добавлен в исключения)"),
    "SIG_TRUSTED": (-60, "neg", "", "подписан известным издателем"),
    "SIG_VALID": (-15, "neg", "", "цифровая подпись цела"),
    "MASQ_PATH": (70, "core", "masquerade", "называется как системная программа Windows, но лежит не в папке Windows"),
    "MASQ_LOOKALIKE": (45, "core", "masquerade", "имя подделано под системную программу Windows"),
    "L_MSHTA_URL": (70, "core", "clickfix", "запускает код прямо из интернета через mshta"),
    "L_REGSVR_URL": (70, "core", "clickfix", "запускает код из интернета через системную утилиту"),
    "L_CRADLE": (60, "core", "clickfix", "скачивает код из интернета и сразу его выполняет"),
    "L_DEFENDER": (50, "core", "defense", "команда отключает защиту Windows или добавляет исключения"),
    "L_OFFICE_PARENT": (50, "core", "clickfix", "командную строку запустил документ Office — так работают вредоносные вложения"),
    "L_LOLBIN_DL": (45, "core", "clickfix", "скачивает файл системной утилитой, которой обычные программы так не пользуются"),
    "L_DOWNLOAD": (35, "core", "clickfix", "команда скачивает файл из интернета"),
    "L_ENC": (30, "core", "persistence", "команда зашифрована (Base64), чтобы её нельзя было прочитать"),
    "L_SCRIPT_USERDIR": (15, "mod", "persistence", "запускает скрипт из папки пользователя или временной папки"),
    "L_DLL_USERDIR": (15, "mod", "persistence", "загружает библиотеку из папки пользователя"),
    "L_HIDDEN": (15, "mod", "persistence", "запускается со скрытым окном"),
    "L_HEADLESS": (15, "mod", "persistence", "запускается через скрытую консоль"),
    "P_HIDDEN_SCRIPT": (30, "core", "persistence", "скрипт из папки пользователя запускается скрытно"),
    "L_SVCHOST_NOK": (50, "core", "masquerade", "системный процесс svchost запущен не так, как его запускает Windows (признак подмены)"),
    "B_OBSERVER_SHY": (70, "core", "miner", "программа перестаёт грузить компьютер, как только открывается Диспетчер задач, и продолжает, когда он закрыт"),
    "B_RANDOMX_MEM": (30, "core", "miner", "скрытая программа держит в памяти около 2 ГБ — столько нужно для добычи Monero"),
    "B_GPU_HIDDEN": (30, "core", "miner", "программа без окна сильно нагружает видеокарту"),
    "B_IDLE_RAMP": (30, "core", "miner", "грузит компьютер только тогда, когда ты отходишь"),
    "B_FLAT_LOAD": (18, "core", "miner", "скрытая программа ровно и без пауз нагружает процессор"),
    "B_LOCK_PAGES": (25, "mod", "miner", "у программы есть редкое право «блокировка страниц в памяти» — майнеры выдают его себе для скорости"),
    "B_WINRING0": (25, "mod", "miner", "рядом лежит драйвер WinRing0 — майнеры ускоряют им добычу"),
    "B_SINGLE_REMOTE": (20, "mod", "miner", "держит одно постоянное соединение с интернетом"),
    "B_NO_IO": (15, "mod", "miner", "при этом почти не обращается к диску"),
    "B_BUSY_THREADS": (10, "mod", "miner", "почти все её потоки заняты счётом"),
    "SYS_BIN": (-30, "neg", "", "это программа из папки Windows"),
    "P_ACCESS": (100, "decisive", "persistence", "подменена системная программа экрана входа — так получают доступ без пароля"),
    "P_WINLOGON": (70, "core", "persistence", "подменён запуск при входе в Windows"),
    "P_IFEO": (60, "core", "persistence", "вместо одной программы Windows запускает другую (перехват запуска)"),
    "P_SPE": (60, "core", "persistence", "при закрытии одной программы тайно запускается другая"),
    "P_WMI": (55, "core", "persistence", "скрытый автозапуск через WMI — в обычном списке автозагрузки его не видно"),
    "P_APPINIT": (55, "core", "persistence", "библиотека встраивается во все программы (AppInit_DLLs)"),
    "P_IFEO_SEC": (50, "core", "defense", "перехвачен запуск системной или защитной программы"),
    "P_LOGONSCRIPT": (50, "core", "persistence", "сценарий входа пользователя — редкий способ автозапуска"),
    "P_FAKE_MS_TASK": (50, "core", "masquerade", "задача планировщика выдаёт себя за задачу Microsoft"),
    "P_POLICYRUN": (40, "core", "persistence", "автозапуск через политики — обычные программы так не делают"),
    "P_SPE_ARMED": (40, "core", "persistence", "слежение за закрытием программы включено"),
    "P_TEMP_AUTORUN": (35, "core", "persistence", "автозапуск из временной или общей папки"),
    "P_SVC_USERDIR": (30, "core", "persistence", "служба Windows запускается из папки пользователя"),
    "C_MSHTA": (100, "decisive", "clickfix", "запуск кода из интернета через mshta"),
    "C_PIPE_SHELL": (55, "core", "clickfix", "скачанное из интернета сразу передано в командную строку"),
    "C_CRADLE": (45, "core", "clickfix", "команда скачивает код из интернета и сразу выполняет"),
    "C_ENC": (45, "core", "clickfix", "команда зашифрована (Base64)"),
    "C_LOLBIN_DL": (40, "core", "clickfix", "скачивание файла системной утилитой"),
    "C_CAPTCHA": (45, "mod", "clickfix", "в команде текст «я не робот» — приём мошеннических сайтов"),
    "C_RUNMRU": (30, "mod", "clickfix", "команду вставили в окно «Выполнить» (Win+R) — так делают по указке поддельных сайтов"),
    "C_RAWIP": (20, "mod", "clickfix", "адрес — голые цифры IP, а не имя сайта"),
    "C_HIDDEN": (15, "mod", "clickfix", "окно спрятано"),
    "C_KNOWN_GOOD": (-70, "neg", "", "адрес известного установщика"),
    "D_HOSTS_AV": (60, "core", "defense", "файл hosts перекрывает сайты антивирусов или обновлений Windows"),
    "D_DEF_BAD": (60, "core", "defense", "в Защитнике Windows опасное исключение или выключенная защита"),
    "D_POLICY_OFF": (60, "core", "defense", "Защитник Windows выключен через политики"),
    "D_RTP_OFF": (55, "core", "defense", "постоянная защита выключена, а другого антивируса нет"),
    "D_DEF_INFO": (20, "core", "defense", "в Защитнике Windows есть исключения"),
    "N_POOL_CONN": (60, "core", "network", "программа соединена с сервером майнинг-пула"),
    "N_MALTRAIL_CONN": (60, "core", "network", "программа соединена с адресом из базы вредоносных серверов"),
    "N_POOL_DNS": (30, "core", "network", "компьютер недавно искал адрес майнинг-пула"),
    "N_MALTRAIL_DNS": (25, "core", "network", "компьютер недавно обращался к адресу из базы вредоносных серверов"),
}
CONTENT_ONLY = {"FP_STRONG", "FP_WEAK", "VI_MISMATCH", "UPX", "CFG_MINER", "CFG_WALLET", "SCR_STRATUM", "SCR_DONATE", "SCR_WALLET",
                "SCR_POOL", "SCR_ALGO", "SCR_CRADLE", "SCR_DEFENDER", "NEAR_KIT", "USER_DIR", "UNSIGNED", "BAD_SIG", "SIG_TRUSTED",
                "SIG_VALID", "DEF_EXCLUDED"}
MINER_CODES = {c for c, v in W.items() if v[2] == "miner" and v[1] != "mod"} | {"N_POOL_CONN"}

# ---------------------------------------------------------------- справочники

TRUSTED_RE = re.compile(
    r"microsoft|google|nvidia|advanced micro devices|\bamd\b|intel|valve|discord|epic games|riot games|electronic arts|ubisoft|"
    r"battleye|easyanticheat|easy anti-cheat|jetbrains|python software foundation|mozilla|adobe|logitech|razer|lenovo|apple|oracle|"
    r"github|openjs|node\.js|docker|zoom video|telegram|spotify|opera|brave software|yandex|vivaldi|anthropic|openai|blizzard|"
    r"rockstar|mojang|roblox|vmware|samsung|asustek|micro-star|giga-byte|realtek|qualcomm|dell|hp inc|hewlett|corsair|steelseries|"
    r"autodesk|figma|slack|dropbox|wargaming|lesta|kaspersky|eset|doctor web|malwarebytes|avast|avg tech|bitdefender|sophos|"
    r"emsisoft|gen digital|nortonlifelock|mcafee|trend micro|f-secure|withsecure|cloudflare|igor pavlov|win\.rar|rarlab|"
    r"notepad\+\+|obs project|videolan|the git|johannes schindelin|postgresql|enterprisedb|unity technologies|steam|xiaomi|"
    r"tencent|bytedance|whatsapp|meta platforms|amazon|atlassian|postman|cursor|anysphere|exafunction|tailscale|wireguard|proton", re.I)
SECURITY_RE = re.compile(r"microsoft|kaspersky|eset|doctor web|malwarebytes|avast|avg tech|bitdefender|sophos|emsisoft|gen digital|"
                         r"nortonlifelock|mcafee|trend micro|f-secure|withsecure|hybrid analysis|virustotal", re.I)

SYSTEM_NAMES = {  # имя → где обязано лежать (относительно папки Windows)
    "svchost": ("system32", "syswow64"), "explorer": ("", "syswow64"), "csrss": ("system32",), "lsass": ("system32",),
    "smss": ("system32",), "wininit": ("system32",), "winlogon": ("system32",), "services": ("system32",),
    "conhost": ("system32", "syswow64"), "taskhostw": ("system32",), "dwm": ("system32",), "runtimebroker": ("system32",),
    "spoolsv": ("system32",), "sihost": ("system32",), "ctfmon": ("system32", "syswow64"), "dllhost": ("system32", "syswow64"),
    "audiodg": ("system32",), "searchindexer": ("system32", "syswow64"), "fontdrvhost": ("system32",),
    "lsm": ("system32",), "wudfhost": ("system32",), "rundll32": ("system32", "syswow64"), "taskmgr": ("system32", "syswow64"),
}
LOOKALIKE_OK = {"taskhost", "service", "iexplore", "explorer++", "explore", "console", "servicehost", "host", "dllhst3g"}
LOLBINS = {"powershell", "pwsh", "cmd", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "conhost", "certutil", "bitsadmin",
           "msiexec", "schtasks", "wmic", "curl", "explorer", "forfiles", "pcalua", "installutil", "msbuild", "regasm", "regsvcs",
           "odbcconf", "cmstp", "hh", "control", "svchost", "taskeng", "dllhost"}
SHELLS = {"cmd", "powershell", "pwsh", "bash", "sh", "zsh", "wsl", "python", "pythonw", "py", "node", "conhost", "wt", "openconsole",
          "windowsterminal", "git-bash", "mintty", "busybox", "ruby", "perl", "php", "java", "javaw", "deno", "bun", "wscript", "cscript"}
TEXT_TOOLS = {"grep", "rg", "findstr", "ag", "git", "code", "notepad", "notepad++", "less", "more", "cat", "sed", "awk", "find",
              "claude", "cursor", "sublime_text", "devenv", "idea64", "pycharm64", "webstorm64", "yara", "yara64", "strings", "strings64"}
OFFICE = {"winword", "excel", "powerpnt", "outlook", "msaccess", "mspub", "onenote", "wps", "et", "wpp", "acrord32", "acrobat"}
SEC_TARGETS = {"taskmgr.exe", "msmpeng.exe", "mpcmdrun.exe", "mrt.exe", "regedit.exe", "msconfig.exe", "sethc.exe", "utilman.exe",
               "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe", "atbroker.exe", "procexp.exe", "procexp64.exe",
               "autoruns.exe", "autoruns64.exe", "mbam.exe", "avp.exe", "ekrn.exe", "cureit.exe", "securityhealthservice.exe",
               "smartscreen.exe", "rstrui.exe", "cmd.exe", "powershell.exe", "scanhub.exe", "minersearch.exe"}
TASKMGR_REPLACERS = re.compile(r"procexp|systeminformer|processhacker|taskmgr|taskexplorer", re.I)

MINING_PORTS = {3333, 3334, 3335, 3336, 3357, 4444, 5555, 5588, 6666, 7777, 8899, 9999, 10128, 10300, 13333, 14433, 14444,
                15555, 17777, 20535, 20580, 45560, 45700}
STRICT_POOL_RE = re.compile(
    r"(nanopool\.org|2miners\.com|f2pool\.com|supportxmr\.com|hashvault\.pro|moneroocean\.stream|herominers\.com|nicehash\.com|"
    r"ethermine\.org|unmineable\.com|minergate\.com|c3pool\.(com|org)|kryptex\.(network|org|com)|zergpool\.com|woolypooly\.com|"
    r"flexpool\.io|coinhive\.com|cryptoloot\.pro|minexmr\.com|xmrpool\.(eu|net)|monerohash\.com|dwarfpool\.com|ravenminer\.com|"
    r"viabtc\.(com|net)|antpool\.com|xmrig\.com|pool\.hashvault|gulf\.moneroocean|rx\.unmineable|p2pool\.io|miningocean\.org|"
    r"ezil\.me|hiveon\.(net|com)|k1pool\.com|skypool\.org|zpool\.ca|prohashing\.com|mining-dutch\.nl|bohemianpool\.com)", re.I)

STRATUM_RE = re.compile(r"stratum\d?\+(?:tcp|ssl|tls|udp)://[\w.\-]+(?::\d+)?", re.I)
XMR_RE = re.compile(r"(?<![0-9A-Za-z])[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?:[1-9A-HJ-NP-Za-km-z]{11})?(?![0-9A-Za-z])")
USER_WALLET_RE = re.compile(r"(?:^|\s)(?:-u|--user|--wallet|--wal)[= ]+[\"']?(?:[A-Za-z]{2,8}:)?"
                            r"(0x[a-fA-F0-9]{40}|bc1[ac-hj-np-z02-9]{20,}|[13][1-9A-HJ-NP-Za-km-z]{25,34}|[A-Za-z0-9]{34,})(?![\w\\/])")
POOL_ARG_RE = re.compile(r"(?:^|\s)(?:-o|--url|--pool|-P|--server|--stratum)[= ]+[\"']?(?:\w+://)?([\w\-]+(?:\.[\w\-]+)+):(\d{2,5})\b", re.I)
USER_ARG_RE = re.compile(r"(?:^|\s)(?:-u|--user|--wallet)[= ]+\S", re.I)
ALGO_RE = re.compile(r"(?:^|\s)(?:--algo|--coin|-a)[= ]+[\"']?(rx/\w+|randomx|cn(?:-\w+)?/[\w\-]+|cryptonight[\w/\-]*|kawpow|ethash|etchash|"
                     r"autolykos2?|octopus|firopow|progpow\w*|equihash[\w,]*|ghostrider|monero|xmr|verushash|astrobwt[\w/]*|"
                     r"argon2/\w+|panthera|beamhash\w*|cuckatoo\d*|nexapow|karlsenhash|kheavyhash)(?![\w])", re.I)
FLAG_RE = re.compile(r"(?<![\w\-])(--rig-id|--cpu-max-threads-hint|--randomx-[\w\-]+|--cuda(?:-[\w\-]+)?|--opencl(?:-[\w\-]+)?|--nicehash|"
                     r"--cpu-priority|--no-huge-pages|--huge-pages|--max-cpu-usage|--donate-over-proxy|--cpu-affinity|"
                     r"--asm|--cpu-no-yield|--pass|--keepalive|--no-color|--print-time|--tls-fingerprint)(?![\w\-])", re.I)
DONATE_RE = re.compile(r"(?<![\w\-])--donate-level(?![\w\-])", re.I)
BACKGROUND_RE = re.compile(r"(?<![\w\-])(--background|-B)(?=\s|$)")

DL_RE = re.compile(r"\b(iwr|irm|invoke-webrequest|invoke-restmethod|curl(?:\.exe)?|wget|downloadstring|downloaddata|"
                   r"net\.webclient|start-bitstransfer|httpclient|xmlhttp|winhttp)\b", re.I)
IEX_RE = re.compile(r"(\|\s*iex\b|\biex\s*[\(\$&\"']|\binvoke-expression\b|\|\s*invoke-expression|\biex\s*$|\[scriptblock\]::create|"
                    r"\.invoke\(\)|&\s*\(\s*\[scriptblock\])", re.I)
URL_RE = re.compile(r"https?://[^\s\"'|)<>]+", re.I)
BARE_HOST_RE = re.compile(r"\b(?:irm|iwr|curl(?:\.exe)?|wget)\s+(?:-\w+\s+)*[\"']?((?:[\w\-]+\.)+[a-z]{2,})(?:/[^\s\"'|]*)?", re.I)
ENC_RE = re.compile(r"(?:^|\s)[-/]e(?:nc|ncodedcommand|c|ncodedc\w*|n|nco\w*)?\s+[\"']?([A-Za-z0-9+/=]{40,})", re.I)
HIDDEN_RE = re.compile(r"(?:^|\s)[-/]w(?:in|indowstyle)?\s+(?:h(?:id(?:den)?)?|1)\b|\bwindowstyle\s+hidden\b|-nowindow\b|createnowindow", re.I)
HEADLESS_RE = re.compile(r"\bconhost(?:\.exe)?[\"']?\s+--headless\b", re.I)
DEFENDER_RE = re.compile(r"(add-mppreference\s+.*-exclusion|set-mppreference\s+.*-disable\w+\s+(?:\$true|1)|"
                         r"disableantispyware|sc\s+(?:stop|delete|config)\s+windefend|mpcmdrun(?:\.exe)?[\"']?\s+-removedefinitions)", re.I)
LOLBIN_DL_RE = re.compile(r"(certutil(?:\.exe)?\s+.*-urlcache|certutil(?:\.exe)?\s+.*-decode\b|bitsadmin(?:\.exe)?\s+.*/transfer|"
                          r"msiexec(?:\.exe)?\s+.*[/-][iq]\w*\s+.*https?://|msiexec(?:\.exe)?\s+.*https?://)", re.I)
MSHTA_RE = re.compile(r"\bmshta(?:\.exe)?[\"']?\s+[\"']?(https?://|javascript:|vbscript:|\\\\)", re.I)
REGSVR_RE = re.compile(r"(regsvr32(?:\.exe)?\s+.*(/i:\s*https?://|scrobj\.dll)|rundll32(?:\.exe)?\s+.*(javascript:|vbscript:|https?://))", re.I)
PIPE_SHELL_RE = re.compile(r"\b(curl(?:\.exe)?|wget|iwr|irm)\b[^|]*\|\s*(cmd|powershell|pwsh|sh|bash)\b", re.I)
CAPTCHA_RE = re.compile(r"(not a robot|я не робот|recaptcha|captcha|verification\s*(id|code|hash)|cloudflare|human verif|✅|"
                        r"подтвержд\w+,? что вы человек|ray id)", re.I)
RAWIP_RE = re.compile(r"(?:https?://|\s)(?!127\.|10\.|192\.168\.|0\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?=[/\s\"'|]|$)")
SCRIPT_PATH_RE = re.compile(r"[\"']?((?:[A-Za-z]:\\|%\w+%\\|\\\\)[^\"'|<>*?&\r\n]*?\.(?:vbs|vbe|js|jse|wsf|wsh|hta|ps1|bat|cmd))(?=[\"'\s,]|$)", re.I)
DLL_PATH_RE = re.compile(r"[\"']?((?:[A-Za-z]:\\|%\w+%\\)[^\"'|<>*?\r\n,]*?\.(?:dll|ocx|cpl|dat|bin|tmp))(?=[\"'\s,]|$)", re.I)
SCR_HIDDEN_RE = re.compile(r"(-w(?:indowstyle)?\s+h(?:idden)?\b|\.run\s*\(?[^\r\n]*,\s*0\b|start\s+/min\b|start\s+/b\b|createnowindow|"
                           r"vbhide|sw_hide|windowstyle\s*=\s*['\"]?hidden|shellexecute[^\r\n]*,\s*0\s*\)?)", re.I)
KNOWN_GOOD_RE = re.compile(
    r"(?:^|[./@])(get\.scoop\.sh|chocolatey\.org|claude\.ai|anthropic\.com|astral\.sh|bun\.sh|deno\.land|christitus\.com|"
    r"massgrave\.dev|get\.activated\.win|rustup\.rs|pnpm\.io|aka\.ms|microsoft\.com|ohmyposh\.dev|github\.com|"
    r"githubusercontent\.com|ollama\.com|opencode\.ai|tailscale\.com|starship\.rs|vercel\.app|cursor\.com|openai\.com|"
    r"docker\.com|python\.org|nodejs\.org|volta\.sh|mise\.run|moonrepo\.dev|npmjs\.(com|org)|pypa\.io|windows\.net|"
    r"jetbrains\.com|google\.com|googleapis\.com|cloudflare\.com|huggingface\.co|localhost|127\.0\.0\.1)(?=[/:\s\"'|]|$)", re.I)
SECRET_RES = [
    (re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|token|secret|api[_-]?key|apikey|access[_-]?key|auth(?:orization)?|bearer|key|credential)"
                r"(\s*[=:]\s*|\s+)([\"']?)[^\s\"'|;&]{4,}"), r"\1\2\3***"),
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"), "://***:***@"),
    (re.compile(r"\b(gh[pousr]_|sk-|xox[bap]-|AKIA|AIza|glpat-|hf_)[A-Za-z0-9_\-]{8,}"), r"\1***"),
    (re.compile(r"[A-Za-z0-9+/_\-]{28,}={0,2}"), lambda m: m.group(0)[:6] + "…"),
]

# «Отпечатки» майнеров в файле: (строка в нижнем регистре, очки). ≥ 5 очков — сильный отпечаток, 2–4 — слабый.
NEEDLES = [
    (b"donate.v2.xmrig.com", 3), (b"--donate-level", 3), (b"xmr-stak", 3), (b"phoenixminer", 3), (b"nbminer", 3), (b"lolminer", 3),
    (b"srbminer", 3), (b"nanominer", 3), (b"teamredminer", 3), (b"mining.authorize", 3), (b"mining.subscribe", 3),
    (b"stratum+tcp://", 3), (b"stratum+ssl://", 3), (b"t-rex nvidia gpu miner", 3), (b"gminer", 2), (b"wildrig", 3),
    (b"xmrig", 2), (b"nicehash", 2), (b"cpuminer", 2), (b"ethminer", 2), (b"moneroocean", 2), (b"supportxmr", 2),
    (b"nanopool.org", 2), (b"2miners.com", 2), (b"hashvault.pro", 2), (b"unmineable", 2), (b"minexmr", 2),
    (b"randomx", 1), (b"cryptonight", 1), (b"kawpow", 1), (b"ethash", 1), (b"autolykos", 1), (b"ghostrider", 1),
    (b"--cpu-max-threads-hint", 2), (b"--rig-id", 2),
    (b"x\0m\0r\0i\0g\0", 2), (b"l\0o\0l\0m\0i\0n\0e\0r\0", 3), (b"n\0b\0m\0i\0n\0e\0r\0", 3), (b"p\0h\0o\0e\0n\0i\0x\0m\0i\0n\0e\0r\0", 3),
    (b"s\0r\0b\0m\0i\0n\0e\0r\0", 3), (b"n\0a\0n\0o\0m\0i\0n\0e\0r\0", 3), (b"t\0e\0a\0m\0r\0e\0d\0m\0i\0n\0e\0r\0", 3),
]
# Быстрый отсев: каждая строка из NEEDLES содержит хотя бы один «якорь» — без якоря кусок файла дальше не разбираем.
ANCHORS = [b"xmr", b"miner", b"stratum", b"randomx", b"cryptonight", b"mining.", b"kawpow", b"ethash", b"autolykos", b"donate",
           b"nicehash", b"ghostrider", b"wildrig", b"--rig-id", b"--cpu-max", b"moneroocean", b"nanopool", b"hashvault", b"unmineable",
           b"x\0m\0r\0", b"m\0i\0n\0e\0r\0"]
VI_KEY = "OriginalFilename".encode("utf-16le")

EXE_EXT = (".exe", ".scr", ".com", ".pif")
SCRIPT_EXT = (".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta")
CFG_NAMES = {"config.json", "config.txt", "pools.txt", "pools.json", "cpu.txt", "nvidia.txt", "amd.txt", "config.ini", "miner.json",
             "miner.conf", "config.cfg", "start.json", "settings.json", "appsettings.json"}
SKIP_DIRS = {"node_modules", ".git", ".svn", "__pycache__", "site-packages", "user data", "windowsapps", "windows defender",
             "windows defender advanced threat protection", "package cache", "npm-cache", ".nuget", "crashdumps", "d3dscache",
             "inetcache", "temporary internet files", "gpucache", "code cache", "cachestorage", "service worker", "indexeddb",
             "local storage", "session storage", "shadercache", "grshadercache", "fontcache", "winsxs", "assembly", "$recycle.bin",
             "system volume information", "docker", "wsl", "ollama-models", "quarantine", "yara", "signatures", "definition updates",
             "typescript", "cached_data", "blob_storage", "dawncache", "pip", "uv", "cargo", "go-build", "gradle", "maven", "conda",
             "windowspowershell", "modules", "dotnet", "nuget", "vscode-cpptools", "extensions", "jedi", "ms-playwright"}
SKIP_DIRS_QUICK = {"cache", "caches", "cache2", "packages", "installer", "logs", "log", "locales", "resources", "lib", "libs",
                   "include", "share", "doc", "docs", "fonts", "icons", "images", "assets", "media", "sounds", "localization", "lang",
                   "translations", "plugins", "themes", "history", "microsoft.net", "squirreltemp", "updates", "update"}
SKIP_PATH_RE = re.compile(r"\\(mozilla\\firefox\\profiles|opera software\\[^\\]+|yandex\\yandexbrowser\\user data|"
                          r"microsoft\\(edge|edgewebview|edgeupdate|onedrive|teams|office|visualstudio|vscode|windows\\(inetcache|"
                          r"webcache|explorer|history|caches|fonts|apprepository|wer|notifications|powershell)|"
                          r"search\\data|diagnosis|windows nt|netframework|network|provisioning|storage health|"
                          r"devicesync|identitycrl|mapdata|smsrouter|crypto|vault|credentials|protect|systemcertificates)|"
                          r"jetbrains|programs\\(python|microsoft vs code|cursor)|claude|anthropic|\.vscode|"
                          r"steam\\(steamapps|htmlcache|appcache)|nvidia corporation\\(nv_cache|drs|downloader)|"
                          r"package cache|usoshared|regid\.[^\\]+|ssh|comms|connecteddevicesplatform)(\\|$)", re.I)


# ================================================================ чистые функции (их проверяет dev\hunter_selftest.py)

def _low(p):
    return (p or "").lower().replace("/", "\\").rstrip("\\")


def base_name(path):
    """Имя файла без расширения, в нижнем регистре: C:\\x\\SvcHost.EXE → svchost."""
    b = os.path.basename((path or "").replace("/", "\\").strip('"')).lower()
    return b[:-4] if b.endswith((".exe", ".com", ".scr", ".pif")) else b


def under(path, dirs):
    p = _low(path)
    return any(p == d or p.startswith(d + "\\") for d in dirs if d)


def in_user_dir(path, user_dirs=None):
    return under(path, USER_DIRS if user_dirs is None else user_dirs)


def in_system_dir(path):
    return under(path, [WINDIR] + PF_DIRS)


def exe_from_command(cmd):
    """Путь к запускаемому файлу из строки команды (как system.exe_from_command, без зависимостей)."""
    if not cmd:
        return ""
    cmd = os.path.expandvars(cmd.strip())
    if cmd.startswith('"'):
        return cmd[1:].split('"', 1)[0]
    m = re.match(r"(.+?\.(exe|com|bat|cmd|vbs|js|ps1|scr|lnk))(\s|$)", cmd, re.I)
    return m.group(1) if m else cmd.split(" ")[0]


def is_own(cmd="", exe="", own_roots=None):
    """Своё ли это: файл из папки ScanHub или известная форма команды наших задач (датчики, очистка памяти, сторож).
    Смотрим на путь и форму команды, а не на название: «ScanHub» в имени задачи ничего не даёт."""
    roots = OWN_ROOTS if own_roots is None else [_low(r) for r in own_roots]
    if exe and under(exe, roots):
        return True
    c = os.path.expandvars(cmd or "").strip()
    if not c:
        return False
    if ENC_RE.search(c) or IEX_RE.search(c) or URL_RE.search(c):
        return False
    paths = re.findall(r'"([^"]+)"', c) + [t for t in c.split() if ":\\" in t]
    paths = [p.strip('"') for p in paths]
    first = exe_from_command(c)
    host = base_name(first)
    # conhost --headless powershell … -File "<наша папка>\x.ps1"   |   powershell … -File "<наша папка>\x.ps1"
    m = re.search(r'-File\s+"?([^"]+?\.ps1)"?\s*$', c, re.I)
    if host in ("conhost", "powershell") and m and under(m.group(1), roots):
        if host == "powershell" or re.match(r'^"?[^"]*conhost(\.exe)?"?\s+--headless\s+powershell(\.exe)?\s', c, re.I):
            return True
    # "<python>\pythonw.exe" "<ScanHub>\scanhub.py" …
    if host in ("python", "pythonw", "py"):
        scripts = [p for p in paths if p.lower().endswith((".py", ".pyw"))]
        if scripts and under(scripts[0], roots):
            return True
    if under(first, roots):
        return True
    return False


def edit_distance(a, b, cap=3):
    """Расстояние Дамерау — Левенштейна (перестановка соседних букв = 1)."""
    if abs(len(a) - len(b)) >= cap:
        return cap
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                v = min(v, prev2[j - 2] + 1)
            cur.append(v)
        prev2, prev = prev, cur
    return min(prev[-1], cap)


_HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a", "!": "i"})


def masquerade_signals(name, exe):
    """Подделка под системную программу. name — имя процесса/файла, exe — полный путь ('' — путь неизвестен, не судим)."""
    n = base_name(name or exe)
    if not n or not exe:
        return []
    p = _low(exe)
    if n in SYSTEM_NAMES:
        allowed = [(WINDIR + "\\" + d).rstrip("\\") for d in SYSTEM_NAMES[n]]
        d = os.path.dirname(p)
        if d in allowed or under(p, [WINDIR + r"\winsxs", WINDIR + r"\servicing", WINDIR + r"\softwaredistribution",
                                     WINDIR + r"\systemapps", WINDIR + r"\system32\dllcache"]):
            return []
        return [("MASQ_PATH", f"{os.path.basename(exe)} в {os.path.dirname(exe)}")]
    if under(p, [WINDIR]) or n in LOOKALIKE_OK or len(n) < 4:
        return []
    h = n.translate(_HOMO)
    for s in SYSTEM_NAMES:
        if len(s) < 5:
            continue
        if (h == s and n != s) or (edit_distance(n, s) == 1 and abs(len(n) - len(s)) <= 1):
            return [("MASQ_LOOKALIKE", f"{os.path.basename(exe)} ≈ {s}.exe")]
    return []


def cmd_signals(cmd):
    """Улики майнера в команде запуска процесса."""
    c = cmd or ""
    if len(c) < 8:
        return []
    out = []
    m = STRATUM_RE.search(c)
    if m:
        out.append(("CMD_STRATUM", m.group(0)[:80]))
    if DONATE_RE.search(c):
        out.append(("CMD_DONATE", "--donate-level"))
    m = XMR_RE.search(c) or USER_WALLET_RE.search(c)
    pool = POOL_ARG_RE.search(c)
    if m and (m.re is XMR_RE or pool or out):
        w = m.group(0).strip() if m.re is XMR_RE else m.group(1)
        out.append(("CMD_WALLET", w[:8] + "…" + w[-4:]))
    if pool:
        host, port = pool.group(1), int(pool.group(2))
        if STRICT_POOL_RE.search(host) or (USER_ARG_RE.search(c) and (port in MINING_PORTS or re.search(r"pool|mine|xmr|hash", host, re.I))):
            out.append(("CMD_POOL", f"{host}:{port}"))
    m = ALGO_RE.search(c)
    if m:
        out.append(("CMD_ALGO", m.group(1)))
    flags = sorted({f.lower() for f in FLAG_RE.findall(c)})
    for f in flags[:3]:
        out.append(("CMD_FLAGS", f))
    if out and BACKGROUND_RE.search(c):
        out.append(("CMD_BACKGROUND", "--background"))
    # одиночные --pass/--asm/--opencl встречаются у обычных программ: без других улик — не считаем
    if out and all(code == "CMD_FLAGS" for code, _ in out) and len(out) < 2:
        return []
    return out


def decode_enc(cmd):
    """Расшифровать -EncodedCommand (Base64 UTF-16LE). '' — если не получилось."""
    m = ENC_RE.search(cmd or "")
    if not m:
        return ""
    try:
        b = m.group(1)
        raw = base64.b64decode(b + "=" * (-len(b) % 4))
        t = raw.decode("utf-16le", "ignore")
        return t if sum(ch.isprintable() or ch in "\r\n\t" for ch in t) > len(t) * 0.9 else ""
    except Exception:
        return ""


def launcher_signals(cmd, user_dirs=None):
    """Улики скрытого запуска в команде (процесс или запись автозагрузки). Возвращает (улики, путь_скрипта_или_'')."""
    c = os.path.expandvars(cmd or "")
    if len(c) < 6:
        return [], ""
    out, script = [], ""
    host = base_name(exe_from_command(c))
    inner = decode_enc(c)
    text = c + ("\n" + inner if inner else "")
    if MSHTA_RE.search(text):
        out.append(("L_MSHTA_URL", "mshta + адрес"))
    if REGSVR_RE.search(text):
        out.append(("L_REGSVR_URL", "regsvr32/rundll32 + адрес"))
    dl, iex = DL_RE.search(text), IEX_RE.search(text)
    if dl and iex and (URL_RE.search(text) or BARE_HOST_RE.search(text)):
        out.append(("L_CRADLE", f"{dl.group(1)} … iex"))
    elif dl and URL_RE.search(text) and host in LOLBINS and re.search(r"downloadfile|-outfile|-o\s|start-process|\.exe\b.*https?://|https?://.*\.(exe|dll|ps1|bat|vbs|msi)\b", text, re.I):
        out.append(("L_DOWNLOAD", dl.group(1)))
    if DEFENDER_RE.search(text):
        out.append(("L_DEFENDER", "Add/Set-MpPreference"))
    if LOLBIN_DL_RE.search(text):
        out.append(("L_LOLBIN_DL", "certutil/bitsadmin/msiexec + адрес"))
    if host in ("powershell", "pwsh", "cmd", "conhost") and ENC_RE.search(c) and re.search(r"powershell|pwsh", c, re.I):
        out.append(("L_ENC", "Base64" + ("" if inner else " (не расшифровалось)")))
    if host in LOLBINS:
        m = SCRIPT_PATH_RE.search(c)
        if m and in_user_dir(m.group(1), user_dirs):
            script = m.group(1)
            out.append(("L_SCRIPT_USERDIR", script[-80:]))
        if host in ("rundll32", "regsvr32"):
            m = DLL_PATH_RE.search(c)
            if m and in_user_dir(m.group(1), user_dirs):
                out.append(("L_DLL_USERDIR", m.group(1)[-80:]))
    if out or host in LOLBINS:
        if HIDDEN_RE.search(c):
            out.append(("L_HIDDEN", "-WindowStyle Hidden"))
        if HEADLESS_RE.search(c):
            out.append(("L_HEADLESS", "conhost --headless"))
    for code, ev in cmd_signals(inner):
        out.append((code, ev))
    codes = {c for c, _ in out}
    if "L_SCRIPT_USERDIR" in codes and codes & {"L_HIDDEN", "L_HEADLESS"}:
        out.append(("P_HIDDEN_SCRIPT", os.path.basename(script)))
    return out, script


def script_signals(text):
    """Улики в тексте скрипта (.bat/.cmd/.ps1/.vbs/.js): запуск майнера, скачивание-и-запуск, отключение защиты."""
    t = text or ""
    out = []
    flat = re.sub(r"[\^`]\s*\r?\n\s*", " ", t)          # склеить переносы строк cmd (^) и PowerShell (`)
    mp = {"CMD_STRATUM": "SCR_STRATUM", "CMD_DONATE": "SCR_DONATE", "CMD_WALLET": "SCR_WALLET", "CMD_POOL": "SCR_POOL", "CMD_ALGO": "SCR_ALGO"}
    seen = set()
    for line in flat.splitlines() or [flat]:
        for code, ev in cmd_signals(line[:4000]):
            code = mp.get(code)
            if code and code not in seen:
                seen.add(code)
                out.append((code, ev))
    if "SCR_STRATUM" not in seen:
        m = STRATUM_RE.search(t)
        if m:
            out.append(("SCR_STRATUM", m.group(0)[:80]))
    dl, iex = DL_RE.search(t), IEX_RE.search(t)
    if dl and iex and URL_RE.search(t) and not KNOWN_GOOD_RE.search(" ".join(URL_RE.findall(t)[:5])):
        out.append(("SCR_CRADLE", f"{dl.group(1)} … iex"))
    if DEFENDER_RE.search(t):
        out.append(("SCR_DEFENDER", "Add/Set-MpPreference"))
    if out and SCR_HIDDEN_RE.search(t):
        out.append(("SCR_HIDDEN", "скрытое окно"))
    return out


def config_signals(text):
    """Файл настроек майнера: pools + (randomx | cpu | donate-level | autosave), либо формат xmr-stak."""
    t = (text or "")[:300000]
    low = t.lower()
    out = []
    xmrig = '"pools"' in low and any(k in low for k in ('"randomx"', '"cpu"', '"donate-level"', '"autosave"'))
    stak = '"pool_list"' in low and ('"wallet_address"' in low or '"pool_address"' in low)
    if not (xmrig or stak):
        return out
    out.append(("CFG_MINER", "pools + " + ", ".join(k for k in ("randomx", "donate-level", "autosave", "cpu", "pool_list") if f'"{k}"' in low)))
    url = re.search(r'"(?:url|pool_address)"\s*:\s*"([^"]{4,120})"', t, re.I)
    user = re.search(r'"(?:user|wallet_address)"\s*:\s*"([^"]{20,130})"', t, re.I)
    if (url and (STRATUM_RE.search(url.group(1)) or STRICT_POOL_RE.search(url.group(1)) or re.search(r":\d{3,5}$", url.group(1)))) \
            or (user and (XMR_RE.search(user.group(1)) or len(user.group(1)) >= 34)):
        out.append(("CFG_WALLET", (url.group(1)[:60] if url else "кошелёк")))
    return out


def mask_secrets(s, limit=160):
    """Спрятать пароли/ключи/длинные коды и обрезать — в находки попадает только такая строка."""
    s = re.sub(r"\s+", " ", s or "").strip()
    for rx, rep in SECRET_RES:
        s = rx.sub(rep, s)
    return s if len(s) <= limit else s[:limit - 1] + "…"


def clickfix_signals(cmd, source="history"):
    """Следы ClickFix/стилера в одной команде. source: 'runmru' (окно «Выполнить») или 'history' (история PowerShell)."""
    c = (cmd or "").strip()
    if len(c) < 8:
        return []
    out = []
    inner = decode_enc(c)
    text = c + ("\n" + inner if inner else "")
    if MSHTA_RE.search(text):
        out.append(("C_MSHTA", "mshta + адрес"))
    dl, iex = DL_RE.search(text), IEX_RE.search(text)
    has_url = URL_RE.search(text) or BARE_HOST_RE.search(text)
    if PIPE_SHELL_RE.search(text) and has_url:
        out.append(("C_PIPE_SHELL", "скачать | командная строка"))
    elif dl and iex and has_url:
        out.append(("C_CRADLE", f"{dl.group(1)} … iex"))
    if ENC_RE.search(c) and re.search(r"powershell|pwsh", c, re.I):
        out.append(("C_ENC", "Base64"))
    if LOLBIN_DL_RE.search(text) or REGSVR_RE.search(text):
        out.append(("C_LOLBIN_DL", "certutil/bitsadmin/msiexec/regsvr32 + адрес"))
    if not out:
        return []
    if CAPTCHA_RE.search(text):
        out.append(("C_CAPTCHA", CAPTCHA_RE.search(text).group(0)[:30]))
    if HIDDEN_RE.search(text):
        out.append(("C_HIDDEN", "-w hidden"))
    if RAWIP_RE.search(text):
        out.append(("C_RAWIP", RAWIP_RE.search(text).group(1)))
    if source == "runmru":
        out.append(("C_RUNMRU", "Win+R"))
    else:
        hosts = [u for u in URL_RE.findall(text)] + [m for m in BARE_HOST_RE.findall(text)]
        if hosts and all(KNOWN_GOOD_RE.search(re.sub(r"^https?://", "", h).split("/")[0]) for h in hosts) \
                and not any(code in ("C_CAPTCHA", "C_MSHTA", "C_RAWIP") for code, _ in out):
            out.append(("C_KNOWN_GOOD", re.sub(r"^https?://", "", hosts[0]).split("/")[0]))
    return out


def autorun_signals(item, user_dirs=None):
    """Пере-оценка записи system.autoruns() общими весами. Возвращает (улики, путь_скрипта, lolbin?)."""
    kind, name, cmd = item.get("kind") or "", item.get("name") or "", item.get("cmd") or ""
    exe = item.get("exe") or ""
    host = base_name(exe)
    lol = host in LOLBINS and under(exe, [WINDIR])
    out, script = launcher_signals(cmd, user_dirs)
    if kind == "WMI-подписка":
        out.append(("P_WMI", name[:60]))
    elif kind == "Вход в Windows":
        out.append(("P_WINLOGON", f"{name} = {cmd[:80]}"))
    elif kind == "Перехват запуска":
        spe = (item.get("where") or "") == "SilentProcessExit"
        out.append(("P_SPE" if spe else "P_IFEO", f"{name} → {cmd[:80]}"))
        if item.get("armed"):
            out.append(("P_SPE_ARMED", "GlobalFlag 0x200"))
        if name.lower() in SEC_TARGETS and not (name.lower() == "taskmgr.exe" and TASKMGR_REPLACERS.search(cmd)):
            out.append(("P_IFEO_SEC", name))
    elif kind == "AppInit_DLLs":
        out.append(("P_APPINIT", cmd[:80]))
    elif kind == "Сценарий входа":
        out.append(("P_LOGONSCRIPT", cmd[:80]))
    elif kind == "Реестр (политики)":
        out.append(("P_POLICYRUN", name[:60]))
    elif kind == "Экран входа" or item.get("replaced"):
        out.append(("P_ACCESS", name))
    elif kind == "Служба (не авто)" or (kind == "Служба" and in_user_dir(exe, user_dirs) and not lol):
        if in_user_dir(exe, user_dirs):
            out.append(("P_SVC_USERDIR", name[:60]))
    if kind == "Задача" and (item.get("where") or "").lower().startswith("\\microsoft\\") and exe and not in_system_dir(exe):
        out.append(("P_FAKE_MS_TASK", (item.get("where") or "") + name))
    if exe and not lol and under(exe, TEMP_DIRS if user_dirs is None else [d for d in user_dirs if "temp" in d or "public" in d]):
        out.append(("P_TEMP_AUTORUN", exe[-80:]))
    return out, script, lol


def evaluate(signals, signed=None):
    """Чистый подсчёт. signals — {код: [улики]} или список кодов. → (очки, уровень или None)."""
    codes = list(signals)
    counts = {c: (len(signals[c]) if isinstance(signals, dict) and isinstance(signals[c], (list, tuple)) else 1) for c in codes}
    core = sum(W[c][0] * (min(counts[c], 3) if c == "CMD_FLAGS" else 1) for c in codes if W[c][1] in ("core", "decisive"))
    mods = sum(W[c][0] for c in codes if W[c][1] == "mod")
    neg = sum(W[c][0] for c in codes if W[c][1] == "neg")
    score = core + (min(mods, 2 * core) if core else 0) + neg
    decisive = any(W[c][1] == "decisive" for c in codes)
    ncore = sum(1 for c in codes if W[c][1] in ("core", "decisive"))
    npos = sum(1 for c in codes if W[c][0] > 0)
    level = None
    if score >= T_THREAT and (decisive or ncore >= 2 or npos >= 3):
        level = "threat"
    elif score >= T_SUSP:
        level = "suspicious"
    elif score >= T_INFO:
        level = "info"
    if level == "threat":
        if all(c in CONTENT_ONLY for c in codes):
            level = "suspicious"                      # лежит без дела — не заражение
        elif ("SIG_TRUSTED" in codes or "SIG_VALID" in codes) and not any(c.startswith(("MASQ", "P_", "L_")) for c in codes) \
                and any(c in MINER_CODES for c in codes):
            level = "suspicious"                      # подписанный майнер — скорее поставлен самим человеком
    if "FP_STRONG" in codes and level is None and core:
        level = "info"                                # подписанный файл с кодом майнера всё равно показываем
    return max(score, 0), level


# ================================================================ отпечатки в файле

def fingerprint_file(path, limit=40 << 20, tail=2 << 20, stopped=lambda: False):
    """Прочитать файл кусками (не больше limit с начала + tail с конца) и найти отпечатки майнеров.
    → {"pts", "hits", "upx", "orig", "mz", "partial"} или None, если файл не читается."""
    try:
        size = os.path.getsize(path)
        f = open(path, "rb")
    except OSError:
        return None
    res = {"pts": 0, "hits": [], "upx": False, "orig": "", "mz": False, "partial": size > limit + tail}
    found = {}
    chunk_size, overlap = 4 << 20, 96
    try:
        with f:
            head = f.read(4096)
            res["mz"] = head[:2] == b"MZ"
            res["upx"] = b"UPX0" in head and b"UPX1" in head
            f.seek(0)
            prev, read = b"", 0
            spans = [(0, min(size, limit))] + ([(size - tail, size)] if size > limit + tail else [])
            for start, end in spans:
                f.seek(start)
                pos, prev = start, b""
                while pos < end and not stopped():
                    data = f.read(min(chunk_size, end - pos))
                    if not data:
                        break
                    pos += len(data)
                    read += len(data)
                    buf = prev + data
                    prev = data[-overlap:]
                    if not res["orig"]:
                        i = buf.find(VI_KEY)
                        if i >= 0:
                            raw = buf[i + len(VI_KEY):i + len(VI_KEY) + 300].lstrip(b"\0")
                            if len(raw) % 2:
                                raw = raw[:-1]
                            res["orig"] = raw.decode("utf-16le", "ignore").split("\0")[0].strip()[:80]
                    low = buf.lower()
                    if not any(a in low for a in ANCHORS):
                        continue
                    for needle, pts in NEEDLES:
                        if needle not in found and needle in low:
                            found[needle] = pts
    except OSError:
        return None
    # одинаковые по смыслу строки (ASCII и UTF-16) считаем один раз
    names = {}
    for needle, pts in found.items():
        n = needle.replace(b"\0", b"").decode("ascii", "replace")
        names[n] = max(names.get(n, 0), pts)
    if not any(v >= 2 for v in names.values()):
        names = {}                        # одни названия алгоритмов («ethash» есть внутри «GetHash») — не улика
    res["hits"] = sorted(names, key=lambda n: -names[n])[:12]
    res["pts"] = sum(names.values())
    return res


def fp_signals(fp, path):
    """Улики из отпечатков файла."""
    if not fp:
        return []
    out = []
    if fp["pts"] >= 5:
        out.append(("FP_STRONG", ", ".join(fp["hits"][:6])))
    elif fp["pts"] >= 2:
        out.append(("FP_WEAK", ", ".join(fp["hits"][:4])))
    if fp.get("upx"):
        out.append(("UPX", "секции UPX0/UPX1"))
    orig = base_name(fp.get("orig") or "")
    disk = base_name(path)
    if orig and disk and len(orig) >= 3:
        o, d = re.sub(r"\.(dll|mui|tmp)$", "", orig), re.sub(r"[\s_\-.()\d]+", "", disk)
        o2 = re.sub(r"[\s_\-.()\d]+", "", o)
        if o2 and d and o2 not in d and d not in o2:
            out.append(("VI_MISMATCH", f"настоящее имя: {fp['orig']}"))
    return out


# ================================================================ «физика майнера»: поведение вместо строк
#
# Упаковщик прячет строки, переименование — имя, но майнер не может перестать быть майнером:
# он ровно и без пауз считает, почти не трогает диск, держит одно соединение с пулом, RandomX занимает ~2 ГБ,
# скрытные сборки затихают при Диспетчере задач и разгоняются, когда человек отошёл. Это и измеряем.

def _mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def _cv(xs):
    """Коэффициент вариации: разброс относительно среднего (0 — идеально ровно)."""
    m = _mean(xs)
    if not xs or m <= 0:
        return 9.0
    return (sum((x - m) ** 2 for x in xs) / len(xs)) ** 0.5 / m


def physics_signals(feat):
    """Поведенческие улики одного процесса. feat:
      cpu        — [доля всех ядер, %] по секундам;   ncpu — логических ядер
      hidden     — нет видимого окна ни у него, ни у родителей, ни у «братьев» с тем же файлом
      private_mb — собственная память;  threads — потоков;  io_bps — обмен с диском, байт/с
      remotes    — число разных внешних адресов, с которыми есть соединение
      lock_pages — в токене есть SeLockMemoryPrivilege;  gpu — нагрузка на видеокарту, % (или None)
      winring0   — рядом лежит WinRing0*.sys
    Основные улики (flat/память/видеокарта) — только для скрытых процессов; остальные их усиливают."""
    cpu = [c for c in (feat.get("cpu") or []) if c is not None]
    ncpu = feat.get("ncpu") or 1
    m, cv = _mean(cpu), _cv(cpu)
    out = []
    if not feat.get("hidden"):
        return out
    if len(cpu) >= 6 and m >= 10 and cv <= 0.15:
        out.append(("B_FLAT_LOAD", f"{m:.0f}% всех ядер, разброс {cv * 100:.0f}%"))
    priv = feat.get("private_mb") or 0
    if len(cpu) >= 4 and m >= 6 and 2050 <= priv <= 2750:
        out.append(("B_RANDOMX_MEM", f"{priv:.0f} МБ своей памяти"))
    gpu = feat.get("gpu")
    if gpu is not None and gpu >= 50:
        out.append(("B_GPU_HIDDEN", f"видеокарта {min(gpu, 100):.0f}%"))
    if not out:
        return out
    if feat.get("io_bps") is not None and feat["io_bps"] < 65536:
        out.append(("B_NO_IO", f"{feat['io_bps'] / 1024:.0f} КБ/с"))
    if feat.get("remotes") == 1:
        out.append(("B_SINGLE_REMOTE", feat.get("remote") or "1 адрес"))
    if feat.get("lock_pages"):
        out.append(("B_LOCK_PAGES", "SeLockMemoryPrivilege"))
    if feat.get("winring0"):
        out.append(("B_WINRING0", str(feat["winring0"])[-60:]))
    busy = m / 100 * ncpu
    thr = feat.get("threads") or 0
    if thr and busy >= 1.5 and thr <= busy + 8:
        out.append(("B_BUSY_THREADS", f"{thr} потоков, занято ≈{busy:.0f}"))
    return out


def observer_shy(base, during, after):
    """Опыт с «приманкой»: нагрузка до, во время и после появления процесса с именем Диспетчера задач.
    True — если была устойчивая нагрузка, она упала минимум на 70 % и затем вернулась минимум на 60 %."""
    base, during, after = [x for x in base if x is not None], [x for x in during if x is not None], [x for x in after if x is not None]
    if len(base) < 4 or len(during) < 3 or len(after) < 3:
        return False
    mb = _mean(base)
    return mb >= 4 and _cv(base) <= 0.35 and _mean(during) <= 0.3 * mb and _mean(after) >= 0.6 * mb


def idle_correlation(obs):
    """obs — [(сколько секунд человек не трогал мышь/клавиатуру, нагрузка %)] из разных наблюдений.
    True — если программа грузит компьютер, только когда человек отошёл."""
    idle = [c for i, c in obs if i >= 120]
    active = [c for i, c in obs if i < 30]
    if len(idle) < 3 or len(active) < 3:
        return False
    mi = _mean(idle)
    return mi >= 15 and _mean(active) <= 0.25 * mi


def winring0_suspicious(image, user_dirs=None):
    """Драйвер WinRing0 в папке пользователя/временной папке (а не в папке известной программы для железа)."""
    p = _low(os.path.expandvars(image or ""))
    p = re.sub(r"^\\\?\?\\", "", p)
    return bool(p) and "winring0" in os.path.basename(p) and in_user_dir(p, user_dirs)


# ================================================================ сборка находок

class Ent:
    """Один «подозреваемый»: файл, процесс без файла, запись автозагрузки, след команды или системная настройка."""

    def __init__(self, key, kind, path="", name=""):
        self.key, self.kind, self.path, self.name = key, kind, path, name
        self.signals = {}          # код → [улики]
        self.pids = []
        self.autoruns = []         # [{"kind","where","name","cmd"}]
        self.cmd = ""
        self.sig = None            # {"status","signer"}
        self.no_sig = False        # подпись ничего не значит (системная оболочка)
        self.when = ""
        self.hosts = []            # сайты из команды (до обрезки — для ответа «откуда скачивалось»)
        self.title = ""
        self.note = ""

    def add(self, code, ev=""):
        lst = self.signals.setdefault(code, [])
        if ev and ev not in lst and len(lst) < 4:
            lst.append(ev)

    def core(self):
        return any(W[c][1] in ("core", "decisive") for c in self.signals)


LEVEL_ORDER = {"threat": 0, "suspicious": 1, "info": 2}
CAT_TITLES = {
    "miner": {"threat": "Скрытый майнер", "suspicious": "Похоже на программу для майнинга", "info": "Упоминание майнинга"},
    "persistence": {"threat": "Вредоносный автозапуск", "suspicious": "Подозрительный автозапуск", "info": "Необычный автозапуск"},
    "masquerade": {"threat": "Подделка под системную программу", "suspicious": "Программа выдаёт себя за системную",
                   "info": "Имя похоже на системное"},
    "clickfix": {"threat": "След заражения через поддельную «проверку»", "suspicious": "Опасная команда из интернета",
                 "info": "Команда скачивала и запускала код"},
    "defense": {"threat": "Защита Windows выведена из строя", "suspicious": "Защита Windows ослаблена", "info": "Настройки защиты"},
    "network": {"threat": "Связь с вредоносным сервером", "suspicious": "Подозрительное соединение", "info": "Сетевой след"},
}
WHY_LEAD = {
    ("miner", "threat"): "Это похоже на скрытый майнер: программа добывает криптовалюту для чужого человека за счёт твоего компьютера. "
                         "Из-за неё компьютер греется, шумит и тормозит. Для файлов опасности нет, но её нужно убрать.",
    ("miner", "suspicious"): "Это программа (или её части) для добычи криптовалюты. Если ты ставил майнер сам — всё в порядке, "
                             "можно ничего не делать. Если нет — её стоит убрать: кто-то может зарабатывать на твоём компьютере.",
    ("miner", "info"): "Внутри файла есть упоминания майнинга, но серьёзных признаков нет. Скорее всего, это обычная программа. "
                       "Делать ничего не нужно.",
    ("persistence", "threat"): "Что-то закрепилось в системе способом, которым пользуются вредоносные программы, чтобы запускаться "
                               "при каждом включении и оставаться незаметными.",
    ("persistence", "suspicious"): "Эта запись запускается сама вместе с Windows необычным способом. Так делают и вредоносные программы, "
                                   "и некоторые обычные. Если не знаешь, что это, — лучше отключить (это обратимо).",
    ("persistence", "info"): "Необычный, но не обязательно опасный способ автозапуска. Если программу ставил ты — всё в порядке.",
    ("masquerade", "threat"): "Программа притворяется частью Windows — называется как системная, но лежит в чужой папке. "
                              "Настоящие системные программы так не делают; это типичная маскировка вирусов.",
    ("masquerade", "suspicious"): "Программа называется как системная (или очень похоже), но находится не там, где положено. "
                                  "Это частый приём маскировки. Проверь её онлайн, прежде чем что-то делать.",
    ("masquerade", "info"): "Имя напоминает системную программу. Серьёзных признаков нет — скорее всего, совпадение.",
    ("clickfix", "threat"): "Похоже, на этом компьютере выполнили команду с мошеннического сайта (поддельная «проверка, что вы не робот» "
                            "или «исправление ошибки»). Такие команды ставят программы, которые крадут пароли и сессии из браузера.",
    ("clickfix", "suspicious"): "Эта команда скачивает код из интернета и сразу его запускает. Так работают и некоторые установщики, "
                                "и мошеннические «проверки». Если вводил её не ты и не по инструкции, которой доверяешь, — считай опасной.",
    ("clickfix", "info"): "Когда-то была выполнена команда, которая скачивает и запускает код из интернета. Если это был установщик, "
                          "который ты запускал сам, — всё в порядке.",
    ("defense", "threat"): "Защита Windows отключена или обойдена так, как это делают вирусы, чтобы антивирус их не видел.",
    ("defense", "suspicious"): "Защита Windows ослаблена. Если это настраивал не ты — это мог сделать вирус, чтобы спрятаться.",
    ("defense", "info"): "В настройках защиты есть изменения. Скорее всего, их сделал ты или одна из твоих программ.",
    ("network", "threat"): "Программа на компьютере связана с сервером, который известен как вредоносный или майнинговый.",
    ("network", "suspicious"): "Программа соединена с адресом из списка подозрительных. Списки иногда ошибаются, поэтому стоит проверить, "
                               "что это за программа.",
    ("network", "info"): "Компьютер недавно обращался к адресу, связанному с майнингом или из списка подозрительных. Это могло быть "
                         "и открытие сайта в браузере. Само по себе не опасно.",
}
TODO = {
    "threat": "Что делать: нажми предложенное действие ниже — ScanHub ничего не удаляет безвозвратно, всё можно вернуть.",
    "suspicious": "Что делать: если не знаешь, что это, — проверь онлайн или отключи. Если знаешь и ставил сам — ничего.",
    "info": "Что делать: ничего, это просто к сведению.",
}
# совет точнее общего — для находок, где решает «это был ты или нет»
TODO_CAT = {
    ("clickfix", "info"): "Если эту команду вводил ты сам (например, по инструкции к программе, которой доверяешь) — всё в порядке, "
                          "нажми «Это был я». Если не помнишь — запусти глубокую проверку и смени пароли в браузере: так часто ставят воришек паролей.",
    ("clickfix", "suspicious"): "Если команду вводил не ты или ты сделал это по просьбе сайта («подтверди, что ты не робот») — "
                                "сразу смени пароли от почты и банка с другого устройства и запусти глубокую и ультра проверку.",
    ("clickfix", "threat"): "Смени пароли от почты, банка и соцсетей с другого устройства (телефона), выйди из всех сеансов, "
                            "затем запусти ультра проверку — она найдёт то, что успело поставиться.",
}
HOST_RE = re.compile(r"(?=https?://([^/\s'\"|;]+)([^\s'\"|;]*))", re.I)   # с заглядыванием: ловит и адрес внутри адреса


def cmd_hosts(cmd):
    """Сайты из команды по порядку: «aizaozao.com», «raw.githubusercontent.com/автор/проект»."""
    out = []
    for host, rest in HOST_RE.findall(cmd or ""):
        h = host.lower()
        if h in ("raw.githubusercontent.com", "github.com", "gist.githubusercontent.com"):
            h += "/" + "/".join([x for x in rest.split("/") if x][:2])
        if h not in out:
            out.append(h)
    return out[:4]


# ---------------------------------------------------------------- «это был я»: скрытые человеком находки
IGNORE_FILE = os.path.join(DATA, "hunter_ignore.json")


def load_ignored():
    try:
        with open(IGNORE_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def set_ignored(d):
    os.makedirs(DATA, exist_ok=True)
    tmp = IGNORE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(tmp, IGNORE_FILE)


def summarize(found, stopped=False):
    """Вердикт и строка итога по списку находок."""
    n = {lv: sum(1 for f in found if f["level"] == lv) for lv in ("threat", "suspicious", "info")}
    verdict = "threat" if n["threat"] else "suspicious" if n["suspicious"] else "info" if n["info"] else "clean"
    label = (f"найдено опасного: {n['threat']}" + (f", подозрительного: {n['suspicious']}" if n["suspicious"] else "") if n["threat"] else
             f"подозрительного: {n['suspicious']} — стоит посмотреть" if n["suspicious"] else
             f"опасного не найдено; к сведению: {n['info']}" if n["info"] else
             "скрытых майнеров, следов стилеров и вредоносного автозапуска не найдено")
    if stopped:
        label = "проверка остановлена; " + label
    return verdict, label, n


def finding_id(category, key):
    return hashlib.sha1(f"{category}|{key}".lower().encode("utf-8", "replace")).hexdigest()[:12]


def build_finding(ent):
    """Ent → находка (или None, если улик мало)."""
    score, level = evaluate(ent.signals)
    if not level:
        return None
    pos = sorted((c for c in ent.signals if W[c][0] > 0), key=lambda c: (-(W[c][1] in ("decisive", "core")), -W[c][0]))
    cat = next((W[c][2] for c in pos if W[c][2]), "persistence")
    # подделка имени вместе с кодом майнера — это майнер; ClickFix-след остаётся ClickFix
    if any(c in MINER_CODES for c in ent.signals) and cat in ("masquerade", "persistence", "network"):
        cat = "miner"
    what = ent.name or (os.path.basename(ent.path) if ent.path else "")
    title = ent.title or (CAT_TITLES[cat][level] + (f": {what}" if what else ""))
    reasons = [W[c][3] for c in pos][:6]
    neg = [W[c][3] for c in ent.signals if W[c][0] < 0]
    why = WHY_LEAD[(cat, level)]
    if ent.note:
        why += " " + ent.note
    why += " Почему так решил: " + "; ".join(reasons) + "."
    if neg:
        why += " В пользу программы: " + "; ".join(neg) + (f" ({ent.sig['signer']})" if ent.sig and ent.sig.get("signer") else "") + "."
    if ent.when:
        why += f" Примерная дата: {ent.when}."
    why += " " + ("Что делать: " + TODO_CAT[(cat, level)] if (cat, level) in TODO_CAT else TODO[level])
    evidence = []
    for c in pos + [c for c in ent.signals if W[c][0] < 0]:
        ev = "; ".join(ent.signals[c])
        evidence.append(f"{c} {W[c][0]:+d}" + (f": {ev}" if ev else ""))
    if ent.cmd:
        evidence.append("команда: " + mask_secrets(ent.cmd, 200))
    for a in ent.autoruns[:3]:
        evidence.append(f"автозапуск: {a['kind']} · {a.get('where') or ''} · {a['name']}")
    if ent.sig:
        evidence.append(f"подпись: {ent.sig.get('status')} {ent.sig.get('signer') or ''}".strip())
    actions = []
    strong = level in ("threat", "suspicious")
    is_file = bool(ent.path) and os.path.isfile(ent.path) and not under(ent.path, [WINDIR])
    if strong:
        for pid in ent.pids[:3]:
            actions.append({"kind": "kill", "target": pid, "label": f"Остановить процесс (PID {pid})"})
        for a in ent.autoruns[:4]:
            if a["kind"] == "Задача":
                actions.append({"kind": "disable_task", "target": (a.get("where") or "\\") + a["name"],
                                "label": f"Отключить задачу «{a['name']}»"})
            else:
                actions.append({"kind": "disable_autorun", "target": {"kind": a["kind"], "where": a.get("where") or "", "name": a["name"]},
                                "label": f"Отключить автозапуск «{a['name']}»"})
        if is_file:
            if ent.path.lower().endswith(EXE_EXT + (".dll",)):
                actions.append({"kind": "quarantine", "target": ent.path, "label": "Убрать файл в карантин (можно вернуть)"})
            else:
                actions.append({"kind": "recycle", "target": ent.path, "label": "Убрать файл в Корзину"})
    if is_file:
        if ent.path.lower().endswith(EXE_EXT + (".dll",)):
            actions.append({"kind": "online_check", "target": ent.path, "label": "Проверить файл онлайн"})
        actions.append({"kind": "open_folder", "target": ent.path, "label": "Показать в папке"})
    return {"id": finding_id(cat, ent.key), "level": level, "score": score, "category": cat, "title": title, "why": why,
            "lead": WHY_LEAD[(cat, level)] + (" " + ent.note if ent.note else ""), "reasons": reasons,
            "pros": neg + ([ent.sig["signer"]] if neg and ent.sig and ent.sig.get("signer") else []),
            "todo": TODO_CAT.get((cat, level)) or TODO[level].replace("Что делать: ", "").capitalize(),
            "cmd": mask_secrets(ent.cmd, 300) if ent.cmd else "", "hosts": ent.hosts or cmd_hosts(ent.cmd), "when": ent.when,
            "evidence": evidence, "path": ent.path or "", "pid": ent.pids[0] if ent.pids else None, "actions": actions}


def explain(finding):
    """Находка одним понятным текстом (для отчёта, ИИ-агента, окна «подробнее»)."""
    lvl = {"threat": "ОПАСНО", "suspicious": "ПОДОЗРИТЕЛЬНО", "info": "к сведению"}[finding["level"]]
    lines = [f"[{lvl}] {finding['title']}", finding["why"]]
    if finding.get("path"):
        lines.append("Файл: " + finding["path"])
    if finding.get("evidence"):
        lines.append("Улики: " + " | ".join(finding["evidence"]))
    if finding.get("actions"):
        lines.append("Можно сделать: " + "; ".join(a["label"] for a in finding["actions"]))
    return "\n".join(lines)


# ================================================================ охотник

class Hunter:
    """Собирает улики со всех слоёв в «подозреваемых» и превращает их в находки.
    Для проверок все внешние зависимости подменяются: user_dirs, own_roots, sign (функция подписей), cache_file."""

    def __init__(self, mode="quick", emit=print, stopped=lambda: False, user_dirs=None, own_roots=None, sign=None, cache_file=CACHE_FILE):
        self.mode, self.emit, self.stopped = mode, emit, stopped
        self.deep = mode == "deep"
        self.user_dirs = USER_DIRS if user_dirs is None else [_low(d) for d in user_dirs]
        self.own_roots = OWN_ROOTS if own_roots is None else [_low(d) for d in own_roots]
        self.sign = sign
        self.cache_file = cache_file
        self.ents = {}
        self.fp_queue = {}          # путь(lower) → (путь, приоритет)
        self.stats = {"mode": mode, "layers": {}, "errors": {}, "not_checked": []}
        self.cache = {"v": 3, "fp": {}, "sig": {}, "hist": {}}
        self.cache_dirty = False
        self._load_cache()
        self.fp_limit = (96 << 20) if self.deep else (24 << 20)

    # ---- кэш
    def _load_cache(self):
        try:
            if self.cache_file and os.path.exists(self.cache_file):
                c = json.load(open(self.cache_file, encoding="utf-8"))
                if c.get("v") == 3:
                    self.cache = c
                    for part in ("fp", "sig", "hist"):
                        self.cache.setdefault(part, {})
        except (OSError, ValueError):
            pass

    def save_cache(self):
        if not (self.cache_file and self.cache_dirty):
            return
        try:
            for part in ("fp", "sig"):
                d = self.cache[part]
                if len(d) > 20000:                       # не даём кэшу расти бесконечно
                    for k in list(d)[:len(d) - 15000]:
                        d.pop(k, None)
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            tmp = self.cache_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False)
            os.replace(tmp, self.cache_file)
        except OSError:
            pass

    @staticmethod
    def _stamp(path):
        try:
            st = os.stat(path)
            return [st.st_size, int(st.st_mtime)]
        except OSError:
            return None

    def fingerprint(self, path):
        st = self._stamp(path)
        if not st:
            return None
        k = _low(path)
        c = self.cache["fp"].get(k)
        if c and c[0] == st and c[2] == (1 if self.deep else 0) or (c and c[0] == st and not c[1].get("partial")):
            self.stats["fp_cached"] = self.stats.get("fp_cached", 0) + 1
            return c[1]
        fp = fingerprint_file(path, self.fp_limit, stopped=self.stopped)
        if fp is not None and not self.stopped():
            self.cache["fp"][k] = [st, fp, 1 if self.deep else 0]
            self.cache_dirty = True
            self.stats["fp_read"] = self.stats.get("fp_read", 0) + 1
        return fp

    # ---- «подозреваемые»
    def ent(self, key, kind, path="", name=""):
        e = self.ents.get(key)
        if not e:
            e = self.ents[key] = Ent(key, kind, path, name)
        return e

    def file_ent(self, path):
        return self.ent("f:" + _low(path), "file", path)

    def own(self, cmd="", exe=""):
        return is_own(cmd, exe, self.own_roots)

    def queue_fp(self, path, prio=5):
        k = _low(path)
        if k not in self.fp_queue or self.fp_queue[k][1] > prio:
            self.fp_queue[k] = (path, prio)

    # ---- слой процессов
    def add_process(self, p):
        """p: {pid, ppid, name, exe, cmd, parent} — всё, что удалось узнать о процессе."""
        name, exe, cmd = p.get("name") or "", p.get("exe") or "", p.get("cmd") or ""
        if self.own(cmd, exe):
            self.stats["own_skipped"] = self.stats.get("own_skipped", 0) + 1
            return None
        n = base_name(name or exe)
        sigs = []
        if n not in TEXT_TOOLS:
            cs = cmd_signals(cmd)
            if cs and n in SHELLS:
                sigs.append(("CMD_MENTION", ", ".join(ev for _, ev in cs)[:100]))
            else:
                sigs += cs
        script = ""
        if n in LOLBINS or n in SHELLS:
            ls, script = launcher_signals(cmd, self.user_dirs)
            sigs += [s for s in ls if not s[0].startswith("CMD_")]
            if base_name(p.get("parent") or "") in OFFICE and n in ("powershell", "pwsh", "cmd", "mshta", "wscript", "cscript", "rundll32", "regsvr32"):
                sigs.append(("L_OFFICE_PARENT", p.get("parent")))
        sigs += masquerade_signals(name, exe)
        if n == "svchost" and cmd.strip() and under(exe, [WINDIR]) and not re.search(r"\s[-/]k\s", cmd + " ", re.I):
            sigs.append(("L_SVCHOST_NOK", mask_secrets(cmd, 80)))
        system = (not exe) or under(exe, [WINDIR]) and not any(c.startswith("MASQ") for c, _ in sigs)
        if system:
            if not sigs:
                return None
            e = self.ent(f"p:{p.get('pid')}", "proc", "", name)
            e.no_sig = True
        else:
            e = self.file_ent(exe)
            if not in_system_dir(exe) or sigs:
                self.queue_fp(exe, 1 if in_user_dir(exe, self.user_dirs) else 2)
            if in_user_dir(exe, self.user_dirs):
                e.add("USER_DIR")
        e.add("RUNNING", f"PID {p.get('pid')}")
        if p.get("pid") is not None and p["pid"] not in e.pids:
            e.pids.append(p["pid"])
        if sigs and not e.cmd:
            e.cmd = cmd
        for code, ev in sigs:
            e.add(code, ev)
        if script:
            self._script_into(e, script)
        return e

    def _script_into(self, e, script):
        """Автозапуск/процесс запускает скрипт из папки пользователя — читаем сам скрипт и добавляем его улики."""
        script = os.path.expandvars(script)
        if self.own(exe=script):
            return
        try:
            if os.path.getsize(script) <= 512 << 10:
                for code, ev in script_signals(read_text(script)):
                    e.add(code, ev)
                if not e.path:
                    e.path = script
        except OSError:
            pass

    # ---- слой автозагрузки
    def add_autorun(self, item):
        cmd, exe = item.get("cmd") or "", item.get("exe") or ""
        if self.own(cmd, exe):
            self.stats["own_skipped"] = self.stats.get("own_skipped", 0) + 1
            return None
        sigs, script, lol = autorun_signals(item, self.user_dirs)
        rec = {"kind": item.get("kind") or "", "where": item.get("where") or "", "name": item.get("name") or "", "cmd": cmd}
        exists = bool(exe) and os.path.isfile(exe)
        if exists and not lol:
            e = self.file_ent(exe)
            if not in_system_dir(exe):
                self.queue_fp(exe, 0)
            if in_user_dir(exe, self.user_dirs):
                e.add("USER_DIR")
            for code, ev in masquerade_signals(os.path.basename(exe), exe):
                e.add(code, ev)
        else:
            if not sigs:
                return None
            e = self.ent(f"a:{rec['kind']}|{rec['where']}|{rec['name']}", "autorun", "", rec["name"])
            e.no_sig = lol or not exists
        e.add("AUTORUN", f"{rec['kind']}: {rec['name']}"[:80])
        if rec not in e.autoruns:
            e.autoruns.append(rec)
        if sigs and not e.cmd:
            e.cmd = cmd
        for code, ev in sigs:
            e.add(code, ev)
        if item.get("sig") and not e.sig and not e.no_sig:
            e.sig = item["sig"]
        if script:
            self._script_into(e, script)
        return e

    # ---- слой следов команд
    def add_trace(self, cmd, source, when=""):
        sigs = clickfix_signals(cmd, source)
        if not sigs:
            return None
        shown = mask_secrets(cmd)
        e = self.ent(f"t:{source}:{hashlib.sha1(cmd.encode('utf-8', 'replace')).hexdigest()[:16]}", "trace")
        e.name = "окно «Выполнить» (Win+R)" if source == "runmru" else "история PowerShell"
        e.cmd, e.when, e.no_sig = shown, when, True
        e.hosts = cmd_hosts(cmd)
        for code, ev in sigs:
            e.add(code, ev)
        return e

    # ---- слой диска
    def scan_tree(self, roots, walk_budget, max_depth, max_dirs=60000):
        """Ограниченный обход папок в ширину: сначала верхние уровни. Скрипты и конфиги разбираем сразу, exe — в очередь."""
        t0 = time.time()
        st = {"dirs": 0, "files": 0, "exes": 0, "scripts": 0, "configs": 0, "partial": False}
        q = deque()
        seen = set()
        for r in roots:
            if r and os.path.isdir(r) and _low(r) not in seen and not under(r, self.own_roots):
                seen.add(_low(r))
                q.append((r.rstrip("\\").rstrip("/"), 0))
        skip = SKIP_DIRS | (set() if self.deep else SKIP_DIRS_QUICK)
        while q:
            if self.stopped() or time.time() - t0 > walk_budget or st["dirs"] >= max_dirs:
                st["partial"] = True
                break
            d, depth = q.popleft()
            st["dirs"] += 1
            try:
                it = os.scandir(d)
            except OSError:
                continue
            exes, cands = [], []
            with it:
                for en in it:
                    try:
                        nm = en.name.lower()
                        if en.is_dir(follow_symlinks=False):
                            if en.is_symlink() or (en.stat(follow_symlinks=False).st_file_attributes & 0x400):
                                continue                      # ссылки и точки соединения не проходим
                            full = _low(en.path)
                            if depth + 1 > max_depth or nm in skip or full in seen or under(full, self.own_roots) or SKIP_PATH_RE.search(full):
                                continue
                            seen.add(full)
                            q.append((en.path, depth + 1))
                            continue
                        st["files"] += 1
                        ext = os.path.splitext(nm)[1]
                        if ext in EXE_EXT:
                            exes.append(en)
                        elif ext in SCRIPT_EXT or nm in CFG_NAMES or ext == ".json":
                            cands.append((en, ext, nm))
                    except OSError:
                        continue
            for en in exes:
                st["exes"] += 1
                path = en.path
                ms = masquerade_signals(en.name, path)
                if ms:
                    e = self.file_ent(path)
                    for code, ev in ms:
                        e.add(code, ev)
                    if in_user_dir(path, self.user_dirs):
                        e.add("USER_DIR")
                    self.queue_fp(path, 0)
                else:
                    try:
                        self.queue_fp(path, 6 - min(3, (time.time() - en.stat().st_mtime) < 30 * 86400))   # свежие — раньше
                    except OSError:
                        pass
            njson = 0
            for en, ext, nm in cands:
                try:
                    size = en.stat().st_size
                except OSError:
                    continue
                is_cfg = nm in CFG_NAMES or (ext == ".json" and exes and njson < 6)
                if ext == ".json" and nm not in CFG_NAMES:
                    njson += 1
                if is_cfg and 20 <= size <= 512 << 10:
                    st["configs"] += 1
                    sigs = config_signals(read_text(en.path, 300000))
                elif ext in SCRIPT_EXT and 10 <= size <= (256 << 10 if ext != ".js" else 64 << 10):
                    st["scripts"] += 1
                    sigs = script_signals(read_text(en.path))
                else:
                    continue
                if sigs:
                    e = self.file_ent(en.path)
                    for code, ev in sigs:
                        e.add(code, ev)
                    if in_user_dir(en.path, self.user_dirs):
                        e.add("USER_DIR")
        st["took"] = round(time.time() - t0, 1)
        return st

    def run_fp_queue(self, budget, max_prio=9):
        """Проверить содержимое exe из очереди (по приоритету), пока есть время. Остальное — в следующий раз (кэш помнит)."""
        t0 = time.time()
        done = left = 0
        for k, (path, prio) in sorted(self.fp_queue.items(), key=lambda kv: kv[1][1]):
            if prio > max_prio:
                continue
            if self.stopped() or time.time() - t0 > budget:
                left += 1
                continue
            self.fp_queue.pop(k, None)
            if self.own(exe=path):
                continue
            fp = self.fingerprint(path)
            done += 1
            sigs = fp_signals(fp, path)
            if any(c.startswith("FP_") for c, _ in sigs):
                e = self.file_ent(path)
                for code, ev in sigs:
                    e.add(code, ev)
                if in_user_dir(path, self.user_dirs):
                    e.add("USER_DIR")
            elif sigs and ("f:" + k) in self.ents:
                for code, ev in sigs:
                    self.ents["f:" + k].add(code, ev)
        return done, left

    # ---- завершение
    def _fold_neighbours(self):
        """Конфиг/скрипт майнера рядом с exe-майнером — одна находка, а не три."""
        by_dir = {}
        for e in self.ents.values():
            if e.kind == "file" and ("FP_STRONG" in e.signals or "FP_WEAK" in e.signals):
                by_dir.setdefault(os.path.dirname(_low(e.path)), e)
        for k in list(self.ents):
            e = self.ents[k]
            if e.kind != "file" or not any(c.startswith(("CFG_", "SCR_")) for c in e.signals) or e.autoruns or e.pids:
                continue
            host = by_dir.get(os.path.dirname(_low(e.path)))
            if host and host is not e and any(c in ("CFG_MINER", "SCR_STRATUM", "SCR_DONATE", "SCR_POOL", "SCR_WALLET") for c in e.signals):
                host.add("NEAR_KIT", os.path.basename(e.path))
                if "SCR_HIDDEN" in e.signals:
                    host.add("SCR_HIDDEN", os.path.basename(e.path))
                del self.ents[k]

    def _apply_signatures(self):
        need = []
        for e in self.ents.values():
            if e.no_sig or e.kind != "file" or not e.path or e.sig or not e.path.lower().endswith(EXE_EXT + (".dll",)):
                continue
            if evaluate(e.signals)[0] >= T_INFO or "FP_STRONG" in e.signals:
                st = self._stamp(e.path)
                c = self.cache["sig"].get(_low(e.path))
                if st and c and c[0] == st:
                    e.sig = c[1]
                elif st:
                    need.append(e)
        if need and self.sign is None:
            try:
                import system
                self.sign = system.signatures
            except Exception as ex:            # без system.py подписи не проверить — считаем неизвестными
                self.stats["errors"]["signatures"] = str(ex)[:200]
                self.sign = lambda paths: {}
        if need:
            try:
                res = {_low(k): v for k, v in (self.sign([e.path for e in need]) or {}).items()}
            except Exception as ex:
                self.stats["errors"]["signatures"] = str(ex)[:200]
                res = {}
            for e in need:
                s = res.get(_low(e.path))
                if s:
                    e.sig = s
                    self.cache["sig"][_low(e.path)] = [self._stamp(e.path), s]
                    self.cache_dirty = True
        self.stats["signatures_checked"] = len(need)
        for e in self.ents.values():
            s = e.sig
            if not s or e.no_sig:
                continue
            status, signer = s.get("status") or "", s.get("signer") or ""
            if status == "Valid":
                if SECURITY_RE.search(signer):
                    for c in ("FP_STRONG", "FP_WEAK", "UPX", "VI_MISMATCH", "NEAR_KIT"):
                        e.signals.pop(c, None)         # у антивирусов и Microsoft эти строки — их базы, а не майнер
                e.add("SIG_TRUSTED" if TRUSTED_RE.search(signer) else "SIG_VALID", signer[:60])
                if re.search(r"microsoft", signer, re.I):
                    for c in ("MASQ_PATH", "P_FAKE_MS_TASK", "P_SVC_USERDIR"):
                        e.signals.pop(c, None)         # настоящая программа Microsoft (Defender живёт в ProgramData)
                elif TRUSTED_RE.search(signer):
                    e.signals.pop("P_SVC_USERDIR", None)   # службы известных издателей часто лежат в ProgramData
            elif status == "NotSigned":
                e.add("UNSIGNED")
            elif status and status != "UnknownError":
                e.add("BAD_SIG", status)

    def findings(self):
        self._fold_neighbours()
        self._apply_signatures()
        out = []
        for e in self.ents.values():
            try:
                f = build_finding(e)
            except Exception as ex:
                self.stats["errors"]["build:" + e.key[:40]] = str(ex)[:200]
                continue
            if f:
                out.append(f)
        out.sort(key=lambda f: (LEVEL_ORDER[f["level"]], -f["score"], f["title"]))
        return out


def read_text(path, limit=256 << 10):
    try:
        with open(path, "rb") as f:
            raw = f.read(limit)
    except OSError:
        return ""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    if raw[:3] == b"\xef\xbb\xbf":
        raw = raw[3:]
    if len(raw) > 8 and raw[1:2] == b"\0" and raw[3:4] == b"\0":
        return raw.decode("utf-16le", "replace")
    return raw.decode("utf-8", "replace")


# ================================================================ сбор данных с настоящей системы

def _ancestors():
    """Собственный процесс и его предки: их команды (в т. ч. тестовые) не считаем уликами."""
    pids = {os.getpid()}
    if psutil:
        try:
            p = psutil.Process()
            for a in p.parents():
                pids.add(a.pid)
        except Exception:
            pass
    return pids


def list_processes():
    """[{pid, ppid, name, exe, cmd, parent}] — через psutil, иначе через PowerShell (CIM)."""
    out = []
    if psutil:
        raw = {}
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline"]):
            i = p.info
            cl = i.get("cmdline") or []
            raw[i["pid"]] = {"pid": i["pid"], "ppid": i.get("ppid"), "name": i.get("name") or "", "exe": i.get("exe") or "",
                             "cmd": " ".join(f'"{a}"' if " " in a and not a.startswith('"') else a for a in cl)}
        for p in raw.values():
            p["parent"] = (raw.get(p["ppid"]) or {}).get("name", "")
            out.append(p)
        return out
    import system
    rows = system.as_list(system.ps("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"))
    names = {r.get("ProcessId"): r.get("Name") or "" for r in rows if isinstance(r, dict)}
    for r in rows:
        if isinstance(r, dict):
            out.append({"pid": r.get("ProcessId"), "ppid": r.get("ParentProcessId"), "name": r.get("Name") or "",
                        "exe": r.get("ExecutablePath") or "", "cmd": r.get("CommandLine") or "", "parent": names.get(r.get("ParentProcessId"), "")})
    return out


def _reg_values(root, path):
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            n = winreg.QueryInfoKey(k)
            vals = {}
            for i in range(n[1]):
                name, val, _ = winreg.EnumValue(k, i)
                vals[name] = val
            return vals, n[2]
    except OSError:
        return None, 0


def _reg_subkeys(root, path):
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return [winreg.EnumKey(k, i) for i in range(winreg.QueryInfoKey(k)[0])]
    except OSError:
        return []


def _filetime(ft):
    try:
        return time.strftime("%d.%m.%Y", time.localtime(ft / 10_000_000 - 11644473600))
    except (OSError, ValueError, OverflowError):
        return ""


def read_traces(history_tail=96 << 10, max_lines=600):
    """[(команда, источник, дата)] из окна «Выполнить» и истории PowerShell. Читаем только хвост истории."""
    out = []
    if winreg:
        vals, ft = _reg_values(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")
        for name, val in (vals or {}).items():
            if name != "MRUList" and isinstance(val, str):
                out.append((val[:-2] if val.endswith("\\1") else val, "runmru", _filetime(ft)))
    hist_dir = os.path.join(ENV.get("APPDATA", ""), r"Microsoft\Windows\PowerShell\PSReadLine")
    try:
        files = [os.path.join(hist_dir, n) for n in os.listdir(hist_dir) if n.lower().endswith("_history.txt")]
    except OSError:
        files = []
    for fpath in files:
        try:
            size = os.path.getsize(fpath)
            when = time.strftime("%d.%m.%Y", time.localtime(os.path.getmtime(fpath)))
            with open(fpath, "rb") as f:
                f.seek(max(0, size - history_tail))
                text = f.read().decode("utf-8", "replace")
        except OSError:
            continue
        lines = text.splitlines()[-max_lines:]
        if size > history_tail and lines:
            lines = lines[1:]                           # первая строка хвоста может быть обрезана
        seen = set()
        for ln in lines:
            ln = ln.strip().rstrip("`")
            if len(ln) >= 8 and ln not in seen:
                seen.add(ln)
                out.append((ln, "history", "не позже " + when))
    return out


def read_registry_extras(user_dirs=None):
    """То, чего нет в system.autoruns(): пара GlobalFlag+SilentProcessExit, службы из папок пользователя, политики Defender."""
    items, defense, ring = [], [], []
    if not winreg:
        return items, defense, ring
    HKLM = winreg.HKEY_LOCAL_MACHINE
    ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    spe = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
    for name in _reg_subkeys(HKLM, spe):
        v, _ = _reg_values(HKLM, spe + "\\" + name)
        mon = (v or {}).get("MonitorProcess")
        if mon:
            g, _ = _reg_values(HKLM, ifeo + "\\" + name)
            flag = (g or {}).get("GlobalFlag") or 0
            try:
                flag = int(flag, 0) if isinstance(flag, str) else int(flag)
            except ValueError:
                flag = 0
            items.append({"kind": "Перехват запуска", "where": "SilentProcessExit", "name": name, "cmd": str(mon),
                          "exe": exe_from_command(str(mon)), "armed": bool(flag & 0x200), "extra": True})
    svc = r"SYSTEM\CurrentControlSet\Services"
    for name in _reg_subkeys(HKLM, svc):
        v, _ = _reg_values(HKLM, svc + "\\" + name)
        if not v or not isinstance(v.get("ImagePath"), str) or v.get("Start") == 4:
            continue
        img = os.path.expandvars(v["ImagePath"]).strip()
        img = re.sub(r"^\\\?\?\\", "", img)
        if img.lower().startswith("\\systemroot\\"):
            img = WINDIR + img[11:]
        elif img.lower().startswith("system32\\"):
            img = WINDIR + "\\" + img
        exe = exe_from_command(img)
        if "winring0" in name.lower() or "winring0" in img.lower():
            ring.append(img)
        if exe and in_user_dir(exe, user_dirs):
            items.append({"kind": "Служба (не авто)", "where": f"Start={v.get('Start')}", "name": name, "cmd": img, "exe": exe, "extra": True})
    pol = r"SOFTWARE\Policies\Microsoft\Windows Defender"
    v, _ = _reg_values(HKLM, pol)
    if (v or {}).get("DisableAntiSpyware") == 1:
        defense.append(("D_POLICY_OFF", "DisableAntiSpyware=1"))
    v, _ = _reg_values(HKLM, pol + r"\Real-Time Protection")
    for k in ("DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableScriptScanning"):
        if (v or {}).get(k) == 1:
            defense.append(("D_POLICY_OFF", f"{k}=1"))
    for sub in ("Paths", "Processes", "Extensions"):
        v, _ = _reg_values(HKLM, pol + r"\Exclusions" + "\\" + sub)
        for name in (v or {}):
            defense.append(("D_DEF_INFO", f"исключение через политики ({sub}): {name}"))
    return items, defense, ring


NO_WINDOW = 0x08000000
MONITOR_NAMES = {"taskmgr", "procexp", "procexp64", "processhacker", "systeminformer", "perfmon", "resmon", "procmon", "procmon64",
                 "anvir", "processlasso", "taskexplorer"}
DECOY_NAMES = ("Taskmgr.exe", "ProcessHacker.exe", "procexp64.exe")
WINDOW_STOP = {"explorer", "svchost", "services", "wininit", "winlogon", "userinit", "sihost", "taskhostw", "system", "smss",
               "csrss", "runtimebroker", "taskeng", "wmiprvse", "dllhost", "startmenuexperiencehost", "shellexperiencehost"}
PS_GPU = r"""
$a = @{}
1..3 | ForEach-Object {
  (Get-Counter '\GPU Engine(*)\Utilization Percentage').CounterSamples | Where-Object { $_.CookedValue -gt 1 -and $_.InstanceName -match 'pid_(\d+).*engtype_(3d|compute|cuda)' } |
    ForEach-Object { $null = $_.InstanceName -match 'pid_(\d+)'; $k = $matches[1]; $a[$k] = [double]$a[$k] + $_.CookedValue }
  Start-Sleep -Milliseconds 600 }
@($a.GetEnumerator() | ForEach-Object { @{pid=[int]$_.Key; gpu=[math]::Round($_.Value / 3, 1)} }) | ConvertTo-Json -Compress
"""


def idle_seconds():
    """Сколько секунд человек не трогал мышь и клавиатуру."""
    try:
        import ctypes

        class LII(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
        li = LII()
        li.cbSize = ctypes.sizeof(li)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(li)):
            return max(0, ((ctypes.windll.kernel32.GetTickCount() - li.dwTime) & 0xFFFFFFFF) / 1000)
    except Exception:
        pass
    return 0


def visible_window_pids():
    """PID процессов, у которых есть видимое окно с заголовком."""
    import ctypes
    from ctypes import wintypes
    u = ctypes.windll.user32
    pids = set()

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _):
        if u.IsWindowVisible(hwnd) and u.GetWindowTextLengthW(hwnd) > 0:
            pid = wintypes.DWORD()
            u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pids.add(pid.value)
        return True
    u.EnumWindows(cb, 0)
    return pids


def has_lock_pages(pid):
    """Есть ли в токене процесса право «Блокировка страниц в памяти» (SeLockMemoryPrivilege). None — не удалось узнать."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
    h = k32.OpenProcess(0x1000, False, pid)
    if not h:
        return None
    tok = wintypes.HANDLE()
    try:
        if not adv.OpenProcessToken(h, 0x8, ctypes.byref(tok)):
            return None
        luid = ctypes.create_string_buffer(8)
        if not adv.LookupPrivilegeValueW(None, "SeLockMemoryPrivilege", luid):
            return None
        size = wintypes.DWORD()
        adv.GetTokenInformation(tok, 3, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value or 4)
        if not adv.GetTokenInformation(tok, 3, buf, size, ctypes.byref(size)):
            return None
        count = struct.unpack_from("<I", buf, 0)[0]
        want = luid.raw
        return any(buf.raw[4 + i * 12:12 + i * 12] == want for i in range(count))
    finally:
        if tok:
            k32.CloseHandle(tok)
        k32.CloseHandle(h)


class Sampler(threading.Thread):
    """Раз в секунду записывает, сколько процессорного времени и обмена с диском набрал каждый процесс.
    Работает всё время проверки, поэтому в быстрой проверке «физика» достаётся бесплатно."""

    def __init__(self, interval=1.0, skip=()):
        super().__init__(daemon=True, name="hunter-sampler")
        self.interval, self.skip = interval, set(skip)
        self.samples = []            # [{"t", "idle", "cpu": {pid: секунд}, "io": {pid: байт}}]
        self.born = {}
        self._halt = threading.Event()
        self.ncpu = (psutil.cpu_count() if psutil else os.cpu_count()) or 1
        try:
            from metrics import proc_table
            proc_table()
            self.table = proc_table
        except Exception:
            self.table = None

    def tick(self):
        cpu, io = {}, {}
        if self.table:                       # вся таблица процессов одним системным вызовом (metrics.proc_table)
            for pid, r in self.table().items():
                if pid in self.skip or pid in (0, 4):
                    continue
                cpu[pid], io[pid] = r["cpu"], r["io"]
                self.born.setdefault(pid, r["create"])
        else:
            for p in psutil.process_iter(["cpu_times", "io_counters", "create_time"]):
                i, pid = p.info, p.pid
                ct = i.get("cpu_times")
                if pid in self.skip or pid in (0, 4) or not ct:
                    continue
                cpu[pid] = ct.user + ct.system
                ioc = i.get("io_counters")
                if ioc:
                    io[pid] = ioc.read_bytes + ioc.write_bytes
                self.born.setdefault(pid, i.get("create_time"))
        self.samples.append({"t": time.time(), "idle": idle_seconds(), "cpu": cpu, "io": io})

    def run(self):
        while not self._halt.is_set():
            try:
                self.tick()
            except Exception:
                pass
            self._halt.wait(self.interval)

    def stop(self):
        self._halt.set()

    def window(self, t0=0.0, t1=1e18):
        return [x for x in list(self.samples) if t0 <= x["t"] <= t1]

    def series(self, pid, t0=0.0, t1=1e18):
        """Нагрузка процесса по секундам, % от всех ядер (None — процесса в этот момент не было)."""
        ss, out = self.window(t0, t1), []
        for a, b in zip(ss, ss[1:]):
            if pid in a["cpu"] and pid in b["cpu"] and b["t"] > a["t"]:
                out.append(max(0.0, (b["cpu"][pid] - a["cpu"][pid]) / (b["t"] - a["t"]) / self.ncpu * 100))
            else:
                out.append(None)
        return out

    def io_bps(self, pid, t0=0.0, t1=1e18):
        ss = [x for x in self.window(t0, t1) if pid in x["io"]]
        if len(ss) < 2 or ss[-1]["t"] <= ss[0]["t"]:
            return None
        return max(0.0, (ss[-1]["io"][pid] - ss[0]["io"][pid]) / (ss[-1]["t"] - ss[0]["t"]))

    def hot(self, t0=0.0, t1=1e18, min_mean=6.0, min_n=4):
        ss = self.window(t0, t1)
        pids = set().union(*[x["cpu"].keys() for x in ss]) if ss else set()
        out = {}
        for pid in pids:
            ser = [v for v in self.series(pid, t0, t1) if v is not None]
            if len(ser) >= min_n and _mean(ser) >= min_mean:
                out[pid] = ser
        return out

    def idle(self, t0=0.0, t1=1e18):
        v = sorted(x["idle"] for x in self.window(t0, t1))
        return v[len(v) // 2] if v else 0


class Decoy:
    """«Приманка»: безвредная копия системного ping.exe под именем Диспетчера задач и похожих программ.
    Лежит в data/hunter_probe (своя папка ScanHub), живёт несколько секунд, после опыта всё удаляется.
    Настоящие системные файлы не трогаем: только читаем ping.exe, чтобы скопировать."""

    def __init__(self, seconds):
        self.seconds, self.dir, self.procs, self.files = seconds, os.path.join(DATA, "hunter_probe"), [], []

    def __enter__(self):
        src = os.path.join(WINDIR, "System32", "PING.EXE")
        os.makedirs(self.dir, exist_ok=True)
        ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        for name in DECOY_NAMES:
            v, _ = _reg_values(winreg.HKEY_LOCAL_MACHINE, ifeo + "\\" + name) if winreg else (None, 0)
            if v and v.get("Debugger"):
                continue                      # запуск этого имени перехвачен (например, Process Explorer вместо Диспетчера) — не трогаем
            dst = os.path.join(self.dir, name)
            try:
                shutil.copyfile(src, dst)
                self.files.append(dst)
                self.procs.append(subprocess.Popen([dst, "-n", str(self.seconds + 20), "127.0.0.1"], creationflags=NO_WINDOW,
                                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            except OSError:
                pass
        return self

    def __exit__(self, *_):
        for pr in self.procs:
            try:
                pr.kill()
                pr.wait(5)
            except Exception:
                pass
        for _ in range(10):
            left = []
            for f in self.files:
                try:
                    os.remove(f)
                except FileNotFoundError:
                    pass
                except OSError:
                    left.append(f)
            self.files = left
            if not left:
                break
            time.sleep(0.3)
        try:
            os.rmdir(self.dir)
        except OSError:
            pass
        return False


def observer_test(sampler, stopped=lambda: False, emit=lambda *_: None, skip=()):
    """Опыт «затихает ли при Диспетчере задач». → ({pid: улика}, пояснение для статистики).
    Берём процессы с устойчивой нагрузкой, на 11 с показываем «приманку», 12 с смотрим после. Кто затих и вернулся —
    проверяем вторым прогоном: совпадение дважды подряд случайным не бывает."""
    def wait(sec):
        end = time.time() + sec
        while time.time() < end:
            if stopped():
                return False
            time.sleep(0.25)
        return True

    def cycle(base_win, cands, show, after):
        with Decoy(show) as d:
            if not d.procs:
                return None
            td0 = time.time()
            ok = wait(show)
            td1 = time.time()
        if not ok or not wait(after):
            return None
        ta1 = time.time()
        res = {}
        for pid in cands:
            b, du, af = sampler.series(pid, *base_win), sampler.series(pid, td0 + 2.5, td1), sampler.series(pid, td1 + 3, ta1)
            if observer_shy(b, du, af):
                res[pid] = (_mean([x for x in b if x is not None]), _mean([x for x in du if x is not None]),
                            _mean([x for x in af if x is not None]), (td1 + 3, ta1))
        return res

    t0 = time.time()
    if not wait(8):
        return {}, "остановлено"
    base = (t0, time.time())
    cands = [pid for pid in sampler.hot(*base, min_mean=4) if pid not in skip]
    if not cands:
        return {}, "нет программ с постоянной нагрузкой — опыт не нужен"
    emit("  опыт: на несколько секунд показываю «приманку» с именем Диспетчера задач — скрытные майнеры при нём затихают…")
    first = cycle(base, cands, 11, 12)
    if first is None:
        return {}, "приманку запустить не удалось"
    if not first:
        return {}, f"проверено программ под нагрузкой: {len(cands)}, никто не затих"
    emit("  кто-то затих — повторяю опыт, чтобы исключить совпадение…")
    out = {}
    second = cycle(next(iter(first.values()))[3], list(first), 10, 10) or {}
    for pid, (b, du, af, _) in first.items():
        if pid in second:
            b2, du2, af2, _ = second[pid]
            out[pid] = f"нагрузка {b:.0f}% → {du:.0f}% при «Диспетчере задач» → {af:.0f}% после; повтор: {b2:.0f}% → {du2:.0f}% → {af2:.0f}%"
    return out, f"проверено программ под нагрузкой: {len(cands)}, затихли дважды: {len(out)}"


def is_hidden(pid, wpids, info):
    """Нет видимого окна ни у процесса, ни у его родителей (до проводника), ни у других процессов того же файла.
    info — {pid: {"ppid", "name", "exe"}}. Консольное окно принадлежит conhost — его засчитываем владельцу консоли."""
    w = set(wpids)
    for q in list(w):
        if base_name((info.get(q) or {}).get("name")) in ("conhost", "openconsole"):
            w.add((info.get(q) or {}).get("ppid"))
    cur, seen = pid, set()
    for _ in range(8):
        i = info.get(cur)
        if not i or cur in seen:
            break
        seen.add(cur)
        if cur != pid and base_name(i.get("name")) in WINDOW_STOP:
            break
        if cur in w:
            return False
        cur = i.get("ppid")
    exe = _low((info.get(pid) or {}).get("exe"))
    if exe and any(q in w for q, i in info.items() if _low(i.get("exe")) == exe):
        return False
    return True


def observe(seconds=6):
    """Короткое наблюдение без проверки: пополняет историю «нагрузка ↔ человек отошёл» (для улики B_IDLE_RAMP).
    Его может вызывать «Сторож» раз в 15 минут — так история набирается и в простое, а не только во время проверок."""
    if not psutil:
        return 0
    sm = Sampler(1.0, _ancestors())
    sm.start()
    time.sleep(max(3, seconds))
    sm.stop()
    h = Hunter("quick", emit=lambda *_: None)
    n = _record_history(h, sm, {p["pid"]: p for p in list_processes()}, visible_window_pids())
    h.save_cache()
    return n


def _record_history(h, sm, info, wpids):
    """Одна запись на файл за наблюдение: [время, простой человека, нагрузка]. Пишем скрытые процессы под нагрузкой
    и те, что уже были в истории (чтобы видеть и моменты, когда они молчат)."""
    hist, idle, now, n = h.cache["hist"], sm.idle(), int(time.time()), 0
    best = {}
    for pid in (sm.window()[-1]["cpu"] if sm.samples else {}):
        i = info.get(pid)
        exe = _low((i or {}).get("exe"))
        if not exe or h.own(exe=exe):
            continue
        ser = [v for v in sm.series(pid) if v is not None]
        m = _mean(ser)
        if exe in hist or (m >= 6 and len(ser) >= 4 and is_hidden(pid, wpids, info)):
            best[exe] = max(best.get(exe, 0), m)
    for exe, m in best.items():
        hist.setdefault(exe, []).append([now, int(idle), round(m, 1)])
        hist[exe] = hist[exe][-40:]
        n += 1
    for exe in list(hist):                                   # файлы, которых давно нет, из истории убираем
        if now - hist[exe][-1][0] > 60 * 86400:
            del hist[exe]
    if n:
        h.cache_dirty = True
    return n


PS_EXTRAS = r"""
$o = @{}
try { $o.filters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop | ForEach-Object { @{name=[string]$_.Name; query=[string]$_.Query} })
      $o.bindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object { @{filter=[string]$_.Filter.Name; consumer=[string]$_.Consumer.Name; cls=[string]$_.Consumer.CimClass.CimClassName} })
      $o.wmi_ok = $true } catch { $o.wmi_ok = $false }
$o.dns = @(Get-DnsClientCache | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | ForEach-Object { @{e=[string]$_.Entry; d=[string]$_.Data} })
try { $m = Get-MpComputerStatus -ErrorAction Stop; $o.mp = @{rtp=[bool]$m.RealTimeProtectionEnabled; av=[bool]$m.AntivirusEnabled; mode=[string]$m.AMRunningMode; tamper=[bool]$m.IsTamperProtected} } catch { $o.mp = $null }
$o.av = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { @{name=[string]$_.displayName; state=[int]$_.productState} })
$o | ConvertTo-Json -Compress -Depth 4
"""


def scan(mode="quick", emit=print, stopped=lambda: False, admin_out=None, autoruns=None, net=None, intel_res=None):
    """Полная проверка этого компьютера.

    mode      — "quick" (≈15–25 с) или "deep" (несколько минут: глубже диск, больше файлов, сверка с базой Maltrail на диске).
    emit      — функция для строк хода работы; stopped — функция «пора остановиться?».
    admin_out — текст вывода Get-MpPreference | ConvertTo-Json, уже собранный помощником с правами администратора (или None).
    autoruns / net / intel_res — уже готовые результаты system.autoruns(), system.network(), intel.check_network(),
                если вызывающий их только что собрал (чтобы не запускать второй раз).
    → {"verdict", "label", "findings", "stats", "took"}
    """
    t_start = time.time()
    deep = mode == "deep"
    h = Hunter(mode, emit, stopped)
    st = h.stats
    bg = {}
    selfp = _ancestors()

    def layer(name, fn):
        """Один слой: ошибка не роняет проверку, время и ошибка попадают в stats."""
        if stopped():
            return None
        t0 = time.time()
        try:
            return fn()
        except Exception as ex:                       # noqa: BLE001 — слой не должен ронять всю проверку
            st["errors"][name] = f"{type(ex).__name__}: {ex}"[:300]
            return None
        finally:
            st["layers"][name] = round(st["layers"].get(name, 0) + time.time() - t0, 2)

    def bg_run(name, fn):
        def run():
            t0 = time.time()
            try:
                bg[name] = fn()
            except Exception as ex:                   # noqa: BLE001
                st["errors"][name] = f"{type(ex).__name__}: {ex}"[:300]
                bg[name] = None
            st["layers"][name] = round(time.time() - t0, 2)
        t = threading.Thread(target=run, daemon=True, name="hunter-" + name)
        t.start()
        return t

    try:
        import system
    except Exception as ex:                           # noqa: BLE001
        system = None
        st["errors"]["system"] = str(ex)[:200]

    # медленные сборщики (PowerShell) — в фоне, пока идут процессы и диск
    threads = {}
    if system:
        if autoruns is None:
            threads["autoruns"] = bg_run("autoruns", system.autoruns)
        if net is None:
            threads["network"] = bg_run("network", system.network)
        threads["extras"] = bg_run("extras", lambda: system.ps(PS_EXTRAS, timeout=90))

    sampler = None
    if psutil:
        sampler = Sampler(1.0, selfp)
        sampler.start()
    else:
        st["not_checked"].append("поведение программ (нагрузка, память) — не установлен модуль psutil")
    if system and deep:
        threads["gpu"] = bg_run("gpu", lambda: system.ps(PS_GPU, timeout=60))

    # ---- а) процессы
    emit("  смотрю запущенные программы и их команды…")
    procs = layer("processes_list", list_processes) or []
    st["processes"] = len(procs)
    pid_ent = {}

    def do_procs():
        for p in procs:
            if p["pid"] in selfp or p["pid"] in (0, 4):
                continue
            e = h.add_process(p)
            if e:
                pid_ent[p["pid"]] = e
        mon = sorted({p["name"] for p in procs if base_name(p["name"]) in MONITOR_NAMES})
        if mon:
            st["monitor_open"] = mon
            st["not_checked"].append(f"открыт {', '.join(mon)} — скрытные майнеры при нём затихают; закрой его и повтори проверку")
    layer("processes", do_procs)

    # ---- е) следы команд
    def do_traces():
        tr = read_traces()
        st["traces_checked"] = len(tr)
        for cmd, source, when in tr:
            h.add_trace(cmd, source, when)
    emit("  ищу следы опасных команд (окно «Выполнить», история PowerShell)…")
    layer("traces", do_traces)

    # ---- д) реестр: то, чего нет в autoruns()
    extra_items, defense, ring_drivers = layer("registry", lambda: read_registry_extras()) or ([], [], [])
    for it in extra_items:
        layer("registry", lambda it=it: h.add_autorun(it))

    # ---- б) содержимое запущенных программ
    emit("  проверяю, что внутри запущенных программ (ищу код майнеров)…")
    r = layer("fingerprint_running", lambda: h.run_fp_queue(60 if deep else 7, max_prio=2))
    st["fp_running"] = {"checked": r[0], "left": r[1]} if r else None

    # ---- в) диск
    emit("  просматриваю папки, где прячутся майнеры…")
    roots = [ENV.get("APPDATA"), ENV.get("LOCALAPPDATA"), ENV.get("ProgramData"), ENV.get("TEMP"), r"C:\Users\Public"]
    if deep:
        roots += [WINDIR + r"\Temp", os.path.join(os.path.expanduser("~"), "Downloads"), os.path.join(os.path.expanduser("~"), "Desktop")]
    st["disk"] = layer("disk", lambda: h.scan_tree([x for x in roots if x], 120 if deep else 6, 9 if deep else 4))

    # ---- д) автозагрузка
    if "autoruns" in threads:
        emit("  жду список автозагрузки…")
        threads["autoruns"].join(240)
        autoruns = bg.get("autoruns")

    def do_autoruns():
        items = autoruns or []
        st["autoruns"] = len(items)
        weak = 0
        for it in items:
            e = h.add_autorun(it)
            if e and not e.core() and it.get("level") in ("warn", "bad"):
                weak += 1
        st["autoruns_weak_only"] = weak               # «без подписи / из папки пользователя» без других улик — не находка
    if autoruns is not None:
        layer("persistence", do_autoruns)
    else:
        st["not_checked"].append("автозагрузка: список не получен")

    # содержимое exe из автозагрузки — в первую очередь, потом остальное с диска
    spent = time.time() - t_start
    r1 = layer("fingerprint_autoruns", lambda: h.run_fp_queue(60 if deep else 6, max_prio=0))
    left = (240 if deep else 21) - (time.time() - t_start)
    r2 = layer("fingerprint_disk", lambda: h.run_fp_queue(max(left, 150 if deep else 3)))
    st["fp_disk"] = {"checked": (r1[0] if r1 else 0) + (r2[0] if r2 else 0), "left": r2[1] if r2 else 0}
    if r2 and r2[1]:
        st["not_checked"].append(f"содержимое {r2[1]} программ на диске — не хватило времени, проверю в следующий раз"
                                 + ("" if deep else " (или запусти глубокую проверку)"))
    if st.get("disk") and st["disk"].get("partial"):
        st["not_checked"].append("часть папок — не хватило времени" + ("" if deep else "; глубокая проверка смотрит всё"))

    # ---- з) сеть
    for name in ("network", "extras"):
        if name in threads:
            threads[name].join(120)
    if net is None:
        net = bg.get("network")
    extras = bg.get("extras") or {}

    def do_network():
        by_pid = {}
        for e in h.ents.values():
            for pid in e.pids:
                by_pid[pid] = e
        ip_pool = {}
        pool_names = set()
        for d in (extras.get("dns") or []):
            if isinstance(d, dict) and STRICT_POOL_RE.search(d.get("e") or ""):
                pool_names.add(d["e"].lower())
                if d.get("d"):
                    ip_pool[d["d"]] = d["e"]
        ports = 0
        for c in (net or {}).get("connections", []):
            ip = (c.get("remote") or "").rsplit(":", 1)[0]
            e = by_pid.get(c["pid"])
            if c["pid"] in selfp or h.own(exe=c.get("exe") or ""):
                continue
            if ip in ip_pool:
                if not e:
                    exe = c.get("exe") or ""
                    e = h.file_ent(exe) if exe and not under(exe, [WINDIR]) else h.ent(f"p:{c['pid']}", "proc", "", c.get("name") or "")
                    e.add("RUNNING", f"PID {c['pid']}")
                    e.pids.append(c["pid"])
                    by_pid[c["pid"]] = e
                e.add("N_POOL_CONN", f"{ip_pool[ip]} ({c.get('remote')})")
            if c.get("flags"):
                ports += 1
                if e:
                    e.add("POOL_PORT", c.get("remote") or "")
        st["pool_port_conns"] = ports                 # порт сам по себе — не улика, только счётчик
        if pool_names:
            e = h.ent("n:pooldns", "net")
            e.title = "Компьютер недавно искал адрес майнинг-пула"
            for n in sorted(pool_names)[:4]:
                e.add("N_POOL_DNS", n)
        for line in (net or {}).get("hosts_tampered", []):
            e = h.ent("d:hosts", "system", os.path.join(WINDIR, r"System32\drivers\etc\hosts"))
            e.title, e.no_sig = "Файл hosts перекрывает сайты защиты или обновлений", True
            e.note = "Если ты сам отключал обновления или пользовался «активатором» — это его след."
            e.add("D_HOSTS_AV", line[:80])
        # привязки WMI: имя фильтра и запрос — к уже найденной WMI-подписке
        if extras.get("wmi_ok") is False:
            st["not_checked"].append("скрытый автозапуск через WMI — нужны права администратора")
        for b in (extras.get("bindings") or []):
            if not isinstance(b, dict):
                continue
            flt = next((f for f in (extras.get("filters") or []) if isinstance(f, dict) and f.get("name") == b.get("filter")), {})
            for e in h.ents.values():
                if "P_WMI" in e.signals and b.get("consumer") in (e.name, *(a["name"] for a in e.autoruns)):
                    e.add("P_WMI", f"фильтр {b.get('filter')}: {(flt.get('query') or '')[:70]}")
    if net is not None or extras:
        layer("network_score", do_network)
    else:
        st["not_checked"].append("сеть: данные не получены")

    # база Maltrail (только уже скачанная; в интернет не ходим)
    def do_intel():
        res = intel_res
        if res is None and deep:
            import intel
            if intel.trails_accepted() and os.path.exists(intel.TRAILS):
                emit("  сверяю соединения с базой вредоносных адресов (уже скачанной)…")
                res = intel.check_network(lambda *_: None, update=False)
        if not res or not res.get("ok"):
            return
        by_pid = {pid: e for e in h.ents.values() for pid in e.pids}
        for hit in res.get("hits", []):
            if hit.get("kind") == "conn":
                if hit.get("pid") in selfp or h.own(exe=hit.get("exe") or ""):
                    continue
                e = by_pid.get(hit.get("pid"))
                if not e:
                    exe = hit.get("exe") or ""
                    e = h.file_ent(exe) if exe and not under(exe, [WINDIR]) else h.ent(f"p:{hit.get('pid')}", "proc", "", hit.get("process") or "")
                    e.add("RUNNING", f"PID {hit.get('pid')}")
                    e.pids.append(hit.get("pid"))
                e.add("N_MALTRAIL_CONN", f"{hit.get('indicator')} — {hit.get('what')}"[:90])
            elif hit.get("kind") == "dns":
                e = h.ent("n:maltraildns", "net")
                e.title = "Обращения к адресам из базы вредоносных серверов"
                e.add("N_MALTRAIL_DNS", f"{hit.get('indicator')} — {hit.get('what')}"[:90])
            elif hit.get("kind") == "hosts":
                e = h.ent("d:hosts", "system", os.path.join(WINDIR, r"System32\drivers\etc\hosts"))
                e.no_sig = True
                e.add("D_HOSTS_AV", (hit.get("text") or "")[:90])
    layer("intel", do_intel)

    # ---- ж) защита
    def do_defense():
        excl = []
        for code, ev in defense:
            e = h.ent("d:policy" if code == "D_POLICY_OFF" else "d:definfo", "system")
            e.title = "Защитник Windows выключен через политики" if code == "D_POLICY_OFF" else "Исключения Защитника Windows"
            e.no_sig = True
            e.add(code, ev)
        mp, avs = extras.get("mp"), [a for a in (extras.get("av") or []) if isinstance(a, dict)]
        other_av = [a["name"] for a in avs if a.get("name") and "defender" not in a["name"].lower() and (a.get("state", 0) >> 12) & 1]
        if isinstance(mp, dict) and mp.get("rtp") is False and not other_av and mp.get("mode") != "Passive Mode":
            e = h.ent("d:rtp", "system")
            e.title, e.no_sig = "Постоянная защита Windows выключена", True
            e.note = "Если выключал сам на время — включи обратно в «Безопасность Windows»."
            e.add("D_RTP_OFF", "RealTimeProtectionEnabled=False")
        st["defender"] = {"realtime": (mp or {}).get("rtp") if isinstance(mp, dict) else None, "other_av": other_av}
        if admin_out:
            import deepscan
            r = deepscan.defender_prefs_check(admin_out)
            st["defender"]["exclusions"] = r.get("label")
            for lvl, text in r.get("items", []):
                e = h.ent("d:defbad" if lvl == "bad" else "d:definfo", "system")
                e.title = "Опасные исключения или выключенная защита Defender" if lvl == "bad" else "Исключения Защитника Windows"
                e.no_sig = True
                e.add("D_DEF_BAD" if lvl == "bad" else "D_DEF_INFO", text[:110])
            try:
                d = json.loads(admin_out[admin_out.index("{"):admin_out.rindex("}") + 1])
                v = d.get("ExclusionPath") or []
                excl = [_low(os.path.expandvars(str(x))) for x in (v if isinstance(v, list) else [v])]
            except ValueError:
                pass
            for e in h.ents.values():
                if e.kind == "file" and e.core() and any(x and under(e.path, [x]) for x in excl):
                    e.add("DEF_EXCLUDED", "путь в исключениях Defender")
        else:
            st["not_checked"].append("исключения Защитника Windows — нужны права администратора")
    layer("defense", do_defense)

    # ---- и) «физика майнера»: поведение процессов за время проверки (+ опыт с приманкой в глубокой проверке)
    def do_physics():
        ph = st["physics"] = {}
        shy = {}
        if deep and not st.get("monitor_open") and not stopped():
            shy, ph["observer_test"] = observer_test(sampler, stopped, emit, skip=selfp)
        elif deep:
            ph["observer_test"] = "пропущен: открыт Диспетчер задач или похожая программа"
        sampler.stop()
        ph["samples"] = len(sampler.samples)
        gpu = {}
        if "gpu" in threads:
            threads["gpu"].join(30)
            for g in (bg.get("gpu") or []) if isinstance(bg.get("gpu"), list) else ([bg["gpu"]] if isinstance(bg.get("gpu"), dict) else []):
                if isinstance(g, dict) and g.get("pid"):
                    gpu[g["pid"]] = g.get("gpu") or 0
            ph["gpu_sampled"] = bool(bg.get("gpu") is not None)
        info = {p["pid"]: p for p in procs}
        wpids = visible_window_pids()
        hot = sampler.hot(min_mean=6)
        cand = set(hot) | set(shy) | {pid for pid, g in gpu.items() if g >= 50}
        for pid in cand - set(info):                 # программа появилась уже во время проверки
            try:
                pp = psutil.Process(pid)
                info[pid] = {"pid": pid, "ppid": pp.ppid(), "name": pp.name(), "exe": pp.exe(), "cmd": " ".join(pp.cmdline()), "parent": ""}
            except Exception:
                pass
        ph["hot"] = len(hot)
        remotes = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.pid and c.raddr and c.status == "ESTABLISHED" and not c.raddr.ip.startswith(("127.", "::1", "fe80", "169.254.")):
                    remotes.setdefault(c.pid, set()).add(f"{c.raddr.ip}:{c.raddr.port}")
        except Exception:
            pass
        ring_bad = [r for r in ring_drivers if winring0_suspicious(r)]
        if ring_drivers:
            ph["winring0"] = ring_drivers[:3]
        _record_history(h, sampler, info, wpids)
        for pid in cand:
            i = info.get(pid)
            if not i or pid in selfp or h.own(i.get("cmd") or "", i.get("exe") or ""):
                continue
            exe, name = i.get("exe") or "", i.get("name") or ""
            ser = hot.get(pid) or [v for v in sampler.series(pid) if v is not None]
            feat = {"cpu": ser, "ncpu": sampler.ncpu, "hidden": is_hidden(pid, wpids, info), "io_bps": sampler.io_bps(pid),
                    "remotes": len(remotes.get(pid, ())), "remote": next(iter(remotes.get(pid, ())), ""), "gpu": gpu.get(pid)}
            try:
                pp = psutil.Process(pid)
                mi = pp.memory_info()
                feat["private_mb"] = getattr(mi, "private", mi.rss) / 1048576
                feat["threads"] = pp.num_threads()
                user = ""
                try:
                    user = pp.username() or ""
                except Exception:
                    pass
                if not re.search(r"(SYSTEM|СИСТЕМА|SERVICE|СЛУЖБА)$", user, re.I):
                    feat["lock_pages"] = bool(has_lock_pages(pid))
            except Exception:
                pass
            if exe:
                try:
                    sib = [n for n in os.listdir(os.path.dirname(exe)) if n.lower().startswith("winring0") and n.lower().endswith(".sys")]
                except OSError:
                    sib = []
                feat["winring0"] = (sib[0] if sib else "") or (ring_bad[0] if ring_bad else "")
            sigs = physics_signals(feat)
            if pid in shy:
                sigs.append(("B_OBSERVER_SHY", shy[pid]))
            if exe and feat["hidden"] and idle_correlation([(o[1], o[2]) for o in h.cache["hist"].get(_low(exe), [])]):
                sigs.append(("B_IDLE_RAMP", "по истории наблюдений"))
            e = pid_ent.get(pid)
            if not sigs:
                if e and e.core() and _mean(ser) >= 20:
                    e.add("HIGH_CPU", f"{_mean(ser):.0f}% всех ядер")
                continue
            if not e:
                if exe and not under(exe, [WINDIR]):
                    e = h.file_ent(exe)
                    if in_user_dir(exe):
                        e.add("USER_DIR")
                else:
                    e = h.ent(f"p:{pid}", "proc", "", name)
                    e.no_sig = True
                e.add("RUNNING", f"PID {pid}")
                if pid not in e.pids:
                    e.pids.append(pid)
            if e.kind == "proc":
                e.add("SYS_BIN", exe[-60:])
            if _mean(ser) >= 20:
                e.add("HIGH_CPU", f"{_mean(ser):.0f}% всех ядер")
            for code, ev in sigs:
                e.add(code, ev)
    if sampler:
        layer("physics", do_physics)
        sampler.stop()

    found = layer("findings", h.findings) or []
    h.save_cache()
    # «это был я»: скрытое человеком не показываем, пока находка не стала серьёзнее, чем когда её скрыли
    ign = load_ignored()
    rank = {"info": 0, "suspicious": 1, "threat": 2}
    hidden = [f for f in found if f["id"] in ign and rank[f["level"]] <= rank.get(ign[f["id"]].get("level"), 0)]
    found = [f for f in found if f not in hidden]
    st["hidden"] = [{"id": f["id"], "title": f["title"]} for f in hidden]
    verdict, label, n = summarize(found, stopped())
    st.update(counts=n, entities=len(h.ents), stopped=bool(stopped()), psutil=bool(psutil))
    took = round(time.time() - t_start, 1)
    emit(f"  готово за {took} с: {label}")
    return {"verdict": verdict, "label": label, "findings": found, "stats": st, "took": took}


def _main(argv):
    deep, as_json = "--deep" in argv, "--json" in argv
    res = scan("deep" if deep else "quick", emit=(lambda *_: None) if as_json else print)
    if as_json:
        print(json.dumps(res, ensure_ascii=False, indent=1))
        return 0
    print()
    print(f"ИТОГ: {res['verdict'].upper()} — {res['label']}  ({res['took']} с)")
    for f in res["findings"]:
        print("-" * 100)
        print(f"{f['score']:>4}  " + explain(f))
    print("-" * 100)
    st = res["stats"]
    print("слои, с:", json.dumps(st["layers"], ensure_ascii=False))
    print("статистика:", json.dumps({k: v for k, v in st.items() if k not in ("layers", "errors", "not_checked")}, ensure_ascii=False))
    if st["not_checked"]:
        print("не проверено:", "; ".join(st["not_checked"]))
    if st["errors"]:
        print("ошибки слоёв:", json.dumps(st["errors"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
