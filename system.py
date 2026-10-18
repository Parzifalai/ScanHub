"""Системные проверки ScanHub: автозагрузка, сеть, драйверы, здоровье ПК, очистка, hosts, сторож.

Всё разовое: функции запускаются по кнопке и сразу завершаются. Постоянно ничего не работает
(кроме «сторожа», если пользователь сам его включит: это задача планировщика раз в 15 минут).
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import psutil

NO_WINDOW = 0x08000000
ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
HOSTS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")
WINDIR = os.environ.get("SystemRoot", r"C:\Windows").lower()
USER_DIRS = [p.lower() for p in filter(None, [os.environ.get("TEMP"), os.environ.get("APPDATA"),
                                              os.environ.get("LOCALAPPDATA"), os.environ.get("ProgramData"),
                                              r"C:\Users\Public"])]
MARK_BEGIN, MARK_END = "# >>> ScanHub: блокировка майнинг-доменов", "# <<< ScanHub"
NOCOIN_URL = "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"
WATCH_TASK = r"ScanHub\Сторож"

MINING_PORTS = {3333, 3334, 3335, 3336, 3357, 4444, 5555, 5588, 6666, 7777, 8899, 9999, 10128, 10300, 13333,
                14433, 14444, 15555, 17777, 20535, 20580, 45560, 45700}
POOL_RE = re.compile(r"(xmr|monero|nanopool|2miners|f2pool|supportxmr|hashvault|moneroocean|herominers|nicehash|"
                     r"ethermine|unmineable|minergate|c3pool|kryptex|zergpool|woolypooly|flexpool|coinhive|"
                     r"cryptoloot|webminepool|minexmr|crypto-pool|hashcity|prohashing|miningpool|mining-pool|"
                     r"\bminer\b|xmrig)", re.I)
AV_DOMAINS = re.compile(r"(kaspersky|drweb|eset|malwarebytes|virustotal|avast|avg\.com|bitdefender|norton|"
                        r"mcafee|sophos|windowsupdate|update\.microsoft|defender|wdcp\.microsoft|clamav|filescan)", re.I)
SCRIPT_HOSTS = ("powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "cmd.exe", "conhost")
BAD_ARGS = re.compile(r"(-enc\b|-encodedcommand|-w(indowstyle)?\s+h(idden)?|iex\b|invoke-expression|"
                      r"downloadstring|downloadfile|frombase64|http[s]?://|\\temp\\|\\appdata\\)", re.I)


def ps(script, timeout=180, env=None):
    """Выполнить PowerShell-скрипт и вернуть разобранный JSON (или None)."""
    full = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='SilentlyContinue'; " + script
    r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", full],
                       capture_output=True, timeout=timeout, creationflags=NO_WINDOW,
                       env={**os.environ, **(env or {})})
    out = r.stdout.decode("utf-8", "replace").strip()
    try:
        return json.loads(out) if out else None
    except ValueError:
        return None


def as_list(x):
    return [] if x is None else x if isinstance(x, list) else [x]


def in_user_dir(path):
    p = (path or "").lower()
    return any(p.startswith(d) for d in USER_DIRS)


def signatures(paths):
    """Пакетная проверка Authenticode: {путь: {status, signer}}."""
    paths = sorted({p for p in paths if p and os.path.isfile(p)})
    if not paths:
        return {}
    tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8")
    json.dump(paths, tmp)
    tmp.close()
    res = ps("(Get-Content -Raw -Encoding UTF8 $env:SH_LIST | ConvertFrom-Json) | ForEach-Object { "
             "$s = Get-AuthenticodeSignature -LiteralPath $_; [pscustomobject]@{p=$_; st=[string]$s.Status; "
             "cn=($s.SignerCertificate.Subject -replace '^CN=\"?([^\",]+).*','$1')} } | ConvertTo-Json -Compress",
             timeout=600, env={"SH_LIST": tmp.name})
    os.unlink(tmp.name)
    return {r["p"]: {"status": r["st"], "signer": r["cn"] or ""} for r in as_list(res) if isinstance(r.get("p"), str)}


def exe_from_command(cmd):
    """Достать путь к exe из строки команды автозагрузки."""
    if not cmd:
        return ""
    cmd = os.path.expandvars(cmd.strip())
    if cmd.startswith('"'):
        return cmd[1:].split('"', 1)[0]
    m = re.match(r"(.+?\.(exe|com|bat|cmd|vbs|js|ps1|scr|lnk))(\s|$)", cmd, re.I)
    return m.group(1) if m else cmd.split(" ")[0]


# ================================================================ автозагрузка

def autoruns():
    """Всё, что запускается с Windows (без прав администратора): реестр, папки, задачи, службы, WMI."""
    data = ps(r"""
$r = @()
$keys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
foreach ($k in $keys) { $i = Get-ItemProperty $k; if ($i) { $i.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
  ForEach-Object { $r += [pscustomobject]@{kind='Реестр'; where=($k -replace ':\\Software\\Microsoft\\Windows\\CurrentVersion',''); name=$_.Name; cmd=[string]$_.Value} } } }
$sh = New-Object -ComObject WScript.Shell
foreach ($d in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")) {
  Get-ChildItem -LiteralPath $d -File | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
    $t = if ($_.Extension -eq '.lnk') { $l = $sh.CreateShortcut($_.FullName); ('"' + $l.TargetPath + '" ' + $l.Arguments) } else { '"' + $_.FullName + '"' }
    $r += [pscustomobject]@{kind='Папка автозагрузки'; where=$d; name=$_.Name; cmd=$t} } }
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { $t = $_
  $t.Actions | Where-Object { $_.Execute } | ForEach-Object {
    $r += [pscustomobject]@{kind='Задача'; where=$t.TaskPath; name=$t.TaskName; cmd=('"' + $_.Execute.Trim('"') + '" ' + $_.Arguments); author=[string]$t.Author} } }
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' } | ForEach-Object {
  $r += [pscustomobject]@{kind='Служба'; where=$_.State; name=$_.Name; cmd=[string]$_.PathName; author=[string]$_.DisplayName} }
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | ForEach-Object {
  $r += [pscustomobject]@{kind='WMI-подписка'; where='root\subscription'; name=$_.Name; cmd=[string]$_.CommandLineTemplate} }
Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
  $r += [pscustomobject]@{kind='WMI-подписка'; where='root\subscription'; name=$_.Name; cmd=[string]$(if ($_.ScriptFileName) { $_.ScriptFileName } else { 'скрипт: ' + ([string]$_.ScriptText).Substring(0, [Math]::Min(150, ([string]$_.ScriptText).Length)) })} }
# классические места закрепления, которые не видно в «Автозагрузке» Диспетчера задач
foreach ($h in 'HKLM','HKCU') { $wl = Get-ItemProperty "${h}:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
  foreach ($n in 'Shell','Userinit') { if ($wl.$n) { $r += [pscustomobject]@{kind='Вход в Windows'; where="$h Winlogon"; name=$n; cmd=[string]$wl.$n} } } }
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
  $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
  if ($d) { $r += [pscustomobject]@{kind='Перехват запуска'; where='IFEO'; name=$_.PSChildName; cmd=[string]$d} } }
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue | ForEach-Object {
  $m = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).MonitorProcess
  if ($m) { $r += [pscustomobject]@{kind='Перехват запуска'; where='SilentProcessExit'; name=$_.PSChildName; cmd=[string]$m} } }
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
  $w = Get-ItemProperty $k -ErrorAction SilentlyContinue
  if ($w.AppInit_DLLs -and $w.LoadAppInit_DLLs -eq 1) { $r += [pscustomobject]@{kind='AppInit_DLLs'; where=$k; name='AppInit_DLLs'; cmd=[string]$w.AppInit_DLLs} } }
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run') {
  $i = Get-ItemProperty $k -ErrorAction SilentlyContinue; if ($i) { $i.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
  ForEach-Object { $r += [pscustomobject]@{kind='Реестр (политики)'; where=$k; name=$_.Name; cmd=[string]$_.Value} } } }
$ls = (Get-ItemProperty 'HKCU:\Environment' -ErrorAction SilentlyContinue).UserInitMprLogonScript
if ($ls) { $r += [pscustomobject]@{kind='Сценарий входа'; where='HKCU\Environment'; name='UserInitMprLogonScript'; cmd=[string]$ls} }
$r | ConvertTo-Json -Compress -Depth 3
""", timeout=300)
    items = []
    for d in as_list(data):
        exe = exe_from_command(d.get("cmd"))
        if exe and not os.path.isabs(exe):
            found = shutil.which(exe)
            exe = found or exe
        items.append({**d, "exe": exe})
    # Winlogon: нормально — только explorer.exe и userinit.exe; всё остальное — подмена входа в Windows
    def normal_logon(i):
        v = (i.get("cmd") or "").strip().strip(",").lower()
        if i["name"] == "Shell":
            return v in ("explorer.exe", os.path.join(WINDIR, "explorer.exe").lower()) or (i["where"].startswith("HKCU") and not v)
        return [x.strip() for x in v.split(",") if x.strip()] in ([os.path.join(WINDIR, "system32", "userinit.exe").lower()], ["userinit.exe"])
    items = [i for i in items if not (i["kind"] == "Вход в Windows" and normal_logon(i))]
    # «залипание клавиш» и другие программы экрана входа: если подменены — это бэкдор (запуск cmd без пароля)
    sys32 = os.path.join(WINDIR, "system32")
    access = [os.path.join(sys32, n) for n in ("sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe", "Narrator.exe", "DisplaySwitch.exe", "AtBroker.exe")]
    asig = {k.lower(): v for k, v in signatures([a for a in access if os.path.exists(a)]).items()}
    for a in access:
        s = asig.get(a.lower())
        if s and (s["status"] != "Valid" or "microsoft" not in s["signer"].lower()):
            items.append({"kind": "Экран входа", "where": sys32, "name": os.path.basename(a), "cmd": a, "exe": a, "replaced": True})

    # системные службы и задачи Microsoft из папки Windows — не интересны, их сотни
    def boring(i):
        e = i["exe"].lower()
        return (i["kind"] in ("Служба", "Задача") and e.startswith(WINDIR)
                and not BAD_ARGS.search(i.get("cmd") or "") and not os.path.basename(e).startswith(SCRIPT_HOSTS))
    items = [i for i in items if not boring(i)]
    sigs = signatures([i["exe"] for i in items])
    for i in items:
        s = sigs.get(i["exe"])
        i["sig"] = s
        flags = []
        e, cmd = i["exe"].lower(), i.get("cmd") or ""
        if i["kind"] == "WMI-подписка":
            flags.append("WMI-подписка: так закрепляются продвинутые вредоносы")
        if i["kind"] == "Вход в Windows":
            flags.append("подменён запуск при входе в Windows (Winlogon) — так закрепляются вредоносы")
        if i["kind"] == "Перехват запуска":
            flags.append(f"вместо или вместе с {i['name']} запускается другая программа — так вредоносы перехватывают запуск")
        if i["kind"] == "AppInit_DLLs":
            flags.append("библиотека встраивается во все программы (AppInit_DLLs) — так действуют вредоносы")
        if i["kind"] == "Сценарий входа":
            flags.append("сценарий входа пользователя — редкий способ автозапуска, которым пользуются вредоносы")
        if i["kind"] == "Реестр (политики)":
            flags.append("автозапуск через политики — обычные программы так не делают")
        if i.get("replaced"):
            flags.append("системная программа экрана входа подменена — так получают командную строку без пароля")
        if not os.path.exists(i["exe"]):
            flags.append("файл не найден (осталась запись)")
        elif s and s["status"] != "Valid":
            flags.append("без цифровой подписи" if s["status"] == "NotSigned" else f"подпись: {s['status']}")
        if in_user_dir(e) and (not s or s["status"] != "Valid"):
            flags.append("запускается из папки пользователя")
        if os.path.basename(e).startswith(SCRIPT_HOSTS) and BAD_ARGS.search(cmd):
            flags.append("скрипт с подозрительными аргументами")
        ms_signed = bool(s and s["status"] == "Valid" and "microsoft" in s["signer"].lower())
        if i["kind"] == "Задача" and (i.get("where") or "").startswith("\\Microsoft\\") and not e.startswith(WINDIR) \
                and "program files" not in e and not ms_signed:
            flags.append("задача маскируется под Microsoft")
        bad = any(k in f for f in flags for k in ("маскируется", "подозрительными", "WMI", "Winlogon", "перехватывают", "AppInit",
                                                  "подменена", "сценарий входа"))
        i["flags"] = flags
        i["level"] = "bad" if bad else "warn" if [f for f in flags if "не найден" not in f] else \
            "info" if flags else "ok"
    order = {"bad": 0, "warn": 1, "info": 2, "ok": 3}
    items.sort(key=lambda i: (order[i["level"]], i["kind"], i["name"].lower()))
    return items


# ================================================================ сеть

def network():
    conns, listen = [], []
    procs = {}
    for c in psutil.net_connections(kind="inet"):
        if not c.pid:
            continue
        if c.pid not in procs:
            try:
                p = psutil.Process(c.pid)
                procs[c.pid] = (p.name(), p.exe())
            except (psutil.Error, OSError):
                procs[c.pid] = ("?", "")
        name, exe = procs[c.pid]
        row = {"pid": c.pid, "name": name, "exe": exe, "local": f"{c.laddr.ip}:{c.laddr.port}"}
        if c.status == "LISTEN":
            if c.laddr.ip not in ("127.0.0.1", "::1"):
                listen.append({**row, "port": c.laddr.port, "ip": c.laddr.ip})
        elif c.raddr and c.status == "ESTABLISHED":
            row.update(remote=f"{c.raddr.ip}:{c.raddr.port}", rport=c.raddr.port)
            row["flags"] = (["порт, типичный для майнинг-пулов"] if c.raddr.port in MINING_PORTS else [])
            conns.append(row)
    dns = as_list(ps("Get-DnsClientCache | Select-Object -ExpandProperty Entry -Unique | ConvertTo-Json -Compress"))
    pools = sorted({d for d in dns if isinstance(d, str) and POOL_RE.search(d)})
    hosts_bad = []
    try:
        inside = False
        for line in open(HOSTS, encoding="utf-8", errors="replace"):
            s = line.strip()
            if s.startswith(MARK_BEGIN):
                inside = True
            elif s.startswith(MARK_END):
                inside = False
            elif s and not s.startswith("#") and not inside:
                parts = s.split()
                if len(parts) >= 2 and AV_DOMAINS.search(" ".join(parts[1:])):
                    hosts_bad.append(s)
    except OSError:
        pass
    conns.sort(key=lambda r: (not r["flags"], r["name"].lower()))
    return {"connections": conns, "listening": sorted(listen, key=lambda r: r["port"]), "pool_dns": pools,
            "hosts_tampered": hosts_bad, "dns_count": len(dns)}


# ================================================================ драйверы

GENERIC_DEV = re.compile(r"(?i)^(usb input device|hid-compliant|hid-совместим|usb composite device|составное usb|usb-устройство ввода|"
                         r"запоминающее устройство|usb mass storage|generic|unknown|неизвестное)")


def device_name(name, bus=""):
    """«USB Input Device» ничего не говорит человеку — показываем имя, которое сообщило само устройство («Gaming Mouse»)."""
    name, bus = (name or "").strip(), (bus or "").strip()
    if bus and (not name or GENERIC_DEV.match(name)) and bus.lower() != name.lower():
        return f"{bus} ({name})" if name else bus
    return name or "Неизвестное устройство"


def device_hint(cls, code, dev_id=""):
    """Совет для устройств, у которых драйвер встроен в Windows: «обнови драйвер» им не поможет."""
    c, i = (cls or "").lower(), (dev_id or "").upper()
    if code in (10, 31, 43) and (c in ("hidclass", "mouse", "keyboard", "usb") or i.startswith(("USB\\", "HID\\"))):
        return ("Драйвер у мышей, клавиатур и других USB-устройств ввода встроен в Windows — обновлять его обычно нечего. "
                "Чаще дело в самом устройстве, кабеле или порте: отключи и подключи в другой USB-порт (прямо в ноутбук, без хаба "
                "и переходника), попробуй другой кабель или другой компьютер. Не заработало и там — устройство неисправно. "
                "Если на другом компьютере работает — перезагрузи этот и подключи снова.")
    return ""


def drivers():
    d = ps(r"""
$drv = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -in 'DISPLAY','NET','MEDIA','BLUETOOTH','CAMERA','BIOMETRIC','HIDCLASS','SYSTEM' -and $_.DriverProviderName -ne 'Microsoft' -and $_.DeviceName } |
  Select-Object DeviceName, DeviceClass, DriverVersion, @{n='Date';e={if($_.DriverDate){$_.DriverDate.ToString('yyyy-MM-dd')}}}, DriverProviderName -Unique
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
[pscustomobject]@{drivers=@($drv); maker=$cs.Manufacturer; model=$cs.Model; family=$cs.SystemFamily;
  bios=$bios.SMBIOSBIOSVersion; bios_date=$(if($bios.ReleaseDate){$bios.ReleaseDate.ToString('yyyy-MM-dd')})} | ConvertTo-Json -Compress -Depth 4
""", timeout=180) or {}
    seen, drv = set(), []
    for x in as_list(d.get("drivers")):
        key = (x.get("DeviceName"), x.get("DriverVersion"))
        if key in seen:
            continue
        seen.add(key)
        drv.append(x)
    drv.sort(key=lambda x: (x.get("DeviceClass") or "", x.get("DeviceName") or ""))
    nv = None
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=name,driver_version", "--format=csv,noheader"],
                             capture_output=True, text=True, timeout=15, creationflags=NO_WINDOW).stdout.strip()
        if out:
            name, ver = [x.strip() for x in out.split(",")[:2]]
            nv = {"name": name, "version": ver}
    except Exception:
        pass
    import hwcheck
    probs = [{"Name": p["name"], "PNPClass": p["cls"], "ConfigManagerErrorCode": p["code"], "Bus": p.get("bus"), "Id": p["id"]}
             for p in hwcheck.problem_devices()]
    for p in probs:
        p["Shown"] = device_name(p.get("Name"), p.get("Bus"))
        p["Hint"] = device_hint(p.get("PNPClass"), p.get("ConfigManagerErrorCode"), p.get("Id"))
    # код 14 — «нужна перезагрузка» (часто после обновления прошивки), 45 — устройство просто не подключено: это не ошибки
    return {"problems": [p for p in probs if p.get("ConfigManagerErrorCode") not in (14, 45)],
            "pending": [p for p in probs if p.get("ConfigManagerErrorCode") == 14], "drivers": drv, "maker": d.get("maker"), "model": d.get("model"),
            "family": d.get("family"), "bios": d.get("bios"), "bios_date": d.get("bios_date"), "nvidia": nv}


def driver_updates():
    """Поиск драйверов в Windows Update (только поиск, без установки). Обычно 30–120 секунд."""
    res = ps(r"""
$s = New-Object -ComObject Microsoft.Update.Session
$r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Driver'")
@($r.Updates | ForEach-Object { [pscustomobject]@{title=$_.Title; cls=$_.DriverClass; model=$_.DriverModel;
  date=$(if($_.DriverVerDate){$_.DriverVerDate.ToString('yyyy-MM-dd')}); size=$_.MaxDownloadSize} }) | ConvertTo-Json -Compress
""", timeout=600)
    return as_list(res)


# ================================================================ здоровье ПК

def health():
    d = ps(r"""
$o = [ordered]@{}
$m = Get-MpComputerStatus
$o.defender = @{realtime=$m.RealTimeProtectionEnabled; sig_age=$m.AntivirusSignatureAge; quick_age=$m.QuickScanAge; tamper=$m.IsTamperProtected; enabled=$m.AntivirusEnabled}
$o.firewall = @(Get-NetFirewallProfile | ForEach-Object { @{name=[string]$_.Name; on=[bool]$_.Enabled} })
$pol = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$o.uac = @{lua=$pol.EnableLUA; prompt=$pol.ConsentPromptBehaviorAdmin}
$o.secureboot = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State').UEFISecureBootEnabled
$hf = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
$o.last_update = $(if($hf){$hf.InstalledOn.ToString('yyyy-MM-dd')})
$o.reboot_pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
$o.disks = @(Get-PhysicalDisk | ForEach-Object { @{name=$_.FriendlyName; media=[string]$_.MediaType; health=[string]$_.HealthStatus; size=$_.Size} })
$o.problem_devices = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -notin 0,14,45 }).Count
$os = Get-CimInstance Win32_OperatingSystem
$o.os = @{caption=$os.Caption; build=$os.BuildNumber; installed=$os.InstallDate.ToString('yyyy-MM-dd')}
$o.restore = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore').RPSessionInterval
$tmp = Join-Path $env:TEMP 'scanhub-battery.xml'
powercfg /batteryreport /xml /output $tmp | Out-Null
if (Test-Path $tmp) { [xml]$x = Get-Content $tmp; $b = $x.BatteryReport.Batteries.Battery | Select-Object -First 1
  if ($b) { $o.battery = @{design=[long]$b.DesignCapacity; full=[long]$b.FullChargeCapacity; cycles=[int]$b.CycleCount} }; Remove-Item $tmp }
$o | ConvertTo-Json -Compress -Depth 4
""", timeout=240) or {}
    d["volumes"] = []
    for p in psutil.disk_partitions():
        try:
            u = psutil.disk_usage(p.mountpoint)
            d["volumes"].append({"mount": p.mountpoint.rstrip("\\"), "total": u.total, "free": u.free, "percent": u.percent})
        except OSError:
            pass
    vm = psutil.virtual_memory()
    d["ram"] = {"total": vm.total, "percent": vm.percent}
    d["uptime_days"] = round((time.time() - psutil.boot_time()) / 86400, 1)
    d["winget"] = winget_upgrades()
    return d


def winget_upgrades():
    """Устаревшие программы по данным winget (если он есть)."""
    if not shutil.which("winget"):
        return None
    try:
        r = subprocess.run(["winget", "upgrade", "--accept-source-agreements", "--disable-interactivity"],
                           capture_output=True, timeout=180, creationflags=NO_WINDOW)
        text = r.stdout.decode("utf-8", "replace")
    except Exception:
        return None
    lines = [l.rstrip() for l in text.splitlines()]
    try:
        h = next(i for i, l in enumerate(lines) if l.startswith("---"))
    except StopIteration:
        return []
    header = lines[h - 1]
    cols = [m.start() for m in re.finditer(r"\S+", header)]
    apps = []
    for l in lines[h + 1:]:
        if not l.strip() or len(l) < cols[-1] or re.match(r"^\d+ (upgrades|обновлен)", l):
            continue
        parts = [l[cols[i]:cols[i + 1] if i + 1 < len(cols) else None].strip() for i in range(len(cols))]
        # служебные строки winget («Несколько пакетов содержат номера версий…») режутся по колонкам в мусор — отсекаем по виду id
        if len(parts) >= 4 and re.fullmatch(r"[A-Za-z0-9][\w.\-+]*", parts[1]) and re.match(r"^[\w.\-<>]", parts[3] or ""):
            apps.append({"name": parts[0], "id": parts[1], "version": parts[2], "available": parts[3],
                         "source": parts[4] if len(parts) > 4 else ""})
    apps = [a for a in apps if a["id"] not in NOT_APPS]
    _mark_ghosts(apps)
    return apps


# не программы, а помощники обновления самой Windows: их «обновление» открывает окно обновления системы
NOT_APPS = {"Microsoft.WindowsInstallationAssistant", "Microsoft.UpdateAssistant", "Microsoft.Windows10UpgradeAssistant"}


def _mark_ghosts(apps):
    """winget видит программу по записи в списке установленных. Если программу удалили вручную (папку стёрли),
    запись остаётся, и winget предлагает «обновить» то, чего нет (так было с OKX и Kudu). Такие помечаем ghost:
    деинсталлятора нет и папки установки нет — обновлять нечего, нужно убрать запись."""
    if not apps:
        return
    try:
        import uninstall                      # здесь, а не наверху: uninstall сам импортирует system
        progs = uninstall.programs()
    except Exception:
        return
    for a in apps:
        n = a["name"].lower().rstrip("…").strip()
        cut = a["name"].endswith("…")         # winget обрезает длинные имена
        same = [p for p in progs if (p["name"].lower().startswith(n) if cut else p["name"].lower() == n)
                and (not a["version"] or p["version"] == a["version"] or a["version"] == "Unknown")]
        if same and all(p["broken"] and not p["location"] for p in same):
            a["ghost"] = {"key": same[0]["key"], "name": same[0]["name"]}


# ================================================================ очистка диска

def dir_size(path, limit_s=20):
    total, t0 = 0, time.time()
    for root, dirs, files in os.walk(path, onerror=lambda e: None):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
        if time.time() - t0 > limit_s:
            break
    return total


def _browser_caches():
    la, ra = os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", "")
    pats = {
        "Chrome": [la + r"\Google\Chrome\User Data\*\Cache", la + r"\Google\Chrome\User Data\*\Code Cache"],
        "Edge": [la + r"\Microsoft\Edge\User Data\*\Cache", la + r"\Microsoft\Edge\User Data\*\Code Cache"],
        "Яндекс Браузер": [la + r"\Yandex\YandexBrowser\User Data\*\Cache", la + r"\Yandex\YandexBrowser\User Data\*\Code Cache"],
        "Opera": [la + r"\Opera Software\*\Cache"],
        "Firefox": [la + r"\Mozilla\Firefox\Profiles\*\cache2"],
        "Discord": [ra + r"\discord\Cache", ra + r"\discord\Code Cache"],
    }
    return {k: [p for pat in v for p in glob.glob(pat)] for k, v in pats.items()}


def cleanup_scan():
    la = os.environ.get("LOCALAPPDATA", "")
    cats = [
        {"id": "temp", "label": "Временные файлы (TEMP)", "paths": [os.environ.get("TEMP", "")], "safe": True},
        {"id": "wintemp", "label": "Временные файлы Windows", "paths": [os.path.join(WINDIR, "Temp")], "safe": True},
        {"id": "crash", "label": "Дампы падений программ", "paths": [la + r"\CrashDumps"], "safe": True},
        {"id": "inet", "label": "Кэш Windows (INetCache)", "paths": [la + r"\Microsoft\Windows\INetCache"], "safe": True},
        {"id": "wu", "label": "Загрузки Windows Update", "paths": [os.path.join(WINDIR, r"SoftwareDistribution\Download")],
         "safe": False, "note": "чистит «Очистка диска Windows»"},
    ]
    for name, paths in _browser_caches().items():
        if paths:
            cats.append({"id": "browser:" + name, "label": f"Кэш: {name}", "paths": paths, "safe": True,
                         "note": "закрой " + ("Discord" if name == "Discord" else "браузер") + " перед очисткой"})
    for c in cats:
        c["size"] = sum(dir_size(p, 15) for p in c["paths"] if p and os.path.isdir(p))
    rb = ps(r"$s=(New-Object -ComObject Shell.Application).NameSpace(10); $t=0; $n=0; "
            r"foreach($i in $s.Items()){ $t += $i.ExtendedProperty('Size'); $n++ }; @{size=$t; count=$n} | ConvertTo-Json -Compress")
    big = []
    home = os.path.expanduser("~")
    for name in ("Downloads", "Desktop", "Videos", "Documents"):
        p = os.path.join(home, name)
        if os.path.isdir(p):
            big.append({"path": p, "size": dir_size(p, 20)})
    for p in (r"C:\hiberfil.sys", r"C:\pagefile.sys"):
        try:
            big.append({"path": p, "size": os.stat(p).st_size, "system": True})
        except OSError:
            pass
    return {"categories": cats, "recycle": rb or {"size": 0, "count": 0}, "big": big}


def cleanup_run(ids, older_hours=24):
    """Удалить содержимое выбранных категорий (только файлы старше older_hours; занятые пропускаются)."""
    allowed = {c["id"]: c for c in cleanup_scan()["categories"] if c["safe"]}
    freed, errors, cutoff = 0, 0, time.time() - older_hours * 3600
    for cid in ids:
        c = allowed.get(cid)
        if not c:
            continue
        for base in c["paths"]:
            for root, dirs, files in os.walk(base, topdown=False, onerror=lambda e: None):
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        st = os.lstat(p)
                        if st.st_mtime < cutoff:
                            os.remove(p)
                            freed += st.st_size
                    except OSError:
                        errors += 1
                for d in dirs:
                    try:
                        os.rmdir(os.path.join(root, d))
                    except OSError:
                        pass
    return {"freed": freed, "skipped": errors}


# ================================================================ hosts: блокировка майнинг-доменов

def hosts_status():
    try:
        text = open(HOSTS, encoding="utf-8", errors="replace").read()
    except OSError as e:
        return {"error": str(e)}
    on = MARK_BEGIN in text
    n = 0
    if on:
        block = text.split(MARK_BEGIN, 1)[1].split(MARK_END, 1)[0]
        n = sum(1 for l in block.splitlines() if l.strip() and not l.startswith("#"))
    return {"enabled": on, "domains": n}


def _hosts_without_block(text):
    while MARK_BEGIN in text:
        a, rest = text.split(MARK_BEGIN, 1)
        b = rest.split(MARK_END, 1)[1] if MARK_END in rest else ""
        text = a.rstrip("\r\n") + "\n" + b.lstrip("\r\n")
    return text


def hosts_prepare(enable):
    """Подготовить новый hosts в data\\hosts.new; записывает его elevated-помощник."""
    text = open(HOSTS, encoding="utf-8", errors="replace").read()
    os.makedirs(DATA, exist_ok=True)
    backup = os.path.join(DATA, "hosts.backup")
    if not os.path.exists(backup):
        shutil.copy2(HOSTS, backup)
    text = _hosts_without_block(text)
    if enable:
        raw = urllib.request.urlopen(urllib.request.Request(NOCOIN_URL, headers={"User-Agent": "ScanHub"}),
                                     timeout=60).read().decode("utf-8", "replace")
        domains = sorted({l.split()[1] for l in raw.splitlines()
                          if l.strip() and not l.startswith("#") and len(l.split()) >= 2 and l.split()[1] not in ("localhost",)})
        block = [MARK_BEGIN, f"# источник: {NOCOIN_URL}"] + [f"0.0.0.0 {d}" for d in domains] + [MARK_END]
        text = text.rstrip("\r\n") + "\n\n" + "\n".join(block) + "\n"
    new = os.path.join(DATA, "hosts.new")
    with open(new, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(text)
    return new


# ================================================================ сторож (задача планировщика)

def watch_explain(text):
    """Срабатывание Сторожа простыми словами: насколько это страшно, что это и что делать.
    lvl: ok — не страшно, warn — стоит посмотреть, bad — важно. go — раздел ScanHub для кнопки."""
    t = text or ""
    m = re.search(r"(процессор|видеокарта) перегревается: (\d+)", t)
    if m:
        who, deg = m.group(1), int(m.group(2))
        cpu = who == "процессор"
        hot = deg >= (100 if cpu else 92)
        return {"lvl": "bad" if hot else "warn", "title": f"{'Процессор' if cpu else 'Видеокарта'} нагрелся до {deg}°C",
                "what": (f"Для ноутбука под нагрузкой (игра, сборка, видео) {deg}°C — {'выше нормы' if hot else 'верхняя граница нормы'}: "
                         f"{'процессор' if cpu else 'видеокарта'} сам снижает частоту, чтобы не перегреться, — отсюда бывают просадки FPS. "
                         "Опасно, если так горячо в простое или часто."),
                "todo": "Не закрывай решётки вентиляции (не ставь ноутбук на кровать или колени), поставь на подставку. Если греется в простое — "
                        "посмотри «Почему шумит»: кто грузит процессор. Раз в 1–2 года ноутбуку нужна чистка от пыли и замена термопасты.",
                "go": "speed:noise", "go_label": "Почему шумит"}
    m = re.search(r"на диске (\S+) осталось ([\d.,]+) ГБ", t)
    if m:
        return {"lvl": "warn", "title": f"Заканчивается место на диске {m.group(1)}",
                "what": f"Осталось {m.group(2)} ГБ. Когда места почти нет, Windows тормозит и не может поставить обновления.",
                "todo": "Очисти мусор и Корзину, потом посмотри, что занимает место.", "go": "clean:junk", "go_label": "Очистить мусор"}
    if re.search(r"майнинг|майнер", t, re.I):
        return {"lvl": "bad", "title": "Похоже на скрытый майнер",
                "what": "Программа нагружала компьютер или обращалась к майнинг-пулу — так ведут себя скрытые майнеры (тайно «добывают» криптовалюту на чужом ПК).",
                "todo": "Запусти глубокую проверку — она найдёт и уберёт майнер. Если это твой собственный майнер — всё в порядке.",
                "go": "scan:deep", "go_label": "Глубокая проверка"}
    m = re.match(r"(.+?\.exe) аварийно завершилась", t, re.I)
    if m:
        app = m.group(1)
        try:
            import appinfo
            about = appinfo.about(app)["ru"]
        except Exception:
            about = ""
        return {"lvl": "ok", "title": f"Программа {app} вылетела",
                "what": (about + " " if about else "") + "Одиночный вылет программы — не опасно для компьютера: она просто закрылась с ошибкой.",
                "todo": "Если не замечал проблем — ничего делать не надо. Если вылетает часто или мешает — открой «Сбои и ошибки»: там видно, как часто и почему.",
                "go": "health:crash", "go_label": "Сбои и ошибки"}
    if re.search(r"синий экран|BugCheck|аппаратн|WHEA", t, re.I):
        return {"lvl": "bad", "title": "Серьёзный сбой Windows", "what": t[:200],
                "todo": "Открой «Сбои и ошибки» — там причина и что сделать.", "go": "health:crash", "go_label": "Сбои и ошибки"}
    if re.search(r"выключ|Kernel-Power", t, re.I):
        return {"lvl": "warn", "title": "Компьютер выключился неправильно", "what": t[:200],
                "todo": "Если выключал кнопкой или садилась батарея — не страшно. Если сам — открой «Сбои и ошибки».", "go": "health:crash", "go_label": "Сбои и ошибки"}
    return {"lvl": "warn", "title": t.split(" — ")[0][:120], "what": t[:240], "todo": "Подробности — в «Сбоях и ошибках».",
            "go": "health:crash", "go_label": "Сбои и ошибки"}


def watch_status():
    r = subprocess.run(["schtasks", "/Query", "/TN", WATCH_TASK], capture_output=True, creationflags=NO_WINDOW)
    alerts = []
    try:
        alerts = json.load(open(os.path.join(DATA, "watch_alerts.json"), encoding="utf-8"))[:20]
    except (OSError, ValueError):
        pass
    for a in alerts:                       # одинаковые строки одного прохода — одной строкой ×N, у каждой — объяснение
        seen = {}
        for f in a.get("found") or []:
            if f in seen:
                seen[f]["count"] += 1
            else:
                seen[f] = {"text": f, "count": 1, **watch_explain(f)}
        a["items"] = list(seen.values())
    return {"enabled": r.returncode == 0, "alerts": alerts}


def watch_set(enable):
    if enable:
        pyw = sys.executable.replace("python.exe", "pythonw.exe")
        tr = f'"{pyw}" "{os.path.join(ROOT, "scanhub.py")}" --watch-once'
        r = subprocess.run(["schtasks", "/Create", "/TN", WATCH_TASK, "/SC", "MINUTE", "/MO", "15", "/TR", tr, "/F"],
                           capture_output=True, creationflags=NO_WINDOW)
    else:
        r = subprocess.run(["schtasks", "/Delete", "/TN", WATCH_TASK, "/F"], capture_output=True, creationflags=NO_WINDOW)
    if r.returncode:
        raise RuntimeError((r.stderr or r.stdout).decode("cp866", "replace").strip())
    return watch_status()


def toast(title, text):
    """Уведомление Windows без сторонних модулей."""
    from html import escape
    xml = (f"<toast><visual><binding template='ToastGeneric'><text>{escape(title)}</text><text>{escape(text)}</text>"
           f"</binding></visual></toast>")
    ps(r"""[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$x = New-Object Windows.Data.Xml.Dom.XmlDocument; $x.LoadXml($env:SH_XML)
$id = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show([Windows.UI.Notifications.ToastNotification]::new($x))""",
       env={"SH_XML": xml})


def watch_once():
    """Один проход сторожа: 40 секунд наблюдения, при подозрении — уведомление."""
    try:                            # история здоровья — раз в сутки, даже если ScanHub не открывали
        __import__("health_history").snapshot()
    except Exception as e:
        __import__("report").record("история здоровья (сторож)", e)
    import metrics
    m = metrics.METRICS
    m.light = True                  # без постоянного опроса видеокарты по процессам — включится, только если она занята
    m.touch()
    for _ in range(8):
        time.sleep(5)
        m.touch()
    snap = m.snapshot()
    sus = snap["suspicious"]
    net = network()
    found = [f"{p['name']}: {'; '.join(p['flags'])}" for p in sus]
    if net["pool_dns"]:
        found.append("обращения к майнинг-пулам: " + ", ".join(net["pool_dns"][:3]))
    found += [f"{c['name']} → {c['remote']} (порт майнинг-пула)" for c in net["connections"] if c["flags"]]
    # перегрев и место на диске
    g = snap.get("gpu") or {}
    if (g.get("temp") or 0) >= 87 or g.get("throttle"):
        found.append(f"видеокарта перегревается: {g.get('temp', 0):.0f}°C")
    ct = (snap.get("sensors") or {}).get("cpu_temp")
    if ct and ct >= 95:
        found.append(f"процессор перегревается: {ct:.0f}°C")
    for p in psutil.disk_partitions():
        try:
            u = psutil.disk_usage(p.mountpoint)
            if "fixed" in p.opts and u.free < 5 * 2 ** 30:
                found.append(f"на диске {p.mountpoint.rstrip(chr(92))} осталось {u.free / 2 ** 30:.1f} ГБ")
        except OSError:
            pass
    # новые сбои с прошлого прохода
    st_path = os.path.join(DATA, "watch_state.json")
    try:
        last = json.load(open(st_path, encoding="utf-8")).get("events_from")
    except (OSError, ValueError):
        last = None
    from datetime import datetime as _dt
    now_iso = _dt.now().astimezone().isoformat()
    if last:
        import diag
        for e in diag.new_events_since(last)[:5]:
            found.append(f"{e['title']} — {e['text'][:120]}")
    json.dump({"events_from": now_iso}, open(st_path, "w", encoding="utf-8"))
    if found:
        path = os.path.join(DATA, "watch_alerts.json")
        try:
            alerts = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError):
            alerts = []
        alerts.insert(0, {"time": time.strftime("%Y-%m-%d %H:%M"), "found": found})
        json.dump(alerts[:100], open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        toast("ScanHub: " + ("подозрение на майнер" if sus or net["pool_dns"] else "что-то не так"), found[0][:180])
    return found


# ================================================================ очистка оперативной памяти

MEMCLEAN_TASK = r"ScanHub\MemClean"
MEMCLEAN_SCRIPT = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "ScanHub", "memclean.ps1")
MEMCLEAN_JSON = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "ScanHub", "memclean.json")


def _mem():
    vm = psutil.virtual_memory()
    return {"total": vm.total, "used": vm.total - vm.available, "percent": vm.percent}


def memclean_installed():
    if not os.path.exists(MEMCLEAN_SCRIPT):
        return False
    return subprocess.run(["schtasks", "/Query", "/TN", MEMCLEAN_TASK], capture_output=True,
                          creationflags=NO_WINDOW).returncode == 0


def mem_quick():
    """Быстрая очистка без прав администратора: сжать рабочие наборы всех доступных процессов (как EmptyWorkingSet)."""
    import ctypes
    k32 = ctypes.windll.kernel32
    k32.OpenProcess.restype = ctypes.c_void_p
    before, trimmed, skipped = _mem(), 0, 0
    for p in psutil.process_iter(["pid"]):
        h = k32.OpenProcess(0x1000 | 0x0100, False, p.info["pid"])     # QUERY_LIMITED_INFORMATION | SET_QUOTA
        if not h:
            skipped += 1
            continue
        try:
            if k32.K32EmptyWorkingSet(ctypes.c_void_p(h)):
                trimmed += 1
        finally:
            k32.CloseHandle(ctypes.c_void_p(h))
    time.sleep(1.5)
    after = _mem()
    return {"mode": "quick", "before": before, "after": after, "freed": max(0, before["used"] - after["used"]),
            "processes": trimmed, "skipped": skipped, "full_available": memclean_installed()}


def mem_full():
    """Полная очистка (как Mem Reduct): задача с правами администратора — рабочие наборы, файловый кэш, изменённые страницы, standby."""
    if not memclean_installed():
        raise RuntimeError("полная очистка не включена — нажми «Включить полную очистку» (один раз попросит UAC)")
    before = _mem()
    t0 = time.time()
    subprocess.run(["schtasks", "/Run", "/TN", MEMCLEAN_TASK], capture_output=True, creationflags=NO_WINDOW)
    res = None
    while time.time() - t0 < 45:
        time.sleep(1)
        try:
            d = json.load(open(MEMCLEAN_JSON, encoding="utf-8-sig"))
            if d.get("t", 0) >= int(t0) - 1:
                res = d
                break
        except (OSError, ValueError):
            pass
    if res is None:
        raise RuntimeError("задача очистки не ответила за 45 секунд")
    time.sleep(1)
    after = _mem()
    ok = {k: res.get(k) == 0 for k in ("working_sets", "file_cache", "modified", "standby")}
    return {"mode": "full", "before": before, "after": after, "freed": max(0, before["used"] - after["used"]),
            "steps": ok, "full_available": True}


# ================================================================ комплектующие

def hardware():
    """Все комплектующие ПК (без прав администратора)."""
    d = ps(r"""
$o = [ordered]@{}
$cs = Get-CimInstance Win32_ComputerSystem; $bios = Get-CimInstance Win32_BIOS; $bb = Get-CimInstance Win32_BaseBoard
$o.system = @{maker=$cs.Manufacturer; model=$cs.Model; family=$cs.SystemFamily; type=[int]$cs.PCSystemType;
  board=("$($bb.Manufacturer) $($bb.Product)").Trim(); bios=$bios.SMBIOSBIOSVersion; bios_date=$(if($bios.ReleaseDate){$bios.ReleaseDate.ToString('yyyy-MM-dd')})}
$o.cpu = @(Get-CimInstance Win32_Processor | ForEach-Object { @{name=$_.Name.Trim(); cores=$_.NumberOfCores; threads=$_.NumberOfLogicalProcessors;
  mhz=$_.MaxClockSpeed; l2=$_.L2CacheSize; l3=$_.L3CacheSize; socket=$_.SocketDesignation; maker=$_.Manufacturer} })
$arr = Get-CimInstance Win32_PhysicalMemoryArray | Select-Object -First 1
$o.ram = @{slots=[int]$arr.MemoryDevices; max_kb=[long]$arr.MaxCapacityEx; total=[long]$cs.TotalPhysicalMemory; modules=@(Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
  @{maker=$_.Manufacturer; part=([string]$_.PartNumber).Trim(); size=[long]$_.Capacity; speed=$_.Speed; cfg=$_.ConfiguredClockSpeed; slot=$_.DeviceLocator;
    type=[int]$_.SMBIOSMemoryType; form=[int]$_.FormFactor} })}
$vram = @{}
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' | ForEach-Object {
  $p = Get-ItemProperty $_.PSPath; if ($p.DriverDesc -and $p.'HardwareInformation.qwMemorySize') { $vram[$p.DriverDesc] = [long]$p.'HardwareInformation.qwMemorySize' } }
$o.gpu = @(Get-CimInstance Win32_VideoController | ForEach-Object { @{name=$_.Name; driver=$_.DriverVersion;
  driver_date=$(if($_.DriverDate){$_.DriverDate.ToString('yyyy-MM-dd')}); vram=$(if($vram[$_.Name]){$vram[$_.Name]}else{[long]$_.AdapterRAM});
  res=$(if($_.CurrentHorizontalResolution){"$($_.CurrentHorizontalResolution)x$($_.CurrentVerticalResolution)"}); hz=$_.CurrentRefreshRate} })
$o.disks = @(Get-PhysicalDisk | ForEach-Object { @{name=$_.FriendlyName; media=[string]$_.MediaType; bus=[string]$_.BusType; size=[long]$_.Size; health=[string]$_.HealthStatus} })
$mons = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID); $sizes = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams)
$o.monitors = @($mons | ForEach-Object { $id = $_.InstanceName; $sz = $sizes | Where-Object { $_.InstanceName -eq $id } | Select-Object -First 1
  @{name=(-join ($_.UserFriendlyName | Where-Object { $_ } | ForEach-Object { [char]$_ })); maker=(-join ($_.ManufacturerName | Where-Object { $_ } | ForEach-Object { [char]$_ }));
    year=$_.YearOfManufacture; w_cm=$(if($sz){$sz.MaxHorizontalImageSize}); h_cm=$(if($sz){$sz.MaxVerticalImageSize})} })
$o.net = @(Get-NetAdapter -Physical | ForEach-Object { @{name=$_.InterfaceDescription; alias=$_.Name; speed=$_.LinkSpeed; status=[string]$_.Status; media=[string]$_.PhysicalMediaType} })
$o.audio = @(Get-CimInstance Win32_SoundDevice | ForEach-Object { @{name=$_.Name; maker=$_.Manufacturer} })
$o.camera = @(Get-PnpDevice -PresentOnly -Class Camera,Image | ForEach-Object { $_.FriendlyName })
$o.bluetooth = @(Get-PnpDevice -PresentOnly -Class Bluetooth | Where-Object { $_.FriendlyName -match 'adapter|radio|wireless|MediaTek|Intel|Realtek|Qualcomm' } | ForEach-Object { $_.FriendlyName })
$b = Get-CimInstance Win32_Battery | Select-Object -First 1
if ($b) { $o.battery = @{name=$b.Name; chem=[int]$b.Chemistry} }
$os = Get-CimInstance Win32_OperatingSystem
$o.os = @{name=$os.Caption; version=$os.Version; build=$os.BuildNumber; arch=$os.OSArchitecture; installed=$os.InstallDate.ToString('yyyy-MM-dd');
  display=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion}
$o | ConvertTo-Json -Compress -Depth 5
""", timeout=180) or {}
    for k in ("cpu", "gpu", "disks", "monitors", "net", "audio", "camera", "bluetooth"):
        d[k] = as_list(d.get(k))
    if d.get("ram"):
        d["ram"]["modules"] = as_list(d["ram"].get("modules"))
    # батарея: ёмкость и износ из отчёта powercfg (как в «Полной проверке»)
    if d.get("battery"):
        rep = ps(r"""$tmp = Join-Path $env:TEMP 'scanhub-hw-battery.xml'; powercfg /batteryreport /xml /output $tmp | Out-Null
if (Test-Path $tmp) { [xml]$x = Get-Content $tmp; $b = $x.BatteryReport.Batteries.Battery | Select-Object -First 1; Remove-Item $tmp
  @{maker=$b.Manufacturer; id=$b.Id; design=[long]$b.DesignCapacity; full=[long]$b.FullChargeCapacity; cycles=[int]$b.CycleCount} | ConvertTo-Json -Compress }""", timeout=60)
        if rep:
            d["battery"].update(rep)
    d["lenovo_wmi"] = bool(ps("[bool](Get-CimClass -Namespace root\\WMI -ClassName LENOVO_GAMEZONE_DATA -ErrorAction SilentlyContinue) | ConvertTo-Json"))
    return d


# ================================================================ программы и подписи

def installed_apps():
    res = ps(r"""
$keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $keys | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, DisplayIcon | ConvertTo-Json -Compress
""", timeout=60)
    apps, seen = [], set()
    for a in as_list(res):
        loc = (a.get("InstallLocation") or "").strip().strip('"')
        icon = (a.get("DisplayIcon") or "").split(",")[0].strip().strip('"')
        path = loc if loc and os.path.isdir(loc) else os.path.dirname(icon) if icon.lower().endswith(".exe") and os.path.exists(icon) else ""
        if not path or a["DisplayName"] in seen:
            continue
        seen.add(a["DisplayName"])
        apps.append({"name": a["DisplayName"], "version": a.get("DisplayVersion") or "", "publisher": a.get("Publisher") or "",
                     "path": path})
    apps.sort(key=lambda x: x["name"].lower())
    return apps


def signature_check(target, emit, details=None):
    """Встроенный «сканер»: цифровые подписи exe/dll (для папки — до 40 файлов)."""
    if os.path.isfile(target):
        files = [target]
    else:
        files = []
        for root, dirs, names in os.walk(target):
            files += [os.path.join(root, n) for n in names if n.lower().endswith((".exe", ".dll", ".sys", ".msi", ".ps1"))]
            if root.count(os.sep) - target.count(os.sep) >= 2 or len(files) > 200:
                dirs[:] = []
        files = sorted(files, key=lambda p: (not p.lower().endswith(".exe"), p))[:40]
    if not files:
        emit("Исполняемых файлов нет.")
        return 0, ["clean", "Нечего проверять"]
    sigs = signatures(files)
    unsigned = 0
    for f in files:
        s = sigs.get(f, {"status": "Unknown", "signer": ""})
        ok = s["status"] == "Valid"
        unsigned += not ok
        if details is not None:
            details.append({"file": f, "name": os.path.basename(f), "status": s["status"], "signer": s.get("signer") or ""})
        emit(f"{'✓' if ok else '✗'} {os.path.basename(f)} — " + (s["signer"] if ok else
             {"NotSigned": "без подписи", "HashMismatch": "ПОДПИСЬ ПОВРЕЖДЕНА (файл изменён после подписи)"}.get(s["status"], s["status"])))
    if any(sigs.get(f, {}).get("status") == "HashMismatch" for f in files):
        return 2, ["suspicious", "Подпись повреждена"]
    if unsigned == 0:
        signer = sigs.get(files[0], {}).get("signer", "")
        return 0, ["clean", f"Подписано: {signer}"[:60] if signer else "Всё подписано"]
    return 5, ["unknown", f"Без подписи: {unsigned} из {len(files)}"]
