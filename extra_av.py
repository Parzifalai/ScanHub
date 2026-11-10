"""Дополнительные антивирусы в конце ультра проверки: сами, по очереди, на максимальной проверке и только поиск.

Без окна (одним запросом UAC, по очереди, каждый можно пропустить):
  Kaspersky Virus Removal Tool  -accepteula -silent -allvolumes -d <папка ScanHub>       — все диски, без -processlevel = ничего не трогает
  Microsoft Safety Scanner      /Q /F /N                                                   — тихо, полная проверка, только найти
  Malwarebytes AdwCleaner       /eula /scan                                                — только поиск
  Emsisoft Emergency Kit        /u, затем /malware /f=<каждый диск> /pup /a /n             — память, следы, руткиты + все диски
  Dr.Web CureIt!                /GO /QU /FULL /RP:<отчёт> (ключи Dr.Web Scanner)           — если версия CureIt их не понимает,
                                                                                            откроется её окно — нажать «Начать» самому
Со своим окном (у них нет режима без окна): ESET Online Scanner и Malwarebytes — ScanHub открывает их за своим окном,
нажимает «Начать» / «Сканировать» (UI Automation по названиям кнопок, русские и английские), а в конце поднимает их окно.
Если производитель переделал окно и кнопку не найти — говорим честно: «нажми сам».

Отчёты копируются в data\\reports\\<ультра>-extra, следы сканеров (C:\\AdwCleaner, msert.log, папки сканеров) по галочке удаляются.
"""
import glob
import json
import os
import re
import subprocess
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
APPS = os.path.join(ROOT, "apps")
NO_WINDOW = 0x08000000
WINDIR = os.environ.get("SystemRoot", r"C:\Windows")

SILENT = ["kvrt", "msert", "adwcleaner", "emsisoft", "cureit"]
GUI = ["eset", "malwarebytes"]
NAMES = {"kvrt": "Kaspersky Virus Removal Tool", "msert": "Microsoft Safety Scanner", "adwcleaner": "Malwarebytes AdwCleaner",
         "emsisoft": "Emsisoft Emergency Kit", "cureit": "Dr.Web CureIt!", "eset": "ESET Online Scanner", "malwarebytes": "Malwarebytes"}
HOURS = {"kvrt": 6, "msert": 6, "adwcleaner": 0.3, "emsisoft": 6, "cureit": 5}       # предел на сканер (полная проверка всех дисков)
CTL = os.path.join(DATA, "ultra_extra_ctl")              # окно пишет сюда «skip» — пропустить текущий сканер
ALIVE = os.path.join(DATA, "ultra_extra_alive")          # ScanHub обновляет раз в 5 с — если он закрылся, сканер останавливается


def fixed_drives():
    import ctypes
    out = []
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if mask & (1 << i):
            d = f"{chr(65 + i)}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(d) == 3:          # DRIVE_FIXED
                out.append(d)
    return out or ["C:\\"]


def out_file(tid):
    return os.path.join(DATA, f"ultra_extra_{tid}.out")


def ops_for(tid, exe, rep):
    """Операции администратора для одного сканера: запуск (с пропуском и страховкой alive) и копирование его отчёта."""
    run = lambda cmd, **k: {"type": "run", "cmd": cmd, "cwd": os.path.dirname(exe), "timeout": int(HOURS[tid] * 3600),
                            "stdout_file": out_file(tid), "alive": ALIVE, "label": f"{NAMES[tid]}: проверяю", **k}
    t0 = time.time() - 5
    if tid == "kvrt":
        return [{"type": "mkdir", "path": os.path.join(rep, "kvrt")},
                run([exe, "-accepteula", "-silent", "-allvolumes", "-dontencrypt", "-d", os.path.join(rep, "kvrt")])]
    if tid == "msert":
        return [run([exe, "/Q", "/F", "/N"]),
                {"type": "copy_glob", "src_dir": os.path.join(WINDIR, "debug"), "pattern": "msert.log", "dst_dir": os.path.join(rep, "msert"),
                 "newer_than": t0, "timeout": 60}]
    if tid == "adwcleaner":
        return [run([exe, "/eula", "/scan"]),
                {"type": "copy_glob", "src_dir": r"C:\AdwCleaner\Logs", "pattern": "AdwCleaner*.txt", "dst_dir": os.path.join(rep, "adwcleaner"),
                 "newer_than": t0, "timeout": 60}]
    if tid == "emsisoft":
        return [{"type": "run", "cmd": [exe, "/u"], "cwd": os.path.dirname(exe), "timeout": 1800, "label": "Emsisoft: обновляю базы"},
                run([exe, "/malware"] + [f"/f={d}" for d in fixed_drives()] + ["/pup", "/a", "/n"])]
    if tid == "cureit":
        return [{"type": "mkdir", "path": os.path.join(rep, "cureit")},
                run([exe, "/GO", "/QU", "/FULL", "/LNG:ru", f"/RP:{os.path.join(rep, 'cureit', 'report.txt')}"])]
    return []


def traces(tid, exe):
    """Что удалить после проверки (галочка «удалить сканеры»): сама программа и следы, которые она оставляет."""
    out = []
    if exe:
        d = os.path.dirname(exe)
        # папка сканера в apps — удаляем целиком только если она внутри apps (CureIt, найденный в «Загрузках», не трогаем)
        if os.path.abspath(d).lower().startswith(os.path.abspath(APPS).lower() + os.sep):
            out.append(os.path.join(APPS, os.path.relpath(d, APPS).split(os.sep)[0]))
    if tid == "adwcleaner":
        out.append(r"C:\AdwCleaner")
    if tid == "msert":
        out.append(os.path.join(WINDIR, "debug", "msert.log"))
    if tid == "kvrt":
        out += glob.glob(r"C:\KVRT*_Data")
    return out


# ---------------------------------------------------------------- разбор итогов

THREAT_WORDS = re.compile(r"(?i)\b(trojan|backdoor|worm|virus|ransom|rootkit|miner|stealer|spy|exploit|HEUR:|Trojan\.|Win32/|Win64/|"
                          r"троян|вирус|червь|руткит|майнер|угроз[аы] найден|обнаружен[оа]?\s+угроз)")


def _read(p, limit=400_000):
    for enc in ("utf-8-sig", "utf-16", "cp1251"):
        try:
            with open(p, encoding=enc) as f:
                t = f.read(limit)
            if t.count("\x00") < len(t) // 10:
                return t
        except (OSError, UnicodeError):
            continue
    return ""


def parse(tid, res, rep):
    """→ {"v": clean|threat|pup|error|skipped, "text": коротко, "items": [что найдено]}."""
    if not res:
        return {"v": "error", "text": "не запускался", "items": []}
    if res.get("skipped"):
        return {"v": "skipped", "text": "пропущен", "items": []}
    if res.get("stopped"):
        return {"v": "skipped", "text": "остановлен", "items": []}
    out = _read(out_file(tid)) or res.get("out") or ""
    code = res.get("code")
    if tid == "msert":
        log = _read(next(iter(glob.glob(os.path.join(rep, "msert", "msert.log"))), ""))
        last = log[log.rfind("Microsoft Safety Scanner"):] if "Microsoft Safety Scanner" in log else log
        hits = [l.strip() for l in last.splitlines() if re.search(r"(?i)threat detected|->.*(infected|detected)|Detected:", l)]
        if re.search(r"(?i)no infection found", last) and not hits:
            return {"v": "clean", "text": "заражений не найдено", "items": []}
        if hits:
            return {"v": "threat", "text": f"найдено: {len(hits)}", "items": hits[:15]}
        return {"v": "error" if code not in (0, None) else "clean", "text": f"код завершения {code}" if code else "заражений не найдено", "items": []}
    if tid == "adwcleaner":
        log = "\n".join(_read(p) for p in glob.glob(os.path.join(rep, "adwcleaner", "*.txt")))
        hits = [l.strip() for l in log.splitlines() if re.match(r"\s*(PUP|Adware|Malware|Trojan|Hijacker|PUM)\.", l)]
        pre = [l.strip() for l in log.splitlines() if re.match(r"\s*Preinstalled\.", l)]
        if not log:
            return {"v": "error", "text": "отчёт не найден" + (f" (код {code})" if code else ""), "items": []}
        if hits:
            return {"v": "pup", "text": f"рекламное и нежелательное ПО: {len(hits)}", "items": hits[:20]}
        return {"v": "clean", "text": "рекламного мусора нет" + (f" · предустановленного производителем: {len(pre)}" if pre else ""), "items": []}
    if tid == "emsisoft":
        found = [l.strip() for l in out.splitlines() if re.search(r"(?i)detected|found|обнаружен", l) and not re.search(r"(?i)\b0\s+(infections|objects|threats)", l)]
        if code == 0:
            return {"v": "clean", "text": "угроз нет", "items": []}
        if code == 1:
            return {"v": "threat", "text": "найдены угрозы", "items": found[:15]}
        return {"v": "error", "text": f"код завершения {code}", "items": found[:5]}
    if tid == "kvrt":
        txt = out + "\n" + "\n".join(_read(p) for p in glob.glob(os.path.join(rep, "kvrt", "**", "*.txt"), recursive=True))
        hits = [l.strip() for l in txt.splitlines() if THREAT_WORDS.search(l) and not re.search(r"(?i)\b(0|no)\s+(threats|угроз)", l)]
        m = re.search(r"(?i)(threats? (found|detected)|обнаружено угроз|найдено угроз)\D{0,5}(\d+)", txt)
        n = int(m.group(3)) if m else len(hits)
        if n:
            return {"v": "threat", "text": f"найдено угроз: {n}", "items": hits[:15]}
        if not txt.strip():
            return {"v": "error", "text": f"ничего не сообщил (код {code})", "items": []}
        return {"v": "clean", "text": "угроз не найдено", "items": []}
    if tid == "cureit":
        txt = "\n".join(_read(p) for p in glob.glob(os.path.join(rep, "cureit", "*.txt"))) or out
        hits = [l.strip() for l in txt.splitlines() if re.search(r"(?i)infected|заражен|инфицирован|подозрит", l) and not re.search(r"(?i):\s*0\b", l)]
        if hits:
            return {"v": "threat", "text": f"найдено: {len(hits)}", "items": hits[:15]}
        if not txt.strip():
            return {"v": "clean" if code == 0 else "error", "text": "отчёта нет — итог в окне CureIt" if code else "угроз не найдено", "items": []}
        return {"v": "clean", "text": "угроз не найдено", "items": []}
    return {"v": "error", "text": "неизвестный сканер", "items": []}


# ---------------------------------------------------------------- ESET и Malwarebytes: своё окно, ScanHub нажимает кнопки

UIA_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$a = $env:SH_ARGS | ConvertFrom-Json
$deadline = (Get-Date).AddSeconds([int]$a.seconds)
$done = @()
function Find-Win {
  $ps = Get-Process -Name $a.procs -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 }
  foreach ($p in $ps) { $w = [System.Windows.Automation.AutomationElement]::FromHandle($p.MainWindowHandle); if ($w) { return $w } }
  return $null
}
while ((Get-Date) -lt $deadline -and $done.Count -lt $a.steps.Count) {
  Start-Sleep -Milliseconds 1500
  $w = Find-Win
  if (-not $w) { continue }
  $all = $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
  foreach ($step in $a.steps) {
    if ($done -contains $step.id) { continue }
    foreach ($el in $all) {
      $n = $el.Current.Name
      if (-not $n -or $n -notmatch $step.rx) { continue }
      $ct = $el.Current.ControlType.ProgrammaticName
      if ($ct -notmatch 'Button|Hyperlink|RadioButton|ListItem|CheckBox|Text') { continue }
      $ok = $false
      foreach ($pat in @([System.Windows.Automation.InvokePattern]::Pattern, [System.Windows.Automation.SelectionItemPattern]::Pattern, [System.Windows.Automation.TogglePattern]::Pattern)) {
        $o = $null
        if ($el.TryGetCurrentPattern($pat, [ref]$o)) {
          if ($pat -eq [System.Windows.Automation.InvokePattern]::Pattern) { $o.Invoke() }
          elseif ($pat -eq [System.Windows.Automation.SelectionItemPattern]::Pattern) { $o.Select() }
          else { if ($o.Current.ToggleState -ne 'On') { $o.Toggle() } }
          $ok = $true; break
        }
      }
      if ($ok) { $done += $step.id; Write-Output ("clicked " + $step.id + ": " + $n); break }
    }
    break        # шаги — строго по порядку: следующий ищем после того, как нажат этот
  }
}
Write-Output ("done " + ($done -join ","))
"""

# шаги нажатий: по порядку, регулярные выражения по названию элемента (русский и английский интерфейс)
GUI_STEPS = {
    "eset": [
        {"id": "start", "rx": r"(?i)^(начать работу|get started|начать)$"},
        {"id": "terms", "rx": r"(?i)(принимаю|accept)"},
        {"id": "continue", "rx": r"(?i)^(продолжить|continue)$"},
        {"id": "full", "rx": r"(?i)(полное сканирование|full scan)"},
        {"id": "pua", "rx": r"(?i)(включить.*нежелательн|enable.*potentially unwanted)"},
        {"id": "scan", "rx": r"(?i)(начать сканирование|start scan)"},
    ],
    "malwarebytes": [
        {"id": "scan", "rx": r"(?i)^(сканировать|scan|начать проверку|scan now)$"},
    ],
}
GUI_PROCS = {"eset": ["esetonlinescanner", "ESETOnlineScanner"], "malwarebytes": ["Malwarebytes", "mbam"]}


def launch_gui(tid, exe, log):
    """Открыть сканер со своим окном и нажать в нём «Начать» (в фоне, до 6 минут — пока человек подтверждает UAC и окно грузится)."""
    try:
        os.startfile(exe)
    except OSError as e:
        log(f"  {NAMES[tid]}: не открылся — {e}")
        return None
    res = {"clicked": [], "done": False}

    def click():
        env = dict(os.environ, SH_ARGS=json.dumps({"procs": GUI_PROCS[tid], "steps": GUI_STEPS[tid], "seconds": 360}))
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", UIA_PS], env=env,
                               capture_output=True, text=True, timeout=420, creationflags=NO_WINDOW)
            for line in (r.stdout or "").splitlines():
                if line.startswith("clicked "):
                    res["clicked"].append(line[8:])
                    log(f"  {NAMES[tid]}: нажал «{line.split(': ', 1)[-1]}»")
        except Exception as e:
            log(f"  {NAMES[tid]}: не получилось нажать кнопки — {e}")
        res["done"] = True
    threading.Thread(target=click, daemon=True).start()
    return res


def bring_front(tid):
    """Поднять окно сканера поверх ScanHub (если Windows не даст — окно мигнёт на панели задач)."""
    import ctypes
    try:
        import psutil
    except ImportError:
        return
    user32 = ctypes.windll.user32
    for p in psutil.process_iter(["name", "pid"]):
        if any((p.info["name"] or "").lower().startswith(n.lower()) for n in GUI_PROCS[tid]):
            found = []

            def cb(h, _):
                pid = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(h, ctypes.byref(pid))
                if pid.value == p.info["pid"] and user32.IsWindowVisible(h) and user32.GetWindowTextLengthW(h):
                    found.append(h)
                return True
            user32.EnumWindows(ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)(cb), 0)
            for h in found[:1]:
                user32.ShowWindow(h, 9)                  # SW_RESTORE
                if not user32.SetForegroundWindow(h):
                    user32.FlashWindow(h, True)


def mbam_results(since):
    """Итог проверки Malwarebytes из его файлов результатов (если доступны без администратора)."""
    out = []
    for p in sorted(glob.glob(r"C:\ProgramData\Malwarebytes\MBAMService\ScanResults\*.json"), key=os.path.getmtime)[-3:]:
        if os.path.getmtime(p) < since:
            continue
        try:
            d = json.load(open(p, encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        n = d.get("threatsDetected") or len(d.get("threats") or [])
        out.append({"file": p, "threats": n, "items": [t.get("threatName") or t.get("name") for t in (d.get("threats") or [])][:15]})
    return out
