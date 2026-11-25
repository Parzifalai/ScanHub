"""«Что это?» у процесса на главной: что это за программа, чья она на самом деле и опасна ли — коротко и точно.

Шаг 1 (сразу, без интернета): все копии процесса, их родители и командные строки, службы внутри, подпись и сведения
файла. Главное — найти настоящего хозяина: msedgewebview2 сам по себе ничего не делает, это встроенный браузер чужого
окна (ScanHub, Teams, виджеты) — хозяина называет ключ --webview-exe-name в его командной строке; svchost — это
конкретные службы; python/powershell/node — конкретный скрипт.
Шаг 2 (фоном): VirusTotal по отпечатку файла (сам файл никуда не уходит) и мнение ИИ-агента по всем этим данным.
"""
import json
import os
import re
import subprocess
import threading
import time
import uuid

NO_WINDOW = 0x08000000
ROOT = os.path.dirname(os.path.abspath(__file__))
WINDIR = os.environ.get("SystemRoot", r"C:\Windows").lower()

PS = r"""$a = $env:SH_ARG | ConvertFrom-Json
$all = @(Get-CimInstance Win32_Process)
$byId = @{}; foreach ($p in $all) { $byId[[int]$p.ProcessId] = $p }
$ids = @($a.pids | ForEach-Object { [int]$_ })
$sel = @(if ($ids.Count) { $all | Where-Object { $ids -contains [int]$_.ProcessId } } else { $all | Where-Object { $_.Name -ieq $a.name } })
$fallback = $false
if (-not $sel.Count -and $ids.Count) { $sel = @($all | Where-Object { $_.Name -ieq $a.name }); $fallback = $true }
$procs = foreach ($p in ($sel | Select-Object -First 40)) {
  $chain = @(); $q = $p
  for ($i = 0; $i -lt 5; $i++) {
    $pp = $byId[[int]$q.ParentProcessId]
    if (-not $pp -or ($pp.CreationDate -and $q.CreationDate -and $pp.CreationDate -gt $q.CreationDate)) { break }
    $chain += [pscustomobject]@{name = $pp.Name; path = $pp.ExecutablePath; pid = [int]$pp.ProcessId; cmd = $pp.CommandLine}
    $q = $pp
  }
  [pscustomobject]@{pid = [int]$p.ProcessId; path = $p.ExecutablePath; cmd = $p.CommandLine
                    started = $(if ($p.CreationDate) { $p.CreationDate.ToString('s') }); parents = @($chain)}
}
$pidset = @($sel | ForEach-Object { [int]$_.ProcessId })
$svc = @(Get-CimInstance Win32_Service -Filter "State='Running'" | Where-Object { $pidset -contains [int]$_.ProcessId } |
         ForEach-Object { [pscustomobject]@{pid = [int]$_.ProcessId; name = $_.Name; display = $_.DisplayName; path = $_.PathName} })
$files = foreach ($x in @($sel | ForEach-Object { $_.ExecutablePath } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 4)) {
  $o = [ordered]@{path = $x}
  try { $s = Get-AuthenticodeSignature -LiteralPath $x; $o.status = [string]$s.Status
        $o.signer = ($s.SignerCertificate.Subject -replace '^CN="?([^",]+).*', '$1') } catch {}
  try { $v = (Get-Item -LiteralPath $x).VersionInfo; $o.company = $v.CompanyName; $o.product = $v.ProductName
        $o.desc = $v.FileDescription; $o.version = $v.ProductVersion; $o.size = (Get-Item -LiteralPath $x).Length } catch {}
  [pscustomobject]$o
}
[pscustomobject]@{procs = @($procs); services = $svc; files = @($files); fallback = $fallback} | ConvertTo-Json -Depth 6 -Compress"""

# системные имена: где они обязаны лежать. Тот же файл в другой папке — классическая маскировка вируса
SYSTEM_HOME = {
    "svchost.exe": r"\system32\svchost.exe", "csrss.exe": r"\system32\csrss.exe", "lsass.exe": r"\system32\lsass.exe",
    "services.exe": r"\system32\services.exe", "winlogon.exe": r"\system32\winlogon.exe", "smss.exe": r"\system32\smss.exe",
    "wininit.exe": r"\system32\wininit.exe", "conhost.exe": r"\system32\conhost.exe", "dwm.exe": r"\system32\dwm.exe",
    "explorer.exe": r"\explorer.exe", "taskhostw.exe": r"\system32\taskhostw.exe", "rundll32.exe": r"\system32\rundll32.exe",
    "dllhost.exe": r"\system32\dllhost.exe", "spoolsv.exe": r"\system32\spoolsv.exe", "sihost.exe": r"\system32\sihost.exe",
    "runtimebroker.exe": r"\system32\runtimebroker.exe", "searchindexer.exe": r"\system32\searchindexer.exe",
}
TRUSTED = re.compile(r"^(microsoft|google|mozilla|nvidia|advanced micro devices|amd|intel|realtek|valve|apple|adobe|"
                     r"oracle|python software foundation|github|discord|telegram|zoom|logitech|lenovo|asus|msi|"
                     r"dell|hp |hp inc|steelseries|razer|corsair|epic games|riot games|roblox|jetbrains|anthropic|"
                     r"openai|opera|brave|yandex|kaspersky|eset|malwarebytes|dr\.web|doctor web|spotify|electronic arts|"
                     r"ubisoft|blizzard|activision|cloudflare|docker|node\.js|openjs|vivaldi|obs|notepad\+\+|7-zip|"
                     r"rarlab|igor pavlov|alexander roshal|nordvpn|proton|wargaming|lesta)", re.I)
SCRIPT_HOSTS = {"python.exe", "pythonw.exe", "powershell.exe", "pwsh.exe", "node.exe", "java.exe", "javaw.exe", "wscript.exe",
                "cscript.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "electron.exe"}
SCRIPT_RE = re.compile(r"""(?:"([^"]+\.(?:py|pyw|ps1|js|mjs|cjs|jar|vbs|vbe|jse|wsf|bat|cmd|hta|dll)(?:,\S+)?)"|(\S+\.(?:py|pyw|ps1|js|mjs|cjs|jar|vbs|vbe|jse|wsf|bat|cmd|hta|dll)(?:,\S+)?))""", re.I)

_CACHE = {}          # (имя, отпечаток копий) → итог шага 1, на 60 с: повторное нажатие — мгновенно
JOBS = {}            # фоновая часть: VirusTotal и агент


def _ps(arg, timeout=25):
    r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", PS], capture_output=True,
                       timeout=timeout, env={**os.environ, "SH_ARG": json.dumps(arg)}, creationflags=NO_WINDOW)
    out = r.stdout.decode("utf-8", "replace") if r.stdout[:3] == b"\xef\xbb\xbf" else r.stdout.decode("cp866", "replace")
    try:
        return json.loads(out[out.index("{"):])
    except ValueError:
        try:
            return json.loads(r.stdout.decode("utf-8", "replace")[r.stdout.decode("utf-8", "replace").index("{"):])
        except ValueError:
            return {}


def _arr(x):
    return [] if x is None else x if isinstance(x, list) else [x]


FRIENDLY = {"searchhost": "поиск и меню «Пуск» Windows", "startmenuexperiencehost": "меню «Пуск» Windows",
            "widgets": "виджеты Windows", "widgetservice": "виджеты Windows", "widgetboard": "виджеты Windows",
            "ms-teams": "Microsoft Teams", "msteams": "Microsoft Teams", "olk": "Outlook (новый)", "hxoutlook": "Почта Windows",
            "whatsapp.root": "WhatsApp", "whatsapp": "WhatsApp", "island": "Island (панель сверху экрана)",
            "copilot": "Copilot", "msedge": "браузер Edge", "phoneexperiencehost": "«Связь с телефоном»",
            "shellexperiencehost": "оболочка Windows (уведомления, часы)", "textinputhost": "клавиатура и эмодзи Windows",
            "lockapp": "экран блокировки Windows", "gamebar": "игровая панель Xbox", "explorer": "Проводник"}


def _app_name(path, fallback=""):
    """Понятное имя: «ScanHub» для всего из папки ScanHub, «поиск и меню «Пуск»» для SearchHost и т. п."""
    p = (path or "").lower()
    if p.startswith(ROOT.lower()):
        return "ScanHub"
    base = re.sub(r"\.exe$", "", os.path.basename(path or fallback), flags=re.I) or fallback
    return FRIENDLY.get(base.lower(), base)


def _owner_of_webview(procs):
    """Хозяева окон WebView2: ключ --webview-exe-name=… есть у каждого процесса WebView2."""
    owners = {}
    for p in procs:
        m = re.search(r"--webview-exe-name=(\"[^\"]+\"|\S+)", p.get("cmd") or "", re.I)
        name = m.group(1).strip('"') if m else None
        if not name:                                   # нет командной строки (чужой пользователь / администратор) — по родителю
            par = next((x for x in _arr(p.get("parents")) if (x.get("name") or "").lower() != "msedgewebview2.exe"), None)
            name = par.get("name") if par else None
        if name:
            owners[name] = owners.get(name, 0) + 1
    return owners


def _script_of(cmd):
    m = SCRIPT_RE.search(cmd or "")
    return (m.group(1) or m.group(2)) if m else None


def _sig_text(f):
    st = f.get("status")
    return {"Valid": f"подписан: {f.get('signer') or 'издатель не указан'}", "NotSigned": "без цифровой подписи",
            "HashMismatch": "подпись ПОВРЕЖДЕНА — файл изменён после подписи", "NotTrusted": "подпись ненадёжная (сертификат не доверенный)",
            "UnknownError": "подпись не проверяется (сертификат не доверенный)"}.get(st, f"подпись: {st}" if st else "подпись не прочиталась")


def inspect(name, pids=None):
    name = str(name or "").strip()
    if not re.search(r"\.\w{2,4}$", name):
        name += ".exe"
    low = name.lower()
    pids = [int(x) for x in (pids or []) if str(x).isdigit()][:40]
    key = (low, tuple(sorted(pids)))
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < 60:
        return hit[1]
    raw = _ps({"name": name, "pids": pids})
    procs, services, files = _arr(raw.get("procs")), _arr(raw.get("services")), _arr(raw.get("files"))
    try:
        import appinfo
        what = appinfo.about(name, (files[0].get("path") if files else "") or "").get("ru") or ""
    except Exception:
        what = ""
    facts = {"имя": name, "копий": len(procs), "что_это": what}
    why, level = [], "ok"
    owner = None

    if not procs:
        res = {"name": name, "what": what, "level": "info", "verdict": "Сейчас не запущен",
               "why": ["Процесс уже закрылся — проверить нечего. Нажми «Что это?» снова, когда он снова появится в нагрузке."],
               "facts": facts, "path": None}
        return res

    # --- чей это процесс на самом деле
    if low == "msedgewebview2.exe":
        owners = _owner_of_webview(procs)
        if owners:
            names = sorted(owners, key=owners.get, reverse=True)
            nice = ["ScanHub (это окно)" if _app_name(n).lower() == "scanhub" or n.lower() in ("python.exe", "pythonw.exe") and _scanhub_py(procs) else _app_name(n)
                    for n in names]
            owner = nice[0]
            facts["хозяева_окон_WebView2"] = {n: owners[k] for n, k in zip(nice, names)}
            what = ("Это не отдельная программа, а встроенный браузер Microsoft Edge (WebView2): в нём нарисованы окна других программ. "
                    f"Здесь его используют: {', '.join(nice[:4])}.")
    elif low == "svchost.exe" and services:
        sv = [s.get("display") or s.get("name") for s in services]
        owner = "службы Windows: " + ", ".join(sv[:3]) + (f" и ещё {len(sv) - 3}" if len(sv) > 3 else "")
        facts["службы_внутри"] = sv[:10]
    elif low in SCRIPT_HOSTS:
        scripts = [s for s in (_script_of(p.get("cmd")) for p in procs) if s]
        if scripts:
            facts["запущенные_скрипты"] = sorted(set(scripts))[:5]
            sc = scripts[0]
            owner = "ScanHub" if sc.lower().startswith(ROOT.lower()) or os.path.basename(sc).lower() in ("scanhub.py",) else os.path.basename(sc)
            what = (what + " " if what else "") + f"Сейчас выполняет: {os.path.basename(sc)}" + (f" (и ещё {len(set(scripts)) - 1})" if len(set(scripts)) > 1 else "") + "."
    if not owner:                                      # кто запустил: первый родитель, который не этот же процесс
        par_names = []
        for p in procs:
            par = next((x for x in _arr(p.get("parents")) if (x.get("name") or "").lower() != low), None)
            if par:
                par_names.append(_app_name(par.get("path"), par.get("name") or ""))
        if par_names:
            top = max(set(par_names), key=par_names.count)
            facts["запустил"] = top
            if top == "Проводник":
                owner = "ты сам (через «Пуск», ярлык или Проводник)"
            elif top.lower() in ("services", "svchost"):
                owner = "Windows (служба или задача по расписанию)"
            else:
                owner = top
    if low == "msedgewebview2.exe" and not owner:
        owner = "неизвестная программа"

    # --- файлы: подпись, путь, маскировка
    paths = [f.get("path") for f in files if f.get("path")]
    facts["файлы"] = [{"путь": f.get("path"), "подпись": _sig_text(f), "компания": f.get("company"), "продукт": f.get("product"),
                       "описание": f.get("desc"), "версия": f.get("version")} for f in files]
    if not paths:
        why.append("Путь к файлу виден только с правами администратора — ScanHub проверил то, что доступно.")
        if low in SYSTEM_HOME or low == "svchost.exe":
            level = "ok" if services or low in SYSTEM_HOME else level
    for f in files:
        p = (f.get("path") or "").lower()
        st = f.get("status")
        home = SYSTEM_HOME.get(low)
        if home and not (p.startswith(WINDIR) and (p.endswith(home) or p.endswith(home.replace("system32", "syswow64")))):
            level = "bad"
            why.append(f"Системное имя {name}, но файл лежит не на своём месте ({f.get('path')}) — так маскируются вирусы.")
        if st == "HashMismatch":
            level = "bad"
            why.append("Файл изменён после подписи производителя — настоящие программы так не делают.")
        elif st == "Valid":
            signer = f.get("signer") or ""
            why.append(f"Подписан «{signer}» — подпись действительная." + ("" if TRUSTED.search(signer) else " Издатель малоизвестный, но подпись настоящая."))
        elif st == "NotSigned":
            risky = re.search(r"\\(temp|tmp|downloads|загрузки)\\|\\appdata\\(local|roaming)\\[^\\]+\.exe$|\\programdata\\[^\\]+\.exe$|\\users\\public\\", p)
            if risky:
                level = "warn" if level == "ok" else level
                why.append(f"Без цифровой подписи и запущен из {'временной папки' if re.search(r'temp|tmp', p) else 'папки, куда пишет кто угодно'} — так часто прячутся майнеры и трояны. Нужна проверка.")
            elif p.startswith(ROOT.lower()):
                why.append("Без подписи, но это файл самого ScanHub.")
            else:
                level = "warn" if level == "ok" and not re.search(r"\\program files", p) else level
                why.append("Без цифровой подписи — у небольших программ это бывает, но издателя не подтвердить." +
                           (" Установлен в Program Files как обычная программа." if "\\program files" in p else ""))
        elif st:
            level = "warn" if level == "ok" else level
            why.append(_sig_text(f).capitalize() + ".")
    if raw.get("fallback"):
        why.insert(0, "Та копия, что грузила компьютер, уже закрылась — ниже все копии, что работают сейчас.")
    why = list(dict.fromkeys(why))                     # одинаковые строки по разным версиям файла — один раз
    if len(paths) > 1 and low not in ("msedgewebview2.exe",):
        why.append(f"Копии запущены из разных мест ({len(paths)}) — проверь каждое.")
        level = "warn" if level == "ok" else level

    if owner and owner.startswith("ScanHub") and level == "ok":
        why.insert(0, "Это часть самого ScanHub.")
    verdict = {"ok": "Не опасно", "warn": "Стоит проверить", "bad": "Похоже на вирус"}[level]
    facts.update(хозяин=owner, вердикт_ScanHub=verdict, почему=why)
    res = {"name": name, "what": what, "owner": owner, "count": len(procs), "level": level, "verdict": verdict, "why": why,
           "files": [{"path": f.get("path"), "sig": _sig_text(f), "company": f.get("company")} for f in files],
           "services": [s.get("display") or s.get("name") for s in services][:8], "path": paths[0] if paths else None, "facts": facts}
    _CACHE[key] = (time.time(), res)
    return res


def _scanhub_py(procs):
    return any(ROOT.lower() in (x.get("cmd") or "").lower() for p in procs for x in _arr(p.get("parents")))


def start(res, cfg, assistant_mod):
    """Фоновая часть: VirusTotal по отпечатку файла, затем мнение агента. Возвращает id для опроса."""
    jid = uuid.uuid4().hex[:10]
    job = JOBS[jid] = {"vt": None, "vt_status": "running", "ai": None, "ai_status": "waiting", "ai_error": None}

    def work():
        p = res.get("path")
        if p and os.path.isfile(p) and cfg.get("virustotal_key"):
            try:
                job["vt"] = _vt(p, cfg, assistant_mod)
            except Exception as e:
                job["vt"] = {"text": f"не удалось: {e}", "level": "info"}
        elif p and os.path.isfile(p):
            job["vt"] = {"text": "нет ключа VirusTotal (вводится в ⚙ Настройках)", "level": "info"}
        else:
            job["vt"] = {"text": "файл не виден без прав администратора — VirusTotal не спрашивали", "level": "info"}
        job["vt_status"] = "done"
        if not cfg.get("ai_provider"):
            job.update(ai_status="off")
            return
        facts = dict(res.get("facts") or {})
        facts["VirusTotal"] = (job["vt"] or {}).get("text")
        job["ai"] = assistant_mod.start("procwho", {"facts": facts}, cfg)["id"]
        job["ai_status"] = "running"

    threading.Thread(target=work, daemon=True).start()
    return jid


def _vt(path, cfg, assistant_mod):
    r = assistant_mod._online(path, cfg).get("VirusTotal")
    if isinstance(r, str):
        return {"text": r if r != "файла нет в базе" else "VirusTotal этот файл ещё не видел (редкая или новая версия)",
                "level": "info"}
    pos, total = str(r.get("вредоносным_считают") or "0 из 0").split(" из ")
    pos, total = int(pos or 0), int(total or 0)
    who = r.get("кто_нашёл") or []
    if pos >= 4:
        return {"text": f"{pos} из {total} антивирусов считают вредоносным" + (f": {who[0]}" if who else ""), "level": "bad", "pos": pos}
    if pos:
        return {"text": f"{pos} из {total} антивирусов отметили его — единичные срабатывания обычно ложные" + (f" ({who[0]})" if who else ""),
                "level": "warn", "pos": pos}
    return {"text": f"0 из {total} антивирусов — чисто", "level": "ok", "pos": 0}


def view(jid, assistant_mod):
    job = JOBS.get(jid)
    if not job:
        return None
    out = {k: job[k] for k in ("vt", "vt_status", "ai_status")}
    if job.get("ai"):
        a = assistant_mod.view(job["ai"]) or {}
        out["ai_status"] = a.get("status") or "running"
        out["ai"] = a.get("answer") or ""
        out["ai_error"] = a.get("error")
        out["ai_step"] = (a.get("steps") or [""])[-1] if a.get("steps") else ""
    return out
