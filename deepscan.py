"""Глубокая проверка: все сканеры по очереди, один запрос прав администратора, общий итог."""
import atomtraits
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid

import services
import system

ROOT = os.path.dirname(os.path.abspath(__file__))
ANSI = __import__("re").compile(r"\x1b\[[0-9;?]*[A-Za-z]")
DATA = os.path.join(ROOT, "data")
NO_WINDOW = 0x08000000
ORDER = ["threat", "suspicious", "error", "unknown", "clean", "skipped"]
RISKY = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".jar", ".lnk", ".msi", ".sys", ".com")
APPDATA_EXT = (".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".hta", ".lnk", ".com", ".pif", ".wsf")
SCAN_EXT = RISKY + (".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".docm", ".xlsm", ".pptm", ".doc", ".xls", ".pdf",
                    ".apk", ".py", ".wsf", ".vbe", ".jse", ".cpl", ".pif", ".msix", ".appx")


def hot_spots():
    """Места, где вредоносы бывают чаще всего."""
    home, env = os.path.expanduser("~"), os.environ
    dirs = [os.path.join(home, "Downloads"), os.path.join(home, "Desktop"), env.get("TEMP", ""),
            os.path.join(env.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.join(env.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\StartUp")]
    try:                                       # папки загрузок, выбранные в браузерах (часто на другом диске)
        import intel
        dirs += [d for d in intel.download_folders() if d not in dirs]
    except Exception:
        pass
    return [d for d in dirs if d and os.path.isdir(d)]


def appdata_executables(limit=3000):
    """Исполняемые файлы в AppData и ProgramData (там прячутся майнеры), без огромных кэшей."""
    out = []
    skip = (r"\cache", r"\code cache", r"\gpucache", r"\node_modules", "\\packages\\", r"\windowsapps", "\\temp\\",
            r"\package cache", r"\programdata\microsoft", r"\microsoft\windows defender",
            r"\nvidia corporation\downloader", r"\squirreltemp", r"\installer")
    for base in (os.environ.get("APPDATA"), os.environ.get("LOCALAPPDATA"), os.environ.get("ProgramData")):
        if not base:
            continue
        for root, dirs, files in os.walk(base, onerror=lambda e: None):
            low = root.lower()
            if any(s in low + "\\" for s in skip) or low.count("\\") - base.count("\\") > 4:
                dirs[:] = []
                continue
            for f in files:
                if f.lower().endswith(APPDATA_EXT):
                    full = os.path.join(root, f)
                    try:
                        if os.path.getsize(full) <= 50 * 1024 * 1024:
                            out.append(full)
                    except OSError:
                        pass
            if len(out) >= limit:
                return out
    return out


MS_LOGS = r"C:\_MinerSearchLogs"
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
# мелкие пометки MinerSearch «[!]» — что они значат простыми словами
MS_MINOR = {
    "Сертификат подписавшего просрочен": "у подписи файла истёк срок — обычно это просто старая версия программы, не вирус",
    "Нет доверия корневому сертификату": "подпись выдана центром, которому Windows не доверяет — так у некоторых драйверов и китайских программ; насторожиться, только если программа незнакомая",
    "В этом объекте нет подписи": "у файла нет цифровой подписи — так у многих бесплатных и самодельных программ, само по себе не опасно",
    "Файл не найден": "запись ссылается на уже удалённый файл — мусор",
    "Не удалось вычислить хеш": "файл не удалось прочитать (занят или облачный)",
    "Подозрительный путь": "программа лежит в необычном месте",
    "Пустая задача": "задача планировщика без программы — мусор",
    "Файл или подпись вероятно были повреждены": "файл или его подпись изменены — стоит проверить этот файл",
}


def parse_minersearch(text):
    """Отчёт MinerSearch → {threats, warn, minor: {вид: [строки]}}. Легенду в начале отчёта пропускаем (в ней нет времени и пути)."""
    import re as _re
    threats, warn, minor, cur = [], [], {}, ""
    for line in text.splitlines():
        c = _re.search(r"Сканирование: (\S+\.exe)", line)
        if c:
            cur = c.group(1)                           # о каком процессе следующая строка «Обнаружен вредоносный процесс»
        m = _re.search(r"\[(!{1,4})\]\s+(.+)", line)
        if not m:
            continue
        lvl, body = len(m.group(1)), m.group(2).strip()
        if not _re.search(r"^\[\d\d\.\d\d\.\d{4}", line.strip()) and not _re.search(r"[A-Za-z]:\\|\\\\|PID|HKLM|HKCU|\.exe", body, _re.I):
            continue                                   # строка легенды: «[!!!]   Обнаружена угроза»
        body = body.replace("\\\\\\", "").replace("\\\\?\\", "")
        if lvl >= 3:
            if "процесс" in body and cur and cur not in body:
                body = f"{body} — {cur}"
            if body[:300] not in threats:
                threats.append(body[:300])
        elif lvl == 2:
            if _re.search(r"доступен только онлайн|Сторожевой процесс|Найдено угроз", body):
                continue
            if body[:300] not in warn:
                warn.append(body[:300])
        else:
            kind = next((k for k in MS_MINOR if body.startswith(k)), None)
            minor.setdefault(kind or body.split(" ")[0], []).append(body[:300])
    return {"threats": threats, "warn": warn, "minor": minor}


def run_elevated(ops, timeout=1800, on_started=None, on_progress=None, ctl=None):
    """Выполнить операции от администратора одним запросом UAC. ops: [{"type":"run","cmd":[...]} | {"type":"copy",...}].

    Задание передаётся прямо в командной строке процесса (сжатый JSON в base64), а не файлом: файл в папке data может
    подменить любая программа пользователя в момент, когда человек подтверждает UAC. Командную строку после запуска
    поменять нельзя. Результат процесс администратора создаёт заново (файл не должен существовать заранее).
    on_started — вызывается, когда человек подтвердил UAC и процесс администратора начал работу."""
    import base64
    import zlib
    jid = uuid.uuid4().hex
    out = os.path.join(DATA, f"elev_{jid}.out.json")
    started = os.path.join(DATA, f"elev_{jid}.started")
    prog = os.path.join(DATA, f"elev_{jid}.progress")
    blob = base64.urlsafe_b64encode(zlib.compress(json.dumps({"ops": ops, "out": out, "started": started, "progress": prog, "ctl": ctl},
                                                             ensure_ascii=False).encode("utf-8"), 9)).decode()
    if len(blob) > 30000:
        raise RuntimeError("слишком много операций для одного запроса администратора")
    py = sys.executable.replace("pythonw.exe", "python.exe")
    psc = ("$a = $env:SH_ARG | ConvertFrom-Json; "
           "$p = Start-Process -FilePath $a.py -ArgumentList $a.args -Verb RunAs -Wait -WindowStyle Hidden -PassThru; "
           "exit $p.ExitCode")
    arg = json.dumps({"py": py, "args": f'-I "{os.path.join(ROOT, "scanhub.py")}" --elevated-b64 {blob}'})
    try:
        p = subprocess.Popen(["powershell", "-NoProfile", "-Command", psc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             env={**os.environ, "SH_ARG": arg}, creationflags=NO_WINDOW)
        t0, told, last = time.time(), False, None
        while p.poll() is None:
            if not told and on_started and os.path.exists(started):
                told = True
                try:
                    on_started()
                except Exception:
                    pass
            if on_progress and os.path.exists(prog):
                try:
                    cur = open(prog, encoding="utf-8").read().strip()
                    if cur and cur != last:
                        last = cur
                        on_progress(cur)
                except Exception:
                    pass
            if time.time() - t0 > timeout:
                p.kill()
                break
            time.sleep(0.5)
        if not os.path.exists(out):
            raise PermissionError("права администратора не выданы (UAC отменён)")
        return json.load(open(out, encoding="utf-8"))
    finally:
        for f in (out, started, prog):
            try:
                os.remove(f)
            except OSError:
                pass


def elevated_main(blob):
    """Точка входа процесса с правами администратора (задание — из командной строки)."""
    import base64
    import zlib
    spec = json.loads(zlib.decompress(base64.urlsafe_b64decode(blob)).decode("utf-8"))
    if os.path.dirname(os.path.abspath(spec["out"])).lower() != DATA.lower():
        return
    st = spec.get("started")
    if st and os.path.dirname(os.path.abspath(st)).lower() == DATA.lower():
        try:                                  # отметка «UAC подтверждён» — окно перестаёт писать «жду подтверждения»
            os.close(os.open(st, os.O_WRONLY | os.O_CREAT | os.O_EXCL))
        except OSError:
            pass
    in_data = lambda p: bool(p) and os.path.dirname(os.path.abspath(p)).lower() == DATA.lower()
    prog, ctl = spec.get("progress"), spec.get("ctl")
    prog = prog if in_data(prog) else None
    ctl = ctl if in_data(ctl) else None
    results, stopped = [], False
    for op in spec["ops"]:
        if stopped:
            results.append({"ok": False, "stopped": True})
            continue
        if prog and op.get("label"):
            try:                              # что сейчас делается — для окна (только текст, обратно команды не принимаются)
                with open(prog, "w", encoding="utf-8") as f:
                    f.write(op["label"])
            except OSError:
                pass
        try:
            if op["type"] == "run" and ctl:
                # долгая операция, которую можно пропустить или остановить: окно пишет в ctl только слова skip/stop
                # stdout_file — вывод сразу в файл (его можно читать, пока программа пишет); alive — файл, который ScanHub
                # обновляет раз в секунду: если ScanHub закрылся или упал, программа не остаётся работать с правами администратора
                outf = op.get("stdout_file") if in_data(op.get("stdout_file")) else None
                alive = op.get("alive") if in_data(op.get("alive")) else None
                fh = open(outf, "wb") if outf else None
                p = subprocess.Popen(op["cmd"], stdout=fh or subprocess.PIPE, stderr=subprocess.DEVNULL if fh else subprocess.STDOUT,
                                     cwd=op.get("cwd"), creationflags=NO_WINDOW)
                import threading
                buf = []
                if not fh:
                    threading.Thread(target=lambda: buf.append(p.stdout.read()), daemon=True).start()
                t0, cmd = time.time(), None
                while p.poll() is None:
                    time.sleep(0.5)
                    try:
                        cmd = open(ctl, encoding="utf-8").read().strip()
                    except OSError:
                        cmd = None
                    if alive and time.time() - t0 > 30:
                        try:
                            if time.time() - os.path.getmtime(alive) > 20:
                                cmd = "stop"
                        except OSError:
                            cmd = "stop"
                    if cmd in ("skip", "stop") or time.time() - t0 > op.get("timeout", 1800):
                        subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True, creationflags=NO_WINDOW)
                        try:
                            os.remove(ctl)
                        except OSError:
                            pass
                        break
                p.wait()
                if fh:
                    fh.close()
                time.sleep(0.2)
                out = system_decode(buf[0]) if buf and buf[0] else ""
                if cmd == "stop":
                    stopped = True
                results.append({"ok": cmd not in ("skip", "stop"), "code": p.returncode, "out": out[-4000:],
                                "skipped": cmd == "skip", "stopped": cmd == "stop"})
                continue
            if op["type"] == "mkdir":
                os.makedirs(op["path"], exist_ok=True)
                results.append({"ok": True})
            elif op["type"] == "remove":
                if os.path.exists(op["path"]):
                    os.remove(op["path"])
                results.append({"ok": True})
            elif op["type"] == "rmtree":
                import shutil
                shutil.rmtree(op["path"], ignore_errors=True)
                results.append({"ok": True})
            elif op["type"] == "copy":
                import shutil
                shutil.copyfile(op["src"], op["dst"])
                results.append({"ok": True})
            elif op["type"] == "copy_glob":
                # отчёт, который программа с правами администратора закрыла от обычного пользователя (HiJackThis):
                # копия в папке ScanHub получает права этой папки — ScanHub прочитает её без администратора
                import glob as _g
                import shutil
                os.makedirs(op["dst_dir"], exist_ok=True)
                got = []
                for f in _g.glob(os.path.join(op["src_dir"], op["pattern"])):
                    if os.path.getmtime(f) >= op.get("newer_than", 0):
                        d = os.path.join(op["dst_dir"], os.path.basename(f))
                        shutil.copyfile(f, d)
                        got.append(d)
                results.append({"ok": True, "files": got})
            elif op["type"] == "run":
                r = subprocess.run(op["cmd"], capture_output=True, timeout=op.get("timeout", 1200),
                                   cwd=op.get("cwd"), creationflags=NO_WINDOW)
                results.append({"ok": True, "code": r.returncode,
                                "out": system_decode(r.stdout) + system_decode(r.stderr)})
            elif op["type"] == "reg_set":
                import tweaks
                tweaks.reg_set_local(op["root"], op["key"], op["name"], op["kind"], op["value"])
                results.append({"ok": True})
            elif op["type"] == "reg_del":
                import tweaks
                tweaks.reg_del_local(op["root"], op["key"], op["name"])
                results.append({"ok": True})
            elif op["type"] == "clean":
                import pcclean
                def tell(n, fr, label=op.get("label") or "очистка"):
                    if prog:
                        try:
                            with open(prog, "w", encoding="utf-8") as f:
                                f.write(f"{label}: удалено файлов {n:,} · {fr / 2 ** 20:,.0f} МБ".replace(",", " "))
                        except OSError:
                            pass
                freed, skipped = pcclean.clean_paths(op["paths"], op.get("older_hours", 24), tell)
                results.append({"ok": True, "freed": freed, "skipped": skipped})
            elif op["type"] == "delay_delete":
                # занятые файлы — удалить при следующей перезагрузке (файлы раньше папок: Windows выполняет по порядку)
                import ctypes
                p, todo, n = op["path"], [], 0
                if os.path.isdir(p) and not os.path.islink(p) and not os.path.isjunction(p):
                    for root, dirs, files in os.walk(p, topdown=False):
                        todo += [os.path.join(root, f) for f in files] + [os.path.join(root, d) for d in dirs]
                todo.append(p)
                for x in todo:
                    if ctypes.windll.kernel32.MoveFileExW(x, None, 4):      # MOVEFILE_DELAY_UNTIL_REBOOT
                        n += 1
                results.append({"ok": n > 0, "scheduled": n})
            elif op["type"] == "recycle":
                import pcclean
                n, errs = pcclean.to_recycle(op["paths"])
                results.append({"ok": not errs, "removed": n, "error": "; ".join(errs)[:300] if errs else None})
            else:
                results.append({"ok": False, "error": f"неизвестная операция {op['type']}"})
        except Exception as e:
            results.append({"ok": False, "error": str(e)})
    # файл создаётся только новым: если кто-то заранее подложил по этому пути ссылку на системный файл — не пишем
    fd = os.open(spec["out"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False)


def system_decode(b):
    # sfc и некоторые утилиты пишут в UTF-16LE: почти каждый второй байт — 0x00 (латиница) или 0x04 (кириллица)
    odd = b[1::2]
    if len(b) > 8 and sum(1 for x in odd if x in (0, 4)) > len(odd) * 0.7:
        return b.decode("utf-16-le", "replace").replace("\x00", "")
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            pass
    return b.decode("utf-8", "replace")


def verify(found, engine, cfg, stopped=lambda: False):
    """Перепроверка находок сканера: подпись цела и VirusTotal не подтверждает → ложная тревога.
    found: {путь: имя угрозы}. Возвращает (вердикт, настоящие, ложные, пути-подозреваемые)."""
    sigs = system.signatures(list(found))
    vt = services.VirusTotal(cfg["virustotal_key"], lambda m: None, stopped) if cfg.get("virustotal_key") else None
    vt_cache, checked = {}, 0
    real, fp, suspects = [], [], set()
    for path, sg in sigs.items():
        if "\\windowsapps\\" in path.lower() and sg["status"] != "Valid":
            sigs[path] = {"status": "Valid", "signer": "пакет Microsoft Store (MSIX)"}
    # сначала сверяем неподписанные: для них мнение VirusTotal решает
    order = sorted(found, key=lambda p: (sigs.get(p) or {}).get("status") == "Valid")
    for path in order:
        name = found[path]
        sg = sigs.get(path) or {"status": "Unknown", "signer": ""}
        if "\\windowsapps\\" in path.lower():
            sg = {"status": "Valid", "signer": "пакет Microsoft Store (MSIX)"}
        signed = sg["status"] == "Valid"
        confirm = None
        if vt and checked < 6 and os.path.isfile(path):
            h = services.sha256(path)
            if h not in vt_cache:
                code, body = vt.call(f"/files/{h}")
                st = body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) if code == 200 else {}
                vt_cache[h] = st.get("malicious") if code == 200 else None
                checked += 1
            confirm = vt_cache.get(h)
        vt_txt = "" if confirm is None else f", VirusTotal: {confirm} из ~70"
        if signed and (confirm is None or confirm <= 2):
            fp.append(f"ложная тревога {engine}: {os.path.basename(path)} — {name}; подпись «{sg['signer']}» цела{vt_txt} · {path}")
        elif confirm == 0:
            fp.append(f"вероятно ложная тревога {engine}: {os.path.basename(path)} — {name}; без подписи, но ни один из ~70 "
                      f"антивирусов на VirusTotal не считает файл опасным · {path}")
        else:
            real.append(f"{name} · {path} ({'без подписи' if not signed else 'подписан'}{vt_txt})")
            suspects.add(path)
    return ("threat" if real else "clean"), real, fp, suspects


def sysfiles_check(sfc=True, disk=False):
    """Проверки с правами администратора одним запросом UAC (только проверка, ничего не меняют):
    sfc — DISM /CheckHealth + sfc /verifyonly (10–15 минут); disk — CHKDSK-сканирование томов, SMART, TRIM."""
    return sysfiles_parse(run_elevated(sysfiles_ops(sfc, disk), timeout=3600), sfc, disk)


def sysfiles_ops(sfc=True, disk=False):
    import tweaks
    ops = []
    if sfc:
        ops += [{"type": "run", "cmd": ["DISM.exe", "/Online", "/Cleanup-Image", "/CheckHealth"], "timeout": 600},
                {"type": "run", "cmd": ["sfc.exe", "/verifyonly"], "timeout": 2400}]
    if disk:
        ops += tweaks.disk_admin_ops()
    return ops


def sysfiles_parse(res, sfc=True, disk=False):
    import tweaks
    out = {}
    if disk:
        out["disk"] = tweaks.disk_admin_parse(res[-1])
    if not sfc:
        return out
    dism_out = res[0].get("out", "") if res and res[0].get("ok") else res[0].get("error", "") if res else ""
    sfc_out = res[1].get("out", "") if len(res) > 1 and res[1].get("ok") else ""
    # формулировки сверены с ru-RU\sfc.exe.mui и Dism\ru-RU\CbsProvider.dll.mui (+ английские)
    low = " ".join(dism_out.lower().split())
    if "no component store corruption" in low or "повреждение хранилища компонентов не обнаружено" in low:
        dism = "ok"
    elif "not repairable" in low or "восстановить невозможно" in low:
        dism = "broken"
    elif "is repairable" in low or "подлежит восстановлению" in low:
        dism = "repairable"
    else:
        dism = "unknown"
    low = " ".join(sfc_out.lower().split())
    if "repair pending which requires reboot" in low or "для завершения восстановления системы требуется перезагрузка" in low:
        sfc = "reboot"                                 # Windows ждёт перезагрузки после обновлений — SFC даже не начинал
    elif "metadata" in low and "corrupt" in low or "метаданные компонентов повреждены" in low:
        sfc = "violations"
    elif "did not find any integrity violations" in low or "не обнаружила нарушений целостности" in low:
        sfc = "ok"
    elif "found integrity violations" in low or "обнаружила нарушения целостности" in low:
        sfc = "violations"
    elif "another servicing" in low or "выполняется другая операция обслуживания" in low:
        sfc = "busy"
    elif "could not" in low or "не удается" in low or "невозможно" in low:
        sfc = "error"
    else:
        sfc = "unknown"
    tail = lambda t: "\n".join(l.strip() for l in t.splitlines() if l.strip() and "%" not in l)[-600:]
    r = {**out, "dism": dism, "sfc": sfc, "dism_text": tail(dism_out), "sfc_text": tail(sfc_out)}
    if dism in ("repairable", "broken"):
        try:
            r["dism_hist"] = dism_history()
        except Exception:
            pass
        try:
            r["corrupt"] = corrupt_summary(r.get("dism_hist"))
        except Exception:
            pass
    r["cards"] = sysfiles_cards(r)
    return r


# ---------------------------------------------------------------- системные файлы: история и понятный вывод
NO_SOURCE = {"0x800f0915": "Windows не нашла исправных копий", "0x800f081f": "Windows не нашла исправных копий",
             "0x800f0906": "не удалось скачать исправные копии", "0x800f0950": "не удалось скачать исправные копии"}


def dism_history(path=r"C:\Windows\Logs\DISM\dism.log"):
    """Последние запуски восстановления/сканирования из журнала DISM (читается без прав администратора).
    → {"restore": {"when", "code"}, "scan": "when"}. Берётся последнее восстановление, которое дошло до конца
    («Ending Dism.exe session»); оборванные (закрыли окно, выключили ПК) пропускаются. code=None — закончилось без ошибки."""
    import re as _re
    out, cur = {}, None
    for l in open(path, encoding="utf-8", errors="replace"):
        m = _re.match(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d).*Executing command line: (.+)", l)
        if m:
            cmd = m.group(2).lower()
            cur = {"when": m.group(1), "code": None} if "/restorehealth" in cmd else None
            if "/scanhealth" in cmd:
                out["scan"] = m.group(1)
            continue
        if cur is None:
            continue
        e = _re.search(r"hr:(0x[0-9a-f]{8})", l, _re.I)
        if e and e.group(1).lower() != "0x00000000" and not cur["code"]:
            cur["code"] = e.group(1).lower()
        if "Ending Dism.exe session" in l:
            out["restore"] = cur
            cur = None
    return out


COMPONENT_KINDS = [  # что за компонент — словами; cosmetic: на работу Windows почти не влияет
    (r"userexperience|appxmain|oobe|shellexperience|startmenu|cortana|webexperience", "оформление Windows (иконки, меню «Пуск»)", True),
    (r"windowsappruntime|winappsdk|appsdk", "компоненты для приложений (Windows App SDK)", True),
    (r"languagepack|lp_|-ru-ru|-en-us", "языковые файлы", True),
    (r"servicingstack|cbs|wcp|kernel|ntoskrnl|driver|drivers|\.sys", "важные системные файлы", False),
]


def corrupt_summary(hist=None):
    """Что именно повреждено — по последнему ScanHealth/RestoreHealth в журнале CBS. Журналы старше текущего лежат в CbsPersist_*.cab
    (имя — время в UTC, когда журнал закрыт): берём один нужный архив. Итог кешируется в data/sysfiles_corrupt.json."""
    import calendar, glob as _g, re as _re, shutil as _sh, subprocess as _sp, tempfile
    when = max([x for x in ((hist or {}).get("scan"), ((hist or {}).get("restore") or {}).get("when")) if x] or [""])
    if not when:
        return None
    cache_f = os.path.join(DATA_DIR, "sysfiles_corrupt.json")
    try:
        c = json.load(open(cache_f, encoding="utf-8"))
        if c.get("when") == when and c.get("v") == 2:
            return c
    except (OSError, ValueError):
        pass
    t = time.mktime(time.strptime(when, "%Y-%m-%d %H:%M:%S"))
    logs = r"C:\Windows\Logs\CBS"
    cabs = []
    for f in _g.glob(os.path.join(logs, "CbsPersist_*.cab")):
        m = _re.search(r"_(\d{14})\.cab$", f)
        if m:
            cabs.append((calendar.timegm(time.strptime(m.group(1), "%Y%m%d%H%M%S")), f))
    later = sorted(x for x in cabs if x[0] >= t)
    src, tmp = (later[0][1] if later else os.path.join(logs, "CBS.log")), None
    try:
        if src.endswith(".cab"):
            tmp = tempfile.mkdtemp(prefix="scanhub-cbs-")
            _sp.run(["expand.exe", src, "-F:*", tmp], capture_output=True, timeout=180, creationflags=NO_WINDOW)
            got = _g.glob(os.path.join(tmp, "*"))
            if not got:
                return None
            src = got[0]
        day = when[:10]
        items = set()
        with open(src, "rb") as fh:
            for raw in fh:
                if b"CSI Payload Corrupt" not in raw or not raw.startswith(day.encode()):
                    continue
                l = raw.decode("utf-8", "replace")
                m = _re.search(r"Payload Corrupt\W+(?:\(n\)\W+)?([^\\\s]+)\\(.+?)\s*$", l)
                if m:
                    items.add((m.group(1), m.group(2)))
    finally:
        if tmp:
            _sh.rmtree(tmp, ignore_errors=True)
    if not items:
        return None
    kinds, versions, cosmetic = {}, set(), True
    for comp, _f in items:
        v = _re.search(r"_(\d+\.\d+\.\d+\.\d+)_", comp)
        if v:
            versions.add(v.group(1))
        for rx, label, cos in COMPONENT_KINDS:
            if _re.search(rx, comp, _re.I):
                kinds[label] = kinds.get(label, 0) + 1
                cosmetic = cosmetic and cos
                break
        else:
            kinds["другие системные файлы"] = kinds.get("другие системные файлы", 0) + 1
            cosmetic = False
    r = {"v": 2, "when": when, "n": len(items), "versions": sorted(versions), "kinds": dict(sorted(kinds.items(), key=lambda x: -x[1])),
         "cosmetic": cosmetic}
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        json.dump(r, open(cache_f, "w", encoding="utf-8"), ensure_ascii=False)
    except OSError:
        pass
    return r


def _ru_date(when):
    try:
        t = time.strptime(when[:10], "%Y-%m-%d")
        return f"{t.tm_mday} {['января', 'февраля', 'марта', 'апреля', 'мая', 'июня', 'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря'][t.tm_mon - 1]}"
    except (ValueError, TypeError):
        return when or ""


def sysfiles_cards(r):
    """Итог проверки системных файлов — карточки, понятные без знания DISM и SFC: {lvl, title, text, action}.
    action: "repair" — кнопка «Восстановить» (только когда она может помочь), None — делать ничего не нужно или нельзя."""
    C = []
    add = lambda lvl, title, text="", action=None: C.append({"lvl": lvl, "title": title, "text": text, "action": action})
    dism, sfc = r.get("dism"), r.get("sfc")
    cor, hist = r.get("corrupt") or {}, (r.get("dism_hist") or {}).get("restore") or {}
    what = ""
    if cor.get("n"):
        top = next(iter(cor["kinds"]), "")
        what = f"Повреждено файлов: {cor['n']}" + (f", в основном — {top}." if top else ".")
    if dism == "repairable":
        code = hist.get("code")
        if code in NO_SOURCE:
            add("warn", "Повреждение в хранилище Windows — сейчас его не починить",
                (what + " " if what else "") +
                ("На работу компьютера это почти не влияет. " if cor.get("cosmetic") else "") +
                f"Восстановление уже пробовали {_ru_date(hist.get('when'))}, но {NO_SOURCE[code][0].lower() + NO_SOURCE[code][1:] if not NO_SOURCE[code].startswith('Windows') else NO_SOURCE[code]} — так бывает на тестовых сборках Windows. "
                "Делать ничего не нужно: починится со следующим обновлением Windows.")
        elif sfc == "violations":
            add("bad", "Повреждены системные файлы Windows",
                (what + " " if what else "") + "Нажми «Восстановить»: Windows скачает исправные копии и заменит испорченные. 15–30 минут, "
                "нужен интернет, потом перезагрузка. Твои файлы и программы не трогает.", "repair")
        else:
            add("warn", "Windows отметила повреждение в хранилище системных файлов",
                (what + " " if what else "") + "Хранилище — это «склад» исправных копий, через него ставятся обновления. " +
                ("Сами системные файлы целы. " if sfc == "ok" else "") +
                "Нажми «Восстановить»: Windows скачает исправные копии — 15–30 минут, нужен интернет. Твои файлы и программы не трогает.", "repair")
    elif dism == "broken":
        add("bad", "Хранилище системных файлов повреждено, Windows не чинит его сама",
            (what + " " if what else "") + "Поможет «восстановление поверх» с официального образа Windows: файлы и программы остаются. "
            "Если компьютер работает нормально — можно отложить до следующего большого обновления.")
    elif dism == "ok":
        add("ok", "Хранилище системных файлов исправно")
    if sfc == "ok":
        add("ok", "Системные файлы целы")
    elif sfc == "violations" and dism != "repairable":
        add("bad", "Повреждены системные файлы Windows", "Нажми «Восстановить»: 15–30 минут, потом перезагрузка. Твои файлы и программы не трогает.", "repair")
    elif sfc in ("reboot", "busy"):
        add("warn", "Системные файлы не проверены: Windows ждёт перезагрузки",
            "После обновлений Windows нужно перезагрузиться — до этого проверка не запускается. Перезагрузи компьютер и проверь снова.")
    elif sfc == "error":
        add("warn", "Проверка системных файлов не получилась", "Перезагрузи компьютер и попробуй снова.")
    return C


DEFENDER_PREFS = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, "
                  "ExclusionExtension, DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection, DisableScriptScanning, "
                  "DisableBlockAtFirstSeen, MAPSReporting, PUAProtection | ConvertTo-Json -Compress")
RISKY_EXT = {"exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "jar", "msi", "com", "pif", "lnk", "sys"}
RISKY_PROC = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
              "explorer.exe", "svchost.exe", "python.exe", "pythonw.exe", "java.exe", "javaw.exe", "conhost.exe", "msiexec.exe"}


def defender_prefs_check(out):
    """Исключения и выключенные защиты Defender. Вредоносы часто добавляют себе исключение (целый диск, AppData, *.exe),
    чтобы антивирус их не видел. Возвращает {"items": [(уровень, текст)], "label"}."""
    try:
        d = json.loads(out[out.index("{"):out.rindex("}") + 1])
    except ValueError:
        return {"items": [], "label": "Defender не ответил"}
    lst = lambda v: [str(x) for x in (v if isinstance(v, list) else [v] if v else [])]
    env = os.environ
    home = os.path.expanduser("~").lower().rstrip("\\")
    broad = {home, os.path.dirname(home), env.get("APPDATA", "").lower(), env.get("LOCALAPPDATA", "").lower(), env.get("TEMP", "").lower(),
             env.get("ProgramData", "").lower(), env.get("SystemRoot", "").lower(), os.path.join(home, "downloads"),
             os.path.join(home, "desktop"), os.path.join(home, "documents"), env.get("ProgramFiles", "").lower(),
             env.get("ProgramFiles(x86)", "").lower(), os.path.join(env.get("SystemRoot", "c:\\windows").lower(), "temp")} - {""}
    items = []
    for p in lst(d.get("ExclusionPath")):
        n = os.path.expandvars(p).lower().rstrip("\\")
        if "*" in n or len(n) <= 3 or n in broad:
            items.append(("bad", f"исключена папка {p} — Defender не проверяет в ней ничего; так прячутся вредоносы"))
        else:
            items.append(("info", f"исключена папка {p} — проверь, что добавлял её ты"))
    for e in lst(d.get("ExclusionExtension")):
        x = e.lower().lstrip("*.")
        items.append(("bad" if x in RISKY_EXT else "info", f"исключены все файлы .{x}" + (" — программы этого типа Defender не проверяет" if x in RISKY_EXT else "")))
    for p in lst(d.get("ExclusionProcess")):
        b = os.path.basename(p).lower()
        items.append(("bad" if b in RISKY_PROC or "*" in b else "info", f"исключён процесс {p}" +
                      (" — всё, что он делает, Defender не проверяет; так прячутся скрипты вредоносов" if b in RISKY_PROC else "")))
    off = {"DisableRealtimeMonitoring": "защита в реальном времени", "DisableBehaviorMonitoring": "наблюдение за поведением",
           "DisableIOAVProtection": "проверка скачанных файлов", "DisableScriptScanning": "проверка скриптов",
           "DisableBlockAtFirstSeen": "блокировка новых угроз через облако"}
    for k, t in off.items():
        if d.get(k) is True:
            items.append(("bad", f"выключено: {t} — если выключал не ты, это сделал вредонос"))
    if d.get("MAPSReporting") == 0:
        items.append(("info", "облачная защита Defender выключена — новые угрозы он узнаёт позже"))
    if d.get("PUAProtection") == 0:
        items.append(("info", "защита от нежелательных программ (рекламного мусора) выключена — её можно включить в «Безопасность Windows»"))
    nbad = sum(1 for lvl, _ in items if lvl == "bad")
    label = (f"опасных исключений и выключенных защит: {nbad}" if nbad else
             f"исключений: {sum(1 for lvl, _ in items if lvl == 'info')} — обычные" if items else "исключений нет, защиты включены")
    return {"items": items, "label": label}


class DeepScan:
    """job — словарь задачи ScanHub; ctx — функции сервера (exe_path, manifest, config, state, metrics)."""

    def __init__(self, job, ctx):
        self.job, self.ctx = job, ctx
        self.emit = job["lines"].append
        self.steps = job["steps"] = []

    def step(self, sid, title, hint=""):
        s = {"id": sid, "title": title, "hint": hint, "status": "pending", "verdict": None, "label": "", "findings": [],
             "files": [], "problem": None, "fix": None}
        self.steps.append(s)
        return s

    def stopped(self):
        return self.job.get("stop")

    @staticmethod
    def fail(s, label, problem, fix=None, verdict="error"):
        """Шаг, который должен был сработать, но не сработал: показываем это пользователю с кнопкой исправления."""
        s.update(verdict=verdict, label=label, problem=problem, fix=fix)

    def add_files(self, s, found, engine):
        for path, name in found.items():
            if path in self.suspects and os.path.isfile(path) and not any(f["path"] == path for f in s["files"]):
                s["files"].append({"path": path, "name": name, "engine": engine})

    def run_tool(self, cmd, cwd=None, timeout=3600, show=True):
        """Запустить консольный сканер и отдавать вывод в общий лог (без цветов и анимаций прогресса)."""
        p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                             creationflags=NO_WINDOW, env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"})
        self.job["pid"] = p.pid
        lines, t0 = [], time.time()
        for raw in p.stdout:
            line = ANSI.sub("", system_decode(raw))
            line = next((seg for seg in reversed(line.split("\r")) if seg.strip()), "").rstrip()
            if not line:
                continue
            lines.append(line)
            if show and len(line) < 600:
                self.emit("    " + line)
            if self.stopped() or time.time() - t0 > timeout:
                p.kill()
                break
        code = p.wait()
        self.job["pid"] = None
        return code, lines

    def tool(self, tid):
        m = self.ctx["manifest"](tid)
        ts = self.ctx["state"]()["tools"].get(tid, {})
        exe = self.ctx["exe_path"](m, ts)
        return m, ts, exe

    # ------------------------------------------------------------ шаги
    def run(self):
        plan = [
            ("procs", "Внедрённый код в процессах", "HollowsHunter, с правами администратора (в том же окне — MinerSearch)", self.s_hollows),
            ("miners", "Скрытые майнеры", "MinerSearch (только поиск, ничего не удаляет) и наблюдение за нагрузкой", self.s_miners),
            ("network", "Сеть", "соединения, обращения к майнинг-пулам, подмена hosts, 1,7 млн адресов вредоносов (Maltrail)", self.s_network),
            ("autoruns", "Автозагрузка", "реестр, папки, задачи, службы, WMI, вход в Windows, перехват запуска, экран входа", self.s_autoruns),
            ("drivers", "Уязвимые драйверы", "драйверы, через которые вирусы выключают антивирус (база LOLDrivers)", self.s_drivers),
            ("certs", "Корневые сертификаты", "поддельные сертификаты для перехвата HTTPS (Sysinternals Sigcheck)", self.s_certs),
            ("defexcl", "Настройки Defender", "исключения и выключенные защиты — вредоносы прячутся так от антивируса", self.s_defexcl),
            ("browsers", "Браузеры", "расширения не из магазина и с опасными правами, политики, подмена прокси", self.s_browsers),
            ("origin", "Откуда скачаны программы", "сайты-источники файлов в Загрузках и на Рабочем столе: поддельные и опасные (FMHY, Maltrail)", self.s_origin),
            ("defender", "Microsoft Defender", "быстрая проверка: память и системные места", self.s_defender),
            ("clamav", "ClamAV", "программы, скрипты, архивы и документы в Загрузках, на Рабочем столе, в TEMP и AppData", self.s_clamav),
            ("yara", "Правила YARA", "7 тыс. правил Elastic и YARA Forge по тем же файлам, что и ClamAV", self.s_yara),
            ("atomscan", "Atomdrift Scan", "процессы, автозагрузка и временные папки (ИИ-анализ)", self.s_atomscan),
            ("online", "Онлайн-сверка", "VirusTotal и Filescan по подозрительным файлам", self.s_online),
        ]
        for sid, title, hint, _ in plan:
            self.step(sid, title, hint)
        self.suspects = set()            # exe, которые стоит сверить онлайн
        self.targets = None              # список файлов для ClamAV и YARA
        skip = self.ctx.get("skip") or {}   # шаги, уже выполненные раньше (например, Defender в ультра проверке)
        for (sid, title, hint, fn), s in zip(plan, self.steps):
            if self.stopped():
                s.update(status="skipped", label="остановлено")
                continue
            if sid in skip:
                s.update(status="skipped", verdict="skipped", label=skip[sid])
                self.emit(f"\n━━ {title} ━━\n  пропущено: {skip[sid]}")
                continue
            s["status"] = "running"
            self.emit(f"\n━━ {title} ━━")
            try:
                fn(s)
            except Exception as e:
                self.fail(s, "ошибка", f"шаг завершился с ошибкой: {e}")
                self.emit(f"  ошибка: {e}")
            if s.get("problem"):
                self.emit(f"  ⚠ не сработало как нужно: {s['problem']}")
            s["status"] = "skipped" if s.get("verdict") == "skipped" else "done"
        problems = [{"step": s["title"], "text": s["problem"], "fix": s["fix"]} for s in self.steps if s.get("problem")]
        self.job["problems"] = problems
        vs = [s["verdict"] for s in self.steps if s["verdict"] and s["verdict"] not in ("skipped", "error")]
        worst = min(vs, key=ORDER.index) if vs else ("error" if problems else "clean")
        labels = {"threat": "Найдены угрозы", "suspicious": "Есть подозрения", "error": "Проверки не сработали",
                  "unknown": "Угроз не найдено", "clean": "Угроз не найдено"}
        label = labels[worst] + (f" · не сработало проверок: {len(problems)}" if problems and worst != "error" else "")
        code = 1 if worst == "threat" else 2 if worst == "suspicious" else 3 if worst == "error" else 0
        return code, [worst if worst != "unknown" else "clean", label]

    def _minersearch_ops(self):
        """MinerSearch — в том же окне UAC, что и HollowsHunter: только поиск (--scan-only), без окон, отчёт копируем к себе."""
        if "miners" in (self.ctx.get("skip") or {}):
            return []
        m, ts, exe = self.tool("minersearch")
        if not exe and self.ctx.get("install"):
            self.emit("  MinerSearch ещё не скачан — скачиваю (~5 МБ, с проверкой подписи и VirusTotal)…")
            try:
                if self.ctx["install"]("minersearch"):
                    m, ts, exe = self.tool("minersearch")
            except Exception as e:
                self.emit(f"  MinerSearch не скачался: {e}")
        if not exe:
            return []
        self.ms_t0 = time.time()
        self.ms_dir = os.path.join(DATA_DIR, "reports", self.job["id"] + "-minersearch")
        return [{"type": "run", "cmd": [exe, "--accept-eula", "--console-mode", "--scan-only", "--no-review-interact"],
                 "cwd": os.path.dirname(exe), "timeout": 1500},
                {"type": "copy_glob", "src_dir": MS_LOGS, "pattern": "MinerSearch_*.log", "dst_dir": self.ms_dir,
                 "newer_than": self.ms_t0 - 5, "timeout": 60}]

    def s_hollows(self, s):
        m, ts, exe = self.tool("hollowshunter")
        if not exe:
            return self.fail(s, "не установлен", "HollowsHunter не установлен — внедрённый код в процессах не проверен",
                             {"install": "hollowshunter"})
        rep = os.path.join(ts["path"], "reports")
        args = [exe, "/json", "/quiet", "/ofilter", "1", "/dir", rep, "/uniqd"]
        out, admin = "", True
        try:
            self.emit("  запрашиваю права администратора (одно окно UAC)…")
            # в том же окне UAC — исключения и выключенные защиты Defender (без прав администратора Windows их не показывает)
            ms_ops = self._minersearch_ops()
            if ms_ops:
                self.emit("  в том же окне — MinerSearch (поиск майнеров, только проверка, ~3–5 минут)")
            res = run_elevated([{"type": "run", "cmd": args, "cwd": ts["path"], "timeout": 900},
                                {"type": "run", "cmd": ["powershell", "-NoProfile", "-Command", DEFENDER_PREFS], "timeout": 90}] + ms_ops,
                               timeout=900 + 90 + sum(o["timeout"] for o in ms_ops) + 120)
            out = res[0].get("out", "")
            self.defender_prefs = res[1].get("out", "") if len(res) > 1 and res[1].get("ok") else None
            if ms_ops:
                self.ms_res = res[2:4]
        except PermissionError:
            admin = False
            self.emit("  без прав администратора: проверяю только свои процессы")
            code, lines = self.run_tool(args, cwd=ts["path"], timeout=900)
            out = "\n".join(lines)
        try:
            js = json.loads(out[out.index("{"): out.rindex("}") + 1])
        except ValueError:
            js = {}
        n = js.get("suspicious_count", 0)
        scanned = js.get("scanned_count") or js.get("scanned")
        procs = []
        for p in js.get("suspicious", []) or []:
            name = p.get("name") if isinstance(p, dict) else str(p)
            pid = p.get("pid") if isinstance(p, dict) else ""
            path = ""
            try:
                import psutil
                path = psutil.Process(int(pid)).exe()
            except Exception:
                pass
            procs.append((name, pid, path))
        sigs = system.signatures([x[2] for x in procs if x[2]]) if procs else {}
        sigs = {k.lower(): v for k, v in sigs.items()}
        unsigned = 0
        for name, pid, path in procs:
            sg = sigs.get(path.lower()) if path else None
            who = f"подписан: {sg['signer']}" if sg and sg["status"] == "Valid" else "без цифровой подписи" if sg else "файл не определён"
            if not (sg and sg["status"] == "Valid"):
                unsigned += 1
                if path:
                    self.suspects.add(path)
            s["findings"].append(f"{name} (PID {pid}) — найден внедрённый или изменённый код · {who}" + (f" · {path}" if path else ""))
        if procs:
            s["findings"].append("Частая ложная тревога: браузеры, Discord и VS Code (Electron), Java, .NET и игры с античитом сами меняют "
                                 "свой код в памяти. Насторожиться стоит, если процесс незнакомый, без подписи или запущен из AppData/Temp.")
        if n and not procs:
            s["findings"].append(f"подозрительных процессов: {n} (подробности в отчёте {rep})")
        note = "" if admin else " (без прав администратора)"
        if not js and not n:
            return self.fail(s, "нет отчёта", "HollowsHunter не выдал отчёт: " + (out.strip()[-200:] or "пустой вывод"))
        if not admin:
            s.update(problem="права администратора не выданы (UAC отменён) — проверены только твои процессы, системные пропущены",
                     fix={"rerun": True})
        # все отмеченные процессы подписаны известными издателями — скорее всего ложная тревога (JIT, античит)
        s.update(verdict=("suspicious" if unsigned or not procs else "unknown") if n else "clean",
                 label=(f"подозрительных процессов: {n}" + ("" if unsigned or not procs else " — все подписаны, скорее всего ложная тревога")
                        if n else f"внедрений нет{note}") +
                       (f", проверено {scanned}" if scanned else ""))
        self.emit("  " + s["label"])

    def s_miners(self, s):
        met = self.ctx.get("metrics")
        if not met:
            return self.fail(s, "нет psutil", "не установлен модуль psutil: pip install psutil")
        met.touch()
        self.emit("  наблюдаю за нагрузкой 20 секунд…")
        for _ in range(10):
            time.sleep(2)
            met.touch()
        snap = met.snapshot()
        for p in snap["suspicious"]:
            s["findings"].append(f"{p['name']} — {'; '.join(p['flags'])} · {p['exe']}")
            if p["exe"]:
                self.suspects.add(p["exe"])
        top = snap["top_cpu"][:3]
        self.emit("  больше всего нагружают: " + ", ".join(f"{p['name']} {p['cpu']}%" for p in top))
        ms = self._minersearch_result(s)
        threat = bool(ms and ms["threats"])
        s.update(verdict="threat" if threat else "suspicious" if s["findings"] and (not ms or ms["warn"] or snap["suspicious"]) else "clean",
                 label=(f"MinerSearch: угроз {len(ms['threats'])}" if threat else
                        f"подозрительных процессов: {len(snap['suspicious'])}" if snap["suspicious"] else
                        "майнеров не видно" + (" (и MinerSearch ничего не нашёл)" if ms else "")))

    def _minersearch_result(self, s):
        """Разбор отчёта MinerSearch из того же окна UAC. Мелкие пометки о подписях — одной понятной строкой, не как угроза."""
        res = getattr(self, "ms_res", None)
        m, ts, exe = self.tool("minersearch")
        if not exe:
            s.setdefault("notes", []).append("MinerSearch не установлен — работал только встроенный поиск майнеров")
            return None
        if res is None:
            if "miners" not in (self.ctx.get("skip") or {}):
                self.emit("  MinerSearch не запускался: права администратора не выданы")
            return None
        files = (res[1].get("files") or []) if len(res) > 1 else []
        logs = sorted(files, key=os.path.getmtime)
        if not logs:
            run = res[0] if res else {}
            self.emit(f"  MinerSearch не оставил отчёт (код {run.get('code')}): {(run.get('out') or run.get('error') or '')[-300:]}")
            s.update(problem="MinerSearch не оставил отчёт — поиск майнеров сделан только встроенными средствами", fix={"run": ["minersearch", "scanonly"]})
            return None
        raw = open(logs[-1], "rb").read()
        text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
        r = parse_minersearch(text)
        self.emit(f"  MinerSearch: угроз {len(r['threats'])}, предупреждений {len(r['warn'])}, мелких пометок {sum(len(v) for v in r['minor'].values())} · отчёт {logs[-1]}")
        for t in r["threats"][:15]:
            s["findings"].append("⚠ MinerSearch: " + t)
        for t in r["warn"][:10]:
            s["findings"].append("MinerSearch: " + t)
        if r["minor"]:
            s["findings"].append("MinerSearch, мелкие пометки (это не угрозы): " + "; ".join(
                f"{MS_MINOR.get(k, k)} — {len(v)}" for k, v in r["minor"].items()))
        self.job["minersearch_log"] = logs[-1]
        return r

    def s_network(self, s):
        n = system.network()
        for c in n["connections"]:
            if c["flags"]:
                s["findings"].append(f"{c['name']} → {c['remote']}: порт, типичный для майнинг-пулов")
                if c["exe"]:
                    self.suspects.add(c["exe"])
        for d in n["pool_dns"]:
            s["findings"].append(f"было обращение к адресу майнинг-пула: {d}")
        for h in n["hosts_tampered"]:
            s["findings"].append(f"hosts блокирует сайт антивируса/обновлений: {h}")
        self.emit(f"  соединений: {len(n['connections'])}, слушающих портов: {len(n['listening'])}, записей DNS: {n['dns_count']}")
        bad = bool(n["hosts_tampered"] or n["pool_dns"])
        try:
            import intel
            r = intel.check_network(self.emit)
            for h in r["hits"]:
                s["findings"].append(("⚠ " if h["level"] == "bad" else "") + h["text"])
                if h.get("exe"):
                    self.suspects.add(h["exe"])
            bad = bad or any(h["level"] == "bad" for h in r["hits"])
            if not r["ok"]:
                s.update(problem=("базы адресов вредоносов Maltrail ещё не скачаны: их лицензия бесплатна только для защиты своих компьютеров, "
                                  "поэтому первый раз их скачиваешь ты сам — кнопкой справа" if not intel.trails_accepted() else
                                  "базы адресов вредоносов (Maltrail) не скачались") + " — проверены только майнинг-пулы и hosts",
                         fix={"run": ["netintel", "update"]})
        except Exception as e:
            self.emit(f"  сверка с базами Maltrail не удалась: {e}")
            s.update(problem=f"сверка с базами адресов вредоносов не удалась: {e}", fix={"run": ["netintel", "update"]})
        s.update(verdict="threat" if bad else "suspicious" if s["findings"] else "clean",
                 label=f"находок: {len(s['findings'])}" if s["findings"] else "ничего подозрительного")

    def s_autoruns(self, s):
        items = system.autoruns()
        bad = [i for i in items if i["level"] == "bad"]
        warn = [i for i in items if i["level"] == "warn"]
        for i in bad + warn:
            s["findings"].append(f"{i['kind']} «{i['name']}» — {'; '.join(i['flags'])} · {i['exe']}")
            if os.path.isfile(i["exe"]):
                self.suspects.add(i["exe"])
        self.emit(f"  записей автозагрузки (без системных): {len(items)}; подозрительных: {len(bad)}, внимания: {len(warn)}")
        # просто «без подписи» — не повод для тревоги: такие файлы сверит онлайн-шаг
        s.update(verdict="threat" if bad else "unknown" if warn else "clean",
                 label=(f"подозрительных: {len(bad)}" + (f", без подписи: {len(warn)}" if warn else "") if bad
                        else f"{len(items)} записей; без подписи: {len(warn)} — сверю онлайн" if warn
                        else f"{len(items)} записей, всё в порядке"))

    def s_defexcl(self, s):
        out = getattr(self, "defender_prefs", None)
        if out is None:
            return self.fail(s, "не проверено", "исключения Defender читаются только с правами администратора — окно UAC было отменено "
                                                "или HollowsHunter не установлен", {"rerun": True}, verdict="skipped")
        r = defender_prefs_check(out)
        s["findings"] += [f"{lvl == 'bad' and '⚠ ' or ''}{t}" for lvl, t in r["items"]]
        bad = any(lvl == "bad" for lvl, _ in r["items"])
        s.update(verdict="suspicious" if bad else "unknown" if r["items"] else "clean",
                 label=r["label"])
        self.emit("  " + s["label"])

    def s_browsers(self, s):
        import browsers
        r = browsers.audit()
        f = browsers.findings(r)
        s["findings"] += [t for lvl, t in f if lvl in ("bad", "warn")]
        bad = any(lvl == "bad" for lvl, _ in f)
        n = sum(1 for lvl, _ in f if lvl in ("bad", "warn"))
        self.emit(f"  браузеры: {', '.join(r['browsers']) or 'не найдены'}; расширений: {len(r['extensions'])}")
        s.update(verdict="suspicious" if bad else "unknown" if n else "clean",
                 label=f"на что посмотреть: {n}" if n else f"расширений: {len(r['extensions'])}, всё из магазинов")

    def s_drivers(self, s):
        import intel
        try:
            r = intel.check_drivers(self.emit)
        except Exception as e:
            return self.fail(s, "не проверено", f"база уязвимых драйверов не скачалась: {e}", {"run": ["byovd", "update"]})
        mal = [h for h in r["hits"] if h["category"] == "malicious"]
        live = [h for h in r["hits"] if h["category"] != "malicious" and intel.live_driver(h, r)]
        s["drivers"] = []
        for h in r["hits"]:
            s["findings"].append(("⚠ " if h in mal or h in live else "") + intel._drv_text(h, r) + f" · {h['path']}")
            if h in live and h.get("service"):
                try:
                    own = intel.driver_owner(h)
                except Exception:
                    own = {}
                s["drivers"].append({"service": h["service"], "file": os.path.basename(h["path"]), "path": h["path"], "start": h["start"],
                                     "loaded": h["loaded"], **own})
            if h in mal and os.path.isfile(h["path"]):
                s["files"].append({"path": h["path"], "name": "вредоносный драйвер", "engine": "LOLDrivers"})
        if not r["blocklist"]:
            s["findings"].append("⚠ блок-лист уязвимых драйверов Microsoft выключен — включи в «Приватность и защита → Защита Windows»")
        s.update(verdict="threat" if mal else "suspicious" if live else "unknown" if r["hits"] else "clean",
                 label=f"вредоносных: {len(mal)}" if mal else f"уязвимых в работе: {len(live)}" if live
                       else f"уязвимых на диске (не работают или заблокированы): {len(r['hits'])}" if r["hits"]
                       else f"проверено {r['checked']}, известных уязвимых нет")
        self.emit("  " + s["label"])

    def s_certs(self, s):
        import intel
        m, ts, exe = self.tool("rootcerts")
        if not exe:
            return self.fail(s, "не установлен", "Sigcheck не скачан — корневые сертификаты не проверены", {"install": "rootcerts"}, verdict="skipped")
        certs = intel.check_rootcerts(exe, self.emit)
        bad = [c for c in certs if c["level"] == "bad"]
        warn = [c for c in certs if c["level"] == "warn"]
        if bad or warn:
            s["findings"].append(intel.CERT_EXPLAIN)
        for c in bad + warn:
            s["findings"].append(("⚠ " if c in bad else "") + f"{c['subject']} [{c['store']}] — {c['why']}")
        s.update(verdict="threat" if bad else "suspicious" if warn else "clean",
                 label=f"перехватчиков HTTPS: {len(bad)}" if bad else f"неизвестных: {len(warn)}" if warn
                       else "посторонних нет" + (f" (известных: {len(certs)})" if certs else ""))
        self.emit("  " + s["label"])

    def s_origin(self, s):
        import intel
        try:
            r = intel.check_downloads(self.emit)
        except Exception as e:
            return self.fail(s, "не проверено", f"списки опасных сайтов не скачались: {e}", {"run": ["origin", "update"]})
        for it in r["items"]:
            s["findings"].append(("⚠ " if it["level"] == "bad" else "") + f"{os.path.basename(it['path'])} — {it['via']} {it['host']}: {it['why']}")
            if it["level"] == "bad" and it["path"].lower().endswith((".exe", ".msi", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js")):
                self.suspects.add(it["path"])          # такие файлы сверит онлайн-шаг
            if it["level"] == "bad" and os.path.isfile(it["path"]) and not any(f["path"] == it["path"] for f in s["files"]):
                s["files"].append({"path": it["path"], "name": f"скачан с {it['host']}", "engine": "origin"})
        bad = sum(1 for it in r["items"] if it["level"] == "bad")
        s.update(verdict="suspicious" if bad else "unknown" if r["items"] else "clean",
                 label=(f"с опасных сайтов: {bad}" + (f", с не рекомендуемых: {len(r['items']) - bad}" if len(r["items"]) > bad else "")) if bad
                       else f"с не рекомендуемых сайтов: {len(r['items'])}" if r["items"]
                       else f"скачанных программ и архивов: {r['files']}, все с обычных сайтов" if r["files"] else "скачанных программ нет")
        self.emit("  " + s["label"])

    def s_defender(self, s):
        exe = os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe")
        code, lines = self.run_tool([exe, "-Scan", "-ScanType", "1"], timeout=3600)
        if code == 2:
            s["findings"] += [l.strip() for l in lines if "Threat" in l or "угроз" in l.lower()][:10]
        if code not in (0, 2):
            tail = " · ".join(l.strip() for l in lines[-3:] if l.strip())[:200]
            return self.fail(s, f"ошибка (код {code})", f"Defender не выполнил проверку (код {code}){': ' + tail if tail else ''}. "
                             "Возможно, Defender выключен или его заменил другой антивирус.", {"open": "defender"})
        s.update(verdict="threat" if code == 2 else "clean",
                 label="найдены угрозы" if code == 2 else "угроз нет")

    def _targets_file(self):
        """Только опасные типы файлов из «горячих» папок (до 100 МБ, до 4 уровней) + программы из AppData."""
        files = []
        for base in hot_spots():
            for root, dirs, names in os.walk(base, onerror=lambda e: None):
                if root.count(os.sep) - base.count(os.sep) >= 4 or "\\claude\\" in root.lower() + "\\":
                    dirs[:] = []
                for n in names:
                    if n.lower().endswith(SCAN_EXT):
                        f = os.path.join(root, n)
                        try:
                            if os.path.getsize(f) <= 100 * 1024 * 1024:
                                files.append(f)
                        except OSError:
                            pass
                if len(files) > 6000:
                    break
        files += appdata_executables()
        self.targets = files
        tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", encoding="utf-8")
        tmp.write("\n".join(files))
        tmp.close()
        return tmp.name, files

    def s_clamav(self, s):
        m, ts, exe = self.tool("clamav")
        if not exe:
            return self.fail(s, "не установлен", "ClamAV не установлен — файлы этим движком не проверены", {"install": "clamav"})
        db = os.path.join(ts["path"], "database")
        if not (os.path.isdir(db) and any(f.startswith("daily") for f in os.listdir(db))):
            return self.fail(s, "нет баз", "у ClamAV не скачаны базы — файлы этим движком не проверены", {"run": ["clamav", "update"]})
        listfile, files = self._targets_file()
        self.emit(f"  проверяю {len(files)} файлов: программы, скрипты, архивы и документы из Загрузок, Рабочего стола, TEMP, автозагрузки и AppData…")
        code, lines = self.run_tool([exe, f"--database={db}", "--infected", "--max-filesize=50M", "--max-scansize=60M",
                                     "--max-recursion=6", "--max-files=300", "--max-scantime=30000",
                                     f"--file-list={listfile}"], cwd=ts["path"], timeout=1500)
        os.unlink(listfile)
        found = {}
        for l in lines:
            l = l.strip()
            if l.endswith(" FOUND") and ": " in l:
                path, name = l[:-6].rsplit(": ", 1)
                found[path] = name
        if code not in (0, 1):
            tail = " · ".join(l.strip() for l in lines[-3:] if l.strip())[:200]
            return self.fail(s, f"ошибка (код {code})", f"ClamAV завершился с ошибкой (код {code}){': ' + tail if tail else ''}",
                             {"run": ["clamav", "update"]})
        if not found:
            return s.update(verdict="clean", label="угроз нет")
        v, real, fp = self.verify_findings(found, "ClamAV")
        self.add_files(s, found, "ClamAV")
        s["findings"] += real[:30] + fp[:30]
        s.update(verdict=v, label=(f"угроз: {len(real)}" if real else "угроз нет") +
                 (f", ложных тревог ClamAV: {len(fp)}" if fp else ""))

    def verify_findings(self, found, engine):
        v, real, fp, suspects = verify(found, engine, self.ctx["config"](), self.stopped)
        self.suspects |= suspects
        if real:
            self.emit(f"  подтверждённых угроз: {len(real)}")
        if fp:
            self.emit(f"  ложных тревог (подписанные программы): {len(fp)}")
        return v, real, fp

    def s_yara(self, s):
        import yarascan
        try:
            import yara_x  # noqa: F401
        except ImportError:
            return self.fail(s, "нет движка", "не установлен модуль yara-x: pip install yara-x")
        if not yarascan.installed():
            return self.fail(s, "нет правил", "правила YARA не скачаны — этот шаг ничего не проверил", {"run": ["yara", "update"]})
        files = self.targets or self._targets_file()[1]
        m = yarascan.meta()
        self.emit(f"  {m['rules']} правил (YARA Forge {m['version']} + Elastic) по {len(files)} файлам…")
        found, n, errs = yarascan.scan(files, self.emit, self.stopped, time_limit=900)
        self.emit(f"  проверено файлов: {n}" + (f", не прочитано: {errs}" if errs else ""))
        if n < len(files) * 0.5 and not self.stopped():
            s["problem"] = f"проверена только часть файлов ({n} из {len(files)}) — истекло время шага"
        if not found:
            return s.update(verdict="clean", label=f"чисто ({n} файлов)")
        names = {p: ", ".join(h["id"] for h in hs[:2]) for p, hs in found.items()}
        hard = {p: v for p, v in names.items() if any(h["sev"] == "threat" for h in found[p])}
        soft = {p: v for p, v in names.items() if p not in hard}
        v1, real1, fp1 = self.verify_findings(hard, "YARA") if hard else ("clean", [], [])
        v2, real2, fp2 = self.verify_findings(soft, "YARA") if soft else ("clean", [], [])
        self.add_files(s, names, "YARA")
        s["findings"] += real1[:20] + ["подозрение: " + x for x in real2[:20]] + fp1[:15] + fp2[:15]
        s.update(verdict="threat" if real1 else "suspicious" if real2 else "clean",
                 label=(f"угроз: {len(real1)}" if real1 else f"подозрительных: {len(real2)}" if real2 else f"чисто ({n} файлов)") +
                       (f", ложных срабатываний: {len(fp1) + len(fp2)}" if fp1 or fp2 else ""))

    def s_atomscan(self, s):
        m, ts, exe = self.tool("atomscan")
        if not exe:
            return self.fail(s, "не установлен", "Atomdrift Scan не установлен — ИИ-анализ не выполнен", {"install": "atomscan"})
        # «sys» — программы запущенных процессов, автозагрузка и временные папки; JSON — по объекту на файл
        try:                                                  # правила — без образцов вирусов (см. atomtraits)
            atomtraits.update(self.emit, exe)
        except Exception as e:
            self.emit(f"  правила Atomdrift не обновились ({e}) — проверяю с уже скачанными")
        self.emit("  ИИ-анализ программ запущенных процессов, автозагрузки и временных папок (5–8 минут)…")
        code, lines = self.run_tool([exe, "--no-update", "-f", "json", "sys"], cwd=ts["path"], timeout=900, show=False)
        atomtraits.purge_testdata()
        if code not in (0, 1, 2):
            tail = " · ".join(l.strip() for l in lines[-3:] if l.strip() and not l.startswith("{"))[:200]
            return self.fail(s, f"ошибка (код {code})", f"Atomdrift Scan завершился с ошибкой (код {code}){': ' + tail if tail else ''}")
        found, total = {}, 0
        for l in lines:
            if not l.startswith("{"):
                continue
            try:
                o = json.loads(l)
            except ValueError:
                continue
            total += 1
            ml = o.get("ml") or {}
            path = ((o.get("raw") or {}).get("files") or [{}])[0].get("path", "")
            lvl, prob = ml.get("lvl", -1), ml.get("prob", 0) or 0
            if path and (lvl >= 1 or prob >= 0.5) and not path.lower().startswith(ROOT.lower()):
                found[path] = f"atomscan: {round(prob * 100)}% {'вредонос' if lvl >= 2 else 'подозрительно'}"
        self.emit(f"  проверено файлов: {total}, отмечено: {len(found)}")
        if not found:
            return s.update(verdict="clean", label=f"чисто ({total} файлов)")
        v, real, fp = self.verify_findings(found, "atomscan")
        self.add_files(s, found, "atomscan")
        s["findings"] += real[:20] + fp[:20]
        s.update(verdict="suspicious" if real else "clean",
                 label=(f"подозрительных: {len(real)}" if real else f"чисто ({total} файлов)") +
                       (f", ложных тревог: {len(fp)}" if fp else ""))

    def s_online(self, s):
        cfg = self.ctx["config"]()
        if not self.suspects:
            return s.update(verdict="clean", label="сверять нечего: подозрительных файлов нет")
        files = sorted(self.suspects)[:6]
        verdicts = []
        for key, name in (("virustotal_key", "virustotal"), ("filescan_key", "filescan"), ("metadefender_key", "metadefender"),
                          ("hybrid_key", "hybrid")):
            if not cfg.get(key):
                continue
            svc = services.SERVICES[name](cfg[key], self.emit, self.stopped)
            for f in files:
                if not os.path.isfile(f):
                    continue
                try:
                    v = svc.lookup(f)
                except Exception as e:
                    self.emit(f"  {name}: {e}")
                    continue
                verdicts.append(v)
                if v in ("threat", "suspicious"):
                    s["findings"].append(f"{name}: {os.path.basename(f)} — {services.LABELS[v].lower()}")
                    if not any(x["path"] == f for x in s["files"]):     # чтобы файл можно было сразу убрать в карантин
                        s["files"].append({"path": f, "name": f"{name}: {services.LABELS[v].lower()}", "engine": name})
        if not verdicts:
            if not any(cfg.get(k) for k in ("virustotal_key", "filescan_key", "metadefender_key", "hybrid_key")):
                return self.fail(s, "нет API-ключей", f"подозрительных файлов: {len(files)}, но онлайн-сверка не выполнена — не заданы ключи "
                                 "VirusTotal и Filescan", {"settings": True})
            return self.fail(s, "сервисы не ответили", "VirusTotal и Filescan не ответили (нет интернета или исчерпан лимит запросов)")
        v = min(verdicts, key=ORDER.index)
        s.update(verdict="clean" if v == "unknown" else v,
                 label=f"проверено файлов: {len(files)}" + (f", опасных/подозрительных: {len(s['findings'])}" if s["findings"] else ", всё чисто"))
