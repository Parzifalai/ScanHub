"""Безопасное обновление программ через winget: скачать → проверить на вирусы → тихо установить.

1. winget скачивает установщик в data\\updates (и сам сверяет его SHA-256 с манифестом).
2. ScanHub проверяет файл: цифровая подпись, Microsoft Defender, VirusTotal по хэшу (без загрузки файла).
   Defender нашёл угрозу или ≥3 антивирусов на VirusTotal — программа «придерживается» и не ставится.
3. Установка тихая: winget ставит ту же версию, что проверили (--version), и сверяет ту же контрольную сумму из манифеста.
   Программы «для тебя» (scope: user) — без прав администратора; «для всех» (scope: machine) — одним окном UAC на все сразу.
Каждую программу можно пропустить, а всё — остановить.
"""
import glob
import hashlib
import os
import re
import shutil
import subprocess
import time

import deepscan
import services
import system

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
UPD = os.path.join(DATA, "updates")
NO_WINDOW = 0x08000000
WINGET = os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Microsoft\WindowsApps\winget.exe")
COMMON = ["--accept-source-agreements", "--accept-package-agreements", "--disable-interactivity"]
NOISE = re.compile(r"^[\s\-\\|/█▒▓░]*$|\d+(\.\d+)?\s*[KMG]B\s*/|^\s*\d+%\s*$")
STATE = {"wait": "ждёт", "download": "скачивается", "scan": "проверяется", "ready": "проверено, ждёт установки", "install": "ставится",
         "done": "обновлено", "held": "придержано", "skipped": "пропущено", "error": "не получилось", "stopped": "остановлено"}


def winget_exe():
    return WINGET if os.path.exists(WINGET) else shutil.which("winget") or "winget"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def manifest_info(text):
    """Нужные поля из манифеста winget (YAML без библиотек: значения простые)."""
    get = lambda k: (re.search(rf"^\s*{k}:\s*(.+?)\s*$", text, re.M) or [None, None])[1]
    return {"sha": (get("InstallerSha256") or "").lower(), "scope": (get("Scope") or "").lower(), "type": (get("InstallerType") or "").lower(),
            "elevation": (get("ElevationRequirement") or "").lower(), "publisher": get("Publisher") or "", "url": get("InstallerUrl") or ""}


UAC_NOTE = "в нём будет «Python» — это ScanHub, он написан на Python"


class Updater:
    """job — задача ScanHub (видна в консоли); apps — [{"id","name","version","available"}]; ctx — config, notify."""

    def __init__(self, job, apps, ctx, force=()):
        self.job, self.ctx, self.force = job, ctx, set(force)
        self.emit = job["lines"].append
        job["apps"] = [{**a, "state": "wait", "label": STATE["wait"], "notes": [], "scope": None} for a in apps]
        self.proc = None
        self.ctl = os.path.join(DATA, f"upd_{job['id']}.ctl")

    # ------------------------------------------------------------ управление
    def stopped(self):
        return bool(self.job.get("stop"))

    def skip_current(self):
        """Пропустить программу, которая сейчас скачивается/проверяется/ставится."""
        self.job["skip"] = True
        if self.proc and self.proc.poll() is None:
            subprocess.run(["taskkill", "/PID", str(self.proc.pid), "/T", "/F"], capture_output=True, creationflags=NO_WINDOW)
        if self.job.get("phase") == "elevated":
            open(self.ctl, "w").write("skip")

    def stop(self):
        self.job["stop"] = True
        self.skip_current()
        if self.job.get("phase") == "elevated":
            open(self.ctl, "w").write("stop")

    def set(self, a, state, label=None):
        a["state"] = state
        a["label"] = label or STATE[state]
        self.job["progress"] = f"{a['name']}: {a['label']}"

    def run_cmd(self, cmd, timeout):
        """Команда с выводом в консоль ScanHub; её можно прервать «Пропустить»/«Остановить»."""
        self.emit("  $ " + " ".join(cmd[:6]) + (" …" if len(cmd) > 6 else ""))
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
        t0, out = time.time(), []
        for raw in self.proc.stdout:
            line = deepscan.system_decode(raw)
            line = next((x for x in reversed(line.split("\r")) if x.strip()), "").rstrip()
            if line and not NOISE.search(line):
                out.append(line)
                self.emit("    " + line[:300])
            if time.time() - t0 > timeout:
                self.proc.kill()
                out.append("время вышло")
                break
        code = self.proc.wait()
        self.proc = None
        return code, out

    # ------------------------------------------------------------ шаги
    def run(self):
        os.makedirs(UPD, exist_ok=True)
        apps = self.job["apps"]
        self.job["phase"] = "check"
        for a in apps:
            if self.stopped():
                break
            self.job["skip"] = False
            try:
                self.check(a)
            except Exception as e:
                self.set(a, "error", f"не получилось проверить: {e}")
            if self.job.get("skip") and a["state"] not in ("held", "error"):
                self.set(a, "skipped")
                self.cleanup(a)
        ready = [a for a in apps if a["state"] == "ready"]
        user = [a for a in ready if a["scope"] != "machine"]
        machine = [a for a in ready if a["scope"] == "machine"]
        self.job["phase"] = "install"
        for a in user:
            if self.stopped():
                break
            self.job["skip"] = False
            self.install_user(a)
        if machine and not self.stopped():
            self.install_machine(machine)
        for a in apps:
            if a["state"] in ("wait", "ready", "download", "scan", "install"):
                self.set(a, "stopped")
            self.cleanup(a)                      # установщики больше не нужны (придержанные — тоже: «всё равно обновить» скачает заново)
        try:
            os.remove(self.ctl)
        except OSError:
            pass
        n = {k: sum(1 for a in apps if a["state"] == k) for k in STATE}
        parts = [f"обновлено {n['done']} из {len(apps)}"] + [f"{STATE[k]}: {n[k]}" for k in ("held", "error", "skipped", "stopped") if n[k]]
        self.emit("\n" + " · ".join(parts))
        v = "threat" if n["held"] else "error" if n["error"] and not n["done"] else "clean"
        return (1 if n["held"] else 0), [v, ("Остановлено · " if self.stopped() else "") + " · ".join(parts)]

    def check(self, a):
        self.emit(f"\n━━ {a['name']} {a['version']} → {a['available']} ━━")
        if re.fullmatch(r"[0-9A-Z]{12}", a["id"]):          # Microsoft Store: проверено магазином, ставится без администратора
            a.update(scope="user")
            a["notes"].append("из Microsoft Store — приложения там проверяет Microsoft")
            return self.set(a, "ready")
        folder = os.path.join(UPD, re.sub(r"[^\w.\-]", "_", a["id"]))
        shutil.rmtree(folder, ignore_errors=True)
        self.set(a, "download")
        code, out = self.run_cmd([winget_exe(), "download", "--id", a["id"], "-e", "--version", a["available"], "-d", folder] + COMMON, 3600)
        if self.job.get("skip") or self.stopped():
            return
        files = [f for f in glob.glob(os.path.join(folder, "*")) if not f.lower().endswith((".yaml", ".yml"))]
        man = next(iter(glob.glob(os.path.join(folder, "*.yaml"))), None)
        if code != 0 or not files:
            msg = next((l for l in reversed(out) if "0x" in l or "ошибк" in l.lower() or "error" in l.lower()), "winget не скачал установщик")
            return self.set(a, "error", f"не скачался: {msg.strip()[:160]}")
        f = max(files, key=os.path.getsize)
        info = manifest_info(open(man, encoding="utf-8", errors="replace").read()) if man else {}
        a.update(file=f, size=os.path.getsize(f), scope=info.get("scope") or ("machine" if "_machine_" in os.path.basename(f).lower() else None),
                 type=info.get("type"))
        if info.get("elevation") in ("elevationrequired", "elevatesself"):
            a["scope"] = "machine"
        if not a["scope"]:                       # манифест не говорит — смотрим, где программа записана: HKCU — «для тебя»
            a["scope"] = self.installed_scope(a["name"])
        # ---- проверка
        self.set(a, "scan")
        if info.get("sha") and sha256(f) != info["sha"]:
            return self.set(a, "held", "контрольная сумма не совпала с манифестом — файл подменён или повреждён")
        sig = system.signatures([f]).get(f.lower()) or system.signatures([f]).get(f) or {}
        if sig.get("status") == "Valid":
            a["notes"].append(f"подписан: {sig['signer']}")
            a["signer"] = sig["signer"]
        else:
            a["notes"].append("установщик без цифровой подписи" if sig.get("status") in (None, "NotSigned") else f"подпись: {sig.get('status')}")
        self.emit("  проверяю Microsoft Defender…")
        mp = os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe")
        code, out = self.run_cmd([mp, "-Scan", "-ScanType", "3", "-File", f, "-DisableRemediation"], 1800)
        if self.job.get("skip") or self.stopped():
            return
        if code == 2:
            return self.set(a, "held", "Microsoft Defender нашёл угрозу в установщике — не ставлю")
        a["notes"].append("Defender: угроз нет" if code == 0 else f"Defender не проверил (код {code})")
        key = self.ctx["config"]().get("virustotal_key")
        if key:
            self.emit("  сверяю с VirusTotal по хэшу (сам файл никуда не отправляется)…")
            lines = []
            vt = services.SERVICES["virustotal"](key, lambda l: (lines.append(l), self.emit("  " + l)), lambda: self.job.get("skip") or self.stopped())
            try:
                v = vt.lookup(f)
            except Exception as e:
                v = None
                a["notes"].append(f"VirusTotal не ответил: {e}")
            det = next((l.strip() for l in lines if "антивирус" in l and "/" in l), "")
            if v == "threat" and a["id"] not in self.force:
                return self.set(a, "held", f"VirusTotal: {det or 'опасно'} — не ставлю")
            if v in ("threat", "suspicious"):
                a["notes"].append(f"VirusTotal: {det} — 1–2 срабатывания из ~70 обычно ложные" if v == "suspicious" else f"VirusTotal: {det} (ставится по твоему решению)")
            elif v == "clean":
                a["notes"].append(f"VirusTotal: {det or 'чисто'}")
            elif v == "unknown":
                a["notes"].append("VirusTotal: файла нет в базе — обычно это новые версии")
        else:
            a["notes"].append("VirusTotal не подключён (⚙ Настройки) — проверено только Defender и подписью")
        self.set(a, "ready", "проверено — " + ("ставится вместе с другими «для всех» (одно окно UAC)" if a["scope"] == "machine" else "ставится без прав администратора"))

    def installed_scope(self, name):
        if not hasattr(self, "_progs"):
            try:
                import uninstall
                self._progs = {p["name"].lower(): p["key"] for p in uninstall.programs()}
            except Exception:
                self._progs = {}
        key = self._progs.get(name.lower(), "")
        return "user" if key.startswith("HKCU") else "machine"      # неизвестно — безопаснее ставить с правами (одно окно на все)

    def upgrade_cmd(self, a):
        return [winget_exe(), "upgrade", "--id", a["id"], "-e", "--version", a["available"], "--silent"] + COMMON

    def install_user(self, a):
        self.set(a, "install", "ставится (без прав администратора)")
        code, out = self.run_cmd(self.upgrade_cmd(a), 3600)
        self.finish(a, code, out)

    def install_machine(self, apps):
        self.job["phase"] = "elevated"
        for a in apps:
            self.set(a, "install", "ждёт подтверждения администратора (одно окно UAC на все)")
        self.job["progress"] = f"Подтверди окно UAC ({UAC_NOTE}) — поставлю сразу {len(apps)} {('программу', 'программы', 'программ')[0 if len(apps) == 1 else 1 if len(apps) < 5 else 2]}"
        self.ctx["notify"]("Нужно подтверждение", f"Обновление программ: одно окно UAC на {len(apps)} шт.")
        ops = [{"type": "run", "cmd": self.upgrade_cmd(a), "timeout": 3600, "label": a["id"]} for a in apps]
        by_id = {a["id"]: a for a in apps}

        def started():
            self.job["progress"] = "права выданы ✓ — ставлю программы по очереди"
            for a in apps:
                self.set(a, "ready", "ждёт очереди на установку")

        def progress(label):
            if label in by_id:
                self.set(by_id[label], "install", "ставится (с правами администратора)")
                self.emit(f"  ставлю {by_id[label]['name']}…")
        try:
            res = deepscan.run_elevated(ops, timeout=4 * 3600, on_started=started, on_progress=progress, ctl=self.ctl)
        except PermissionError:
            for a in apps:
                self.set(a, "skipped", "окно UAC отменено — не поставлено")
            return
        for a, r in zip(apps, res):
            if r.get("skipped"):
                self.set(a, "skipped")
            elif r.get("stopped"):
                self.set(a, "stopped")
            else:
                out = (r.get("out") or "").splitlines()
                for l in out[-6:]:
                    if l.strip() and not NOISE.search(l):
                        self.emit("    " + l.strip()[:300])
                self.finish(a, r.get("code"), out)

    def finish(self, a, code, out):
        if self.job.get("skip"):
            return self.set(a, "skipped")
        text = " ".join(out[-8:]).lower()
        if code == 0 or "успешно установлено" in text or "successfully installed" in text:
            return self.set(a, "done", f"обновлено до {a['available']}")
        hint = ("установщик просит перезагрузку — обновится после неё" if code in (3010, 1641, -1978335135) else
                "программа сейчас открыта — закрой её и обнови снова" if "используется" in text or "in use" in text or code == -1978334962 else
                "winget не нашёл подходящего обновления" if code == -1978335189 else
                "у новой версии нет установщика, который подходит к установленной (другая разрядность, область или это новая "
                "основная версия, которая ставится рядом, а не поверх) — обнови с сайта программы или оставь как есть"
                if "применимый установщик не найден" in text or "no applicable installer" in text else
                f"код {code}")
        self.set(a, "done" if code in (3010, 1641) else "error", hint if code in (3010, 1641) else f"не установилось: {hint}")

    def cleanup(self, a):
        """Скачанный установщик больше не нужен — место на диске важнее."""
        folder = os.path.join(UPD, re.sub(r"[^\w.\-]", "_", a["id"]))
        shutil.rmtree(folder, ignore_errors=True)
