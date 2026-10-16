"""Онлайн-сервисы проверки: VirusTotal и Filescan.io.

По умолчанию отправляется только SHA-256 файла (сам файл не уходит никуда).
Загрузка файла целиком — отдельный режим, только по явной кнопке.
"""
import base64
import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

RISKY = {".exe", ".dll", ".scr", ".msi", ".com", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
         ".wsf", ".hta", ".jar", ".lnk", ".zip", ".rar", ".7z", ".iso", ".img", ".docm", ".xlsm", ".pptm", ".apk",
         ".py", ".appx", ".msix", ".cpl", ".pif"}
MAX_UPLOAD = 32 * 1024 * 1024


class ServiceError(Exception):
    pass


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def files_for(target, limit):
    """Файл — он сам; папка — до limit самых свежих «опасных» файлов."""
    if os.path.isfile(target):
        return [target], 0
    found = []
    for root, _, names in os.walk(target):
        for n in names:
            if os.path.splitext(n)[1].lower() in RISKY:
                p = os.path.join(root, n)
                try:
                    found.append((os.path.getmtime(p), p))
                except OSError:
                    pass
    # сначала программы и скрипты (их чаще всего подменяют), потом библиотеки и архивы; внутри — самые свежие
    prio = lambda p: 0 if p.lower().endswith((".exe", ".msi", ".scr", ".com")) else 1 if p.lower().endswith((".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".jar")) else 2
    found.sort(key=lambda x: (prio(x[1]), -x[0]))
    return [p for _, p in found[:limit]], max(0, len(found) - limit)


def request(url, headers, data=None, method=None, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": "ScanHub", **headers}, data=data, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except ValueError:
            body = {}
        return e.code, body


def multipart(fields, file_field, path):
    boundary = uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    name = os.path.basename(path).replace('"', "_")
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; filename="{name}"\r\n'
                 f"Content-Type: application/octet-stream\r\n\r\n".encode())
    with open(path, "rb") as f:
        parts.append(f.read())
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def worst(verdicts):
    order = ["threat", "suspicious", "error", "unknown", "clean"]
    return min(verdicts, key=order.index) if verdicts else "unknown"


LABELS = {"threat": "Опасно", "suspicious": "Подозрительно", "clean": "Чисто", "unknown": "Нет в базе",
          "error": "Ошибка"}
CODES = {"clean": 0, "threat": 1, "suspicious": 2, "error": 3, "unknown": 5}


# ---------------------------------------------------------------- VirusTotal

class VirusTotal:
    API = "https://www.virustotal.com/api/v3"
    _lock = threading.Lock()
    _calls = []          # бесплатный ключ: 4 запроса в минуту

    def __init__(self, key, emit, stopped, details=None):
        self.key, self.emit, self.stopped = key, emit, stopped
        self.details = details if details is not None else []

    def call(self, path, data=None, ctype=None, method=None):
        for attempt in range(4):
            with self._lock:
                now = time.time()
                self._calls[:] = [t for t in self._calls if now - t < 60]
                wait = 60 - (now - self._calls[0]) + 0.5 if len(self._calls) >= 4 else 0
            if wait > 0:
                self.emit(f"  лимит бесплатного ключа (4 запроса/мин) — жду {int(wait)} с…")
                time.sleep(wait)
            if self.stopped():
                raise ServiceError("остановлено")
            with self._lock:
                self._calls.append(time.time())
            h = {"x-apikey": self.key, "accept": "application/json"}
            if ctype:
                h["Content-Type"] = ctype
            code, body = request(self.API + path, h, data, method)
            if code == 429:
                self.emit("  VirusTotal: превышен лимит, жду минуту…")
                time.sleep(61)
                continue
            if code == 401:
                raise ServiceError("неверный API-ключ VirusTotal (Настройки)")
            return code, body
        raise ServiceError("VirusTotal не отвечает из-за лимитов")

    def describe(self, attrs, sha, path=None, name=None):
        stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(v for k, v in stats.items() if k in ("malicious", "suspicious", "undetected", "harmless"))
        label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        results = attrs.get("last_analysis_results") or attrs.get("results") or {}
        names = [f"{e}: {r.get('result')}" for e, r in results.items()
                 if r.get("category") in ("malicious", "suspicious") and r.get("result")]
        v = "threat" if mal >= 3 else "suspicious" if mal or sus else "clean"
        self.emit(f"  {mal}/{total} антивирусов считают вредоносным" + (f", {sus} — подозрительным" if sus else "")
                  + (f" — {label}" if label else ""))
        for n in names[:12]:
            self.emit(f"    · {n}")
        if len(names) > 12:
            self.emit(f"    · …и ещё {len(names) - 12}")
        if sha:
            self.emit(f"  отчёт: https://www.virustotal.com/gui/file/{sha}")
        sig = attrs.get("signature_info") or {}
        self.details.append({
            "file": path, "name": name or (os.path.basename(path) if path else ""), "sha": sha, "verdict": v,
            "positives": mal, "suspicious": sus, "total": total, "label": label,
            "link": f"https://www.virustotal.com/gui/file/{sha}" if sha else None,
            "engines": sorted(({"e": e, "c": r.get("category") or "", "r": r.get("result") or ""} for e, r in results.items()),
                              key=lambda x: (["malicious", "suspicious"].index(x["c"]) if x["c"] in ("malicious", "suspicious") else 2, x["e"].lower())),
            "type": attrs.get("type_description"), "names": (attrs.get("names") or [])[:5],
            "first": attrs.get("first_submission_date"), "reputation": attrs.get("reputation"),
            "votes": attrs.get("total_votes"), "signer": sig.get("signers") or sig.get("subject"), "signed": sig.get("verified"),
            "product": sig.get("product"), "size": attrs.get("size")})
        return v

    def lookup(self, path):
        sha = sha256(path)
        self.emit(f"{os.path.basename(path)}  sha256 {sha}")
        code, body = self.call(f"/files/{sha}")
        if code == 404:
            self.emit("  нет в базе VirusTotal (файл там ещё никто не проверял)")
            self.details.append({"file": path, "name": os.path.basename(path), "sha": sha, "verdict": "unknown", "missing": True})
            return "unknown"
        if code != 200:
            raise ServiceError(f"VirusTotal ответил {code}: {body.get('error', {}).get('message', '')}")
        return self.describe(body["data"]["attributes"], sha, path)

    def wait_analysis(self, aid):
        for _ in range(60):
            code, body = self.call(f"/analyses/{aid}")
            attrs = body.get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                return attrs, body.get("meta", {})
            self.emit(f"  анализ: {attrs.get('status', '…')}")
            time.sleep(15)
        raise ServiceError("анализ идёт слишком долго — проверь позже по ссылке")

    def upload(self, path):
        size = os.path.getsize(path)
        if size > MAX_UPLOAD:
            raise ServiceError("файл больше 32 МБ — бесплатный API такие не принимает")
        self.emit(f"Загружаю {os.path.basename(path)} ({size // 1024} КБ) в VirusTotal…")
        data, ctype = multipart({}, "file", path)
        code, body = self.call("/files", data, ctype)
        if code != 200:
            raise ServiceError(f"загрузка не удалась ({code}): {body.get('error', {}).get('message', '')}")
        attrs, meta = self.wait_analysis(body["data"]["id"])
        return self.describe(attrs, (meta.get("file_info") or {}).get("sha256") or sha256(path), path)

    def url(self, link):
        self.emit(f"Ссылка: {link}")
        uid = base64.urlsafe_b64encode(link.encode()).decode().rstrip("=")
        code, body = self.call(f"/urls/{uid}")
        if code == 200:
            self.emit("  уже есть в базе:")
            return self.describe(body["data"]["attributes"], None, name=link) or "clean"
        data = urllib.parse.urlencode({"url": link}).encode()
        code, body = self.call("/urls", data, "application/x-www-form-urlencoded")
        if code != 200:
            raise ServiceError(f"VirusTotal ответил {code}")
        attrs, _ = self.wait_analysis(body["data"]["id"])
        self.emit(f"  отчёт: https://www.virustotal.com/gui/url/{uid}")
        return self.describe(attrs, None, name=link)


# ---------------------------------------------------------------- Filescan.io

FS_VERDICT = {"malicious": "threat", "likely_malicious": "threat", "suspicious": "suspicious",
              "benign": "clean", "no_threat": "clean", "informational": "clean", "unknown": "unknown"}


class Filescan:
    API = "https://www.filescan.io/api"

    def __init__(self, key, emit, stopped, details=None):
        self.key, self.emit, self.stopped = key, emit, stopped
        self.details = details if details is not None else []

    def call(self, path, data=None, ctype=None):
        h = {"X-Api-Key": self.key, "accept": "application/json"}
        if ctype:
            h["Content-Type"] = ctype
        code, body = request(self.API + path, h, data)
        if code in (401, 403):
            raise ServiceError("неверный API-ключ Filescan (Настройки)")
        if code == 429:
            raise ServiceError("Filescan: превышен лимит запросов, попробуй позже")
        return code, body

    def lookup(self, path):
        sha = sha256(path)
        self.emit(f"{os.path.basename(path)}  sha256 {sha}")
        code, body = self.call(f"/reputation/hash?sha256={sha}")
        if code == 404:
            self.emit("  нет в базе Filescan")
            self.details.append({"file": path, "name": os.path.basename(path), "sha": sha, "verdict": "unknown", "missing": True})
            return "unknown"
        if code != 200:
            raise ServiceError(f"Filescan ответил {code}")
        raw = str(body.get("overall_verdict") or "unknown").lower()
        v = FS_VERDICT.get(raw, "unknown")
        reps = body.get("filescan_reports") or []
        self.emit(f"  вердикт: {raw}" + (f" (отчётов: {len(reps)})" if reps else ""))
        link = None
        if reps:
            link = f"https://www.filescan.io/uploads/{reps[0].get('flow_id')}/reports/{reps[0].get('report_id')}/overview"
            self.emit(f"  отчёт: {link}")
        self.details.append({"file": path, "name": os.path.basename(path), "sha": sha, "verdict": v, "raw": raw,
                             "reports": len(reps), "link": link})
        return v

    def wait_flow(self, flow):
        for _ in range(80):
            if self.stopped():
                raise ServiceError("остановлено")
            code, body = self.call(f"/scan/{flow}/report")
            if body.get("allFinished"):
                verdicts = []
                for rid, rep in (body.get("reports") or {}).items():
                    fv = rep.get("finalVerdict") or {}
                    raw = str(fv.get("verdict") or rep.get("verdict") or "unknown").lower()
                    verdicts.append(FS_VERDICT.get(raw, "unknown"))
                    self.emit(f"  вердикт: {raw}")
                self.emit(f"  отчёт: https://www.filescan.io/uploads/{flow}")
                self.details.append({"file": self._path, "name": os.path.basename(self._path or "") or self._path,
                                     "verdict": worst(verdicts), "raw": ", ".join(sorted(set(verdicts))),
                                     "link": f"https://www.filescan.io/uploads/{flow}"})
                return worst(verdicts)
            self.emit(f"  анализ: {body.get('state') or 'в очереди'}")
            time.sleep(max(5, (body.get("pollPause") or 5000) / 1000))
        raise ServiceError("анализ идёт слишком долго — проверь позже по ссылке")

    def upload(self, path):
        size = os.path.getsize(path)
        if size > 100 * 1024 * 1024:
            raise ServiceError("файл слишком большой для загрузки")
        self.emit(f"Загружаю {os.path.basename(path)} ({size // 1024} КБ) в Filescan (приватно)…")
        self._path = path
        data, ctype = multipart({"is_private": "true"}, "file", path)
        code, body = self.call("/scan/file", data, ctype)
        if code != 200 or "flow_id" not in body:
            raise ServiceError(f"загрузка не удалась ({code}): {body.get('detail', '')}")
        return self.wait_flow(body["flow_id"])

    def url(self, link):
        self.emit(f"Ссылка: {link}")
        self._path = link
        data, ctype = urllib.parse.urlencode({"url": link, "is_private": "true"}).encode(), \
            "application/x-www-form-urlencoded"
        code, body = self.call("/scan/url", data, ctype)
        if code != 200 or "flow_id" not in body:
            raise ServiceError(f"Filescan ответил {code}: {body.get('detail', '')}")
        return self.wait_flow(body["flow_id"])


# ---------------------------------------------------------------- MetaDefender Cloud (OPSWAT)

MD_CAT = {0: "undetected", 1: "malicious", 2: "suspicious", 3: "failure", 4: "malicious", 6: "malicious", 7: "type-unsupported",
          8: "malicious", 9: "type-unsupported", 10: "type-unsupported", 11: "failure", 12: "failure", 13: "type-unsupported",
          14: "failure", 15: "failure", 16: "timeout", 18: "malicious", 19: "type-unsupported", 22: "type-unsupported", 23: "type-unsupported"}


class MetaDefender:
    """~20–30 антивирусных движков OPSWAT. Сверка только по хэшу — сам файл не отправляется."""
    API = "https://api.metadefender.com/v4"

    def __init__(self, key, emit, stopped, details=None):
        self.key, self.emit, self.stopped = key, emit, stopped
        self.details = details if details is not None else []

    def call(self, path):
        code, body = request(self.API + path, {"apikey": self.key, "accept": "application/json"})
        if code in (401, 403):
            raise ServiceError("неверный API-ключ MetaDefender (Настройки)")
        if code == 429:
            raise ServiceError("MetaDefender: исчерпан лимит бесплатного ключа, попробуй позже")
        return code, body

    def lookup(self, path):
        sha = sha256(path)
        self.emit(f"{os.path.basename(path)}  sha256 {sha}")
        code, body = self.call(f"/hash/{sha}")
        if code == 404:
            self.emit("  нет в базе MetaDefender")
            self.details.append({"file": path, "name": os.path.basename(path), "sha": sha, "verdict": "unknown", "missing": True})
            return "unknown"
        if code != 200:
            raise ServiceError(f"MetaDefender ответил {code}: {(body.get('error') or {}).get('messages', [''])[0]}")
        sr = body.get("scan_results") or {}
        engines = []
        for name, d in (sr.get("scan_details") or {}).items():
            c = MD_CAT.get(d.get("scan_result_i"), "failure")
            engines.append({"e": name, "c": c, "r": d.get("threat_found") or ""})
        mal = sum(1 for e in engines if e["c"] == "malicious")
        sus = sum(1 for e in engines if e["c"] == "suspicious")
        total = sr.get("total_avs") or len(engines)
        v = "threat" if mal >= 3 else "suspicious" if mal or sus else "clean"
        link = f"https://metadefender.com/results/hash/{sha}"
        self.emit(f"  {mal}/{total} движков считают вредоносным" + (f", {sus} — подозрительным" if sus else ""))
        for e in [e for e in engines if e["c"] in ("malicious", "suspicious")][:12]:
            self.emit(f"    · {e['e']}: {e['r']}")
        self.emit(f"  отчёт: {link}")
        engines.sort(key=lambda x: (["malicious", "suspicious"].index(x["c"]) if x["c"] in ("malicious", "suspicious") else 2, x["e"].lower()))
        self.details.append({"file": path, "name": (body.get("file_info") or {}).get("display_name") or os.path.basename(path), "sha": sha,
                             "verdict": v, "positives": mal, "suspicious": sus, "total": total, "engines": engines, "link": link,
                             "type": (body.get("file_info") or {}).get("file_type_description")})
        return v


# ---------------------------------------------------------------- Hybrid Analysis (CrowdStrike)

HA_VERDICT = {"malicious": "threat", "suspicious": "suspicious", "no specific threat": "clean", "whitelisted": "clean",
              "no verdict": "unknown"}


class HybridAnalysis:
    """Песочница CrowdStrike: что файл делал при запуске у них. Только поиск по хэшу — файл не отправляется."""
    API = "https://hybrid-analysis.com/api/v2"

    def __init__(self, key, emit, stopped, details=None):
        self.key, self.emit, self.stopped = key, emit, stopped
        self.details = details if details is not None else []

    def call(self, path):
        # бесплатный API требует именно такой User-Agent
        code, body = request(self.API + path, {"api-key": self.key, "accept": "application/json", "User-Agent": "Falcon Sandbox"})
        if code in (401, 403):
            msg = body.get("message", "") if isinstance(body, dict) else ""
            raise ServiceError("неверный API-ключ Hybrid Analysis (Настройки)" + (f": {msg}" if msg else ""))
        if code == 429:
            raise ServiceError("Hybrid Analysis: превышен лимит запросов, попробуй позже")
        return code, body

    def lookup(self, path):
        sha = sha256(path)
        self.emit(f"{os.path.basename(path)}  sha256 {sha}")
        code, body = self.call(f"/overview/{sha}")
        if code == 200 and isinstance(body, dict) and (body.get("verdict") or body.get("sha256")):
            raw = str(body.get("verdict") or "no verdict").lower()
            score, family, multi = body.get("threat_score"), body.get("vx_family"), body.get("multiscan_result")
        else:
            code2, rep = self.call(f"/search/hash?hash={sha}")
            reps = rep if isinstance(rep, list) else (rep.get("reports") or []) if isinstance(rep, dict) else []
            if code2 != 200 or not reps:
                self.emit("  нет в базе Hybrid Analysis (файл в их песочнице никто не запускал)")
                self.details.append({"file": path, "name": os.path.basename(path), "sha": sha, "verdict": "unknown", "missing": True})
                return "unknown"
            order = ["malicious", "suspicious", "no specific threat", "whitelisted", "no verdict"]
            worst_rep = min(reps, key=lambda r: order.index(str(r.get("verdict") or "no verdict").lower())
                            if str(r.get("verdict") or "no verdict").lower() in order else 9)
            raw = str(worst_rep.get("verdict") or "no verdict").lower()
            score, family, multi = worst_rep.get("threat_score"), worst_rep.get("vx_family"), worst_rep.get("av_detect")
        v = HA_VERDICT.get(raw, "unknown")
        link = f"https://hybrid-analysis.com/sample/{sha}"
        self.emit(f"  вердикт песочницы: {raw}" + (f", оценка угрозы {score}/100" if score is not None else "")
                  + (f", семейство {family}" if family else "") + (f", антивирусы {multi}%" if multi else ""))
        self.emit(f"  отчёт: {link}")
        self.details.append({"file": path, "name": os.path.basename(path), "sha": sha, "verdict": v, "raw": raw, "score": score,
                             "family": family, "multiscan": multi, "link": link})
        return v


# ---------------------------------------------------------------- CIRCL hashlookup (известные чистые файлы)

class Circl:
    """База известных файлов CIRCL (NIST NSRL — файлы из дистрибутивов программ, сборки Windows и Linux). Ключ не нужен.
    Не ищет вирусы: подтверждает, что файл — оригинальный из известного дистрибутива. Это снимает ложные тревоги эвристик."""
    API = "https://hashlookup.circl.lu/lookup"

    def __init__(self, key, emit, stopped, details=None):
        self.emit, self.stopped = emit, stopped
        self.details = details if details is not None else []

    def lookup(self, path):
        h1, h2 = hashlib.sha1(), hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h1.update(chunk)
                h2.update(chunk)
        sha1, sha = h1.hexdigest(), h2.hexdigest()
        self.emit(f"{os.path.basename(path)}  sha1 {sha1}")
        body = None
        for alg, h in (("sha1", sha1), ("sha256", sha)):
            code, b = request(f"{self.API}/{alg}/{h}", {"accept": "application/json"}, timeout=30)
            if code == 200 and isinstance(b, dict) and b.get("SHA-1"):
                body = b
                break
            if code not in (200, 404):
                raise ServiceError(f"CIRCL ответил {code}")
        if not body:
            self.emit("  нет в базе известных файлов — это нормально для новых версий, игр и небольших программ")
            self.details.append({"file": path, "name": os.path.basename(path), "sha": sha, "verdict": "unknown", "missing": True})
            return "unknown"
        trust = body.get("hashlookup:trust", 50)
        bad = bool(body.get("KnownMalicious"))
        src = body.get("source") or ""
        prod = body.get("ProductName") or ""
        self.emit(f"  известный файл: {body.get('FileName') or ''}" + (f" · {prod}" if prod else "") + f" · база {src} · доверие {trust}/100"
                  + (" · ОТМЕЧЕН КАК ВРЕДОНОСНЫЙ" if bad else ""))
        v = "threat" if bad else "clean"
        self.details.append({"file": path, "name": os.path.basename(path), "sha": sha, "verdict": v, "known": True, "trust": trust,
                             "source": src, "product": str(prod), "malicious": bad,
                             "link": f"https://hashlookup.circl.lu/lookup/sha1/{sha1}"})
        return v


SERVICES = {"virustotal": VirusTotal, "filescan": Filescan, "metadefender": MetaDefender, "hybrid": HybridAnalysis, "circl": Circl}


def run(service, action, key, target, emit, stopped, limit=None, details=None):
    """Выполнить действие сервиса; вернуть (код, [вердикт, подпись]). details — сюда складываются подробности по файлам."""
    s = SERVICES[service](key, emit, stopped, details)
    try:
        if action == "lookup":
            files, rest = files_for(target, limit or (8 if service == "virustotal" else 20))
            if service == "virustotal" and len(files) > 4:
                emit(f"Файлов: {len(files)} — с бесплатным ключом это займёт около {(len(files) + 3) // 4} мин (4 запроса в минуту).")
            if not files:
                emit("В папке нет исполняемых файлов, скриптов или архивов — проверять нечего.")
                return 0, ["clean", "Нечего проверять"]
            if len(files) > 1 or rest:
                emit(f"Проверяю {len(files)} главных файлов: сначала программы и скрипты, потом библиотеки"
                     + (f" (ещё {rest} пропущено — бесплатный ключ VirusTotal даёт 4 запроса в минуту)" if rest and service == "virustotal"
                        else f" (ещё {rest} пропущено)" if rest else "") + ". Отправляются только хэши.\n")
            verdicts = []
            for i, p in enumerate(files, 1):
                if stopped():
                    break
                if len(files) > 1:
                    emit(f"[{i}/{len(files)}]")
                try:
                    verdicts.append(s.lookup(p))
                except OSError as e:
                    emit(f"  не прочитать файл: {e}")
            v = worst(verdicts)
            if len(verdicts) > 1:
                emit(f"\nИтог по {len(verdicts)} файлам: " + ", ".join(
                    f"{LABELS[k].lower()} — {verdicts.count(k)}" for k in LABELS if verdicts.count(k)))
        elif action == "upload":
            if not os.path.isfile(target):
                raise ServiceError("загружать можно только отдельный файл")
            v = s.upload(target)
        elif action == "url":
            v = s.url(target)
        else:
            raise ServiceError(f"неизвестное действие {action}")
        if service == "circl" and v == "clean":          # CIRCL не «чисто», а «файл известный» — он не ищет вирусы
            return CODES[v], [v, "Известный файл"]
        return CODES[v], [v, LABELS[v]]
    except ServiceError as e:
        emit(f"[{service}] {e}")
        return 3, ["error", str(e)[:60]]
