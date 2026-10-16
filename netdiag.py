"""«Почему тормозит интернет»: где именно проблема — в компьютере, Wi‑Fi/роутере, DNS или у провайдера.

Шаги (~30 секунд, около 30 МБ трафика на замер скорости):
* сетевой адаптер, шлюз (роутер), DNS-серверы, VPN; для Wi‑Fi — сигнал, диапазон, скорость соединения;
* задержка и потери до роутера и до интернета (1.1.1.1, 8.8.8.8) — ICMP через функцию Windows IcmpSendEcho: без прав
  администратора и не зависит от языка системы;
* скорость ответа DNS: текущий сервер и для сравнения 1.1.1.1;
* скорость скачивания и отдачи — speed.cloudflare.com.
Ничего не меняет.
"""
import ctypes
import json
import os
import random
import re
import socket
import statistics
import struct
import subprocess
import time
import urllib.request
from ctypes import wintypes as wt

NO_WINDOW = 0x08000000


# ---------------------------------------------------------------- ICMP без прав администратора
class _IPOPT(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
                ("OptionsData", ctypes.c_void_p)]


class _ECHO(ctypes.Structure):
    _fields_ = [("Address", wt.ULONG), ("Status", wt.ULONG), ("RoundTripTime", wt.ULONG), ("DataSize", wt.USHORT),
                ("Reserved", wt.USHORT), ("Data", ctypes.c_void_p), ("Options", _IPOPT)]


def ping(host, count=20, timeout_ms=1000, gap=0.15):
    """{sent, lost, loss_pct, avg, min, max, jitter} в миллисекундах."""
    ip = socket.gethostbyname(host)
    iph = ctypes.WinDLL("iphlpapi")
    iph.IcmpCreateFile.restype = wt.HANDLE
    iph.IcmpSendEcho.argtypes = [wt.HANDLE, wt.ULONG, ctypes.c_void_p, wt.WORD, ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, wt.DWORD]
    iph.IcmpSendEcho.restype = wt.DWORD
    iph.IcmpCloseHandle.argtypes = [wt.HANDLE]
    h = iph.IcmpCreateFile()
    addr = struct.unpack("<L", socket.inet_aton(ip))[0]
    data = b"ScanHub-netdiag-32-bytes-payload"
    buf = ctypes.create_string_buffer(ctypes.sizeof(_ECHO) + len(data) + 8)
    times, lost = [], 0
    try:
        for _ in range(count):
            n = iph.IcmpSendEcho(h, wt.ULONG(addr), data, len(data), None, buf, len(buf), timeout_ms)
            rep = _ECHO.from_buffer(buf)
            if n and rep.Status == 0:
                times.append(rep.RoundTripTime)
            else:
                lost += 1
            time.sleep(gap)
    finally:
        iph.IcmpCloseHandle(h)
    out = {"host": host, "ip": ip, "sent": count, "lost": lost, "loss_pct": round(lost * 100 / count)}
    if times:
        diffs = [abs(a - b) for a, b in zip(times, times[1:])]
        out.update(avg=round(statistics.mean(times), 1), min=min(times), max=max(times), jitter=round(statistics.mean(diffs), 1) if diffs else 0)
    return out


# ---------------------------------------------------------------- DNS: прямой запрос к серверу
def dns_time(server, name, timeout=2.0):
    qid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t = time.perf_counter()
    try:
        s.sendto(q, (server, 53))
        while True:
            d, _ = s.recvfrom(1500)
            if d[:2] == struct.pack(">H", qid):
                return round((time.perf_counter() - t) * 1000, 1)
    except OSError:
        return None
    finally:
        s.close()


def dns_test(server):
    names = [f"{random.randint(10 ** 6, 10 ** 7)}.example.com", "www.microsoft.com", "www.youtube.com", "ya.ru", "github.com"]
    res = [dns_time(server, n) for n in names]
    ok = [r for r in res if r is not None]
    return {"server": server, "avg": round(statistics.mean(ok), 1) if ok else None, "fail": len(res) - len(ok), "max": max(ok) if ok else None}


# ---------------------------------------------------------------- адаптер, Wi‑Fi
INFO_PS = r"""$ifx = (Find-NetRoute -RemoteIPAddress 1.1.1.1 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex } | Select-Object -First 1).InterfaceIndex
if ($ifx) { $c = Get-NetIPConfiguration -InterfaceIndex $ifx } else { $c = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1 }
$rx = 'WARP|VPN|TAP|WireGuard|Wintun|OpenVPN|Cloudflare|Tunnel|Proton|Nord|Outline|Hiddify|v2ray|Radmin|ZeroTier|Hamachi|Tailscale'
$vpn = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match $rx } | ForEach-Object { $_.InterfaceDescription })
[pscustomobject]@{ name = $c.InterfaceAlias; desc = $c.NetAdapter.InterfaceDescription; speed = $c.NetAdapter.LinkSpeed;
  media = [string]$c.NetAdapter.PhysicalMediaType; gateway = $c.IPv4DefaultGateway.NextHop; dns = @($c.DNSServer | Where-Object AddressFamily -eq 2 | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique);
  via_vpn = [bool]($c.NetAdapter.InterfaceDescription -match $rx); vpn = $vpn } | ConvertTo-Json -Compress -Depth 3"""


def _ps(script, timeout=60):
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " + script],
                           capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        return json.loads(r.stdout.decode("utf-8", "replace").strip() or "null")
    except Exception:
        return None


def wifi():
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, timeout=15, creationflags=NO_WINDOW).stdout
    except Exception:
        return None
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            text = out.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        return None
    if not re.search(r"(?im)^\s*(State|Состояние)\s*:\s*(connected|подключено)", text):
        return None
    get = lambda *keys: next((m.group(1).strip() for k in keys for m in [re.search(rf"(?im)^\s*{k}\s*:\s*(.+)$", text)] if m), None)
    sig = get("Signal", "Сигнал")
    return {"signal": int(re.sub(r"\D", "", sig)) if sig and re.search(r"\d", sig) else None, "radio": get("Radio type", "Тип радио"),
            "band": get("Band", "Диапазон"), "channel": get("Channel", "Канал"),
            "rx": get(r"Receive rate \(Mbps\)", r"Скорость приема \(Мбит/с\)", r"Скорость приёма \(Мбит/с\)"),
            "tx": get(r"Transmit rate \(Mbps\)", r"Скорость передачи \(Мбит/с\)")}


# ---------------------------------------------------------------- скорость (Cloudflare)
def speed_down(seconds=8, size=50_000_000):
    req = urllib.request.Request(f"https://speed.cloudflare.com/__down?bytes={size}", headers={"User-Agent": "ScanHub"})
    got, t0 = 0, time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            while time.perf_counter() - t0 < seconds:
                chunk = r.read(262144)
                if not chunk:
                    break
                got += len(chunk)
    except Exception as e:
        return {"error": str(e)[:120]}
    dt = time.perf_counter() - t0
    return {"mbps": round(got * 8 / dt / 1e6, 1), "mb": round(got / 1e6, 1), "seconds": round(dt, 1)}


def speed_up(size=8_000_000):
    data = os.urandom(size)
    req = urllib.request.Request("https://speed.cloudflare.com/__up", data=data, method="POST",
                                 headers={"User-Agent": "ScanHub", "Content-Type": "application/octet-stream"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
    except Exception as e:
        return {"error": str(e)[:120]}
    dt = time.perf_counter() - t0
    return {"mbps": round(size * 8 / dt / 1e6, 1), "seconds": round(dt, 1)}


# ---------------------------------------------------------------- всё вместе + вывод «где проблема»
def run(progress=lambda s: None, speed=True):
    R = {"when": time.strftime("%Y-%m-%dT%H:%M:%S")}
    progress("2% · смотрю сетевой адаптер")
    R["adapter"] = _ps(INFO_PS) or {}
    R["wifi"] = wifi()
    gw = R["adapter"].get("gateway")
    if gw:
        progress("8% · пингую роутер (20 раз)")
        try:
            R["gateway"] = ping(gw, 20)
        except OSError as e:
            R["gateway"] = {"error": str(e)}
    progress("30% · пингую интернет (1.1.1.1 и 8.8.8.8)")
    R["internet"] = [ping("1.1.1.1", 20), ping("8.8.8.8", 10)]
    progress("58% · проверяю DNS")
    dns = [d for d in (R["adapter"].get("dns") or []) if re.fullmatch(r"[\d.]+", str(d))][:2]
    R["dns"] = [dns_test(d) for d in dns] + ([dns_test("1.1.1.1")] if "1.1.1.1" not in dns else [])
    if speed:
        progress("65% · меряю скорость скачивания (~8 с)")
        R["down"] = speed_down()
        progress("85% · меряю скорость отдачи")
        R["up"] = speed_up()
    R["verdict"], R["findings"] = judge(R)
    return R


def judge(R):
    F = []
    add = lambda lvl, t, s="": F.append({"lvl": lvl, "t": t, "s": s})
    w, g = R.get("wifi"), R.get("gateway") or {}
    net = [x for x in R.get("internet") or [] if x.get("avg") is not None]
    inet = min(net, key=lambda x: x["avg"]) if net else {}
    inet_loss = max((x.get("loss_pct", 100) for x in R.get("internet") or []), default=100)
    where = []
    if not R.get("adapter", {}).get("gateway"):
        add("bad", "Нет подключения к сети", "Компьютер не видит роутер: проверь кабель или подключение к Wi‑Fi.")
        return "Нет подключения к сети", F
    if w:
        sig = w.get("signal")
        if sig is not None and sig < 50:
            add("warn", f"Слабый сигнал Wi‑Fi: {sig}%", "Подойди ближе к роутеру или убери преграды. Если есть диапазон 5 ГГц — подключись к нему (обычно сеть с «5G» в названии).")
            where.append("wifi")
        elif sig is not None:
            add("ok", f"Сигнал Wi‑Fi хороший: {sig}%", f"{w.get('band') or ''} {w.get('radio') or ''}".strip())
        if w.get("band") and "2.4" in w["band"] and (sig or 0) >= 50:
            add("info", "Подключено на 2,4 ГГц", "Этот диапазон медленнее и чаще забит соседскими сетями. Если роутер умеет 5 ГГц — подключись к нему.")
    if g.get("loss_pct") == 100 and inet.get("avg") is not None:
        add("info", "Роутер не отвечает на пинг", "Некоторые роутеры так настроены — это не ошибка, раз интернет работает.")
    elif g.get("loss_pct", 0) >= 5 or g.get("avg", 0) > 30 or g.get("jitter", 0) > 20:
        add("bad", f"Связь с роутером нестабильна: потери {g.get('loss_pct')}%, задержка {g.get('avg')} мс",
            "Проблема между компьютером и роутером: Wi‑Fi (сигнал, помехи) или сам роутер. Перезагрузи роутер; на Wi‑Fi — подойди ближе или подключись кабелем.")
        where.append("router")
    elif g.get("avg") is not None:
        add("ok", f"До роутера всё хорошо: {g['avg']} мс, потерь {g['loss_pct']}%")
    if inet_loss >= 5 or inet.get("avg", 999) > 120 or inet.get("jitter", 0) > 30:
        if "router" not in where:
            add("bad", f"Проблема дальше роутера: до интернета {inet.get('avg', '—')} мс, потери {inet_loss}%",
                "До роутера связь хорошая, а дальше — нет. Это у провайдера или в самом роутере: перезагрузи роутер; если не поможет — звони провайдеру.")
            where.append("isp")
    elif inet.get("avg") is not None:
        add("ok", f"До интернета хорошо: {inet['avg']} мс, потерь {inet_loss}%")
    dns = [d for d in R.get("dns") or [] if d.get("avg") is not None]
    cur = [d for d in dns if d["server"] != "1.1.1.1"]
    cf = next((d for d in dns if d["server"] == "1.1.1.1"), None)
    if cur and cf and cur[0]["avg"] > max(80, cf["avg"] * 3):
        add("warn", f"DNS медленный: {cur[0]['avg']} мс (1.1.1.1 — {cf['avg']} мс)",
            "Сайты дольше начинают открываться. Можно поставить DNS 1.1.1.1 в настройках сетевого адаптера или роутера.")
        where.append("dns")
    elif cur:
        add("ok", f"DNS отвечает быстро: {cur[0]['avg']} мс")
    if any(d.get("fail") for d in R.get("dns") or []):
        add("warn", "DNS иногда не отвечает", "Если сайты иногда не открываются с первого раза — причина может быть здесь.")
    down, up = R.get("down") or {}, R.get("up") or {}
    if down.get("mbps") is not None:
        lvl = "warn" if down["mbps"] < 10 else "ok"
        add(lvl, f"Скорость: скачивание {down['mbps']} Мбит/с, отдача {up.get('mbps', '—')} Мбит/с",
            "Для видео в 4K нужно около 25 Мбит/с, для звонков — 3–5." + (" Сравни с тарифом: если намного меньше — проверь, не качает ли что-то другой компьютер или телефон, и позвони провайдеру." if lvl == "warn" else ""))
    elif down.get("error"):
        add("warn", "Скорость измерить не удалось", down["error"])
    ad = R.get("adapter", {})
    vpn = ad.get("vpn") or []
    if ad.get("via_vpn"):
        add("info", "Интернет идёт через VPN: " + (ad.get("desc") or ""), "Задержка и скорость зависят от VPN. Для проверки выключи его и повтори.")
    elif vpn:
        add("info", "Установлен VPN, но интернет идёт мимо него: " + ", ".join(vpn[:2]),
            "Это нормально для программ вроде Radmin VPN или ZeroTier — они нужны для игр по локальной сети и интернет не замедляют.")
    verdict = {"wifi": "Похоже, дело в слабом Wi‑Fi", "router": "Проблема между компьютером и роутером", "isp": "Проблема у провайдера или в роутере",
               "dns": "Медленный DNS"}.get(where[0]) if where else "Интернет в порядке"
    return verdict, F
