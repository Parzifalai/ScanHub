"""Браузеры: расширения, политики и прокси — частый способ закрепиться у угонщиков браузера, рекламного мусора и стилеров.

Только чтение: ничего не удаляет. Расширения удаляются в самом браузере, политики — в разделе реестра Policies.
"""
import glob
import json
import os
import re
import subprocess
import winreg

NO_WINDOW = 0x08000000
LA, RA = os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", "")

# браузер -> (папка данных, папки профилей внутри неё или сама папка — профиль, ветка политик)
CHROMIUM = [
    ("Google Chrome", os.path.join(LA, r"Google\Chrome\User Data"), r"Google\Chrome"),
    ("Microsoft Edge", os.path.join(LA, r"Microsoft\Edge\User Data"), r"Microsoft\Edge"),
    ("Brave", os.path.join(LA, r"BraveSoftware\Brave-Browser\User Data"), r"BraveSoftware\Brave"),
    ("Яндекс Браузер", os.path.join(LA, r"Yandex\YandexBrowser\User Data"), r"YandexBrowser"),
    ("Vivaldi", os.path.join(LA, r"Vivaldi\User Data"), r"Vivaldi"),
    ("Opera", os.path.join(RA, r"Opera Software\Opera Stable"), r"Opera Software\Opera"),
    ("Opera GX", os.path.join(RA, r"Opera Software\Opera GX Stable"), r"Opera Software\Opera GX"),
]
STORES = ("clients2.google.com/service/update2/crx", "edge.microsoft.com/extensionwebstorebase", "extension-updates.opera.com",
          "addons.opera.com", "api.browser.yandex.ru", "update.extensions.yandex", "extensions.vivaldi")
# location в Preferences: 4 — распакованное (режим разработчика), 7/9 — поставлено политикой, 2/3/6 — внешней программой
LOC_UNPACKED, LOC_POLICY, LOC_EXTERNAL = {4}, {7, 9}, {2, 3, 6}
ALL_SITES = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "http://*/", "https://*/"}
RISKY_PERMS = {"debugger": "может управлять вкладками как отладчик", "nativeMessaging": "общается с программами на компьютере",
               "proxy": "может пустить весь трафик через свой прокси", "management": "управляет другими расширениями",
               "cookies": "читает cookie (входы в аккаунты)", "webRequestBlocking": "может менять любые запросы",
               "privacy": "меняет настройки приватности браузера", "downloads.open": "открывает скачанные файлы",
               "clipboardRead": "читает буфер обмена"}
POLICY_KEYS = {"ExtensionInstallForcelist": "принудительно ставит расширения", "HomepageLocation": "задаёт домашнюю страницу",
               "RestoreOnStartupURLs": "задаёт страницы при запуске", "NewTabPageLocation": "задаёт новую вкладку",
               "DefaultSearchProviderSearchURL": "задаёт поисковик", "DefaultSearchProviderName": "задаёт поисковик",
               "ProxyServer": "задаёт прокси", "ProxyPacUrl": "задаёт прокси (PAC)", "ProxyMode": "задаёт режим прокси",
               "ExtensionInstallSources": "разрешает ставить расширения с чужих сайтов",
               "DeveloperToolsAvailability": "запрещает инструменты разработчика", "ExtensionSettings": "управляет расширениями"}


def _json(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _msg(folder, manifest, value):
    """«__MSG_appName__» → настоящее название из _locales."""
    m = re.fullmatch(r"__MSG_(\w+?)__", value or "")
    if not m:
        return value
    key = m.group(1).lower()
    for loc in [manifest.get("default_locale"), "ru", "en", "en_US"]:
        if not loc:
            continue
        msgs = _json(os.path.join(folder, "_locales", loc, "messages.json")) or {}
        for k, v in msgs.items():
            if k.lower() == key and isinstance(v, dict) and v.get("message"):
                return v["message"]
    return value


def _profiles(root):
    if os.path.isfile(os.path.join(root, "Preferences")):          # Opera: папка — сама профиль
        return [(root, "")]
    out = []
    for d in ["Default"] + sorted(os.path.basename(p) for p in glob.glob(os.path.join(root, "Profile *"))):
        p = os.path.join(root, d)
        if os.path.isdir(p):
            name = ((_json(os.path.join(p, "Preferences")) or {}).get("profile") or {}).get("name") or d
            out.append((p, name))
    return out


def _chromium(browser, root):
    exts = []
    for prof, pname in _profiles(root):
        settings = {}
        for f in ("Secure Preferences", "Preferences"):
            s = ((_json(os.path.join(prof, f)) or {}).get("extensions") or {}).get("settings") or {}
            for k, v in s.items():
                settings.setdefault(k, {}).update(v if isinstance(v, dict) else {})
        base = os.path.join(prof, "Extensions")
        ids = set(os.listdir(base)) if os.path.isdir(base) else set()
        ids |= {k for k, v in settings.items() if v.get("location") in LOC_UNPACKED and v.get("path")}
        for eid in sorted(ids):
            st = settings.get(eid, {})
            loc = st.get("location")
            if loc in (5, 10):                                        # встроенные компоненты браузера
                continue
            folder = st.get("path") if loc in LOC_UNPACKED else None
            if not folder:
                vers = sorted(glob.glob(os.path.join(base, eid, "*")), key=os.path.getmtime)
                folder = vers[-1] if vers else None
            elif not os.path.isabs(folder):
                folder = os.path.join(base, eid, folder)
            man = _json(os.path.join(folder, "manifest.json")) if folder else None
            man = man or st.get("manifest") or {}
            if not man:
                continue
            perms = [p for p in (man.get("permissions") or []) + (man.get("optional_permissions") or []) if isinstance(p, str)]
            hosts = [p for p in (man.get("host_permissions") or []) if isinstance(p, str)] + [p for p in perms if "/" in p or p == "<all_urls>"]
            for cs in man.get("content_scripts") or []:
                hosts += [m for m in cs.get("matches") or [] if isinstance(m, str)]
            upd = man.get("update_url") or ""
            from_store = st.get("from_webstore") or any(s in upd for s in STORES)
            exts.append({"browser": browser, "profile": pname, "id": eid, "name": _msg(folder or "", man, man.get("name") or eid),
                         "version": man.get("version", ""), "enabled": not st.get("disable_reasons") and st.get("state", 1) != 0,
                         "store": bool(from_store), "unpacked": loc in LOC_UNPACKED, "policy": loc in LOC_POLICY,
                         "external": loc in LOC_EXTERNAL, "all_sites": any(h in ALL_SITES or h.startswith("*://*/") for h in hosts),
                         "risky": sorted({p for p in perms if p in RISKY_PERMS}), "path": folder or ""})
    return exts


def _firefox():
    exts = []
    for prof in glob.glob(os.path.join(RA, r"Mozilla\Firefox\Profiles\*")):
        data = _json(os.path.join(prof, "extensions.json")) or {}
        for a in data.get("addons") or []:
            if a.get("type") != "extension" or str(a.get("location", "")).startswith("app-system") or a.get("location") == "app-builtin":
                continue
            perms = ((a.get("userPermissions") or {}).get("permissions") or [])
            hosts = ((a.get("userPermissions") or {}).get("origins") or [])
            loc = a.get("location", "")
            exts.append({"browser": "Firefox", "profile": os.path.basename(prof).split(".", 1)[-1], "id": a.get("id", ""),
                         "name": (a.get("defaultLocale") or {}).get("name") or a.get("id", ""), "version": a.get("version", ""),
                         "enabled": bool(a.get("active")), "store": loc == "app-profile" and (a.get("signedState") or 0) > 0,
                         "unpacked": loc == "app-temporary", "policy": False, "external": loc.startswith(("winreg", "app-global")),
                         "unsigned": (a.get("signedState") or 0) <= 0, "all_sites": any(h in ALL_SITES for h in hosts),
                         "risky": sorted({p for p in perms if p in RISKY_PERMS}), "path": a.get("path") or ""})
    return exts


def _reg_values(hive, path):
    out = {}
    try:
        with winreg.OpenKey(hive, path) as k:
            i = 0
            while True:
                try:
                    n, v, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out[n] = v
                i += 1
            j = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, j)
                except OSError:
                    break
                out[sub] = list(_reg_values(hive, path + "\\" + sub).values())
                j += 1
    except OSError:
        pass
    return out


def _policies():
    out = []
    branches = [(b, r"SOFTWARE\Policies\\" + p) for b, _, p in CHROMIUM] + [("Firefox", r"SOFTWARE\Policies\Mozilla\Firefox")]
    for browser, path in branches:
        for hive, hn in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
            vals = _reg_values(hive, path)
            hits = {k: v for k, v in vals.items() if k in POLICY_KEYS or (browser == "Firefox" and k in ("Extensions", "Proxy", "Homepage"))}
            if hits:
                out.append({"browser": browser, "key": f"{hn}\\{path}",
                            "items": [{"name": k, "what": POLICY_KEYS.get(k, "управляет браузером"), "value": str(v)[:300]} for k, v in hits.items()]})
    return out


def _proxy():
    res = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
            def val(n):
                try:
                    return winreg.QueryValueEx(k, n)[0]
                except OSError:
                    return None
            if val("ProxyEnable") == 1 and val("ProxyServer"):
                res["proxy"] = str(val("ProxyServer"))
                res["bypass"] = str(val("ProxyOverride") or "")
            if val("AutoConfigURL"):
                res["pac"] = str(val("AutoConfigURL"))
    except OSError:
        pass
    try:
        out = subprocess.run(["netsh", "winhttp", "show", "proxy"], capture_output=True, timeout=20, creationflags=NO_WINDOW).stdout
        txt = out.decode("cp866", "replace")
        m = re.search(r"(?:Proxy Server\(s\)|Прокси-сервер\(ы\)|прокси-сервер\S*)\s*:\s*(\S+)", txt, re.I)
        if m:
            res["winhttp"] = m.group(1)
    except Exception:
        pass
    return res


def _err(where, e):
    try:
        import report
        report.record(where, e)
    except Exception:
        pass


def audit():
    exts, failed = [], []            # браузер, профиль которого не прочитался, — показываем, а не молчим «всё чисто»
    for browser, root, _ in CHROMIUM:
        if os.path.isdir(root):
            try:
                exts += _chromium(browser, root)
            except Exception as e:
                failed.append({"browser": browser, "error": str(e)[:200]})
                _err(f"браузеры: {browser}", e)
    try:
        exts += _firefox()
    except Exception as e:
        failed.append({"browser": "Firefox", "error": str(e)[:200]})
        _err("браузеры: Firefox", e)
    pol, px = _policies(), _proxy()
    forced = {v.split(";")[0] for p in pol for i in p["items"] if i["name"] == "ExtensionInstallForcelist" for v in re.findall(r"[a-p]{32}[^',\]]*", i["value"])}
    try:                                   # база расширений, удалённых из магазинов за вредоносность (MalExt Sentry)
        import intel
        known = intel.malext_db()
    except Exception:
        known = {}
    for e in exts:
        flags = []
        mx = known.get(e["id"]) if e["browser"] != "Firefox" else None
        if mx:
            e["malext"] = mx
            flags.append(f"в базе вредоносных расширений: {intel.malext_reason(mx['reason'])} (удалено из магазина)")
        if e["policy"] or e["id"] in forced:
            flags.append("поставлено принудительно через политику — так закрепляются угонщики браузера")
        if e["unpacked"]:
            flags.append("распаковано вручную (режим разработчика) — если ты не ставил его сам, удали")
        elif not e["store"]:
            flags.append("установлено не из магазина расширений" + (" другой программой" if e["external"] else ""))
        if e.get("unsigned"):
            flags.append("без подписи Mozilla")
        if e["all_sites"]:
            flags.append("читает и меняет все сайты")
        flags += [RISKY_PERMS[p] for p in e["risky"]]
        e["flags"] = flags
        # поставлено политикой или чужой программой — так действуют угонщики; распакованное вручную обычно ставил сам человек
        forced_in = e["policy"] or e["id"] in forced or e.get("unsigned") or (not e["store"] and not e["unpacked"])
        broad = e["all_sites"] or bool(set(e["risky"]) & {"debugger", "proxy", "nativeMessaging", "management", "cookies"})
        e["level"] = "bad" if forced_in and broad else "warn" if forced_in or e["unpacked"] else "info" if broad else "ok"
        if mx:
            e["level"] = "bad" if mx["bad"] else "warn" if e["level"] in ("info", "ok") else e["level"]
    order = {"bad": 0, "warn": 1, "info": 2, "ok": 3}
    exts.sort(key=lambda e: (order[e["level"]], e["browser"], e["name"].lower()))
    return {"extensions": exts, "policies": pol, "proxy": px, "failed": failed,
            "browsers": sorted({b for b, root, _ in CHROMIUM if os.path.isdir(root)} | ({"Firefox"} if glob.glob(os.path.join(RA, r"Mozilla\Firefox\Profiles\*")) else set()))}


def findings(r):
    """Короткие выводы для глубокой и ультра проверки: [(уровень, текст)]."""
    out = []
    for e in r["extensions"]:
        if e["level"] in ("bad", "warn"):
            out.append((e["level"], f"{e['browser']}: расширение «{e['name']}» — {'; '.join(e['flags'])}"))
    for p in r["policies"]:
        out.append(("warn", f"{p['browser']}: браузером управляют политики ({', '.join(i['what'] for i in p['items'])}) — {p['key']}"))
    px = r["proxy"]
    if px.get("proxy"):
        out.append(("warn", f"Весь трафик Windows идёт через прокси {px['proxy']} — если это не твой VPN или программа, это перехват"))
    if px.get("pac"):
        out.append(("warn", f"Задан скрипт настройки прокси (PAC): {px['pac']} — так подменяют сайты и рекламу"))
    if px.get("winhttp"):
        out.append(("info", f"Прокси для служб Windows (WinHTTP): {px['winhttp']}"))
    return out
