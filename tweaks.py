"""Изменения системы с откатом: приватность, контекстное меню, встроенные приложения, игровой режим,
брандмауэр, автозагрузка и время загрузки, точки восстановления, проверки диска с правами администратора.

Правило: перед изменением исходное значение сохраняется в data\\backups\\tweaks.json — «Вернуть как было» восстанавливает его точно.
Значения в HKCU меняются напрямую, в HKLM и службы — через одного помощника с правами администратора (один UAC).
"""
import ctypes
import json
import os
import re
import struct
import subprocess
import time
import winreg
from datetime import datetime

import psutil

import system

NO_WINDOW = 0x08000000
ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
BACKUPS = os.path.join(DATA, "backups")
TWEAK_BAK = os.path.join(BACKUPS, "tweaks.json")
HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCR": winreg.HKEY_CLASSES_ROOT}
KINDS = {"dword": winreg.REG_DWORD, "sz": winreg.REG_SZ, "expand_sz": winreg.REG_EXPAND_SZ, "binary": winreg.REG_BINARY}
KIND_NAMES = {v: k for k, v in KINDS.items()}


def load(path, default):
    try:
        return json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(value, open(path + ".tmp", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    os.replace(path + ".tmp", path)


# ================================================================ реестр: чтение/запись

def reg_get(root, key, name):
    """(есть ли значение, тип, данные)."""
    try:
        with winreg.OpenKey(HIVES[root], key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            v, t = winreg.QueryValueEx(k, name)
            if isinstance(v, bytes):
                v = v.hex()
            return True, KIND_NAMES.get(t, "sz"), v
    except OSError:
        return False, None, None


def reg_set_local(root, key, name, kind, value):
    with winreg.CreateKeyEx(HIVES[root], key, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
        if kind == "binary" and isinstance(value, str):
            value = bytes.fromhex(value)
        winreg.SetValueEx(k, name, 0, KINDS[kind], value)


def reg_del_local(root, key, name):
    try:
        with winreg.OpenKey(HIVES[root], key, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
            winreg.DeleteValue(k, name)
    except FileNotFoundError:
        pass


def apply_ops(ops, run_elevated):
    """ops: [{"root","key","name","kind","value"} | {"root","key","name","delete":True} | {"service","start"}].
    Сначала часть с правами администратора (если UAC отменят — не изменится ничего), потом HKCU."""
    local, admin = [], []
    for o in ops:
        (local if o.get("root") == "HKCU" and "ps" not in o else admin).append(o)
    if admin:
        el = []
        for o in admin:
            if "ps" in o:          # команда PowerShell (компоненты Windows, настройки Defender)
                el.append({"type": "run", "ps": True, "cmd": ["powershell", "-NoProfile", "-Command",
                                                              "$ErrorActionPreference='Stop'; " + o["ps"]], "timeout": 600})
            elif "service" in o:
                el.append({"type": "reg_set", "root": "HKLM", "key": rf"SYSTEM\CurrentControlSet\Services\{o['service']}",
                           "name": "Start", "kind": "dword", "value": o["start"]})
                if o["start"] == 4:
                    el.append({"type": "run", "cmd": ["sc", "stop", o["service"]], "timeout": 60})
                elif o.get("start_now"):
                    el.append({"type": "run", "cmd": ["sc", "start", o["service"]], "timeout": 60})
            elif o.get("delete"):
                el.append({"type": "reg_del", "root": o["root"], "key": o["key"], "name": o["name"]})
            else:
                el.append({"type": "reg_set", "root": o["root"], "key": o["key"], "name": o["name"], "kind": o["kind"], "value": o["value"]})
        res = run_elevated(el)
        bad = [r.get("error") for r in res if not r.get("ok")]
        bad += [(r.get("out") or "").strip()[-200:] or f"код {r.get('code')}" for o, r in zip(el, res)
                if o.get("ps") and r.get("ok") and r.get("code")]
        if bad:
            raise RuntimeError("; ".join(b for b in bad if b)[:300])
    for o in local:
        if o.get("delete"):
            reg_del_local(o["root"], o["key"], o["name"])
        else:
            reg_set_local(o["root"], o["key"], o["name"], o["kind"], o["value"])
    return True


def svc_start(name):
    ok, _, v = reg_get("HKLM", rf"SYSTEM\CurrentControlSet\Services\{name}", "Start")
    return v if ok else None


# ================================================================ приватность

CDM = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
R = lambda root, key, name, value, kind="dword": {"root": root, "key": key, "name": name, "kind": kind, "value": value}

PRIVACY = [
    dict(id="ads_id", title="Рекламный идентификатор", rec=True,
         desc="Windows выдаёт тебе ID, по которому приложения подбирают персональную рекламу. После выключения реклама не исчезнет, но перестанет "
              "строиться на твоих данных.",
         ops=[R("HKCU", r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0)]),
    dict(id="tailored", title="Персональные предложения по диагностическим данным", rec=True,
         desc="Microsoft использует сведения о том, как ты пользуешься Windows, чтобы показывать советы и рекламу своих сервисов.",
         ops=[R("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Privacy", "TailoredExperiencesWithDiagnosticDataEnabled", 0)]),
    dict(id="suggestions", title="Реклама и советы в «Пуске» и «Параметрах»", rec=True,
         desc="Убирает «рекомендуемые» приложения в меню «Пуск», подсказки в Параметрах и всплывающие советы Windows.",
         ops=[R("HKCU", CDM, n, 0) for n in ("SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled",
                                               "SubscribedContent-353694Enabled", "SubscribedContent-353696Enabled",
                                               "SystemPaneSuggestionsEnabled", "SoftLandingEnabled")]),
    dict(id="silent_apps", title="Тихая установка «рекомендованных» приложений", rec=True,
         desc="Windows сама скачивает игры и приложения-партнёры (Candy Crush, TikTok и т.п.) после обновлений. Это запретит такие установки; "
              "уже установленное удаляется в разделе «Программы → Встроенные приложения».",
         ops=[R("HKCU", CDM, n, 0) for n in ("SilentInstalledAppsEnabled", "OemPreInstalledAppsEnabled", "PreInstalledAppsEnabled")]),
    dict(id="lockscreen", title="Реклама и «факты» на экране блокировки", rec=True,
         desc="Убирает текстовые подсказки и рекламу поверх картинки экрана блокировки. Сама картинка «Windows: интересное» останется.",
         ops=[R("HKCU", CDM, "RotatingLockScreenOverlayEnabled", 0), R("HKCU", CDM, "SubscribedContent-338387Enabled", 0)]),
    dict(id="bing", title="Интернет-результаты Bing в поиске «Пуска»", rec=True,
         desc="Поиск в «Пуске» перестанет отправлять каждый набранный запрос в Bing и показывать веб-результаты — останутся только файлы, "
              "программы и параметры. Работает быстрее.",
         ops=[R("HKCU", r"Software\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", 1),
              R("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", 0)]),
    dict(id="feedback", title="Запросы отзывов от Windows", rec=True,
         desc="Окошки «Насколько вероятно, что вы порекомендуете Windows…» больше не появятся.",
         ops=[R("HKCU", r"Software\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", 0)]),
    dict(id="typing", title="Сбор рукописного ввода и набора текста", rec=True,
         desc="Windows отправляет образцы того, что ты печатаешь и пишешь пером, чтобы «улучшать распознавание». Подсказки клавиатуры продолжат работать.",
         ops=[R("HKCU", r"Software\Microsoft\InputPersonalization", "RestrictImplicitInkCollection", 1),
              R("HKCU", r"Software\Microsoft\InputPersonalization", "RestrictImplicitTextCollection", 1),
              R("HKCU", r"Software\Microsoft\InputPersonalization\TrainedDataStore", "HarvestContacts", 0),
              R("HKCU", r"Software\Microsoft\Personalization\Settings", "AcceptedPrivacyPolicy", 0)]),
    dict(id="recall", title="Recall — снимки экрана для ИИ", rec=True,
         desc="Функция компьютеров Copilot+: каждые несколько секунд сохраняет снимки экрана, чтобы потом искать по ним. Если на твоём ПК "
              "её нет — настройка просто ничего не изменит.",
         ops=[R("HKCU", r"Software\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", 1)]),
    dict(id="activity", title="Журнал действий", rec=True, admin=True,
         desc="Windows запоминает открытые файлы и сайты и может синхронизировать их с облаком Microsoft. Выключение не влияет на «Недавние файлы» Проводника.",
         ops=[R("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0),
              R("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", 0)]),
    dict(id="telemetry", title="Телеметрия Windows и её служба", rec=True, admin=True,
         desc="Ставит минимальный уровень отправки диагностических данных и отключает службу телеметрии (DiagTrack). Честно: на Windows Pro "
              "минимум — «Обязательные данные», полностью выключить телеметрию можно только в Enterprise. Обновления это не ломает.",
         ops=[R("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),
              {"service": "DiagTrack", "start": 4}, {"service": "dmwappushservice", "start": 4}]),
    dict(id="track_progs", title="Отслеживание запускаемых программ", rec=False,
         desc="Windows запоминает, что ты запускаешь, чтобы показывать «Часто используемые» в «Пуске». Выключишь — этот список пропадёт.",
         ops=[R("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Start_TrackProgs", 0)]),
    dict(id="copilot", title="Copilot в Windows", rec=False,
         desc="Убирает встроенного помощника Copilot (кнопку и боковую панель). Отдельное приложение Copilot, если установлено, удаляется в «Встроенных приложениях».",
         ops=[R("HKCU", r"Software\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", 1)]),
    dict(id="chrome_ai", title="Chrome: не скачивать ИИ-модель (до 4 ГБ)", rec=False, admin=True,
         desc="Chrome втихую скачивает модель Gemini Nano (weights.bin, до 4 ГБ) для «Помоги написать» и встроенного ИИ сайтов. Политика Google "
              "запрещает загрузку и удаляет уже скачанную модель. В настройках Chrome появится строка «Управляется вашей организацией» — "
              "так Chrome показывает любые политики. Если Chrome не установлен, ничего не изменится.",
         ops=[R("HKLM", r"SOFTWARE\Policies\Google\Chrome", "GenAILocalFoundationalModelSettings", 1)]),
    dict(id="edge_boost", title="Edge: не держать браузер в памяти", rec=False, admin=True,
         desc="«Ускорение запуска» Edge оставляет его процессы работать в фоне после входа в Windows и после закрытия окон, чтобы Edge открывался "
              "на секунду быстрее. Выключишь — освободится немного оперативной памяти, а первое открытие Edge (и окна ScanHub) станет чуть дольше.",
         ops=[R("HKLM", r"SOFTWARE\Policies\Microsoft\Edge", "StartupBoostEnabled", 0)]),
]


def _op_applied(o):
    if "service" in o:
        return svc_start(o["service"]) == o["start"]
    ok, _, v = reg_get(o["root"], o["key"], o["name"])
    return ok and v == o["value"]


def privacy_status():
    bak = load(TWEAK_BAK, {})
    out = []
    for t in PRIVACY:
        applied = all(_op_applied(o) for o in t["ops"])
        partial = not applied and any(_op_applied(o) for o in t["ops"])
        out.append({k: t[k] for k in ("id", "title", "desc", "rec")} | {"admin": bool(t.get("admin")), "applied": applied, "partial": partial,
                                                                           "can_revert": ("privacy:" + t["id"]) in bak})
    return out


def _backup_ops(tag, ops):
    bak = load(TWEAK_BAK, {})
    if tag in bak:                                  # сохраняем только самое первое (исходное) состояние
        return
    saved = []
    for o in ops:
        if "service" in o:
            saved.append({"service": o["service"], "start": svc_start(o["service"])})
        else:
            ok, kind, v = reg_get(o["root"], o["key"], o["name"])
            saved.append({"root": o["root"], "key": o["key"], "name": o["name"], "exists": ok, "kind": kind, "value": v})
    bak[tag] = {"ops": saved, "when": datetime.now().isoformat(timespec="seconds")}
    save(TWEAK_BAK, bak)


def _restore_ops(tag):
    bak = load(TWEAK_BAK, {})
    b = bak.get(tag)
    if not b:
        return []
    ops = []
    for s in b["ops"]:
        if "service" in s:
            if s["start"] is not None:
                ops.append({"service": s["service"], "start": s["start"], "start_now": s["start"] == 2})
        elif s["exists"]:
            ops.append({"root": s["root"], "key": s["key"], "name": s["name"], "kind": s["kind"], "value": s["value"]})
        else:
            ops.append({"root": s["root"], "key": s["key"], "name": s["name"], "delete": True})
    return ops


def driver_disable(service, run_elevated):
    """Уязвимый драйвер: не загружать при старте Windows (Start=4). Исходное значение — в резервной копии, «Включить обратно» вернёт."""
    ops = [{"service": service, "start": 4}]
    _backup_ops("drv:" + service, ops)
    apply_ops(ops, run_elevated)
    return {"service": service, "start": 4}


def driver_restore(service, run_elevated):
    ops = _restore_ops("drv:" + service)
    if not ops:
        raise RuntimeError("нет сохранённого исходного состояния драйвера")
    apply_ops(ops, run_elevated)
    bak = load(TWEAK_BAK, {})
    bak.pop("drv:" + service, None)
    save(TWEAK_BAK, bak)
    return {"service": service, "start": ops[0].get("start")}


def driver_disabled(service):
    return "drv:" + service in load(TWEAK_BAK, {})


def privacy_apply(ids, run_elevated):
    ops = []
    for t in PRIVACY:
        if t["id"] in ids:
            _backup_ops("privacy:" + t["id"], t["ops"])
            ops += t["ops"]
    apply_ops(ops, run_elevated)
    return privacy_status()


def privacy_revert(ids, run_elevated):
    ops = []
    for i in ids:
        ops += _restore_ops("privacy:" + i)
    apply_ops(ops, run_elevated)
    bak = load(TWEAK_BAK, {})
    for i in ids:
        bak.pop("privacy:" + i, None)
    save(TWEAK_BAK, bak)
    return privacy_status()


# ================================================================ защита Windows
# Каждый пункт: как проверить (state → True «защищено» / False / None «не применимо»), чем исправить:
#   ops — значения реестра (исходные сохраняются, «вернуть как было» точный), ps/ps_revert — команда PowerShell и обратная,
#   launch — страница Windows, где это включается вручную (Windows не даёт менять это программам: защита от подмены,
#   целостность памяти — Windows сама проверяет несовместимые драйверы).

CI_HVCI = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
SEC_PS = r"""$o = @{}
try { $s = Get-MpComputerStatus; $o.tamper = [bool]$s.IsTamperProtected; $o.rt = [bool]$s.RealTimeProtectionEnabled; $o.am = [string]$s.AMRunningMode } catch {}
try { $p = Get-MpPreference; $o.pua = [int]$p.PUAProtection; $o.maps = [int]$p.MAPSReporting } catch {}
try { $d = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard; $o.vbs = @($d.SecurityServicesRunning | % { [int]$_ }) } catch {}
try { $o.bitlocker = (New-Object -ComObject Shell.Application).NameSpace(17).ParseName($env:SystemDrive).ExtendedProperty('System.Volume.BitLockerProtection') } catch {}
try { $o.fw = @(Get-NetFirewallProfile | % { @{ n = [string]$_.Name; e = ([string]$_.Enabled -eq 'True') } }) } catch {}
$o | ConvertTo-Json -Compress -Depth 4"""


def _rv(root, key, name):
    ok, _, v = reg_get(root, key, name)
    return v if ok else None


def _sec_facts():
    f = system.ps(SEC_PS, timeout=90) or {}
    f["build"] = int(platform_build() or 0)
    f["hvci_cfg"] = _rv("HKLM", CI_HVCI, "Enabled")
    f["blocklist"] = _rv("HKLM", r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable")
    f["ppl"] = _rv("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
    f["ss"] = _rv("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled")
    f["ss_pol"] = _rv("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen")
    f["smb1"] = svc_start("mrxsmb10")
    f["ps2"] = _rv("HKLM", r"SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine", "PowerShellVersion")
    f["rdp"] = _rv("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    f["autorun"] = _rv("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun")
    f["secureboot"] = _rv("HKLM", r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    return f


def _defender_on(f):
    return f.get("am") in (None, "", "Normal", "EDR Block Mode")


SECURITY = [
    dict(id="tamper", title="Защита Defender от подмены", rec=True, launch="threatsettings",
         state=lambda f: f.get("tamper") if _defender_on(f) else None,
         desc="Не даёт вирусам и «твикерам» тихо выключить антивирус. Windows разрешает включить её только вручную: «Защита от вирусов и угроз → "
              "Управление настройками → Защита от подделки»."),
    dict(id="pua", title="Defender: блокировать нежелательные программы", rec=True, admin=True,
         state=lambda f: (f.get("pua") == 1) if "pua" in f and _defender_on(f) else None,
         ps="Set-MpPreference -PUAProtection Enabled", ps_revert="Set-MpPreference -PUAProtection Disabled",
         desc="Блокирует рекламное ПО, «ускорители», майнеры в установщиках и программы, которые ставят что-то в нагрузку. По умолчанию в "
              "Windows эта защита выключена. Кряки и активаторы тоже начнут блокироваться — их можно разрешить в журнале защиты."),
    dict(id="cloud", title="Defender: облачная защита", rec=True, admin=True,
         state=lambda f: (f.get("maps", 0) > 0) if "maps" in f and _defender_on(f) else None,
         ps="Set-MpPreference -MAPSReporting Advanced", ps_revert="Set-MpPreference -MAPSReporting Disabled",
         desc="Defender спрашивает облако Microsoft о новых, ещё не известных файлах и узнаёт свежие вирусы за секунды, а не после обновления баз."),
    dict(id="blocklist", title="Блок-лист уязвимых драйверов Microsoft", rec=True, admin=True,
         state=lambda f: f.get("blocklist") == 1 or (f.get("blocklist") is None and f["build"] >= 22621) or 2 in (f.get("vbs") or []),
         ops=[R("HKLM", r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable", 1)],
         desc="Windows не даёт загружать старые драйверы с известными дырами — через них вымогатели выключают антивирусы. Нужна перезагрузка. "
              "Подробнее — проверка «Уязвимые драйверы» в разделе «Сканеры»."),
    dict(id="hvci", title="Целостность памяти (изоляция ядра)", rec=True, launch="coreisolation",
         state=lambda f: 2 in (f.get("vbs") or []) if "vbs" in f else (f.get("hvci_cfg") == 1 if f.get("hvci_cfg") is not None else None),
         desc="Вредоносный код не сможет попасть в ядро Windows. Включается в «Безопасность устройства → Изоляция ядра»: Windows сама "
              "проверит, нет ли несовместимых драйверов (старые утилиты вентиляторов, RGB, античиты), и покажет их. Нужна перезагрузка."),
    dict(id="lsa", title="Защита LSA от кражи паролей", rec=True, admin=True,
         state=lambda f: f.get("ppl") in (1, 2),
         ops=[R("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 2)],
         desc="Не даёт программам вроде Mimikatz вытащить пароли и токены входа из памяти Windows. Нужна перезагрузка. Изредка мешает старым "
              "считывателям смарт-карт и VPN-плагинам — тогда верни как было."),
    dict(id="smartscreen", title="SmartScreen для скачанных программ", rec=True, admin=True,
         state=lambda f: f.get("ss_pol") != 0 and str(f.get("ss") or "Warn").lower() != "off",
         ops=[R("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Warn", "sz")],
         desc="Предупреждает перед запуском незнакомой программы из интернета. Запустить всё равно можно: «Подробнее → Выполнить в любом случае»."),
    dict(id="firewall", title="Брандмауэр включён для всех сетей", rec=True, admin=True,
         state=lambda f: all(p["e"] for p in f["fw"]) if f.get("fw") else None,
         ps="Set-NetFirewallProfile -All -Enabled True",
         desc="Брандмауэр Windows закрывает входящие подключения из сети. Выключенный профиль (например, «Общедоступная сеть» в кафе) — "
              "открытая дверь."),
    dict(id="smb1", title="Старый протокол SMBv1", rec=True, admin=True,
         state=lambda f: f.get("smb1") is None or f.get("smb1") == 4,
         ps="Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null",
         ps_revert="Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -All | Out-Null",
         desc="Через него распространялся WannaCry. Нужен только очень старым сетевым дискам и принтерам (эпохи Windows XP). Нужна перезагрузка."),
    dict(id="ps2", title="PowerShell 2.0", rec=True, admin=True,
         state=lambda f: f.get("ps2") != "2.0",
         ps="Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null",
         ps_revert="Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -All | Out-Null",
         desc="Старая версия без защиты от вредоносных скриптов (AMSI) — вирусы запускают её, чтобы антивирус не увидел скрипт. "
              "Современному PowerShell не нужна."),
    dict(id="rdp", title="Удалённый рабочий стол (RDP)", rec=True, admin=True,
         state=lambda f: f.get("rdp") != 0,
         ops=[R("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1)],
         desc="Позволяет подключаться к этому ПК по сети. Если ты им не пользуешься — лучше выключить: RDP подбирают ботами по паролю."),
    dict(id="autorun", title="Автозапуск с флешек и дисков", rec=True, admin=True,
         state=lambda f: f.get("autorun") == 255,
         ops=[R("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255)],
         desc="Флешка или диск не смогут ничего запустить сами при подключении. Открывать их вручную это не мешает."),
    dict(id="bitlocker", title="Шифрование диска (BitLocker)", rec=False, launch="bitlocker",
         state=lambda f: (f.get("bitlocker") in (1, 3, 5)) if f.get("bitlocker") is not None else None,
         desc="Если ноутбук украдут, файлы без пароля Windows не прочитать. Перед включением сохрани ключ восстановления (в аккаунт Microsoft "
              "или распечатай): без него после замены деталей или сброса BIOS данные не вернуть."),
    dict(id="secureboot", title="Безопасная загрузка (Secure Boot)", rec=False,
         state=lambda f: (f.get("secureboot") == 1) if f.get("secureboot") is not None else None,
         desc="Не даёт загрузчикам-руткитам запуститься раньше Windows. Включается только в настройках BIOS/UEFI (раздел Security или Boot)."),
]


def security_status():
    f = _sec_facts()
    bak = load(TWEAK_BAK, {})
    out = []
    for t in SECURITY:
        try:
            ok = t["state"](f)
        except Exception:
            ok = None
        kind = "fix" if (t.get("ops") or t.get("ps")) else "manual" if t.get("launch") else "info"
        out.append({k: t[k] for k in ("id", "title", "desc", "rec")} | {
            "admin": bool(t.get("admin")), "ok": ok, "kind": kind, "launch": t.get("launch"),
            "can_revert": ("security:" + t["id"]) in bak and bool(t.get("ops") or t.get("ps_revert"))})
    return out


def security_apply(ids, run_elevated):
    ops, bak = [], load(TWEAK_BAK, {})
    for t in SECURITY:
        if t["id"] not in ids:
            continue
        if t.get("ops"):
            _backup_ops("security:" + t["id"], t["ops"])
            ops += t["ops"]
        elif t.get("ps"):
            ops.append({"ps": t["ps"]})
            if t.get("ps_revert") and ("security:" + t["id"]) not in bak:
                bak["security:" + t["id"]] = {"ps": t["ps_revert"], "when": datetime.now().isoformat(timespec="seconds")}
    apply_ops(ops, run_elevated)
    if bak:
        cur = load(TWEAK_BAK, {})
        cur.update({k: v for k, v in bak.items() if k.startswith("security:") and k not in cur})
        save(TWEAK_BAK, cur)
    return security_status()


def security_revert(ids, run_elevated):
    bak, ops = load(TWEAK_BAK, {}), []
    for i in ids:
        b = bak.get("security:" + i)
        if b and b.get("ps"):
            ops.append({"ps": b["ps"]})
        elif b:
            ops += _restore_ops("security:" + i)
    apply_ops(ops, run_elevated)
    bak = load(TWEAK_BAK, {})
    for i in ids:
        bak.pop("security:" + i, None)
    save(TWEAK_BAK, bak)
    return security_status()


# ================================================================ контекстное меню

VERB_PLACES = [("*", "файлы"), ("AllFilesystemObjects", "файлы и папки"), ("Directory", "папки"),
               ("Directory\\Background", "пустое место в папке"), ("Drive", "диски"), ("Folder", "папки")]
BUILTIN_VERBS = {"open", "opennewwindow", "opennewprocess", "opennewtab", "explore", "find", "print", "printto", "runas", "runasuser",
                 "edit", "cmd", "powershell", "pintohome", "pintostartscreen", "updateencryptionsettings", "properties", "openas",
                 "play", "preview", "printto", "taskbarpin", "unpin", "removeproperties", "windows.*", "wsl", "anycode",
                 "opencontaining", "openinwt"}
BLOCKED = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"
CLASSIC = r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"


def _indirect(s):
    if not s or not s.startswith("@"):
        return s
    buf = ctypes.create_unicode_buffer(512)
    if ctypes.windll.shlwapi.SHLoadIndirectString(s, buf, 512, None) == 0:
        return buf.value
    return s


def _subkeys(hive, path):
    try:
        k = winreg.OpenKey(hive, path)
    except OSError:
        return []
    out = []
    i = 0
    while True:
        try:
            out.append(winreg.EnumKey(k, i))
        except OSError:
            break
        i += 1
    return out


def _value(hive, path, name=""):
    try:
        return winreg.QueryValueEx(winreg.OpenKey(hive, path), name)[0]
    except OSError:
        return None


def _owner(path):
    """Где реально лежит ключ HKCR: в HKCU\\Software\\Classes или HKLM\\Software\\Classes."""
    for root, base in (("HKCU", r"Software\Classes"), ("HKLM", r"SOFTWARE\Classes")):
        try:
            winreg.OpenKey(HIVES[root], f"{base}\\{path}").Close()
            return root, f"{base}\\{path}"
        except OSError:
            pass
    return None, None


def ctx_scan():
    HKCR = winreg.HKEY_CLASSES_ROOT
    items, dlls = [], {}
    blocked = set()
    for root in ("HKLM", "HKCU"):
        try:
            k = winreg.OpenKey(HIVES[root], BLOCKED)
            i = 0
            while True:
                try:
                    blocked.add(winreg.EnumValue(k, i)[0].lower())
                except OSError:
                    break
                i += 1
        except OSError:
            pass
    # 1) пункты-команды (shell\verb)
    for place, where in VERB_PLACES:
        for verb in _subkeys(HKCR, f"{place}\\shell"):
            if verb.lower() in BUILTIN_VERBS or verb.lower().startswith("windows."):
                continue
            path = f"{place}\\shell\\{verb}"
            cmd = _value(HKCR, path + "\\command") or ""
            if not cmd and not _value(HKCR, path, "ExplorerCommandHandler") and not _value(HKCR, path, "SubCommands"):
                continue
            exe = system.exe_from_command(cmd) if cmd else ""
            if exe.lower().startswith(os.environ.get("SystemRoot", r"C:\Windows").lower()) and "\\system32\\" in exe.lower():
                continue
            label = _indirect(_value(HKCR, path, "MUIVerb") or _value(HKCR, path) or verb) or verb
            disabled = _value(HKCR, path, "LegacyDisable") is not None or _value(HKCR, path, "ProgrammaticAccessOnly") is not None
            owner, real = _owner(path)
            items.append({"id": f"verb|{path}", "kind": "verb", "label": label.replace("&", ""), "where": where, "exe": exe,
                          "enabled": not disabled, "admin": owner != "HKCU", "reg": real or path})
    # 2) расширения оболочки (shellex\ContextMenuHandlers) — только сторонние
    seen = set()
    for place, where in VERB_PLACES:
        for name in _subkeys(HKCR, f"{place}\\shellex\\ContextMenuHandlers"):
            clsid = _value(HKCR, f"{place}\\shellex\\ContextMenuHandlers\\{name}") or name
            if not re.fullmatch(r"\{[0-9A-Fa-f-]{36}\}", clsid or ""):
                continue
            dll = _value(HKCR, f"CLSID\\{clsid}\\InprocServer32") or ""
            dll = os.path.expandvars(dll.strip('"'))
            if not dll or dll.lower().startswith(os.environ.get("SystemRoot", r"C:\Windows").lower()):
                continue
            key = clsid.lower()
            if key in seen:
                for it in items:
                    if it.get("clsid") == key and where not in it["where"]:
                        it["where"] += ", " + where
                continue
            seen.add(key)
            label = _value(HKCR, f"CLSID\\{clsid}") or name
            items.append({"id": f"ext|{clsid}", "kind": "ext", "clsid": key, "label": label, "name": name, "where": where, "exe": dll,
                          "exists": os.path.exists(dll), "enabled": key not in blocked, "admin": True})
    # кто сделал: описание и компания из файла
    files = sorted({i["exe"] for i in items if i.get("exe") and os.path.exists(i["exe"])})
    info = {}
    if files:
        tmp = os.path.join(DATA, "ctx_files.json")
        json.dump(files, open(tmp, "w", encoding="utf-8"))
        res = system.ps("(Get-Content -Raw -Encoding UTF8 $env:SH_LIST | ConvertFrom-Json) | ForEach-Object { $v = (Get-Item -LiteralPath $_).VersionInfo; "
                        "[pscustomobject]@{p=$_; c=$v.CompanyName; d=$v.FileDescription; n=$v.ProductName} } | ConvertTo-Json -Compress",
                        timeout=120, env={"SH_LIST": tmp})
        os.remove(tmp)
        info = {r["p"]: r for r in system.as_list(res) if isinstance(r, dict)}
    for i in items:
        v = info.get(i.get("exe"), {})
        i["company"] = (v.get("c") or "").strip()
        i["product"] = (v.get("n") or v.get("d") or "").strip()
    items.sort(key=lambda i: (i["product"] or i["label"]).lower())
    classic = _value(winreg.HKEY_CURRENT_USER, CLASSIC) is not None
    win11 = int(platform_build()) >= 22000
    return {"items": items, "classic": classic, "win11": win11, "packaged": ctx_packaged()}


def platform_build():
    try:
        return _value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber") or "0"
    except OSError:
        return "0"


def ctx_packaged():
    """Пункты нового меню Windows 11, которые добавляют приложения-пакеты (только просмотр)."""
    res = system.ps("Get-AppxPackage | Where-Object { -not $_.IsFramework } | Select-Object Name, InstallLocation, PackageFamilyName | ConvertTo-Json -Compress",
                    timeout=60)
    out = []
    for p in system.as_list(res):
        loc = p.get("InstallLocation") or ""
        man = os.path.join(loc, "AppxManifest.xml")
        try:
            text = open(man, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if "fileExplorerContextMenus" in text and not any(o["name"] == p["Name"] for o in out):
            m = re.search(r"<DisplayName>([^<]+)</DisplayName>", text)
            disp = (m.group(1) if m else p["Name"]).strip()
            out.append({"name": p["Name"], "display": p["Name"] if disp.startswith("ms-resource") else disp})
    return out


def ctx_set(item_id, enable, run_elevated):
    kind, _, ref = item_id.partition("|")
    if kind == "verb":
        root, real = _owner(ref)
        if not root:
            raise RuntimeError("пункт не найден")
        bak = load(TWEAK_BAK, {})
        bak.setdefault("ctx:" + ref, {"ops": [{"root": root, "key": real, "name": "LegacyDisable", "exists": False, "kind": None, "value": None}],
                                       "when": datetime.now().isoformat(timespec="seconds")})
        save(TWEAK_BAK, bak)
        op = {"root": root, "key": real, "name": "LegacyDisable"}
        apply_ops([{**op, "delete": True}] if enable else [{**op, "kind": "sz", "value": ""}], run_elevated)
    elif kind == "ext":
        op = {"root": "HKLM", "key": BLOCKED, "name": ref}
        apply_ops([{**op, "delete": True}] if enable else [{**op, "kind": "sz", "value": "ScanHub"}], run_elevated)
    elif kind == "classic":
        if enable:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, CLASSIC, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "")
        else:
            for p in (CLASSIC, CLASSIC.rsplit("\\", 1)[0]):
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, p)
                except OSError:
                    pass
    return True


def restart_explorer():
    subprocess.run(["taskkill", "/F", "/IM", "explorer.exe"], capture_output=True, creationflags=NO_WINDOW)
    time.sleep(1)
    subprocess.Popen(["explorer.exe"])
    return True


# ================================================================ встроенные приложения (debloat)

# группа: ad — реклама и пробники; opt — по желанию; keep — лучше оставить
APPX = {
    "Microsoft.BingNews": ("ad", "Новости", "Лента новостей MSN."),
    "Microsoft.BingWeather": ("opt", "Погода", "Погода от MSN. Виджет погоды на панели задач работает и без неё."),
    "Microsoft.BingSearch": ("ad", "Поиск Bing", "Отдельное приложение поиска Bing."),
    "Microsoft.GetHelp": ("ad", "Техническая поддержка", "Чат поддержки Microsoft."),
    "Microsoft.Getstarted": ("ad", "Советы", "Подсказки «Начало работы»."),
    "Microsoft.MicrosoftSolitaireCollection": ("ad", "Solitaire Collection", "Пасьянсы с рекламой."),
    "Microsoft.People": ("ad", "Люди", "Старая адресная книга, больше не развивается."),
    "Microsoft.WindowsFeedbackHub": ("ad", "Центр отзывов", "Отправка отзывов в Microsoft."),
    "Clipchamp.Clipchamp": ("opt", "Clipchamp", "Видеоредактор Microsoft (часть функций платная)."),
    "Microsoft.MicrosoftOfficeHub": ("ad", "Microsoft 365 (Office)", "Рекламный «вход» в платную подписку Office. Сам Office, если установлен, не трогается."),
    "Microsoft.M365Companions": ("ad", "Помощники Microsoft 365", "Мини-приложения для подписки Microsoft 365."),
    "Microsoft.PowerAutomateDesktop": ("ad", "Power Automate", "Автоматизация для офиса, дома почти не нужна."),
    "Microsoft.Todos": ("opt", "Microsoft To Do", "Список дел. Оставь, если пользуешься."),
    "Microsoft.OutlookForWindows": ("opt", "Outlook (новый)", "Новый почтовый клиент. Оставь, если читаешь в нём почту."),
    "microsoft.windowscommunicationsapps": ("ad", "Почта и Календарь (старые)", "Microsoft прекратила их поддержку, заменены новым Outlook."),
    "Microsoft.Windows.DevHome": ("ad", "Dev Home", "Панель для разработчиков, Microsoft её закрыла."),
    "Microsoft.WindowsMaps": ("ad", "Карты", "Офлайн-карты Windows, почти никто не пользуется."),
    "Microsoft.ZuneVideo": ("opt", "Кино и ТВ", "Старый видеоплеер. Видео откроет «Медиаплеер» или VLC."),
    "Microsoft.ZuneMusic": ("keep", "Медиаплеер", "Современный плеер музыки и видео Windows."),
    "MicrosoftCorporationII.QuickAssist": ("opt", "Быстрая помощь", "Удалённая помощь. Через неё часто действуют мошенники «из поддержки»."),
    "Microsoft.YourPhone": ("opt", "Связь с телефоном", "Звонки и уведомления с Android/iPhone на ПК. Оставь, если пользуешься."),
    "Microsoft.MixedReality.Portal": ("ad", "Портал смешанной реальности", "Для VR-шлемов Windows Mixed Reality, поддержка прекращена."),
    "Microsoft.Microsoft3DViewer": ("ad", "Просмотр 3D", "Просмотрщик 3D-моделей."),
    "Microsoft.SkypeApp": ("ad", "Skype", "Skype закрыт в 2025 году."),
    "MSTeams": ("opt", "Microsoft Teams", "Мессенджер Microsoft. Оставь, если пользуешься для учёбы или работы."),
    "Microsoft.Copilot": ("opt", "Copilot", "ИИ-помощник Microsoft."),
    "Microsoft.Windows.Ai.Copilot.Provider": ("opt", "Copilot", "ИИ-помощник Microsoft."),
    "MicrosoftWindows.Client.WebExperience": ("opt", "Виджеты", "Панель виджетов (погода, новости). Если не открываешь её — можно удалить."),
    "Microsoft.StartExperiencesApp": ("keep", "Компоненты «Пуска»", "Часть нового меню «Пуск»."),
    "Microsoft.Windows.Photos": ("keep", "Фотографии", "Стандартный просмотр фото."),
    "Microsoft.Paint": ("keep", "Paint", ""), "Microsoft.WindowsNotepad": ("keep", "Блокнот", ""),
    "Microsoft.WindowsCalculator": ("keep", "Калькулятор", ""), "Microsoft.WindowsTerminal": ("keep", "Терминал", ""),
    "Microsoft.ScreenSketch": ("keep", "Ножницы", "Снимки экрана."), "Microsoft.WindowsCamera": ("keep", "Камера", ""),
    "Microsoft.WindowsAlarms": ("keep", "Часы", "Будильник и таймер."), "Microsoft.WindowsSoundRecorder": ("keep", "Звукозапись", ""),
    "Microsoft.MicrosoftStickyNotes": ("keep", "Записки", ""),
    "Microsoft.WindowsStore": ("keep", "Microsoft Store", "Без него не установить и не обновить приложения из магазина."),
    "Microsoft.StorePurchaseApp": ("keep", "Покупки в Store", ""),
    "Microsoft.DesktopAppInstaller": ("keep", "Установщик приложений (winget)", "Нужен для обновления программ."),
    "Microsoft.SecHealthUI": ("keep", "Безопасность Windows", ""),
    "Microsoft.GamingApp": ("keep", "Xbox", "Нужно для Game Pass и игр из Microsoft Store."),
    "Microsoft.XboxGamingOverlay": ("keep", "Xbox Game Bar", "Оверлей Win+G: запись экрана, FPS. Нужен некоторым играм."),
    "Microsoft.XboxIdentityProvider": ("keep", "Вход в Xbox", "Нужен для входа в игры с аккаунтом Xbox."),
    "Microsoft.Xbox.TCUI": ("keep", "Интерфейс Xbox", "Нужен играм с аккаунтом Xbox."),
    "Microsoft.XboxGameOverlay": ("opt", "Старый оверлей Xbox", "Предыдущая версия Game Bar."),
    "Microsoft.XboxSpeechToTextOverlay": ("opt", "Речь в текст для Xbox", "Субтитры в голосовом чате Xbox."),
    "E046963F.LenovoCompanion": ("keep", "Lenovo Vantage", "Режимы питания, батареи и вентиляторов Lenovo, обновления драйверов."),
    "NVIDIACorp.NVIDIAControlPanel": ("keep", "Панель управления NVIDIA", ""),
    "MicrosoftWindows.CrossDevice": ("keep", "Связь устройств", "Нужен «Связи с телефоном» и общему буферу обмена."),
    "BytedancePte.Ltd.TikTok": ("ad", "TikTok", "Предустановленный TikTok. Удали, если не ставил его сам."),
    "SpotifyAB.SpotifyMusic": ("opt", "Spotify", "Оставь, если слушаешь музыку в Spotify."),
    "6F71D7A7.HotspotShieldFreeVPN": ("ad", "Hotspot Shield VPN", "Бесплатный VPN с рекламой, часто приходит предустановленным."),
}
KEEP_PREFIX = ("Microsoft.VCLibs", "Microsoft.NET", "Microsoft.UI.Xaml", "Microsoft.WinAppRuntime", "MicrosoftCorporationII.WinAppRuntime",
               "Microsoft.LanguageExperiencePack", "Microsoft.Ink.", "Microsoft.Services.Store", "Microsoft.Windows.", "windows.",
               "Microsoft.WidgetsPlatformRuntime", "Microsoft.ApplicationCompatibilityEnhancements", "MicrosoftWindows.")
CODECS = re.compile(r"(VideoExtension|ImageExtension|WebMediaExtensions|RawImageExtension|HEIF|HEVC|VP9|AV1|AVC|MPEG2|Webp)", re.I)


def appx_list():
    res = system.ps("Get-AppxPackage | Where-Object { -not $_.IsFramework -and $_.SignatureKind -ne 'System' } | "
                    "Select-Object Name, PackageFullName, PackageFamilyName, Version, NonRemovable, SignatureKind, InstallLocation | ConvertTo-Json -Compress",
                    timeout=90)
    out, seen = [], set()
    for p in system.as_list(res):
        name = p.get("Name") or ""
        if name in seen or p.get("NonRemovable"):
            continue
        seen.add(name)
        size = 0
        if p.get("InstallLocation") and os.path.isdir(p["InstallLocation"]):
            size = system.dir_size(p["InstallLocation"], 2)
        if name in APPX:
            grp, title, desc = APPX[name]
        elif CODECS.search(name):
            grp, title, desc = "keep", name.replace("Microsoft.", ""), "Кодек: без него не откроются некоторые фото или видео."
        elif name.startswith(KEEP_PREFIX) or p.get("SignatureKind") != "Store":
            continue                                    # служебные компоненты и пакеты обычных программ (Edge, OneDrive, Claude…): их не трогаем
        else:
            grp, title, desc = "other", _display(p), "Приложение из Microsoft Store — скорее всего, установлено тобой."
        out.append({"name": name, "full": p.get("PackageFullName"), "family": p.get("PackageFamilyName"), "title": title, "desc": desc,
                    "grp": grp, "version": p.get("Version"), "size": size})
    order = {"ad": 0, "opt": 1, "other": 2, "keep": 3}
    out.sort(key=lambda a: (order[a["grp"]], a["title"].lower()))
    return out


def _display(p):
    try:
        text = open(os.path.join(p["InstallLocation"], "AppxManifest.xml"), encoding="utf-8", errors="replace").read()
        m = re.search(r"<DisplayName>([^<]+)</DisplayName>", text)
        if m and not m.group(1).startswith("ms-resource"):
            return m.group(1).strip()
    except (OSError, TypeError, KeyError):
        pass
    return re.sub(r"^[0-9A-F]{8}\.|^[\w]+\.", "", p.get("Name") or "")


def appx_remove(fulls):
    fulls = [f for f in fulls if re.fullmatch(r"[\w.\-~]+", f or "")]
    tmp = os.path.join(DATA, "appx_rm.json")
    json.dump(fulls, open(tmp, "w", encoding="utf-8"))
    res = system.ps("(Get-Content -Raw -Encoding UTF8 $env:SH_LIST | ConvertFrom-Json) | ForEach-Object { $e = $null; "
                    "try { Remove-AppxPackage -Package $_ -ErrorAction Stop } catch { $e = $_.Exception.Message }; "
                    "[pscustomobject]@{p=$_; e=$e} } | ConvertTo-Json -Compress", timeout=900, env={"SH_LIST": tmp})
    os.remove(tmp)
    rows = system.as_list(res)
    return {"removed": [r["p"] for r in rows if not r.get("e")], "errors": [f"{r['p'].split('_')[0]}: {r['e'][:160]}" for r in rows if r.get("e")]}


# ================================================================ игровой режим

GAME_FILE = os.path.join(DATA, "gamemode.json")
BEST_PERF = "ded574b5-45a0-4f42-8737-46345c09c238"
UPDATERS = ("GoogleUpdate.exe", "MicrosoftEdgeUpdate.exe", "AdobeARM.exe", "jusched.exe", "OneDriveStandaloneUpdater.exe",
            "SoftwareUpdate.exe", "DropboxUpdate.exe", "BraveUpdate.exe", "updater.exe", "Update.exe", "CCleanerUpdate.exe",
            "AvastUpdate.exe", "operaupdate.exe", "YandexUpdate.exe", "service_update.exe")
GAME_SERVICES = [("wuauserv", "Центр обновления Windows"), ("UsoSvc", "Оркестратор обновлений"), ("DoSvc", "Оптимизация доставки"),
                 ("WSearch", "Индексирование поиска"), ("SysMain", "SysMain (предзагрузка)")]
GAME_OPTS = [
    dict(id="power", title="Режим питания «Максимальная производительность»", rec=True,
         desc="Процессор и видеокарта меньше сбрасывают частоты. Больше шума и расхода батареи — после игры режим вернётся."),
    dict(id="updaters", title="Закрыть фоновые обновлялки программ", rec=True,
         desc="Google Update, Edge Update, Adobe и подобные программы, которые качают обновления в фоне. При следующем запуске компьютера они вернутся сами."),
    dict(id="memory", title="Очистить оперативную память", rec=True,
         desc="Освобождает память от неактивных программ перед игрой (как кнопка «Очистить память»)."),
    dict(id="capture", title="Выключить фоновую запись игр Xbox", rec=True,
         desc="Game Bar может постоянно записывать последние минуты игры — это отнимает несколько FPS. Win+G и снимки экрана продолжат работать."),
    dict(id="gamemode", title="Включить «Игровой режим» Windows", rec=True,
         desc="Встроенная функция: Windows ставит игру в приоритет и не устанавливает обновления во время игры."),
    dict(id="services", title="Приостановить обновления и индексирование", rec=False, admin=True,
         desc="Останавливает Windows Update, оптимизацию доставки, индексирование поиска и SysMain, чтобы они не нагружали диск и сеть. "
              "Попросит права администратора; после игры службы запустятся снова."),
]


def _overlay():
    g = ctypes.c_byte * 16
    buf = g()
    if ctypes.windll.powrprof.PowerGetEffectiveOverlayScheme(ctypes.byref(buf)) == 0:
        import uuid
        return str(uuid.UUID(bytes_le=bytes(buf)))
    return None


def _set_overlay(guid):
    import uuid
    b = (ctypes.c_byte * 16).from_buffer_copy(uuid.UUID(guid).bytes_le)
    return ctypes.windll.powrprof.PowerSetActiveOverlayScheme(ctypes.byref(b)) == 0


def game_status():
    st = load(GAME_FILE, {"active": False})
    st["options"] = GAME_OPTS
    st["overlay"] = _overlay()
    return st


def game_on(opts, run_elevated, mem_fn):
    st = load(GAME_FILE, {"active": False})
    if st.get("active"):
        return game_status()
    saved, log = {"opts": opts}, []
    if "power" in opts:
        saved["overlay"] = _overlay()
        ok = _set_overlay(BEST_PERF)
        log.append("режим питания: максимальная производительность" if ok else "режим питания: Windows не дала сменить")
    if "capture" in opts:
        saved["capture"] = [reg_get("HKCU", r"Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled"),
                            reg_get("HKCU", r"System\GameConfigStore", "GameDVR_Enabled")]
        reg_set_local("HKCU", r"Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled", "dword", 0)
        reg_set_local("HKCU", r"System\GameConfigStore", "GameDVR_Enabled", "dword", 0)
        log.append("фоновая запись Xbox выключена")
    if "gamemode" in opts:
        saved["gamemode"] = reg_get("HKCU", r"Software\Microsoft\GameBar", "AutoGameModeEnabled")
        reg_set_local("HKCU", r"Software\Microsoft\GameBar", "AutoGameModeEnabled", "dword", 1)
        log.append("игровой режим Windows включён")
    if "updaters" in opts:
        killed = []
        for p in psutil.process_iter(["name", "exe"]):
            n = p.info.get("name") or ""
            if n in UPDATERS and (n not in ("updater.exe", "Update.exe") or "google" in (p.info.get("exe") or "").lower()):
                try:
                    p.kill()
                    killed.append(n)
                except psutil.Error:
                    pass
        log.append(f"закрыто обновлялок: {len(killed)}" + (f" ({', '.join(sorted(set(killed)))})" if killed else ""))
    if "services" in opts:
        running = [s for s, _ in GAME_SERVICES if _svc_running(s)]
        saved["services"] = running
        if running:
            try:
                run_elevated([{"type": "run", "cmd": ["net", "stop", s, "/y"], "timeout": 90} for s in running])
                log.append("приостановлены: " + ", ".join(dict(GAME_SERVICES)[s] for s in running))
            except PermissionError:
                saved["services"] = []
                log.append("службы не остановлены: UAC отменён")
    if "memory" in opts:
        try:
            r = mem_fn()
            log.append(f"освобождено памяти: {r['freed'] // 2 ** 20} МБ")
        except Exception as e:
            log.append(f"очистка памяти: {e}")
    st = {"active": True, "since": datetime.now().isoformat(timespec="seconds"), "saved": saved, "log": log}
    save(GAME_FILE, st)
    return game_status()


def _svc_running(name):
    try:
        return psutil.win_service_get(name).status() == "running"
    except Exception:
        return False


def game_off(run_elevated):
    st = load(GAME_FILE, {"active": False})
    if not st.get("active"):
        return game_status()
    s, log = st.get("saved", {}), []
    if s.get("overlay"):
        _set_overlay(s["overlay"])
        log.append("режим питания возвращён")
    for (ok, kind, v), (key, name) in zip(s.get("capture") or [], [(r"Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled"),
                                                                    (r"System\GameConfigStore", "GameDVR_Enabled")]):
        if ok:
            reg_set_local("HKCU", key, name, kind, v)
        else:
            reg_del_local("HKCU", key, name)
    if "gamemode" in s:
        ok, kind, v = s["gamemode"]
        if ok:
            reg_set_local("HKCU", r"Software\Microsoft\GameBar", "AutoGameModeEnabled", kind, v)
        else:
            reg_del_local("HKCU", r"Software\Microsoft\GameBar", "AutoGameModeEnabled")
    # режим выключен сразу — не дожидаясь окна UAC: службы Windows и так запускает сама, когда они нужны
    if s.get("services"):
        log.append("службы обновлений и поиска запускаются (подтверди окно UAC; если отменить — Windows запустит их сама)")
    save(GAME_FILE, {"active": False, "last_log": log, "ended": datetime.now().isoformat(timespec="seconds")})
    if s.get("services"):
        import threading

        def restart():
            try:
                run_elevated([{"type": "run", "cmd": ["net", "start", x], "timeout": 90} for x in s["services"]])
            except Exception:
                pass
        threading.Thread(target=restart, daemon=True).start()
    return game_status()


# ================================================================ брандмауэр

def firewall_audit():
    res = system.ps(r"""
$af = @{}; Get-NetFirewallApplicationFilter | ForEach-Object { $af[$_.InstanceID] = $_.Program }
$pf = @{}; Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | ForEach-Object { $pf[$_.InstanceID] = "$($_.Protocol) $($_.LocalPort)" }
Get-NetFirewallRule -Direction Inbound -Action Allow | ForEach-Object {
  [pscustomobject]@{id=$_.Name; name=$_.DisplayName; group=$_.Group; enabled=[string]$_.Enabled; profile=[string]$_.Profile; prog=$af[$_.InstanceID];
    port=$pf[$_.InstanceID]; src=[string]$_.PolicyStoreSourceType} } | ConvertTo-Json -Compress
""", timeout=180)
    rules = []
    for r in system.as_list(res):
        builtin = bool(r.get("group")) and str(r["group"]).startswith("@")
        prog = os.path.expandvars(r.get("prog") or "Any")
        port = (r.get("port") or "").strip()
        flags = []
        if prog not in ("Any", "System") and not os.path.exists(prog):
            flags.append(ORPHAN_FLAG)
        if system.in_user_dir(prog) and "\\appdata\\local\\programs\\" not in prog.lower():
            flags.append("разрешено программе из папки пользователя или TEMP")
        if prog == "Any" and port.endswith(" Any") and not builtin:
            flags.append("открыты все порты для всех программ")
        if "Public" in (r.get("profile") or "") or r.get("profile") == "Any":
            pub = True
        else:
            pub = False
        rules.append({"id": r["id"], "name": r.get("name") or r["id"], "builtin": builtin, "enabled": r.get("enabled") == "True",
                      "profile": r.get("profile"), "public": pub, "prog": prog, "port": port, "flags": flags,
                      "level": "warn" if flags and r.get("enabled") == "True" else "ok"})
    mine = [r for r in rules if not r["builtin"]]
    mine.sort(key=lambda r: (r["level"] != "warn", not r["enabled"], r["name"].lower()))
    return {"rules": mine, "builtin": sum(1 for r in rules if r["builtin"] and r["enabled"]),
            "warn": sum(1 for r in mine if r["level"] == "warn"), "enabled": sum(1 for r in mine if r["enabled"])}


def firewall_set(rule_ids, enable, run_elevated):
    ids = [rule_ids] if isinstance(rule_ids, str) else list(rule_ids)
    # у правил, которые Windows создаёт сама («TCP Query User{…}C:\users\…\zoom.exe»), в имени есть путь, «\» и «!».
    # Поэтому имя — строка PowerShell в одинарных кавычках (подстановок в ней нет, кавычка удваивается), а правило
    # ищется точным сравнением: -Name понимает [ ] * ? как шаблон. Какие правила можно менять, проверяет сервер (_only_found).
    if not ids or not all(isinstance(i, str) and i and "\n" not in i and "\r" not in i and len(i) < 600 for i in ids):
        raise RuntimeError("неверный идентификатор правила")
    lit = ",".join("'" + i.replace("'", "''") + "'" for i in ids)
    verb = "Enable-NetFirewallRule" if enable else "Disable-NetFirewallRule"
    ps = (f"$ids = @({lit}); $r = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {{ $ids -ccontains $_.Name }}); "
          f"if ($r.Count) {{ $r | {verb} -ErrorAction Stop }}; 'FOUND=' + $r.Count")
    res = run_elevated([{"type": "run", "cmd": ["powershell", "-NoProfile", "-Command", ps], "timeout": 180}])
    out = res[0].get("out") or res[0].get("error") or ""
    if not res[0].get("ok") or res[0].get("code"):
        raise RuntimeError(out[-300:] or "не удалось")
    m = re.search(r"FOUND=(\d+)", out)
    if m and int(m.group(1)) == 0:
        raise RuntimeError("эти правила уже удалены — обнови список")
    return True


ORPHAN_FLAG = "программы больше нет — правило осталось от удалённого приложения"


def firewall_remove(rule_ids, run_elevated):
    """Удалить правила брандмауэра, которые остались от удалённых программ (файла программы нет).
    Описание правил перед удалением сохраняется в data\\backups\\firewall_removed.json — если программу поставить снова,
    Windows сама спросит разрешение заново."""
    ids = list(rule_ids or [])
    if not ids or not all(isinstance(i, str) and i and "\n" not in i and "\r" not in i and len(i) < 600 for i in ids):
        raise RuntimeError("неверный идентификатор правила")
    lit = ",".join("'" + i.replace("'", "''") + "'" for i in ids)
    ps = (f"$ids = @({lit}); $r = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {{ $ids -ccontains $_.Name }}); "
          f"if ($r.Count) {{ $r | Remove-NetFirewallRule -ErrorAction Stop }}; 'FOUND=' + $r.Count")
    try:
        audit = {r["id"]: r for r in firewall_audit()["rules"]}
        bak = os.path.join(DATA, "backups", "firewall_removed.json")
        old = load(bak, [])
        old.append({"when": datetime.now().isoformat(timespec="seconds"), "rules": [audit.get(i, {"id": i}) for i in ids]})
        os.makedirs(os.path.dirname(bak), exist_ok=True)
        save(bak, old[-50:])
    except Exception:
        pass
    res = run_elevated([{"type": "run", "cmd": ["powershell", "-NoProfile", "-Command", ps], "timeout": 180}])
    out = res[0].get("out") or res[0].get("error") or ""
    if not res[0].get("ok") or res[0].get("code"):
        raise RuntimeError(out[-300:] or "не удалось")
    m = re.search(r"FOUND=(\d+)", out)
    return {"removed": int(m.group(1)) if m else len(ids)}


# ================================================================ автозагрузка и время загрузки

RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
BOOT_FILE = os.path.join(DATA, "boot.json")


def _approved(root, sub, name):
    try:
        with winreg.OpenKey(HIVES[root], f"{APPROVED}\\{sub}") as k:
            v = winreg.QueryValueEx(k, name)[0]
            return not (isinstance(v, bytes) and v and v[0] & 1)       # 02/06 — включено, 03/07 — выключено
    except OSError:
        return True


def startup_list():
    items = []
    places = [("HKCU", RUN, 0, "Run", "реестр (для тебя)"), ("HKLM", RUN, winreg.KEY_WOW64_64KEY, "Run", "реестр (для всех)"),
              ("HKLM", RUN, winreg.KEY_WOW64_32KEY, "Run32", "реестр (для всех, 32-бит)")]
    for root, key, view, sub, where in places:
        try:
            k = winreg.OpenKey(HIVES[root], key, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        i = 0
        while True:
            try:
                name, cmd, _ = winreg.EnumValue(k, i)
            except OSError:
                break
            i += 1
            items.append({"id": f"{root}|{sub}|{name}", "name": name, "cmd": str(cmd), "where": where, "admin": root == "HKLM",
                          "enabled": _approved(root, sub, name), "source": "reg"})
    for root, folder, where in (("HKCU", os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"), "папка автозагрузки"),
                                ("HKLM", os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\StartUp"), "папка автозагрузки (для всех)")):
        if not os.path.isdir(folder):
            continue
        for f in os.listdir(folder):
            if f.lower() == "desktop.ini":
                continue
            items.append({"id": f"{root}|StartupFolder|{f}", "name": os.path.splitext(f)[0], "cmd": os.path.join(folder, f), "where": where,
                          "admin": root == "HKLM", "enabled": _approved(root, "StartupFolder", f), "source": "folder"})
    # программы, автозапуск которых когда-то выключил Kudu (он удалял записи из реестра и сохранял их у себя)
    kudu = os.path.join(os.environ.get("APPDATA", ""), "kudu", "disabled-startups.json")
    have = {i["name"].lower() for i in items}
    for d in system.as_list(load(kudu, [])):
        if isinstance(d, dict) and d.get("name") and d["name"].lower() not in have and "HKCU" in (d.get("location") or "").upper():
            items.append({"id": f"KUDU|{d['name']}", "name": d["name"], "cmd": d.get("command") or "", "where": "отключено программой Kudu",
                          "admin": False, "enabled": False, "source": "kudu"})
    lnk = [i["cmd"] for i in items if i["cmd"].lower().endswith(".lnk")]
    targets = {}
    if lnk:
        tmp = os.path.join(DATA, "startup_lnk.json")
        json.dump(lnk, open(tmp, "w", encoding="utf-8"))
        res = system.ps("$sh = New-Object -ComObject WScript.Shell; @((Get-Content -Raw -Encoding UTF8 $env:SH_LIST | ConvertFrom-Json) | "
                        "ForEach-Object { [pscustomobject]@{p=$_; t=$sh.CreateShortcut($_).TargetPath} }) | ConvertTo-Json -Compress",
                        timeout=60, env={"SH_LIST": tmp})
        os.remove(tmp)
        targets = {r["p"]: r["t"] for r in system.as_list(res) if isinstance(r, dict) and r.get("t")}
    for i in items:
        exe = targets.get(i["cmd"]) or system.exe_from_command(i["cmd"])
        i["exe"] = exe
    sigs = system.signatures([i["exe"] for i in items])
    boot = load(BOOT_FILE, {})
    slow = {s["name"].lower(): s for s in boot.get("apps", [])}
    for i in items:
        s = sigs.get(i["exe"])
        i["signer"] = s["signer"] if s and s["status"] == "Valid" else ""
        i["missing"] = bool(i["exe"]) and not os.path.exists(i["exe"])
        hit = slow.get(os.path.basename(i["exe"] or "").lower())
        i["delay_ms"] = hit["degradation"] if hit else None
    items.sort(key=lambda i: (not i["enabled"], i["name"].lower()))
    return {"items": items, "boot": boot or None}


def startup_set(item_id, enable, run_elevated):
    root, sub, name = (item_id.split("|", 2) + ["", ""])[:3]
    if root == "KUDU":
        kudu = os.path.join(os.environ.get("APPDATA", ""), "kudu", "disabled-startups.json")
        d = next((x for x in system.as_list(load(kudu, [])) if isinstance(x, dict) and x.get("name") == sub), None)
        if not d:
            raise RuntimeError("запись Kudu не найдена")
        reg_set_local("HKCU", RUN, d["name"], "sz", d["command"])
        return True
    data = (b"\x02" if enable else b"\x03") + b"\x00\x00\x00" + (b"\x00" * 8 if enable else struct.pack("<Q", int((time.time() + 11644473600) * 1e7)))
    op = {"root": root, "key": f"{APPROVED}\\{sub}", "name": name, "kind": "binary", "value": data.hex()}
    apply_ops([op], run_elevated)
    return True


def boot_trace(run_elevated):
    """Журнал «Диагностика производительности» (нужны права администратора): время загрузок и кто их замедлял."""
    script = r"""[Console]::OutputEncoding=[Text.Encoding]::UTF8
$ev = Get-WinEvent -LogName 'Microsoft-Windows-Diagnostics-Performance/Operational' -MaxEvents 600 -ErrorAction SilentlyContinue | Where-Object { $_.Id -ge 100 -and $_.Id -le 110 }
@($ev | ForEach-Object { $x = [xml]$_.ToXml(); $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
  [pscustomobject]@{id=$_.Id; t=$_.TimeCreated.ToString('o'); d=$d} }) | ConvertTo-Json -Depth 4 -Compress"""
    res = run_elevated([{"type": "run", "cmd": ["powershell", "-NoProfile", "-Command", script], "timeout": 180}])
    out = res[0].get("out", "") if res and res[0].get("ok") else ""
    try:
        evs = system.as_list(json.loads(out[out.index("["):] if "[" in out else out))
    except ValueError:
        raise RuntimeError("журнал загрузки пуст или недоступен")
    boots = [e for e in evs if e["id"] == 100]
    if not boots:
        raise RuntimeError("Windows ещё не записала ни одной загрузки (журнал пуст — так бывает после чистой установки)")
    # события 101–110 записываются в течение нескольких минут после события 100 своей загрузки
    others = [e for e in evs if e["id"] != 100]
    hist = []
    for i, b in enumerate(boots[:15]):
        d = b["d"]
        upto = boots[i - 1]["t"] if i else "9999"
        window = [e for e in others if _plus(b["t"], -60) <= e["t"] <= _plus(b["t"], 900) and e["t"] < upto]
        hist.append({"t": b["t"], "total": int(d.get("BootTime") or 0), "main": int(d.get("MainPathBootTime") or 0),
                     "post": int(d.get("BootPostBootTime") or 0), "degraded": d.get("BootIsDegradation") == "true",
                     "slow": _boot_slow(window)})
    all_apps = {}
    for e in evs:
        if e["id"] == 101:
            n = (e["d"].get("Name") or "").lower()
            if n:
                x = all_apps.setdefault(n, {"name": e["d"].get("FriendlyName") or e["d"].get("Name"), "file": n, "count": 0, "degradation": 0})
                x["count"] += 1
                x["degradation"] = max(x["degradation"], int(e["d"].get("DegradationTime") or 0))
    data = {"collected": datetime.now().isoformat(timespec="seconds"), "boots": hist, "last": hist[0],
            "slow_last": hist[0]["slow"], "apps": sorted(all_apps.values(), key=lambda r: -r["degradation"])[:30]}
    save(BOOT_FILE, data)
    return data


# что замедляло загрузку: тип события → по-человечески
BOOT_KIND = {101: "программа", 102: "драйвер", 103: "служба", 104: "ядро Windows", 105: "оптимизация Windows", 106: "фоновая оптимизация Windows",
             107: "политики компьютера", 108: "политики пользователя", 109: "устройство", 110: "запуск сеанса Windows"}


def _boot_slow(window):
    rows = []
    for e in window:
        d = e["d"]
        rows.append({"name": d.get("FriendlyName") or d.get("Name") or "?", "file": d.get("Name") or d.get("FileName") or "",
                     "total": int(d.get("TotalTime") or 0), "degradation": int(d.get("DegradationTime") or 0),
                     "kind": BOOT_KIND.get(e["id"], "Windows"), "id": e["id"], "path": d.get("Path") or ""})
    rows.sort(key=lambda r: -r["degradation"])
    try:
        import appinfo
        for r in rows[:15]:
            r["about"] = appinfo.about(r["file"] if r["file"].lower().endswith((".exe", ".sys", ".dll")) else r["name"], r["path"])["ru"]
    except Exception:
        pass
    return rows[:15]


def _plus(iso, seconds):
    from datetime import timedelta
    try:
        return (datetime.fromisoformat(iso) + timedelta(seconds=seconds)).isoformat()
    except ValueError:
        return iso


# ================================================================ точки восстановления

def restore_status():
    ok, _, v = reg_get("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore", "RPSessionInterval")
    pol, _, dis = reg_get("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore", "DisableSR")
    return {"enabled": bool(ok and v) and not (pol and dis == 1), "policy_off": bool(pol and dis == 1),
            "last": load(os.path.join(DATA, "restore.json"), {}).get("last")}


def restore_ops(desc):
    desc = re.sub(r"[^\w .,:()\-«»]", "", desc)[:60] or "ScanHub"
    ps = (f"try {{ Checkpoint-Computer -Description 'ScanHub: {desc}' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop -WarningVariable w 3>$null; "
          "if ($w) { 'SKIP|' + $w[0] } else { 'OK|' } } catch { 'ERR|' + $_.Exception.Message }")
    return {"type": "run", "cmd": ["powershell", "-NoProfile", "-Command", ps], "timeout": 300, "restore": True}


def restore_result(r):
    out = (r.get("out") or r.get("error") or "").strip()
    st = "ok" if "OK|" in out else "skip" if "SKIP|" in out else "error"
    info = {"status": st, "text": out.split("|", 1)[-1].strip()[:300], "when": datetime.now().isoformat(timespec="seconds")}
    if st == "ok":
        save(os.path.join(DATA, "restore.json"), {"last": info["when"]})
    return info


def restore_create(run_elevated, desc="ручная точка"):
    return restore_result(run_elevated([restore_ops(desc)])[0])


def restore_enable(run_elevated):
    res = run_elevated([{"type": "run", "cmd": ["powershell", "-NoProfile", "-Command",
                                                "Enable-ComputerRestore -Drive \"$env:SystemDrive\\\"; "
                                                "vssadmin resize shadowstorage /for=$env:SystemDrive /on=$env:SystemDrive /maxsize=5%"], "timeout": 120},
                        restore_ops("включение защиты системы")])
    return {"status": restore_status(), "point": restore_result(res[1])}


# ================================================================ проверки диска с правами администратора

def disk_admin_ops():
    vols = [p.mountpoint[0] for p in psutil.disk_partitions() if p.fstype == "NTFS" and "fixed" in p.opts]
    ps = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $o = [ordered]@{}; "
          "$o.scan = @(" + ",".join(f"@{{d='{v}'; r=[string](Repair-Volume -DriveLetter {v} -Scan -ErrorAction SilentlyContinue)}}" for v in vols) + "); "
          "$o.smart = @(Get-PhysicalDisk | ForEach-Object { $c = $_ | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue; "
          "@{name=$_.FriendlyName; media=[string]$_.MediaType; temp=$c.Temperature; tmax=$c.TemperatureMax; wear=$c.Wear; hours=$c.PowerOnHours; "
          "rerr=$c.ReadErrorsUncorrected; werr=$c.WriteErrorsUncorrected; rtotal=$c.ReadErrorsTotal} }); "
          "$o.trim = ((fsutil behavior query DisableDeleteNotify) -join ' '); $o | ConvertTo-Json -Depth 4 -Compress")
    return [{"type": "run", "cmd": ["powershell", "-NoProfile", "-Command", ps], "timeout": 1800}]


def disk_admin_parse(r):
    out = r.get("out") or ""
    try:
        d = json.loads(out[out.index("{"):out.rindex("}") + 1])
    except ValueError:
        return {"error": (r.get("error") or out)[-300:]}
    d["scan"] = system.as_list(d.get("scan"))
    d["smart"] = system.as_list(d.get("smart"))
    m = re.search(r"NTFS DisableDeleteNotify\s*=\s*(\d)", d.get("trim") or "")
    d["trim_on"] = (m.group(1) == "0") if m else None
    last = system.ps("$i = Get-ScheduledTask -TaskPath '\\Microsoft\\Windows\\Defrag\\' -TaskName 'ScheduledDefrag' | Get-ScheduledTaskInfo; "
                     "@{last=$(if($i.LastRunTime){$i.LastRunTime.ToString('yyyy-MM-dd')}); res=$i.LastTaskResult} | ConvertTo-Json -Compress", timeout=30) or {}
    d["optimize_last"] = last.get("last")
    return d


def trim_now(run_elevated):
    vols = [p.mountpoint[0] for p in psutil.disk_partitions() if p.fstype == "NTFS" and "fixed" in p.opts]
    res = run_elevated([{"type": "run", "cmd": ["powershell", "-NoProfile", "-Command", f"Optimize-Volume -DriveLetter {v} -ReTrim"], "timeout": 900}
                        for v in vols])
    return {"volumes": vols, "ok": [v for v, r in zip(vols, res) if r.get("ok") and r.get("code") == 0]}
