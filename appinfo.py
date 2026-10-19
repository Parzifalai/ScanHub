"""«Что это за программа» простыми словами — по имени файла, пути и сведениям из самого файла (описание, издатель).
Для разбора сбоев: у каждого вылета/зависания/утечки строка about {"ru", "en"}."""
import ctypes
import os
import re
from ctypes import wintypes

# точные имена файлов — самые частые гости журналов сбоев
KNOWN = {
    "searchprotocolhost.exe": ("Часть поиска Windows: читает содержимое файлов для индекса, чтобы поиск в «Пуске» и Проводнике находил их быстро.",
                               "Part of Windows Search: reads file contents for the index so Start and File Explorer search are fast."),
    "searchindexer.exe": ("Индексатор поиска Windows: строит индекс файлов для быстрого поиска.", "Windows Search indexer: builds the file index for fast search."),
    "searchfilterhost.exe": ("Часть поиска Windows: разбирает файлы для индекса.", "Part of Windows Search: parses files for the index."),
    "explorer.exe": ("Проводник Windows: рабочий стол, панель задач и окна папок.", "Windows Explorer: desktop, taskbar and folder windows."),
    "svchost.exe": ("Системный процесс Windows, внутри которого работают службы.", "A Windows system process that hosts services."),
    "msmpeng.exe": ("Антивирус Microsoft Defender: проверяет файлы при запуске.", "Microsoft Defender antivirus: scans files on access."),
    "onedrive.exe": ("OneDrive — облачное хранилище Microsoft: синхронизирует файлы.", "OneDrive — Microsoft cloud storage: syncs files."),
    "excel.exe": ("Microsoft Excel — таблицы из пакета Office.", "Microsoft Excel — spreadsheets from the Office suite."),
    "winword.exe": ("Microsoft Word — текстовый редактор из пакета Office.", "Microsoft Word — the word processor from the Office suite."),
    "powerpnt.exe": ("Microsoft PowerPoint — презентации из пакета Office.", "Microsoft PowerPoint — presentations from the Office suite."),
    "outlook.exe": ("Microsoft Outlook — почта и календарь из пакета Office.", "Microsoft Outlook — mail and calendar from the Office suite."),
    "onenote.exe": ("OneNote — заметки из пакета Office.", "OneNote — notes from the Office suite."),
    "msaccess.exe": ("Microsoft Access — базы данных из пакета Office.", "Microsoft Access — databases from the Office suite."),
    "officeclicktorun.exe": ("Служба установки и обновления Microsoft Office.", "The Microsoft Office install and update service."),
    "onedrive.exe": ("OneDrive — облачное хранилище Microsoft: синхронизирует твои файлы с облаком.", "OneDrive — Microsoft's cloud storage: syncs your files with the cloud."),
    "filecoauth.exe": ("Часть OneDrive: помогает совместно редактировать документы Office, лежащие в облаке. Работает в фоне.",
                       "Part of OneDrive: helps co-edit Office documents stored in the cloud. Runs in the background."),
    "filesyncconfig.exe": ("Часть OneDrive: настраивает синхронизацию файлов.", "Part of OneDrive: sets up file syncing."),
    "rtkauduservice64.exe": ("Служба звукового драйвера Realtek: управляет звуком, микрофоном и разъёмами. Работает в фоне.",
                             "Realtek audio driver service: handles sound, microphone and jacks. Runs in the background."),
    "rtkngui64.exe": ("Панель настроек звука Realtek.", "The Realtek sound settings panel."),
    "explorer.exe": ("Проводник Windows — папки, рабочий стол и панель задач.", "Windows Explorer — folders, desktop and taskbar."),
    "searchhost.exe": ("Поиск Windows в меню «Пуск».", "Windows Search in the Start menu."),
    "searchapp.exe": ("Поиск Windows в меню «Пуск».", "Windows Search in the Start menu."),
    "startmenuexperiencehost.exe": ("Меню «Пуск» Windows.", "The Windows Start menu."),
    "shellexperiencehost.exe": ("Часть интерфейса Windows: центр уведомлений, часы, всплывающие окна.", "Part of the Windows interface: notification center, clock, flyouts."),
    "shellhost.exe": ("Часть интерфейса Windows: быстрые настройки и всплывающие панели.", "Part of the Windows interface: quick settings and flyouts."),
    "textinputhost.exe": ("Ввод текста Windows: экранная клавиатура, эмодзи, буфер обмена (Win+V).", "Windows text input: touch keyboard, emoji, clipboard (Win+V)."),
    "applicationframehost.exe": ("Окно-рамка для приложений из Microsoft Store.", "The window frame for Microsoft Store apps."),
    "runtimebroker.exe": ("Посредник Windows, который следит за разрешениями приложений из Store.", "A Windows broker that checks permissions of Store apps."),
    "dwm.exe": ("Диспетчер окон Windows — рисует все окна на экране.", "Desktop Window Manager — draws all windows on screen."),
    "svchost.exe": ("Контейнер служб Windows — внутри работают системные службы.", "The Windows service host — system services run inside it."),
    "widgets.exe": ("Виджеты Windows (погода, новости).", "Windows Widgets (weather, news)."),
    "systemsettings.exe": ("Приложение «Параметры» Windows.", "The Windows Settings app."),
    "taskmgr.exe": ("Диспетчер задач Windows.", "Windows Task Manager."),
    "mmc.exe": ("Консоль управления Windows (диспетчер устройств, службы и др.).", "Windows Management Console (Device Manager, Services, etc.)."),
    "msedge.exe": ("Браузер Microsoft Edge.", "The Microsoft Edge browser."),
    "msedgewebview2.exe": ("WebView2 — встроенный браузер Edge, на нём работают окна многих программ (Teams, виджеты, ScanHub).",
                           "WebView2 — the built-in Edge browser that many programs use for their windows (Teams, widgets, ScanHub)."),
    "chrome.exe": ("Браузер Google Chrome.", "The Google Chrome browser."),
    "firefox.exe": ("Браузер Mozilla Firefox.", "The Mozilla Firefox browser."),
    "opera.exe": ("Браузер Opera.", "The Opera browser."),
    "browser.exe": ("Яндекс Браузер.", "Yandex Browser."),
    "telegram.exe": ("Telegram — мессенджер.", "Telegram — a messenger."),
    "discord.exe": ("Discord — голосовой чат и мессенджер для игр.", "Discord — voice chat and messenger for gaming."),
    "steam.exe": ("Steam — магазин и запускалка игр.", "Steam — the game store and launcher."),
    "steamwebhelper.exe": ("Часть Steam: показывает магазин и библиотеку (встроенный браузер).", "Part of Steam: shows the store and library (built-in browser)."),
    "epicgameslauncher.exe": ("Epic Games Launcher — магазин и запускалка игр.", "Epic Games Launcher — a game store and launcher."),
    "code.exe": ("Visual Studio Code — редактор кода.", "Visual Studio Code — a code editor."),
    "teams.exe": ("Microsoft Teams — видеозвонки и чаты.", "Microsoft Teams — video calls and chats."),
    "ms-teams.exe": ("Microsoft Teams — видеозвонки и чаты.", "Microsoft Teams — video calls and chats."),
    "zoom.exe": ("Zoom — видеозвонки.", "Zoom — video calls."),
    "spotify.exe": ("Spotify — музыка.", "Spotify — music."),
    "obs64.exe": ("OBS Studio — запись экрана и стримы.", "OBS Studio — screen recording and streaming."),
    "nvcontainer.exe": ("Служба драйвера NVIDIA (оверлей, обновления драйвера).", "NVIDIA driver service (overlay, driver updates)."),
    "nvidia overlay.exe": ("Оверлей NVIDIA — запись, фильтры и счётчик FPS поверх игр.", "NVIDIA overlay — recording, filters and FPS counter over games."),
    "nvidia app.exe": ("NVIDIA App — настройки и обновления видеокарты NVIDIA.", "NVIDIA App — settings and updates for the NVIDIA graphics card."),
    "radeonsoftware.exe": ("AMD Software — настройки видеокарты AMD.", "AMD Software — settings for the AMD graphics card."),
    "lenovovantage.exe": ("Lenovo Vantage — фирменная утилита ноутбука Lenovo (режимы, обновления, батарея).", "Lenovo Vantage — Lenovo's laptop utility (modes, updates, battery)."),
    "lenovovantageservice.exe": ("Служба Lenovo Vantage — фоновая часть фирменной утилиты Lenovo.", "Lenovo Vantage service — the background part of Lenovo's utility."),
    "msmpeng.exe": ("Антивирус Microsoft Defender.", "Microsoft Defender antivirus."),
    "wallpaper64.exe": ("Wallpaper Engine — живые обои.", "Wallpaper Engine — live wallpapers."),
    "python.exe": ("Python — язык программирования; на нём работают скрипты и сам ScanHub.", "Python — a programming language; scripts and ScanHub itself run on it."),
    "pythonw.exe": ("Python без окна — на нём работают скрипты и сам ScanHub.", "Windowless Python — scripts and ScanHub itself run on it."),
    "powershell.exe": ("PowerShell — командная строка Windows для скриптов.", "PowerShell — the Windows command line for scripts."),
    "claude.exe": ("Claude — приложение ИИ-помощника Anthropic.", "Claude — Anthropic's AI assistant app."),
    "figma.exe": ("Figma — редактор дизайна интерфейсов.", "Figma — an interface design editor."),
    "photoshop.exe": ("Adobe Photoshop — редактор изображений.", "Adobe Photoshop — an image editor."),
    "afterfx.exe": ("Adobe After Effects — видеоэффекты и анимация.", "Adobe After Effects — video effects and animation."),
    "qbittorrent.exe": ("qBittorrent — торрент-клиент.", "qBittorrent — a torrent client."),
    "dllhost.exe": ("Служебный процесс Windows (COM Surrogate): выполняет чужие модули — например, делает миниатюры картинок и видео в Проводнике. "
                    "Если падает, чаще виноват кодек или расширение Проводника.",
                    "A Windows helper process (COM Surrogate): runs other modules — e.g. makes picture and video thumbnails in Explorer. "
                    "If it crashes, a codec or an Explorer extension is usually to blame."),
    "node.exe": ("Node.js — среда для программ на JavaScript; её используют инструменты разработчика.", "Node.js — a runtime for JavaScript programs, used by developer tools."),
    "ffmpeg.exe": ("FFmpeg — программа для обработки видео и звука; её вызывают другие программы.", "FFmpeg — a video and audio processing tool that other programs call."),
    "ollama app.exe": ("Ollama — запуск ИИ-моделей прямо на компьютере.", "Ollama — runs AI models locally on the computer."),
    "ollama.exe": ("Ollama — запуск ИИ-моделей прямо на компьютере.", "Ollama — runs AI models locally on the computer."),
    "atomscan.exe": ("Сканер Atomdrift из ScanHub.", "The Atomdrift scanner from ScanHub."),
    "clamscan.exe": ("Антивирус ClamAV из ScanHub.", "The ClamAV antivirus from ScanHub."),
    "hollows_hunter.exe": ("Сканер HollowsHunter из ScanHub.", "The HollowsHunter scanner from ScanHub."),
    "conhost.exe": ("Окно консоли Windows (чёрное окно командной строки).", "The Windows console window (the black command-line window)."),
    "werfault.exe": ("Отчёты об ошибках Windows — появляется, когда программа падает.", "Windows Error Reporting — shows up when a program crashes."),
    "audiodg.exe": ("Звуковой движок Windows: через него проходят все звуки и эффекты.", "The Windows audio engine: all sounds and effects go through it."),
    "lsass.exe": ("Важный процесс Windows: вход в систему и пароли.", "A critical Windows process: sign-in and passwords."),
    "wps.exe": ("WPS Office — офисный пакет (аналог Word/Excel).", "WPS Office — an office suite (like Word/Excel)."),
    "et.exe": ("WPS Office — таблицы (аналог Excel).", "WPS Office — spreadsheets (like Excel)."),
}
# приложения из Microsoft Store в журнале записаны именем пакета, без пути
STORE = [
    (r"immersivecontrolpanel", ("Приложение «Параметры» Windows.", "The Windows Settings app.")),
    (r"webexperience", ("Виджеты Windows (погода, новости).", "Windows Widgets (weather, news).")),
    (r"copilot", ("Microsoft Copilot — ИИ-помощник Microsoft.", "Microsoft Copilot — Microsoft's AI assistant.")),
    (r"visualstudiocode", ("Visual Studio Code — редактор кода.", "Visual Studio Code — a code editor.")),
    (r"windowsterminal", ("Терминал Windows.", "Windows Terminal.")),
    (r"windowscalculator", ("Калькулятор Windows.", "Windows Calculator.")),
    (r"photos", ("Приложение «Фотографии».", "The Photos app.")),
    (r"zunevideo|mediaplayer", ("Медиаплеер Windows.", "Windows Media Player.")),
    (r"windowsstore", ("Microsoft Store — магазин приложений.", "Microsoft Store — the app store.")),
    (r"outlookforwindows|olk", ("Новый Outlook — почта.", "New Outlook — mail.")),
    (r"xbox|gaming", ("Приложение Xbox / игровые функции Windows.", "The Xbox app / Windows gaming features.")),
]
# семейство программ — по имени, описанию, издателю или пути
PRODUCTS = [
    (r"onedrive", ("Часть OneDrive — облачного хранилища Microsoft.", "Part of OneDrive — Microsoft's cloud storage.")),
    (r"microsoft office|\\office1\d\\|\\root\\office", ("Часть пакета Microsoft Office.", "Part of the Microsoft Office suite.")),
    (r"realtek", ("Часть звукового драйвера Realtek.", "Part of the Realtek audio driver.")),
    (r"nvidia|\\nv_|nvdisplay|nvcontainer", ("Часть драйвера или программ NVIDIA (видеокарта).", "Part of the NVIDIA (graphics card) driver or software.")),
    (r"\bamd\b|radeon", ("Часть драйвера или программ AMD (видеокарта/процессор).", "Part of the AMD (graphics/CPU) driver or software.")),
    (r"\bintel\b", ("Часть драйвера или программ Intel.", "Part of an Intel driver or software.")),
    (r"lenovo", ("Часть фирменных программ Lenovo для ноутбука.", "Part of Lenovo's laptop software.")),
    (r"steam", ("Часть Steam — магазина игр.", "Part of Steam — the game store.")),
    (r"google", ("Программа Google.", "A Google program.")),
    (r"adobe", ("Программа Adobe.", "An Adobe program.")),
    (r"microsoft edge", ("Часть браузера Microsoft Edge.", "Part of the Microsoft Edge browser.")),
]
# чем занят процесс — по имени файла
ROLES = [
    (r"updat|upgrad", ("служба обновлений программы", "the program's updater")),
    (r"crash|report|werfault", ("отправка отчётов о вылетах разработчику", "the crash reporter")),
    (r"setup|install|uninst", ("установщик или удаляльщик", "an installer or uninstaller")),
    (r"service|svc|daemon|agent", ("её фоновая служба", "its background service")),
    (r"helper|broker|container|host", ("её вспомогательный процесс", "its helper process")),
    (r"launcher", ("запускалка", "the launcher")),
    (r"tray|notif", ("значок у часов и уведомления", "the tray icon and notifications")),
]


def _version_info(path):
    """Описание, продукт и издатель из ресурсов файла (то, что видно в «Свойства → Подробно»)."""
    if not path or not os.path.isfile(path):
        return {}
    try:
        ver = ctypes.WinDLL("version")
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return {}
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return {}
        ptr, ln = ctypes.c_void_p(), wintypes.UINT()
        langs = []
        if ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(ln)) and ln.value >= 4:
            arr = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ushort * (ln.value // 2))).contents
            langs = [f"{arr[i]:04x}{arr[i + 1]:04x}" for i in range(0, len(arr), 2)]
        out = {}
        for lang in langs + ["040904b0", "040904e4", "041904b0"]:
            for k, name in (("desc", "FileDescription"), ("product", "ProductName"), ("company", "CompanyName")):
                if k in out:
                    continue
                if ver.VerQueryValueW(buf, f"\\StringFileInfo\\{lang}\\{name}", ctypes.byref(ptr), ctypes.byref(ln)) and ln.value > 1:
                    v = ctypes.wstring_at(ptr.value, ln.value).strip("\x00 ")
                    if v:
                        out[k] = v[:120]
        return out
    except (OSError, ValueError):
        return {}


def _running_path(name):
    try:
        import psutil
        for pr in psutil.process_iter(["name", "exe"]):
            if (pr.info.get("name") or "").lower() == name and pr.info.get("exe"):
                return pr.info["exe"]
    except Exception:
        pass
    return ""


_PROGS = None


def _installed(name):
    """Установленная программа, которой принадлежит файл (по значку или папке установки) → (название, издатель, путь)."""
    global _PROGS
    if _PROGS is None:
        try:
            import uninstall
            _PROGS = uninstall.programs()
        except Exception:
            _PROGS = []
    for pr in _PROGS:
        if os.path.basename(pr.get("icon") or "").lower() == name:
            return pr["name"], pr.get("publisher", ""), pr["icon"]
        loc = pr.get("location")
        if loc and os.path.isfile(os.path.join(loc, name)):
            return pr["name"], pr.get("publisher", ""), os.path.join(loc, name)
    # по имени: GameLauncher.exe → программа «Game»
    norm = lambda s: re.sub(r"[^a-zа-яё0-9]", "", s.lower())
    base = norm(name[:-4])
    best = max((pr for pr in _PROGS if len(norm(_nover(pr["name"]))) >= 4 and norm(_nover(pr["name"])) in base),
               key=lambda pr: len(pr["name"]), default=None)
    return (best["name"], best.get("publisher", ""), "") if best else None


def _nover(s):
    return re.sub(r"\s+v?\d+(\.\d+)+.*$|\s*\(.*\)$", "", s or "").strip()


_CACHE = {}


def about(app, path=""):
    """{"ru", "en"} — что это за программа, одной-двумя фразами."""
    key = ((app or "").lower(), (path or "").lower())
    if key in _CACHE:
        return _CACHE[key]
    name = (app or os.path.basename(path or "")).strip()
    low = name.lower()
    p = (path or "").lower()
    if low in KNOWN:
        ru, en = KNOWN[low]
        _CACHE[key] = r = {"ru": ru, "en": en}
        return r
    if not low.endswith((".exe", ".sys", ".dll", ".msi", ".com", ".scr")) and "." in low and not path:   # имя пакета Store: Microsoft.Copilot
        hit = next((x for rx, x in STORE if re.search(rx, low)), None)
        ru, en = hit or ("Приложение из Microsoft Store.", "A Microsoft Store app.")
        _CACHE[key] = r = {"ru": ru, "en": en}
        return r
    if not path:                                                          # в журнале утечек пути нет — ищем среди запущенных
        path = _running_path(low)
        p = path.lower()
    vi = _version_info(path)
    hay = " ".join([low, p, vi.get("desc", ""), vi.get("product", ""), vi.get("company", "")]).lower()
    role = next((x for rx, x in ROLES if re.search(rx, low)), None)
    fam = next((x for rx, x in PRODUCTS if re.search(rx, hay)), None)
    title = vi.get("product") or vi.get("desc") or ""
    company = vi.get("company", "").rstrip(". ")
    if not title and low.endswith(".exe"):
        inst = _installed(low)
        if inst:
            title, company = inst[0], company or (inst[1] or "").rstrip(". ")
            if not path and inst[2]:
                path, p = inst[2], inst[2].lower()
    title = _nover(title)
    if company and company.lower() in title.lower():
        company = ""
    folder = ""
    m = re.search(r"\\program files(?: \(x86\))?\\([^\\]+)", path or "", re.I) or re.search(r"\\appdata\\(?:local|roaming)\\(?:programs\\)?([^\\]+)", path or "", re.I)
    if m:
        folder = m.group(1)
    if "\\driverstore\\" in p and fam:
        ru, en = fam[0].rstrip(".") + ": работает в фоне вместе с устройством.", fam[1].rstrip(".") + ": runs in the background with the device."
    elif "\\driverstore\\" in p:
        ru, en = (f"Часть драйвера{' от ' + company if company else ''}: работает в фоне вместе с устройством.",
                  f"Part of a driver{' from ' + company if company else ''}: runs in the background with the device.")
    elif "\\windowsapps\\" in p:
        ru, en = (f"Приложение из Microsoft Store{': ' + title if title else ''}.", f"A Microsoft Store app{': ' + title if title else ''}.")
    elif re.search(r"\\windows\\(system32|syswow64|systemapps)?", p) and "\\windows\\temp" not in p:
        ru, en = (f"Компонент Windows{': ' + vi['desc'] if vi.get('desc') else ''}.", f"A Windows component{': ' + vi['desc'] if vi.get('desc') else ''}.")
    elif re.search(r"\\temp\\|\\tmp\\", p):
        ru, en = ("Программа из временной папки — обычно установщик или распакованная на время утилита.",
                  "A program from a temporary folder — usually an installer or a temporarily unpacked utility.")
    elif title:
        ru, en = (f"Программа «{title}»{' от ' + company if company else ''}.", f"The program \"{title}\"{' by ' + company if company else ''}.")
    elif fam:
        ru, en = fam
    elif folder or path:
        folder = folder or os.path.basename(os.path.dirname(path))
        ru, en = (f"Программа из папки «{folder}».", f"A program from the \"{folder}\" folder.")
    else:
        ru, en = ("", "")
    if role and ru and "в фоне" not in ru:
        ru, en = ru.rstrip(".") + f"; этот файл — {role[0]}.", en.rstrip(".") + f"; this file is {role[1]}."
    _CACHE[key] = r = {"ru": ru, "en": en}
    return r


def annotate(r):
    """Добавляет about к вылетам, зависаниям и утечкам разбора сбоев (и к старому разбору с диска)."""
    if not isinstance(r, dict):
        return r
    for k in ("crashes", "hangs", "leaks"):
        for x in r.get(k) or []:
            if isinstance(x, dict) and "about" not in x:
                x["about"] = about(x.get("app", ""), x.get("path", ""))
    return r
