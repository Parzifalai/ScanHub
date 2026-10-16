"""«Решить» у вылета программы: что можно сделать именно с этой программой.

ScanHub ничего не делает сам — возвращает варианты, человек выбирает кнопку. Варианты — только из уже существующих
безопасных действий ScanHub: обновить программу через проверенный механизм обновлений (winget + проверка установщика
на вирусы), найти драйвер, восстановить системные файлы, открыть «Приложения» Windows для исправления или переустановки.
"""
import os
import re

WIN = os.environ.get("WINDIR", r"C:\Windows")


def _norm(s):
    """Название без версий, разрядности и мусора — чтобы «Microsoft OneDrive 26.178» совпало с «Microsoft OneDrive»."""
    s = re.sub(r"\(.*?\)|\bversion\b|\bx64\b|\bx86\b|\b64-bit\b|\b32-bit\b|v?\d+(\.\d+)+", " ", str(s or "").lower())
    return re.sub(r"[^a-zа-яё0-9]+", " ", s).strip()


def _owner(path, apps):
    """Установленная программа, в папке которой лежит exe (самая длинная совпавшая папка)."""
    p = os.path.normcase(path or "")
    best = None
    for a in apps or []:
        root = os.path.normcase((a.get("path") or "").rstrip("\\/"))
        if root and len(root) > 3 and (p == root or p.startswith(root + os.sep)):
            if not best or len(root) > len(best["path"]):
                best = a
    if not best:                       # exe лежит в папке версии рядом: «…\Microsoft OneDrive\26.178\FileCoAuth.exe»
        for a in apps or []:
            root = os.path.normcase(os.path.dirname((a.get("path") or "").rstrip("\\/")))
            if root and len(root) > 3 and p.startswith(root + os.sep) and os.path.basename(root) not in ("program files", "program files (x86)"):
                best = a
                break
    return best


def _upgrade_for(app_name, upgrades):
    n = _norm(app_name)
    if not n:
        return None
    for u in upgrades or []:
        if u.get("ghost"):
            continue
        un = _norm(u.get("name"))
        if un and (un == n or un.startswith(n) or n.startswith(un)):
            return u
    return None


def crash_fix(app, path, apps, upgrades):
    low = (path or "").lower()
    opts = []
    owner = _owner(path, apps)
    prog = owner["name"] if owner else None
    up = _upgrade_for(prog or app, upgrades)
    if "\\driverstore\\" in low or "\\system32\\drivers\\" in low:
        opts.append({"kind": "go", "page": "health:drivers", "label": "Найти новый драйвер",
                     "desc": "Эта программа — часть драйвера (например, звука или тачпада). Вылеты таких служб обычно лечатся новой версией "
                             "драйвера: ScanHub спросит Windows Update, есть ли она."})
    elif low.startswith(os.path.normcase(WIN).lower() + "\\") and "\\windowsapps\\" not in low:
        opts.append({"kind": "launch", "what": "sfc_repair", "label": "Проверить системные файлы",
                     "desc": "Программа — часть Windows. Если она падает повторно, системные файлы могут быть повреждены: "
                             "DISM и SFC проверят и восстановят их (окно администратора, 10–30 минут)."})
    if up:
        opts.insert(0, {"kind": "update", "ids": [up["id"]], "label": f"Обновить до {up.get('available') or 'новой версии'}",
                        "desc": f"Есть новая версия «{up['name']}» ({up.get('version')} → {up.get('available')}). Разработчики часто исправляют "
                                "вылеты в обновлениях. ScanHub скачает установщик, проверит его на вирусы и поставит."})
    if "\\windowsapps\\" in low:
        opts.append({"kind": "launch", "what": "apps", "label": "Исправить приложение",
                     "desc": "Это приложение из Microsoft Store. В «Приложениях» найди его → «Дополнительные параметры» → «Исправить», "
                             "а если не помогло — «Сбросить» (сбросит его настройки)."})
    elif "\\microsoft office\\" in low:
        opts.append({"kind": "launch", "what": "apps", "label": "Восстановить Office",
                     "desc": "В «Приложениях» найди Microsoft 365 или Office → «Изменить» → «Быстрое восстановление». "
                             "Если вылеты продолжатся — там же «Восстановление по сети»."})
    elif "\\microsoft onedrive\\" in low:
        opts.append({"kind": "info", "label": "Сбросить OneDrive, если повторяется",
                     "desc": "OneDrive обновляется сам, переустанавливать его не нужно. Единичный вылет не страшен. Если повторяется — "
                             "нажми Win+R, вставь %localappdata%\\Microsoft\\OneDrive\\onedrive.exe /reset и нажми Enter: OneDrive "
                             "переподключится, файлы не пропадут."})
    elif prog and not opts:
        opts.append({"kind": "go", "page": "apps:uninst", "label": "Переустановить программу",
                     "desc": f"Новой версии «{prog}» нет. Если вылеты повторяются — удали программу в ScanHub (вместе с остатками) "
                             "и поставь заново с официального сайта: так заменятся повреждённые файлы."})
    if re.search(r"\\steamapps\\common\\", low):
        opts.append({"kind": "info", "label": "Проверить файлы игры в Steam",
                     "desc": "Steam → Библиотека → правой кнопкой по игре → «Свойства» → «Установленные файлы» → «Проверить целостность файлов»."})
    return {"app": app, "path": path, "program": prog, "version": owner.get("version") if owner else None, "options": opts,
            "note": "" if opts else "Готового исправления для этой программы ScanHub не знает. Если вылет был один раз — скорее всего, "
                                    "это случайность. Если повторяется — спроси помощника: он посмотрит журналы."}
