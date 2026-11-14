"""Сторож для Antigravity: пропускает только инструменты ScanHub (и поиск в интернете, если он разрешён).

Antigravity запускает этот скрипт перед каждым шагом агента (хук PreToolUse из временной папки ответа, см. agents.py).
На входе — JSON с шагом, на выходе — {"decision": "allow" | "deny"}. Всё, что не в списке, запрещено: командная
строка, чтение и запись файлов, браузер. Настройки ответа (разрешён ли интернет) лежат рядом: gate.json в папке хука."""
import json
import os
import sys

WEB = {"search_web", "read_url_content"}


def decide(call, web):
    name, args = str(call.get("name") or ""), call.get("args") or {}
    if name == "call_mcp_tool":
        return str(args.get("ServerName") or "").startswith("scanhub")
    if name in ("read_file", "view_file", "list_dir", "list_directory"):
        # описания инструментов ScanHub Antigravity кладёт в свою папку mcp\scanhub_* и читает их перед вызовом
        p = os.path.normcase(os.path.abspath(str(args.get("Path") or args.get("AbsolutePath") or args.get("DirectoryPath") or "")))
        base = os.path.normcase(os.path.join(os.path.expanduser("~"), ".gemini"))
        return p.startswith(base + os.sep) and (os.sep + "mcp" + os.sep + "scanhub") in p and ".." not in p
    return web and name in WEB


def main():
    try:
        opts = json.load(open("gate.json", encoding="utf-8"))
    except (OSError, ValueError):
        opts = {}
    try:
        ok = decide(json.load(sys.stdin).get("toolCall") or {}, bool(opts.get("web")))
    except Exception:
        ok = False
    sys.stdout.write(json.dumps({"decision": "allow" if ok else "deny",
                                 "reason": "В ScanHub помощнику доступны только инструменты ScanHub" + (" и поиск в интернете" if opts.get("web") else "")
                                           + ". Ответь по-другому, без этого шага."}))   # только ASCII: кодировка консоли тут не UTF-8


if __name__ == "__main__":
    main()
