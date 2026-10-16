"""Инструменты ScanHub для ИИ-агентов (Claude Code, Codex) по протоколу MCP.

Агента запускает сам ScanHub (assistant.py) для одного ответа и передаёт сюда адрес своего сервера, номер ответа
и одноразовый ключ (переменные окружения). Этот процесс ничего не делает сам: список инструментов и каждый вызов
он пересылает серверу ScanHub, а сервер решает, что можно: читать данные — всегда, менять систему — только действия
из плана, на которые человек нажал «Сделай сам», с теми же проверками, что и кнопки в окне.

Протокол: JSON-RPC 2.0 построчно через stdin/stdout (MCP stdio)."""
import json
import os
import sys
import urllib.request

URL = os.environ.get("SCANHUB_URL", "http://127.0.0.1:8765")
JOB = os.environ.get("SCANHUB_JOB", "")
KEY = os.environ.get("SCANHUB_AGENT_KEY", "")
PROTOCOL = "2025-06-18"


def _api(path, body):
    req = urllib.request.Request(URL + path, data=json.dumps({"job": JOB, **body}).encode("utf-8"),
                                 headers={"Content-Type": "application/json", "X-Agent-Key": KEY,
                                          "Host": URL.split("//", 1)[1]}, method="POST")
    with urllib.request.urlopen(req, timeout=900) as r:
        return json.load(r)


def _send(msg):
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _handle(req):
    method, rid, params = req.get("method"), req.get("id"), req.get("params") or {}
    if method == "initialize":
        return {"protocolVersion": params.get("protocolVersion") or PROTOCOL, "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "scanhub", "version": "1.0"},
                "instructions": "Инструменты ScanHub: данные этого компьютера (журналы, сбои, устройства, защита, файлы) и действия ScanHub."}
    if method == "tools/list":
        return {"tools": _api("/api/agent/tools", {}).get("tools", [])}
    if method == "tools/call":
        try:
            r = _api("/api/agent/call", {"name": params.get("name", ""), "args": params.get("arguments") or {}})
            return {"content": [{"type": "text", "text": r.get("text", "")}], "isError": bool(r.get("error"))}
        except Exception as e:
            return {"content": [{"type": "text", "text": f"ScanHub не ответил: {e}"}], "isError": True}
    if method == "ping":
        return {}
    if rid is not None:
        raise LookupError(method)
    return None


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        rid = req.get("id")
        try:
            res = _handle(req)
            if rid is not None:
                _send({"jsonrpc": "2.0", "id": rid, "result": res})
        except LookupError:
            _send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"нет метода {req.get('method')}"}})
        except Exception as e:
            if rid is not None:
                _send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": str(e)[:300]}})


if __name__ == "__main__":
    main()
