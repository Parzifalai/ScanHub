"""ИИ-агенты по подписке: Claude Code (подписка Claude Pro/Max) и Codex (подписка ChatGPT Plus/Pro).

ScanHub не входит в аккаунт сам: он запускает официальную программу, в которую человек вошёл своим аккаунтом,
и запросы идут в лимиты его подписки. Каждый ответ — отдельный запуск без сохранения сессии. Встроенные инструменты
агента (командная строка, чтение и правка файлов, интернет) выключены; ему доступны только инструменты ScanHub
через mcp_server.py — читать данные компьютера и, после кнопки «Сделай сам», выполнять действия из плана."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
NO_WINDOW = 0x08000000
STATUS_TIMEOUT = 20
MAX_OUT = 4 * 2 ** 20


class AgentError(Exception):
    pass


# ---------------------------------------------------------------- где лежат программы

def _is_file(p):
    try:
        return os.path.isfile(p)
    except OSError:
        return False


def find_claude():
    """Настоящий claude.exe (официальный установщик или пакет npm); .cmd-обёртки не запускаем — им нужна оболочка."""
    home, appdata = os.path.expanduser("~"), os.environ.get("APPDATA", "")
    cands = [os.path.join(home, ".local", "bin", "claude.exe"), os.path.join(home, ".claude", "local", "claude.exe")]
    roots = [os.path.join(appdata, "npm", "node_modules", "@anthropic-ai", "claude-code")] if appdata else []
    for d in filter(None, os.environ.get("PATH", "").split(os.pathsep)):
        d = d.strip('"')
        cands.append(os.path.join(d, "claude.exe"))
        roots.append(os.path.join(d, "node_modules", "@anthropic-ai", "claude-code"))
    cands += [os.path.join(r, "bin", "claude.exe") for r in roots]
    return next((c for c in cands if _is_file(c)), None)


def find_codex():
    """codex.exe: официальная установка (%LOCALAPPDATA%\\OpenAI\\Codex\\bin), PATH или пакет npm @openai/codex."""
    cands = []
    la = os.environ.get("LOCALAPPDATA", "")
    if la:
        base = os.path.join(la, "OpenAI", "Codex", "bin")
        cands.append(os.path.join(base, "codex.exe"))
        try:
            vers = [os.path.join(base, d, "codex.exe") for d in os.listdir(base)]
            cands += sorted((v for v in vers if _is_file(v)), key=os.path.getmtime, reverse=True)
        except OSError:
            pass
    dirs = [d.strip('"') for d in os.environ.get("PATH", "").split(os.pathsep) if d.strip()]
    cands += [os.path.join(d, "codex.exe") for d in dirs]
    appdata = os.environ.get("APPDATA", "")
    for prefix in dict.fromkeys(dirs + ([os.path.join(appdata, "npm")] if appdata else [])):
        root = os.path.join(prefix, "node_modules", "@openai")
        for vendor in (os.path.join(root, "codex", "node_modules", "@openai", "codex-win32-x64", "vendor"),
                       os.path.join(root, "codex-win32-x64", "vendor"), os.path.join(root, "codex", "vendor")):
            cands += [os.path.join(vendor, "x86_64-pc-windows-msvc", "bin", "codex.exe"),
                      os.path.join(vendor, "x86_64-pc-windows-msvc", "codex", "codex.exe")]
    return next((c for c in cands if _is_file(c)), None)


CLI = {
    "claude_code": {"find": find_claude, "name": "Claude Code", "get": "https://claude.ai/download",
                    "missing": "Нужна бесплатная программа Claude Code: поставь её (claude.ai/download или «npm i -g @anthropic-ai/claude-code»), "
                               "затем нажми «Проверить»."},
    "codex": {"find": find_codex, "name": "Codex", "get": "https://developers.openai.com/codex/cli",
              "missing": "Нужна бесплатная программа Codex от OpenAI: поставь её («npm i -g @openai/codex» или с developers.openai.com/codex), "
                         "затем нажми «Проверить»."},
}
CODEX_AUTH = ["-c", 'forced_login_method="chatgpt"']


def _env(extra=None):
    """Окружение без ключей API: иначе программа тихо перейдёт на оплату по API вместо подписки."""
    drop = {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL"}
    env = {k: v for k, v in os.environ.items() if k.upper() not in drop}
    env.update(extra or {})
    return env


def _run(args, timeout=STATUS_TIMEOUT, cwd=None):
    p = subprocess.run(args, capture_output=True, timeout=timeout, cwd=cwd or tempfile.gettempdir(), env=_env(),
                       creationflags=NO_WINDOW, stdin=subprocess.DEVNULL)
    dec = lambda b: (b or b"").decode("utf-8", "replace")
    return p.returncode, dec(p.stdout), dec(p.stderr)


# ---------------------------------------------------------------- вход в аккаунт

def status(provider):
    """{installed, connected, method, message} — установлена ли программа и вошли ли в неё через подписку."""
    c = CLI[provider]
    exe = c["find"]()
    if not exe:
        return {"installed": False, "connected": False, "method": None, "message": c["missing"], "get": c["get"]}
    try:
        if provider == "claude_code":
            code, out, _ = _run([exe, "auth", "status", "--json"])
            st = json.loads(out[out.index("{"):out.rindex("}") + 1])
            method = str(st.get("authMethod") or "")
            if not st.get("loggedIn"):
                return {"installed": True, "connected": False, "method": None, "message": "Войди в аккаунт Claude — кнопка «Войти»."}
            api = bool(re.search(r"(?i)api|console", method))
            return {"installed": True, "connected": True, "method": "api" if api else "subscription",
                    "message": "Claude Code вошёл по API-ключу: запросы оплачиваются по тарифу API, а не подпиской." if api
                    else "Аккаунт Claude подключён — запросы идут в лимиты твоей подписки."}
        code, out, err = _run([exe, "login", "status", *CODEX_AUTH])
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", out + err)
        chatgpt = re.search(r"(?i)logged in (using|with|via) (a )?chatgpt", text)
        api = re.search(r"(?i)logged in (using|with|via) (an? )?api[ -]?key", text)
        if code == 0 and chatgpt:
            return {"installed": True, "connected": True, "method": "subscription",
                    "message": "Аккаунт ChatGPT подключён — запросы идут в лимиты твоей подписки."}
        return {"installed": True, "connected": False, "method": "api" if api else None,
                "message": "Codex вошёл по API-ключу — войди через аккаунт ChatGPT кнопкой «Войти»." if api else "Войди в аккаунт ChatGPT — кнопка «Войти»."}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"installed": True, "connected": False, "method": None,
                "message": f"Не удалось проверить вход в {c['name']} — обнови программу и нажми «Проверить»."}


_LOGIN = {}


def login(provider):
    """Открыть вход в браузере (окно программы). Ждём до 5 минут в фоне; окно ScanHub опрашивает status()."""
    c = CLI[provider]
    exe = c["find"]()
    if not exe:
        raise AgentError(c["missing"])
    if _LOGIN.get(provider) and _LOGIN[provider].poll() is None:
        return {"started": True}
    args = [exe, "auth", "login", "--claudeai"] if provider == "claude_code" else [exe, "login", *CODEX_AUTH]
    # своё окно консоли: там видна ссылка, если браузер не открылся сам
    _LOGIN[provider] = subprocess.Popen(args, cwd=tempfile.gettempdir(), env=_env(), creationflags=subprocess.CREATE_NEW_CONSOLE)
    threading.Timer(300, lambda p=_LOGIN[provider]: p.poll() is None and p.kill()).start()
    return {"started": True}


# ---------------------------------------------------------------- один ответ агента

def _mcp(url, job, key):
    pyw = sys.executable.replace("python.exe", "pythonw.exe")
    if not os.path.exists(pyw):
        pyw = sys.executable
    return {"command": pyw, "args": [os.path.join(ROOT, "mcp_server.py")],
            "env": {"SCANHUB_URL": url, "SCANHUB_JOB": job, "SCANHUB_AGENT_KEY": key, "PYTHONIOENCODING": "utf-8"}}


def _toml(v):
    return json.dumps(v, ensure_ascii=False)


def run(provider, *, system, prompt, model, url, job, key, stop=lambda: False, timeout=900, max_turns=30):
    """Запустить агента на один ответ. Возвращает текст ответа. stop() — человек нажал «Остановить»."""
    c = CLI[provider]
    exe = c["find"]()
    if not exe:
        raise AgentError(c["missing"])
    st = status(provider)
    if not st["connected"]:
        raise AgentError(st["message"])
    scratch = tempfile.mkdtemp(prefix="scanhub-agent-")       # пустая рабочая папка: агенту нечего там читать
    mcp = _mcp(url, job, key)
    try:
        if provider == "claude_code":
            args = [exe, "-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose",
                    "--system-prompt", system, "--tools", "", "--mcp-config", json.dumps({"mcpServers": {"scanhub": mcp}}),
                    "--strict-mcp-config", "--allowedTools", "mcp__scanhub", "--no-session-persistence", "--setting-sources", "",
                    "--max-turns", str(max_turns)] + ([] if model in ("", "auto") else ["--model", model])
            stdin = json.dumps({"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": prompt}]}}) + "\n"
        else:
            answer = os.path.join(scratch, "answer.txt")
            srv = ("{" + f"command = {_toml(mcp['command'])}, args = {_toml(mcp['args'])}, "
                   f"env = {{ {', '.join(f'{k} = {_toml(v)}' for k, v in mcp['env'].items())} }}, "
                   "startup_timeout_sec = 30, tool_timeout_sec = 900" + "}")
            args = [exe, "exec", *CODEX_AUTH, "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only",
                    "--ignore-user-config", "--ignore-rules", "--color", "never", "--output-last-message", answer,
                    "-c", 'approval_policy="never"', "-c", 'web_search="disabled"', "-c", "project_doc_max_bytes=0",
                    "-c", f"mcp_servers={{ scanhub = {srv} }}",
                    "-c", "features.shell_tool=false", "-c", "features.unified_exec=false", "-c", "features.apps=false",
                    "-c", "features.multi_agent=false", "-c", "features.hooks=false", "-c", "features.memories=false",
                    "-c", "features.plugins=false", "-c", "features.remote_plugin=false", "-c", "features.browser_use=false",
                    "-c", "features.computer_use=false"] + ([] if model in ("", "auto") else ["--model", model]) + ["--", "-"]
            stdin = system + "\n\n---\n\n" + prompt
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=scratch,
                             env=_env(), creationflags=NO_WINDOW)
        out = []
        threading.Thread(target=lambda: out.append(p.stdout.read(MAX_OUT)), daemon=True).start()
        threading.Thread(target=lambda: p.stderr.read(), daemon=True).start()     # диагностику с данными аккаунта не храним
        try:
            p.stdin.write(stdin.encode("utf-8"))
            p.stdin.close()
        except OSError:
            pass
        t0 = time.time()
        while p.poll() is None:
            if stop() or time.time() - t0 > timeout:
                subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True, creationflags=NO_WINDOW)
                raise AgentError("остановлено" if stop() else f"{c['name']} не ответил за {timeout // 60} мин")
            time.sleep(0.3)
        time.sleep(0.2)
        text = (out[0] if out else b"").decode("utf-8", "replace")
        if provider == "claude_code":
            return _claude_result(text)
        try:
            ans = open(answer, encoding="utf-8").read().strip()
        except OSError:
            ans = ""
        if p.returncode != 0 or not ans:
            raise AgentError("ChatGPT не завершил ответ — проверь вход, лимиты подписки и выбранную модель.")
        return ans
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _claude_result(output):
    res = None
    for line in output.splitlines():
        if line.strip().startswith("{"):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("type") == "result":
                res = e
    if not res:
        raise AgentError("Claude не вернул ответ — повтори вопрос.")
    text = (res.get("result") or "").strip() if isinstance(res.get("result"), str) else ""
    if res.get("is_error") or res.get("subtype") != "success":
        if re.search(r"(?i)log ?in|auth|credential|401|403", text):
            raise AgentError("Claude Code не вошёл в аккаунт — войди в настройках помощника.")
        if re.search(r"(?i)limit|usage|quota|429", text):
            raise AgentError("Лимит подписки Claude на сейчас исчерпан — попробуй позже или выбери другую модель.")
        if res.get("subtype") == "error_max_turns":
            raise AgentError("Агент сделал слишком много шагов и не закончил — спроси точнее.")
        raise AgentError("Claude не закончил ответ" + (f": {text[:200]}" if text else " — повтори вопрос."))
    if not text:
        raise AgentError("Claude вернул пустой ответ — повтори вопрос.")
    return text
