"""ИИ-агенты по подписке: Claude Code (подписка Claude Pro/Max), Codex (подписка ChatGPT Plus/Pro)
и Antigravity от Google (модели Gemini Argon/Hydrogen/Flash и другие по подписке Google).

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


def find_agy():
    """agy.exe — программа Antigravity CLI (ставится в %USERPROFILE%\\.gemini\\bin) или из PATH."""
    cands = [os.path.join(os.path.expanduser("~"), ".gemini", "bin", "agy.exe")]
    cands += [os.path.join(d.strip('"'), "agy.exe") for d in os.environ.get("PATH", "").split(os.pathsep) if d.strip()]
    return next((c for c in cands if _is_file(c)), None)


CLI = {
    "claude_code": {"find": find_claude, "name": "Claude Code", "get": "https://claude.ai/download",
                    "missing": "Нужна бесплатная программа Claude Code: поставь её (claude.ai/download или «npm i -g @anthropic-ai/claude-code»), "
                               "затем нажми «Проверить»."},
    "codex": {"find": find_codex, "name": "Codex", "get": "https://developers.openai.com/codex/cli",
              "missing": "Нужна бесплатная программа Codex от OpenAI: поставь её («npm i -g @openai/codex» или с developers.openai.com/codex), "
                         "затем нажми «Проверить»."},
    "antigravity": {"find": find_agy, "name": "Antigravity", "get": "https://antigravity.google/download",
                    "missing": "Нужна бесплатная программа Antigravity от Google с командой agy: поставь её с antigravity.google, "
                               "затем нажми «Проверить»."},
}
AGY_LEVELS = ("low", "medium", "high", "xhigh", "max")
AGY_MODELS = {}                     # id → название из «agy models» (последняя удачная проверка)
CODEX_AUTH = ["-c", 'forced_login_method="chatgpt"']


def _env(extra=None):
    """Окружение без ключей API: иначе программа тихо перейдёт на оплату по API вместо подписки."""
    drop = {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL",
            "GEMINI_API_KEY", "GOOGLE_API_KEY"}
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
        if provider == "antigravity":
            return _agy_status(exe)
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


def _agy_status(exe):
    """Вход в Antigravity проверяем списком моделей: его выдаёт только вошедший аккаунт — заодно запоминаем модели подписки."""
    code, out, err = _run([exe, "models"], timeout=40)
    found = {}
    for line in out.splitlines():
        m = re.match(r"^([a-z0-9][\w.\-]*)\t(.+)$", line.strip("\r"))
        if m:
            found[m.group(1)] = m.group(2).strip()
    if found:
        AGY_MODELS.clear()
        AGY_MODELS.update(found)
        return {"installed": True, "connected": True, "method": "subscription",
                "message": f"Аккаунт Google в Antigravity подключён — запросы идут в лимиты твоей подписки. Моделей доступно: {len(found)}."}
    text = out + err
    if re.search(r"(?i)auth|log ?in|sign ?in|credential|unauthenticated", text):
        return {"installed": True, "connected": False, "method": None, "message": "Войди в Antigravity аккаунтом Google — кнопка «Войти»."}
    return {"installed": True, "connected": False, "method": None,
            "message": "Antigravity не отдал список моделей — проверь интернет и вход (кнопка «Войти»), потом нажми «Проверить»."}


def models(provider):
    """Модели подписки Antigravity: [id, …] (названия — в AGY_MODELS)."""
    if not AGY_MODELS:
        st = status(provider)
        if not st["connected"]:
            raise AgentError(st["message"])
    return list(AGY_MODELS)


_LOGIN = {}


def login(provider):
    """Открыть вход в браузере (окно программы). Ждём до 5 минут в фоне; окно ScanHub опрашивает status()."""
    c = CLI[provider]
    exe = c["find"]()
    if not exe:
        raise AgentError(c["missing"])
    if _LOGIN.get(provider) and _LOGIN[provider].poll() is None:
        return {"started": True}
    # у Antigravity нет отдельной команды входа: при первом запуске он сам открывает вход Google в браузере
    args = [exe, "auth", "login", "--claudeai"] if provider == "claude_code" else [exe] if provider == "antigravity" else [exe, "login", *CODEX_AUTH]
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


IMG_EXT = {"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp", "image/gif": ".gif"}


def _save_images(scratch, images):
    """Картинки человека → файлы image1.png… во временной папке ответа (для Codex и Antigravity)."""
    import base64
    paths = []
    for i, (mime, b64) in enumerate(images or [], 1):
        p = os.path.join(scratch, f"image{i}{IMG_EXT.get(mime, '.png')}")
        with open(p, "wb") as f:
            f.write(base64.b64decode(b64))
        paths.append(p)
    return paths


def _agy_model(model, fast):
    """«Быстро» в Antigravity: та же модель с уровнем размышления low (если он есть в подписке), иначе medium."""
    if not fast or not model or model == "auto":
        return model
    base = re.sub(r"-(low|medium|high|xhigh|max)$", "", model)
    for lvl in ("low", "medium"):
        if f"{base}-{lvl}" in AGY_MODELS:
            return f"{base}-{lvl}"
    return model


def run(provider, *, system, prompt, model, url, job, key, stop=lambda: False, timeout=900, max_turns=30, web=False, fast=False, images=()):
    """Запустить агента на один ответ. Возвращает текст ответа. stop() — человек нажал «Остановить».
    web — разрешить поиск и чтение страниц в интернете (только для вопросов; для «Сделай сам» всегда выключено).
    fast — режим «Быстро» (короткое размышление); images — [(mime, base64)] картинки к вопросу."""
    c = CLI[provider]
    exe = c["find"]()
    if not exe:
        raise AgentError(c["missing"])
    st = status(provider)
    if not st["connected"]:
        raise AgentError(st["message"])
    scratch = tempfile.mkdtemp(prefix="scanhub-agent-")       # пустая рабочая папка: агенту нечего там читать (кроме картинок человека)
    mcp = _mcp(url, job, key)
    extra_env = {}
    try:
        if provider == "antigravity":
            # Antigravity не принимает картинку в сообщении (только текст), но открывает файл из папки ответа — сторож пускает только к ним
            pics = _save_images(scratch, images)
            args = _agy_prepare(exe, scratch, system=system, model=_agy_model(model, fast), mcp=mcp, web=web, timeout=timeout, images=pics)
            if pics:
                prompt = ("Человек приложил к вопросу картинк" + ("у" if len(pics) == 1 else "и") + ": " + ", ".join(os.path.basename(p) for p in pics)
                          + " (в текущей папке). Сначала открой и посмотри " + ("её" if len(pics) == 1 else "их") + ".\n\n" + prompt)
            stdin = json.dumps({"event": "user", "message": {"role": "user", "content": [{"type": "text", "text": prompt}]}},
                               ensure_ascii=False) + "\n"
        elif provider == "claude_code":
            args = [exe, "-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose",
                    "--system-prompt", system, "--tools", "WebSearch,WebFetch" if web else "", "--mcp-config", json.dumps({"mcpServers": {"scanhub": mcp}}),
                    "--strict-mcp-config", "--allowedTools", "mcp__scanhub,WebSearch,WebFetch" if web else "mcp__scanhub",
                    "--no-session-persistence", "--setting-sources", "",
                    "--max-turns", str(max_turns)] + ([] if model in ("", "auto") else ["--model", model])
            content = [{"type": "text", "text": prompt}] + [{"type": "image", "source": {"type": "base64", "media_type": mt, "data": b}}
                                                            for mt, b in images or []]
            stdin = json.dumps({"type": "user", "message": {"role": "user", "content": content}}) + "\n"
            if fast:
                extra_env["MAX_THINKING_TOKENS"] = "2048"          # «Быстро»: короткое размышление
        else:
            answer = os.path.join(scratch, "answer.txt")
            srv = ("{" + f"command = {_toml(mcp['command'])}, args = {_toml(mcp['args'])}, "
                   f"env = {{ {', '.join(f'{k} = {_toml(v)}' for k, v in mcp['env'].items())} }}, "
                   "startup_timeout_sec = 30, tool_timeout_sec = 900" + "}")
            args = [exe, "exec", *CODEX_AUTH, "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only",
                    "--ignore-user-config", "--ignore-rules", "--color", "never", "--output-last-message", answer,
                    "-c", 'approval_policy="never"', "-c", 'web_search="live"' if web else 'web_search="disabled"', "-c", "project_doc_max_bytes=0",
                    "-c", f"mcp_servers={{ scanhub = {srv} }}",
                    "-c", "features.shell_tool=false", "-c", "features.unified_exec=false", "-c", "features.apps=false",
                    "-c", "features.multi_agent=false", "-c", "features.hooks=false", "-c", "features.memories=false",
                    "-c", "features.plugins=false", "-c", "features.remote_plugin=false", "-c", "features.browser_use=false",
                    "-c", "features.computer_use=false"] + ([] if model in ("", "auto") else ["--model", model]) \
                + (["-c", 'model_reasoning_effort="low"'] if fast else []) \
                + [x for p_ in _save_images(scratch, images) for x in ("--image", p_)] + ["--", "-"]
            stdin = system + "\n\n---\n\n" + prompt
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=scratch,
                             env=_env(extra_env), creationflags=NO_WINDOW)
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
        if provider == "antigravity":
            return _agy_result(text)
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


AGY_RULES = """

---
Как работать в ScanHub (Antigravity):
- Ответь человеку сразу текстом в этом же ответе. Не составляй планов реализации, не создавай файлов, артефактов и задач.
- Данные компьютера бери только инструментами сервера scanhub (call_mcp_tool). Командной строки, чтения файлов диска,
  браузера и правки файлов у тебя нет — ScanHub их запрещает; не пытайся, а спроси данные инструментом ScanHub.
"""


def _agy_prepare(exe, scratch, *, system, model, mcp, web, timeout, images=()):
    """Временная папка ответа = проект Antigravity с одним плагином «scanhub»: правила агента, сервер инструментов
    ScanHub и сторож (agy_gate.py), который до каждого шага разрешает только инструменты ScanHub и интернет.
    Общие настройки Antigravity пользователя не меняются."""
    plug = os.path.join(scratch, ".agents", "plugins", "scanhub")
    os.makedirs(os.path.join(plug, "rules"))
    w = lambda name, data: open(os.path.join(plug, name), "w", encoding="utf-8").write(
        data if isinstance(data, str) else json.dumps(data, ensure_ascii=False))
    w("plugin.json", {"name": "scanhub"})
    w("mcp_config.json", {"mcpServers": {"scanhub": mcp}})
    py = sys.executable.replace("pythonw.exe", "python.exe")     # сторож отвечает через stdout — нужен обычный python
    gate = f'"{py if os.path.exists(py) else sys.executable}" "{os.path.join(ROOT, "agy_gate.py")}"'
    w("hooks.json", {"scanhub-gate": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": gate, "timeout": 20}]}]}})
    w("gate.json", {"web": bool(web), "images": [os.path.abspath(p) for p in images or []]})   # 2.2: открыть можно только эти картинки
    w(os.path.join("rules", "AGENTS.md"), system + AGY_RULES)
    settings = os.path.join(scratch, "settings.json")
    open(settings, "w", encoding="utf-8").write(json.dumps({"permissions": {"allow": ["mcp(scanhub_scanhub/*)"]}}))
    args = [exe, "--input-format", "stream-json", "--output-format", "stream-json", "--mode", "plan",
            "--settings", settings, "--disable-slash-commands", "--print-timeout", f"{int(timeout)}s"]
    if model and model != "auto":
        args += ["--model", model]
    return args + ["-p="]


def _agy_forget(conv):
    """Antigravity хранит каждый разговор у себя — данные ПК там не оставляем (файлы освобождаются не сразу)."""
    if not re.fullmatch(r"[0-9a-f\-]{36}", conv or ""):
        return
    base = os.path.join(os.path.expanduser("~"), ".gemini", "antigravity-cli")

    def go():
        for _ in range(10):
            left = 0
            for p in [os.path.join(base, "brain", conv)] + [os.path.join(base, d, conv + s) for d, s in
                                                             (("conversations", ".db"), ("conversations", ".db-wal"),
                                                              ("conversations", ".db-shm"), ("presence", ".lock"))]:
                if os.path.isdir(p):
                    shutil.rmtree(p, ignore_errors=True)
                elif os.path.exists(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
                left += os.path.exists(p)
            if not left:
                return
            time.sleep(3)
    threading.Thread(target=go, daemon=True).start()


def _agy_result(output):
    res = None
    for line in output.splitlines():
        if line.strip().startswith("{"):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("event") == "result":
                res = e.get("result") or {}
    if res is None:
        raise AgentError("Antigravity не вернул ответ — проверь вход в настройках агента и повтори вопрос.")
    _agy_forget(str(res.get("conversation_id") or ""))
    text = str(res.get("response") or "").strip()
    err = str(res.get("error") or "")
    if res.get("status") != "SUCCESS":
        if re.search(r"(?i)auth|log ?in|sign ?in|credential|401|403", err):
            raise AgentError("Antigravity не вошёл в аккаунт — войди в настройках агента.")
        if re.search(r"(?i)quota|limit|exhaust|429|rate", err):
            raise AgentError("Лимит подписки Antigravity на эту модель сейчас исчерпан — попробуй позже или выбери другую модель (например, Flash).")
        if re.search(r"(?i)model", err):
            raise AgentError("Antigravity не принял выбранную модель — нажми «Найти модели» в настройках агента и выбери снова.")
        if re.search(r"(?i)time ?limit|timed? ?out|deadline", err):
            raise AgentError("Antigravity не успел ответить — спроси точнее или выбери модель побыстрее.")
        raise AgentError("Antigravity не закончил ответ" + (f": {err[:200]}" if err else " — повтори вопрос."))
    if not text:
        raise AgentError("Antigravity вернул пустой ответ — повтори вопрос.")
    return text


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
            raise AgentError("Claude Code не вошёл в аккаунт — войди в настройках агента.")
        if re.search(r"(?i)limit|usage|quota|429", text):
            raise AgentError("Лимит подписки Claude на сейчас исчерпан — попробуй позже или выбери другую модель.")
        if res.get("subtype") == "error_max_turns":
            raise AgentError("Агент сделал слишком много шагов и не закончил — спроси точнее.")
        raise AgentError("Claude не закончил ответ" + (f": {text[:200]}" if text else " — повтори вопрос."))
    if not text:
        raise AgentError("Claude вернул пустой ответ — повтори вопрос.")
    return text
