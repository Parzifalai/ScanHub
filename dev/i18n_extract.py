"""Собирает русские фразы, которые может показать окно ScanHub: строки JS (включая куски шаблонов `…${x}…`),
текст и подсказки index.html, строки Python (кроме докстрингов) и тексты реестра сканеров.
Выход: i18n_todo.json — {фраза: [где встречается]} (без кода, комментариев, PowerShell и служебных строк для ИИ).
Перевод — файлы en_*.txt («номер<TAB>перевод»), их собирает i18n_build.py в ui\\en.json."""
import ast
import glob
import json
import os
import re
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # папка ScanHub (dev лежит внутри)

ROOT = ROOT_DIR
HERE = os.path.dirname(os.path.abspath(__file__))
CYR = re.compile(r"[А-Яа-яЁё]")
CODE = re.compile(r"\$\(|=>|\b(const|let|function|return|textContent|innerHTML|ConvertTo-Json|Where-Object|ForEach-Object|"
                  r"Get-[A-Z]\w+|Select-Object)\b|@\{|\[pscustomobject\]|^\s*(//|#|\$)|&\s*echo|\becho\b|\$env:|\.Substring\(|\{\s*\$")
SPLIT = re.compile(r'<[^>]*>|[<>]|="|"\s+(?=[\w-]+=)|"\s*$|^\s*"')
out = {}


def add(s, where):
    for part in re.split(r"\n+", s):
        if CODE.search(part):
            continue
        for piece in SPLIT.split(part):           # «" data-confirm="Удалить?">Удалить» → «Удалить?» и «Удалить»
            p = (piece or "").strip().strip('"').strip()
            if CYR.search(p) and len(p) <= 600 and not CODE.search(p):
                out.setdefault(p, set()).add(where)


def js_strings(src):
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and src[i + 1:i + 2] == "/":
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and src[i + 1:i + 2] == "*":
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c in "'\"":
            j, buf = i + 1, []
            while j < n and src[j] != c and src[j] != "\n":
                if src[j] == "\\":
                    buf.append(src[j:j + 2])
                    j += 2
                    continue
                buf.append(src[j])
                j += 1
            yield "".join(buf)
            i = j + 1
            continue
        if c == "`":
            j, buf, pieces = i + 1, [], []
            while j < n:
                if src[j] == "\\":
                    buf.append(src[j:j + 2])
                    j += 2
                    continue
                if src[j] == "`":
                    break
                if src[j:j + 2] == "${":
                    pieces.append("".join(buf))
                    buf, depth, k, inner = [], 1, j + 2, []
                    while k < n and depth:
                        if src[k] == "{":
                            depth += 1
                        elif src[k] == "}":
                            depth -= 1
                        if depth:
                            inner.append(src[k])
                        k += 1
                    yield from js_strings("".join(inner))
                    j = k
                    continue
                buf.append(src[j])
                j += 1
            pieces.append("".join(buf))
            yield from pieces
            i = j + 1
            continue
        i += 1


for f in glob.glob(os.path.join(ROOT, "ui", "*.js")):
    if f.endswith("i18n.js"):
        continue
    for s in js_strings(open(f, encoding="utf-8").read()):
        add(s.replace("\\n", "\n"), os.path.basename(f))
html = open(os.path.join(ROOT, "ui", "index.html"), encoding="utf-8").read()
html = re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>|<!--[\s\S]*?-->", "", html)
add(html, "index.html")
for a in re.findall(r'(?:title|placeholder|aria-label|data-confirm)="([^"]*)"', html):
    add(a, "index.html")
for f in glob.glob(os.path.join(ROOT, "*.py")):
    if os.path.basename(f) in ("assistant.py",):          # промпты и поля для ИИ — человек их не видит
        tree = ast.parse(open(f, encoding="utf-8").read())
        # но из assistant.py в окно попадают ошибки (AIError) и подписи провайдеров/доступа к файлам
        keep_names = {"AIError", "PROVIDERS", "FILE_MODE_TEXT", "BUTTONS", "STEP_TEXT", "PermissionError", "RuntimeError"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") in keep_names:
                for a in ast.walk(node):
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        add(a.value, "assistant.py")
            if isinstance(node, ast.Assign) and any(getattr(t, "id", "") in keep_names for t in node.targets):
                for a in ast.walk(node.value):
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        add(a.value, "assistant.py")
        continue
    tree = ast.parse(open(f, encoding="utf-8").read())
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)) and node.body \
                and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant):
            docs.add(id(node.body[0].value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
            v = node.value
            if re.fullmatch(r"\w+", v) and "_" in v:              # ключи вроде «сбои_итог»
                continue
            if re.search(r"\\[dswbS]|\(\?[:<!=]|\[\^", v):          # регулярные выражения
                continue
            add(v, os.path.basename(f))


def walk(x):
    if isinstance(x, str):
        add(x, "registry")
    elif isinstance(x, dict):
        for k, v in x.items():
            if k not in ("url", "page", "homepage", "args", "glob", "path", "exe", "id"):
                walk(v)
    elif isinstance(x, list):
        for v in x:
            walk(v)


for f in glob.glob(os.path.join(ROOT, "registry", "*.json")):
    walk(json.load(open(f, encoding="utf-8")))

res = {k: sorted(v) for k, v in sorted(out.items())}
json.dump(res, open(os.path.join(HERE, "i18n_todo.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=0)
print("фраз:", len(res), "символов:", sum(len(k) for k in res))
