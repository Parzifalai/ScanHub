"""Портативный ScanHub: распаковал и запустил, Python ставить не нужно.

Внутри архива — папка ScanHub с python\\ (официальная портативная сборка Python с python.org той же версии,
что и у разработчика) + пакеты из requirements.txt + tkinter (окно выбора файла) из установленного Python.
Результат: ..\\ScanHub-release\\ScanHub-<версия>-portable.zip
"""
import glob
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # папка ScanHub (dev лежит внутри)

SRC = ROOT_DIR
OUT = os.path.join(os.path.dirname(ROOT_DIR), "ScanHub-release")
CACHE = os.path.join(OUT, "cache")
BUILD = os.path.join(OUT, "build")
PYVER = "%d.%d.%d" % sys.version_info[:3]
PYTAG = "python%d%d" % sys.version_info[:2]
BASE = sys.base_prefix
VERSION = next(l.split('"')[1] for l in open(os.path.join(SRC, "scanhub.py"), encoding="utf-8") if l.startswith("VERSION = "))
SKIP_DIRS = {"data", "apps", "_backup", "__pycache__", ".git", "dev", ".github"}
SKIP_EXT = (".pyc", ".lock", ".tmp", ".log")


def step(t):
    print("·", t, flush=True)


def main():
    os.makedirs(CACHE, exist_ok=True)
    emb = os.path.join(CACHE, f"python-{PYVER}-embed-amd64.zip")
    if not os.path.exists(emb):
        url = f"https://www.python.org/ftp/python/{PYVER}/python-{PYVER}-embed-amd64.zip"
        step(f"скачиваю {url}")
        urllib.request.urlretrieve(url, emb + ".part")
        os.replace(emb + ".part", emb)
    shutil.rmtree(BUILD, ignore_errors=True)
    app = os.path.join(BUILD, "ScanHub")
    py = os.path.join(app, "python")
    step("копирую ScanHub")
    for root, dirs, files in os.walk(SRC):
        rel = os.path.relpath(root, SRC)
        dirs[:] = [d for d in dirs if not (rel == "." and d in SKIP_DIRS) and d != "__pycache__"]
        for f in files:
            if not f.endswith(SKIP_EXT):
                dst = os.path.join(app, rel, f)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(os.path.join(root, f), dst)
    step(f"распаковываю Python {PYVER}")
    with zipfile.ZipFile(emb) as z:
        z.extractall(py)
    step("ставлю пакеты из requirements.txt")
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--no-compile",
                    "--target", os.path.join(py, "Lib", "site-packages"), "-r", os.path.join(SRC, "requirements.txt")], check=True)
    step("добавляю tkinter (окно выбора файла и папки)")
    shutil.copytree(os.path.join(BASE, "Lib", "tkinter"), os.path.join(py, "Lib", "tkinter"),
                    ignore=shutil.ignore_patterns("__pycache__", "test*"))
    for dll in ("_tkinter.pyd", "tcl*.dll", "tk*.dll", "libtommath.dll", "zlib1.dll"):
        for f in glob.glob(os.path.join(BASE, "DLLs", dll)):
            shutil.copy2(f, py)
    shutil.copytree(os.path.join(BASE, "tcl"), os.path.join(py, "tcl"), ignore=shutil.ignore_patterns("*.lib", "*.sh", "nmake"))
    step("настраиваю пути Python")
    # ._pth: стандартная библиотека из zip, Lib (tkinter), Lib\site-packages и папка ScanHub (..) — модули ScanHub
    with open(os.path.join(py, f"{PYTAG}._pth"), "w", encoding="utf-8") as f:
        f.write(f"{PYTAG}.zip\n.\nLib\nLib\\site-packages\n..\nimport site\n")
    # ScanHub.exe из папки ScanHub сам выбирает python\pythonw.exe, если он лежит рядом
    out = os.path.join(OUT, "ScanHub-Windows.zip")      # постоянное имя: ссылка releases/latest/download/ScanHub-Windows.zip не меняется
    step("упаковываю")
    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for root, dirs, files in os.walk(app):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in files:
                p = os.path.join(root, f)
                z.write(p, os.path.join("ScanHub", os.path.relpath(p, app)))
                n += 1
    print(out, n, "files", round(os.path.getsize(out) / 2 ** 20, 1), "MB")


if __name__ == "__main__":
    main()
