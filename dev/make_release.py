"""Архив для GitHub Releases: только то, что публикуется (как в .gitignore), внутри — папка ScanHub."""
import os
import sys
import zipfile
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # папка ScanHub (dev лежит внутри)

SRC = ROOT_DIR
OUT_DIR = os.path.join(os.path.dirname(ROOT_DIR), "ScanHub-release")
sys.path.insert(0, SRC)
VERSION = next(l.split('"')[1] for l in open(os.path.join(SRC, "scanhub.py"), encoding="utf-8") if l.startswith("VERSION = "))
SKIP_DIRS = {"data", "apps", "_backup", "__pycache__", ".git", "dev", ".github"}
SKIP_EXT = (".pyc", ".lock", ".tmp", ".log")

os.makedirs(OUT_DIR, exist_ok=True)
out = os.path.join(OUT_DIR, f"ScanHub-{VERSION}.zip")
n = 0
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for root, dirs, files in os.walk(SRC):
        rel = os.path.relpath(root, SRC)
        dirs[:] = [d for d in dirs if not (rel == "." and d in SKIP_DIRS) and d != "__pycache__"]
        for f in files:
            if f.endswith(SKIP_EXT):
                continue
            p = os.path.join(root, f)
            z.write(p, os.path.join("ScanHub", os.path.relpath(p, SRC)))
            n += 1
print(out, n, "files", round(os.path.getsize(out) / 2 ** 20, 2), "MB")
