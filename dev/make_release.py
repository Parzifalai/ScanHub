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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from release_files import published_files       # только файлы из git — без служебных и личных файлов рядом
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for rel in published_files(SRC):
        z.write(os.path.join(SRC, rel), os.path.join("ScanHub", rel))
        n += 1
print(out, n, "files", round(os.path.getsize(out) / 2 ** 20, 2), "MB")
