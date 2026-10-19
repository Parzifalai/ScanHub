"""Растровые значки ScanHub из мастер-SVG: PNG нужных размеров и scanhub.ico (16–256, PNG внутри — Windows Vista+).
16–48 px — упрощённый знак (без тонкой окантовки), 64+ — основной. Запуск после build_logo.py."""
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FINAL = os.path.join(HERE, "final")
OUT = os.path.join(FINAL, "icons")
RENDER = r"C:\Users\marseel\.claude\skills\logo-design\scripts\render_png.py"
os.makedirs(OUT, exist_ok=True)
SMALL, BIG = os.path.join(FINAL, "scanhub-symbol-small.svg"), os.path.join(FINAL, "scanhub-symbol.svg")
ICO_SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
PNG_SIZES = sorted(set(ICO_SIZES + [180, 192, 512, 1024]))


def render(src, size, dst):
    subprocess.run([sys.executable, "-X", "utf8", RENDER, src, "-o", dst, "--size", str(size)], check=True, capture_output=True)


pngs = {}
for s in PNG_SIZES:
    dst = os.path.join(OUT, f"scanhub-{s}.png")
    render(SMALL if s <= 48 else BIG, s, dst)
    pngs[s] = dst
    print("png", s)

# .ico: заголовок + записи + PNG-данные
data = [open(pngs[s], "rb").read() for s in ICO_SIZES]
head = struct.pack("<HHH", 0, 1, len(ICO_SIZES))
off = 6 + 16 * len(ICO_SIZES)
entries = b""
for s, d in zip(ICO_SIZES, data):
    entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(d), off)
    off += len(d)
with open(os.path.join(OUT, "scanhub.ico"), "wb") as f:
    f.write(head + entries + b"".join(data))
print("ico", os.path.getsize(os.path.join(OUT, "scanhub.ico")), "bytes")
