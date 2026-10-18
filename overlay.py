"""Окошко FPS поверх игры. Запускается ScanHub (fps.py) отдельным процессом и читает data\\fps\\overlay.json раз в полсекунды.

Всегда сверху, мышь проходит насквозь (не мешает кликать в игре), фокус не забирает, в панели задач не видно.
Закрывается само, когда в overlay.json приходит stop или данные перестают обновляться дольше 6 секунд (ScanHub закрыли).
Видно поверх игр в режиме «оконный без рамки»; в «эксклюзивном полноэкранном» режиме Windows рисует игру поверх всего.
"""
import ctypes
import json
import os
import sys
import time
import tkinter as tk

PATH = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "fps", "overlay.json")
KEY = "#010203"                      # этот цвет Windows делает прозрачным
BG, FG, DIM = "#101418", "#e8edf3", "#93a1b3"
GOOD, MID, BAD = "#4ade80", "#facc15", "#f87171"


def near(color):
    """Цвет на единицу отличается от цвета цифр — его Windows делает прозрачным. Сглаженные края цифр смешиваются
    с почти тем же цветом, поэтому вокруг цифр нет тёмной каймы (с чёрным ключом она была бы)."""
    r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
    return f"#{r:02x}{g:02x}{b + 1 if b < 255 else b - 1:02x}"


def click_through(win):
    hwnd = ctypes.windll.user32.GetParent(win.winfo_id()) or win.winfo_id()
    GWL_EXSTYLE, WS_EX_LAYERED, WS_EX_TRANSPARENT, WS_EX_TOOLWINDOW, WS_EX_NOACTIVATE = -20, 0x80000, 0x20, 0x80, 0x08000000
    st = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
    ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, st | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE)


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass
    root = tk.Tk()
    root.overrideredirect(True)
    root.attributes("-topmost", True)
    root.attributes("-alpha", 0.92)
    root.configure(bg=KEY)
    root.attributes("-transparentcolor", KEY)
    box = tk.Frame(root, bg=BG, padx=10, pady=4)
    box.pack()
    fps = tk.Label(box, text="—", font=("Bahnschrift SemiBold", 22), fg=GOOD, bg=BG)
    fps.grid(row=0, column=0, rowspan=2, sticky="w", padx=(0, 8))
    l1 = tk.Label(box, text="FPS", font=("Segoe UI", 9), fg=DIM, bg=BG, anchor="w")
    l1.grid(row=0, column=1, sticky="w")
    l2 = tk.Label(box, text="", font=("Segoe UI", 9), fg=FG, bg=BG, anchor="w")
    l2.grid(row=1, column=1, sticky="w")
    root.update_idletasks()
    click_through(root)
    state = {"corner": None, "seen": time.time()}

    def place(corner):
        root.update_idletasks()
        w, h = root.winfo_reqwidth(), root.winfo_reqheight()
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        x = 16 if corner in ("tl", "bl") else sw - w - 16
        y = 16 if corner in ("tl", "tr") else sh - h - 60
        root.geometry(f"+{x}+{y}")

    def tick():
        try:
            d = json.load(open(PATH, encoding="utf-8"))
        except (OSError, ValueError):
            d = None
        now = time.time()
        if d and d.get("stop"):
            return root.destroy()
        if d and now - d.get("t", 0) < 6:
            state["seen"] = now
            f = d.get("fps")
            minimal = d.get("minimal", True)          # «только FPS»: одни цифры, без подписей
            for w in (l1, l2):
                if minimal:
                    w.grid_remove()
                else:
                    w.grid()
            fps.grid_configure(padx=(0, 0) if minimal else (0, 8))
            box.configure(padx=0 if minimal else 10, pady=0 if minimal else 4)
            if d.get("status") == "uac":
                fps.config(text="…", fg=DIM)
                l1.config(text="ScanHub: подтверди окно UAC")
                l2.config(text="")
            elif f is None:
                fps.config(text="—", fg=DIM)
                l1.config(text="FPS · жду игру")
                l2.config(text="")
            else:
                fps.config(text=str(f), fg=GOOD if f >= 55 else MID if f >= 30 else BAD)
                low = d.get("low")
                l1.config(text=f"FPS · {d.get('app') or ''}"[:34] + (f" · просадки до {low}" if low else ""))
                parts = []
                if d.get("gpu_temp") is not None:
                    parts.append(f"GPU {d['gpu_temp']:.0f}°C" + (f" {d['gpu_w']:.0f} Вт" if d.get("gpu_w") is not None else ""))
                if d.get("cpu_temp"):
                    parts.append(f"CPU {d['cpu_temp']:.0f}°C")
                l2.config(text="  ·  ".join(parts))
            # «только FPS» — одни цифры: без подложки, без рамки и без каймы
            col = fps.cget("fg")
            bg = near(col) if minimal else BG
            if state.get("bg") != bg:
                state["bg"] = bg
                root.attributes("-alpha", 1.0 if minimal else 0.92)
                root.configure(bg=bg if minimal else KEY)
                root.attributes("-transparentcolor", bg if minimal else KEY)
                for w in (box, fps, l1, l2):
                    w.configure(bg=bg)
            if d.get("corner") != state["corner"]:
                state["corner"] = d.get("corner")
                place(state["corner"] or "tl")
            else:
                place(state["corner"] or "tl")
            root.attributes("-topmost", True)        # игры иногда поднимают своё окно — возвращаемся наверх
        elif now - state["seen"] > 6:
            return root.destroy()
        root.after(500, tick)

    tick()
    root.mainloop()


if __name__ == "__main__":
    main()
