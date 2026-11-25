"""Напечатать ответы в консоль чужой программы, как будто их набрали на клавиатуре.

Запуск: python contype.py <pid> <ответ1\nответ2…>. Нужен отдельный процесс без своей консоли (DETACHED_PROCESS):
подключиться к чужой консоли (AttachConsole) можно, только если своей нет. Ввод программе перенаправлять нельзя —
тогда .NET Framework не узнаёт размер консоли и MinerSearch падает с «Неверный дескриптор».
"""
import ctypes
import sys
import time
from ctypes import wintypes

k = ctypes.windll.kernel32
k.CreateFileW.restype = wintypes.HANDLE


class KEY(ctypes.Structure):
    _fields_ = [("down", wintypes.BOOL), ("rep", wintypes.WORD), ("vk", wintypes.WORD), ("sc", wintypes.WORD),
                ("ch", wintypes.WCHAR), ("st", wintypes.DWORD)]


class REC(ctypes.Structure):
    _fields_ = [("type", wintypes.WORD), ("key", KEY)]


def main(pid, answers):
    time.sleep(1.0)
    for _ in range(20):
        if k.AttachConsole(pid):
            break
        time.sleep(0.5)
    else:
        return 1
    h = k.CreateFileW("CONIN$", 0xC0000000, 3, None, 3, 0, None)
    recs = []
    for ch in "\r".join(answers) + "\r":
        for down in (1, 0):
            recs.append(REC(1, KEY(down, 1, 0x0D if ch == "\r" else 0, 0, ch, 0)))
    n = wintypes.DWORD()
    ok = k.WriteConsoleInputW(h, (REC * len(recs))(*recs), len(recs), ctypes.byref(n))
    k.CloseHandle(h)
    k.FreeConsole()
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]), sys.argv[2].split("\n")))
