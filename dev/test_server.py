"""Копия сервера ScanHub на порту 8799 для проверки правок: без автообновлений, без окна, рабочий ScanHub (8765) не трогает."""
import http.server
import sys

import os
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # папка ScanHub (dev лежит внутри)
sys.path.insert(0, ROOT_DIR)
import scanhub

scanhub.PORT = 8799
server = scanhub.Server((scanhub.HOST, scanhub.PORT), scanhub.Handler)
print("test ScanHub on http://127.0.0.1:8799/", flush=True)
server.serve_forever()
