"""Запускается ВСТРОЕННЫМ Python портативной сборки: поднимает её сервер на 8796 и открывает страницу."""
import http.server
import os
import threading
import time
import urllib.request

import scanhub

scanhub.PORT = 8796
threading.Thread(target=lambda: http.server.ThreadingHTTPServer((scanhub.HOST, 8796), scanhub.Handler).serve_forever(),
                 daemon=True).start()
time.sleep(1)
print("hello:", urllib.request.urlopen("http://127.0.0.1:8796/api/hello").read().decode())
html = urllib.request.urlopen("http://127.0.0.1:8796/").read().decode()
print("страница:", len(html), "байт, токен подставлен:", "__TOKEN__" not in html)
print("модули ScanHub из:", os.path.dirname(scanhub.__file__))
print("папка data создана:", os.path.isdir(os.path.join(os.path.dirname(scanhub.__file__), "data")))
