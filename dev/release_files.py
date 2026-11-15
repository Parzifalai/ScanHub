"""Какие файлы попадают в архивы выпуска: только те, что хранятся в git (как на GitHub), без папок разработки.

Раньше архивы собирались обходом всей папки — и туда попадало всё, что лежит рядом, но не в репозитории
(служебный кэш Cloudflare support\\.wrangler с названием аккаунта, временные копии ScanHub.exe и т. п.).
Список из git исключает такие вещи сам: всё, что в .gitignore или просто не добавлено, в выпуск не идёт."""
import os
import subprocess

SKIP_TOP = {"dev", ".github", "data", "apps", "_backup", "docs"}   # docs — логотипы и скриншоты для страницы GitHub, программе не нужны


def published_files(root):
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True).stdout.decode("utf-8")
    files = []
    for rel in filter(None, out.split("\0")):
        top = rel.split("/", 1)[0]
        if top in SKIP_TOP or rel.startswith(".git") or "__pycache__" in rel or rel.endswith((".pyc", ".lock", ".tmp", ".log")):
            continue
        p = os.path.join(root, rel.replace("/", os.sep))
        if os.path.isfile(p):                    # удалённый, но ещё не закоммиченный файл — пропускаем
            files.append(rel.replace("/", os.sep))
    return files
