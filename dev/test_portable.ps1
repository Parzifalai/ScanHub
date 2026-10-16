# Проверка портативной сборки: распаковать, запустить ВСТРОЕННЫМ Python без установленного (PATH очищен), открыть страницу.
$ErrorActionPreference = 'Stop'
$t = (Join-Path (Split-Path (Split-Path $PSScriptRoot)) 'ScanHub-release\test-portable')
if (Test-Path $t) { Remove-Item $t -Recurse -Force }
Expand-Archive (Join-Path (Split-Path (Split-Path $PSScriptRoot)) 'ScanHub-release\ScanHub-Windows.zip') $t
$py = "$t\ScanHub\python\python.exe"
$env:PATH = 'C:\Windows\System32;C:\Windows'          # установленного Python не видно
$env:PYTHONPATH = ''
& $py -c "import sys, psutil, yara_x, tkinter; print('python', sys.version.split()[0], sys.executable); print('psutil', psutil.__version__, '| yara-x ok | tk', tkinter.Tcl().eval('info patchlevel'))"
$env:PATH += ';C:\Windows\System32\WindowsPowerShell\v1.0'   # ScanHub зовёт PowerShell
& $py -X utf8 "$PSScriptRoot\portable_probe.py"
Remove-Item $t -Recurse -Force