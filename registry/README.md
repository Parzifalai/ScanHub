# Как добавить сканер в ScanHub

Один инструмент — один JSON-файл в этой папке. После сохранения файла достаточно обновить окно ScanHub, перезапускать его не нужно.

```jsonc
{
  "id": "short-id",                 // латиница, уникальный
  "name": "Как показывать",
  "category": "Антивирус / Антимайнер / Supply-chain …",
  "description": "1–2 предложения: что ищет",
  "repo": "owner/name",             // GitHub, для ссылки и обновлений
  "homepage": "https://…",          // необязательно

  "source": {
    // github-release — бинарник из последнего релиза (zip / tar.gz / голый .exe)
    "type": "github-release",
    "asset": "regex по имени файла релиза под Windows x64",
    "checksums": "SHA256SUMS"       // необязательно: файл сумм в релизе; digest от GitHub проверяется всегда
    // github-source — исходники ветки (для Python/скриптов); версия = короткий sha коммита
    //   "type": "github-source", "branch": "main"
    // system — уже есть в Windows: "path": "%ProgramFiles%\\…\\x.exe", "status_ps": "PowerShell → JSON"
    // direct — файл по прямой ссылке: "url": "…/KVRT.exe", "signer": "Kaspersky" (проверка Authenticode);
    //          версия = Last-Modified на сервере
    // manual — скачивается вручную со страницы с лицензией: "page", "signer", "min_mb", "search": [папки];
    //          ScanHub ищет свежий .exe по подписи
    // service — онлайн-сервис из services.py: "service": "virustotal", "key": "virustotal_key", "signup", "key_page"
    // builtin — встроенная проверка: "builtin": "signature" (system.py) или "yara" (yarascan.py: правила YARA Forge + Elastic,
    //           движок — pip-пакет yara-x; правила в data\yara, на диске закодированы XOR, иначе Defender их удаляет)
    //           или intel.py: "netintel" (адреса вредоносов Maltrail), "origin" (сайты-источники загрузок, FMHY), "osv" (пакеты npm/pip);
    //           базы в data\intel, обновляются сами раз в сутки перед проверкой
    // "checksums" может быть шаблоном: "trufflehog_[\\d.]+_checksums\\.txt"
    // "optional": true у онлайн-сервиса — без ключа он не считается «не участвовавшим» в итоге проверки файла
    // "nokey": true у онлайн-сервиса — ключ не нужен (CIRCL hashlookup)
    // ещё встроенные из intel.py: "byovd" (уязвимые драйверы LOLDrivers, база раз в неделю), "malext" (вредоносные расширения MalExt Sentry)
    // для direct: "filename" (если в ссылке нет имени файла); zip распаковывается, подпись проверяется у exe
  },
  "needs_data": { "glob": "database\\daily.c?d", "label": "Нужно скачать базы", "mode": "update" },  // пока нет — инструмент не участвует в общих проверках
  // для builtin yara вместо glob: "builtin": "yara"
  "section": "scanners | downloadable | online | research",   // research виден только в режиме «Разработчик»
  "simple": "одна фраза человеческим языком для простого режима",
  "auto_update": false,             // по умолчанию автообновление включено
  "max_age_days": 3,                // для сканеров со встроенными базами: через сколько дней «устарел»
  "requires": [{ "path": "C:\\Windows\\System32\\Npcap\\wpcap.dll", "label": "Npcap", "url": "https://npcap.com" }],
  "setup": [["{python}", "-m", "venv", "{dir}\\.venv"]],   // необязательно: команды после распаковки
  "exe": "glob имени исполняемого файла внутри распаковки",
  "admin": false,                   // true — GUI-режимы запускать через UAC

  "exit_codes": { "0": ["clean", "Чисто"], "1": ["threat", "Вредонос"] },
  // вердикты: clean | threat | suspicious | error | launched

  "modes": [
    { "id": "path", "label": "Проверить файл или папку", "target": "path",
      "args": ["{target}"], "multi": true },          // multi — участвует в «Проверить выбранными»
    { "id": "x", "label": "…", "target": "text", "placeholder": "…", "args": ["sub", "{target}"] },
    { "id": "y", "label": "…", "target": "none", "gui": true, "args": [] }
    // "count_regex" + "count_verdict" + "zero_verdict": вердикт по числу из вывода (напр. suspicious_count в JSON)
    // target: none | path (файл или папка) | file | text | url
    // флаги режима: gui (своё окно), console (новое окно терминала), admin (UAC), upload (с подтверждением),
    //               action (для service: lookup | upload | url)
    // вместо args можно задать полный "cmd": ["{python}", "{dir}\\main.py", "{target}"]
    // подстановки: {target} {exe} {dir} {python} {data} (папка data) {registry} (эта папка — для файлов настроек сканеров)
    // "elevated_log": "HiJackThis*.log" — запустить одним окном UAC, дождаться и показать отчёт, который программа сама пишет в свою папку
    //   ("item_regex" — как считать записи отчёта)
    // "elevated": true — консольный сканер, которому нужны права администратора (Emsisoft a2cmd): одно окно UAC, вывод — в ScanHub;
    //   "pre": [["/u"]] — команды перед проверкой в том же UAC (обновление баз), "timeout", "started_text"
    // "handler": "rootcerts" — вывод разбирает intel.handle (Sigcheck → корневые сертификаты)
    // "confirm": "…?" — спросить перед запуском (офлайн-проверка Defender перезагружает ПК)
  ]
}
```

**Защита от подменённых релизов.** Перед установкой с GitHub архив и главный exe сверяются с VirusTotal (если в Настройках есть ключ). Если 5 и больше срабатываний или новый файл блокирует Defender, версия попадает в `held` (state.json) и ставится предыдущая. Кнопка «Установить всё равно» отправляет `force`.

Установленные версии лежат в `apps\<id>\<версия>` рядом со ScanHub. Предыдущая версия сохраняется для отката. Состояние хранится в `data\state.json`, история проверок — в `data\history.json`, логи — в `data\logs`.

Обновить всё без окна: `python scanhub.py --update-all` в папке ScanHub. Эту команду можно повесить на Планировщик заданий.
