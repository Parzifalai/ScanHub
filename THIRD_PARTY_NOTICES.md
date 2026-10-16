# Сторонние программы, базы и сервисы

ScanHub **не содержит и не распространяет** перечисленное ниже. Программы и базы скачиваются на компьютере пользователя с официальных источников, когда он сам нажимает «Установить» / «Скачать» или запускает проверку; сервисы вызываются по их публичным API. Всё остаётся под лицензиями и условиями своих авторов — ими нужно руководствоваться при использовании.

## Программы (скачиваются с официальных сайтов)

| Программа | Источник | Лицензия |
|---|---|---|
| ClamAV | github.com/Cisco-Talos/clamav | GPL-2.0 |
| Atomdrift Scan | github.com/atomdrift-project/scan | Apache-2.0 |
| HollowsHunter | github.com/hasherezade/hollows_hunter | BSD-2-Clause |
| capa | github.com/mandiant/capa | Apache-2.0 |
| Chainsaw | github.com/WithSecureLabs/chainsaw | GPL-3.0 |
| Hayabusa | github.com/Yamato-Security/hayabusa | AGPL-3.0 |
| TruffleHog | github.com/trufflesecurity/trufflehog | AGPL-3.0 |
| witr | github.com/pranshuparmar/witr | Apache-2.0 |
| NtWarden | github.com/mrT4ntr4/NtWarden | MIT |
| MinerSearch | github.com/BlendLog/MinerSearch | лицензия автора |
| HiJackThis+ | dragokas.com / github.com/dragokas/hijackthis | лицензия автора |
| Sysinternals Autoruns, Sigcheck | Microsoft | условия Sysinternals |
| Microsoft Safety Scanner | Microsoft | условия Microsoft |
| Kaspersky Virus Removal Tool | Kaspersky | лицензионное соглашение Kaspersky |
| Dr.Web CureIt! | Doctor Web | бесплатно для домашнего использования, лицензия Dr.Web |
| ESET Online Scanner | ESET | условия ESET |
| Emsisoft Emergency Kit | Emsisoft | лицензия Emsisoft |
| Malwarebytes, AdwCleaner | Malwarebytes | условия Malwarebytes |
| yara-x (pip) | github.com/VirusTotal/yara-x | BSD-3-Clause |
| psutil (pip) | github.com/giampaolo/psutil | BSD-3-Clause |
| anthropic (pip, официальный пакет Claude API) и его зависимости (httpx2, pydantic, anyio и др.) | github.com/anthropics/anthropic-sdk-python | MIT (зависимости — MIT / BSD / Apache-2.0) |
| Claude Code, Codex — не входят в ScanHub: запускаются, если человек сам их установил | claude.ai, developers.openai.com/codex | условия Anthropic и OpenAI |

## Базы и правила (скачиваются на компьютер пользователя)

| База | Источник | Лицензия |
|---|---|---|
| Правила YARA Forge | github.com/YARAHQ/yara-forge | GPL-3.0 (сборка; у отдельных правил — лицензии их авторов) |
| Правила Elastic Security | github.com/elastic/protections-artifacts | Elastic License 2.0 |
| Maltrail Trails | github.com/stamparm/trails | Maltrail Trails Community Data License 1.0 — бесплатно для защиты своих систем, исследований и обучения; встраивание в продукт или сервис для третьих лиц требует письменного разрешения авторов. Поэтому ScanHub скачивает базы только после того, как пользователь сам нажмёт «Скачать базы» для своего компьютера |
| FMHY Filterlist | github.com/fmhy/FMHYFilterlist | GPL-3.0 |
| LOLDrivers | loldrivers.io / github.com/magicsword-io/LOLDrivers | Apache-2.0 |
| MalExt Sentry | github.com/toborrm9/malicious_extension_sentry | MIT |
| NoCoin adblock list | github.com/hoshsadiq/adblock-nocoin-list | MIT |

## Онлайн-сервисы (вызываются по API)

VirusTotal, Filescan.io, MetaDefender Cloud (OPSWAT), Hybrid Analysis (CrowdStrike) — по бесплатному ключу пользователя и на условиях каждого сервиса. CIRCL hashlookup (CERT Люксембурга) и OSV.dev (Google) — публичные API без ключа.

## Благодарности

Набор функций очистки, обслуживания и твиков вдохновлён программой [Kudu](https://github.com/AdventDevInc/kudu) (MIT, © 2026 Advent Development Inc). Код ScanHub написан отдельно, на Python.
