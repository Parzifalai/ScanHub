🇷🇺 [Русская версия](THIRD_PARTY_NOTICES.ru.md)

# Third-party programs, databases and services

Third-party programs, rules, datasets and services that ScanHub downloads or calls at the user's request are NOT part of the "Software" and are not covered by the MIT license in the LICENSE file. They remain under their own licenses and terms.

Apart from the WebView2 libraries (first section), ScanHub **does not contain or distribute** anything listed below. Programs and databases are downloaded onto the user's computer from official sources when the user clicks "Install" / "Download" or starts a scan; services are called through their public APIs. Everything remains under the licenses and terms of its authors, and those terms apply when you use it.

## Included in ScanHub

- **Microsoft WebView2 SDK** 1.0.4314.35 (Microsoft.Web.WebView2.Core.dll, Microsoft.Web.WebView2.WinForms.dll, WebView2Loader.dll in the `window` folder) — © Microsoft Corporation, BSD-3-Clause license (`window/LICENSE-WebView2.txt`). It gives the ScanHub window a frame without the Edge chrome; the WebView2 engine itself is part of Windows.
- **Roomy** (github.com/krezio/roomy) — © 2026 krezio, MIT license. ScanHub contains no Roomy code, but its cleanup reuses Roomy's list of cache locations (Chromium-browser GPU and shader caches, Brave, Vivaldi, Slack, Discord PTB/Canary, blue-screen dumps), its rules for old installers, big untouched downloads and unplayed Steam games, and its safety rules (never follow junctions, hard-blocked personal and system folders), rewritten in Python. License: https://github.com/krezio/roomy/blob/main/LICENSE

## Programs (downloaded from official sites)

| Program | Source | License |
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
| MinerSearch | github.com/BlendLog/MinerSearch | author's license |
| HiJackThis+ | dragokas.com / github.com/dragokas/hijackthis | author's license |
| Sysinternals Autoruns, Sigcheck | Microsoft | Sysinternals terms |
| Microsoft Safety Scanner | Microsoft | Microsoft terms |
| Kaspersky Virus Removal Tool | Kaspersky | Kaspersky license agreement |
| Dr.Web CureIt! | Doctor Web | free for home use, Dr.Web license |
| ESET Online Scanner | ESET | ESET terms |
| Emsisoft Emergency Kit | Emsisoft | Emsisoft license |
| Malwarebytes, AdwCleaner | Malwarebytes | Malwarebytes terms |
| yara-x (pip) | github.com/VirusTotal/yara-x | BSD-3-Clause |
| psutil (pip) | github.com/giampaolo/psutil | BSD-3-Clause |
| anthropic (pip, the official Claude API package) and its dependencies (httpx2, pydantic, anyio, etc.) | github.com/anthropics/anthropic-sdk-python | MIT (dependencies: MIT / BSD / Apache-2.0) |
| Claude Code, Codex — not part of ScanHub: launched only if the user has installed them | claude.ai, developers.openai.com/codex | Anthropic and OpenAI terms |

## Databases and rules (downloaded to the user's computer)

| Database | Source | License |
|---|---|---|
| YARA Forge rules | github.com/YARAHQ/yara-forge | GPL-3.0 (the bundle; individual rules carry their authors' licenses) |
| Elastic Security rules | github.com/elastic/protections-artifacts | Elastic License 2.0 |
| Maltrail Trails | github.com/stamparm/trails | Maltrail Trails Community Data License 1.0 — free for protecting your own systems, research and education; embedding in a product or service for third parties requires written permission from the authors. For this reason ScanHub downloads these databases only after the user clicks "Download databases" for their own computer |
| FMHY Filterlist | github.com/fmhy/FMHYFilterlist | GPL-3.0 |
| LOLDrivers | loldrivers.io / github.com/magicsword-io/LOLDrivers | Apache-2.0 |
| MalExt Sentry | github.com/toborrm9/malicious_extension_sentry | MIT |
| NoCoin adblock list | github.com/hoshsadiq/adblock-nocoin-list | MIT |

## Online services (called through APIs)

VirusTotal, Filescan.io, MetaDefender Cloud (OPSWAT), Hybrid Analysis (CrowdStrike) — using the user's own free key and under each service's terms. CIRCL hashlookup (CERT Luxembourg) and OSV.dev (Google) — public APIs, no key required.

## Acknowledgments

The set of cleanup, maintenance and tweak features is inspired by [Kudu](https://github.com/AdventDevInc/kudu) (MIT, © 2026 Advent Development Inc). ScanHub's code is written separately, in Python.
