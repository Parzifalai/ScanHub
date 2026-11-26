# Code signing policy

Free code signing provided by [SignPath.io](https://signpath.io), certificate by [SignPath Foundation](https://signpath.org).

## What is signed

Only `ScanHub.exe`, the launcher built from [`launcher/`](launcher/) by the GitHub Actions workflow [`.github/workflows/build.yml`](.github/workflows/build.yml). Release archives are produced by that workflow only. The bundled Python runtime is the official python.org build and is already signed by the Python Software Foundation; WebView2 libraries in `window/` are Microsoft's redistributable binaries signed by Microsoft. Third-party scanners are not part of the release: ScanHub downloads them from their vendors' official sites on the user's request.

## Team roles

- Committers and reviewers: [Parzifalai](https://github.com/Parzifalai)
- Approvers: [Parzifalai](https://github.com/Parzifalai)

All team members use multi-factor authentication for GitHub and SignPath.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it. The one routine exception is the update check, which asks GitHub for the latest ScanHub version. What ScanHub sends, where, and when is listed in full in the README table about data (for example, file hashes for reputation lookups, scanner downloads from vendor sites, the opt-in daily usage ping and error reports, and the optional AI agent's requests to the provider the user chooses).
