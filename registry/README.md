🇷🇺 [Русская версия](README.ru.md)

# How to add a scanner to ScanHub

One tool is one JSON file in this folder. After you save the file, just refresh the ScanHub window; no restart is needed.

```jsonc
{
  "id": "short-id",                 // Latin letters, unique
  "name": "Display name",
  "category": "Antivirus / Anti-miner / Supply-chain …",
  "description": "1–2 sentences: what it looks for",
  "repo": "owner/name",             // GitHub, for the link and updates
  "homepage": "https://…",          // optional

  "source": {
    // github-release — binary from the latest release (zip / tar.gz / bare .exe)
    "type": "github-release",
    "asset": "regex for the release file name, Windows x64",
    "checksums": "SHA256SUMS"       // optional: checksum file in the release; GitHub's digest is always verified
    // github-source — branch sources (for Python/scripts); version = short commit sha
    //   "type": "github-source", "branch": "main"
    // system — already in Windows: "path": "%ProgramFiles%\\…\\x.exe", "status_ps": "PowerShell → JSON"
    // direct — file at a direct link: "url": "…/KVRT.exe", "signer": "Kaspersky" (Authenticode check);
    //          version = Last-Modified on the server
    // manual — downloaded by hand from a page with a license: "page", "signer", "min_mb", "search": [folders];
    //          ScanHub looks for a fresh .exe by its signature
    // service — online service from services.py: "service": "virustotal", "key": "virustotal_key", "signup", "key_page"
    // builtin — built-in check: "builtin": "signature" (system.py) or "yara" (yarascan.py: YARA Forge + Elastic rules,
    //           engine is the yara-x pip package; rules are in data\yara, XOR-encoded on disk, otherwise Defender deletes them)
    //           or intel.py: "netintel" (Maltrail malware addresses), "origin" (download origin sites, FMHY), "osv" (npm/pip packages);
    //           databases are in data\intel and update themselves once a day before a scan
    // "checksums" can be a pattern: "trufflehog_[\\d.]+_checksums\\.txt"
    // "optional": true on an online service — without a key it does not count as "did not take part" in the file scan result
    // "nokey": true on an online service — no key needed (CIRCL hashlookup)
    // more built-ins from intel.py: "byovd" (vulnerable drivers from LOLDrivers, database refreshed weekly), "malext" (malicious extensions from MalExt Sentry)
    // for direct: "filename" (if the link has no file name); a zip is unpacked and the signature is checked on the exe
  },
  "needs_data": { "glob": "database\\daily.c?d", "label": "Databases need to be downloaded", "mode": "update" },  // until present, the tool does not take part in general scans
  // for builtin yara, use "builtin": "yara" instead of glob
  "section": "scanners | downloadable | online | research",   // research is visible only in Developer mode
  "simple": "one plain-language sentence for simple mode",
  "auto_update": false,             // auto-update is on by default
  "max_age_days": 3,                // for scanners with built-in databases: how many days until "outdated"
  "requires": [{ "path": "C:\\Windows\\System32\\Npcap\\wpcap.dll", "label": "Npcap", "url": "https://npcap.com" }],
  "setup": [["{python}", "-m", "venv", "{dir}\\.venv"]],   // optional: commands run after unpacking
  "exe": "glob for the executable's name inside the unpacked files",
  "admin": false,                   // true — launch GUI modes through UAC

  "exit_codes": { "0": ["clean", "Clean"], "1": ["threat", "Malware"] },
  // verdicts: clean | threat | suspicious | error | launched

  "modes": [
    { "id": "path", "label": "Scan a file or folder", "target": "path",
      "args": ["{target}"], "multi": true },          // multi — takes part in "Scan with selected"
    { "id": "x", "label": "…", "target": "text", "placeholder": "…", "args": ["sub", "{target}"] },
    { "id": "y", "label": "…", "target": "none", "gui": true, "args": [] }
    // "count_regex" + "count_verdict" + "zero_verdict": verdict from a number in the output (e.g. suspicious_count in JSON)
    // target: none | path (file or folder) | file | text | url
    // mode flags: gui (own window), console (new terminal window), admin (UAC), upload (with confirmation),
    //             action (for service: lookup | upload | url)
    // instead of args you can set a full "cmd": ["{python}", "{dir}\\main.py", "{target}"]
    // substitutions: {target} {exe} {dir} {python} {data} (the data folder) {registry} (this folder — for scanner settings files)
    // "elevated_log": "HiJackThis*.log" — launch with a single UAC prompt, wait, and show the report the program writes to its own folder
    //   ("item_regex" — how to count report entries)
    // "elevated": true — a console scanner that needs administrator rights (Emsisoft a2cmd): one UAC prompt, output goes to ScanHub;
    //   "pre": [["/u"]] — commands run before the scan under the same UAC (database update), "timeout", "started_text"
    // "handler": "rootcerts" — output is parsed by intel.handle (Sigcheck → root certificates)
    // "confirm": "…?" — ask before launching (Defender's offline scan reboots the PC)
  ]
}
```

**Protection against tampered releases.** Before installing from GitHub, the archive and the main exe are checked against VirusTotal (if a key is set in Settings). If there are 5 or more detections, or Defender blocks the new file, the version goes into `held` (state.json) and the previous version is installed. The "Install anyway" button sends `force`.

Installed versions live in `apps\<id>\<version>` next to ScanHub. The previous version is kept for rollback. State is stored in `data\state.json`, scan history in `data\history.json`, logs in `data\logs`.

To update everything without opening the window, run `python scanhub.py --update-all` in the ScanHub folder. You can schedule this command in Task Scheduler.
