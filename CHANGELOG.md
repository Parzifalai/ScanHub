# What's new in ScanHub

🇷🇺 [Русская версия](CHANGELOG.ru.md)

The text of the newest version's section goes into the GitHub release description, and ScanHub shows it in the “Update ScanHub” window.

## 2.5.0

**Miner Hunter: ScanHub's own scanner**
- New tab “Virus protection → Miner Hunter”. Nothing to download, no admin rights needed: a quick check takes about 20 seconds, a deep one 2–4 minutes.
- Recognises a miner by the code inside the file (XMRig, lolMiner, T-Rex, NBMiner, GMiner, PhoenixMiner and others) even when it's renamed to svchost.exe, and finds their configs and launch scripts in your user folders.
- Catches programs posing as Windows ones (svchost.exe outside the Windows folder, “svch0st.exe”), ClickFix traces (a site telling you to “press Win+R and paste a command”), hidden startup (Task Scheduler tasks, services, WMI subscriptions, launch hijacks, a replaced Windows sign-in), switched-off Windows protection and connections to mining pools.
- The deep check watches behaviour: flat load with no window, Monero-sized memory, a busy GPU with no game, and a trap: ScanHub “opens Task Manager” for a few seconds and checks who goes quiet (that's how hidden miners hide).
- No false alarms: “dangerous” needs several pieces of evidence at once; signatures of known publishers and ScanHub's own tasks (sensors, memory cleanup, the Watcher) are taken into account.
- It never deletes anything by itself: each finding has “Stop process”, “Disable task”, “Disable startup”, “Quarantine” and “Check file online” buttons, and changes show up in “What ScanHub changed” with an undo.
- Built into the deep and ultra checks (next to MinerSearch), and the AI agent runs it for “check for miners” in 20 seconds instead of 1–5 minutes.

**Agent: clearer about what it's doing**
- While the agent works you see a step timeline: a scene, the elapsed time and a "Stop" button on top, finished steps with a tick below, and the current step glowing. Repeated steps no longer show twice — they merge into "×2". The chat and the "Final verdict" after checks both look like this.
- The words the agent searches for are now shown in quotes.

**Fixes**
- The “PC is busy while you're away” alert no longer goes silent after about 25 days of Windows uptime without a restart.

## 2.4.0

**Chat history and a memory for the AI agent**
- Every conversation with the agent is saved on this computer until you delete it. Click "History" in the agent's header: in full-window mode the chats open as a list on the left (search, pin, rename, delete), in the side panel — on top of the conversation. The agent names each chat itself.
- The agent remembers important things between conversations: what computer you have, what was already fixed and how it went, what you asked it to remember. It can also look up past conversations ("what did you suggest last time?"). You can see and delete its notes, or turn memory off, in the agent settings.
- Live scenes while the agent works: a radar for miner search, a beam over files for antivirus checks, waves for the network, a fan and thermometer for hardware, scrolling logs, a globe for web searches — plus elapsed time and the step number. The list of what it is doing stays as it was.

**A smarter, steadier agent**
- New skills: printers and the print queue, Windows services that failed, Task Scheduler tasks. It knows today's date, helps with any question (not only ScanHub findings), writes scripts in code blocks with a "Copy" button, and shows tables.
- More honest: it tells what it saw in the data from what it guesses, and never says something is done if it didn't do it. Steps are always phrased informally.
- A long "thorough check" through a subscription (Antigravity, Claude Code, Codex) is no longer cut off after 15 minutes: the agent stops only if it makes no new step for 7 minutes (45 minutes at most), and then says what it managed to check.
- On a free Gemini key it no longer gives up at the rate limit: it waits a few seconds or answers through another model of the same service.
- Miner search ("Find only") no longer stops at MinerSearch's "choose an action" window, so the agent doesn't hang waiting for it. When an anti-miner flags ScanHub's own sensor task (a hidden console), the agent says it's a false alarm.

**Small things**
- ScanHub always opens on the home page; the last page is only kept while the window is open.
- The agent's header shows the same living orb as the menu.

## 2.3.1

**Small fixes**
- The "⋯" menu next to the shield now has "Ultra check", and the menu closes as soon as you pick an item.
- "Exit" no longer asks you to stop work when ScanHub is only reading system info, and the exit window shows clear task names instead of internal ones.
- Leaving the full-window AI agent no longer hides the window for a second.
- The AI agent's header shows the same living orb as the "AI agent" button in the menu.

## 2.3.0

**Deeper junk cleanup, with lessons from Roomy**
- More places to clean: Brave, Vivaldi and Chromium caches; the graphics-card caches inside every Chromium browser (GPUCache, shader caches); Discord PTB and Canary; Slack; the NVIDIA shader cache in ProgramData; memory dumps after blue screens (MEMORY.DMP and Minidump).
- Previous Windows version (Windows.old): ScanHub removes it in one click with Windows' own Disk Cleanup, under a single UAC prompt. It is never ticked by default, because after that you can't roll back.
- "Your files — your call": old installers lying in Downloads, big files there that nobody has opened for over a month, and Steam games you haven't played in over two months. Nothing is ticked in advance; files go to the Recycle Bin, and a game is removed by Steam itself.
- "Open right now" next to a cache: if Chrome, Telegram, Steam and others are running, ScanHub warns you before cleaning, since open apps keep part of their files.
- Safer deleting: the cleanup never follows links to other folders (junctions, symlinks), and a cache folder that is itself a link is skipped. Your Documents, Desktop, Pictures, Videos, Music, Downloads, OneDrive, Windows and Program Files can't be cleaned even by mistake: the check runs again inside the admin process.

**AI agent everywhere**
- The app itself now says "AI agent" instead of "AI assistant": the menu, the panel, its settings, notifications, the verdict after a scan and the server messages.

## 2.2.0

**Built-in AI agent that runs checks and fixes for you**
- Ask in plain words — "check for miners", "what can I clean up?", "check startup" — and the AI agent runs the ScanHub check itself (miner search, Defender quick scan, junk search, startup, PC health, hardware) and answers from the result. Anything that changes the PC (for example cleaning junk) it only proposes, and it runs only after you press "Do it for me".
- Photos and screenshots: attach a picture to the question with the button or just paste it with Ctrl+V (up to 4). Works with Gemini, Claude, ChatGPT, OpenRouter, Ollama, Claude Code, Codex and Antigravity; for models that can't see pictures the button is hidden.
- Fast / Thorough switch above the input. Fast (the default) uses the same model with short thinking, fewer steps and no web search unless you ask for it, so simple questions take seconds. "How big is this program" is now one step: the program list shows each app's folder and size.
- Opened from the menu or with **Ctrl+K**, the agent fills the full panel next to the menu symmetrically from top to bottom: "How can I help?", the input in the middle, suggested questions below, the mode and the model as drop-down lists. The menu stays on the left, and a button hides it completely. "✦ How to fix" next to a finding still opens it as a side panel.
- The chat no longer flickers or jumps to the bottom while the agent is answering, and has a slim scrollbar. Agent settings open from the top with a clear "← Back to the chat" button; ⚙ again or Esc also gets you back.

**New look: frosted glass**
- Panels are frosted glass over slowly drifting light, and the side menu floats as a separate card. It collapses into a strip of icons and remembers your choice; the highlight of the current section slides to the item you clicked.
- The top bar now only holds "Simple / Developer". Notifications, "Message the author" and Settings moved to the bottom of the menu, and the window's ✕ closes ScanHub completely (if a scan is running, it asks first).
- On launch the logo draws itself and the window fades in. Opening a section, its blocks appear one after another, and when the assistant opens or closes, the blocks glide to their new places. Load meters count up and roll smoothly to new values. With animations turned off in Windows there is no motion.

**First start in your language**
- On a non-Russian Windows, ScanHub now opens in English right away (it used to always start in Russian). A language you picked in Settings still wins. Error windows of ScanHub.exe are in English on English Windows too.
- Translated the remaining mixed-language lines in English mode (crash hints, idle-CPU note, process roles, units like "1 d" and "W", decimal points in sizes).

**Fixes**
- The "Download" link in the README returned 404: release 2.1.1 had no ScanHub-Windows.zip. This release has both archives again plus SHA256SUMS.txt.
- Release archives are now built only from files tracked in git, so no stray local files from the build machine can end up inside.
- Atomdrift didn't start: ScanHub downloaded rules written for the scanner's 3.0 beta, which break the stable 2.13.0. The rules now match the scanner version.
- Running from source now needs Python 3.12 or newer (was 3.14), checked by running ScanHub on Python 3.12.10.
- Watchdog alerts are no longer cut off in the middle of a sentence.
- New screenshots in the README, in Russian and English.

## 2.1.1

**One scan verdict, written by the assistant**
- A file or folder scan now ends with a single verdict. While the AI assistant is reading the scanner results, the “safe to run or not” verdict is hidden; you see “Check finished” and a wait indicator instead. Once the assistant answers, its verdict becomes the only one, and the earlier preliminary scanner verdict moves under a “What the scanners found” spoiler. If the assistant is turned off or couldn't answer, you get the regular verdict as before.

**Fewer false alarms**
- Filescan often flags legitimate files as dangerous. Its alerts on files with a valid signature (Microsoft, Valve and others) and on known originals from the NSRL database now count as weak. If it got several legitimate files wrong in one scan, all of its alerts in that scan are treated as weak.
- A file that VirusTotal has known for over two years and that none of the 60+ antivirus engines flags no longer becomes “dangerous” because of isolated alerts from the Hybrid Analysis, MetaDefender or Filescan sandboxes.
- A broken digital signature on such a long-known clean file now produces the warning “the file was modified after signing, check where it came from” instead of “dangerous files in the folder”. By itself it is not treated as a virus.
- If only some of a folder's files were scanned or a scanner broke, the verdict now says: “Scanned N of M files — run a full folder scan”.
- The assistant's final verdict follows the same rules: “don't run it” only for a confirmed threat.

## 2.1.0

**Assistant via Antigravity on your Google subscription**
- The assistant settings have a new option, “Gemini with your subscription (Antigravity)”. ScanHub launches the official Antigravity app, where you are signed in with your Google account, and the answers count against your subscription limits, as already happens with Claude Code and Codex.
- Models come from the subscription itself: Gemini 4 Hydrogen and Argon, Gemini 3.8 Flash, Orchestrator, plus Claude Opus/Sonnet and GPT-OSS if you have them. The model and the reasoning level (Fast (Low), Balanced (Medium), Deep (High), Very deep (XHigh)) are chosen from two separate lists. The defaults are Hydrogen and “Deep (High)”.
- Antigravity works as an agent: it gets computer data through ScanHub's tools and can search the internet for reference information (you can turn this off in the assistant settings). Before each of its steps, ScanHub checks that the step is allowed: the command line, reading and writing files, and the browser are blocked.
- Your Antigravity settings are left unchanged. After each answer, ScanHub deletes the conversation from Antigravity's folder so that no computer data stays there.

**Translation**
- Translated into English the strings that were left untranslated in 2.0.10.

## 2.0.10

**Fewer false alarms in the scan verdict**
- When the AI scanner Atomdrift itself crashed (for example, on its own faulty rule), it exited with the same code as when it finds something, so ScanHub reported “Malware” and the verdict became “Better not to run it”. Now such a failure is shown honestly: “Scanner failed”, with a note in the log that this is not a finding and a suggestion to update Atomdrift. The same applies to the deep scan, which previously reported “clean (0 files)”.
- The folder scan verdict no longer shows a line with a missing name (“: AI scanner Atomdrift…”): if the path ends in “\”, the folder name is now used.

**Summary for another AI**
- Earlier scanner runs on the same path are now listed separately, marked as old, with a note to base the verdict on the fresh scan. A scanner failure in them is labeled “scanner failed” rather than a bare “Exit code 1”, so it isn't mistaken for an alert.
- A folder path with and without a trailing “\” is treated as the same folder, so scan history is no longer lost.

**Update**
- ScanHub understands four-part version numbers (for example, 2.0.10.1).

## 2.0.9

**AI final verdict after a scan**
- After a file or folder scan, a deep scan or an ultra scan, the built-in assistant reads the results of all scanners on its own and briefly tells you “Safe to open”, “Better not to open” or “Don't open it” (for a computer scan: “All good”, “Something to check”, “Threat found”) and what to do right now.
- The assistant really searches the internet: ScanHub itself looks up the file name, its fingerprint (SHA-256) and the files that raised alerts, and the assistant can keep searching and open pages. The verdict includes what is written about the file, with links to the sources.
- Below the verdict there is an “Ask about this scan” field and the buttons “Discuss with the assistant” and “Ask another AI” (a summary for Claude, ChatGPT or Gemini). The conversation continues in the assistant panel, and the assistant remembers this scan.
- Turn it off in the assistant settings: “Final verdict after scans”. For old results opened later, use the “Ask the assistant” button.
- In the “Summary for AI”, the request now starts with an internet search: what this file is, whether it is official, what is written about it. A summary for the deep scan was added too.

**New assistant chat**
- On a wide screen the assistant panel sits next to the page and doesn't cover it; on a narrow one it slides in over the page.
- You can see which scan the conversation is about, plus suggested questions on its topic (“What is this file?”, “Where do I start?”).
- While the assistant is answering, you can see what it is doing right now: searching the internet, reading a page, looking at logs.
- Your messages are on the right; replies are text with a line on the left; the input field grows with the text, and Enter sends.

**Fixed**
- The extra antivirus tools in the ultra scan didn't run. Dr.Web gives CureIt! a random file name, the admin-rights helper didn't recognize it, and the whole set of antiviruses went back for another UAC prompt. Now CureIt! is recognized by Dr.Web's digital signature, and an antivirus that fails the check is simply skipped without blocking the others.
- “Stop” in the file scan didn't stop VirusTotal (and Filescan): they kept waiting out the free key's per-minute limit. They now stop immediately.
- Scanners downloaded in “Preparation” are no longer downloaded a second time in the “Extra antiviruses” step.

**Extra antiviruses are prepared at the start of the ultra scan**
- Kaspersky, Microsoft Safety Scanner, AdwCleaner, Emsisoft and ESET are downloaded (and updated if outdated) in “Preparation”, the first step, rather than a couple of hours later at the end. If the internet drops, you see it right away.
- In the step selection window, each antivirus shows whether it is ready: “ready”, “downloads during “Preparation””, “updates during “Preparation””, “not downloaded — download it yourself” (Dr.Web CureIt!), “not installed — will be skipped” (Malwarebytes).
- CureIt! has the buttons “Download from the Dr.Web site” and “I downloaded it — find it” right there, so you can get it ahead of time, before the scan starts.

## 2.0.7

**Ultra scan: one UAC prompt for the whole scan**
- Administrator rights are requested once, at the very start. Before, the UAC prompt could appear up to five times: before the deep scan, system folder and driver cleanup, system file and disk checks, “for all users” program updates, and the extra antiviruses.
- The rights go to a helper that lives only until the end of the ultra scan (and the program updates at its end). It runs only what the scan itself does: every job is signed with a key known only to ScanHub and the helper, and the helper won't run a foreign command, a registry edit or a file deletion that isn't on the list.
- If the scan finishes, is stopped, or ScanHub is closed, the helper exits on its own (within 30 seconds at most) and closes everything it launched with administrator rights.
- If you cancel the UAC prompt at the start, the scan runs as before: steps that need rights ask for them themselves.

## 2.0.6

**Fewer false alarms in the scan verdict**
- Long-known legitimate files no longer end up as “dangerous” because of isolated detections. A file counts as known if it is in the NIST NSRL database, on the Hybrid Analysis allowlist, or VirusTotal has known it for over a year with a good reputation. Alerts on such files stay in the list, with an explanation of why they look like false positives.
- A “malicious” entry in the CIRCL database with low confidence (below 50 out of 100) is no longer a verdict, just an ordinary signal.
- 1–2 detections out of dozens of antiviruses on VirusTotal and MetaDefender are a weak signal. If three or more services raise an alert on one unfamiliar file, the verdict is “better not to run it”.
- Example: an old game folder (Call of Duty 4) used to get “dangerous — don't run it”; now it gets “safe to use”, with a list of alerts that look like false positives.

**The summary for AI is 4–5 times shorter, with the same data**
- Scanner progress bars (Atomdrift had hundreds of lines of them) and ClamAV warning frames are removed from the logs.
- VirusTotal and MetaDefender: only the antiviruses that fired are listed by name, the rest as counts (“clean — 68, didn't finish — 2”).
- For online services, the log no longer repeats the details: only the result and errors remain.
- For a folder, the summary shows what is in it (files with sizes) and which files exactly were scanned in the quick scan.

## 2.0.5

**Own window instead of Edge**
- ScanHub opens in its own window, without Edge's black strip at the top. The minimize / maximize / close buttons sit in ScanHub's dark header, the window is dragged by the header (double-click to maximize), and the edges, shadow, Snap and Win+arrows work like in a regular window; size and position are remembered. The engine is WebView2, built into Windows 11. If it isn't available (this happens on Windows 10) or the window fails to open, ScanHub opens the old way, through Edge.

**Extra antiviruses run on their own at the end of the ultra scan**
- A new “Extra antiviruses” step: Kaspersky Virus Removal Tool, Microsoft Safety Scanner, AdwCleaner, Emsisoft Emergency Kit and Dr.Web CureIt! (if downloaded) run one after another in the background: a full scan of all disks, detection only. Findings appear in the ultra scan results with a “Cure” button. You can skip any antivirus with a button; if ScanHub is closed, the scanners stop on their own.
- ESET Online Scanner and Malwarebytes (if installed) open in their own windows: ScanHub clicks “Start” / “Scan” itself, and once the buttons are pressed, it brings their window up.
- Scanners are downloaded automatically from their official sites; the “Remove scanners after the scan” checkbox deletes them and their traces (C:\AdwCleaner, the Microsoft log), while the reports stay in ScanHub. Separately: “Download all” and “Remove downloaded” in “Virus protection → Check”.

**RAM cleanup right on the home page**
- The “RAM” tile has a “Clean” button, as in Mem Reduct (a full cleanup if it was enabled; otherwise a quick one that compresses the memory of inactive programs). Under the percentages you can see how much was freed. The other tiles open “Load now” when clicked.

**Summaries for an AI second opinion**
- A “Summary for AI” in the ultra scan results: every step and every finding, ScanHub's advice and information about the computer.
- In all summaries, the request asks the AI to answer in two parts: “Briefly”, a verdict in 2–5 words and what to do, without jargon (for people who don't know the subject), and “In detail”, point by point, each conclusion with a fact from the summary and a confidence level, with false alarms kept apart from real ones.
- “Copy summary for AI” in the file scan result: signature, MD5/SHA-1/SHA-256 hashes, where it was downloaded from, past scans, ScanHub's verdict, each scanner with its verdict, details (VirusTotal per engine) and log, the scanned files, and a ready-made request for a second opinion. Paste it into Claude, ChatGPT or Gemini.
- “Full PC summary for AI” (“PC health → Overview” and the “⋯” menu on the shield): 28 sections — protection, findings, crashes, hardware, sensors, disks, programs, startup, drivers, privacy, browsers, network, threats, scan and health history — with a request to assess the system.
- By default the account name, computer name and email are hidden (a checkbox reveals them); keys and passwords are always hidden. “Save as file” puts a copy in “Downloads”.

**The Gemini assistant answers using your computer's data**
- If the question mentions a program, code, or “crashes / fails / hangs”, ScanHub attaches that program's crashes and log entries before answering, so even the fast model names the real cause instead of generic words. The assistant no longer mistakes the number after “time stamp” in an event for an error code.
- The default Gemini model is 3.5 Flash (smarter); if it is overloaded, it switches to Flash-Lite on its own.
- Answers no longer contain junk like “[[crashes]]”.
- “Explain” starts with a “Briefly” line: one plain sentence saying whether it is dangerous and what to do.

**“Crashes and errors”**
- For crashes of .NET programs, the error text from the log is shown: the real cause (for example, “Class not registered”).

**Fixed**
- “Load in detail” in the metrics block on the home page overlapped the disk bar; it is now on a separate line.

## 2.0.0

**New “Night shift” look**
- A dark interface with a soft glow: a full-height section menu on the left, a header with the assistant, alerts, “Bug or idea?”, settings and exit; large, clear headings and tabs.
- **A live shield on the home page.** It shows the state honestly: blue with a checkmark means all is well; with a yellow badge means something needs fixing; red means a threat was found or protection is off. During an ultra scan, a deep scan or a file scan, a beam runs along the shield, the ring fills up, and the percentage is in the middle; at the end there is a flash and a new mark is drawn in one stroke. The shield tilts slightly and glints as you move the mouse. Colors blend smoothly, and with the Windows “reduce animations” setting everything stays still.
- **Metrics next to the shield:** Windows stability, CPU, RAM, free space on the system disk, with charts; clicking opens “Speed & games → Load now”.
- “What's worth doing” is a single panel, and each item has a sign by shape and color (triangle: worth fixing, circle: for your information, octagon: urgent). Quick actions: the four main ones are large, the rest are under “All quick actions”.

**Sections rebuilt around tasks**
- There were 12 sections; now there are 7, plus scan history and settings at the bottom of the menu:
  - **Virus protection** — check, ultra and deep scan, check a program, quarantine, browsers, Windows Security (together with the firewall and miner protection);
  - **Cleanup & space** — junk and caches, what takes up space, duplicates and empty folders, broken shortcuts, old drivers;
  - **Programs** — uninstall, updates, startup (moved from “Speed”), built-in apps, the right-click menu;
  - **Speed & games** — game mode and FPS, load now (formerly “Resources”), why it's noisy, memory, internet;
  - **PC health** — overview, crashes and errors, devices, hardware and drivers (together), components for programs, history, alerts;
  - **Privacy** — Windows tracking, restore points, what ScanHub changed;
  - **Phone**.
- Old links from hints, alerts and assistant answers lead to the new places on their own; the assistant knows the new section map.

## 1.5.2

**Fixed**
- The ScanHub window and its taskbar button kept showing the old icon (a shield), even after a reboot: the window is Edge, and it was taking the icon from its own cache. On a new version, ScanHub now clears that cache itself, so the window icon is always up to date.

## 1.5.1

**“Arrow-S” logo**
- The mark is lighter: a blue letter S whose upper tail extends to the right as an arrow, with no plate behind it. The arrow tip sits past the edge of the letter, so even at 16 px the mark is not confused with “$”. The blue is chosen to stay visible on both light and dark taskbars. The new icon is used for the app, shortcuts, the window and the tab; all variants and rules are in `docs/logo`.

## 1.5.0

**New “Turn” logo**
- Instead of a shield with a radar, there is now a blue plate, matching the window styling, with an S-arrow on it: ScanHub shows what is wrong and walks you through the fix step by step. The new icon is used for the app, shortcuts, the window and the tab; for small sizes (the taskbar) there is a separate simplified mark that stays readable even at 16 px. All variants and rules are in `docs/logo`.

**New**
- “Check for updates” (“Developer” mode) now also checks for a new version of ScanHub itself; the result appears as a notification at the bottom right, and you can update from there.
- If ScanHub was useful, you can give it a star on GitHub — a quiet request in the first-run wizard and in the “Help the ScanHub author?” card.

**Fixed**
- The GitHub README no longer says “Version 1.0.0”: the version is shown as a badge and is always current. Fixed where the language is switched (⚙ Settings).

## 1.4.4

**New**
- **“How fast Windows boots” (Speed → Startup):** the bars are now clickable — pick a boot and you will see what slowed that particular one; dates are shown under the bars. You can click the “what slowed it down” line: it shows what the program, driver or service is, how much it slowed the boot, what to do (for example, “Turn off autostart” right from here) and “✦ How to fix”.

**Fixed**
- Drivers (.sys) are no longer described as a “Microsoft Store app”.
- Clear descriptions of common Windows components: search (SearchProtocolHost, SearchIndexer), Explorer, svchost, Defender, OneDrive.

Details for each boot appear after you click “refresh” under the chart (one UAC prompt): the Windows boot log can only be read with administrator rights.

## 1.4.3

**New**
- The ScanHub update window can be **minimized**: it turns into a badge at the bottom right (where notifications appear) with a percentage and a progress bar. Click the badge to open the window again.

**Fixed**
- The cards about ScanHub itself on the home screen (“A new version of ScanHub is out”, “Create a shortcut”, statistics) look even again: the text starts next to the icon and the button is on the right. They used to be broken by the program list styling.

## 1.4.2

**New**
- **ScanHub update with progress:** after “Update”, a window opens with a progress bar and percentages — download, checksum verification against GitHub, file installation, restart. If something goes wrong, the window says why and gives a link to the release page.

**Fixed**
- After a network failure (for example, the connection to GitHub dropped), the new-version check waited 6 hours, so the “A new version of ScanHub is out” card never appeared. It now retries after 10 minutes.
- Anonymous statistics: if you updated or switched the language on the same day, the author saw the old version. The record is now updated immediately. The day is counted in local time.
- The cards about ScanHub itself (new version, shortcut, statistics) no longer have a stray “✦ How to fix” button, and the button is aligned properly.

**Clearer**
- Sidebar footer: no long description of the modes, and the ScanHub version is at the very bottom.
- Language selection (Russian · English) is at the very top of ⚙ Settings.

## 1.4.1

**New**
- **“✦ Anything important here?” got much smarter.** Before asking, ScanHub collects facts about each file and folder: whose program it is, whether it is running now, when it was changed and opened, what is inside, the signature, where it was downloaded from, whether it is a copy and whether an already unpacked folder sits next to it. The assistant always searches the web for unfamiliar names, and on its own adds extra items it finds inside folders and in Downloads (repeated installers, old archives).
- **Per-item rating:** “Safe to delete” (with how much space it frees), “Look first” and “Don't delete”, each with a clear reason and a link to the folder.
- **“✦ Review and delete with AI”:** a window with a list — click a path to open the folder, “✦ What is it?” to have the assistant explain in more detail, and “Delete selected” (to the Recycle Bin or permanently). If something was not deleted, ScanHub says why and what to do: “Delete as administrator”, “Delete on restart” or “✦ How to delete?”. Only items the assistant did not mark “Don't delete” can be deleted; drives, the Windows folder and the page file never can.
- **“✦ Continue the conversation”:** ask the assistant about any item in the rating.

**Clearer**
- “Hide the rating” no longer erases it: the rating collapses into a single line, and “Show” opens it again. It also survives a window reload.
- The shredder is moved into “Developer” mode.

## 1.4.0

**New**
- **“✦ Anything important here?”** in all cleanups: junk and caches, “What takes up space” (with a “✦ What can I delete?” button that looks at the biggest files and folders), duplicates, program leftovers, empty folders, broken shortcuts, old drivers. The assistant looks at every item and searches the web when unsure, then labels it “Safe to delete”, “Look first” or “Don't delete” with a reason. Safe items are ticked right away; risky ones are unticked.
- **The assistant searches the web** with any model, not just Claude and ChatGPT via subscription: what a program or error is, whether others have run into the problem. It can be turned on and off in the assistant's settings.
- **Safe download links:** if the assistant advises deleting a file downloaded from an untrusted site, it gives a link to the official site (taken from the winget catalog, with a check that the site doesn't redirect to a foreign domain). Links in answers are clickable and open after confirmation.
- **Replies from the author:** if you write to the author via “Bug or idea?”, the reply arrives right in ScanHub (a notification and “My messages”). Only the person who wrote can see the reply.
- **Removing browser extensions:** the “Delete” button in “Privacy & protection → Browsers” opens the extension's page in the right browser and profile.
- **Firewall:** an explanation of where rules from uninstalled programs come from, and a “Delete rules of uninstalled programs” button.
- **The watchdog explains its alerts:** each one gets “Nothing to worry about”, “Worth a look” or “Important”, what it is and what to do (for example, “PhoneExperienceHost.exe is Phone Link; a single crash is harmless”).
- **Program updates decide for themselves:** if a new version has no suitable installer (for example, OLE DB Driver 18 → 19 is a separate program installed alongside), ScanHub explains, leaves it as is and stops offering it. Every program has “Don't offer”, and hidden ones are in “Hidden updates”.
- **“Show FPS”** in “Quick actions” on the home screen: turns the counter on and off in one click.

**Fixed**
- After every assistant reply, a red line “The assistant did not respond: error” appeared even though the reply had arrived.
- “✦ Do it for me” did not work: the assistant received an empty message and wrote “your message came through empty”.
- After “Disable driver”, nothing happened on screen even though the driver was disabled. ScanHub now says “Done — restart the computer”, and a driver that is disabled but not yet unloaded is no longer considered dangerous.
- “What takes up space”: there was no way back from a folder to the drive level — there is now a path from the root and “← back”.
- Microphone test: the recording was barely audible on a quiet microphone. It is now amplified, and there is “Listen again”.
- Keyboard test: during the test the window goes full screen, and the Win, Alt+Tab and Alt+F4 keys do not trigger in Windows. Exit with Shift+Esc or the button.
- The “FPS only” window shows just the numbers, with no backdrop and no dark border.

**Clearer**
- Reminders about ScanHub itself (setup, shortcut, new version, launch counter) have their own color and an “S” icon, so they are not confused with problems on the computer.
- The “Back to fixing” button can be dismissed with a cross.
- “Extra scanners” no longer lists MinerSearch — it already runs inside the deep and ultra checks.

## 1.3.2

**New**
- The FPS window shows only the FPS numbers by default. The detailed version (drops, temperature, GPU power) is turned on in “Game mode” → “FPS and temperatures”.
- “Suggest an improvement” has its own icon — a light bulb (the ✦ star is the AI assistant).

**Fixed**
- “GPU right now” and the hardware check no longer say “quiet mode is on” when a Lenovo laptop is set to “Performance” (ScanHub reads the mode from the sensors). If the limit is below the maximum, it explains that the GPU gets the last few watts only when the CPU is lightly loaded (NVIDIA Dynamic Boost); if the GPU is not hitting the limit anyway, it says the power is sufficient and the bottleneck is the CPU or the game.

## 1.3.1

**Fixed**
- If the ScanHub window stayed minimized for a long time (for example, during a game), ScanHub could close by itself while the window stayed open, and its buttons silently did nothing (for example, “Turn off game mode”). A minimized window no longer “falls asleep”, and if ScanHub is closed anyway, the window says so directly and revives itself when ScanHub is opened again.
- “Turn off game mode” no longer waits for the administrator prompt: everything is restored immediately, and the update services are restarted separately.

## 1.3.0

**Games**
- **In-game FPS**: a small window in the corner of the screen showing FPS, drops, temperature and GPU power. The mouse passes through it, so it does not get in the game's way. The counting is done by the official Intel PresentMon counter (ScanHub downloads it itself; one UAC prompt is needed). You can close the ScanHub window — the counter keeps running until you turn it off.
- **Post-game summary**: average FPS, how severe the drops were, whether there were stutters and overheating — and what to do about it.

**GPU live** (PC health → Hardware and Game mode): how many watts it draws right now, what limit is allowed and what the maximum is, on charger or on battery. Plug in the charger or switch to “Performance” mode and you immediately see the limit rise.

## 1.2.0

**New**
- **Phone check** (“Phone” section): Android over a cable via USB debugging. It looks for stalkerware apps and apps not from the store (checked against VirusTotal by hash), and checks which apps have accessibility permissions, device administrator rights and notification access, whether the phone is rooted, how long ago the last security update was, and the state of the battery and storage. Nothing is installed on the phone, and ScanHub closes the connection itself.
- **Devices** (PC health → Devices): keyboard, mouse, microphone, sound, camera, Bluetooth — whether they work and, if not, why. Live checks right in the window: microphone level and a 3-second recording, all keys (and key “chatter”), mouse buttons, accidental double-clicks, polling rate, left and right sound, camera. Fixes sticky and filter keys and blocked microphone and camera access. Shows who recently used the microphone and camera.
- **First-run wizard** “Let's get ScanHub ready”: downloads all scanners, databases and threat lists (the Maltrail databases of dangerous addresses — with your consent, otherwise the network check would be incomplete), and while that downloads, helps you paste your VirusTotal, MetaDefender, Filescan and Hybrid Analysis keys and immediately checks that each key works. To reopen it: ⚙ Settings → “First-run setup”.
- **MinerSearch inside the deep and ultra checks**: it downloads itself (during setup and before a check), runs itself, in the same UAC prompt as the process check, and only searches (it deletes nothing). Its minor notes about signatures and certificates are explained in plain words and are not counted as a threat.
- Clearer explanation of root certificates: what they are, which ones are usually harmless (VPNs, banks, laptop utilities, anti-cheats) and which are dangerous.
- **“Bug or idea?”**: you can now suggest an improvement in the same window. You can attach up to three screenshots (with a button, Ctrl+V or drag and drop) — they are compressed in the window and sent to the author as images. The ScanHub error log is attached with a separate checkbox, and you can see how many entries it has.
- **Percentages and “~N min left”** for long tasks: cleanup, disk analysis, duplicates, shredder, ScanHub setup, internet check, file checks, deep and ultra checks.
- The anonymous launch counter is **only with your consent** (asked once on the home screen, changeable in ⚙ Settings).

**Clearer**
- The system file check speaks plainly: what exactly is damaged (for example, “938 theme files — barely affects operation”), offers “Repair” only when it will help, and if Windows can no longer find intact copies (error 0x800f0915 on test builds), it honestly says there is nothing to do. If the check did not start because of a pending restart, it says so. One old Windows flag is no longer shown as a red error.
- “Crashes and errors”: each crash is marked “Nothing to worry about / Worth a look / Important” with an explanation, plus a summary for each day and an overall verdict — dangerous, or just ordinary small stuff.
- Suggestions of other antivirus programs no longer look like ads: a calm list of “what it looks for and how it works”, with no “strongest” labels or bright buttons; when there are no findings, it is collapsed and marked “optional”.
- The AI assistant (Claude Code / Codex) can now search the web for reference information — this can be turned off in the assistant's settings. The description of what it has access to has been corrected.

**Fixed**
- The scanner's “Download” button did not change either during the download or after installation (in the scanner block of the deep and ultra checks). It now immediately says “Downloading…”, shows progress and turns into “Run” by itself.
- At the end of the deep and ultra checks there is a block: “To be as sure as possible that the PC is clean — finish the check with extra scanners”.
- A dropped connection to the window (you closed or reloaded it mid-reply) is no longer logged as a ScanHub error.

## 1.1.1

- Fixed: if another program on the computer had already taken port 8765, the ScanHub window could open someone else's page (“Directory listing”), and ScanHub started a second copy on every shortcut click. Now only ScanHub takes the port, and if it is busy, ScanHub picks the next free one (8766–8775) by itself.

## 1.1.0

**AI assistant**
- Claude and ChatGPT through your own subscription: ScanHub launches the official Claude Code or Codex that you are signed in to, so requests count against your subscription limits. Sign in with a button in the assistant's settings.
- It works as an agent: it collects data itself with ScanHub's tools (logs, crashes, devices, protection, files). It has no command line, no internet and no access to your files.
- **“✦ Do it for me”**: if the assistant suggested actions (disable a vulnerable driver, update a program, remove something from startup, turn on protection…), it carries them out one by one and checks the result. Only approved actions, through the same checks and UAC prompts, recorded in “What ScanHub changed”. It also works with API-key models.
- New API-key options: Claude (Anthropic), ChatGPT (OpenAI), OpenRouter (hundreds of models with one key).

## 1.0.0 — first release

**Virus scanning**
- A file, folder or program — checked by several engines at once (Microsoft Defender, ClamAV, YARA, Atomdrift, digital signature, online hash lookup) with an overall verdict of “safe to run / better not to run”.
- Deep scan of the whole system, “Ultra check” (everything in sequence with a PDF report and a comparison with the previous one), fix wizard.
- Third-party scanners in one click: Kaspersky VRT, Dr.Web CureIt!, ESET, Emsisoft, Malwarebytes, AdwCleaner, HiJackThis+ and others — from official sites, with signature and checksum verification.
- Check before running: right-click a file → “Check in ScanHub”.

**Maintenance**
- Junk cleanup with explanations, disk space, duplicates, uninstalling programs with their leftovers, program updates, old drivers, PATH.
- PC health: crashes and their causes (with a verdict of “dangerous / worth a look / can be ignored”, search by program and a table of all crashing programs), a stability index with an explanation of what lowered it, “what is this program” for every crash, hardware, health history (battery, disks).
- “Why is the internet slow”: Wi-Fi, router, internet, DNS, speed.

**Privacy & protection**
- Privacy settings and built-in Windows protections, browsers, right-click menu, firewall, miner protection, shredder.
- “What ScanHub changed”: all changes, with an “Undo” button.

**Other**
- AI assistant (Ollama, Gemini or DeepSeek): “✦ How to fix” on any finding and a chat about your own PC; it only reads and advises.
- Russian and English interface.
- One-button update, “Found a bug?” — a report to the author, and uninstalling ScanHub with all its traces.
