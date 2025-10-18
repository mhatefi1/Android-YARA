# AndroYara — YARA Scanner for Android

AndroYara brings the power of **YARA** to Android. Point it at a file, a folder, or your installed apps, add your rules, and scan — all **on‑device**.

## What is YARA?

[YARA](https://github.com/VirusTotal/yara) is a pattern‑matching engine widely used by malware researchers and incident responders to **identify, classify, and hunt** files based on rules you write.  
A YARA rule combines:
- **Strings** (literals, hex, regex) and
- **Conditions** (boolean/arithmetical expressions)

to decide whether a file **matches**. YARA is open‑source (BSD 3‑Clause).

## What this app does

- **Buffer‑based scanning**
  - No raw path access
  - Efficient **5MB chunked reads** with de‑duplicated matches
- **Rules picker**
  - Load plaint text or compiled (`.yarac`) rules
- **Privacy**
  - No network calls; scanning happens 100% on device

## Using the app

1. **Select YARA rules**
2. Choose **Installed apps** _or_ **File/Folder**
3. Click on **Start scan**
4. Review results in the expandable **Results** card
5. Tap **Delete** to uninstall or remove