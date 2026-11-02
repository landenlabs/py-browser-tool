<table border="0">
  <tr>
    <td>
      <!-- VERSION -->v6.05.23<br>
      <!-- DATE -->25-May-2026<br>
      macOS &nbsp;|&nbsp; Windows &nbsp;|&nbsp; Linux<br>
      <a href="https://landenlabs.com">Home</a>
    </td>
    <td>
      <a href="https://landenlabs.com">
        <img src="screens/landenlabs_400.webp" width="300" alt="LanDen Labs">
      </a>
    </td>
  </tr>
</table>

# Browser inspection tool

A cross-platform browser inspection tool built with Python. Reports installed
Chrome extensions, the profiles they belong to, and flags extensions whose
`manifest_version` falls below what the current Chrome browser will load.

**By [LanDen Labs](https://github.com/landenlabs) (2026)**

---

## Screenshots

_(coming soon)_

---

## Features

- **Cross-platform default-location discovery.** Pass `--chrome` with no value
  and the tool scans the standard Chrome User Data directory for the current OS
  (Windows / macOS / Linux), including Beta / Canary / Chromium variants.
- **Per-profile summary** (`--profiles`): table showing the on-disk profile dir
  (`Default`, `Profile 1`, ...), the human-readable display name from
  `Local State` / `Preferences`, and installed / enabled / unsupported
  extension counts.
- **Detailed extension listing** (`--summary`): name, version, manifest_version,
  description, profile, and on-disk path for every extension.
- **Localized name resolution.** Extensions whose manifest declares
  `"name": "__MSG_extName__"` are resolved against their
  `_locales/<locale>/messages.json` so the report shows the real human name,
  not the message key.
- **Chrome version header.** Both reports lead with the Chrome version (read
  from `<User Data>/Last Version`) and the minimum extension
  `manifest_version` that version will load.
- **Unsupported-extension flagging.** Extensions with `manifest_version` below
  the browser's minimum are counted in the profile table and shown in RED in
  the summary listing (`Manifest V2 removed` in Chrome 138+).
- **Permission-tolerant.** Component extensions and other ACL-protected paths
  on Windows are skipped with a notice instead of crashing the scan.
- **Standard CLI conventions.** `--version`, `--help` with examples, clean
  Ctrl-C handling, and a full traceback on unexpected errors.

---

## Requirements

- Python 3.10 or later
- No third-party packages — uses only the standard library

---

## Installation

### Run from source

```bash
git clone https://github.com/landenlabs/browser-tools.git
cd browser-tools
python brow-tool.py --help
```

### Build a standalone binary

**macOS**

```bash
pyinstaller --onefile --name brow-tool brow-tool.py
```

**Windows**

```powershell
pyinstaller --onefile --name brow-tool brow-tool.py
```

Both scripts use [PyInstaller](https://pyinstaller.org) and embed the correct icon and version metadata automatically.

---

## Usage

### List profiles and extension counts

```bash
# Auto-detect Chrome at the OS default location
brow-tool.py --profiles --chrome

# Or point at a specific Chrome User Data directory
brow-tool.py --profiles --chrome "%LOCALAPPDATA%\Google\Chrome\User Data"
```

Sample output:

```
[*] Chrome version: 138.0.7204.97  (minimum extension manifest_version: 3 — Manifest V2 removed)
[*] Profiles in: C:\Users\You\AppData\Local\Google\Chrome\User Data

  Profile     Display Name   Installed   Enabled   Unsupported
  ---------   ------------   ---------   -------   -----------
  Default     Personal              12        10             2
  Profile 1   Work                   5         5             0
```

### Detailed per-extension listing

```bash
brow-tool.py --summary --chrome
```

Sample output (one extension per block):

```
=== Profile: Default  ("Personal") ===
  Name             : uBlock Origin
  Version          : 1.56.0
  Manifest Version : 3
  Description      : Finally, an efficient blocker.
  Profile          : Default  ("Personal") (Enabled/Installed)
  Path             : C:\Users\You\...\Extensions\cjpalhdlnbpafiamejdnhcphjbkeiagm\1.56.0_0\manifest.json
```

Extensions whose `manifest_version` is below the browser's minimum are tagged
in red:

```
  Manifest Version : 2  (UNSUPPORTED — below browser minimum 3)
```

### Combine both

```bash
brow-tool.py --profiles --summary --chrome
```

### Find (and delete) dead bookmarks

```bash
# Check every http(s) bookmark; report those that fail to load
brow-tool.py --bookmarks --chrome
brow-tool.py --bookmarks="Work" --chrome

# Also delete the failed ones (asks first; close Chrome; Bookmarks file is backed up)
brow-tool.py --bookmarks --delete-failed --chrome
```

Connection errors, 404s and 5xx responses count as failed. 401/403/429 are
reported as *blocked* (the site likely exists but rejects scripts) and are never
deleted. Use `--timeout SECONDS` to adjust the per-request timeout (default 10).
With Chrome sync enabled, deleted bookmarks may be restored from the sync server.

### Default scan locations

When `--chrome` is given without a path, these are searched in order:

| Platform | Path |
| -------- | ---- |
| Windows  | `%LOCALAPPDATA%\Google\Chrome\User Data` (+ Beta, SxS / Canary, Chromium) |
| macOS    | `~/Library/Application Support/Google/Chrome` (+ Beta, Canary, Chromium) |
| Linux    | `~/.config/google-chrome` (+ beta, unstable, chromium) |

### Other flags

| Flag | Purpose |
| ---- | ------- |
| `--no-color` | Disable ANSI color output (also honors `NO_COLOR` env var) |
| `--version`  | Print version and exit |
| `--help`     | Show full usage and examples |

---

## Project structure

```
browser-tools/
├── brow-tool.py        # Main script (single-file CLI)
├── README.md
├── LICENSE
└── screens/            # Images used in this README
```

---

## License

Apache 2.0 © [LanDen Labs](https://github.com/landenlabs) 2026
