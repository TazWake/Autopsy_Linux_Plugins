# Autopsy Linux Plugins

Custom [Autopsy](https://www.autopsy.com/) ingest modules written in Python (Jython) for Linux digital forensics and incident response (DFIR). Each module targets artifacts that are awkward to review manually at scale—shell history, persistence, authentication logs, and web-server triage—and surfaces structured hits on the Autopsy blackboard and timeline.

Modules are independent: install only what you need, and add new ones as they land in this repository without changing existing layouts.

---

## Requirements

- [Autopsy Forensic Browser](https://www.autopsy.com/download/) with Python ingest modules enabled
- A case containing a Linux disk image or file system (ext4, XFS, etc.) with user home directories and standard paths intact

Modules run inside Autopsy’s embedded Jython runtime; you do not install separate Python packages for the ingest modules themselves.

---

## Quick start

1. Copy the module’s `.py` file into your Autopsy Python modules directory (see [Installation](#installation)).
2. Restart Autopsy (or reload Python modules if your version supports it).
3. Add a data source and run ingest. Enable the module under **Tools → Options → Ingest Modules** (exact menu labels may vary slightly by Autopsy version).
4. Review results under **Interesting Items** and the case timeline where timestamps are available.

---

## Repository layout

```config
Autopsy_Linux_Plugins/
├── README.md                          # This file — project overview and module catalog
├── LICENSE                            # GPLv3
├── LinuxShellHistoryModule/
│   └── LinuxShellHistoryModule.py     # File ingest: shell history triage
└── <FutureModuleName>/                # One directory per module (same pattern)
    └── <FutureModuleName>.py
```

When adding a module, create a sibling directory named after the module, place the ingest script inside it, and add a row to the [module catalog](#module-catalog) below plus a dedicated section under [Modules](#modules).

---

## Module catalog

| Module | Ingest type | Status | Path |
| --- | --- | --- | --- |
| [Linux Shell History & Command Triage](#linux-shell-history--command-triage) | File Ingest | **Available** (v1.1.0) | [`LinuxShellHistoryModule/`](LinuxShellHistoryModule/) |
| [Linux Persistence & Auto-Start Analyzer](#linux-persistence--auto-start-analyzer-planned) | Data Source Ingest | Planned | — |
| [SSH & Authentication Log Parser](#ssh--authentication-log-parser-planned) | File Ingest | Planned | — |
| [Web Shell & Server Triage](#web-shell--server-triage-planned) | File Ingest | Planned | — |

---

## Installation

Autopsy discovers ingest modules from a per-user **python_modules** folder. Copy only the `.py` file (not the whole repository) unless you prefer to symlink or script deployment yourself.

| Platform | Typical path |
| --- | --- |
| Windows | `%APPDATA%\autopsy\python_modules\` |
| Linux | `~/.autopsy/python_modules/` |
| macOS | `~/Library/Application Support/autopsy/python_modules/` |

**Example (Linux Shell History module on Windows):**

```text
copy LinuxShellHistoryModule\LinuxShellHistoryModule.py %APPDATA%\autopsy\python_modules\
```

After copying, restart Autopsy. The module should appear as **Linux Shell History & Command Triage** in the ingest module list.

---

## Modules

### Linux Shell History & Command Triage

**Type:** File Ingest  
**Display name:** Linux Shell History & Command Triage  
**Version:** 1.1.0  
**Source:** [`LinuxShellHistoryModule/LinuxShellHistoryModule.py`](LinuxShellHistoryModule/LinuxShellHistoryModule.py)

#### Purpose

Hands-on-keyboard activity often survives in per-user shell history files spread across `/root` and `/home/*`. This module finds those files during file ingest, optionally recovers command timestamps when `HISTTIMEFORMAT` was enabled on the source host, and flags commands that match a built-in list of high-risk strings.

#### Files processed

The ingest filter matches file names that:

- End with `_history` (e.g. `.python_history`, `.sh_history`), or
- Are named `.bash_history` or `.zsh_history`

Typical locations include `/root/` and `/home/<username>/` (including hidden dotfiles). Only regular files are parsed; directories are skipped.

#### Timestamp handling

Many distributions store shell history as plain command lines. When `HISTTIMEFORMAT` was configured, bash/zsh may prefix commands with epoch lines such as `#1717004400`. The module:

1. Reads a `#<digits>` line as the timestamp for the **next** command line.
2. Posts `TSK_DATETIME` on the blackboard artifact when that epoch is present.
3. Omits datetime when no epoch was associated with the command (avoids bogus timeline dates).

#### Suspicious command detection

Commands are scanned (substring match, case-sensitive) for:

`wget`, `curl`, `chmod +x`, `nc`, `base64`, `shred`, `history -c`, `/dev/shm`

Matches create **Interesting File Hit** artifacts (`TSK_INTERESTING_FILE_HIT`) with:

| Attribute | Content |
| --- | --- |
| Set name | `Suspicious Commands` |
| User name | Derived from path (`root`, `/home/<user>`, or fallbacks) |
| Comment | Full command line and matched keyword |
| Datetime | UNIX epoch (seconds), when available from history format |

View hits under **Interesting Items** in the Autopsy UI. Use the case timeline when `TSK_DATETIME` is populated.

#### Username extraction

| Path pattern | Resolved user |
| --- | --- |
| Contains `/root` | `root` |
| `/home/<username>/...` | `<username>` |
| Other | `System/Service` or `Unknown` |

#### Operational notes

- Run **file ingest** (or a full ingest profile that includes file-level modules) after the data source is added.
- Large or corrupted history files are read via `ReadContentInputStream`; parse errors are logged under the module logger name `LinuxShellHistoryModule`.
- Keyword matching is intentional triage, not proof of malicious activity—validate hits in context.

---

### Linux Persistence & Auto-Start Analyzer (planned)

**Type:** Data Source Ingest (planned)

Will focus on Linux persistence: `/etc/crontab`, `/var/spool/cron/crontabs/*`, systemd unit directories, and `/etc/rc.local`. Goal: unified blackboard visibility for scheduled tasks and services, with emphasis on executables running from unusual paths (`/tmp`, `/dev/shm`, `/var/tmp`).

---

### SSH & Authentication Log Parser (planned)

**Type:** File Ingest (planned)

Will target `/var/log/auth.log` (Debian/Ubuntu family) and `/var/log/secure` (RHEL/CentOS/Rocky). Goal: structured blackboard entries for logins, SSH key acceptance, `sudo` use, and account/group changes to support lateral-movement and brute-force analysis.

---

### Web Shell & Server Triage (planned)

**Type:** File Ingest (planned)

Will combine web server log parsing (Apache, Nginx) with inspection of web roots such as `/var/www/html/`. Goal: flag suspicious access patterns (e.g. fuzzing bursts, suspicious query strings) and anomalous script files (`.php`, `.jsp`, `.py`) in web-accessible directories.

---

## Contributing a new module

1. Add `YourModuleName/YourModuleName.py` implementing Autopsy’s `IngestModuleFactory` / `FileIngestModule` or `DataSourceIngestModule` APIs.
2. Register a row in the [module catalog](#module-catalog) and a subsection under [Modules](#modules).
3. Document install file name, ingest type, target paths, blackboard artifact types, and investigator workflow.
4. Keep module-specific logic in its directory; avoid shared coupling until a real shared library is needed.

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
