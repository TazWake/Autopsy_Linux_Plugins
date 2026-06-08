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
├── LinuxPersistenceModule/
│   └── LinuxPersistenceModule.py      # Data source ingest: persistence triage
├── LinuxAuthLogModule/
│   └── LinuxAuthLogModule.py          # File ingest: SSH & authentication logs
└── <FutureModuleName>/                # One directory per module (same pattern)
    └── <FutureModuleName>.py
```

When adding a module, create a sibling directory named after the module, place the ingest script inside it, and add a row to the [module catalog](#module-catalog) below plus a dedicated section under [Modules](#modules).

---

## Module catalog

| Module | Ingest type | Status | Path |
| --- | --- | --- | --- |
| [Linux Shell History & Command Triage](#linux-shell-history--command-triage) | File Ingest | **Available** (v1.1.0) | [`LinuxShellHistoryModule/`](LinuxShellHistoryModule/) |
| [Linux Persistence & Auto-Start Analyzer](#linux-persistence--auto-start-analyzer) | Data Source Ingest | **Available** (v1.0.0) | [`LinuxPersistenceModule/`](LinuxPersistenceModule/) |
| [SSH & Authentication Log Parser](#ssh--authentication-log-parser) | File Ingest | **Available** (v1.0.0) | [`LinuxAuthLogModule/`](LinuxAuthLogModule/) |
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
copy LinuxPersistenceModule\LinuxPersistenceModule.py %APPDATA%\autopsy\python_modules\
copy LinuxAuthLogModule\LinuxAuthLogModule.py %APPDATA%\autopsy\python_modules\
```

After copying, restart Autopsy. Modules appear in the ingest module list under their display names (see the [module catalog](#module-catalog)).

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

### Linux Persistence & Auto-Start Analyzer

**Type:** Data Source Ingest  
**Display name:** Linux Persistence & Auto-Start Analyzer  
**Version:** 1.0.0  
**Source:** [`LinuxPersistenceModule/LinuxPersistenceModule.py`](LinuxPersistenceModule/LinuxPersistenceModule.py)

#### Purpose

Malware and threat actors commonly survive reboots by abusing cron, systemd, or legacy boot scripts. This module queries the case database for known persistence paths (via Autopsy’s `FileManager`), parses each artifact, and posts structured entries to the blackboard. Commands that execute from unusual directories are elevated into a separate suspicious set for faster triage.

#### Artifacts scanned

| Location | Mechanism |
| --- | --- |
| `/etc/crontab` | System-wide cron |
| `/etc/cron.d/` | Cron drop-in files |
| `/var/spool/cron/crontabs/` | Per-user crontabs (Debian/Ubuntu style) |
| `/var/spool/cron/` | Per-user crontabs (RHEL/CentOS style) |
| `/etc/systemd/system/` | Administrator and attacker-defined systemd units |
| `/usr/lib/systemd/system/` | Vendor units (suspicious `ExecStart` paths only) |
| `/etc/rc.local` | Legacy boot script |

#### Parsed fields

- **Cron:** schedule, owning user, command (including `@reboot` / `@daily` shortcuts in user crontabs)
- **Systemd services:** `ExecStart`, `ExecStartPre`, `ExecStartPost`, `ExecReload`, and `User=` when present
- **Systemd timers:** `OnCalendar`, `OnBootSec`, `OnUnitActiveSec`, `OnStartupSec` (under `/etc/systemd/system/` only)
- **rc.local:** non-comment commands (excluding bare `exit 0`)

#### Blackboard output

Entries are posted as **Interesting File Hit** artifacts with:

| Attribute | Content |
| --- | --- |
| Set name | `Linux Persistence` or `Linux Persistence - Suspicious Paths` |
| User name | Cron owner, systemd `User=`, or `root` / `system` as appropriate |
| Program name | Primary executable token extracted from the command |
| Name | Mechanism type (e.g. `Cron (user crontab)`, `Systemd service`) |
| Comment | Schedule, full command, mechanism detail, and suspicious-path match when applicable |

Suspicious execution paths (substring match, case-insensitive) include:

`/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/shm/`

Suspicious entries receive a **Likely Notable** score; other entries are informational.

#### Operational notes

- Enable as a **data source ingest** module when adding or re-running ingest on a Linux image.
- Vendor systemd units under `/usr/lib/systemd/system/` are not fully enumerated (to avoid thousands of package units); only units whose `ExecStart` references a suspicious path are reported.
- Cron environment lines (e.g. `CRON_TZ=`) are skipped; invalid cron lines are ignored silently.
- Validate hits in context—legitimate admin tasks sometimes use `/tmp` or user systemd units.

---

### SSH & Authentication Log Parser

**Type:** File Ingest  
**Display name:** SSH & Authentication Log Parser  
**Version:** 1.0.0  
**Source:** [`LinuxAuthLogModule/LinuxAuthLogModule.py`](LinuxAuthLogModule/LinuxAuthLogModule.py)

#### Purpose

Lateral movement, privilege escalation, and brute-force activity leave traces in Linux authentication logs. This module parses `auth.log` and `secure` during file ingest, extracts structured fields from each relevant line, and posts timeline-ready entries to the blackboard.

#### Files processed

Under `/var/log/`:

| File pattern | Distribution |
| --- | --- |
| `auth.log` | Debian/Ubuntu |
| `auth.log.*` (uncompressed rotations) | Debian/Ubuntu |
| `secure` | RHEL/CentOS/Rocky |
| `secure-*`, `secure.*` (uncompressed rotations) | RHEL/CentOS/Rocky |

Compressed rotations (`.gz`) are skipped in this version.

#### Events parsed

| Event type | Set name | Status |
| --- | --- | --- |
| SSH login success (password, public key, keyboard-interactive) | `Linux Authentication - SSH Success` | Success |
| SSH failed password / invalid user | `Linux Authentication - Failed Logins` | Failed |
| PAM authentication failure | `Linux Authentication - Failed Logins` | Failed |
| Sudo command execution | `Linux Authentication - Sudo` | Success |
| User or group created / modified | `Linux Authentication - Account Changes` | Created / Modified |

Failed login and account-change events are scored **Likely Notable**.

#### Blackboard output

Entries are posted as **Interesting File Hit** artifacts with:

| Attribute | Content |
| --- | --- |
| Set name | One of the sets listed above |
| Name | Event type (e.g. `SSH Login Failed`, `Sudo Command`) |
| Description | Status (`Success`, `Failed`, `Created`, `Modified`) |
| User name | Target account (SSH user, sudo `USER=`, or created account) |
| IP address | Source IP when present in the log line |
| Host | Hostname from the syslog header |
| Datetime | UNIX epoch (seconds), when the timestamp could be parsed |
| Comment | Caller, port, auth method, command, key fingerprint, group, and raw log line |

#### Timestamp handling

- **ISO-8601** timestamps (common on newer rsyslog/systemd hosts) are parsed directly.
- **Traditional syslog** timestamps (`May 29 10:15:01`) use the year inferred from the log file’s modification time.

#### Operational notes

- Enable as a **file ingest** module when running ingest on a Linux image.
- Large rotated logs are read in full; very busy servers may produce many blackboard entries.
- Validate failed-login clusters and new accounts against other case evidence before drawing conclusions.

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
