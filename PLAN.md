# Autopsy Python Plugins for Linux DFIR

This repository contains proposals and implementations for custom Python (Jython) ingest modules tailored for Linux digital forensics and incident response (DFIR) within the Autopsy Forensic Browser.

---

## 1. Linux Shell History & Command Triage Module

* **Module Type:** File Ingest Module
* **Target Artifacts:** `~/.bash_history`, `~/.zsh_history`, `~/.python_history`, `~/.sh_history` across `/root/` and `/home/*` directories.

### Description

Attacker "hands-on-keyboard" activity is best analyzed through shell history, but hunting through raw text files scattered across multiple user profiles is tedious. This module scans the target file system to identify hidden shell history files. If `HISTTIMEFORMAT` was configured on the target system, it parses the hidden epoch timestamps and maps them directly into Autopsy’s central timeline.

### DFIR Value

* **Automated Alerting:** Automatically scans command strings for high-risk keywords (e.g., `wget`, `curl`, `chmod +x`, `nc`, `base64`, `shred`, or log-clearing commands like `history -c`).
* **Blackboard Integration:** Posts flagged strings to the Autopsy Blackboard as custom or standard artifacts (e.g., `TSK_SUSPICIOUS_COMMAND`), allowing immediate filtering by the investigator.

### Status

Initial version complete

---

## 2. Linux Persistence & Auto-Start Analyzer

* **Module Type:** Data Source Ingest Module
* **Target Artifacts:** `/etc/crontab`, `/var/spool/cron/crontabs/*`, `/etc/systemd/system/`, `/usr/lib/systemd/system/`, and `/etc/rc.local`.

### Description

Malware and live threat actors establish persistent access to survive reboots. On Linux, this usually involves abusing cron jobs or systemd services. Instead of processing every file sequentially, this Data Source module queries the Autopsy SQLite database directly for known persistence paths, extracting execution strings, schedule intervals, and owner privileges.

### DFIR Value

* **Unified Visibility:** Populates a dedicated "Linux Persistence" tab on the Autopsy Blackboard.
* **Anomaly Detection:** Allows an analyst to quickly isolate binaries executing out of unusual or non-standard directories (e.g., `/tmp`, `/dev/shm`, or `/var/tmp`).

---

## 3. SSH & Authentication Log Parser

* **Module Type:** File Ingest Module (Filtered by path/name)
* **Target Artifacts:** `/var/log/auth.log` (Debian/Ubuntu) and `/var/log/secure` (RHEL/CentOS/Rocky Linux).

### Description

Tracking lateral movement, privilege escalation, and brute-force entry is fundamental to root-cause analysis. This module isolates authentication logs and applies structured regex patterns to parse successful/failed logins, accepted SSH keys, elevations via `sudo`, and the creation of rogue user accounts or groups.

### DFIR Value

* **Structured Timelines:** Transforms unstructured log data into structured Blackboard entries containing Source IP, Target User, Event Type, and Status.
* **Correlative Analysis:** Enables immediate sorting of brute-force indicators or anomalous out-of-hours authentications alongside file system changes.

---

## 4. Web Shell & Server Triage Module

* **Module Type:** File Ingest Module
* **Target Artifacts:** Apache (`/var/log/apache2/*`, `/var/log/httpd/*`), Nginx (`/var/log/nginx/*`), and web root directories (`/var/www/html/`, `/var/www/`, `/srv/www/`, and related paths).

### Description

Linux servers are high-value targets for web application exploitation, frequently resulting in web shell deployments for persistent remote command execution. This module applies a two-pronged validation check: it parses web server access logs for anomalous behavior and simultaneously evaluates files in web-accessible directories.

### DFIR Value

* **Log Pattern Matching:** Flags massive bursts of HTTP `404` errors (directory fuzzing) or URI query strings containing execution patterns (`whoami`, `cat /etc/passwd`, SQL injection strings).
* **Rogue Script Detection:** Automatically surfaces newly created or heavily obfuscated `.php`, `.jsp`, or `.py` files residing within the web root.

### Status

Initial version complete
