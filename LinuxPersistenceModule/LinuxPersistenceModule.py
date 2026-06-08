import java.util.logging.Level as Level
import jarray
import re
from java.lang import String
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import ReadContentInputStream
MODULE_NAME = "Linux Persistence & Auto-Start Analyzer"
SET_NAME = "Linux Persistence"
SUSPICIOUS_SET_NAME = "Linux Persistence - Suspicious Paths"

# Execution paths outside standard install locations are common in malware persistence.
SUSPICIOUS_PATH_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
)

# Known Linux persistence locations queried via the case database (FileManager).
PERSISTENCE_QUERIES = (
    {"label": "system crontab", "method": "findFiles", "fileName": "crontab", "parentSubString": "/etc"},
    {"label": "rc.local", "method": "findFiles", "fileName": "rc.local", "parentSubString": "/etc"},
    {"label": "cron drop-ins", "method": "findByParentPath", "parentPath": "/etc/cron.d"},
    {"label": "user crontabs (crontabs)", "method": "findByParentPath", "parentPath": "/var/spool/cron/crontabs"},
    {"label": "user crontabs (cron)", "method": "findByParentPath", "parentPath": "/var/spool/cron"},
    {"label": "systemd units (etc)", "method": "findByParentPath", "parentPath": "/etc/systemd/system"},
    {"label": "systemd units (lib)", "method": "findByParentPath", "parentPath": "/usr/lib/systemd/system"},
)


class LinuxPersistenceModuleFactory(IngestModuleFactoryAdapter):
    def getModuleDisplayName(self):
        return MODULE_NAME

    def getModuleDescription(self):
        return (
            "Finds Linux auto-start and persistence mechanisms (cron, systemd, rc.local), "
            "extracts execution details, and flags binaries running from unusual directories."
        )

    def getModuleVersionNumber(self):
        return "1.0.2"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return LinuxPersistenceDataSourceIngestModule()


class LinuxPersistenceDataSourceIngestModule(DataSourceIngestModule):
    def __init__(self):
        self.logger = Logger.getLogger("LinuxPersistenceModule")
        self.context = None
        self.blackboard = None
        self.file_manager = None
        self.artifact_count = 0

    def startUp(self, context):
        self.context = context
        self.blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        self.file_manager = Case.getCurrentCase().getServices().getFileManager()
        self.logger.log(Level.INFO, MODULE_NAME + " ingest started.")

    def process(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()

        if self.context.isJobCancelled():
            return IngestModule.ProcessResult.OK

        files_to_process = self.collect_persistence_files(dataSource)
        total_files = len(files_to_process)

        self.logger.log(Level.INFO, "Found " + str(total_files) + " candidate persistence files.")
        progressBar.switchToDeterminate(total_files)

        processed = 0
        for abstract_file in files_to_process:
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            try:
                self.process_persistence_file(abstract_file)
            except Exception as ex:
                self.logger.log(
                    Level.SEVERE,
                    "Failed to process persistence file: " + abstract_file.getParentPath() + abstract_file.getName(),
                    ex,
                )

            processed += 1
            progressBar.progress(processed)

        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA,
            MODULE_NAME,
            "Posted " + str(self.artifact_count) + " persistence entries from " + str(total_files) + " files.",
        )
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK

    def shutDown(self):
        self.logger.log(Level.INFO, MODULE_NAME + " ingest completed.")

    def collect_persistence_files(self, dataSource):
        seen_ids = {}
        collected = []
        data_source_id = dataSource.getId()

        for query in PERSISTENCE_QUERIES:
            if self.context.isJobCancelled():
                break

            try:
                if query["method"] == "findFiles":
                    matches = self.file_manager.findFiles(
                        dataSource,
                        query["fileName"],
                        query["parentSubString"],
                    )
                else:
                    matches = self.file_manager.findFilesByParentPath(
                        data_source_id,
                        query["parentPath"],
                    )
            except Exception as ex:
                self.logger.log(Level.WARNING, "Query failed for " + query["label"] + ": " + str(ex))
                continue

            for abstract_file in matches:
                if abstract_file.isDir() or not abstract_file.isFile():
                    continue

                file_id = abstract_file.getId()
                if file_id in seen_ids:
                    continue

                if not self.is_relevant_persistence_file(abstract_file):
                    continue

                seen_ids[file_id] = True
                collected.append(abstract_file)

        return collected

    def is_relevant_persistence_file(self, abstract_file):
        name = abstract_file.getName().lower()
        parent_path = abstract_file.getParentPath().lower()

        if name == "crontab" and "/etc" in parent_path:
            return True
        if name == "rc.local":
            return True
        if "/etc/cron.d" in parent_path:
            return True
        if "/var/spool/cron/crontabs" in parent_path:
            return True
        if parent_path.endswith("/var/spool/cron/") or parent_path.endswith("/var/spool/cron"):
            # RHEL-style per-user crontabs live directly under /var/spool/cron/<user>.
            if name in ("crontabs",) or name.startswith("."):
                return False
            return True

        if parent_path.endswith("/var/spool/cron/crontabs/") or parent_path.endswith("/var/spool/cron/crontabs"):
            return True

        if "/etc/systemd/system" in parent_path or "/usr/lib/systemd/system" in parent_path:
            return name.endswith(".service") or name.endswith(".timer")

        return False

    def process_persistence_file(self, abstract_file):
        content = self.read_file_text(abstract_file)
        if content is None:
            return

        parent_path = abstract_file.getParentPath()
        file_name = abstract_file.getName()
        normalized_parent = parent_path.lower()
        normalized_name = file_name.lower()

        if normalized_name == "crontab" and "/etc" in normalized_parent and "/cron.d" not in normalized_parent:
            self.parse_system_crontab(abstract_file, content, "Cron (system crontab)")
            return

        if "/etc/cron.d" in normalized_parent:
            self.parse_system_crontab(abstract_file, content, "Cron (drop-in)")
            return

        if "/var/spool/cron" in normalized_parent:
            username = self.extract_cron_username(file_name, normalized_parent)
            self.parse_user_crontab(abstract_file, content, username)
            return

        vendor_systemd = "/usr/lib/systemd/system" in normalized_parent

        if normalized_name.endswith(".service"):
            self.parse_systemd_service(abstract_file, content, vendor_systemd)
            return

        if normalized_name.endswith(".timer"):
            self.parse_systemd_timer(abstract_file, content, vendor_systemd)
            return

        if normalized_name == "rc.local":
            self.parse_rc_local(abstract_file, content)

    def read_file_text(self, abstract_file):
        try:
            file_size = abstract_file.getSize()
            if file_size <= 0:
                return ""

            # Jython must use jarray for ReadContentInputStream.read(byte[]).
            input_stream = ReadContentInputStream(abstract_file)
            buffer = jarray.zeros(int(file_size), "b")
            total_read = 0
            while total_read < file_size:
                bytes_read = input_stream.read(buffer, total_read, int(file_size) - total_read)
                if bytes_read <= 0:
                    break
                total_read += bytes_read

            if total_read <= 0:
                return ""

            # str(jarray) returns "array('b', [...])" - decode bytes to text instead.
            # Debian user crontabs may include null-byte padding before the text body.
            return String(buffer, 0, total_read, "UTF-8").replace("\x00", "")
        except Exception as ex:
            self.logger.log(
                Level.WARNING,
                "Unable to read file: " + abstract_file.getParentPath() + abstract_file.getName(),
                ex,
            )
            return None

    def parse_system_crontab(self, abstract_file, content, mechanism):
        for line in content.splitlines():
            entry = self.parse_system_crontab_line(line)
            if entry is None:
                continue

            schedule, username, command = entry
            self.post_persistence_entry(
                abstract_file,
                mechanism,
                command,
                username,
                schedule,
                "System crontab entry",
            )

    def parse_system_crontab_line(self, line):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None

        if stripped.startswith("@"):
            parts = stripped.split(None, 2)
            if len(parts) < 3:
                return None
            return parts[0], parts[1], parts[2]

        parts = stripped.split()
        if len(parts) < 7:
            return None

        schedule = " ".join(parts[0:5])
        username = parts[5]
        command = " ".join(parts[6:])
        return schedule, username, command

    def parse_user_crontab(self, abstract_file, content, username):
        for line in content.splitlines():
            entry = self.parse_user_crontab_line(line, username)
            if entry is None:
                continue

            schedule, owner, command = entry
            self.post_persistence_entry(
                abstract_file,
                "Cron (user crontab)",
                command,
                owner,
                schedule,
                "User crontab entry",
            )

    def parse_user_crontab_line(self, line, username):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None

        if "=" in stripped and not stripped.startswith("@"):
            # Environment assignments such as CRON_TZ=...
            return None

        if stripped.startswith("@"):
            parts = stripped.split(None, 1)
            if len(parts) < 2:
                return None
            return parts[0], username, parts[1]

        parts = stripped.split()
        if len(parts) < 6:
            return None

        schedule = " ".join(parts[0:5])
        command = " ".join(parts[5:])
        return schedule, username, command

    def parse_systemd_service(self, abstract_file, content, vendor_unit):
        unit_name = abstract_file.getName()
        service_user = None
        current_section = None

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].strip().lower()
                continue

            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip().lower()
            value = value.strip()

            if current_section == "service" and key == "user":
                service_user = value
            elif current_section == "service" and key in ("execstart", "execstartpre", "execstartpost", "execreload"):
                if vendor_unit and not self.is_suspicious_command(value)[0]:
                    continue

                owner = service_user if service_user else "root"
                schedule = key
                detail = "Systemd service unit [{0}]".format(unit_name)
                self.post_persistence_entry(
                    abstract_file,
                    "Systemd service",
                    value,
                    owner,
                    schedule,
                    detail,
                )

    def parse_systemd_timer(self, abstract_file, content, vendor_unit):
        if vendor_unit:
            # Vendor timer units are rarely investigative leads unless tied to a custom service path.
            return

        unit_name = abstract_file.getName()
        current_section = None

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].strip().lower()
                continue

            if "=" not in line or current_section != "timer":
                continue

            key, value = line.split("=", 1)
            key = key.strip().lower()
            value = value.strip()

            if key in ("oncalendar", "onbootsec", "onunitactivesec", "onstartupsec"):
                detail = "Systemd timer unit [{0}]".format(unit_name)
                self.post_persistence_entry(
                    abstract_file,
                    "Systemd timer",
                    value,
                    "system",
                    key,
                    detail,
                )

    def parse_rc_local(self, abstract_file, content):
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped in ("exit 0", "exit"):
                continue

            self.post_persistence_entry(
                abstract_file,
                "rc.local",
                stripped,
                "root",
                "boot",
                "Legacy boot script command",
            )

    def extract_cron_username(self, file_name, parent_path):
        if "/crontabs/" in parent_path or parent_path.endswith("/crontabs"):
            return file_name

        # RHEL stores user crontabs as /var/spool/cron/<username>
        if "/var/spool/cron/" in parent_path:
            return file_name

        return "unknown"

    def is_suspicious_command(self, command):
        normalized = command.lower()
        for prefix in SUSPICIOUS_PATH_PREFIXES:
            if prefix in normalized:
                return True, prefix
        return False, None

    def extract_primary_executable(self, command):
        if not command:
            return ""

        cleaned = command.strip()
        if cleaned.startswith("@"):
            parts = cleaned.split(None, 2)
            if len(parts) >= 3:
                cleaned = parts[2]
            elif len(parts) == 2:
                cleaned = parts[1]

        cleaned = re.sub(r"^\s+", "", cleaned)
        if cleaned.startswith("/bin/sh") or cleaned.startswith("/bin/bash"):
            parts = cleaned.split(None, 2)
            if len(parts) >= 3:
                cleaned = parts[2]

        token = cleaned.split(None, 1)[0]
        return token.strip("\"'")

    def post_persistence_entry(self, abstract_file, mechanism, command, username, schedule, detail):
        suspicious, matched_prefix = self.is_suspicious_command(command)
        set_name = SUSPICIOUS_SET_NAME if suspicious else SET_NAME

        program = self.extract_primary_executable(command)
        comment_parts = [
            detail,
            "Mechanism: " + mechanism,
            "Schedule: " + schedule,
            "User: " + username,
            "Command: " + command,
        ]
        if suspicious:
            comment_parts.append("Suspicious path prefix matched: " + matched_prefix)

        comment = " | ".join(comment_parts)

        try:
            art = abstract_file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                MODULE_NAME,
                set_name,
            ))
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME,
                MODULE_NAME,
                username,
            ))
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME,
                MODULE_NAME,
                program if program else command,
            ))
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,
                MODULE_NAME,
                comment,
            ))
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME,
                MODULE_NAME,
                mechanism,
            ))

            self.blackboard.postArtifact(art, MODULE_NAME, self.context.getJobId())
            self.artifact_count += 1
        except Blackboard.BlackboardException as ex:
            self.logger.log(Level.SEVERE, "Failed to post persistence artifact.", ex)
        except Exception as ex:
            self.logger.log(Level.SEVERE, "Unexpected error posting persistence artifact.", ex)
