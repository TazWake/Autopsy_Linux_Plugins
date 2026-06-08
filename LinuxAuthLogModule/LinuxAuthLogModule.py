import java.util.logging.Level as Level
import re
from java.text import SimpleDateFormat
from java.util import Arrays
from java.util import Calendar
from java.util import Locale
from java.util import TimeZone
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import Score

MODULE_NAME = "SSH & Authentication Log Parser"
SET_NAME = "Linux Authentication"
SET_FAILED = "Linux Authentication - Failed Logins"
SET_SUDO = "Linux Authentication - Sudo"
SET_ACCOUNT = "Linux Authentication - Account Changes"
SET_SSH_SUCCESS = "Linux Authentication - SSH Success"

TARGET_LOG_NAMES = ("auth.log", "secure")

# Syslog lines begin with a timestamp, optional hostname, then "process[pid]:" or "process:".
SYSLOG_PREFIX = re.compile(
    r"^(?:"
    r"(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"|"
    r"(?P<traditional>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r")\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<body>.+)$"
)

ISO_DATE_FORMATS = (
    SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX"),
    SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSSX"),
    SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss"),
    SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSS"),
)

TRADITIONAL_DATE_FORMAT = SimpleDateFormat("yyyy MMM dd HH:mm:ss", Locale.ENGLISH)


class LinuxAuthLogModuleFactory(IngestModuleFactoryAdapter):
    def getModuleDisplayName(self):
        return MODULE_NAME

    def getModuleDescription(self):
        return (
            "Parses Linux auth.log and secure logs for SSH logins, failed authentications, "
            "sudo usage, and account or group changes."
        )

    def getModuleVersionNumber(self):
        return "1.0.0"

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return LinuxAuthLogFileIngestModule()


class LinuxAuthLogFileIngestModule(FileIngestModule):
    def __init__(self):
        self.logger = Logger.getLogger("LinuxAuthLogModule")
        self.context = None
        self.blackboard = None
        self.event_patterns = self.build_event_patterns()

    def startUp(self, context):
        self.context = context
        self.blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        self.logger.log(Level.INFO, MODULE_NAME + " ingest started.")

    def shutDown(self):
        self.logger.log(Level.INFO, MODULE_NAME + " ingest completed.")

    def process(self, file):
        if file.isDir() or not file.isFile():
            return IngestModule.ProcessResult.OK

        if not self.is_target_log_file(file):
            return IngestModule.ProcessResult.OK

        try:
            content = self.read_file_text(file)
            if content is None:
                return IngestModule.ProcessResult.OK

            for line in content.splitlines():
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                self.parse_log_line(file, line)

        except Exception as ex:
            self.logger.log(
                Level.SEVERE,
                "Error parsing authentication log: " + file.getParentPath() + file.getName(),
                ex,
            )

        return IngestModule.ProcessResult.OK

    def is_target_log_file(self, file):
        parent_path = file.getParentPath().lower() if file.getParentPath() else ""
        if "/var/log" not in parent_path:
            return False

        name = file.getName().lower()
        if name in TARGET_LOG_NAMES:
            return True
        if name.startswith("auth.log.") and not name.endswith(".gz"):
            return True
        if name.startswith("secure-") or name.startswith("secure."):
            if not name.endswith(".gz"):
                return True

        return False

    def read_file_text(self, file):
        try:
            file_size = file.getSize()
            if file_size <= 0:
                return ""

            input_stream = ReadContentInputStream(file)
            buffer = bytearray(file_size)
            input_stream.read(buffer)
            return str(buffer)
        except Exception as ex:
            self.logger.log(
                Level.WARNING,
                "Unable to read log file: " + file.getParentPath() + file.getName(),
                ex,
            )
            return None

    def build_event_patterns(self):
        return (
            {
                "event_type": "SSH Login Success",
                "set_name": SET_SSH_SUCCESS,
                "status": "Success",
                "score": Score.SCORE_NONE,
                "regex": re.compile(
                    r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2: (?P<key>.+))?"
                ),
            },
            {
                "event_type": "SSH Login Failed (invalid user)",
                "set_name": SET_FAILED,
                "status": "Failed",
                "score": Score.SCORE_LIKELY_NOTABLE,
                "regex": re.compile(
                    r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
                ),
            },
            {
                "event_type": "SSH Login Failed",
                "set_name": SET_FAILED,
                "status": "Failed",
                "score": Score.SCORE_LIKELY_NOTABLE,
                "regex": re.compile(
                    r"Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
                ),
            },
            {
                "event_type": "SSH Invalid User",
                "set_name": SET_FAILED,
                "status": "Failed",
                "score": Score.SCORE_LIKELY_NOTABLE,
                "regex": re.compile(
                    r"Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
                ),
            },
            {
                "event_type": "PAM Authentication Failure",
                "set_name": SET_FAILED,
                "status": "Failed",
                "score": Score.SCORE_LIKELY_NOTABLE,
                "regex": re.compile(
                    r"authentication failure;.*(?:rhost=| rhost=)(?P<ip>\S+)"
                ),
            },
            {
                "event_type": "Sudo Command",
                "set_name": SET_SUDO,
                "status": "Success",
                "score": Score.SCORE_NONE,
                "regex": re.compile(
                    r"sudo:\s+(?P<caller>\S+)\s*:\s*.*USER=(?P<user>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
                ),
            },
            {
                "event_type": "User Created",
                "set_name": SET_ACCOUNT,
                "status": "Created",
                "score": Score.SCORE_LIKELY_NOTABLE,
                "regex": re.compile(r"new user: name=(?P<user>\S+),"),
            },
            {
                "event_type": "Group Created",
                "set_name": SET_ACCOUNT,
                "status": "Created",
                "score": Score.SCORE_LIKELY_NOTABLE,
                "regex": re.compile(r"new group: name=(?P<name>\S+),"),
            },
            {
                "event_type": "Group Added",
                "set_name": SET_ACCOUNT,
                "status": "Created",
                "score": Score.SCORE_LIKELY_NOTABLE,
                "regex": re.compile(r"group added to (?P<target>\S+): name=(?P<name>\S+)"),
            },
            {
                "event_type": "User Added to Group",
                "set_name": SET_ACCOUNT,
                "status": "Modified",
                "score": Score.SCORE_LIKELY_NOTABLE,
                "regex": re.compile(r"add '(?P<user>\S+)' to group '(?P<group>\S+)'"),
            },
        )

    def parse_log_line(self, file, line):
        stripped = line.strip()
        if not stripped:
            return

        syslog_match = SYSLOG_PREFIX.match(stripped)
        if not syslog_match:
            return

        timestamp = self.parse_syslog_timestamp(
            syslog_match.group("iso"),
            syslog_match.group("traditional"),
            file,
        )
        hostname = syslog_match.group("host")
        body = syslog_match.group("body")

        for pattern in self.event_patterns:
            match = pattern["regex"].search(body)
            if match is None:
                continue

            groups = match.groupdict()
            target_user = groups.get("user")
            if target_user is None:
                target_user = groups.get("name")
            if target_user is None:
                target_user = groups.get("caller")

            source_ip = groups.get("ip")
            port = groups.get("port")
            command = groups.get("command")
            key_fingerprint = groups.get("key")
            group_name = groups.get("group")
            caller = groups.get("caller")
            auth_method = groups.get("method")

            self.post_auth_event(
                file,
                pattern["event_type"],
                pattern["set_name"],
                pattern["status"],
                pattern["score"],
                target_user,
                source_ip,
                hostname,
                timestamp,
                stripped,
                port=port,
                command=command,
                key_fingerprint=key_fingerprint,
                group_name=group_name,
                caller=caller,
                auth_method=auth_method,
            )
            return

    def parse_syslog_timestamp(self, iso_value, traditional_value, file):
        if iso_value:
            epoch = self.parse_iso_timestamp(iso_value)
            if epoch is not None:
                return epoch

        if traditional_value:
            return self.parse_traditional_timestamp(traditional_value, file)

        return None

    def parse_iso_timestamp(self, iso_value):
        normalized = iso_value
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+0000"
        elif len(normalized) > 6 and normalized[-3] == ":":
            normalized = normalized[:-3] + normalized[-2:]

        for date_format in ISO_DATE_FORMATS:
            try:
                parsed = date_format.parse(normalized)
                return int(parsed.getTime() / 1000)
            except Exception:
                continue

        return None

    def parse_traditional_timestamp(self, traditional_value, file):
        try:
            reference_epoch = file.getMtime()
            calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
            calendar.setTimeInMillis(reference_epoch * 1000)
            year = calendar.get(Calendar.YEAR)

            parsed = TRADITIONAL_DATE_FORMAT.parse(
                str(year) + " " + traditional_value
            )
            return int(parsed.getTime() / 1000)
        except Exception:
            return None

    def post_auth_event(
        self,
        file,
        event_type,
        set_name,
        status,
        score,
        target_user,
        source_ip,
        hostname,
        timestamp,
        raw_line,
        port=None,
        command=None,
        key_fingerprint=None,
        group_name=None,
        caller=None,
        auth_method=None,
    ):
        comment_parts = [
            "Status: " + status,
            "Event: " + event_type,
        ]
        if target_user:
            comment_parts.append("User: " + target_user)
        if caller and caller != target_user:
            comment_parts.append("Caller: " + caller)
        if source_ip:
            comment_parts.append("Source IP: " + source_ip)
        if port:
            comment_parts.append("Port: " + port)
        if auth_method:
            comment_parts.append("Method: " + auth_method)
        if group_name:
            comment_parts.append("Group: " + group_name)
        if command:
            comment_parts.append("Command: " + command)
        if key_fingerprint:
            comment_parts.append("Key: " + key_fingerprint)
        comment_parts.append("Raw: " + raw_line)

        comment = " | ".join(comment_parts)
        attributes = []

        attributes.append(
            BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                MODULE_NAME,
                set_name,
            )
        )
        attributes.append(
            BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME,
                MODULE_NAME,
                event_type,
            )
        )
        attributes.append(
            BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DESCRIPTION,
                MODULE_NAME,
                status,
            )
        )
        attributes.append(
            BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,
                MODULE_NAME,
                comment,
            )
        )

        if target_user:
            attributes.append(
                BlackboardAttribute(
                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME,
                    MODULE_NAME,
                    target_user,
                )
            )

        if source_ip:
            attributes.append(
                BlackboardAttribute(
                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_IP_ADDRESS,
                    MODULE_NAME,
                    source_ip,
                )
            )

        if hostname:
            attributes.append(
                BlackboardAttribute(
                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_HOST,
                    MODULE_NAME,
                    hostname,
                )
            )

        if timestamp is not None:
            attributes.append(
                BlackboardAttribute(
                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME,
                    MODULE_NAME,
                    timestamp,
                )
            )

        try:
            analysis_result = file.newAnalysisResult(
                BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                score,
                None,
                event_type,
                None,
                Arrays.asList(attributes),
            ).getAnalysisResult()

            job_id = self.context.getJobId() if self.context is not None else None
            if job_id is not None:
                self.blackboard.postArtifact(analysis_result, MODULE_NAME, job_id)
            else:
                Case.getCurrentCase().getServices().getBlackboard().postArtifact(
                    analysis_result,
                    MODULE_NAME,
                )
        except Blackboard.BlackboardException as ex:
            self.logger.log(Level.SEVERE, "Failed to post authentication event.", ex)
        except Exception as ex:
            self.logger.log(Level.SEVERE, "Unexpected error posting authentication event.", ex)
