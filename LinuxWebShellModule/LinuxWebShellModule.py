import java.util.logging.Level as Level
import jarray
import re
from java.lang import String
from java.text import SimpleDateFormat
from java.util import Locale
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import ReadContentInputStream

MODULE_NAME = "Web Shell & Server Triage"
LOGGER_NAME = "LinuxWebShellModule"

SET_ACCESS = "Web Shell - Suspicious Access"
SET_FUZZING = "Web Shell - Directory Fuzzing"
SET_SCRIPT = "Web Shell - Suspicious Script"
SET_OBFUSCATED = "Web Shell - Obfuscated Script"

# Apache (Debian/Ubuntu) and httpd (RHEL/CentOS), plus Nginx log directories.
WEB_LOG_PATH_MARKERS = (
    "/var/log/apache2/",
    "/var/log/httpd/",
    "/var/log/nginx/",
)

# Common document roots and application publish paths on Linux web servers.
WEB_ROOT_PATH_MARKERS = (
    "/var/www/html/",
    "/var/www/",
    "/srv/www/",
    "/usr/share/nginx/html/",
    "/var/www/htdocs/",
)

WEB_SCRIPT_EXTENSIONS = (
    ".php",
    ".php3",
    ".php4",
    ".php5",
    ".phtml",
    ".phar",
    ".jsp",
    ".jspx",
    ".py",
    ".cgi",
    ".pl",
    ".asp",
    ".aspx",
)

# Suspicious web shell file names (basename without path).
SUSPICIOUS_SCRIPT_NAMES = (
    "shell.php",
    "cmd.php",
    "c99.php",
    "r57.php",
    "wso.php",
    "b374k.php",
    "alfa.php",
    "mini.php",
    "up.php",
    "uploader.php",
    "webshell.php",
    "backdoor.php",
    "eval-stdin.php",
)

# URI / query string indicators of exploitation or web shell use.
SUSPICIOUS_URI_PATTERNS = (
    {"label": "whoami probe", "pattern": re.compile(r"whoami", re.IGNORECASE)},
    {"label": "passwd read", "pattern": re.compile(r"/etc/passwd", re.IGNORECASE)},
    {"label": "shadow read", "pattern": re.compile(r"/etc/shadow", re.IGNORECASE)},
    {"label": "path traversal", "pattern": re.compile(r"\.\./\.\./")},
    {"label": "cmd parameter", "pattern": re.compile(r"[?&]cmd=", re.IGNORECASE)},
    {"label": "exec parameter", "pattern": re.compile(r"[?&]exec=", re.IGNORECASE)},
    {"label": "command parameter", "pattern": re.compile(r"[?&]command=", re.IGNORECASE)},
    {"label": "shell parameter", "pattern": re.compile(r"[?&]shell=", re.IGNORECASE)},
    {"label": "eval in URI", "pattern": re.compile(r"eval\s*\(", re.IGNORECASE)},
    {"label": "base64 in URI", "pattern": re.compile(r"base64_decode", re.IGNORECASE)},
    {"label": "union select", "pattern": re.compile(r"union\s+select", re.IGNORECASE)},
    {"label": "sql injection sleep", "pattern": re.compile(r"sleep\s*\(\s*\d+", re.IGNORECASE)},
    {"label": "php tag in URI", "pattern": re.compile(r"<\?php", re.IGNORECASE)},
    {"label": "system call in URI", "pattern": re.compile(r"system\s*\(", re.IGNORECASE)},
    {"label": "passthru in URI", "pattern": re.compile(r"passthru\s*\(", re.IGNORECASE)},
)

# Content patterns that suggest obfuscated server-side web shells.
OBFUSCATION_PATTERNS = (
    {"label": "base64_decode", "pattern": re.compile(r"base64_decode\s*\(", re.IGNORECASE)},
    {"label": "gzinflate", "pattern": re.compile(r"gzinflate\s*\(", re.IGNORECASE)},
    {"label": "gzuncompress", "pattern": re.compile(r"gzuncompress\s*\(", re.IGNORECASE)},
    {"label": "str_rot13", "pattern": re.compile(r"str_rot13\s*\(", re.IGNORECASE)},
    {"label": "eval(", "pattern": re.compile(r"eval\s*\(", re.IGNORECASE)},
    {"label": "assert(", "pattern": re.compile(r"assert\s*\(", re.IGNORECASE)},
    {"label": "shell_exec", "pattern": re.compile(r"shell_exec\s*\(", re.IGNORECASE)},
    {"label": "passthru", "pattern": re.compile(r"passthru\s*\(", re.IGNORECASE)},
    {"label": "system(", "pattern": re.compile(r"system\s*\(", re.IGNORECASE)},
    {"label": "exec(", "pattern": re.compile(r"exec\s*\(", re.IGNORECASE)},
    {"label": "proc_open", "pattern": re.compile(r"proc_open\s*\(", re.IGNORECASE)},
    {"label": "popen(", "pattern": re.compile(r"popen\s*\(", re.IGNORECASE)},
    {"label": "$_POST", "pattern": re.compile(r"\$_POST")},
    {"label": "$_REQUEST", "pattern": re.compile(r"\$_REQUEST")},
    {"label": "create_function", "pattern": re.compile(r"create_function\s*\(", re.IGNORECASE)},
    {"label": "preg_replace /e", "pattern": re.compile(r"preg_replace\s*\([^)]*/e", re.IGNORECASE)},
)

# Apache combined/common and Nginx default access log line.
ACCESS_LOG_LINE = re.compile(
    r'^(?P<remote>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+'
)

ACCESS_LOG_DATE_FORMAT = SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH)

# Minimum 404 responses from one client IP in a single log file to flag fuzzing.
FUZZING_404_THRESHOLD = 50

# Do not load entire multi-gigabyte logs into memory.
MAX_LOG_READ_BYTES = 50 * 1024 * 1024
MAX_SCRIPT_READ_BYTES = 1024 * 1024


class LinuxWebShellModuleFactory(IngestModuleFactoryAdapter):
    def getModuleDisplayName(self):
        return MODULE_NAME

    def getModuleDescription(self):
        return (
            "Parses Apache and Nginx access logs for exploitation indicators and scans "
            "web document roots for suspicious or obfuscated script files."
        )

    def getModuleVersionNumber(self):
        return "1.0.0"

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return LinuxWebShellFileIngestModule()


class LinuxWebShellFileIngestModule(FileIngestModule):
    def __init__(self):
        self.logger = Logger.getLogger(LOGGER_NAME)
        self.context = None
        self.blackboard = None
        self.artifact_count = 0
        self.access_logs_processed = 0
        self.scripts_scanned = 0

    def startUp(self, context):
        self.context = context
        self.blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        self.logger.log(Level.INFO, MODULE_NAME + " ingest started.")

    def shutDown(self):
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA,
            MODULE_NAME,
            "Posted " + str(self.artifact_count) + " web triage hits "
            + "(" + str(self.access_logs_processed) + " access logs, "
            + str(self.scripts_scanned) + " scripts scanned).",
        )
        IngestServices.getInstance().postMessage(message)
        self.logger.log(Level.INFO, MODULE_NAME + " ingest completed.")

    def process(self, file):
        if file.isDir() or not file.isFile():
            return IngestModule.ProcessResult.OK

        if self.is_access_log_file(file):
            self.process_access_log(file)
        elif self.is_web_script_file(file):
            self.process_web_script(file)

        return IngestModule.ProcessResult.OK

    def is_access_log_file(self, file):
        parent_path = self.normalize_path(file.getParentPath())
        if not parent_path:
            return False

        if not self.path_contains_marker(parent_path, WEB_LOG_PATH_MARKERS):
            return False

        name = file.getName().lower()
        if name.endswith(".gz"):
            return False

        if name in ("access.log", "access_log"):
            return True
        if name.startswith("access.log.") and not name.endswith(".gz"):
            return True
        if name.startswith("access_log.") and not name.endswith(".gz"):
            return True

        return False

    def is_web_script_file(self, file):
        parent_path = self.normalize_path(file.getParentPath())
        if not parent_path:
            return False

        if not self.path_contains_marker(parent_path, WEB_ROOT_PATH_MARKERS):
            return False

        name = file.getName().lower()
        for extension in WEB_SCRIPT_EXTENSIONS:
            if name.endswith(extension):
                return True

        return False

    def normalize_path(self, path):
        if not path:
            return ""
        normalized = path.lower()
        if not normalized.endswith("/"):
            normalized = normalized + "/"
        return normalized

    def path_contains_marker(self, normalized_path, markers):
        for marker in markers:
            if marker in normalized_path:
                return True
        return False

    def read_file_text(self, file, max_bytes):
        try:
            file_size = int(file.getSize())
            if file_size <= 0:
                return ""

            read_size = file_size
            if read_size > max_bytes:
                read_size = max_bytes
                self.logger.log(
                    Level.WARNING,
                    "Truncating read of " + file.getParentPath() + file.getName()
                    + " to " + str(max_bytes) + " bytes.",
                )

            input_stream = ReadContentInputStream(file)
            buffer = jarray.zeros(read_size, "b")
            total_read = 0
            while total_read < read_size:
                bytes_read = input_stream.read(buffer, total_read, read_size - total_read)
                if bytes_read <= 0:
                    break
                total_read += bytes_read

            if total_read <= 0:
                return ""

            return String(buffer, 0, total_read, "UTF-8").replace("\x00", "")
        except Exception as ex:
            self.logger.log(
                Level.WARNING,
                "Unable to read file: " + file.getParentPath() + file.getName(),
                ex,
            )
            return None

    def process_access_log(self, file):
        content = self.read_file_text(file, MAX_LOG_READ_BYTES)
        if content is None:
            return

        self.access_logs_processed += 1
        not_found_by_ip = {}
        suspicious_hits = []

        for line in content.splitlines():
            if self.context.isJobCancelled():
                return

            match = ACCESS_LOG_LINE.match(line.strip())
            if match is None:
                continue

            remote_ip = match.group("remote")
            status_code = match.group("status")
            request = match.group("request")
            timestamp_text = match.group("timestamp")

            if status_code == "404":
                count = not_found_by_ip.get(remote_ip, 0) + 1
                not_found_by_ip[remote_ip] = count

            uri = self.extract_request_uri(request)
            if not uri:
                continue

            for pattern in SUSPICIOUS_URI_PATTERNS:
                if pattern["pattern"].search(uri):
                    suspicious_hits.append({
                        "remote_ip": remote_ip,
                        "uri": uri,
                        "request": request,
                        "status": status_code,
                        "timestamp_text": timestamp_text,
                        "match_label": pattern["label"],
                        "line": line.strip(),
                    })
                    break

        for hit in suspicious_hits:
            self.post_hit(
                file,
                SET_ACCESS,
                "Suspicious HTTP request",
                hit["remote_ip"],
                hit["uri"],
                hit["status"],
                hit["timestamp_text"],
                "Matched indicator: " + hit["match_label"] + " | Raw: " + hit["line"],
            )

        for remote_ip, count in not_found_by_ip.items():
            if count >= FUZZING_404_THRESHOLD:
                comment = (
                    "Source IP generated " + str(count) + " HTTP 404 responses in "
                    + file.getParentPath() + file.getName()
                    + " (threshold " + str(FUZZING_404_THRESHOLD) + ")."
                )
                self.post_hit(
                    file,
                    SET_FUZZING,
                    "Directory fuzzing burst",
                    remote_ip,
                    None,
                    "404",
                    None,
                    comment,
                )

    def extract_request_uri(self, request):
        if not request:
            return ""

        parts = request.split(None, 2)
        if len(parts) < 2:
            return request

        return parts[1]

    def process_web_script(self, file):
        self.scripts_scanned += 1
        name = file.getName().lower()
        parent_path = file.getParentPath() if file.getParentPath() else ""

        if name in SUSPICIOUS_SCRIPT_NAMES:
            self.post_hit(
                file,
                SET_SCRIPT,
                "Known web shell filename",
                None,
                parent_path + file.getName(),
                None,
                None,
                "Filename matches a commonly abused web shell name: " + name,
            )

        if self.is_single_letter_php(name):
            self.post_hit(
                file,
                SET_SCRIPT,
                "Single-letter PHP script",
                None,
                parent_path + file.getName(),
                None,
                None,
                "Short PHP filename in web root: " + name,
            )

        content = self.read_file_text(file, MAX_SCRIPT_READ_BYTES)
        if content is None or not content.strip():
            return

        matched_labels = []
        for pattern in OBFUSCATION_PATTERNS:
            if pattern["pattern"].search(content):
                matched_labels.append(pattern["label"])

        if len(matched_labels) >= 2:
            preview = content[:300].replace("\n", " ").replace("\r", " ")
            comment = (
                "Obfuscation indicators: " + ", ".join(matched_labels)
                + " | Preview: " + preview
            )
            self.post_hit(
                file,
                SET_OBFUSCATED,
                "Obfuscated web script",
                None,
                parent_path + file.getName(),
                None,
                None,
                comment,
            )
        elif len(matched_labels) == 1 and self.looks_like_one_liner(content):
            preview = content[:300].replace("\n", " ").replace("\r", " ")
            comment = (
                "Obfuscation indicator: " + matched_labels[0]
                + " in compact script | Preview: " + preview
            )
            self.post_hit(
                file,
                SET_OBFUSCATED,
                "Obfuscated web script",
                None,
                parent_path + file.getName(),
                None,
                None,
                comment,
            )

    def is_single_letter_php(self, lower_name):
        if not lower_name.endswith(".php"):
            return False
        base = lower_name[:-4]
        return len(base) == 1 and base.isalpha()

    def looks_like_one_liner(self, content):
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        if len(lines) <= 3 and len(content) > 80:
            return True
        if len(content) > 200 and content.count(";") >= 3 and "\n" not in content[:200]:
            return True
        return False

    def parse_access_log_timestamp(self, timestamp_text):
        if not timestamp_text:
            return None
        try:
            parsed = ACCESS_LOG_DATE_FORMAT.parse(timestamp_text)
            return int(parsed.getTime() / 1000)
        except Exception:
            return None

    def post_hit(
        self,
        file,
        set_name,
        event_name,
        remote_ip,
        uri,
        status_code,
        timestamp_text,
        comment,
    ):
        try:
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                MODULE_NAME,
                set_name,
            ))
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME,
                MODULE_NAME,
                event_name,
            ))
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT,
                MODULE_NAME,
                comment,
            ))

            if remote_ip:
                art.addAttribute(BlackboardAttribute(
                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_IP_ADDRESS,
                    MODULE_NAME,
                    remote_ip,
                ))

            if uri:
                art.addAttribute(BlackboardAttribute(
                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME,
                    MODULE_NAME,
                    uri,
                ))

            if status_code:
                art.addAttribute(BlackboardAttribute(
                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DESCRIPTION,
                    MODULE_NAME,
                    "HTTP " + status_code,
                ))

            timestamp = self.parse_access_log_timestamp(timestamp_text)
            if timestamp is not None:
                art.addAttribute(BlackboardAttribute(
                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME,
                    MODULE_NAME,
                    timestamp,
                ))

            job_id = self.context.getJobId() if self.context is not None else None
            if job_id is not None:
                self.blackboard.postArtifact(art, MODULE_NAME, job_id)
            else:
                Case.getCurrentCase().getServices().getBlackboard().postArtifact(art, MODULE_NAME)

            self.artifact_count += 1
        except Blackboard.BlackboardException as ex:
            self.logger.log(Level.SEVERE, "Failed to post web triage artifact.", ex)
        except Exception as ex:
            self.logger.log(Level.SEVERE, "Unexpected error posting web triage artifact.", ex)
