import java.util.logging.Level as Level
import jarray
from java.lang import String
from java.lang import System
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactory
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import ReadContentInputStream

class LinuxShellHistoryModuleFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None

    def getModuleDisplayName(self):
        return "Linux Shell History & Command Triage"

    def getModuleDescription(self):
        return "Parses Linux shell history, extracts execution timestamps, and identifies suspicious user activity."

    def getModuleVersionNumber(self):
        return "1.1.1"

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return LinuxShellHistoryFileIngestModule()


class LinuxShellHistoryFileIngestModule(FileIngestModule):
    def __init__(self):
        self.logger = Logger.getLogger("LinuxShellHistoryModule")
        # High-risk DFIR keywords/patterns to flag
        self.suspicious_keywords = ["wget", "curl", "chmod +x", "nc ", "base64", "shred", "history -c", "/dev/shm"]
        self.artifact_count = 0
        self.history_files_processed = 0

    def startUp(self, context):
        self.logger.log(Level.INFO, "Linux Shell History Module Ingest Started.")

    def process(self, file):
        # Filter for typical shell history naming patterns
        filename = file.getName().lower()
        if not (filename.endswith("_history") or filename == ".bash_history" or filename == ".zsh_history"):
            return IngestModule.ProcessResult.OK

        if file.isDir() or not file.isFile():
            return IngestModule.ProcessResult.OK

        # 1. Extract Username from the File Path
        username = self.extract_username(file.getParentPath())

        try:
            # Jython must use jarray for ReadContentInputStream.read(byte[]).
            file_size = int(file.getSize())
            inputStream = ReadContentInputStream(file)
            buffer = jarray.zeros(file_size, "b")
            total_read = 0
            while total_read < file_size:
                bytes_read = inputStream.read(buffer, total_read, file_size - total_read)
                if bytes_read <= 0:
                    break
                total_read += bytes_read
            # str(jarray) returns "array('b', [...])" — decode bytes to text instead.
            content = String(buffer, 0, total_read, "UTF-8").replace("\x00", "")
            lines = content.splitlines()
            self.history_files_processed += 1

            # Stateful Tracking Variables
            current_timestamp = None

            # 2. Sequential Analysis Loop
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Parse Epoch lines (e.g., "#1717004400")
                if line.startswith("#") and line[1:].isdigit():
                    current_timestamp = int(line[1:])
                    continue  # Hold timestamp and move to the next line containing the command

                # Process the Command Line
                command_line = line

                # Evaluate for suspicious keywords
                for keyword in self.suspicious_keywords:
                    if keyword in command_line:
                        # 3. Create Artifact with Timestamp (or Safety Net Fallback) and Username
                        self.create_blackboard_artifact(file, command_line, keyword, username, current_timestamp)

                # Safety Net Reset: Clear the timestamp after processing the command line.
                # If the next command lacks a timestamp, it correctly falls back to None/Null.
                current_timestamp = None

        except Exception as ex:
            self.logger.log(Level.SEVERE, "Error parsing history log for user: " + username, ex)

        return IngestModule.ProcessResult.OK

    def extract_username(self, parent_path):
        """
        Parses the absolute path to isolate the specific Linux user profile.
        """
        if not parent_path:
            return "Unknown"
        
        normalized_path = parent_path.lower()
        
        # Scenario A: Root user home directory
        if "/root" in normalized_path:
            return "root"
        
        # Scenario B: Standard user home directories (/home/username/)
        if "/home/" in normalized_path:
            parts = parent_path.split("/")
            try:
                # Path format is typically: /home/username/
                # Splitting item 0 is '', item 1 is 'home', item 2 is 'username'
                return parts[2]
            except Indexerror:
                return "Unknown_User"
                
        return "System/Service"

    def create_blackboard_artifact(self, file, command_line, matched_keyword, username, timestamp):
        """
        Generates structured hits visible in Autopsy's UI under Interesting Items.
        """
        try:
            # Using the standard Interesting File Hit artifact
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            
            # Attribute: Set Name
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, 
                "Linux Shell History Triage Module", "Suspicious Commands"
            ))
            
            # Attribute: Map Extracted Username
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_NAME, 
                "Linux Shell History Triage Module", username
            ))

            # Attribute: Description details
            description = "User [{0}] executed critical command: {1} (Matched: {2})".format(username, command_line, matched_keyword)
            art.addAttribute(BlackboardAttribute(
                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT, 
                "Linux Shell History Triage Module", description
            ))
            
            # Attribute: Epoch Timestamp & Safety Net Logic
            if timestamp is not None:
                # Autopsy TSK_DATETIME attribute expects UNIX Epoch in seconds
                art.addAttribute(BlackboardAttribute(
                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, 
                    "Linux Shell History Triage Module", timestamp
                ))
            # Safety Net: If timestamp is None, we intentionally omit the TSK_DATETIME attribute.
            # Autopsy will display the hit cleanly without throwing a NullPointerException or setting it to Jan 1, 1970.

            # Push up to the GUI layout engine
            Case.getCurrentCase().getServices().getBlackboard().postArtifact(art, "Linux Shell History Triage Module")
            self.artifact_count += 1

        except Exception as ex:
            self.logger.log(Level.SEVERE, "Failed to post shell history entry to blackboard.", ex)

    def shutDown(self):
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA,
            "Linux Shell History & Command Triage",
            "Posted " + str(self.artifact_count) + " suspicious commands from "
            + str(self.history_files_processed) + " history files.",
        )
        IngestServices.getInstance().postMessage(message)
        self.logger.log(Level.INFO, "Linux Shell History Module Ingest Completed.")