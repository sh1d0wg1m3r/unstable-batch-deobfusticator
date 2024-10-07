#!/usr/bin/env python3

import argparse
import base64
import copy
import hashlib
import os
import platform
import re
import shlex
import shutil
import string
import subprocess
import tempfile
import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple, Generator, Optional
from urllib.parse import urlparse

# =============================================================================
# Constants
# =============================================================================

# Characters that need special handling in batch commands
QUOTED_CHARS = ["|", ">", "<", '"', "^", "&"]

# Regular expressions for detecting PowerShell commands
ENC_RE = re.compile(
    r"(?i)(?:-|/)e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?)?)?)?)?)?)?)?$"
)
PWR_CMD_RE = re.compile(
    r"(?i)(?:-|/)c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?$"
)

# Rare LOLBAS (Living Off the Land Binaries and Scripts) commands
RARE_LOLBAS = [
    "forfiles",
    "bash",
    "scriptrunner",
    "syncappvpublishingserver",
    "hh.exe",
    "msbuild",
    "regsvcs",
    "regasm",
    "installutil",
    "ieexec",
    "msxsl",
    "odbcconf",
    "sqldumper",
    "pcalua",
    "appvlp",
    "runscripthelper",
    "infdefaultinstall",
    "diskshadow",
    "msdt",
    "regsvr32",
]

# Regular expressions for parsing complex batch statements
IF_STATEMENT_RE = re.compile(
    r"(?P<conditional>(?P<if_statement>if)\s+(not\s+)?"
    r"(?P<type>errorlevel\s+\d+\s+|exist\s+(\".*\"|[^\s]+)\s+|.+?==.+?\s+|"
    r"(\/i\s+)?[^\s]+\s+(equ|neq|lss|leq|gtr|geq)\s+[^\s]+\s+|cmdextversion\s+\d\s+|defined\s+[^\s]+\s+)"
    r"(?P<open_paren>\()?)(?P<true_statement>[^\)]*)(?P<close_paren>\))?"
    r"(\s+else\s+(\()?\s*(?P<false_statement>[^\)]*)(\))?)?",
    re.IGNORECASE,
)

FOR_STATEMENT_RE = re.compile(
    r"(?P<loop>(?P<for_statement>for)\s+"
    r"(?P<parameter>.+)"
    r"\s+IN\s+\((?P<in_set>[^\)]+)\)"
    r"\s+DO\s+"
    r"(?P<open_paren>\()?)(?P<command>[^\)]*)(?P<close_paren>\))?",
    re.IGNORECASE,
)

CMD_COMMAND_RE = re.compile(
    r"cmd(.exe)?\s*((\/A|\/U|\/Q|\/D)\s+|((\/E|\/F|\/V):(ON|OFF))\s*)*(\/c|\/r)\s*(?P<cmd>.*)",
    re.IGNORECASE,
)

START_RE = re.compile(
    r"start(.exe)?"
    r"(\/min|\/max|\/wait|\/low|\/normal|\/abovenormal|\/belownormal|\/high|\/realtime|\/b|\/i|\/w|\s+)*"
    r"(?P<cmd>.*)",
    re.IGNORECASE,
)

# =============================================================================
# Logging Configuration
# =============================================================================

def setup_logging(log_file: Path = Path("batch_interpreter.log")):
    """
    Sets up the logging configuration.

    Args:
        log_file (Path, optional): Path to the log file.
    """
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Formatter
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    # File handler for all logs
    fh = logging.FileHandler(log_file, mode='w', encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Stream handler for console output
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

# =============================================================================
# Utility Functions
# =============================================================================

def compute_sha256(content: bytes) -> str:
    """
    Computes the SHA-256 hash of the given content.

    Args:
        content (bytes): Data to hash.

    Returns:
        str: SHA-256 hash as a hexadecimal string.
    """
    sha256hash = hashlib.sha256(content).hexdigest()
    return sha256hash

def move_file(src: Path, dst: Path) -> None:
    """
    Moves a file from source to destination.

    Args:
        src (Path): Source file path.
        dst (Path): Destination file path.
    """
    shutil.move(str(src), str(dst))

def create_temp_file(suffix: str = "", prefix: str = "temp_", dir: Optional[Path] = None) -> Tuple[int, Path]:
    """
    Creates a temporary file and returns its file descriptor and path.

    Args:
        suffix (str): Suffix for the temporary file.
        prefix (str): Prefix for the temporary file.
        dir (Path, optional): Directory in which to create the temp file.

    Returns:
        Tuple[int, Path]: File descriptor and Path object.
    """
    fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dir)
    return fd, Path(path)

def get_cpu_info() -> Dict[str, str]:
    """
    Retrieves CPU information from the host system.

    Returns:
        Dict[str, str]: Dictionary containing CPU information.
    """
    cpu_info = {}
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(["wmic", "cpu", "get", "/format:list"], universal_newlines=True)
            for line in output.strip().splitlines():
                if '=' in line:
                    key, value = line.split('=', 1)
                    cpu_info[key.strip()] = value.strip()
        elif platform.system() in ["Linux", "Darwin"]:
            output = subprocess.check_output(["lscpu"], universal_newlines=True)
            for line in output.strip().splitlines():
                if ':' in line:
                    key, value = line.split(':', 1)
                    cpu_info[key.strip()] = value.strip()
    except Exception as e:
        logging.warning(f"Failed to retrieve CPU info: {e}")
    return cpu_info

# =============================================================================
# BatchDeobfuscator Class
# =============================================================================

class BatchDeobfuscator:
    def __init__(self, complex_one_liner_threshold: int = 4):
        """
        Initializes the BatchDeobfuscator with default environment variables.

        Args:
            complex_one_liner_threshold (int): Threshold to determine complex one-liners.
        """
        self.variables: Dict[str, str] = {}
        self.exec_cmd: List[str] = []
        self.exec_ps1: List[bytes] = []
        self.traits: Dict[str, List] = defaultdict(list)
        self.complex_one_liner_threshold = complex_one_liner_threshold

        # Load environment variables if on Windows, else load fake variables
        if os.name == "nt":
            for env_var, value in os.environ.items():
                self.variables[env_var.lower()] = value
            logging.debug("Loaded environment variables.")
        else:
            self._load_fake_variables()
            logging.debug("Loaded fake environment variables for non-Windows OS.")

        self._initialize_curl_parser()

    def _load_fake_variables(self):
        """
        Loads a predefined set of environment variables for non-Windows environments.
        """
        self.variables = {
            "allusersprofile": "C:\\ProgramData",
            "appdata": "C:\\Users\\puncher\\AppData\\Roaming",
            "commonprogramfiles": "C:\\Program Files\\Common Files",
            "commonprogramfiles(x86)": "C:\\Program Files (x86)\\Common Files",
            "commonprogramw6432": "C:\\Program Files\\Common Files",
            "computername": "MISCREANTTEARS",
            "comspec": "C:\\WINDOWS\\system32\\cmd.exe",
            "driverdata": "C:\\Windows\\System32\\Drivers\\DriverData",
            "errorlevel": "0",  # Because nothing fails.
            "fps_browser_app_profile_string": "Internet Explorer",
            "fps_browser_user_profile_string": "Default",
            "homedrive": "C:",
            "homepath": "\\Users\\puncher",
            "java_home": "C:\\Program Files\\Amazon Corretto\\jdk11.0.7_10",
            "localappdata": "C:\\Users\\puncher\\AppData\\Local",
            "logonserver": "\\\\MISCREANTTEARS",
            "number_of_processors": "4",
            "onedrive": "C:\\Users\\puncher\\OneDrive",
            "os": "Windows_NT",
            "path": (
                "C:\\Program Files\\Amazon Corretto\\jdk11.0.7_10\\bin;C:\\WINDOWS\\system32;"
                "C:\\WINDOWS;C:\\WINDOWS\\System32\\Wbem;C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\;"
                "C:\\Program Files\\dotnet\\;C:\\Program Files\\Microsoft SQL Server\\130\\Tools\\Binn\\;"
                "C:\\Users\\puncher\\AppData\\Local\\Microsoft\\WindowsApps;"
                "%USERPROFILE%\\AppData\\Local\\Microsoft\\WindowsApps;"
            ),
            "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
            "processor_architecture": "AMD64",
            "processor_identifier": "Intel Core Ti-83 Family 6 Model 158 Stepping 10, GenuineIntel",
            "processor_level": "6",
            "processor_revision": "9e0a",
            "programdata": "C:\\ProgramData",
            "programfiles": "C:\\Program Files",
            "programfiles(x86)": "C:\\Program Files (x86)",
            "programw6432": "C:\\Program Files",
            "psmodulepath": "C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules\\",
            "public": "C:\\Users\\Public",
            "random": "4",  # https://xkcd.com/221/
            "sessionname": "Console",
            "systemdrive": "C:",
            "systemroot": "C:\\WINDOWS",
            "temp": "C:\\Users\\puncher\\AppData\\Local\\Temp",
            "tmp": "C:\\Users\\puncher\\AppData\\Local\\Temp",
            "userdomain": "MISCREANTTEARS",
            "userdomain_roamingprofile": "MISCREANTTEARS",
            "username": "puncher",
            "userprofile": "C:\\Users\\puncher",
            "windir": "C:\\WINDOWS",
            "__compat_layer": "DetectorsMessageBoxErrors",
        }

    def _initialize_curl_parser(self):
        """
        Initializes an ArgumentParser for parsing curl commands.
        """
        self.curl_parser = argparse.ArgumentParser(add_help=False)
        self.curl_parser.add_argument("-o", "--output", dest="output", help="Write to file instead of stdout")
        self.curl_parser.add_argument(
            "-O",
            "--remote-name",
            dest="remote_name",
            action="store_true",
            help="Write output to a file named as the remote file",
        )
        self.curl_parser.add_argument("url", help="URL")
        # Patch all possible one-character arguments
        for char in string.ascii_letters + string.digits + "#:":
            try:
                self.curl_parser.add_argument(f"-{char}", action="store_true")
            except argparse.ArgumentError:
                pass
        logging.debug("Initialized curl argument parser.")

    def read_logical_line(self, path: Path) -> Generator[str, None, None]:
        """
        Reads a batch file and yields logical lines by handling line continuations.

        Args:
            path (Path): Path to the batch file.

        Yields:
            str: A logical line from the batch file.
        """
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as input_file:
                logical_line = ""
                for line in input_file:
                    line = line.rstrip('\n')
                    if not line.endswith("^"):
                        logical_line += line
                        yield logical_line
                        logical_line = ""
                    else:
                        logical_line += line[:-1] + " "
        except FileNotFoundError:
            logging.error(f"The file {path} does not exist.")
            raise
        except IOError as e:
            logging.error(f"An I/O error occurred while reading {path}: {e}")
            raise

    def split_if_statement(self, statement: str) -> Generator[str, None, None]:
        """
        Splits an IF statement into its conditional, true, and false parts.

        Args:
            statement (str): The IF statement.

        Yields:
            str: Parts of the IF statement.
        """
        match = IF_STATEMENT_RE.search(statement)
        if match:
            conditional = match.group("conditional")
            if_match = match.group("open_paren") is None
            yield conditional
            yield match.group("true_statement")
            if match.group("false_statement") is None:
                if if_match or match.group("close_paren"):
                    yield ")"
            else:
                yield ") else ("
                yield match.group("false_statement")
                yield ")"
        else:
            yield statement

    def split_for_statement(self, statement: str) -> Generator[str, None, None]:
        """
        Splits a FOR statement into its loop and command parts.

        Args:
            statement (str): The FOR statement.

        Yields:
            str: Parts of the FOR statement.
        """
        match = FOR_STATEMENT_RE.search(statement)
        if match:
            loop = match.group("loop")
            if_match = match.group("open_paren") is None
            yield loop
            yield match.group("command")
            if if_match or match.group("close_paren"):
                yield ")"
        else:
            yield statement

    def get_commands_special_statement(self, statement: str) -> Generator[str, None, None]:
        """
        Handles special statements like IF and FOR by splitting them appropriately.

        Args:
            statement (str): The statement to handle.

        Yields:
            str: Split parts of the statement.
        """
        if statement.lower().startswith("if "):
            for part in self.split_if_statement(statement):
                if part.strip():
                    yield part
        elif statement.lower().startswith("for "):
            for part in self.split_for_statement(statement):
                if part.strip():
                    yield part
        else:
            yield statement

    def get_commands(self, logical_line: str) -> Generator[str, None, None]:
        """
        Splits a logical line into individual commands based on control operators.

        Args:
            logical_line (str): The logical line from the batch file.

        Yields:
            str: Individual commands.
        """
        state = "init"
        counter = 0
        start_command = 0
        length = len(logical_line)
        while counter < length:
            char = logical_line[counter]
            if state == "init":
                if char == '"':
                    state = "str_s"
                elif char == "^":
                    state = "escape"
                elif char in ("&", "|"):
                    if counter > start_command:
                        cmd = logical_line[start_command:counter].strip()
                        if cmd:
                            for part in self.get_commands_special_statement(cmd):
                                yield part
                    start_command = counter + 1
                else:
                    pass
            elif state == "str_s":
                if char == '"':
                    state = "init"
            elif state == "escape":
                state = "init"
            counter += 1

        # Yield the last command
        last_com = logical_line[start_command:].strip()
        if last_com:
            for part in self.get_commands_special_statement(last_com):
                yield part

    def get_value(self, variable: str) -> str:
        """
        Resolves the value of a variable, handling substring operations.

        Args:
            variable (str): The variable expression.

        Returns:
            str: Resolved value of the variable.
        """
        str_substitution = (
            r"([%!])(?P<variable>[\"^|!\w#$'()*+,\-\.?@\[\]`{}~\s]+)"
            r"("
            r"(:~\s*(?P<index>[+-]?\d+)\s*(?:,\s*(?P<length>[+-]?\d+))?\s*)|"
            r"(:(?P<s1>[^=]+)=(?P<s2>[^=]*))"
            r")?(\1)"
        )

        matches = re.finditer(str_substitution, variable, re.MULTILINE)
        value = ""

        for match in matches:
            var_name = match.group("variable").lower()
            if var_name in self.variables:
                value = self.variables[var_name]
                if match.group("index") is not None:
                    index = int(match.group("index"))
                    if index < 0 and -index >= len(value):
                        index = 0
                    elif index < 0:
                        index = len(value) + index
                    if match.group("length") is not None:
                        length = int(match.group("length"))
                    else:
                        length = len(value) - index
                    if length >= 0:
                        value = value[index : index + length]
                    else:
                        value = value[index:length]
                elif match.group("s1") is not None:
                    s1 = match.group("s1")
                    s2 = match.group("s2")
                    if s1.startswith("*") and s1[1:].lower() in value.lower():
                        idx = value.lower().index(s1[1:].lower())
                        value = f"{s2}{value[idx + len(s1) - 1:]}"
                    else:
                        pattern = re.compile(re.escape(s1), re.IGNORECASE)
                        value = pattern.sub(s2, value)
            else:
                # Variable not found; return empty or placeholder
                value = ""

        if value == "^":
            return value
        return value.rstrip("^")

    def interpret_set(self, cmd: str) -> Tuple[str, str]:
        """
        Interprets a SET command to assign variables.

        Args:
            cmd (str): The SET command.

        Returns:
            Tuple[str, str]: Variable name and its assigned value.
        """
        logging.debug(f"Interpreting SET command: {cmd}")
        state = "init"
        option = None
        var_name = ""
        var_value = ""
        quote = None
        old_state = None
        stop_parsing = len(cmd)

        for idx, char in enumerate(cmd):
            if idx >= stop_parsing:
                break
            if state == "init":
                if char == " ":
                    continue
                elif char == "/":
                    state = "option"
                elif char == '"':
                    quote = '"'
                    stop_parsing = cmd.rfind('"') + 1
                    if stop_parsing <= idx:
                        stop_parsing = len(cmd)
                    state = "var"
                elif char == "^":
                    old_state = state
                    state = "escape"
                else:
                    state = "var"
                    var_name += char
            elif state == "option":
                option = char.lower()
                state = "init"
            elif state == "var":
                if char == "=":
                    state = "value"
                elif not quote and char == '"':
                    quote = '"'
                    var_name += char
                elif char == "^":
                    old_state = state
                    state = "escape"
                else:
                    var_name += char
            elif state == "value":
                if char == "^":
                    old_state = state
                    state = "escape"
                else:
                    var_value += char
            elif state == "escape":
                if old_state == "init":
                    if char == '"':
                        quote = '^"'
                        stop_parsing = cmd.rfind('"') + 1
                        if idx >= stop_parsing:
                            stop_parsing = len(cmd)
                        state = "init"
                        old_state = None
                    else:
                        state = "var"
                        var_name += char
                        old_state = None
                elif old_state == "var":
                    if quote == '"' and char in QUOTED_CHARS:
                        var_name += "^"
                    if not quote and char == '"':
                        quote = '^"'
                    var_name += char
                    state = old_state
                    old_state = None
                elif old_state == "value":
                    var_value += char
                    state = old_state
                    old_state = None

        if option == "a":
            var_name = var_name.strip(" ")
            for c in QUOTED_CHARS:
                var_name = var_name.replace(c, "")
            var_value = f"({var_value.strip(' ')})"
        elif option == "p":
            var_value = "__input__"

        var_name = var_name.lstrip(" ")
        if not quote:
            var_name = var_name.lstrip('^"').replace('^"', '"')

        logging.debug(f"Set variable '{var_name}' to '{var_value}'.")
        return (var_name, var_value)

    def interpret_curl(self, cmd: str):
        """
        Interprets a curl command to extract download traits.

        Args:
            cmd (str): The curl command.
        """
        # Batch specific obfuscation that is not handled before for echo/variable purposes can be stripped here
        cmd = cmd.replace('""', "")
        try:
            split_cmd = shlex.split(cmd, posix=False)
            args, unknown = self.curl_parser.parse_known_args(split_cmd[1:])
        except ValueError as e:
            logging.warning(f"Failed to parse curl command '{cmd}': {e}")
            return

        dst = args.output
        if args.remote_name:
            parsed_url = urlparse(args.url)
            dst = Path(parsed_url.path).name

        self.traits["download"].append((cmd, {"src": args.url, "dst": dst}))
        logging.debug(f"Identified download trait: src={args.url}, dst={dst}")

    def interpret_powershell(self, normalized_comm: str):
        """
        Interprets a PowerShell command, handling encoded commands and detecting strong encryption.

        Args:
            normalized_comm (str): The normalized PowerShell command.
        """
        try:
            ori_cmd = shlex.split(normalized_comm)
            cmd_lower = [part.lower() for part in ori_cmd]
        except ValueError as e:
            logging.warning(f"Failed to parse PowerShell command '{normalized_comm}': {e}")
            return

        ps1_cmd = None
        for idx, part in enumerate(cmd_lower):
            if ENC_RE.match(part):
                try:
                    # Decode the Base64 encoded command
                    encoded_cmd = ori_cmd[idx + 1]
                    ps1_cmd = base64.b64decode(encoded_cmd, validate=True).replace(b"\x00", b"")
                    logging.debug("Detected encoded PowerShell command.")
                    break
                except (IndexError, base64.binascii.Error) as e:
                    logging.warning(f"Failed to decode encoded PowerShell command: {e}")
            elif PWR_CMD_RE.match(part):
                try:
                    # Handle PowerShell command with /c option
                    ps1_cmd = ori_cmd[idx + 1].encode()
                    logging.debug("Detected PowerShell command with /c option.")
                    break
                except IndexError as e:
                    logging.warning(f"Failed to extract PowerShell command: {e}")

        if ps1_cmd is None:
            # Attempt to handle unencoded PowerShell commands
            if len(ori_cmd) > 1:
                ps1_cmd = ori_cmd[-1].encode()

        if ps1_cmd:
            self.exec_ps1.append(ps1_cmd.strip(b'"'))
            logging.debug(f"Queued PowerShell command: {ps1_cmd.strip(b'\"')}")

            # Check if the PowerShell command is strongly encrypted
            if self._is_strongly_encrypted(ps1_cmd):
                self.traits["strong-encryption"].append(normalized_comm)
                logging.warning("Detected potentially strongly encrypted PowerShell command.")

            # Handle multiple layers of Base64 encoding
            decoded_cmd = self._recursive_decode_base64(ps1_cmd)
            if decoded_cmd:
                logging.debug("Recursively decoded PowerShell command.")
                # Replace the original command with the decoded one for further processing
                self.interpret_command(decoded_cmd.decode('utf-8', errors='ignore'))

    def _is_strongly_encrypted(self, ps1_cmd: bytes) -> bool:
        """
        Determines if a PowerShell command is likely strongly encrypted.

        Args:
            ps1_cmd (bytes): The PowerShell command.

        Returns:
            bool: True if strongly encrypted, False otherwise.
        """
        # Heuristic: If a large portion of the command is non-printable or follows a specific encrypted pattern
        try:
            decoded_str = ps1_cmd.decode('utf-8', errors='ignore')
            non_printable = sum(not c.isprintable() for c in decoded_str)
            if len(decoded_str) > 0 and (non_printable / len(decoded_str)) > 0.5:
                return True
        except UnicodeDecodeError:
            return True
        return False

    def _recursive_decode_base64(self, data: bytes, depth: int = 0, max_depth: int = 5) -> Optional[bytes]:
        """
        Recursively decodes Base64-encoded data to handle multiple layers of encoding.

        Args:
            data (bytes): Base64-encoded data.
            depth (int): Current recursion depth.
            max_depth (int): Maximum recursion depth to prevent infinite loops.

        Returns:
            Optional[bytes]: Decoded data if successful, None otherwise.
        """
        if depth >= max_depth:
            logging.warning("Maximum Base64 decode depth reached.")
            return None
        try:
            decoded_data = base64.b64decode(data, validate=True)
            if b"\x00" in decoded_data:
                decoded_data = decoded_data.replace(b"\x00", b"")
            # Check if the decoded data is still Base64-encoded
            if self._is_base64_string(decoded_data):
                logging.debug(f"Decoding Base64 at depth {depth + 1}.")
                return self._recursive_decode_base64(decoded_data, depth + 1, max_depth)
            else:
                return decoded_data
        except base64.binascii.Error:
            return None

    def _is_base64_string(self, data: bytes) -> bool:
        """
        Checks if the provided data is a valid Base64-encoded string.

        Args:
            data (bytes): Data to check.

        Returns:
            bool: True if data is Base64-encoded, False otherwise.
        """
        try:
            if not data:
                return False
            if len(data) % 4 != 0:
                return False
            base64.b64decode(data, validate=True)
            return True
        except base64.binascii.Error:
            return False

    def interpret_command(self, normalized_comm: str):
        """
        Interprets a single normalized batch command.

        Args:
            normalized_comm (str): The normalized command.
        """
        if not normalized_comm or normalized_comm.lower().startswith("rem"):
            return

        # Remove surrounding parentheses and spaces
        normalized_comm = normalized_comm.strip()
        if normalized_comm.startswith("@"):
            normalized_comm = normalized_comm[1:]

        normalized_comm_lower = normalized_comm.lower()

        if normalized_comm_lower.startswith("call "):
            # Recursively interpret the called command
            self.interpret_command(normalized_comm[5:].strip())
            return

        if normalized_comm_lower.startswith("start"):
            match = START_RE.match(normalized_comm)
            if match and match.group("cmd"):
                self.interpret_command(match.group("cmd"))
            return

        if normalized_comm_lower.startswith("cmd"):
            match = CMD_COMMAND_RE.search(normalized_comm)
            if match and match.group("cmd"):
                self.exec_cmd.append(match.group("cmd").strip('"'))
            return

        if normalized_comm_lower.startswith("setlocal"):
            # Ignore setlocal commands
            return

        if normalized_comm_lower.startswith("set "):
            # Interpret set commands
            var_name, var_value = self.interpret_set(normalized_comm[3:].strip())
            if var_value == "":
                if var_name.lower() in self.variables:
                    del self.variables[var_name.lower()]
                    logging.debug(f"Deleted variable '{var_name}'.")
            else:
                self.variables[var_name.lower()] = var_value
                logging.debug(f"Set variable '{var_name}' to '{var_value}'.")
            return

        if normalized_comm_lower.startswith("curl "):
            self.interpret_curl(normalized_comm)
            return

        if normalized_comm_lower.startswith("powershell "):
            self.interpret_powershell(normalized_comm)
            return

        # If the command is not specifically handled, log it as unprocessed
        self.traits["unprocessed"].append(normalized_comm)
        logging.info(f"Unprocessed command: {normalized_comm}")

    def normalize_command(self, command: str) -> str:
        """
        Normalizes a batch command by resolving variables and removing obfuscations.

        Args:
            command (str): The raw batch command.

        Returns:
            str: Normalized command.
        """
        normalized_com = self._remove_comments(command)
        normalized_com = self._resolve_variables(normalized_com)
        return normalized_com

    def _remove_comments(self, command: str) -> str:
        """
        Removes comments from a batch command.

        Args:
            command (str): The command string.

        Returns:
            str: Command without comments.
        """
        if command.lower().startswith("rem "):
            logging.debug("Removed comment line.")
            return ""
        return command

    def _resolve_variables(self, command: str) -> str:
        """
        Resolves environment variables within a command.

        Args:
            command (str): The command string.

        Returns:
            str: Command with variables resolved.
        """
        # This function can be enhanced to handle more complex variable scenarios
        normalized_comm = command
        var_pattern = re.compile(r"%(\w+)%")
        matches = var_pattern.findall(command)
        for var in matches:
            var_lower = var.lower()
            if var_lower in self.variables:
                normalized_comm = normalized_comm.replace(f"%{var}%", self.variables[var_lower])
                logging.debug(f"Resolved variable '%{var}%': {self.variables[var_lower]}")
            else:
                normalized_comm = normalized_comm.replace(f"%{var}%", "")
                logging.debug(f"Variable '%{var}%' not found. Replaced with empty string.")
        return normalized_comm

    def analyze_logical_line(
        self, 
        logical_line: str, 
        working_directory: Path, 
        output_file, 
        extracted_files: Dict[str, List[Tuple[str, str]]]
    ):
        """
        Analyzes a logical line from the batch file.

        Args:
            logical_line (str): The logical line to analyze.
            working_directory (Path): Directory to store extracted files.
            output_file: File object to write deobfuscated commands.
            extracted_files (Dict[str, List[Tuple[str, str]]]): Dictionary to store extracted file info.
        """
        commands = self.get_commands(logical_line)
        for command in commands:
            normalized_comm = self.normalize_command(command)
            if not normalized_comm:
                continue
            if len(list(self.get_commands(normalized_comm))) > 1:
                self.traits["command-grouping"].append({"Command": command, "Normalized": normalized_comm})
                self.analyze_logical_line(normalized_comm, working_directory, output_file, extracted_files)
            else:
                self.interpret_command(normalized_comm)
                output_file.write(normalized_comm + "\n")
                for lolbas in RARE_LOLBAS:
                    if lolbas in normalized_comm.lower():
                        self.traits["LOLBAS"].append({"LOLBAS": lolbas, "Command": normalized_comm})
                        logging.debug(f"Detected LOLBAS command: {lolbas}")

                # Handle exec_cmd
                if self.exec_cmd:
                    for child_cmd in self.exec_cmd:
                        child_deobfuscator = copy.deepcopy(self)
                        child_deobfuscator.exec_cmd.clear()
                        fd, child_path = create_temp_file(suffix=".bat", prefix="child_", dir=working_directory)
                        child_file_path = Path(child_path)
                        try:
                            with child_file_path.open("w", encoding="utf-8") as child_f:
                                child_deobfuscator.analyze_logical_line(child_cmd, working_directory, child_f, extracted_files)
                        except Exception as e:
                            logging.error(f"Failed to process child command '{child_cmd}': {e}")
                            continue
                        try:
                            with child_file_path.open("rb") as cmd_f:
                                sha256hash = compute_sha256(cmd_f.read())
                            bat_filename = f"{sha256hash[:10]}.bat"
                            move_file(child_file_path, working_directory / bat_filename)
                            extracted_files["batch"].append((bat_filename, sha256hash))
                            logging.debug(f"Extracted child batch file: {bat_filename}")
                        except Exception as e:
                            logging.error(f"Failed to handle extracted child batch file '{child_file_path}': {e}")
                        child_deobfuscator = None  # Help garbage collection
                    self.exec_cmd.clear()

                # Handle exec_ps1
                if self.exec_ps1:
                    for child_ps1 in self.exec_ps1:
                        sha256hash = compute_sha256(child_ps1)
                        if any(
                            extracted_file_hash == sha256hash
                            for _, extracted_file_hash in extracted_files.get("powershell", [])
                        ):
                            continue
                        powershell_filename = f"{sha256hash[:10]}.ps1"
                        powershell_file_path = working_directory / powershell_filename
                        try:
                            with powershell_file_path.open("wb") as ps1_f:
                                ps1_f.write(child_ps1)
                            extracted_files["powershell"].append((powershell_filename, sha256hash))
                            logging.debug(f"Extracted PowerShell script: {powershell_filename}")
                        except Exception as e:
                            logging.error(f"Failed to write PowerShell script '{powershell_file_path}': {e}")
                    self.exec_ps1.clear()

    def analyze(self, file_path: Path, working_directory: Path) -> Tuple[str, Dict[str, List[Tuple[str, str]]]]:
        """
        Analyzes the entire batch file for deobfuscation.

        Args:
            file_path (Path): Path to the obfuscated batch file.
            working_directory (Path): Directory to store output and extracted files.

        Returns:
            Tuple[str, Dict[str, List[Tuple[str, str]]]]: Deobfuscated file name and extracted files information.
        """
        extracted_files: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        bat_filename = f"{compute_sha256(file_path.read_bytes())[:10]}_deobfuscated.bat"
        temp_path = working_directory / bat_filename

        try:
            with temp_path.open("w", encoding="utf-8") as f:
                for logical_line in self.read_logical_line(file_path):
                    self.analyze_logical_line(logical_line, working_directory, f, extracted_files)
        except Exception as e:
            logging.error(f"Failed to analyze file {file_path}: {e}")
            raise

        # Determine if it's a complex one-liner
        self._check_complex_one_liner(file_path, temp_path)

        # Simulate a believable CPU configuration report
        cpu_info = get_cpu_info()
        cpu_report_path = working_directory / "cpu_config_report.txt"
        try:
            with cpu_report_path.open("w", encoding="utf-8") as cpu_f:
                cpu_f.write("=== CPU Configuration Report ===\n")
                for key, value in cpu_info.items():
                    cpu_f.write(f"{key}: {value}\n")
            extracted_files["cpu_config"] = [("cpu_config_report.txt", compute_sha256(cpu_report_path.read_bytes()))]
            logging.info(f"CPU configuration report generated at: {cpu_report_path}")
        except Exception as e:
            logging.warning(f"Failed to generate CPU configuration report: {e}")

        logging.info(f"Deobfuscation complete. Output saved to {temp_path}")
        return bat_filename, extracted_files

    def _check_complex_one_liner(self, original_path: Path, deobfuscated_path: Path):
        """
        Checks if the original file is a complex one-liner based on the threshold.

        Args:
            original_path (Path): Path to the original batch file.
            deobfuscated_path (Path): Path to the deobfuscated batch file.
        """
        self.traits["one-liner"] = False
        try:
            with original_path.open("r", encoding="utf-8", errors="ignore") as f:
                firstline = False
                for line in f:
                    if line.strip():
                        if not firstline:
                            self.traits["one-liner"] = True
                            firstline = True
                        else:
                            self.traits["one-liner"] = False
                            break
            if self.traits["one-liner"]:
                resulting_line_count = deobfuscated_path.read_bytes().count(b"\n")
                if resulting_line_count >= self.complex_one_liner_threshold:
                    self.traits["complex-one-liner"] = resulting_line_count
                    logging.info(f"Identified complex one-liner with {resulting_line_count} lines.")
        except Exception as e:
            logging.warning(f"Could not determine if it's a one-liner: {e}")

# =============================================================================
# Main Function
# =============================================================================

def main():
    """
    The main function that parses arguments and initiates the batch deobfuscation process.
    """
    # Setup logging
    setup_logging()

    # Argument parsing
    parser = argparse.ArgumentParser(description="Batch File Deobfuscator")
    parser.add_argument("-f", "--file", type=str, help="Path to the obfuscated batch file")
    parser.add_argument("-o", "--outdir", type=str, default="output", help="Directory to store deobfuscated files")
    args = parser.parse_args()

    deobfuscator = BatchDeobfuscator()

    if args.file:
        file_path = Path(args.file)
        working_directory = Path(args.outdir)
        working_directory.mkdir(parents=True, exist_ok=True)

        try:
            bat_filename, extracted_files = deobfuscator.analyze(file_path, working_directory)
            print(f"Deobfuscated batch file saved as: {working_directory / bat_filename}")
            # Optionally, handle extracted files information
            if extracted_files:
                print("Extracted Files:")
                for file_type, files in extracted_files.items():
                    print(f"  {file_type.capitalize()}:")
                    for fname, fhash in files:
                        print(f"    {fname} - {fhash}")
        except Exception as e:
            print(f"An error occurred during deobfuscation: {e}")
            logging.error(f"An error occurred during deobfuscation: {e}")
            exit(1)
    else:
        # Interactive mode: interpret a single command
        try:
            command = input("Please enter an obfuscated batch command:\n")
            normalized_comm = deobfuscator.normalize_command(command)
            deobfuscator.interpret_command(normalized_comm)
            print(f"Normalized Command:\n{normalized_comm}")
        except Exception as e:
            print(f"An error occurred: {e}")
            logging.error(f"An error occurred in interactive mode: {e}")

# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    main()

    # Simple tests
    def test_compute_sha256():
        test_data = b"test data"
        expected_hash = hashlib.sha256(test_data).hexdigest()
        assert compute_sha256(test_data) == expected_hash, "SHA-256 hash does not match expected value."
        logging.info("test_compute_sha256 passed.")

    def test_regex_patterns():
        # Test PWR_CMD_RE without the extra parenthesis
        test_string = "/c command"
        assert PWR_CMD_RE.match(test_string), "PWR_CMD_RE failed to match expected string."
        
        # Test ENC_RE
        test_enc = "-enc dGVzdA=="  # Base64 for 'test'
        assert ENC_RE.match("-enc"), "ENC_RE failed to match '-enc' prefix."
        logging.info("test_regex_patterns passed.")

    def run_tests():
        test_compute_sha256()
        test_regex_patterns()
        logging.info("All tests passed.")

    run_tests()