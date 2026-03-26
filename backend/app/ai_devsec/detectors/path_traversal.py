import re
from typing import List
from .base import Detector
from .utils import truncate_line
from ..schemas import Finding

_USER_INPUT_NAMES = re.compile(
    r"\b(request\.(args|form|json|data|files|params|get|values|POST|GET)"
    r"|user_input|user_file|filename|filepath|path_param"
    r"|input_path|file_name|upload_name|query_param)\b",
    re.IGNORECASE,
)

_FS_CALLS = re.compile(
    r"\b(open\s*\(|os\.path\.(join|abspath|realpath)\s*\("
    r"|pathlib\.Path\s*\("
    r"|os\.(remove|unlink|rename|mkdir|makedirs|listdir|scandir|stat|chmod|chown)\s*\("
    r"|shutil\.(copy|move|rmtree)\s*\()",
    re.IGNORECASE,
)

_TRAVERSAL_LITERAL = re.compile(r"\.\.[\\/]|\.\.%2[Ff]|%2[Ee]%2[Ee]")

_PATH_CONCAT = re.compile(
    r"['\"][\w./\\-]*(uploads?|files?|static|media|tmp|temp|data)[\w./\\-]*['\"]\s*\+",
    re.IGNORECASE,
)


class PathTraversalDetector(Detector):
    name = "path_traversal"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []

        for lineno, line in enumerate(code.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue

            if _TRAVERSAL_LITERAL.search(line):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity="HIGH",
                        confidence=0.9,
                        message="Path traversal sequence '../' found in string literal.",
                        line=lineno,
                        evidence=truncate_line(line),
                        recommendation=(
                            "Never trust path components from user input. "
                            "Use os.path.basename() to strip directory parts, then join onto a fixed base directory. "
                            "Verify the resolved path starts with your intended base: "
                            "assert os.path.realpath(full_path).startswith(os.path.realpath(BASE_DIR))"
                        ),
                    )
                )
                continue

            if _FS_CALLS.search(line) and _USER_INPUT_NAMES.search(line):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity="HIGH",
                        confidence=0.8,
                        message="User-controlled value passed directly to a file-system call — possible path traversal.",
                        line=lineno,
                        evidence=truncate_line(line),
                        recommendation=(
                            "Sanitize file paths before use: strip with os.path.basename(), "
                            "then verify the joined path is still inside your intended directory. "
                            "Example: safe = os.path.realpath(os.path.join(BASE, os.path.basename(user_name)))"
                        ),
                    )
                )
                continue

            if _PATH_CONCAT.search(line):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity="MEDIUM",
                        confidence=0.65,
                        message="Directory path string concatenated with a variable — possible path traversal if variable is user-controlled.",
                        line=lineno,
                        evidence=truncate_line(line),
                        recommendation=(
                            "Avoid string concatenation for paths. Use os.path.join() and then "
                            "validate the result with os.path.realpath() to prevent traversal."
                        ),
                    )
                )

        return findings