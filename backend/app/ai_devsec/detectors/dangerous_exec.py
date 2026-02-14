import re
from typing import List
from .base import Detector
from ..schemas import Finding

PATTERNS = [
    ("eval()", re.compile(r"\beval\s*\(")),
    ("exec()", re.compile(r"\bexec\s*\(")),
    ("os.system()", re.compile(r"\bos\.system\s*\(")),
    ("subprocess.run/call/Popen()", re.compile(r"\bsubprocess\.(run|call|Popen)\s*\(")),
    ("shell=True", re.compile(r"\bshell\s*=\s*True\b")),
]

def _safe(line: str, max_len: int = 180) -> str:
    line = line.strip()
    return (line[:max_len] + "…") if len(line) > max_len else line

class DangerousExecDetector(Detector):
    name = "dangerous_exec"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            for label, rx in PATTERNS:
                if rx.search(line):
                    findings.append(
                        Finding(
                            detector=self.name,
                            severity="HIGH",
                            confidence=0.8,
                            message=f"Potentially dangerous execution primitive: {label}",
                            line=lineno,
                            evidence=_safe(line),
                            recommendation="Avoid dynamic execution. Never use shell=True unless inputs are strictly controlled."
                        )
                    )
        return findings
