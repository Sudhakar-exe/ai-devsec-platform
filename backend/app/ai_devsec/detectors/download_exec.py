import re
from typing import List
from .base import Detector
from ..schemas import Finding

# High-signal patterns commonly used for malicious install / execution
PATTERNS = [
    ("curl pipe to bash/sh", re.compile(r"\bcurl\b.*\|\s*(bash|sh)\b", re.IGNORECASE)),
    ("wget pipe to bash/sh", re.compile(r"\bwget\b.*\|\s*(bash|sh)\b", re.IGNORECASE)),
    ("curl then bash/sh", re.compile(r"\bcurl\b.*;\s*(bash|sh)\b", re.IGNORECASE)),
    ("wget then bash/sh", re.compile(r"\bwget\b.*;\s*(bash|sh)\b", re.IGNORECASE)),
    ("PowerShell IEX", re.compile(r"\bpowershell\b.*\b(iex|invoke-expression)\b", re.IGNORECASE)),
    ("Invoke-WebRequest + IEX", re.compile(r"invoke-webrequest.*\|\s*(iex|invoke-expression)", re.IGNORECASE)),
]

def _safe(line: str, max_len: int = 180) -> str:
    line = line.strip()
    return (line[:max_len] + "…") if len(line) > max_len else line

class DownloadExecDetector(Detector):
    name = "download_exec"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []

        for lineno, line in enumerate(code.splitlines(), start=1):
            for label, rx in PATTERNS:
                if rx.search(line):
                    findings.append(
                        Finding(
                            detector=self.name,
                            severity="CRITICAL",
                            confidence=0.85,
                            message=f"Suspicious download-and-execute pattern detected: {label}",
                            line=lineno,
                            evidence=_safe(line),
                            recommendation="Do not pipe remote content into a shell. Download, verify integrity (hash/signature), review, then execute safely."
                        )
                    )

        return findings
