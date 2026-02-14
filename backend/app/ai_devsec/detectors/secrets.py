import re
from typing import List
from .base import Detector
from ..schemas import Finding

PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("Generic API Key assignment", re.compile(r"\bapi[_-]?key\b\s*[:=]\s*['\"][^'\"]{16,}['\"]", re.IGNORECASE)),
    ("Private key header", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

def _safe(line: str, max_len: int = 180) -> str:
    line = line.strip()
    return (line[:max_len] + "…") if len(line) > max_len else line

class SecretsDetector(Detector):
    name = "secrets"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            for label, rx in PATTERNS:
                if rx.search(line):
                    findings.append(
                        Finding(
                            detector=self.name,
                            severity="CRITICAL",
                            confidence=0.9,
                            message=f"Possible secret detected: {label}",
                            line=lineno,
                            evidence=_safe(line),
                            recommendation="Remove it, rotate the credential, and store it in env vars or a secret manager."
                        )
                    )
        return findings
