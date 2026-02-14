import re
from typing import List
from .base import Detector
from ..schemas import Finding

# Key/value style credentials (very common in configs)
KV_PATTERNS = [
    ("Hardcoded password", re.compile(r"\b(pass(word)?|passwd)\b\s*[:=]\s*(['\"]).+?\3", re.IGNORECASE)),
    ("Hardcoded secret", re.compile(r"\bsecret\b\s*[:=]\s*(['\"]).+?\1", re.IGNORECASE)),
    ("Hardcoded token", re.compile(r"\b(token|api[_-]?token|access[_-]?token)\b\s*[:=]\s*(['\"]).+?\2", re.IGNORECASE)),
]

# Header-style tokens
AUTH_HEADER = ("Authorization header token", re.compile(r"\bauthorization\b\s*:\s*bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE))

# Simple "user:pass@" in URLs (basic)
URL_CREDS = ("Credentials in URL", re.compile(r"://[^/\s:]+:[^/\s@]+@", re.IGNORECASE))

def mask_sensitive(text: str) -> str:
    """
    Replace the detected secret value with ***.
    This isn't perfect masking, but it prevents accidental leakage in logs/UI.
    """
    # Mask quoted values in key=value patterns
    text = re.sub(r"(\b(pass(word)?|passwd|secret|token|api[_-]?token|access[_-]?token)\b\s*[:=]\s*)(['\"]).+?(\3)",
                  r"\1\3***\4",
                  text,
                  flags=re.IGNORECASE)

    # Mask bearer tokens
    text = re.sub(r"(\bauthorization\b\s*:\s*bearer\s+)[^\s]+", r"\1***", text, flags=re.IGNORECASE)

    # Mask credentials in URL user:pass@
    text = re.sub(r"://([^/\s:]+):([^/\s@]+)@", r"://***:***@", text, flags=re.IGNORECASE)

    return text.strip()[:180] + ("…" if len(text.strip()) > 180 else "")

class HardcodedCredsDetector(Detector):
    name = "hardcoded_creds"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []

        for lineno, line in enumerate(code.splitlines(), start=1):

            # KV style
            for label, rx in KV_PATTERNS:
                if rx.search(line):
                    findings.append(
                        Finding(
                            detector=self.name,
                            severity="HIGH",
                            confidence=0.8,
                            message=f"{label} detected.",
                            line=lineno,
                            evidence=mask_sensitive(line),
                            recommendation="Remove hardcoded credentials. Use environment variables or a secret manager."
                        )
                    )

            # Authorization header
            label, rx = AUTH_HEADER
            if rx.search(line):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity="HIGH",
                        confidence=0.85,
                        message=f"{label} detected.",
                        line=lineno,
                        evidence=mask_sensitive(line),
                        recommendation="Do not hardcode auth tokens. Inject them securely via secrets/ENV."
                    )
                )

            # URL creds
            label, rx = URL_CREDS
            if rx.search(line):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity="HIGH",
                        confidence=0.75,
                        message=f"{label} detected.",
                        line=lineno,
                        evidence=mask_sensitive(line),
                        recommendation="Remove credentials from URLs. Use secure credential storage and separate auth configuration."
                    )
                )

        return findings
