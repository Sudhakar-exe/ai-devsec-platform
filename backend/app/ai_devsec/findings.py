"""
All data models (schemas) used across the project, plus the shared
helper functions that sanitise evidence before it appears in a Finding.
"""

import re
from typing import List, Optional, Literal
from pydantic import BaseModel, Field


# Severity type 

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# Evidence helpers

def truncate_line(line: str, max_len: int = 180) -> str:
    """Trim a line of evidence so it never bloats a Finding."""
    line = line.strip()
    return (line[:max_len] + "…") if len(line) > max_len else line


def mask_sensitive(text: str) -> str:
    s = text.strip()

    # key/value credentials: password="x", secret='x', token = "x"
    s = re.sub(
        r'(?P<key>\b(?:pass(?:word)?|passwd|secret|token|api[_-]?token|access[_-]?token)\b\s*[:=]\s*)'
        r'(?P<q>["\'])(?P<val>.*?)(?P=q)',
        r'\g<key>\g<q>***\g<q>',
        s,
        flags=re.IGNORECASE,
    )

    # Authorization: Bearer <token>
    s = re.sub(
        r'(?P<prefix>\bauthorization\b\s*:\s*bearer\s+)\S+',
        r'\g<prefix>***',
        s,
        flags=re.IGNORECASE,
    )

    # user:pass@ inside connection URLs
    s = re.sub(r'://[^/\s:]+:[^/\s@]+@', r'://***:***@', s, flags=re.IGNORECASE)

    return s[:180] + ("…" if len(s) > 180 else "")


# Scan models

class Finding(BaseModel):
    """A single security issue discovered by one detector."""
    detector:       str
    severity:       Severity
    confidence:     float = Field(ge=0.0, le=1.0)
    message:        str
    file:           Optional[str]   = None
    line:           Optional[int]   = None
    evidence:       Optional[str]   = None
    recommendation: Optional[str]   = None


class ScanRequest(BaseModel):
    """Payload sent to the /scan endpoint."""
    code:     str            = Field(min_length=1)
    filename: Optional[str]  = None
    source:   Optional[str]  = "paste"


class ScanResponse(BaseModel):
    """Response returned by /scan and /scan-diff."""
    risk_score: int          = Field(ge=0, le=100)
    findings:   List[Finding]
    summary:    str


class DiffScanRequest(BaseModel):
    """Payload sent to the /scan-diff endpoint."""
    diff: str = Field(min_length=1)


# chat models

class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    text: str


class ChatRequest(BaseModel):
  
    findings:     List[Finding]
    scanned_code: str
    message:      str           = Field(min_length=1)
    history:      List[ChatMessage] = []


class ChatResponse(BaseModel):
    reply: str