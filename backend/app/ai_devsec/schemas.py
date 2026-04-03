from pydantic import BaseModel, Field
from typing import List, Optional, Literal

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

class Finding(BaseModel):
    detector: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None

class ScanRequest(BaseModel):
    code: str = Field(min_length=1)
    filename: Optional[str] = None
    source: Optional[str] = "paste"

class ScanResponse(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    findings: List[Finding]
    summary: str

class DiffScanRequest(BaseModel):
    diff: str = Field(min_length=1)



# ── Gemini chat ────────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: Literal["user", "model"]
    text: str

class ChatRequest(BaseModel):
    findings: List[Finding]
    scanned_code: str
    message: str = Field(min_length=1)
    history: List[ChatMessage] = []

class ChatResponse(BaseModel):
    reply: str