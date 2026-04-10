from fastapi import APIRouter, Query, HTTPException, Body
from typing import Optional, Annotated

from .findings import ScanRequest, ScanResponse, ChatRequest, ChatResponse
from .service import run_scan, run_diff_scan
from .claude import chat_with_claude


router = APIRouter(prefix="/api/ai-devsec", tags=["ai-devsec"])


@router.post("/scan", response_model=ScanResponse)
async def scan(
    code: Annotated[
        str,
        Body(
            media_type="text/plain",
            description="Paste your code here — any language, any length.",
            examples=["import os\nos.system('whoami')\npassword = 'admin123'\n"],
        ),
    ],
    filename: Optional[str] = Query(None, description="Optional filename for context (e.g. app.py)"),
):
    """Scan a code snippet for security vulnerabilities."""
    if not code or not code.strip():
        raise HTTPException(status_code=422, detail="Request body must not be empty.")
    return run_scan(ScanRequest(code=code, filename=filename))


@router.post("/scan-diff", response_model=ScanResponse)
async def scan_diff(
    diff: Annotated[
        str,
        Body(
            media_type="text/plain",
            description="Paste the raw output of `git diff` here.",
            examples=["diff --git a/app.py b/app.py\n+++ b/app.py\n@@ -1,1 +1,2 @@\n+password = 'hunter2'\n"],
        ),
    ],
):
    """Scan only the added lines from a git diff for security vulnerabilities."""
    if not diff or not diff.strip():
        raise HTTPException(status_code=422, detail="Request body must not be empty.")
    return run_diff_scan(diff)


@router.post("/chat", response_model=ChatResponse, tags=["ai-chat"])
async def chat(req: ChatRequest):
    """
    Send a message to the Claude AI assistant.
    The assistant already knows what was found in the last scan.
    """
    try:
        reply = await chat_with_claude(
            findings=req.findings,
            scanned_code=req.scanned_code,
            message=req.message,
            history=req.history,
        )
        return ChatResponse(reply=reply)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))