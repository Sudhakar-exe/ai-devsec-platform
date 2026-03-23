from fastapi import APIRouter, Query, HTTPException, Body
from typing import Optional, Annotated
from .schemas import ScanRequest, ScanResponse
from .service import run_scan, run_diff_scan


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
    """
    Scan a code snippet for security vulnerabilities.

    Paste your code directly into the **Request body** box above.
    Optionally pass `?filename=yourfile.py` in the URL for richer findings.

    **curl example:**
    ```
    curl -X POST http://localhost:8000/api/ai-devsec/scan \\
         -H "Content-Type: text/plain" \\
         --data-binary @yourfile.py
    ```
    """
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
    """
    Scan only the **added lines** from a git diff for security vulnerabilities.

    Paste the raw output of `git diff` into the **Request body** box above.

    **curl example (pipe git diff directly):**
    ```
    git diff HEAD | curl -X POST http://localhost:8000/api/ai-devsec/scan-diff \\
         -H "Content-Type: text/plain" --data-binary @-
    ```
    """
    if not diff or not diff.strip():
        raise HTTPException(status_code=422, detail="Request body must not be empty.")
    return run_diff_scan(diff)