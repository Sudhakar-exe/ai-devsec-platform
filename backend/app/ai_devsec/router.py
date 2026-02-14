from fastapi import APIRouter
from .schemas import ScanRequest, ScanResponse
from .service import run_scan

router = APIRouter(prefix="/api/ai-devsec", tags=["ai-devsec"])

@router.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    return run_scan(req)

@router.post("/scan-diff", response_model=ScanResponse)
def scan_diff(diff: str):
    from .service import run_diff_scan
    return run_diff_scan(diff)

