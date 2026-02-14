from fastapi import APIRouter
from .schemas import ScanRequest, ScanResponse, DiffScanRequest
from .service import run_scan, run_diff_scan


router = APIRouter(prefix="/api/ai-devsec", tags=["ai-devsec"])

@router.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    return run_scan(req)

@router.post("/scan-diff", response_model=ScanResponse)
def scan_diff(req: DiffScanRequest):
    return run_diff_scan(req.diff)


