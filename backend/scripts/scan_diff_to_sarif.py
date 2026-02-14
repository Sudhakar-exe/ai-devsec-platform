import sys
import json
from pathlib import Path

# Allow importing backend.app.* when running as a script
sys.path.append(str(Path(__file__).resolve().parents[2]))

from backend.app.ai_devsec.schemas import DiffScanRequest
from backend.app.ai_devsec.service import run_diff_scan
from backend.app.ai_devsec.sarif import findings_to_sarif

def main():
    if len(sys.argv) < 2:
        print("Usage: python backend/scripts/scan_diff_to_sarif.py <diff_file>", file=sys.stderr)
        sys.exit(2)

    diff_path = Path(sys.argv[1])
    diff_text = diff_path.read_text(encoding="utf-8", errors="ignore")

    # validate request shape (good habit)
    _ = DiffScanRequest(diff=diff_text)

    resp = run_diff_scan(diff_text)
    sarif = findings_to_sarif(resp.findings)

    print(json.dumps({"risk_score": resp.risk_score, "summary": resp.summary}, indent=2), file=sys.stderr)
    print(json.dumps(sarif))

    # Fail CI if HIGH/CRITICAL exists
    severities = {f.severity for f in resp.findings}
    if "CRITICAL" in severities or "HIGH" in severities:
        sys.exit(1)

if __name__ == "__main__":
    main()
