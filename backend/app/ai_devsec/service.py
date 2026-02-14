from typing import List
from .schemas import ScanRequest, ScanResponse, Finding
from .detectors.secrets import SecretsDetector
from .detectors.dangerous_exec import DangerousExecDetector
from .detectors.hardcoded_creds import HardcodedCredsDetector
from .detectors.insecure_http import InsecureHTTPDetector
from .detectors.download_exec import DownloadExecDetector


WEIGHTS = {"LOW": 10, "MEDIUM": 25, "HIGH": 45, "CRITICAL": 70}

DETECTORS = [
    SecretsDetector(),
    DangerousExecDetector(),
    HardcodedCredsDetector(),
    InsecureHTTPDetector(),
    DownloadExecDetector(),
]

def compute_risk_score(findings: List[Finding]) -> int:
    score = 0
    for f in findings:
        score += int(WEIGHTS[f.severity] * float(f.confidence))
    return min(score, 100)

def extract_added_lines_with_metadata(diff_text: str):
    """
    Extract added lines from a git diff and preserve:
    - filename
    - new file line number
    """
    current_file = None
    new_line_number = 0

    extracted = []

    for line in diff_text.splitlines():

        # Detect filename
        if line.startswith("+++ b/"):
            current_file = line.replace("+++ b/", "").strip()
            continue

        # Detect hunk header
        if line.startswith("@@"):
            # Example: @@ -10,6 +10,8 @@
            parts = line.split(" ")
            for part in parts:
                if part.startswith("+"):
                    # Remove "+" and split by comma
                    new_line_number = int(part[1:].split(",")[0])
            continue

        # Added line
        if line.startswith("+") and not line.startswith("+++"):
            extracted.append({
                "file": current_file,
                "line": new_line_number,
                "code": line[1:]
            })
            new_line_number += 1

        # Context line (not + or -)
        elif not line.startswith("-"):
            new_line_number += 1

    return extracted


def run_diff_scan(diff_text: str) -> ScanResponse:
    extracted_entries = extract_added_lines_with_metadata(diff_text)

    findings: List[Finding] = []

    for entry in extracted_entries:
        req = ScanRequest(code=entry["code"])
        result = run_scan(req)

        for finding in result.findings:
            finding.file = entry["file"]
            finding.line = entry["line"]
            finding.message = f"{entry['file']}:{entry['line']} - {finding.message}"
            findings.append(finding)

    risk_score = compute_risk_score(findings)

    if not findings:
        summary = "No risky patterns detected in diff."
    else:
        summary = f"{len(findings)} issue(s) detected across modified files."

    return ScanResponse(
        risk_score=risk_score,
        findings=findings,
        summary=summary
    )



def run_scan(req: ScanRequest) -> ScanResponse:
    findings: List[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector.run(req.code))

    risk_score = compute_risk_score(findings)

    if not findings:
        summary = "No risky patterns detected by current rules."
    else:
        top = max(findings, key=lambda f: WEIGHTS[f.severity]).severity
        summary = f"{len(findings)} finding(s). Top severity: {top}. Risk score: {risk_score}/100."

    return ScanResponse(risk_score=risk_score, findings=findings, summary=summary)
