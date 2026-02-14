from typing import List
from .schemas import ScanRequest, ScanResponse, Finding
from .detectors.secrets import SecretsDetector
from .detectors.dangerous_exec import DangerousExecDetector

WEIGHTS = {"LOW": 10, "MEDIUM": 25, "HIGH": 45, "CRITICAL": 70}

DETECTORS = [
    SecretsDetector(),
    DangerousExecDetector(),
]

def compute_risk_score(findings: List[Finding]) -> int:
    score = 0
    for f in findings:
        score += int(WEIGHTS[f.severity] * float(f.confidence))
    return min(score, 100)

def extract_added_lines_from_diff(diff_text: str) -> str:
    """
    Extract only newly added lines (starting with '+')
    from a git diff. Ignores diff metadata lines.
    """
    added_lines = []

    for line in diff_text.splitlines():
        # Skip diff metadata lines
        if line.startswith("+++"):
            continue
        if line.startswith("+"):
            # Remove the leading '+'
            added_lines.append(line[1:])

    return "\n".join(added_lines)

def run_diff_scan(diff_text: str) -> ScanResponse:
    extracted_code = extract_added_lines_from_diff(diff_text)

    # Reuse existing scan logic
    req = ScanRequest(code=extracted_code)
    return run_scan(req)


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
