"""
Core scan logic. Imports the detector list from detectors.py and the
data models from findings.py.
"""

from typing import List

from .findings import Finding, ScanRequest, ScanResponse
from .detectors import DETECTORS


WEIGHTS = {"LOW": 10, "MEDIUM": 25, "HIGH": 45, "CRITICAL": 70}


def compute_risk_score(findings: List[Finding]) -> int:
    """Sum (weight x confidence) for every finding, capped at 100."""
    score = sum(int(WEIGHTS[f.severity] * f.confidence) for f in findings)
    return min(score, 100)


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


def extract_added_lines(diff_text: str) -> list:
    current_file = None
    new_line_number = 0
    extracted = []

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line.replace("+++ b/", "").strip()
        elif line.startswith("@@"):
            for part in line.split():
                if part.startswith("+"):
                    new_line_number = int(part[1:].split(",")[0])
                    break
        elif line.startswith("+") and not line.startswith("+++"):
            extracted.append(
                {"file": current_file, "line": new_line_number, "code": line[1:]}
            )
            new_line_number += 1
        elif not line.startswith("-"):
            new_line_number += 1

    return extracted


def run_diff_scan(diff_text: str) -> ScanResponse:
    """Scan only the added lines in a git diff."""
    findings: List[Finding] = []

    for entry in extract_added_lines(diff_text):
        result = run_scan(ScanRequest(code=entry["code"]))
        for f in result.findings:
            f.file = entry["file"]
            f.line = entry["line"]
            f.message = f"{entry['file']}:{entry['line']} - {f.message}"
            findings.append(f)

    risk_score = compute_risk_score(findings)
    summary = (
        "No risky patterns detected in diff."
        if not findings
        else f"{len(findings)} issue(s) detected across modified files."
    )
    return ScanResponse(risk_score=risk_score, findings=findings, summary=summary)
