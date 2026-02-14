from __future__ import annotations
from typing import List, Dict, Any
from .schemas import Finding

SARIF_VERSION = "2.1.0"

def _severity_to_level(sev: str) -> str:
    # SARIF levels: note | warning | error
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev == "MEDIUM":
        return "warning"
    return "note"

def _rule_id(detector: str) -> str:
    return f"ai-devsec/{detector}"

def findings_to_sarif(findings: List[Finding]) -> Dict[str, Any]:
    """
    Convert findings into SARIF so GitHub can display them in Code Scanning / PR annotations.
    """
    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        rid = _rule_id(f.detector)

        # Build a "rule" entry once per detector
        if rid not in rules_map:
            rules_map[rid] = {
                "id": rid,
                "name": f.detector,
                "shortDescription": {"text": f.detector},
                "fullDescription": {"text": f.recommendation or f.message},
                "help": {"text": f.recommendation or "Review and fix the issue."},
            }

        # Location is optional but highly recommended
        location = None
        if f.file and f.line:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": int(f.line)}
                }
            }

        result: Dict[str, Any] = {
            "ruleId": rid,
            "level": _severity_to_level(f.severity),
            "message": {"text": f.message},
            "properties": {
                "severity": f.severity,
                "confidence": float(f.confidence),
                "detector": f.detector,
            },
        }

        if location:
            result["locations"] = [location]

        if f.evidence:
            result["message"]["text"] += f" | Evidence: {f.evidence}"

        results.append(result)

    sarif = {
        "version": SARIF_VERSION,
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI DevSec Platform",
                        "informationUri": "https://github.com/",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif
