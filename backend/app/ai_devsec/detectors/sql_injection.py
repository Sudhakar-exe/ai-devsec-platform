import re
from typing import List
from .base import Detector
from .utils import truncate_line
from ..schemas import Finding

_INJECTION_PATTERNS = [
    (
        "f-string SQL query",
        re.compile(r'f["\'].*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b.*\{', re.IGNORECASE),
    ),
    (
        "%-format SQL query",
        re.compile(r'["\'].*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b.*["\'].*%\s*[^(]', re.IGNORECASE),
    ),
    (
        ".format() SQL query",
        re.compile(r'["\'].*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b.*["\']\.format\(', re.IGNORECASE),
    ),
    (
        "string concatenation in SQL query",
        re.compile(r'["\'].*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b.*["\']\s*\+', re.IGNORECASE),
    ),
    (
        "string concatenation in SQL query",
        re.compile(r'\+\s*["\'].*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b', re.IGNORECASE),
    ),
]


class SQLInjectionDetector(Detector):
    name = "sql_injection"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []

        for lineno, line in enumerate(code.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("--"):
                continue

            for label, rx in _INJECTION_PATTERNS:
                if rx.search(line):
                    findings.append(
                        Finding(
                            detector=self.name,
                            severity="CRITICAL",
                            confidence=0.85,
                            message=f"Potential SQL injection via {label}.",
                            line=lineno,
                            evidence=truncate_line(line),
                            recommendation=(
                                "Never build SQL queries with string formatting or concatenation. "
                                "Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', (user_id,)). "
                                "For ORMs, use built-in query builders (e.g. SQLAlchemy's filter())."
                            ),
                        )
                    )
                    break  # one finding per line is enough

        return findings