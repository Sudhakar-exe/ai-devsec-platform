import re
from typing import List
from .base import Detector
from .utils import truncate_line
from ..schemas import Finding

_PATTERNS = [
    (
        "Flask DEBUG=True",
        "HIGH",
        0.9,
        re.compile(r"\bapp\.run\s*\(.*\bdebug\s*=\s*True\b", re.IGNORECASE),
        "Flask's debug mode enables the Werkzeug interactive debugger, which allows "
        "arbitrary Python code execution from the browser. Never deploy with debug=True. "
        "Use environment variables: debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true'",
    ),
    (
        "Flask DEBUG config set to True",
        "HIGH",
        0.9,
        re.compile(r"\bapp\.config\s*\[.?DEBUG.?\]\s*=\s*True\b", re.IGNORECASE),
        "Flask debug mode enabled via app.config. This exposes an interactive debugger "
        "on error pages. Set via environment variable only, never hardcode True.",
    ),
    (
        "Django DEBUG=True",
        "HIGH",
        0.9,
        re.compile(r"^\s*DEBUG\s*=\s*True\b", re.IGNORECASE),
        "Django's DEBUG=True exposes full stack traces, local variables, settings, "
        "and all SQL queries to anyone who triggers an error. "
        "Set DEBUG = os.getenv('DJANGO_DEBUG', 'False') == 'True' and never commit DEBUG=True.",
    ),
    (
        "Django ALLOWED_HOSTS = ['*']",
        "MEDIUM",
        0.9,
        re.compile(r"\bALLOWED_HOSTS\s*=\s*\[?\s*['\"]?\*['\"]?\s*\]?"),
        "ALLOWED_HOSTS=['*'] disables Django's host header validation, enabling "
        "HTTP Host header injection attacks. List your actual domains explicitly.",
    ),
    (
        "SSL certificate verification disabled (verify=False)",
        "HIGH",
        0.95,
        re.compile(r"\bverify\s*=\s*False\b"),
        "Disabling SSL verification removes all protection against man-in-the-middle attacks. "
        "Fix the certificate issue instead of disabling verification. "
        "Never ship verify=False in production code.",
    ),
    (
        "SSL context: CERT_NONE",
        "HIGH",
        0.95,
        re.compile(r"\bssl\.CERT_NONE\b"),
        "ssl.CERT_NONE disables certificate validation entirely. "
        "Use ssl.CERT_REQUIRED and provide a valid CA bundle.",
    ),
    (
        "SSL context: check_hostname=False",
        "HIGH",
        0.9,
        re.compile(r"\bcheck_hostname\s*=\s*False\b"),
        "Disabling hostname checking allows an attacker with any valid certificate to "
        "intercept your connections. Set check_hostname=True.",
    ),
    (
        "assert used as a security/auth check",
        "MEDIUM",
        0.75,
        re.compile(
            r"\bassert\s+.*(auth|permission|is_admin|logged_in|is_authenticated"
            r"|access|authorized|allowed|role|token|user)\b",
            re.IGNORECASE,
        ),
        "Python assert statements are completely removed when running with the -O flag, "
        "making any security check that relies on assert trivially bypassable. "
        "Replace with an explicit if/raise: if not condition: raise PermissionError('...')",
    ),
    (
        "Bare except clause (hides all errors including security events)",
        "LOW",
        0.7,
        re.compile(r"^\s*except\s*:\s*$|^\s*except\s+Exception\s*:\s*$"),
        "Catching all exceptions silently swallows security-relevant errors. "
        "Catch only the specific exceptions you expect, and log unexpected ones.",
    ),
]


class DebugMisconfigDetector(Detector):
    name = "debug_misconfig"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []

        for lineno, line in enumerate(code.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue

            for label, severity, confidence, rx, recommendation in _PATTERNS:
                if rx.search(line):
                    findings.append(
                        Finding(
                            detector=self.name,
                            severity=severity,
                            confidence=confidence,
                            message=f"Dangerous misconfiguration: {label}.",
                            line=lineno,
                            evidence=truncate_line(line),
                            recommendation=recommendation,
                        )
                    )

        return findings