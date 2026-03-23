import re
from typing import List
from .base import Detector
from ..schemas import Finding

HTTP_PATTERN = re.compile(r"http://", re.IGNORECASE)

# These are safe local addresses — flagging them would be a false positive
_SAFE_HOSTS = re.compile(
    r"http://(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(:\d+)?(/|$|\s|['\"])",
    re.IGNORECASE,
)


class InsecureHTTPDetector(Detector):
    name = "insecure_http"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []

        for lineno, line in enumerate(code.splitlines(), start=1):
            if HTTP_PATTERN.search(line) and not _SAFE_HOSTS.search(line):
                findings.append(
                    Finding(
                        detector=self.name,
                        severity="MEDIUM",
                        confidence=0.7,
                        message="Insecure HTTP connection detected (use HTTPS).",
                        line=lineno,
                        evidence=line.strip(),
                        recommendation="Use HTTPS instead of HTTP to ensure encrypted communication.",
                    )
                )

        return findings