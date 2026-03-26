import re
from typing import List
from .base import Detector
from .utils import truncate_line
from ..schemas import Finding

_PATTERNS = [
    (
        "pickle.loads()",
        "CRITICAL",
        0.9,
        re.compile(r"\bpickle\.(loads?|Unpickler)\s*\("),
        "pickle can execute arbitrary code when deserializing untrusted data. "
        "Use JSON or a schema-validated format (e.g. Pydantic, marshmallow) instead. "
        "If pickle is required, only ever unpickle data you generated yourself.",
    ),
    (
        "yaml.load() without Loader",
        "CRITICAL",
        0.9,
        re.compile(r"\byaml\.load\s*\(\s*(?![^)]*Loader\s*=\s*yaml\.(?:Safe|Base)Loader)"),
        "yaml.load() with PyYAML's default loader can execute arbitrary Python code. "
        "Replace with yaml.safe_load() or pass Loader=yaml.SafeLoader explicitly.",
    ),
    (
        "marshal.loads()",
        "HIGH",
        0.85,
        re.compile(r"\bmarshal\.(loads?|load)\s*\("),
        "marshal is not secure against maliciously crafted data. "
        "It is designed for internal CPython use only. Use JSON or another safe format.",
    ),
    (
        "jsonpickle.decode()",
        "CRITICAL",
        0.9,
        re.compile(r"\bjsonpickle\.decode\s*\("),
        "jsonpickle.decode() can deserialize arbitrary Python objects and execute code. "
        "Only use it with data you fully trust and control.",
    ),
    (
        "shelve.open()",
        "MEDIUM",
        0.7,
        re.compile(r"\bshelve\.open\s*\("),
        "shelve uses pickle internally and is vulnerable to the same attacks. "
        "Do not open shelve files from untrusted sources.",
    ),
]


class InsecureDeserializationDetector(Detector):
    name = "insecure_deserialization"

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
                            message=f"Insecure deserialization: {label} can execute arbitrary code on untrusted input.",
                            line=lineno,
                            evidence=truncate_line(line),
                            recommendation=recommendation,
                        )
                    )

        return findings