import re
from typing import List
from .base import Detector
from .utils import truncate_line
from ..schemas import Finding

_PATTERNS = [
    (
        "MD5 used for security",
        "HIGH",
        0.8,
        re.compile(r"\bhashlib\.md5\s*\(|\.new\s*\(\s*['\"]md5['\"]", re.IGNORECASE),
        "MD5 is cryptographically broken — collisions can be found in seconds. "
        "Do not use MD5 for password hashing, integrity verification, or digital signatures. "
        "For passwords use bcrypt/argon2. For integrity use SHA-256 or SHA-3.",
    ),
    (
        "SHA-1 used for security",
        "HIGH",
        0.8,
        re.compile(r"\bhashlib\.sha1\s*\(|\.new\s*\(\s*['\"]sha1['\"]", re.IGNORECASE),
        "SHA-1 is cryptographically broken since 2017 (SHAttered attack). "
        "Replace with SHA-256 (hashlib.sha256) or SHA-3.",
    ),
    (
        "DES cipher",
        "CRITICAL",
        0.9,
        re.compile(r"\bDES\b|\bDES3\b|\bTripleDES\b|algorithms\.(DES|TripleDES)\b", re.IGNORECASE),
        "DES has a 56-bit key and was cracked in 1999. 3DES is deprecated by NIST (2023). "
        "Use AES-256-GCM instead.",
    ),
    (
        "RC4 cipher",
        "CRITICAL",
        0.9,
        re.compile(r"\bRC4\b|\bARC4\b|algorithms\.ARC4\b", re.IGNORECASE),
        "RC4 has severe statistical biases and has been prohibited by RFC 7465. "
        "Use AES-256-GCM or ChaCha20-Poly1305.",
    ),
    (
        "Blowfish cipher",
        "MEDIUM",
        0.8,
        re.compile(r"\bBlowfish\b|algorithms\.Blowfish\b", re.IGNORECASE),
        "Blowfish has a 64-bit block size making it vulnerable to SWEET32 birthday attacks. "
        "Use AES-256-GCM instead.",
    ),
    (
        "ECB cipher mode",
        "HIGH",
        0.9,
        re.compile(r"\bECB\b|modes\.ECB\b|MODE_ECB\b|mode\s*=\s*['\"]?ECB['\"]?", re.IGNORECASE),
        "ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking data patterns. "
        "Use AES-GCM or AES-CBC with a random IV instead.",
    ),
    (
        "random module used for security token/key/salt/password",
        "HIGH",
        0.85,
        re.compile(
            r"\brandom\.(random|randint|choice|choices|randrange|randbytes|getrandbits)\s*\(",
            re.IGNORECASE,
        ),
        "Python's random module uses a Mersenne Twister — it is NOT cryptographically secure "
        "and can be predicted after observing enough outputs. "
        "Use secrets.token_hex(), secrets.token_bytes(), or os.urandom() for security-sensitive values.",
    ),
    (
        "random.seed() with fixed value",
        "HIGH",
        0.9,
        re.compile(r"\brandom\.seed\s*\(\s*\d+\s*\)"),
        "A fixed seed makes random output fully deterministic and predictable. "
        "Never seed the random module with a constant in security-sensitive code.",
    ),
    (
        "Hardcoded zero IV or nonce",
        "HIGH",
        0.85,
        re.compile(
            r"\biv\s*=\s*b?['\"]\\x00+['\"]|\bnonce\s*=\s*b?['\"]\\x00+['\"]"
            r"|\biv\s*=\s*bytes?\(\s*\d+\s*\)|\bnonce\s*=\s*bytes?\(\s*\d+\s*\)",
            re.IGNORECASE,
        ),
        "A hardcoded or all-zeros IV/nonce defeats the security of the cipher. "
        "Always generate a fresh random IV/nonce for each encryption: iv = os.urandom(16).",
    ),
]


class WeakCryptographyDetector(Detector):
    name = "weak_cryptography"

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
                            message=f"Weak cryptography: {label}.",
                            line=lineno,
                            evidence=truncate_line(line),
                            recommendation=recommendation,
                        )
                    )

        return findings