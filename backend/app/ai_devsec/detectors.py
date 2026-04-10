"""
detectors.py  —  All 10 security detectors in one file.

Each detector inherits from Detector, defines its PATTERNS, and implements run().
To add a new detector: write the class, add an instance to DETECTORS at the bottom.
"""

import re
from abc import ABC, abstractmethod
from typing import List

from .findings import Finding, truncate_line, mask_sensitive


# ──────────────────────────────────────────────────────────────────────────────
# Base class
# ──────────────────────────────────────────────────────────────────────────────

class Detector(ABC):
    name: str

    @abstractmethod
    def run(self, code: str) -> List[Finding]:
        raise NotImplementedError


# ──────────────────────────────────────────────────────────────────────────────
# 1. Secrets
# ──────────────────────────────────────────────────────────────────────────────

_SECRETS_PATTERNS = [
    ("AWS Access Key",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token",
     re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("Generic API Key assignment",
     re.compile(r"\bapi[_-]?key\b\s*[:=]\s*['\"][^'\"]{16,}['\"]", re.IGNORECASE)),
    ("Private key header",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]


class SecretsDetector(Detector):
    name = "secrets"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            for label, rx in _SECRETS_PATTERNS:
                if rx.search(line):
                    findings.append(Finding(
                        detector=self.name, severity="CRITICAL", confidence=0.9,
                        message=f"Possible secret detected: {label}",
                        line=lineno, evidence=truncate_line(line),
                        recommendation="Remove it, rotate the credential, and store it in env vars or a secret manager.",
                    ))
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# 2. Dangerous execution
# ──────────────────────────────────────────────────────────────────────────────

_EXEC_PATTERNS = [
    ("eval()",                      re.compile(r"\beval\s*\(")),
    ("exec()",                      re.compile(r"\bexec\s*\(")),
    ("os.system()",                 re.compile(r"\bos\.system\s*\(")),
    ("subprocess.run/call/Popen()", re.compile(r"\bsubprocess\.(run|call|Popen)\s*\(")),
    ("shell=True",                  re.compile(r"\bshell\s*=\s*True\b")),
]


class DangerousExecDetector(Detector):
    name = "dangerous_exec"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            for label, rx in _EXEC_PATTERNS:
                if rx.search(line):
                    findings.append(Finding(
                        detector=self.name, severity="HIGH", confidence=0.8,
                        message=f"Potentially dangerous execution primitive: {label}",
                        line=lineno, evidence=truncate_line(line),
                        recommendation="Avoid dynamic execution. Never use shell=True unless inputs are strictly controlled.",
                    ))
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# 3. Hardcoded credentials
# ──────────────────────────────────────────────────────────────────────────────

_CREDS_KV = [
    ("Hardcoded password",
     re.compile(r"\b(pass(word)?|passwd)\b\s*[:=]\s*(['\"]).*?\3", re.IGNORECASE)),
    ("Hardcoded secret",
     re.compile(r"\bsecret\b\s*[:=]\s*(['\"]).*?\1", re.IGNORECASE)),
    ("Hardcoded token",
     re.compile(r"\b(token|api[_-]?token|access[_-]?token)\b\s*[:=]\s*(['\"]).*?\2", re.IGNORECASE)),
]
_CREDS_BEARER = re.compile(r"\bauthorization\b\s*:\s*bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
_CREDS_URL    = re.compile(r"://[^/\s:]+:[^/\s@]+@", re.IGNORECASE)


class HardcodedCredsDetector(Detector):
    name = "hardcoded_creds"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            for label, rx in _CREDS_KV:
                if rx.search(line):
                    findings.append(Finding(
                        detector=self.name, severity="HIGH", confidence=0.8,
                        message=f"{label} detected.",
                        line=lineno, evidence=mask_sensitive(line),
                        recommendation="Remove hardcoded credentials. Use environment variables or a secret manager.",
                    ))
            if _CREDS_BEARER.search(line):
                findings.append(Finding(
                    detector=self.name, severity="HIGH", confidence=0.85,
                    message="Authorization header token detected.",
                    line=lineno, evidence=mask_sensitive(line),
                    recommendation="Do not hardcode auth tokens. Inject them securely via secrets/ENV.",
                ))
            if _CREDS_URL.search(line):
                findings.append(Finding(
                    detector=self.name, severity="HIGH", confidence=0.75,
                    message="Credentials in URL detected.",
                    line=lineno, evidence=mask_sensitive(line),
                    recommendation="Remove credentials from URLs. Use secure credential storage.",
                ))
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# 4. Insecure HTTP
# ──────────────────────────────────────────────────────────────────────────────

_HTTP_RX    = re.compile(r"http://", re.IGNORECASE)
_SAFE_HOSTS = re.compile(
    r"http://(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)(:\d+)?(/|$|\s|['\"])",
    re.IGNORECASE,
)


class InsecureHTTPDetector(Detector):
    name = "insecure_http"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            if _HTTP_RX.search(line) and not _SAFE_HOSTS.search(line):
                findings.append(Finding(
                    detector=self.name, severity="MEDIUM", confidence=0.7,
                    message="Insecure HTTP connection detected (use HTTPS).",
                    line=lineno, evidence=truncate_line(line),
                    recommendation="Use HTTPS instead of HTTP to ensure encrypted communication.",
                ))
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# 5. Download and execute
# ──────────────────────────────────────────────────────────────────────────────

_DLEXEC_PATTERNS = [
    ("curl pipe to bash/sh",    re.compile(r"\bcurl\b.*\|\s*(bash|sh)\b",          re.IGNORECASE)),
    ("wget pipe to bash/sh",    re.compile(r"\bwget\b.*\|\s*(bash|sh)\b",          re.IGNORECASE)),
    ("curl then bash/sh",       re.compile(r"\bcurl\b.*;\s*(bash|sh)\b",           re.IGNORECASE)),
    ("wget then bash/sh",       re.compile(r"\bwget\b.*;\s*(bash|sh)\b",           re.IGNORECASE)),
    ("PowerShell IEX",          re.compile(r"\bpowershell\b.*\b(iex|invoke-expression)\b", re.IGNORECASE)),
    ("Invoke-WebRequest + IEX", re.compile(r"invoke-webrequest.*\|\s*(iex|invoke-expression)", re.IGNORECASE)),
]


class DownloadExecDetector(Detector):
    name = "download_exec"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            for label, rx in _DLEXEC_PATTERNS:
                if rx.search(line):
                    findings.append(Finding(
                        detector=self.name, severity="CRITICAL", confidence=0.85,
                        message=f"Suspicious download-and-execute pattern detected: {label}",
                        line=lineno, evidence=truncate_line(line),
                        recommendation="Do not pipe remote content into a shell. Download, verify integrity, review, then execute safely.",
                    ))
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# 6. SQL injection
# Note: quote characters in the patterns use a character class [quote_chars]
# where quote_chars is built at module load to avoid Python string conflicts.
# ──────────────────────────────────────────────────────────────────────────────

_Q = r"""['"]{1}"""   # matches either " or '

_SQL_PATTERNS = [
    ("f-string SQL query",
     re.compile(r"f" + _Q + r".*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b.*\{", re.IGNORECASE)),
    ("%-format SQL query",
     re.compile(_Q + r".*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b.*" + _Q + r".*%\s*[^(]", re.IGNORECASE)),
    (".format() SQL query",
     re.compile(_Q + r".*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b.*" + _Q + r"\.format\(", re.IGNORECASE)),
    ("string concatenation in SQL (right side)",
     re.compile(_Q + r".*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b.*" + _Q + r"\s*\+", re.IGNORECASE)),
    ("string concatenation in SQL (left side)",
     re.compile(r"\+\s*" + _Q + r".*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b", re.IGNORECASE)),
]


class SQLInjectionDetector(Detector):
    name = "sql_injection"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            s = line.strip()
            if s.startswith("#") or s.startswith("//") or s.startswith("--"):
                continue
            for label, rx in _SQL_PATTERNS:
                if rx.search(line):
                    findings.append(Finding(
                        detector=self.name, severity="CRITICAL", confidence=0.85,
                        message=f"Potential SQL injection via {label}.",
                        line=lineno, evidence=truncate_line(line),
                        recommendation=(
                            "Never build SQL queries with string formatting or concatenation. "
                            "Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', (user_id,))."
                        ),
                    ))
                    break  # one finding per line is enough
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# 7. Insecure deserialization
# ──────────────────────────────────────────────────────────────────────────────

_DESER_PATTERNS = [
    ("pickle.loads()", "CRITICAL", 0.9,
     re.compile(r"\bpickle\.(loads?|Unpickler)\s*\("),
     "pickle can execute arbitrary code when deserializing untrusted data. Use JSON or Pydantic instead."),
    ("yaml.load() without Loader", "CRITICAL", 0.9,
     re.compile(r"\byaml\.load\s*\(\s*(?![^)]*Loader\s*=\s*yaml\.(?:Safe|Base)Loader)"),
     "yaml.load() with the default loader can execute arbitrary Python code. Use yaml.safe_load() instead."),
    ("marshal.loads()", "HIGH", 0.85,
     re.compile(r"\bmarshal\.(loads?|load)\s*\("),
     "marshal is not secure against maliciously crafted data. Use JSON or another safe format."),
    ("jsonpickle.decode()", "CRITICAL", 0.9,
     re.compile(r"\bjsonpickle\.decode\s*\("),
     "jsonpickle.decode() can deserialize arbitrary Python objects and execute code."),
    ("shelve.open()", "MEDIUM", 0.7,
     re.compile(r"\bshelve\.open\s*\("),
     "shelve uses pickle internally. Do not open shelve files from untrusted sources."),
]


class InsecureDeserializationDetector(Detector):
    name = "insecure_deserialization"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            for label, severity, confidence, rx, rec in _DESER_PATTERNS:
                if rx.search(line):
                    findings.append(Finding(
                        detector=self.name, severity=severity, confidence=confidence,
                        message=f"Insecure deserialization: {label} can execute arbitrary code on untrusted input.",
                        line=lineno, evidence=truncate_line(line), recommendation=rec,
                    ))
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# 8. Path traversal
# ──────────────────────────────────────────────────────────────────────────────

_PT_USER_INPUT = re.compile(
    r"\b(request\.(args|form|json|data|files|params|get|values|POST|GET)"
    r"|user_input|user_file|filename|filepath|path_param"
    r"|input_path|file_name|upload_name|query_param)\b",
    re.IGNORECASE,
)
_PT_FS_CALLS = re.compile(
    r"\b(open\s*\(|os\.path\.(join|abspath|realpath)\s*\("
    r"|pathlib\.Path\s*\("
    r"|os\.(remove|unlink|rename|mkdir|makedirs|listdir|scandir|stat|chmod|chown)\s*\("
    r"|shutil\.(copy|move|rmtree)\s*\()",
    re.IGNORECASE,
)
_PT_LITERAL = re.compile(r"\.\.[\\/]|\.\.%2[Ff]|%2[Ee]%2[Ee]")
_PT_CONCAT  = re.compile(
    r"['\"][\w./\\-]*(uploads?|files?|static|media|tmp|temp|data)[\w./\\-]*['\"]\s*\+",
    re.IGNORECASE,
)


class PathTraversalDetector(Detector):
    name = "path_traversal"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            if _PT_LITERAL.search(line):
                findings.append(Finding(
                    detector=self.name, severity="HIGH", confidence=0.9,
                    message="Path traversal sequence '../' found in string literal.",
                    line=lineno, evidence=truncate_line(line),
                    recommendation=(
                        "Use os.path.basename() to strip directory parts, then join onto a fixed base. "
                        "Verify: os.path.realpath(full_path).startswith(os.path.realpath(BASE_DIR))"
                    ),
                ))
                continue
            if _PT_FS_CALLS.search(line) and _PT_USER_INPUT.search(line):
                findings.append(Finding(
                    detector=self.name, severity="HIGH", confidence=0.8,
                    message="User-controlled value passed directly to a file-system call — possible path traversal.",
                    line=lineno, evidence=truncate_line(line),
                    recommendation="Sanitize with os.path.basename() and verify the final path stays inside BASE_DIR.",
                ))
                continue
            if _PT_CONCAT.search(line):
                findings.append(Finding(
                    detector=self.name, severity="MEDIUM", confidence=0.65,
                    message="Directory path concatenated with a variable — possible path traversal if variable is user-controlled.",
                    line=lineno, evidence=truncate_line(line),
                    recommendation="Use os.path.join() and validate the result with os.path.realpath().",
                ))
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# 9. Weak cryptography
# ──────────────────────────────────────────────────────────────────────────────

_CRYPTO_PATTERNS = [
    ("MD5 used for security", "HIGH", 0.8,
     re.compile(r"\bhashlib\.md5\s*\(|\.new\s*\(\s*['\"]md5['\"]", re.IGNORECASE),
     "MD5 is cryptographically broken. Use SHA-256 or SHA-3 for integrity; bcrypt/argon2 for passwords."),
    ("SHA-1 used for security", "HIGH", 0.8,
     re.compile(r"\bhashlib\.sha1\s*\(|\.new\s*\(\s*['\"]sha1['\"]", re.IGNORECASE),
     "SHA-1 is broken since 2017 (SHAttered). Use SHA-256 or SHA-3."),
    ("DES cipher", "CRITICAL", 0.9,
     re.compile(r"\bDES\b|\bDES3\b|\bTripleDES\b|algorithms\.(DES|TripleDES)\b", re.IGNORECASE),
     "DES was cracked in 1999. 3DES is deprecated by NIST. Use AES-256-GCM."),
    ("RC4 cipher", "CRITICAL", 0.9,
     re.compile(r"\bRC4\b|\bARC4\b|algorithms\.ARC4\b", re.IGNORECASE),
     "RC4 is prohibited by RFC 7465. Use AES-256-GCM or ChaCha20-Poly1305."),
    ("Blowfish cipher", "MEDIUM", 0.8,
     re.compile(r"\bBlowfish\b|algorithms\.Blowfish\b", re.IGNORECASE),
     "Blowfish's 64-bit blocks are vulnerable to SWEET32. Use AES-256-GCM."),
    ("ECB cipher mode", "HIGH", 0.9,
     re.compile(r"\bECB\b|modes\.ECB\b|MODE_ECB\b|mode\s*=\s*['\"]?ECB['\"]?", re.IGNORECASE),
     "ECB leaks data patterns. Use AES-GCM or AES-CBC with a random IV."),
    ("random module (not crypto-safe)", "HIGH", 0.85,
     re.compile(r"\brandom\.(random|randint|choice|choices|randrange|randbytes|getrandbits)\s*\(", re.IGNORECASE),
     "Python's random module is not cryptographically secure. Use secrets.token_hex() or os.urandom()."),
    ("random.seed() with fixed value", "HIGH", 0.9,
     re.compile(r"\brandom\.seed\s*\(\s*\d+\s*\)"),
     "A fixed seed makes output predictable. Never seed random with a constant in security code."),
    ("Hardcoded zero IV or nonce", "HIGH", 0.85,
     re.compile(
         r"\biv\s*=\s*b?['\"]\\x00+['\"]|\bnonce\s*=\s*b?['\"]\\x00+['\"]"
         r"|\biv\s*=\s*bytes?\(\s*\d+\s*\)|\bnonce\s*=\s*bytes?\(\s*\d+\s*\)",
         re.IGNORECASE,
     ),
     "A hardcoded or all-zeros IV/nonce defeats cipher security. Use iv = os.urandom(16)."),
]


class WeakCryptographyDetector(Detector):
    name = "weak_cryptography"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            for label, severity, confidence, rx, rec in _CRYPTO_PATTERNS:
                if rx.search(line):
                    findings.append(Finding(
                        detector=self.name, severity=severity, confidence=confidence,
                        message=f"Weak cryptography: {label}.",
                        line=lineno, evidence=truncate_line(line), recommendation=rec,
                    ))
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# 10. Debug and misconfiguration
# ──────────────────────────────────────────────────────────────────────────────

_MISCONFIG_PATTERNS = [
    ("Flask DEBUG=True", "HIGH", 0.9,
     re.compile(r"\bapp\.run\s*\(.*\bdebug\s*=\s*True\b", re.IGNORECASE),
     "Flask debug mode exposes an interactive browser console. Never deploy with debug=True."),
    ("Flask DEBUG via app.config", "HIGH", 0.9,
     re.compile(r"\bapp\.config\s*\[.?DEBUG.?\]\s*=\s*True\b", re.IGNORECASE),
     "Flask debug mode exposes an interactive debugger on error pages. Set via environment variable only."),
    ("Django DEBUG=True", "HIGH", 0.9,
     re.compile(r"^\s*DEBUG\s*=\s*True\b", re.IGNORECASE),
     "Django DEBUG=True exposes stack traces, SQL queries, and settings. Use os.getenv('DJANGO_DEBUG')."),
    ("Django ALLOWED_HOSTS wildcard", "MEDIUM", 0.9,
     re.compile(r"\bALLOWED_HOSTS\s*=\s*\[?\s*['\"]?\*['\"]?\s*\]?"),
     "ALLOWED_HOSTS=['*'] disables host header validation. List your actual domains explicitly."),
    ("SSL verify=False", "HIGH", 0.95,
     re.compile(r"\bverify\s*=\s*False\b"),
     "Disabling SSL verification removes MITM protection. Fix the certificate instead."),
    ("ssl.CERT_NONE", "HIGH", 0.95,
     re.compile(r"\bssl\.CERT_NONE\b"),
     "ssl.CERT_NONE disables certificate validation. Use ssl.CERT_REQUIRED."),
    ("check_hostname=False", "HIGH", 0.9,
     re.compile(r"\bcheck_hostname\s*=\s*False\b"),
     "Disabling hostname checking allows MITM with any valid certificate. Set check_hostname=True."),
    ("assert used as auth check", "MEDIUM", 0.75,
     re.compile(
         r"\bassert\s+.*(auth|permission|is_admin|logged_in|is_authenticated"
         r"|access|authorized|allowed|role|token|user)\b",
         re.IGNORECASE,
     ),
     "assert statements are stripped in optimized mode (-O). Use explicit if/raise for security checks."),
    ("Bare except clause", "LOW", 0.7,
     re.compile(r"^\s*except\s*:\s*$|^\s*except\s+Exception\s*:\s*$"),
     "Catching all exceptions swallows security-relevant errors. Catch specific exceptions and log unexpected ones."),
]


class DebugMisconfigDetector(Detector):
    name = "debug_misconfig"

    def run(self, code: str) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            for label, severity, confidence, rx, rec in _MISCONFIG_PATTERNS:
                if rx.search(line):
                    findings.append(Finding(
                        detector=self.name, severity=severity, confidence=confidence,
                        message=f"Dangerous misconfiguration: {label}.",
                        line=lineno, evidence=truncate_line(line), recommendation=rec,
                    ))
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# Master list — imported by service.py
# ──────────────────────────────────────────────────────────────────────────────

DETECTORS: List[Detector] = [
    SecretsDetector(),
    DangerousExecDetector(),
    HardcodedCredsDetector(),
    InsecureHTTPDetector(),
    DownloadExecDetector(),
    SQLInjectionDetector(),
    InsecureDeserializationDetector(),
    PathTraversalDetector(),
    WeakCryptographyDetector(),
    DebugMisconfigDetector(),
]