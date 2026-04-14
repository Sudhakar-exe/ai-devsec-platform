# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

**Setup:**
```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
```

**Run the server** (from project root):
```bash
uvicorn backend.app.main:app --reload
# Serves API on http://localhost:8000
# Frontend served from frontend/index.html via static files or opened directly
```

**Run tests:**
```bash
pytest backend/tests/ -v
# Run a single test:
pytest backend/tests/test_ai_devsec.py::test_dangerous_exec_detector_flags_os_system -v
```

**Environment:**
- Copy `.env` and set `ANTHROPIC_API_KEY` (required for Claude AI features)

## Architecture

**Backend**: FastAPI with a layered design — HTTP routes → service → detectors → data models.

**Frontend**: Single `frontend/index.html` file with all CSS and JS embedded. No build step.

### API Endpoints (`backend/app/ai_devsec/router.py`)
- `POST /api/ai-devsec/scan` — scan a plain-text code snippet
- `POST /api/ai-devsec/scan-diff` — parse a git diff, scan only added lines
- `POST /api/ai-devsec/chat` — conversational follow-up using scan context

### Key Files
- `backend/app/ai_devsec/detectors.py` — 10 `Detector` subclasses; add new detectors here and register them in the `DETECTORS` list
- `backend/app/ai_devsec/service.py` — `run_scan()` orchestrates all detectors; `compute_risk_score()` weights findings by severity (LOW=10, MEDIUM=25, HIGH=45, CRITICAL=70) × confidence, capped at 100; `extract_added_lines()` parses git diffs
- `backend/app/ai_devsec/claude.py` — async Claude API client using `claude-opus-4-5`; builds conversation history and injects scan context into the system prompt
- `backend/app/ai_devsec/findings.py` — Pydantic models (`Finding`, `ScanResponse`, `ChatRequest/Response`); `mask_sensitive()` redacts credential values in evidence before returning to clients
- `frontend/index.html` — tab-based UI for code scanning, diff scanning, and chat

### Detector Pattern
Each detector inherits from a base `Detector` class and implements regex-based pattern matching. The 10 built-in detectors cover: secrets, dangerous exec, hardcoded credentials, insecure HTTP, download-exec chains, SQL injection, insecure deserialization, path traversal, weak cryptography, and debug misconfiguration.
