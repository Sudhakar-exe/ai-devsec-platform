"""
Gemini chat service.

Sends scan findings + conversation history to the Gemini API and
returns a plain-text reply. The system prompt establishes Gemini as
a senior security engineer who already knows what was found in the code.
"""

import os
import httpx
from typing import List

from .schemas import Finding, ChatMessage


GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL   = "gemini-1.5-flash"
GEMINI_URL     = (
    f"https://generativelanguage.googleapis.com/v1beta/models"
    f"/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
)


def _build_system_prompt(findings: List[Finding], scanned_code: str) -> str:
    """
    Build the system instruction that primes Gemini with full scan context.
    """
    if findings:
        findings_text = "\n".join(
            f"- [{f.severity}] {f.detector} at line {f.line or '?'}: {f.message}\n"
            f"  Evidence: {f.evidence or 'N/A'}\n"
            f"  Recommendation: {f.recommendation or 'N/A'}"
            for f in findings
        )
    else:
        findings_text = "No vulnerabilities were detected."

    return f"""You are an expert security engineer reviewing code that has just been scanned by an automated SAST (Static Application Security Testing) tool called AI DevSec Platform.

Your job is to:
1. Help the user understand each security vulnerability found in their code.
2. Explain WHY it is dangerous in simple, clear language.
3. Show them exactly HOW to fix it with corrected code examples.
4. Answer any follow-up questions they have about their code or the findings.

Always be friendly, precise, and educational. Use code blocks when showing examples.
If the user asks about something unrelated to security or their code, politely steer the conversation back.

--- SCANNED CODE ---
{scanned_code[:3000]}{"..." if len(scanned_code) > 3000 else ""}

--- SCAN FINDINGS ({len(findings)} issue(s)) ---
{findings_text}
---

The user may now ask you questions about these findings or their code."""


async def chat_with_gemini(
    findings: List[Finding],
    scanned_code: str,
    message: str,
    history: List[ChatMessage],
) -> str:
    """
    Send a message to Gemini with full context and return the reply text.
    Raises RuntimeError on API errors so the router can return a clean HTTP 502.
    """
    if not GEMINI_API_KEY:
        raise RuntimeError(
            "GEMINI_API_KEY is not set. "
            "Add it to your .env file and restart the server."
        )

    # Build the conversation contents array
    # Gemini expects alternating user/model turns.
    contents = []
    for turn in history:
        contents.append({
            "role": turn.role,
            "parts": [{"text": turn.text}],
        })

    # Append the current user message
    contents.append({
        "role": "user",
        "parts": [{"text": message}],
    })

    payload = {
        "system_instruction": {
            "parts": [{"text": _build_system_prompt(findings, scanned_code)}]
        },
        "contents": contents,
        "generationConfig": {
            "temperature": 0.4,      # low = more precise / less creative
            "maxOutputTokens": 1024,
        },
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(GEMINI_URL, json=payload)

    if response.status_code != 200:
        raise RuntimeError(
            f"Gemini API returned {response.status_code}: {response.text[:300]}"
        )

    data = response.json()

    try:
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"Unexpected Gemini response shape: {e} — {data}")