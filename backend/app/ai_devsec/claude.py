"""
claude.py
---------
Claude AI chat service.

Sends scan findings + conversation history to the Anthropic Claude API
and returns a plain-text reply. The system prompt establishes Claude as
a senior security engineer who already knows what was found in the code.
"""

import os
import httpx
from typing import List

from .findings import Finding, ChatMessage


ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL      = "claude-opus-4-5"
ANTHROPIC_URL     = "https://api.anthropic.com/v1/messages"


def _build_system_prompt(findings: List[Finding], scanned_code: str) -> str:
    """
    Build the system prompt that gives Claude full context about the scan
    before the user's first message arrives.
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

    return f"""You are an expert security engineer reviewing code that has just been \
scanned by an automated SAST (Static Application Security Testing) tool called \
AI DevSec Platform.

Your job is to:
1. Help the user understand each security vulnerability found in their code.
2. Explain WHY it is dangerous in simple, clear language.
3. Show them exactly HOW to fix it with corrected code examples.
4. Answer any follow-up questions they have about their code or the findings.

Always be friendly, precise, and educational. Use code blocks when showing examples.
If the user asks about something unrelated to security or their code, politely steer \
the conversation back.

--- SCANNED CODE ---
{scanned_code[:3000]}{"..." if len(scanned_code) > 3000 else ""}

--- SCAN FINDINGS ({len(findings)} issue(s)) ---
{findings_text}
---

The user may now ask you questions about these findings or their code."""


async def chat_with_claude(
    findings: List[Finding],
    scanned_code: str,
    message: str,
    history: List[ChatMessage],
) -> str:
    """
    Send a message to Claude with full scan context and return the reply.

    Claude's messages API expects:
      - A top-level system prompt (separate from messages)
      - A messages array of {"role": "user"|"assistant", "content": str} dicts
      - Roles must strictly alternate user / assistant

    Raises RuntimeError on API or auth errors so the router returns HTTP 502.
    """
    if not ANTHROPIC_API_KEY:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. "
            "Add it to your .env file and restart the server."
        )

    # Build the messages array from history + current message.
    # Claude uses "user" and "assistant" (not "model").
    messages = [
        {"role": turn.role, "content": turn.text}
        for turn in history
    ]
    messages.append({"role": "user", "content": message})

    payload = {
        "model":      CLAUDE_MODEL,
        "max_tokens": 1024,
        "system":     _build_system_prompt(findings, scanned_code),
        "messages":   messages,
    }

    headers = {
        "x-api-key":         ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(ANTHROPIC_URL, json=payload, headers=headers)

    if response.status_code != 200:
        raise RuntimeError(
            f"Claude API returned {response.status_code}: {response.text[:300]}"
        )

    data = response.json()

    try:
        return data["content"][0]["text"]
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"Unexpected Claude response shape: {e} — {data}")