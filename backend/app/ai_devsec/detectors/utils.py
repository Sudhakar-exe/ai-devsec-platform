"""Shared utilities for detectors."""


def truncate_line(line: str, max_len: int = 180) -> str:
    """Truncate a line of evidence to avoid excessively long output."""
    line = line.strip()
    return (line[:max_len] + "…") if len(line) > max_len else line