"""Per-finding fix-suggestion orchestrator.

Takes a SARIF Finding + the source root, reads a window around the finding,
and asks Claude for a minimal corrective patch via LLMClient.suggest_fix.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from .llm_client import FixSuggestion, LLMClient
from .sarif_parser import Finding

log = logging.getLogger(__name__)

# Lines of context above/below the finding line to send to Claude.
DEFAULT_WINDOW = 12


@dataclass
class FindingWithFix:
    """Pair a Finding with its (optional) fix suggestion."""

    finding: Finding
    fix: FixSuggestion | None


def _read_window(
    src_root: Path,
    file_uri: str,
    around_line: int,
    context: int = DEFAULT_WINDOW,
) -> str:
    """Return a numbered code window around `around_line`."""
    rel = unquote(file_uri)
    if rel.startswith("file://"):
        rel = rel[len("file://") :]
    rel = rel.lstrip("/")
    full = (src_root / rel).resolve()
    if not full.exists():
        return f"<source not found: {full}>"
    try:
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:  # noqa: BLE001
        return f"<unable to read {full}: {e}>"
    if not lines or around_line <= 0:
        return "<empty source>"
    lo = max(1, around_line - context)
    hi = min(len(lines), around_line + context)
    return "\n".join(f"{n:>4}: {lines[n - 1]}" for n in range(lo, hi + 1))


def _build_user_prompt(
    finding: Finding,
    requirement: str,
    code_window: str,
    language: str,
) -> str:
    return (
        f"# Detection requirement\n"
        f"{requirement.strip()}\n\n"
        f"# Finding\n"
        f"- File: `{finding.file_uri}` at line {finding.start_line}\n"
        f"- Rule: `{finding.rule_id}` (severity: {finding.severity})\n"
        f"- Message: {finding.message.strip()}\n"
        f"- Language: `{language}`\n\n"
        f"# Vulnerable code (numbered lines, finding is at line {finding.start_line})\n"
        f"```\n{code_window}\n```\n\n"
        f"Return a minimal fix as per the schema. The `fixed_code` field should "
        f"contain the corrected version of the same line range above; keep the "
        f"line numbers as a leading column so the patch reads naturally."
    )


def suggest_fixes(
    client: LLMClient,
    findings: list[Finding],
    src_root: Path,
    requirement: str,
    language: str,
    context_lines: int = DEFAULT_WINDOW,
) -> list[FindingWithFix]:
    """One Claude call per finding (serial). Failed calls become FindingWithFix(fix=None)."""
    paired: list[FindingWithFix] = []
    for i, finding in enumerate(findings, start=1):
        log.info(
            "Suggesting fix for finding %d/%d: %s:%d",
            i,
            len(findings),
            finding.file_uri,
            finding.start_line,
        )
        window = _read_window(src_root, finding.file_uri, finding.start_line, context_lines)
        prompt = _build_user_prompt(finding, requirement, window, language)
        fix = client.suggest_fix(prompt)
        if fix is None:
            log.warning("No fix returned for finding at %s:%d", finding.file_uri, finding.start_line)
        paired.append(FindingWithFix(finding=finding, fix=fix))
    return paired
