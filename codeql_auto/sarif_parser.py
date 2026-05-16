"""Parse SARIF 2.1.0 output and render a Markdown report."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file_uri: str
    start_line: int
    end_line: int
    snippet: str  # source context with line numbers


def _read_context(src_root: Path, rel_path: str, line: int, context: int = 3) -> str:
    """Read ±context lines around `line` from rel_path, with line numbers."""
    try:
        # SARIF URIs can be percent-encoded; normalize the simple case
        from urllib.parse import unquote

        rel = unquote(rel_path)
        # Strip file:// prefix if present
        if rel.startswith("file://"):
            rel = rel[len("file://") :]
        # Drop a leading slash so the join works on relative paths
        rel = rel.lstrip("/")
        full = (src_root / rel).resolve()
        if not full.exists():
            return f"<source not found: {full}>"
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
        lo = max(1, line - context)
        hi = min(len(lines), line + context)
        out = []
        for n in range(lo, hi + 1):
            marker = ">>>" if n == line else "   "
            out.append(f"{n:>4} {marker} {lines[n - 1]}")
        return "\n".join(out)
    except Exception as exc:  # pragma: no cover
        return f"<unable to read context: {exc}>"


def parse_sarif(sarif_path: Path, src_root: Path) -> list[Finding]:
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for run in data.get("runs", []):
        # Build rule lookup for severity
        rules_by_id: dict[str, dict] = {}
        for rule in (run.get("tool", {}).get("driver", {}).get("rules") or []):
            rid = rule.get("id")
            if rid:
                rules_by_id[rid] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "<unknown>")
            severity = result.get("level") or (
                rules_by_id.get(rule_id, {})
                .get("defaultConfiguration", {})
                .get("level", "warning")
            )
            message = (result.get("message", {}) or {}).get("text", "<no message>")

            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                uri = artifact.get("uri", "<unknown>")
                start_line = int(region.get("startLine", 0) or 0)
                end_line = int(region.get("endLine", start_line) or start_line)
                snippet = _read_context(src_root, uri, start_line) if start_line else ""
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        file_uri=uri,
                        start_line=start_line,
                        end_line=end_line,
                        snippet=snippet,
                    )
                )
    return findings


def render_markdown(
    findings: list[Finding],
    requirement: str,
    language: str,
    database_path: Path,
    query_path: Path,
    sarif_path: Path,
    iterations: int,
    explanation: str,
    findings_with_fixes: list | None = None,  # list[FindingWithFix] from fix_suggester
) -> str:
    """Render the report.

    If `findings_with_fixes` is provided, fix suggestions are inlined after each
    finding's code block. It must align 1:1 with `findings` (same order).
    """
    fix_lookup = {}
    if findings_with_fixes is not None:
        if len(findings_with_fixes) != len(findings):
            raise ValueError(
                f"findings_with_fixes length ({len(findings_with_fixes)}) "
                f"does not match findings length ({len(findings)})"
            )
        for i, pair in enumerate(findings_with_fixes):
            fix_lookup[i] = pair.fix  # may be None

    fixes_generated = sum(1 for f in fix_lookup.values() if f is not None)

    lines = [
        "# CodeQL Detection Report",
        "",
        f"- **Requirement**: {requirement}",
        f"- **Language**: `{language}`",
        f"- **Database**: `{database_path}`",
        f"- **Generated query**: `{query_path}`",
        f"- **SARIF**: `{sarif_path}`",
        f"- **LLM iterations until success**: {iterations}",
    ]
    if findings_with_fixes is not None:
        lines.append(
            f"- **Fix suggestions**: {fixes_generated}/{len(findings)} generated"
        )
    lines += [
        "",
        "## Query summary",
        "",
        explanation.strip() or "_(no explanation provided)_",
        "",
        f"## Findings ({len(findings)})",
        "",
    ]

    if not findings:
        lines += [
            "_No findings. The query compiled and ran, but no matches were produced. "
            "Consider broadening the requirement or re-running with `--max-repair` higher._",
            "",
        ]
        return "\n".join(lines)

    for i, f in enumerate(findings, start=1):
        lines += [
            f"### #{i} — `{f.file_uri}:{f.start_line}`",
            "",
            f"- **Rule**: `{f.rule_id}`",
            f"- **Severity**: `{f.severity}`",
            "",
            f.message.strip(),
            "",
            "**Vulnerable code:**",
            "",
            "```",
            f.snippet,
            "```",
            "",
        ]

        fix = fix_lookup.get(i - 1)
        if fix is not None:
            extras = ""
            if fix.extra_imports:
                extras = (
                    " New imports: "
                    + ", ".join(f"`{m}`" for m in fix.extra_imports)
                    + "."
                )
            lines += [
                "**Suggested fix:**",
                "",
                "```",
                fix.fixed_code.rstrip(),
                "```",
                "",
                f"_Rationale_: {fix.rationale.strip()}{extras}",
                "",
            ]
        elif findings_with_fixes is not None:
            lines += [
                "_Fix suggestion: not generated (LLM call failed; see logs)._",
                "",
            ]

    return "\n".join(lines)
