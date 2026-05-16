"""Compile and run generated `.ql` queries via the `codeql` CLI."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "qlpack_templates"

# Mapping from canonical CodeQL language name to template basename
TEMPLATE_BY_LANG = {
    "python": "python.yml",
    "java-kotlin": "java.yml",
    "cpp": "cpp.yml",
    "go": "go.yml",
    "csharp": "csharp.yml",
    "ruby": "ruby.yml",
    "swift": "swift.yml",
}


@dataclass
class QueryRunResult:
    success: bool
    stderr: str
    sarif_path: Path | None
    stage: str  # "compile" or "analyze"


def _stage_query(workdir: Path, ql_code: str, language: str) -> Path:
    """Write the .ql file and a qlpack.yml into a fresh workdir."""
    workdir.mkdir(parents=True, exist_ok=True)
    query_path = workdir / "query.ql"
    query_path.write_text(ql_code, encoding="utf-8")

    template = TEMPLATE_DIR / TEMPLATE_BY_LANG[language]
    qlpack = workdir / "qlpack.yml"
    shutil.copyfile(template, qlpack)
    return query_path


def _truncate(text: str, max_chars: int = 4000) -> str:
    if len(text) <= max_chars:
        return text
    head = text[: max_chars // 2]
    tail = text[-max_chars // 2 :]
    return f"{head}\n... [{len(text) - max_chars} chars truncated] ...\n{tail}"


def compile_and_run(
    ql_code: str,
    language: str,
    database: Path,
    workdir: Path,
    sarif_out: Path,
    analyze_timeout_s: int = 600,
) -> QueryRunResult:
    """Stage the query, compile it, then analyze if compile succeeded."""
    query_path = _stage_query(workdir, ql_code, language)

    # Stage 1: compile-only check (fast fail)
    compile_args = [
        "codeql",
        "query",
        "compile",
        "--check-only",
        str(query_path),
    ]
    log.info("Compiling: %s", " ".join(compile_args))
    proc = subprocess.run(compile_args, capture_output=True, text=True)
    if proc.returncode != 0:
        stderr = proc.stderr or proc.stdout
        log.warning("compile failed (rc=%d):\n%s", proc.returncode, stderr)
        return QueryRunResult(
            success=False,
            stderr=_truncate(stderr),
            sarif_path=None,
            stage="compile",
        )

    # Stage 2: analyze
    analyze_args = [
        "codeql",
        "database",
        "analyze",
        str(database),
        str(query_path),
        "--format=sarif-latest",
        f"--output={sarif_out}",
        "--rerun",
    ]
    log.info("Analyzing: %s", " ".join(analyze_args))
    proc = subprocess.run(
        analyze_args,
        capture_output=True,
        text=True,
        timeout=analyze_timeout_s,
    )
    if proc.returncode != 0:
        stderr = proc.stderr or proc.stdout
        log.warning("analyze failed (rc=%d):\n%s", proc.returncode, stderr)
        return QueryRunResult(
            success=False,
            stderr=_truncate(stderr),
            sarif_path=None,
            stage="analyze",
        )

    log.info("Analysis complete. SARIF: %s", sarif_out)
    return QueryRunResult(
        success=True,
        stderr="",
        sarif_path=sarif_out,
        stage="analyze",
    )
