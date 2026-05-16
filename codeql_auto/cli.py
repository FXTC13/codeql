"""Command-line entry point for codeql-auto."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .db_builder import (
    BuildCommandRequired,
    CodeQLNotFound,
    DatabaseSpec,
    build_database,
    detect_language,
    normalize_language,
)
from .llm_client import LLMClient
from .repair_loop import run_with_repair
from .sarif_parser import parse_sarif, render_markdown

log = logging.getLogger("codeql_auto")


def _add_run_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--src", type=Path, required=True, help="Source code root directory")
    p.add_argument(
        "--requirement",
        required=True,
        help="Natural-language detection requirement",
    )
    p.add_argument(
        "--language",
        help="Target language (python|java|cpp|go|csharp|ruby|swift). "
        "Auto-detected from file extensions if omitted.",
    )
    p.add_argument(
        "--build-cmd",
        help="Build command for compiled languages (e.g. 'mvn -B compile', 'make')",
    )
    p.add_argument(
        "--snippet",
        help="Optional inline code snippet to give Claude as extra context",
    )
    p.add_argument(
        "--snippet-file",
        type=Path,
        help="Read --snippet content from this file",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./codeql-out"),
        help="Directory for db/, query.ql, results.sarif, report.md",
    )
    p.add_argument("--max-repair", type=int, default=3, help="Max repair iterations")
    p.add_argument("--model", default="claude-opus-4-7", help="Claude model ID")
    p.add_argument(
        "--effort",
        default="high",
        choices=["low", "medium", "high", "max"],
        help="Reasoning effort for Claude (max requires Opus tier)",
    )
    p.add_argument(
        "--skip-db-build",
        action="store_true",
        help="Reuse an existing database at <output-dir>/db instead of rebuilding",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG logging")


def cmd_run(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    src: Path = args.src.resolve()
    if not src.is_dir():
        log.error("--src %s is not a directory", src)
        return 2

    # Resolve language
    try:
        if args.language:
            lang = normalize_language(args.language)
        else:
            lang = detect_language(src)
            log.info("Auto-detected language: %s", lang)
    except ValueError as e:
        log.error(str(e))
        return 2

    # Prepare output layout
    out: Path = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    db_path = out / "db"
    workdir = out / "workdir"
    sarif_path = out / "results.sarif"
    query_archive = out / "query.ql"
    report_path = out / "report.md"

    # Resolve optional snippet
    snippet: str | None = args.snippet
    if args.snippet_file and not snippet:
        snippet = args.snippet_file.read_text(encoding="utf-8")

    # 1. Build database
    if args.skip_db_build and db_path.exists():
        log.info("Skipping database build; using existing %s", db_path)
    else:
        spec = DatabaseSpec(
            src=src,
            language=lang,
            db_path=db_path,
            build_cmd=args.build_cmd,
        )
        try:
            build_database(spec)
        except CodeQLNotFound as e:
            log.error(str(e))
            return 3
        except BuildCommandRequired as e:
            log.error(str(e))
            return 4

    # 2. Generate + run + repair
    client = LLMClient(model=args.model, effort=args.effort)
    try:
        outcome = run_with_repair(
            client=client,
            requirement=args.requirement,
            language=lang,
            database=db_path,
            workdir=workdir,
            sarif_out=sarif_path,
            snippet=snippet,
            max_iters=args.max_repair,
        )
    except Exception as e:  # noqa: BLE001 -- surface anything to the user
        log.exception("Generation/execution pipeline failed: %s", e)
        return 5

    # 3. Archive the final query regardless of success
    query_archive.write_text(outcome.final_query.ql_code, encoding="utf-8")

    if not outcome.success:
        log.error(
            "Repair loop exhausted after %d iterations. Last %s stderr saved.",
            outcome.iterations,
            outcome.final_run.stage,
        )
        (out / "last_stderr.txt").write_text(
            outcome.final_run.stderr, encoding="utf-8"
        )
        return 6

    # 4. Parse SARIF + render report
    findings = parse_sarif(sarif_path, src_root=src)
    md = render_markdown(
        findings=findings,
        requirement=args.requirement,
        language=lang,
        database_path=db_path,
        query_path=query_archive,
        sarif_path=sarif_path,
        iterations=outcome.iterations,
        explanation=outcome.final_query.explanation,
    )
    report_path.write_text(md, encoding="utf-8")

    print()
    print(f"✓ Database:  {db_path}")
    print(f"✓ Query:     {query_archive}")
    print(f"✓ SARIF:     {sarif_path}")
    print(f"✓ Report:    {report_path}")
    print(f"✓ Findings:  {len(findings)}")
    print(f"✓ LLM iterations: {outcome.iterations}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="codeql-auto",
        description="LLM-driven CodeQL automation (Claude + codeql CLI).",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Build DB, generate query, analyze, report")
    _add_run_args(run_p)
    run_p.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
