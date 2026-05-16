"""Drive the LLM <-> CodeQL repair loop."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from .llm_client import (
    LLMClient,
    QLQuery,
    build_initial_user_prompt,
    build_repair_user_prompt,
)
from .query_runner import QueryRunResult, compile_and_run

log = logging.getLogger(__name__)


@dataclass
class RepairOutcome:
    success: bool
    iterations: int
    final_query: QLQuery
    final_run: QueryRunResult
    history: list[dict]  # the messages array as sent on the last call


def run_with_repair(
    client: LLMClient,
    requirement: str,
    language: str,
    database: Path,
    workdir: Path,
    sarif_out: Path,
    snippet: str | None = None,
    max_iters: int = 3,
) -> RepairOutcome:
    """Generate a query, run it, and repair-loop on failures."""
    messages: list[dict] = [
        {
            "role": "user",
            "content": build_initial_user_prompt(requirement, language, snippet),
        }
    ]

    last_query: QLQuery | None = None
    last_run: QueryRunResult | None = None

    for i in range(1, max_iters + 1):
        log.info("=== Iteration %d/%d ===", i, max_iters)
        query = client.generate(language, messages)
        last_query = query
        log.info("Generated query (confidence=%s): %s", query.confidence, query.explanation)

        run = compile_and_run(
            ql_code=query.ql_code,
            language=language,
            database=database,
            workdir=workdir,
            sarif_out=sarif_out,
        )
        last_run = run

        if run.success:
            log.info("Query succeeded on iteration %d", i)
            return RepairOutcome(
                success=True,
                iterations=i,
                final_query=query,
                final_run=run,
                history=messages,
            )

        log.warning("Iteration %d failed at %s stage", i, run.stage)

        # Append the assistant's structured output and the repair feedback.
        # We re-serialize the parsed Pydantic into the JSON Claude would have
        # returned so multi-turn context stays coherent.
        messages.append(
            {
                "role": "assistant",
                "content": query.model_dump_json(),
            }
        )
        messages.append(
            {
                "role": "user",
                "content": build_repair_user_prompt(run.stage, run.stderr),
            }
        )

    assert last_query is not None and last_run is not None
    return RepairOutcome(
        success=False,
        iterations=max_iters,
        final_query=last_query,
        final_run=last_run,
        history=messages,
    )
