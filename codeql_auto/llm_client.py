"""Claude API client for CodeQL query generation.

Uses prompt caching to amortize the CodeQL reference (~10K tokens) across
multiple requests / repair iterations within a 1-hour window.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

import anthropic
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).parent / "prompts"
EXAMPLES_DIR = PROMPTS_DIR / "examples"

# Map canonical CodeQL language → few-shot filename
EXAMPLE_BY_LANG = {
    "python": "python.ql",
    "java-kotlin": "java.ql",
    "cpp": "cpp.ql",
    "go": "go.ql",
    "csharp": "csharp.ql",
    "ruby": "ruby.ql",
    "swift": "swift.ql",
}


class QLQuery(BaseModel):
    ql_code: str = Field(description="Complete .ql file content, ready for codeql query compile")
    explanation: str = Field(description="1-3 sentence summary of what the query detects")
    confidence: Literal["high", "medium", "low"] = Field(
        description="Self-assessed confidence the query will compile and find real issues"
    )


def _load_system_prompt() -> str:
    return (PROMPTS_DIR / "system_codeql.md").read_text(encoding="utf-8")


def _load_few_shot(language: str) -> str:
    filename = EXAMPLE_BY_LANG.get(language)
    if not filename:
        return ""
    path = EXAMPLES_DIR / filename
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def build_system_blocks(language: str) -> list[dict]:
    """Build the cached system prompt: reference doc + language-specific few-shot.

    Both blocks share one cache_control breakpoint on the last block so the entire
    prefix (tools + system) caches together with a 1h TTL.
    """
    system_doc = _load_system_prompt()
    few_shot = _load_few_shot(language)

    blocks: list[dict] = [
        {
            "type": "text",
            "text": system_doc,
        },
        {
            "type": "text",
            "text": (
                f"## Few-shot example for language `{language}`\n\n"
                f"```ql\n{few_shot}\n```\n"
                if few_shot
                else f"## No few-shot available for language `{language}`."
            ),
            "cache_control": {"type": "ephemeral", "ttl": "1h"},
        },
    ]
    return blocks


def build_initial_user_prompt(
    requirement: str,
    language: str,
    snippet: str | None = None,
) -> str:
    parts = [
        f"Target language: `{language}`",
        "",
        "Detection requirement:",
        requirement.strip(),
    ]
    if snippet:
        parts += [
            "",
            "Reference code snippet (for context only; the actual analysis runs against a full database):",
            "```",
            snippet.strip(),
            "```",
        ]
    parts += [
        "",
        "Produce a complete `.ql` query satisfying the requirement. "
        "Follow every rule in the system prompt.",
    ]
    return "\n".join(parts)


def build_repair_user_prompt(stage: str, stderr: str) -> str:
    return (
        f"The previous query failed at the `{stage}` stage. "
        f"`codeql` reported:\n\n```\n{stderr}\n```\n\n"
        f"Diagnose the root cause and return a corrected full `.ql` file. "
        f"Do not return a patch."
    )


class LLMClient:
    """Thin wrapper around `Anthropic.messages.parse` with cached system prompt."""

    def __init__(
        self,
        model: str = "claude-opus-4-7",
        max_tokens: int = 8000,
        effort: Literal["low", "medium", "high", "max"] = "high",
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self.effort = effort
        self.client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()

    def generate(
        self,
        language: str,
        messages: list[dict],
    ) -> QLQuery:
        """Send `messages` to Claude with cached system prompt; return parsed QLQuery."""
        system_blocks = build_system_blocks(language)

        log.debug("Calling %s with %d messages", self.model, len(messages))
        response = self.client.messages.parse(
            model=self.model,
            max_tokens=self.max_tokens,
            thinking={"type": "adaptive"},
            output_config={"effort": self.effort},
            system=system_blocks,
            messages=messages,
            output_format=QLQuery,
        )

        # Log cache effectiveness
        usage = response.usage
        log.info(
            "Tokens: input=%d cache_read=%d cache_write=%d output=%d",
            usage.input_tokens,
            getattr(usage, "cache_read_input_tokens", 0) or 0,
            getattr(usage, "cache_creation_input_tokens", 0) or 0,
            usage.output_tokens,
        )

        parsed = response.parsed_output
        if parsed is None:
            raise RuntimeError(
                f"Claude returned no parsed output. stop_reason={response.stop_reason!r}"
            )
        return parsed
