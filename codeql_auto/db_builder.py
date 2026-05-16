"""Build CodeQL databases from source trees via the `codeql` CLI."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# CodeQL CLI's --language=<NAME> values
LANGUAGE_ALIASES = {
    "python": "python",
    "py": "python",
    "java": "java-kotlin",
    "kotlin": "java-kotlin",
    "kt": "java-kotlin",
    "cpp": "cpp",
    "c++": "cpp",
    "c": "cpp",
    "go": "go",
    "csharp": "csharp",
    "cs": "csharp",
    "c#": "csharp",
    "ruby": "ruby",
    "rb": "ruby",
    "swift": "swift",
}

COMPILED_LANGUAGES = {"java-kotlin", "cpp", "csharp", "swift"}


@dataclass
class DatabaseSpec:
    src: Path
    language: str  # CodeQL canonical language name
    db_path: Path
    build_cmd: str | None = None


class CodeQLNotFound(RuntimeError):
    pass


class BuildCommandRequired(ValueError):
    pass


def normalize_language(raw: str) -> str:
    key = raw.strip().lower()
    if key not in LANGUAGE_ALIASES:
        raise ValueError(
            f"Unsupported language {raw!r}. Supported: {sorted(set(LANGUAGE_ALIASES))}"
        )
    return LANGUAGE_ALIASES[key]


def detect_language(src: Path) -> str:
    """Best-effort language detection by file extension count."""
    counts: dict[str, int] = {}
    ext_map = {
        ".py": "python",
        ".java": "java-kotlin",
        ".kt": "java-kotlin",
        ".c": "cpp",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".cxx": "cpp",
        ".h": "cpp",
        ".hpp": "cpp",
        ".go": "go",
        ".cs": "csharp",
        ".rb": "ruby",
        ".swift": "swift",
    }
    for p in src.rglob("*"):
        if p.is_file() and p.suffix.lower() in ext_map:
            counts[ext_map[p.suffix.lower()]] = counts.get(ext_map[p.suffix.lower()], 0) + 1
    if not counts:
        raise ValueError(f"Could not detect language under {src}; pass --language explicitly")
    lang, _ = max(counts.items(), key=lambda kv: kv[1])
    return lang


def ensure_codeql_available() -> str:
    """Return the path to the `codeql` executable or raise."""
    exe = shutil.which("codeql")
    if not exe:
        raise CodeQLNotFound(
            "`codeql` not found on PATH. Install from "
            "https://github.com/github/codeql-cli-binaries/releases"
        )
    return exe


def build_database(spec: DatabaseSpec, overwrite: bool = True) -> Path:
    """Run `codeql database create` and return the database path."""
    ensure_codeql_available()

    if spec.language in COMPILED_LANGUAGES and not spec.build_cmd:
        raise BuildCommandRequired(
            f"Language {spec.language!r} requires --build-cmd, "
            f"e.g. `--build-cmd \"mvn -B compile\"` for Java, "
            f"`--build-cmd \"make\"` for C/C++."
        )

    if spec.db_path.exists() and overwrite:
        log.info("Removing existing database at %s", spec.db_path)
        shutil.rmtree(spec.db_path)

    args = [
        "codeql",
        "database",
        "create",
        str(spec.db_path),
        f"--language={spec.language}",
        f"--source-root={spec.src}",
    ]
    if spec.build_cmd:
        args.append(f"--command={spec.build_cmd}")

    log.info("Running: %s", " ".join(args))
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        log.error("codeql database create failed:\nSTDOUT:\n%s\nSTDERR:\n%s",
                  proc.stdout, proc.stderr)
        raise RuntimeError(
            f"codeql database create exited with {proc.returncode}. See logs."
        )
    log.info("Database built at %s", spec.db_path)
    return spec.db_path
