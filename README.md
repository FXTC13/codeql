# codeql-auto

LLM-driven CodeQL automation. You describe what you want to detect; Claude
generates the `.ql` query, the script runs it, and you get a Markdown report.

## How it works

```
requirement (natural language) + source code
      ↓
codeql database create        ──┐
      ↓                          │
Claude (claude-opus-4-7)         │  ←  CodeQL syntax reference cached
generates a .ql file              │      via prompt caching (1h TTL)
      ↓                          │
codeql query compile             │
      ↓                          │
codeql database analyze --sarif  │
      ↓                          │
on failure: stderr → Claude     ←┘  (up to --max-repair iterations)
      ↓
SARIF → Markdown report
```

Supported target languages: **Python, Java/Kotlin, C/C++, Go, C#, Ruby, Swift**.

## Prerequisites

1. **CodeQL CLI ≥ 2.16** on `PATH`. Verify with `codeql version`.
   Install from <https://github.com/github/codeql-cli-binaries/releases>.
2. **Python 3.10+**.
3. **`ANTHROPIC_API_KEY`** in env.

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
```

## Usage

```bash
python -m codeql_auto.cli run \
  --src examples/vulnerable_python \
  --requirement "Detect command injection: subprocess calls with shell=True where the command argument comes from an HTTP request parameter" \
  --language python \
  --output-dir out/smoke
```

Outputs land in `out/smoke/`:

- `db/` — CodeQL database
- `query.ql` — the final query Claude produced (after any repair iterations)
- `results.sarif` — raw SARIF for IDE / Code Scanning consumption
- `report.md` — human-readable report with code snippets

### Compiled languages

Java, C/C++, C#, Swift need an explicit build command:

```bash
python -m codeql_auto.cli run \
  --src path/to/java/project \
  --requirement "SQL injection via Statement.execute" \
  --language java \
  --build-cmd "mvn -B compile" \
  --output-dir out/java
```

### Reusing a database across runs

After the first run, subsequent invocations against the same source tree can
skip the (often slow) database build:

```bash
python -m codeql_auto.cli run \
  --src examples/vulnerable_python \
  --requirement "Different detection requirement..." \
  --output-dir out/smoke \
  --skip-db-build
```

### All flags

```
python -m codeql_auto.cli run --help
```

| Flag | Default | Purpose |
|---|---|---|
| `--src` | (required) | Source tree to analyze |
| `--requirement` | (required) | Natural-language detection ask |
| `--language` | auto-detect | One of `python java cpp go csharp ruby swift` |
| `--build-cmd` | none | Required for compiled languages |
| `--snippet` / `--snippet-file` | none | Extra code context for Claude |
| `--output-dir` | `./codeql-out` | Output directory |
| `--max-repair` | `3` | Max LLM repair iterations on compile/run failure |
| `--model` | `claude-opus-4-7` | Claude model ID |
| `--effort` | `high` | `low` \| `medium` \| `high` \| `max` (max is Opus-only) |
| `--skip-db-build` | off | Reuse existing `<output-dir>/db` |
| `-v` | off | DEBUG logging |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Bad CLI arguments / unknown language |
| 3 | `codeql` not on PATH |
| 4 | Compiled language requires `--build-cmd` |
| 5 | Pipeline error (API failure, etc.) |
| 6 | Repair loop exhausted; query never compiled |

When code 6 happens, `last_stderr.txt` and the last attempted `query.ql` are
written to the output directory for debugging.

## Cost notes

The CodeQL reference + few-shot example total around 10K tokens. With prompt
caching (`ttl: "1h"`), only the first iteration in a 1h window pays full
price; subsequent iterations and repair turns read from cache at ~10% of
input cost. Check the log line `Tokens: input=… cache_read=… cache_write=…`
to confirm cache hits.

## Limitations

- Pre-built `*Query` modules are preferred when a vulnerability class has one
  in the CodeQL standard library. Novel detection logic that doesn't map to a
  pre-built module relies entirely on Claude composing a custom
  `DataFlow::ConfigSig` — quality varies, the repair loop helps.
- Community qlpacks (e.g. `codeql/python-queries`) are not auto-installed.
  Generated queries that depend on them will fail compile; broaden the
  requirement or pre-install the pack.
- No false-positive filtering pass yet. SARIF results pass through verbatim.
