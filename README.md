# mcp-disclosure

**A configuration disclosure CLI for AI agent / MCP setups.**

Most scanners tell you what they found. mcp-disclosure also tells you **what it looked for and did not
find**, and **what it cannot look at all** — side by side, in one report.

That third column is the point. A clean report from a tool that never checked is worse than no
report, because it reads as a clean bill of health. mcp-disclosure names the gaps instead of leaving
them blank.

```
## 1. What we scanned and found
- prompt_injection_defense: 154 finding(s) — bfc3c4a7…, … (+149 more — see JSON `findings`)

## 2. What we scanned but did not find
No findings ≠ proof of safety — undetected as of 2026-08-22T08:51:19Z, per cisco-mcp-scanner unavailable
- secret_exposure: no findings

## 3. What this tool cannot scan
### 3a. Technical axes this scanner cannot report on
- logging: Not observable via this scanner. readiness rule id HEUR-015 is dropped from
  mcp-scanner 4.8.3 CLI output (report_generator.py:82). …
### 3b. Organizational / contractual evidence required
#### dpa
- [ ] Data Processing Agreement (DPA) document
```

## Usage

```bash
npx mcp-disclosure --help               # what it does and every flag it takes
npx mcp-disclosure scan                 # scan the current directory
npx mcp-disclosure scan --path ./repo   # scan a specific directory
npx mcp-disclosure scan --allow-remote  # opt in to scanning remote MCP endpoints (off by default)
npx mcp-disclosure scan --scan-timeout 300000   # raise the per-scan timeout (default 120000 ms)
```

Writes two files next to the scanned directory:

- `mcp-disclosure-findings.md` — the report you read
- `mcp-disclosure-findings.json` — the same data, complete (the markdown truncates long ID lists)

Exit codes: `0` report written · `1` no configuration found / Python missing · `2` ontology or
render failed closed · `3` unexpected error.

## No network calls

mcp-disclosure makes **zero network calls of its own**. No telemetry, no upload, no license check.
Everything runs locally and the report never leaves your disk unless you move it.

One deliberate exception, and it is opt-in: `--allow-remote` lets the underlying scanner connect
to remote MCP endpoints you have configured. Without that flag, remote targets are **never placed
in the scanner's argv at all** — they are listed as unscanned instead. When you do pass it, the
report carries a banner saying a remote connection happened.

## Requirements

- **Node.js ≥ 20**
- **Python ≥ 3.11.4** with `cisco-ai-mcp-scanner` installed:

```bash
pip install cisco-ai-mcp-scanner
```

mcp-disclosure does not install it for you and does not try to. If the scanner is missing, the run
still produces a report — one that says every technical axis was **not evaluated**, with the
reason. It will not tell you things look fine.

If your system Python is older than 3.11.4, an isolated environment works:

```bash
uv venv --python 3.12 && uv pip install cisco-ai-mcp-scanner
export PATH="$PWD/.venv/bin:$PATH"
```

## Known limitations

These are limits we have measured, not hypotheticals. We would rather list them than have you
discover them.

### 1. Masking is best-effort on unfamiliar field names

Findings can carry raw excerpts from your configuration, so every value is masked before it
reaches the report. Two mechanisms do this: a **key denylist** (fields like `matched_string`,
`authorization`, `token` are masked regardless of content) and **value-based detection**
(token prefixes, JWTs, URL credentials, high-entropy strings ≥ 20 chars).

**If the scanner returns a secret under a field name we do not know, only the value-based check
defends it.** A short, low-entropy secret in an unrecognized field can survive. Nested objects and
arrays are masked wholesale for this reason — over-masking beats under-masking.

If you find a leak, that is a bug worth reporting.

### 2. Five of the fifteen axes cannot be reported on at all

`tool_permission`, `auth_oauth`, `data_flow`, `logging`, and `sdlc` are technically scannable in
principle, but the scanner's CLI drops the identifiers we would need. Its JSON output keeps only a
per-analyzer rollup — the individual rule ids (`HEUR-001`…`HEUR-020`) exist inside the scanner and
never reach the output. Every output format derives from the same rollup, so switching formats does
not help.

The report says this per axis, with the reason. It does not report them as "clean".

### 3. Version and ruleset cannot be pinned

`mcp-scanner` has no `--version` flag, so the report cannot record which scanner build produced it,
and no ruleset identifier is exposed either. Both show as `unavailable`. The scanned configuration
**is** hashed (`target_hash`), so you can at least tell whether two reports looked at the same input.

### 4. What we have actually exercised

The end-to-end path has been run against a local stdio MCP server. Remote endpoints, static JSON
tool files, and package targets are covered by fixtures, not by a live run. The `yara` and
`vulnerable_package` analyzers have only been observed firing against crafted inputs.

## Remote scanning is off by default (ADR-006)

| Enforcement point | What it does |
|---|---|
| `buildScannerArgs` | Returns `null` for a remote target unless `--allow-remote` — the URL never enters argv |
| `runScanner` | Records the target as `unscanned` with reason `remote_out_of_scope`, and keeps going |
| `render` | Emits a remote-connection banner whenever a remote target was actually scanned |

A local-only run and a remote-enabled run are therefore distinguishable from the report alone.

## What this tool is not

It does not certify, audit, or attest anything, and it will not produce a document that claims to.
Those words are on a denylist that the test suite enforces against every report template. What it
produces is a **self-attested configuration disclosure** — a starting point for a conversation with
whoever is asking you security questions, not an answer to them.

## License

MIT
