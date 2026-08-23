# mcp-disclosure Configuration Findings

**Self-attested scan** — This scan is self-attested — run by the assessed organization itself, not an independent third party.

| Field | Value |
|---|---|
| Scanner | `cisco/mcp-scanner` |
| Scanner version | `0.9.3` |
| Ruleset hash | `sha256:4f2a…c81b` |
| Scanned at | `2026-08-22T04:11:07Z` |
| Target hash | `sha256:9d13…7ae0` (`/home/acme/agent-platform` @ `git:3f9c2a1`) |
| Python runtime | `3.11.9` |
| Report schema | `mcp-disclosure/v0` |

> **Scope of this report.** This document reports what a configuration scanner observed in the
> files listed below. It is **not** a certification, an attestation of compliance, or an audit
> result. Coverage limits are stated explicitly in section 3.

---

## Coverage at a glance

| | Axis group | Axes | Result |
|:--:|---|:--:|---|
| **1** | **Checked — findings present** | 2 of 15 | **4 findings** (1 high, 2 medium, 1 low) |
| **2** | **Checked — nothing found** | 3 of 15 | No findings ≠ proof of safety (see §2) |
| **3** | **Partially checked** | 5 of 15 | Presence heuristics only — effectiveness **not** verified |
| **4** | **Not checkable by this tool** | 5 of 15 | Evidence request form generated (§4) |

**Questionnaire genre notice.** Real procurement documents (e.g. Microsoft SSPA Section K) may
contain **zero** questions this report can answer — those ask for policy documents and
organizational statements, not configuration state. Measured on 126 real questionnaire items:
vendor-published checklists 55–70% answerable, enterprise procurement documents 0 of 18.

---

## 1. Checked — findings present

### 1.1 `prompt_injection_defense` — 2 findings

| ID | Severity | Rule | Target | Line |
|---|:--:|---|---|--:|
| `a1f0c93d21b47e05` | **high** | `YARA/tool_description_injection` | `.mcp.json` → server `notion` | 42 |
| `7c22b8ef4019a6d3` | medium | `HEUR-004/no_input_boundary` | `agents/researcher.md` | 17 |

**`a1f0c93d21b47e05`** — Tool description contains instruction-like text that an agent may execute.
*Evidence:* `scanner_detected` · taxonomy `AITech-1.2` · matched rule `tool_description_injection`.
*Raw excerpt:* `{"description": "***REDACTED***"}` — matched content withheld (see §5 Redaction).

**`7c22b8ef4019a6d3`** — No input boundary marker between system prompt and user-supplied content.
*Evidence:* `scanner_detected` · heuristic `HEUR-004`.

### 1.2 `vulnerable_deps` — 2 findings

| ID | Severity | Rule | Target | Line |
|---|:--:|---|---|--:|
| `e480b1a7cc32f95d` | medium | `pip-audit/GHSA-xxxx-yyyy` | `requirements.txt` | 8 |
| `35d9ae60fb1c8402` | low | `pip-audit/PYSEC-2026-118` | `requirements.txt` | 23 |

---

## 2. Checked — nothing found

These axes were scanned and produced no findings.

> **No findings ≠ proof of safety — undetected as of 2026-08-22T04:11:07Z, per cisco/mcp-scanner 0.9.3.**

| Axis | Analyzer | What was examined |
|---|---|---|
| `secret_exposure` | YARA (10 rules) | Literal credentials in configuration files |
| `malicious_pattern` | YARA + static | Known malicious package/command patterns |
| `operational_reliability` | Readiness (17 heuristics) | Startup, retry, and error-path configuration |

---

## 3. Partially checked

⚠️ **These axes were examined only for the *presence* of configuration — not for whether it
actually works.** A buyer should read this section as "the setting exists", never as "the control
is effective".

| Axis | What we could see | What we could **not** see |
|---|---|---|
| `tool_permission` | Permission fields are declared for 6 of 7 MCP servers | Whether the granted scope matches least privilege |
| `auth_oauth` | 2 of 7 servers declare OAuth; 5 use unauthenticated stdio | Token lifetime, rotation, revocation behaviour |
| `data_flow` | Declared endpoints and transports | Actual runtime egress |
| `logging` | Log destination configured | Retention, integrity, access control on logs |
| `sdlc` | CI configuration file present | Review gates, branch protection, release process |

**Unmatched ontology patterns: 1** — `AITech-4.*` matched 0 findings in this run. Either the
environment has nothing in that class, or the mapping is stale. Treated as *unknown*, not as *clean*.

**Unclassified findings: 0** — every finding mapped to an axis.

---

## 4. Not checkable by this tool

These five axes cannot be established from configuration files at all. They are organizational and
contractual facts. **This report does not answer them, and does not attempt to.**

| Axis | Why not checkable | Evidence you will need to supply |
|---|---|---|
| `incident_response` | Process, not configuration | IR plan document + date of last exercise |
| `data_retention` | Policy, not configuration | Retention schedule + deletion procedure |
| `subprocessor` | Contractual | Subprocessor list + flow-down terms |
| `training_data` | Organizational statement | Statement on customer data use in model training |
| `dpa` | Contractual | Executed DPA / SCCs where applicable |

### Evidence request form (copy into your questionnaire response)

```
[ ] Incident response plan (PDF) — last tabletop exercise: ____________
[ ] Data retention schedule — retention period: ______  deletion method: ______
[ ] Subprocessor list — as of: ____________
[ ] Training-data statement — customer data used for training? Y / N
[ ] Executed DPA — counterparty: ____________  date: ____________
```

---

## 5. Redaction and limits

- Values matched by credential-like rules are replaced with `***REDACTED***` before they reach this
  document. Raw scanner output is stored redacted; unmasked originals are never written.
- Remote MCP endpoints were **not contacted**. 1 remote server was excluded from scanning:

| Target | Reason |
|---|---|
| `mcp://vendor.example.com/sse` (server `crm-bridge`) | `remote_out_of_scope` — run with `--allow-remote` to include (this report would then state that remote endpoints were contacted) |

- Unscanned due to failure: 0.
- This tool reports observations from one scanner at one point in time. It does not establish that
  any control is effective, and it is not a substitute for review by a qualified assessor.

---

*Generated by mcp-disclosure v0 · `npx mcp-disclosure scan` · report schema `mcp-disclosure/v0`*
