# AgentTrust Findings Report
**This scan is self-attested — run by the assessed organization itself, not an independent third party**
Scanner: cisco-mcp-scanner unavailable · Ruleset: unavailable · Scanned: 2026-08-22T08:51:19.954Z · Target: 400040c9acf1a4f1 · Python: Python 3.12.12

> ⚠️ Scanner version is unavailable: mcp-scanner exposes no --version flag, so the version-range check was skipped and the report cannot pin the exact scanner build. Ruleset identifier is unavailable for the same reason.
> Notice: procurement-style questionnaires (e.g., Microsoft SSPA) may have zero questions answerable by this report.

## 1. What we scanned and found
- **prompt_injection_defense**: 154 finding(s) — 74369f48cbbe47a1, 7f0aec46b438d855, 0aa4e9d9e5b91a19, 254427b9eaee04cb, 2a419367fd108e5e, … (+149 more — see JSON `findings`)
- **operational_reliability**: 13 finding(s) — d127a0f13d13d96c, 0bf4aadfe00eace9, fb94ee421840c930, d287837b58870b4f, 1216992f33f76e06, … (+8 more — see JSON `findings`)

## 2. What we scanned but did not find
No findings ≠ proof of safety — undetected as of 2026-08-22T08:51:19.954Z, per cisco-mcp-scanner unavailable
- **secret_exposure**: no findings
- **vulnerable_deps**: no findings
- **malicious_pattern**: no findings

## 3. What this tool cannot scan

### 3a. Technical axes this scanner cannot report on
- **tool_permission**: Not observable via this scanner. readiness rule id HEUR-018 is dropped from mcp-scanner 4.8.3 CLI output (report_generator.py:82 serializes only details["threat_type"]), and the assumed destructive_capabilities YARA rule does not exist (all 10 rule files checked). The axis is technically scannable, but this scanner's CLI emits no signal for it.
- **auth_oauth**: Not observable via this scanner. readiness rule id HEUR-019 is dropped from mcp-scanner 4.8.3 CLI output (report_generator.py:82). The axis is technically scannable, but this scanner's CLI emits no signal for it.
- **data_flow**: Not observable via this scanner. No analyzer producing taint-tracking signals has been observed. None of the four key-free analyzers in mcp-scanner 4.8.3 (yara, readiness, vulnerable_package, prompt_defense) emits a signal for this axis.
- **logging**: Not observable via this scanner. readiness rule id HEUR-015 is dropped from mcp-scanner 4.8.3 CLI output (report_generator.py:82). The axis is technically scannable, but this scanner's CLI emits no signal for it.
- **sdlc**: Not observable via this scanner. No analyzer producing build/release pipeline signals has been observed. None of the four key-free analyzers in mcp-scanner 4.8.3 emits a signal for this axis.

### 3b. Organizational / contractual evidence required
Hand this section to whoever owns the answer — it is already a checklist.

#### incident_response
- [ ] Incident response runbook / SLA document (detection→response→post-mortem process)

#### data_retention
- [ ] Data retention policy document (retention period, deletion procedure)

#### subprocessor
- [ ] Subprocessor (4th-party vendor) disclosure document

#### training_data
- [ ] Model training-data usage policy statement (from LLM provider or self)

#### dpa
- [ ] Data Processing Agreement (DPA) document

Unmapped findings: 0

Ontology patterns with zero matches this scan: 11 (see JSON `unmatchedSignals` for the full list — normal for patterns unrelated to this scan's findings; investigate only if a pattern is *always* zero across repeated scans)