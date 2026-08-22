# mcp-scanner exit code / CLI 실측 (Task 8b, Session 1 실측 게이트)

> 실측일: 2026-08-22 · 대상: `cisco-ai-mcp-scanner` PyPI 패키지 (설치 시점 최신판, **버전 4.8.3**)
> 방법: 격리 venv(`uv venv --python 3.12` + `uv pip install cisco-ai-mcp-scanner`)에 설치 후
> `mcp-scanner --help`, `config --help`, `remote --help` 및 실제 로컬 stdio MCP 서버
> (`@modelcontextprotocol/server-everything`)를 대상으로 여러 조합을 직접 실행해 stdout/stderr/
> exit code를 관측했다. 이 문서는 "미실측 — 설치 후 채울 표" 자리가 아니라 **실측 결과**다
> (설치가 이 세션에서 실제로 성공했다 — 시스템 python3(3.10.12)는 요구버전(>=3.11.4) 미달이라
> 별도 python3.12 격리 venv를 만들어 우회했다).

## ⚠️ 핵심 발견 — Spec §0 전제사항과 실제가 다른 지점

| # | Spec 가정 | 실측 결과 |
|---|---|---|
| 1 | `--config <path>`로 단일 파일 지정 | **틀림.** `config` 서브커맨드 + `--config-path <path>`. 글로벌 플래그(`--format`/`--analyzers`)는 서브커맨드 **앞**에 와야 한다(argparse subparsers 제약) |
| 2 | `--remote <url>`로 원격 지정 | **틀림.** `remote` 서브커맨드 + `--server-url <url>` |
| 3 | 지원 버전 범위 "0.x" | **틀림.** 실제 설치판은 **4.8.3**(PyPI 최신). `--version` 플래그 자체가 없다(아래 참조) |
| 4 | `mcp-scanner --version`으로 버전 확인 가능 | **틀림.** `--version`은 인식되지 않는 인자 — argparse가 exit **2**로 거부한다. CLI로 버전을 얻을 방법이 없다(`getScannerVersion()`은 이미 실패 시 `null`을 반환하도록 설계돼 있어 안전하게 처리되지만, 실전에서 항상 `null`이 된다) |
| 5 | `scan_results[].findings[]`가 개별 finding **배열** | **틀림(구조 자체가 다름).** `scan_results[]`는 "도구/프롬프트/리소스 1개당 1개 원소"이고, 그 안의 `findings`는 배열이 아니라 **분석기명을 키로 하는 롤업 요약 객체**(`{yara_analyzer: {...}, readiness_analyzer: {...}}`) |
| 6 | finding에 `rule`/`rule_id` 필드 존재 | **틀림.** 그런 필드가 없다. 있는 것은 `severity`(단일값)·`threat_names`(배열, 실측에서는 `["unknown"]` 1종만 관측)·`threat_summary`(자유 텍스트)·`total_findings`(개수)뿐 |
| 7 | 기본 `--analyzers`(api,yara,llm)로 로컬 스캔 가능 | **틀림.** 기본값은 API/LLM 키 미설정 시 대상과 무관하게 **항상 exit 1**로 실패한다. 로컬·키 불요 조합은 `yara,readiness,vulnerable_package` (실측 확인) |

## CLI 인자 형태 (실측)

```bash
# 로컬 설정 파일 1개 스캔 (키 불요)
mcp-scanner --format raw --analyzers yara,readiness,vulnerable_package \
  config --config-path <path-to-.mcp.json>

# 원격 서버 스캔 (--allow-remote 옵트인 시에만 argv에 포함, ADR-006)
mcp-scanner --format raw --analyzers yara,readiness,vulnerable_package \
  remote --server-url <url>
```

## exit code 표 (실측)

| exit code | 상황 | stdout | stderr | `classifyScannerFailure` 분류 |
|:--:|---|---|---|---|
| **0** | 정상 종료 — 대상 연결 성공, 또는 개별 대상 연결 실패(MCP 핸드셰이크 불가 등)도 포함 | 유효 JSON 봉투(`server_url`/`scan_results`/`requested_analyzers`). 연결 실패 시 `scan_results: []`로 조용히 계속 | 연결 실패 로그(WARNING/ERROR 라인)가 남을 수 있으나 실행은 계속됨 | 해당 없음 — ADR-007 1차 판정(stdout JSON 파싱)이 이미 성공해 이 함수 자체가 호출되지 않음 |
| **1** | 스캐너 자체의 치명적 오류 — ①`--config-path`가 가리키는 파일 없음(`FileNotFoundError`) ②요청한 analyzer가 필요로 하는 API/LLM 키 미설정 | **0바이트**(항상 비어 있음) | Python traceback 또는 "API analyzer requested but MCP_SCANNER_API_KEY not configured" 류 메시지 | `scanner_error`, meaning="scanner fatal error — invalid --config-path, or a requested analyzer is missing its required API/LLM key" |
| **2** | argparse 인자 파싱 오류 — 존재하지 않는 플래그, 또는 플래그 순서 오류(서브커맨드 뒤에 글로벌 플래그) | 비어 있음 | argparse 표준 usage + "unrecognized arguments: ..." | `scanner_error`, meaning="argument parsing error — invalid/unrecognized CLI flag or flag ordering" |

## raw 봉투 스키마 실측 (구조 교정 — A-1 codex 반영의 후속)

Task 8a가 조사 문서 기반 "최선 추정"으로 만든 `parseScannerRawEnvelope()`는 최상위 3개 키
(`server_url`/`scan_results`/`requested_analyzers`)는 맞았지만, `scan_results[]` **내부 구조를
잘못 추정**했다. 실측 확인 후 `src/scanner-envelope.ts`를 아래 실제 구조로 재작성했다(상세 근거는
그 파일 상단 주석 참조, `fixtures/mcp-scanner-4.8.3/raw-envelope.json`은 실제 캡처 발췌본):

```json
{
  "server_url": "...",
  "scan_results": [
    {
      "status": "completed",
      "is_safe": false,
      "findings": {
        "yara_analyzer": { "severity": "SAFE", "threat_names": [], "threat_summary": "...", "total_findings": 0 },
        "readiness_analyzer": { "severity": "HIGH", "threat_names": ["unknown"], "threat_summary": "...", "total_findings": 7, "mcp_taxonomies": [] }
      },
      "tool_name": "echo",
      "tool_description": "...",
      "item_type": "tool",
      "server_source": "...",
      "server_name": "everything"
    }
  ],
  "requested_analyzers": ["yara", "readiness", "vulnerable_package"]
}
```

## 미실측으로 남는 항목 (다음 세션 재확인 필요)

> ⚠️ **2026-08-22 Session 2 착수 전 재측정으로 아래 항목 다수가 해소됐다.**
> 전문·재현 명령·원본 출력 → `docs/planning/SPEC-v0-cli-AMENDMENT-01-signal-map.md` §2 ·
> `docs/measurements/2026-08-22-signal-space/`

### 해소됨 (재측정 완료)

- ✅ **Prompt Defense 12종 카테고리 표기**: `--analyzers`에 **`prompt_defense`를 넣으면 키 없이
  exit 0으로 동작**한다(api/llm 불요). `threat_names`에 12종이 **정확 문자열**로 실린다
  (`INSTRUCTION_OVERRIDE` `DATA_LEAKAGE` `ROLE_ESCAPE` `INDIRECT_INJECTION`
  `OUTPUT_WEAPONIZATION` `OUTPUT_MANIPULATION` `MULTILANG_BYPASS` `UNICODE_ATTACK`
  `CONTEXT_OVERFLOW` `SOCIAL_ENGINEERING` `INPUT_VALIDATION` `ABUSE_PREVENTION`).
  ⚠️ 분석기 키가 **두 개** 나온다 — `prompt_defense_analyzer`(항상 0건, 유령) /
  `promptdefense_analyzer`(실제 finding). 후자를 써야 한다.
- ✅ **YARA 발화 시 `threat_names` 표기**: 악성 패턴을 심은 정적 입력으로 발화시켜 실측했다.
  값 공간은 **7종** — `PROMPT INJECTION` `CREDENTIAL HARVESTING` `CODE EXECUTION`
  `INJECTION ATTACK` `SYSTEM MANIPULATION` `DATA EXFILTRATION` `TOOL POISONING`.
  YARA 룰 파일은 10개이나 threat_type으로 7종에 합쳐진다(룰 단위 구분 불가).
- ✅ **`mcp_taxonomies`는 "항상 빈 배열"이 아니다 — 구 서술을 폐기한다.** 그 관측은
  `readiness_analyzer`만 봤기 때문이었다. **YARA가 발화하면**, 그리고 `promptdefense_analyzer`는
  상시, `aitech`/`aisubtech`가 설명문까지 붙어 나온다(예: `AITech-1.1`/`AISubtech-1.1.1`).
  `readiness_analyzer`만 필드는 있고 항상 `[]`다.

### 여전히 미실측

- **`vulnerable_package` 발화 시 출력**: 실제 취약 의존성을 가진 대상이 없어 미발화. 소스상
  `threat_type`은 상수 `"VULNERABLE_DEPENDENCY"` 단일값이며 CVE ID는 `threat_summary` 첫 문장에만
  남는다(`vulnerable_package_analyzer.py:365`) — 키로 쓸 수 없다.
- **`data_flow`/`sdlc`(AITech-N.N)**: 이 스캐너가 그 축을 채우는 사례를 아직 못 봤다.

### 치명적 구조 발견 — rule 식별자는 존재하나 CLI가 버린다

`report_generator.py:32` `results_to_json()`이 finding당 `details["threat_type"]` **하나만**
직렬화한다(`:82`). 실제로 존재하는 `details["rule_id"]`(`HEUR-001`~`HEUR-020`)와
`details["raw_response"]["rule"]`(YARA 룰명)은 **출력에 복사되지 않는다.** 요약도
`summaries[0]` 첫 문장만 남는다(`:128`) — `total_findings: 7`이어도 문장은 1개다.

`raw`/`summary`/`detailed`/`by_tool`/`by_analyzer`/`by_severity`/`table` **7개 포맷 전부**가 이
함수 출력에서 파생되므로(`_format_raw()` = `json.dumps(self.scan_data)`, `:344`) **포맷을 바꿔도
못 건진다.** 이것이 개정안 #01의 근거다.
