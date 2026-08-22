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
그 파일 상단 주석 참조, `fixtures/mcp-scanner-0.1.0/raw-envelope.json`은 실제 캡처 발췌본):

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

- **Prompt Defense 12종 카테고리의 실제 `rule`/`threat_names` 표기**: 이번 실측 대상
  (`server-everything`)은 프롬프트 인젝션성 콘텐츠를 포함하지 않아 `prompt_defense`류 분석기
  자체를 트리거하지 못했다(애초에 `--analyzers`에 `api`/`llm`을 포함해야 할 수도 있음 — 그건
  키가 필요해 이번 세션 범위 밖). 여전히 미확인.
- **`data_flow`/`sdlc`/`accepts_taxonomy`(AITech-N.N)**: `mcp_taxonomies` 필드가 실측에서 항상
  빈 배열이었다 — 이 스캐너가 그 축을 채우는 실제 사례를 아직 못 봤다.
- **YARA 분석기가 실제로 위협을 탐지했을 때의 `threat_names`/`rule` 표기**: 이번 실측은 전부
  `yara_analyzer: SAFE`였다(테스트 대상 서버가 실제 악성 패턴을 갖지 않음) — 악성 패턴 탐지 시
  `threat_names`에 어떤 문자열이 들어가는지는 여전히 미확인.
- **⚠️ ontology.yaml 설계 재검토 필요(Session 2 착수 전)**: `rule_map`이 `HEUR-001`·
  `credential_harvesting`·`CVE-*`·`prompt_injection` 같은 "개별 finding rule 식별자"를
  전제하는데, 실측된 raw 출력에는 그런 rule 필드 자체가 없다(`(analyzer, threat_name)` 롤업만
  있음). Session 2의 `ontology.ts`/`normalize.ts` 설계는 이 사실을 반영해 `rule_map`의 키 공간을
  다시 정의해야 할 가능성이 높다 — IMPL-NOTES.md 참조.
