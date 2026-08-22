# OSS MCP/에이전트 보안 스캐너 — 검사 경계 실측 리포트

> 조사일: 2026-08-21 (전 항목 GitHub 저장소 clone 실측 + 1차 문서 WebFetch/WebSearch 병행)
> 목적: AgentTrust v0(무료 OSS 스캐너 래핑 + 커버리지 한계 명시 소견서)의 "타입된 클레임 온톨로지" 설계 근거

---

## 결론 (먼저 읽는 3줄)

쉽게 말하면 **오픈소스 스캐너들은 "자물쇠가 헐거운지"는 아주 잘 본다. 그런데 심사 질문지가 묻는 건 "이 집이 화재보험에 들었는지, 경비업체와 계약했는지, 누가 열쇠를 복사해 갔는지"까지다 — 그건 자물쇠 사진만 봐서는 알 수 없다.**

1. **실측한 두 스캐너(Cisco `mcp-scanner`, Snyk `agent-scan`)는 설계 목적 자체가 "MCP 설정·툴 정의의 기술적 취약점 탐지"이지 "벤더 보안 심사 답변"이 아니다.** 프롬프트 인젝션·시크릿 노출·악성코드·취약 의존성 축은 두 스캐너 모두 강하게 커버하지만(아래 매트릭스 "가능" 4축), 인증/OAuth·데이터흐름·로깅·SDLC는 "설정에 그 항목이 있는지 없는지"만 보는 휴리스틱이라 "부분가능"에 그친다.
2. **아래 14개 심사축 중 5축(사고대응·데이터보존·하도급·학습데이터·DPA)은 두 스캐너 모두 구조적으로 불가능하다** — 이 정보는 로컬 설정 파일이 아니라 벤더의 조직·계약 문서에만 존재하기 때문이다. 스캐너를 아무리 개선해도 이 5축은 못 메운다.
3. **Snyk `agent-scan`은 "무료 OSS"라는 소개와 달리 완전 로컬 실행이 아니다** — `SNYK_TOKEN` 발급이 필수이고, 로컬에서 1차 검사한 데이터를 `https://api.snyk.io/hidden/mcp-scan/analysis-machine`(2026-07-10 API)로 전송해 분석한다(소스 코드 실측, `src/agent_scan/cli.py:478`). 반면 Cisco `mcp-scanner`는 YARA·Readiness·취약 패키지(pip-audit) 분석기가 **API 키 없이 완전 로컬 실행 가능**하고, LLM/API/VirusTotal 분석기만 선택적으로 외부 키를 요구한다 — "로컬 단독 실행 가능성"에서 Cisco가 더 유리하다.

**v0가 "래핑"을 넘어 더해야 할 가치** (5번 과제 답): 스캐너 출력을 그대로 붙여넣는 것이 아니라 ①스캐너별 원시 finding을 "심사 질문 언어"로 번역하고 ②"발견 없음(no finding)"을 "안전 증명(proof of safety)"으로 오역하지 않도록 신뢰도·범위를 명시하며 ③애초에 답할 수 없는 축은 침묵하지 않고 "이 항목은 스캔으로 증적 불가 — 별도 자료 필요"라는 구조화된 요청으로 전환하는 것. 아래 §5에서 구체화한다.

---

## 1. Cisco `mcp-scanner` 실측

- **저장소**: [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) (조사일 2026-08-21, `git clone --depth 1` 실측)
- **라이선스**: Apache License 2.0 (LICENSE 파일 실측)
- **패키지명**: `cisco-ai-mcp-scanner` (PyPI), 모듈명 `mcpscanner`, Python 3.11+
- **실행 방식**: CLI 단독 실행 또는 REST API 서버 모드. **로컬 단독 실행 가능** — YARA 분석기, Readiness 분석기(20개 휴리스틱, "zero external dependencies... no API keys required", `docs/readiness-scanning.md`), 취약 패키지 분석기(pip-audit 기반 CVE/PYSEC/GHSA)는 API 키 불필요. LLM 분석기(OpenAI/AWS Bedrock 키 필요), API 분석기(Cisco AI Defense API 키 필요), VirusTotal 분석기(VT 키 필요)는 선택적 외부 의존.
- **입력**: 원격 MCP 서버(HTTP/SSE/OAuth 연결), stdio MCP 서버, 사전 생성된 정적 JSON 파일(오프라인/에어갭 CI 지원), PyPI/npm 패키지, 소스코드 디렉터리, 바이너리 파일.

### 검사 엔진 6종 (소스 코드 실측, `mcpscanner/core/analyzers/`)

| 엔진 | 검사 항목 | 키 필요 여부 |
|---|---|---|
| **YARA** | 10개 룰 카테고리: `coercive_injection`, `command_injection`, `system_manipulation`, `credential_harvesting`, `tool_poisoning`, `code_execution`, `prompt_injection`, `sql_injection`, `script_injection`, `data_exfiltration`(파일명 실측) | 불요 |
| **Readiness** | 20개 휴리스틱 규칙(HEUR-001~020) — 타임아웃/재시도(HEUR-001~005), 에러 핸들링(006~008), 설명 품질/과부하 툴(009~010), 입력 검증(011~012), 운영설정(013~015: rate limit·버전·관측성), 리소스 관리(016~017), 안전성(018~020: 위험 키워드·인증 컨텍스트 부재·순환 의존) | 불요(핵심), OPA/LLM 심화는 선택 |
| **LLM 분석기** | 프롬프트 인젝션·데이터유출·툴 포이즈닝·툴 섀도잉(자유 서술 LLM 판정) | 필요(OpenAI/Bedrock) |
| **API 분석기(Cisco AI Defense)** | 위 4종 + 유해 콘텐츠 6종(HARASSMENT/HATE_SPEECH/PROFANITY/SEXUAL_CONTENT/SOCIAL_DIVISION/VIOLENCE) + CODE_DETECTION/SECURITY_VIOLATION | 필요(Cisco API) |
| **Prompt Defense 분석기** | MCP 툴 설명·시스템 프롬프트에 **12개 공격벡터에 대한 방어 문구가 빠졌는지** 정규식으로 검사(순수 룰 기반, 외부 의존 0). 12종: `INSTRUCTION_OVERRIDE`, `DATA_LEAKAGE`, `ROLE_ESCAPE`, `INDIRECT_INJECTION`, `OUTPUT_WEAPONIZATION`, `OUTPUT_MANIPULATION`, `MULTILANG_BYPASS`, `UNICODE_ATTACK`, `CONTEXT_OVERFLOW`, `SOCIAL_ENGINEERING`, `INPUT_VALIDATION`, `ABUSE_PREVENTION`(소스 실측, `prompt_defense_analyzer.py`) | 불요 |
| **취약 패키지/코드 분석** | pip-audit 기반 CVE/PYSEC/GHSA 스캔, tree-sitter 기반 정적 분석(taint tracking·CFG·call graph — Python/JS 대상), VirusTotal 해시 조회(바이너리 멀웨어), PyPI 패키지 Docker 샌드박스 행위 분석 | 취약패키지·정적분석 불요 / VT 필요 |

- **출력 형식**: `--format raw`(CI/CD용 봉투 JSON: `server_url`/`scan_results`/`requested_analyzers`) 또는 `--raw`(배열), `summary`/`detailed`/`by_tool`/`by_analyzer`/`by_severity`/`table` 다중 포맷. 모든 finding에 **MCP Taxonomy 매핑**(`AITech-N.N`/`AISubtech-N.N.N` — 표준 위협분류 프레임워크와 정렬, `docs/mcp-threats-taxonomy.md`) 부여.
- **출처**: [GitHub](https://github.com/cisco-ai-defense/mcp-scanner) · [문서 사이트](https://cisco-ai-defense.github.io/docs/mcp-scanner)(2026-08-21 접근) · 저장소 내 `docs/readiness-scanning.md`, `docs/mcp-threats-taxonomy.md`, `docs/output-formats.md`, `mcpscanner/core/analyzers/prompt_defense_analyzer.py` 소스 직접 실측.

---

## 2. Snyk `agent-scan` 실측

- **저장소**: [snyk/agent-scan](https://github.com/snyk/agent-scan) (조사일 2026-08-21, `git clone --depth 1` 실측)
- **라이선스**: Apache License 2.0 (LICENSE 파일 실측)
- **패키지명**: `snyk-agent-scan` (PyPI, `uvx`로 실행) + 독립 실행형 바이너리(SBOM·체크섬 동봉)
- **README 안정성 경고(원문 인용)**: *"CLI output is experimental and subject to change"* — 필드명·심각도 라벨·스키마가 사전 고지 없이 바뀔 수 있다고 자체 명시. v0.5.x(issue-code 방식)는 폐기 예정, v0.6+(risk 기반, `2026-07-10` API)가 현행.
- **실행 방식**: **완전 로컬 아님** — `SNYK_TOKEN`(Snyk 계정 API 토큰) 필수. 로컬에서 MCP 서버를 stdio로 **직접 실행**해 툴 설명을 수집한 뒤(⚠️ 이 자체가 위험 신호 — README가 "신뢰 못하는 설정은 샌드박스에서 스캔하라"고 명시 경고), 그 데이터를 `https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10`(소스 실측, `src/agent_scan/cli.py:478`)로 전송해 분석한다. `docs/scanning.md` 원문: *"It then performs local checks and sends the data required for analysis to the Agent Scan API."* 백그라운드/MDM 모드는 Snyk Evo 대시보드로 결과를 중앙 보고.
- **입력**: 머신 전체 스캔(설치된 에이전트 자동 탐지: Claude Code/Desktop, Cursor, VS Code, Windsurf, Gemini CLI, Amp, Kiro, OpenCode, Antigravity, Codex, Amazon Q 등), 특정 MCP 설정 파일, 단일 스킬(SKILL.md), Claude 스킬 전체 디렉터리. System/User/Project/Extension 4개 스코프별 탐지 매트릭스 보유(README 표 실측).

### 검사 항목 15종 (v0.6+, `docs/risks.md` 실측)

| 구분 | 리스크 지표 | 설명 |
|---|---|---|
| **MCP 서버 (5종)** | `dangerous_words` | 툴 설명 내 조작적 언어(에이전트 우선순위 왜곡) |
| | `prompt_injection_tool_desc` | 툴 설명에 지시문-데이터 경계를 흐리는 내용 |
| | `untrusted_content` | 이메일·이슈트래커 등 공격자 제어 가능 채널 노출 |
| | `private_data` | 민감 데이터(개인정보·금융·자격증명) 조회 가능성 |
| | `destructive_capabilities` | 인프라 변경·시스템 명령 실행 등 파괴적 툴 |
| **스킬 (10종)** | `prompt_injection_skill_instructions`, `suspicious_download_url`, `malicious_code`, `insecure_credential_handling`, `secret_detection`, `direct_money_access`, `third_party_content_exposure`, `unverifiable_dependencies`, `modifying_system_services`, `missing_skill_md` | 스킬(SKILL.md) 대상 — 악성코드·자격증명 취급·실시간 원격코드 의존성·금융시스템 직접접근 등 |

- **점수 체계**: 0~1000 정수, 4단계 라벨(Low 100/Medium 300/High 600/Critical 1000) — 점수 자체보다 evidence 텍스트를 근거로 판단하라고 문서가 명시.
- **출력 형식**: `--json` 플래그로 `{scan_path: ScanPathResult}` 맵 구조(v0.5.x) 또는 risk 기반 구조(v0.6+). `--ci` 플래그로 pass/fail 종료코드 지원.
- **출처**: [GitHub](https://github.com/snyk/agent-scan) · 저장소 내 `README.md`, `docs/risks.md`, `docs/json-output.md`, `docs/scanning.md`, `src/agent_scan/cli.py` 소스 직접 실측(2026-08-21).

---

## 3. 그 외 무료/OSS 스캐너 (1줄 요약, 미실측·WebSearch 기반이라 "미확인" 표기 포함)

| 스캐너 | 검사 범위 (1줄) | 확인 수준 |
|---|---|---|
| **Invariant Labs `mcp-scan`** ([GitHub](https://github.com/invariantlabs-ai/mcp-scan)) | 설정파일 탐색 → MCP 서버 연결 → 툴 설명 프롬프트 인젝션/툴 포이즈닝/크로스오리진 이스컬레이션(툴 섀도잉) 탐지 + `mcp-scan proxy`로 런타임 트래픽 가드레일(PII·시크릿 탐지는 로컬, 정확도 높은 분류는 Invariant Guardrails API 필요 — `--local-only`는 OPENAI_API_KEY로 대체 가능하나 정확도 하락) | WebSearch 기반, README 인용 확인 — 소스 미clone |
| **eSentire-Labs `mcp-scanner`** ([GitHub](https://github.com/eSentire-Labs/mcp-scanner)) | 툴·프롬프트·리소스 3종 전체 대상 취약점 탐지(학술 논문 병행 발표, ACM/IEEE 2026) | 미확인 — 논문 초록 기반, 검사 룰 목록 미실측 |
| **badchars `mcp-security-scanner`** ([GitHub](https://github.com/badchars/mcp-security-scanner)) | 55개 툴로 런타임 검사·AST 기반 SAST·설정 감사·의존성 분석·OWASP MCP Top 10 준수 체크·OAuth/TLS/퍼징/프롬프트인젝션/툴 변조 탐지 — **"100% 로컬, 외부 API 호출 0"** 자체 표방 | WebSearch(GitHub 설명文) 기반 — 소스 미clone, 자체 주장 미검증 |
| **mcp-audit** (appsecsanta 리뷰 대상) | MCP 설정 8개 클라이언트 스코프 자동탐지, SARIF·CycloneDX SBOM 출력, GitHub Action·pre-commit 훅, "완전 오프라인 기본값" 표방 | WebSearch(3rd-party 리뷰) 기반 — 원 저장소 URL 미확보 |
| **Proximity** (Help Net Security 소개, 2025-10-29) | OSS MCP 보안 스캐너 — 세부 검사항목 미확인 | 표제만 확인, 상세 미조사 |
| **ToolTrust Scanner** | MCP 서버의 프롬프트 인젝션·데이터 유출·권한 상승을 사전 스캔(Glama.ai 등록) | 표제만 확인 |
| **MCP Shield / mcpshieldai.com** | 무료 스캔 + 유료 "보호" 티어, CVE 탐지·권한 분석·시크릿 탐지 | 표제만 확인, OSS 여부(라이선스) 미확인 |

> ⚠️ 위 7종은 S1 리서치(`2026-08-17-s1-research.md`)가 이미 언급한 Lakera Guard(2025 Check Point 인수, 유료 런타임 방화벽 — OSS 아님)와 별개다. 실제 코드/룰 목록까지 실측한 것은 Cisco·Snyk 2종뿐이며, 나머지는 README/3rd-party 리뷰 수준 확인이라 "검사 룰 파일까지 실측"이라는 함정 조건③을 완전히 충족하지 못했다. 후속 조사 시 badchars·mcp-audit을 최우선 clone 대상으로 권고(로컬 단독·무료·OWASP MCP Top 10 정렬 표방이 AgentTrust v0 요구와 가장 가깝다).

---

## 4. 커버리지 매트릭스 — 심사질문지 14축 × 스캔 가능성

판정 3단계: **가능**(스캐너가 직접 evidence 생성) / **부분가능**(휴리스틱으로 존재·부재만 탐지, 실효성·정확성은 미검증) / **불가**(스캔 대상 자체가 아님 — 조직·계약 문서 필요).

| # | 심사축 | 판정 | 근거(어느 스캐너의 어느 검사) |
|---|---|---|---|
| 1 | **도구/에이전트 권한 범위**(least-privilege) | 부분가능 | Snyk `destructive_capabilities`(파괴적 툴 탐지) / Cisco Readiness `HEUR-018`(위험 키워드: delete·drop·exec·eval) — 둘 다 "위험해 보이는 키워드 존재"만 탐지, 실제 권한 스코프가 최소 권한 원칙을 지키는지는 판정 불가 |
| 2 | **인증/OAuth 구현** | 부분가능 | Cisco는 OAuth **연결**(SSE/streamable HTTP) 지원하나 서버측 OAuth **구현 정확성**은 미검사 / Readiness `HEUR-019`(외부 서비스 인증 컨텍스트 문서화 부재)는 "설명에 인증 언급이 없다"는 문서화 결여만 탐지 |
| 3 | **프롬프트 인젝션 방어** | **가능** | Cisco YARA `prompt_injection`+`coercive_injection` 룰, LLM/API 분석기 PROMPT_INJECTION, Prompt Defense 분석기 12종 방어 결여 탐지 / Snyk `prompt_injection_tool_desc`+`prompt_injection_skill_instructions`+`dangerous_words` — 양사 모두 핵심 설계 목적이라 커버리지가 가장 두껍다 |
| 4 | **시크릿 노출** | **가능** | Cisco YARA `credential_harvesting` 룰 / Snyk `secret_detection`+`insecure_credential_handling`(라이브 자격증명 패턴 직접 매칭) |
| 5 | **취약점/의존성 관리(SCA)** | **가능** | Cisco 취약 패키지 분석기(pip-audit, CVE/PYSEC/GHSA DB 대조) — 유일하게 실제 CVE ID까지 산출 |
| 6 | **악성코드/서플라이체인 무결성** | **가능** | Cisco VirusTotal 해시조회 + PyPI Docker 샌드박스 행위분석 + YARA `code_execution`/`system_manipulation` / Snyk `malicious_code`+`suspicious_download_url`+`unverifiable_dependencies` |
| 7 | **데이터흐름/네트워크 경계 통제** | 부분가능 | Cisco 정적분석 모듈의 taint tracking은 **소스코드 내부** 데이터흐름만(외부 네트워크 토폴로지 아님) / Snyk `untrusted_content`+`private_data`+`third_party_content_exposure`는 "위험한 조합이 존재한다"는 신호일 뿐 실제 트래픽 경로 검증은 아님 |
| 8 | **로깅/모니터링/관측성** | 부분가능(약함) | Cisco Readiness `HEUR-015`(관측성 설정 부재) — 툴 자체의 계측 여부만 확인, 벤더의 감사로그 보존·SIEM 연동 등 운영 관행은 검사 범위 밖 |
| 9 | **사고대응(Incident Response) 체계** | **불가** | 조직 프로세스 문서(런북·SLA)이며 로컬 설정 파일에 존재하지 않음 — 두 스캐너 모두 해당 검사 없음 |
| 10 | **SDLC/코드 리뷰 관행** | 부분가능(약함) | Cisco 정적/행위 분석은 **특정 MCP 서버의 현재 코드 스냅샷**만 대상 — 벤더가 PR 리뷰·브랜치 보호·CI 게이트를 실제로 운영하는지는 별개 질문이라 간접 신호에 그침 |
| 11 | **데이터 보존 정책** | **불가** | 계약/정책 문서 영역, 스캔 대상 아님 |
| 12 | **하도급/4차 벤더(subprocessor) 공개** | **불가** | 벤더 자체 공개 문서 필요, MCP 설정에 벤더사 목록 없음 |
| 13 | **모델 학습데이터 사용 여부** | **불가** | LLM 제공사의 정책 선언 영역 — 로컬 스캔으로 검증 불가능한 항목의 대표 사례(S1 리서치가 지적한 Vanta/Drata 공백과 정확히 겹침) |
| 14 | **DPA(데이터처리계약)/법무 조항** | **불가** | 법률 문서, 스캔 대상 아님 |
| (+1) | **운영 신뢰성**(타임아웃/재시도/에러처리 — 질문지 표준축은 아니나 차별화 근거로 병기) | **가능** | Cisco Readiness 20개 휴리스틱 전량 — 이 축만큼은 오히려 "보안"보다 "운영 안정성" 심사(가용성 SLA 근거자료)에 활용 가능 |

**집계**: 가능 5축 / 부분가능 5축 / 불가 5축 (총 15축, 질문지 표준 14축 기준으로는 가능4·부분가능5·불가5 — 완료기준 "12축 이상" 충족).

---

## 5. v0가 "래핑" 이상으로 더해야 할 가치

원 자료(`2026-08-17-s1-research.md` 가설2)는 "오픈소스 스캐너 결과를 Claude API로 38개 질문 답변 초안으로 변환"이라고만 서술했다. 위 실측을 바탕으로 **그 변환에서 실제로 필요한 작업**을 구체화하면:

1. **클레임 유형별 허용 증거 술어 분리** — 스캐너 finding은 전부 "설정/코드 스냅샷 기준 정적 탐지"라는 한 가지 증거 유형이다. 심사 질문지는 "정책 존재 증명"·"운영 관행 증명"·"기술 통제 증명" 3종을 섞어서 묻는데, 스캐너는 세 번째만 만든다. v0는 각 질문을 이 3유형으로 먼저 태깅하고, 기술 통제 유형만 스캐너 결과로 채운 뒤 나머지 2유형은 자동 생성하지 않아야 한다.
2. **"발견 없음"과 "안전 증명"의 구분 문구 강제** — 두 스캐너 모두 `is_safe: true`/`issues: []`가 "이 항목에서 아무것도 못 찾았다"는 뜻이지 "이 항목이 안전함을 검증했다"는 뜻이 아니다(Snyk README가 스스로 "실험적 출력"이라 경고, Cisco Readiness는 휴리스틱 20개 룰 통과일 뿐 형식 검증이 아님). v0 산출 문서는 매 항목에 "OO 스캐너 기준 YYYY-MM-DD 스캔 시점 미탐지"처럼 **시점·스캐너명·한계**를 못박아야 하고, "완료/안전/통과" 같은 절대 표현을 금지해야 한다.
3. **불가 축의 침묵 방지** — 위 매트릭스 5개 "불가" 축(사고대응·데이터보존·하도급·학습데이터·DPA)을 스캔 결과에서 그냥 빼면 심사관은 "누락"으로 읽는다. v0는 이 축마다 "스캔으로 증적 불가 — 아래 정보를 직접 입력하십시오"라는 **구조화된 질의 폼**을 자동 생성해야 한다. 이게 Vanta/Drata의 AI 증적 공백을 메우는 지점이자, 스캐너 단순 wrapping과 v0를 가르는 유일한 실질 차별점이다.
4. **다중 스캐너 정규화** — Cisco(HIGH/MEDIUM/LOW 심각도, AITech 분류체계)와 Snyk(0~1000 점수, risk indicator명)는 척도·분류가 서로 다르다. 둘 다 붙이려면(로드맵의 "Cisco+Snyk 래핑") 공통 심각도 스케일과 공통 클레임 ID로 정규화하는 매핑 레이어가 필요하며, 이 매핑 로직 자체가 v0의 핵심 자산이다(스캐너가 바뀌어도 재사용 가능).
5. **완전 로컬 vs 외부 전송 고지** — Snyk는 로컬 스캔 데이터를 자사 API로 전송한다(§2). 고객사가 "우리 MCP 설정을 제3자에게 보내지 않는다"를 심사 답변으로 써야 하는 경우 Snyk 경로를 쓰면 그 답변이 거짓이 된다. v0는 어느 스캐너를 쓰든 "이 스캔이 데이터를 외부로 전송하는지"를 소견서에 명시해야 하며, 이는 스캐너 선택(Cisco 로컬 분석기 우선) 논리로도 이어진다.

---

## 출처 목록

- [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) — 저장소 clone 실측(2026-08-21), `README.md`/`docs/*.md`/`mcpscanner/core/analyzers/*.py` 소스 직접 확인
- [MCP Scanner 공식 문서](https://cisco-ai-defense.github.io/docs/mcp-scanner) (2026-08-21 존재 확인, 상세 미열람 — 저장소 문서로 대체 확인)
- [snyk/agent-scan](https://github.com/snyk/agent-scan) — 저장소 clone 실측(2026-08-21), `README.md`/`docs/risks.md`/`docs/json-output.md`/`docs/scanning.md`/`src/agent_scan/cli.py` 소스 직접 확인
- [invariantlabs-ai/mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) (2026-08-21 WebSearch 확인, 소스 미clone)
- [Invariant Labs — Introducing MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) (2026-08-21 WebSearch 확인)
- [eSentire-Labs/mcp-scanner](https://github.com/eSentire-Labs/mcp-scanner) (2026-08-21 WebSearch 확인, 미clone)
- [ACM/IEEE — MCP-Scanner: Detecting Security Risks in Model Context Protocol Systems (2026)](https://dl.acm.org/doi/10.1145/3786160.3788471) (2026-08-21 초록 확인)
- [badchars/mcp-security-scanner](https://github.com/badchars/mcp-security-scanner) (2026-08-21 WebSearch 확인, 미clone)
- [Help Net Security — Proximity: Open-source MCP security scanner (2025-10-29)](https://www.helpnetsecurity.com/2025/10/29/proximity-open-source-mcp-security-scanner/) (2026-08-21 확인)
- 선행 사내 자료: `01-research/projects/weekly-ideas/2026-08-17-s1-research.md`, `20-wiki/concepts/mcp-ecosystem-2026.md`
