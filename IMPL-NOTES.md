# 구현 중 발견 사항 (Spec과 어긋난 점, 있으면 기록)

- Task 8: Spec의 RED 테스트 스니펫(§8.5)은 "scanOne을 mock하여..."라는 주석뿐 실제 코드가 없었다.
  Task 7이 이미 `ScanDeps`(spawn 주입) 설계를 확립해 뒀으므로, 그 설계를 그대로 이어받아
  EventEmitter 기반 fake spawn으로 대체 구현(모킹 함정 회피, Task 7의 설계 의도와 일치).

- **Task 8b — mcp-scanner 실측이 Spec §0 전제사항 다수를 뒤집었다.** 브리프는 "이 머신에
  미설치일 가능성이 높다"고 가정했으나, 시스템 python3(3.10.12)가 요구버전(>=3.11.4) 미달이라
  `pip install`이 1차 실패한 뒤 `uv venv --python 3.12`로 격리 venv를 만들어 실제 설치·실행에
  성공했다(버전 4.8.3). 실측 결과 전체 표는 `docs/scanner-exit-codes.md` 참조. 요지만 적으면:
  1. **CLI 플래그가 전부 다르다** — `--config <path>`가 아니라 `config --config-path <path>`
     서브커맨드, `--remote <url>`이 아니라 `remote --server-url <url>` 서브커맨드. 글로벌 플래그는
     서브커맨드보다 먼저 와야 한다(argparse 제약). `buildScannerArgs()`를 실측대로 재작성했다
     (commit 참조).
  2. **기본 `--analyzers`(api,yara,llm)는 API/LLM 키 없이는 항상 exit 1**이다 — ADR-001/002(로컬
     전용) 준수를 위해 `--analyzers yara,readiness,vulnerable_package`(키 불요 확인됨)로 고정했다.
     이 결정은 Spec에 명시된 바 없는 이 세션의 신규 결정이다.
  3. **`--version` 플래그 자체가 존재하지 않는다**(exit 2, argparse 거부). `getScannerVersion()`은
     이미 실패 시 null을 반환하도록 설계돼 있어 안전하게 처리되지만, 실전에서 CLI로 버전 문자열을
     얻을 방법이 전혀 없다는 사실이 새로 확인됐다 — package.json의 `supportedScannerRange: "0.x"`도
     실제 설치판(4.8.3)과 맞지 않지만, 이 값 자체의 재정의는 Task 8b의 명시 책임 항목이 아니라서
     고치지 않고 코멘트로만 남겼다(§12 미결 승계).
  4. **raw 봉투의 `scan_results[]` 내부 구조가 Spec §5.1b 추정과 근본적으로 다르다.** Spec은
     "분석기 실행 1회당 1개 원소, 그 안에 개별 finding 배열(`rule`/`rule_id` 필드 보유)"을
     가정했다. 실측은 "스캔 대상 항목(도구/프롬프트/리소스) 1개당 1개 원소, 그 안의 `findings`는
     **분석기명을 키로 하는 롤업 요약 객체**(`severity`/`threat_names`/`threat_summary`/
     `total_findings`)"였다 — **`rule`/`rule_id` 필드 자체가 원본에 없다.** `parseScannerRawEnvelope()`와
     그 타입(`RawScanResultEntry`/`RawAnalyzerSummary`)을 실측 구조로 전면 재작성했고, RED 확인은
     "구 구현을 새 실측 fixture에 그대로 돌리면 findings 0건이 나온다"(정확히 A-1이 막으려던
     그 버그)는 사실로 직접 증명했다(node -e 재현, 실제 커밋에는 포함 안 됨 — 코드 diff와 테스트가
     그 증거를 대체한다).
  5. **⚠️ Session 2 착수 전 재검토 필요 — ontology.yaml 설계 전제 자체가 흔들린다.** Spec §5.4의
     `rule_map`(`HEUR-001`·`credential_harvesting`·`CVE-*`·`prompt_injection` 등)은 "개별 finding에
     안정적인 rule 식별자가 있다"를 전제하는데, 실측 결과 그런 필드가 없다. Session 2가 그대로
     `ontology.yaml`을 작성하면 `rule_map`이 실제 finding과 절대 매칭되지 않아(axis: null 전건)
     제품의 핵심 가치(15축 커버리지 분류)가 무의미해질 위험이 크다. 이 세션은 Spec을 고치지 말라는
     지시를 받았으므로 여기 기록만 남긴다 — Session 2 착수 세션은 이 문서와
     `docs/scanner-exit-codes.md`를 먼저 읽어야 한다.
  6. Prompt Defense 12종 카테고리·`data_flow`/`sdlc`/`accepts_taxonomy`(AITech-N.N)·YARA 실제
     탐지 시 `threat_names` 표기는 이번 실측 대상(무해한 레퍼런스 MCP 서버)으로는 트리거되지 않아
     여전히 미실측이다(§0 전제사항 그대로 유지, 다음 세션 재확인 필요).

- **환경 발견 — bare `node --test`(Node 22.22)는 `dist/test/*.js`뿐 아니라 `test/*.ts` 원본도
  같이 주워서 실행하다 전부 `ERR_MODULE_NOT_FOUND`로 죽는다.** Node 22.6+의 내장 TypeScript
  type-stripping이 기본 활성화돼 `.ts` 파일도 테스트 러너 기본 glob에 잡히는데, 우리 소스는
  NodeNext 컨벤션대로 `.js` 확장자로 import한다(`from './discover.js'`) — 컴파일 전 원본
  `.ts` 상태에서는 그 `.js` 파일이 실존하지 않아 모듈 해석이 실패한다. **이것은 구현 결함이
  아니라 Node 테스트러너 자동탐색과 우리 빌드 파이프라인의 상호작용**이다. Spec이 정한 정식
  검증 명령은 `package.json`의 `"test": "node --test dist/test/**/*.test.js"`(선행 `pretest`가
  `npm run build` 실행)이며, `npm test`(또는 `npm run build && node --test dist/test/**/*.test.js`)
  로는 22/22 전부 GREEN이다. 완료 보고의 "3개 명령 실측"에는 브리프가 요청한 bare `node --test`
  원문 출력(실패 포함)과 `npm test` 출력(GREEN)을 함께 남긴다 — 실패를 숨기지 않되 원인을 밝힌다.

- **Session 2 착수 전 재측정 (2026-08-22) — 위 5번 항목의 후속·정정.** "안정적인 rule 식별자가
  없다"는 진단은 **절반만 맞았다.** 식별자(`details["rule_id"]` = `HEUR-001`~`HEUR-020`,
  `details["raw_response"]["rule"]` = YARA 룰명)는 스캐너 내부에 **실존**하는데,
  `report_generator.py:32 results_to_json()`이 `details["threat_type"]` 하나만 직렬화하면서
  버린다(`:82`). 7개 출력 포맷 전부가 이 함수에서 파생되므로 포맷 교체로는 못 건진다.
  추가로 **`mcp_taxonomies`가 "항상 빈 배열"이라는 위 6번 서술은 폐기한다** — readiness만 봤기
  때문이었고, YARA 발화 시·`promptdefense_analyzer`는 `aitech`/`aisubtech`를 정상 반환한다.
  그리고 **`prompt_defense` 분석기는 API 키 없이 exit 0으로 동작**하며 12종 카테고리를 정확
  문자열로 낸다 — Session 1의 `--analyzers` 조합에서 빠져 있었다.
  → 개정안: `docs/planning/SPEC-v0-cli-AMENDMENT-01-signal-map.md` (**[STOP] 승인 대기 — 승인 전
  Task 9 착수 금지**). 재현 명령·원본 출력: 그 문서 §2 · `docs/measurements/2026-08-22-signal-space/`

- **Session 2 구현 중 발견 (2026-08-22)**
  1. **테스트 fixture 자체가 틀려서 검증 경로를 안 타는 사례.** `assignAxis` 의 "taxonomy 가
     signal_map 을 이긴다" 충돌 테스트에서 `AISubtech-1.1.1` 을 충돌값으로 썼는데, 그 ID 는
     이미 `prompt_injection_defense` 소유라 선언 순서상 그쪽이 먼저 이겼다 — 테스트는
     **통과했지만 검증하려던 경로를 타지 않았다.** 소유자 없는 `AISubtech-4.1.1` 로 교체.
     교훈: 충돌 fixture 에는 **아무도 소유하지 않은 값**을 써야 한다. Spec §8.5 Task 13·17 에도
     같은 정정을 반영했다.
  2. **`wiring-check.sh` 가 흔한 영어 단어 심볼에서 과다 계상한다.** `normalize` → 190곳으로
     보고하지만 실제 프로덕션 소비처는 1곳이다(node_modules·dist·문서 산문까지 긁는 것으로 보임).
     반대로 `assignAxis` 는 0곳으로 나왔는데 실제로는 1곳에서 호출된다(과소 계상). 완료 보고에
     이 숫자를 필수로 적게 돼 있어 그대로 믿으면 틀린 숫자가 커밋 메시지에 박힌다 — 프로젝트
     `src/`·`bin/` 한정 grep 으로 교차 확인할 것.
     하네스 갭 기록: `harness-gaps/2026-08-22-wiring-check-common-word-false-positive.md`
  3. **`--analyzers` 에 `prompt_defense` 를 넣으면 출력 분석기 키가 둘로 갈린다** —
     `prompt_defense_analyzer`(항상 0건 유령) / `promptdefense_analyzer`(실제 finding).
     스캐너 쪽 이름 불일치(`report_generator.py:51` vs `:65`)이며, 파서의 `total_findings<=0`
     스킵이 유령을 걸러준다. ontology 의 `signal_map` 은 **반드시 후자**를 키로 써야 한다.
