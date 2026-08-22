# P5 Session 1 진행상황

- 착수: 2026-08-22
- 범위: Spec §8.5 Task 1 ~ Task 8b (Session 1, 9 SP)

- [x] Task 1: 프로젝트 골격 (package.json, tsconfig.json) — commit d792486
- [x] Task 2: src/types.ts 핵심 타입 선언 — commit a412c30 (tsc --noEmit 0 errors, test 2/2 pass)
- [x] Task 3: src/discover.ts — commit f98ecab (test 2/2 pass)
- [x] Task 4: src/version-check.ts (checkPythonAvailable/getScannerVersion) — commit de94edd (test 2/2 pass)
- [x] Task 5: types.ts Unscanned/UnscannedReason 보강 — commit 2d6fb9e (tsc 0 errors, test 1/1 pass)
- [x] Task 6: buildScannerArgs — commit 78345c5 (test 3/3 pass)
- [x] Task 7: scanOne + classifyScannerFailure — commit 48d9a1d (test 2/2 pass, 전체 12/12 pass)
- [x] Task 8: runScanner — commit ac53406 (전체 13/13 pass, RED 테스트는 spawn 모킹 함정을 피해 ScanDeps 주입 fake로 작성)
- [x] Task 8a: parseScannerRawEnvelope + raw-envelope.json fixture — commit 9515bc2 (전체 16/16 pass)
- [x] Task 8b: 실측 게이트 — mcp-scanner 4.8.3을 격리 venv(uv+python3.12)에 실제 설치·실행해
  CLI 플래그/exit code/raw 스키마를 실측(브리프의 "미설치 가능성" 예상과 달리 설치 성공).
  buildScannerArgs/classifyScannerFailure/parseScannerRawEnvelope를 실측 결과로 재작성.
  상세: docs/scanner-exit-codes.md, IMPL-NOTES.md. 전체 22/22 pass.

- **Session 1 완료** (2026-08-22). 총 11개 커밋(Task 1~8b, IMPL-NOTES 발견 기록 1건 추가).
  `npm test` 22/22 GREEN. bare `node --test`는 Node 22의 TS 자동탐색 이슈로 8건 실패(원인은
  구현 결함이 아님 — IMPL-NOTES.md 참조), `npm test`(Spec 정의 검증 경로)로는 전건 GREEN.

## P5 Session 2 진행상황

- 착수: 2026-08-22
- 범위: Spec §8.5 Task 9 ~ (Session 2, 6 SP) — **단, 착수 전 Spec 개정 게이트를 먼저 통과했다**

- [x] **Spec 개정안 #01** — `rule_map` → `signal_map` 재설계. Session 2 착수 전 mcp-scanner
  4.8.3 재측정으로 Session 1 진단을 정정했다(rule 식별자는 실존하나 CLI 가 직렬화에서 버린다).
  부수 수확 2건: `prompt_defense` 분석기가 키 없이 동작(12종 정확 문자열) · `mcp_taxonomies`
  는 "항상 빈 배열"이 아님(YARA 발화·promptdefense 는 AISubtech 반환).
  Human 승인 → Spec 본문 반영. commit 594953b(개정안) · 36fe3e7(Spec 반영 + Task 6)
- [x] Task 6 수정: `LOCAL_SAFE_ANALYZERS` 에 `prompt_defense` 추가 — commit 36fe3e7 (23/23)
- [x] Task 9: `ontology.yaml` v1 — 15축, signal_map/signal_status/unreachable_reason
- [x] Task 10: `src/ontology.ts` — `loadAxisTable` fail-closed(누락축·값불량·중복신호·
  사유누락·신호없는 reachable·coverage×signal_status 교차) — **전체 42/42 GREEN**
  판별력 실증: 검증 2종을 임시 제거하니 5건 FAIL → 원복 후 42/42 복구(잔재 grep 0건)
  ⚠️ **배선: 0곳** (재현: `wiring-check.sh loadAxisTable`) — 소비처(`cli.ts`)는 Task 25 다.
  만들었지만 아직 아무도 부르지 않는다.

- [x] **Spec §12 미결 ⑤ 선처리** — `RawFinding` 에 `analyzer`/`threatName` 분리 + threat_name
  단위 팬아웃 + `mcp_taxonomies` 객체 파싱 **잠복 버그** 수정 — commit 86c6403 (49/49)
  fixture 추가: `raw-envelope-yara-fired.json`(실측 발췌 — YARA 발화 4건 + 4분석기 1건)
- [x] Task 11: `groupAndAssignMatchIndex` — 해시 정렬 그룹핑 + 중복 접기 — commit 178868b
- [x] Task 12: `computeStableId` — sha256 16자, 셔플 재현성 — commit 178868b
- [x] Task 13: `assignAxis` 3단 폴백(taxonomy → signal_map → null) — commit 178868b
  ⚠️ 테스트 작성 중 실제 오류 1건 자체 발견: 충돌 fixture 로 쓴 `AISubtech-1.1.1` 이 이미
  `prompt_injection_defense` 소유라 검증하려던 경로를 안 탔다 → 소유자 없는 `AISubtech-4.1.1` 로 교체
- [x] Task 14: `redact` 마스킹 파이프 — KEY_DENYLIST + JWT 패턴 + 엔트로피 2차 방어선
- [x] Task 15: `normalize()` 통합 + `computeUnmatchedSignals` — **전체 91/91 GREEN**

- **Session 2 완료** (2026-08-22). Task 9~15 (6 SP) + Spec 개정 게이트 + §12 미결 ⑤ 선처리.
  커밋 5개. `npm test` **91/91 GREEN**(Session 1 대비 +69건).
  엔드투엔드 확인: 실측 봉투 fixture → 파서 → normalize → **17건 전건 분류, 미분류 0건**
  (prompt_injection_defense 13 / malicious_pattern 2 / secret_exposure 1 / operational_reliability 1).
  판별력 실증(역변조 5회): ontology 검증 2종·팬아웃·taxonomy 파싱·taxonomy 우선순위·
  unmatchedSignals 집계를 각각 깨뜨려 대응 테스트가 죽는 것을 확인. 잔재 grep 0건.

### ⚠️ 배선 현황 (완료 아님 — 정직 표기)

| 심볼 | 프로덕션 소비처 | 상태 |
|---|--:|---|
| `assignAxis`·`redact`·`computeStableId`·`groupAndAssignMatchIndex`·`computeUnmatchedSignals` | 1~2곳 | ✅ `normalize()` 가 소비 |
| `normalize` | 0곳 | ⛔ 미배선 |
| `loadAxisTable` | 0곳 | ⛔ 미배선 |
| `parseScannerRawEnvelope` | 0곳 | ⛔ 미배선 |

셋의 소비처는 `src/cli.ts` (**Task 25, Session 4**) 다 — 아직 파이프라인 전체를 잇는 코드가 없다.
재현: `grep -rn '\bnormalize\b' src/ bin/ | grep -v 'export function'`
⚠️ `wiring-check.sh normalize` 는 **190곳**을 보고하는데 이는 오탐이다(흔한 영어 단어라
node_modules·문서까지 긁는다). 하네스 갭으로 기록:
`forge-outputs/11-platform/pipelines/harness-gaps/2026-08-22-wiring-check-common-word-false-positive.md`

- 다음: **Session 3 — Task 16~19**(클레임 매핑 + 커버리지 3칸 렌더, 5 SP).
  Task 19 render 는 개정안 #01 의 `unreachable_reason` 을 소견서에 출력해야 한다.
