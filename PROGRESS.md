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

- 다음: Task 11~12(normalize 1/3·2/3) — **착수 전 Spec §12 미결 ⑤ 선처리 필수**
  (`RawFinding` 에 `analyzer`/`threatName` 분리 + `mcp_taxonomies` 객체 파싱 버그)
