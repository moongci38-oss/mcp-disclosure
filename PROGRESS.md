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
⚠️ `wiring-check.sh normalize` 가 **190곳**을 보고했는데 오탐이었다.
**원인은 처음 적은 것과 다르다** — node_modules 를 긁은 게 아니라 그 도구가 **agenttrust 를
아예 쳐다보지 않았다**(검색 루트가 `~/forge` 고정이었다). 190곳은 전부 forge 안의 hit 이다.
→ **2026-08-22 도구 수리 완료**(forge `c8b02801`): 검색 범위 자동 판정 + 범위 항상 출력.
재측정하니 `normalize` **5곳**(전부 실제 `src/*.ts`)이다.

## P5 Session 3 진행상황 — 클레임 매핑 + 커버리지 3칸 렌더 (5 SP)

- [x] Task 16: `src/map.ts` `mapFindingsToClaims` — 축당 정확히 1클레임(항상 15개)
  ⚠️ **술어를 3종으로 확장**(개정안 #01 §4.4 의 직접 귀결): `scanner_detected` /
  `scanner_not_detected`(검사했고 못 찾음) / **`scanner_cannot_detect`**(애초에 볼 수 없음
  + `unreachable_reason`). 뒤의 둘을 뭉치면 "못 본 것"이 "깨끗한 것"으로 읽힌다.
  Spec FR-03.1 · AC-03j 신설 반영.
- [x] Task 17: `test/ontology.mutation.test.ts` — 변이 5종(신호 제거 2 · promptdefense 면제 ·
  taxonomy 우선순위 · signal_status 뒤집기)으로 매핑 검사의 판별력 실증
- [x] Task 18: `src/render.ts` fail-closed — 15축 누락 / 메타 6필드 결손 / **칸 배정 유실**
  (술어가 늘었는데 filter 를 안 고쳐 축이 조용히 사라지는 것) → RenderError
- [x] Task 19: `render()` 본체 — 3칸 소견서. **3절을 3a/3b 로 분리**했다:
  3a = 도구 한계(신호가 안 오는 기술 축, 사유 동반) / 3b = 조직·계약 증적.
  이 분리가 없으면 partial 5축이 소견서에서 **통째로 사라진다**(실제로 그럴 뻔했다).
- [x] Task 20: 증적 요청 폼 체크리스트화 — 3b 만 `- [ ]` 체크박스.
  3a 에는 붙이지 않는다(도구 한계를 "서류 내면 되는 것"으로 오독시키지 않기 위해)
- [x] **Spec §0 위반 1건 자체 발견·수정**: `unreachable_reason` 5건이 한글이라 영문 소견서에
  한글이 섞여 나왔다("소견서 본문은 영어로 통일" 위반). 영문화 + 회귀 방지 테스트 2종 추가
  (한글 혼입 금지 · 사유 구체성 하한)

- **Session 3 완료** (2026-08-22). `npm test` **125/125 GREEN**.
  실측 fixture 엔드투엔드로 소견서 생성 확인 — 1칸 4축(13/1/2/1건) · 2칸 1축 ·
  3a 5축(사유 포함) · 3b 5축(체크박스) · Unmapped 0.
  판별력 실증(역변조): 3a 칸 삭제 + 버킷팅 가드 해제 → 3건 FAIL, 원복 후 복구.

### ⚠️ 배선 현황 — 파이프라인이 아직 이어져 있지 않다

```
$ for f in src/*.ts; do b=$(basename $f .ts);     [ $(grep -rl "from './$b.js'" src/ | wc -l) -eq 0 ] && echo "$b: importer 0"; done
discover / map / normalize / render / runner / scanner-envelope / version-check → 전부 0
$ ls bin/   → 디렉터리 없음 (package.json 의 bin.agenttrust 가 가리키는 파일이 없다)
```

9개 모듈 중 **7개가 아무 데서도 import 되지 않는다.** `types`·`ontology`·`masking` 만 다른
모듈이 쓰고 있고, 이들을 하나로 잇는 `src/cli.ts` 와 `bin/agenttrust.js` 는 **Task 25(Session 4)**
다. 즉 조각은 다 만들어졌고 각각 테스트로 검증됐지만, **`npx agenttrust scan` 은 아직 실행되지
않는다.** 이것을 "완료"라고 부르지 않는다.

⚠️ `wiring-check.sh` 가 `normalize` 를 190곳으로 보고했으나 **오탐**이었다(그 도구가
agenttrust 가 아니라 `~/forge` 를 뒤지고 있었다). **2026-08-22 수리 완료** — 이제 검색 범위를
자동 판정하고 항상 출력한다. 이 시점의 정본은 위 import 그래프다.

## P5 Session 4 진행상황 — 판별력 테스트 + 배선 + 도그푸딩 (4 SP)

- [x] Task 21: 금지 술어 회귀 — 정확일치 + 대소문자/하이픈/동의어 + 발견 0건 경로 + 실측 경로
- [x] Task 22: 시크릿 회귀 — sk-/중첩객체/JWT/authorization + 롤업 raw(threat_summary) + URL 자격증명
- [x] Task 23: coverage fail-closed **역변조 실증** — `verified: mutation-kills-check(AC-03c)`
- [x] Task 24: 원격 차단 E2E — spawn 주입 스파이(호출횟수·사유·혼합입력·argv 전량 검사)
- [x] Task 25: `src/cli.ts` + `bin/agenttrust.js` — **전 모듈 배선 완료**
  Spec 초안 대비 3곳 수정: ontology 를 cwd 아닌 모듈 기준으로 해석(안 그러면 `npx` 실행이 죽는다) ·
  ontology 1회 읽기 · 직접 실행 가드(없으면 `node cli.js` 가 조용히 exit 0)
- [x] Task 26: **도그푸딩** — 실제 스캐너 첫 연결. 24초, findings 167 / unscanned 0 / 미분류 0
- [x] Task 27: `README.md` — 사용법 · 네트워크 0 · Known limitations 4종 · ADR-006 집행표

### 🔴 도그푸딩이 잡은 것 (기록: `docs/dogfooding/2026-08-22-selfscan.md`)

| # | 등급 | 내용 | 조치 |
|--:|---|---|---|
| ① | **치명** | 스캐너 부재로 **스캔 0건인데 기술축 5개를 "검사했지만 못 찾았다"로 보고** | `ScanOutcome` 신설(필수 인자) · 성사 0건이면 `scanner_cannot_detect` · 실패 배너를 문서 맨 위로 · 회귀 5건 |
| ② | 높음 | 재현 메타 자리표시자(`unset`)가 `assertMetaComplete` 를 **무사통과** | 자리표시자 거부 · 실측된 부재는 `unavailable` 로 구분 · `target_hash` 실제 계산 |
| ③ | 중간 | 1절이 ID 154개 통짜 나열 — 가장 중요한 절이 해시 덩어리 | 개수+표본 5개+`see JSON` |
| ④ | 낮음 | `supportedScannerRange "0.x"` ↔ 실제 4.8.3 불일치 | **미조치** — 실측 버전이 하나뿐이라 범위 근거 없음. Spec §12 ⑥ 승계 |

①이 이 세션의 핵심이다. **없는 폴더를 뒤져놓고 "양말이 없네"라고 한 셈**이고, 제품이 존재하는
이유와 정반대되는 출력이었다. fixture 로는 절대 안 잡혔을 버그다 — 도그푸딩을 태스크로 못 박아
둔 이유가 그대로 증명됐다.

- **Session 4 완료** (2026-08-22). `npm test` **152/152 GREEN**.
  ✅ **배선 완료** — `npx agenttrust scan` 이 실제로 소견서 2종을 생성한다(bin 경유 경로도 테스트).
  판별력 실증(역변조 총 9회): ontology 검증 2종 · 팬아웃 · taxonomy 파싱 · taxonomy 우선순위 ·
  unmatchedSignals · 3a 칸 · 버킷팅 가드 · assertCoverageComplete · ADR-006 차단.
  전부 원복 확인, 잔재 grep 0건.

### 남은 것

- ~~**Task 28~29 미착수**~~ — **오독이었다(2026-08-22 정정).** Spec 의 "29 태스크"는
  **번호 1~27 + `8a` + `8b`** 를 센 것이다(Session 1 이 codex 반영으로 2개 신설).
  누락된 태스크는 없고 **Task 1~27 전량 완료**다.
  재현: `grep -cE '^\*\*Task [0-9]+[a-z]?:' docs/planning/SPEC-v0-cli.md` → `29`
- Spec §12 미결: ⑤(종결) · ⑥ fixture 디렉터리명/`supportedScannerRange` 정리 · ①npm 배포명

### Spec 감사 결과 (2026-08-22, Session 4 후속)

**Spec 자체는 정합했다** — 태스크 번호·SP(9+6+5+4=24)·§4.2 exit code 표 모두 코드와 일치.
대신 **반대 방향 드리프트**가 있었다: 도그푸딩 수정분이 코드에만 있고 Spec 에는 없었다.
§8.5 스니펫을 다음 세션이 그대로 복사하면 방금 고친 버그를 되살린다.

- **조치**: `§8.6 구현 확정 사항` 신설 — §8.5 계획과 출하 코드가 다른 **12개 지점**을 이유와 함께
  표로 기록. §8.5 헤더에 "착수 시점 계획, 정본은 §8.6 과 src/" 경고 삽입.
- **AC 정정 1건**: `AC-05a`("md/json finding 행 수 일치")는 1절 축약 이후 **성립 불가**였다 →
  "markdown 표기 건수 합 == json 분류 findings 수"로 재정의.
- **AC 신설 2건**: `AC-02e`(자리표시자 메타 거부) · `AC-03k`(스캔 성사 0건 → cannot_detect).
- **미검증 AC 5건 보강**: `AC-01a`(target 에 설정 원문 미포함) · `AC-01g`(Python 미가용 시
  안내 + 스택트레이스 없음 — `PATH=''` 로 실경로 재현) · `AC-02a`(메타 6필드 전부 노출) ·
  `AC-03a`(claim 의 finding_ids 가 전부 실재 ID) · `AC-04b`(미분류 N≥1 실제 개수).
  판별력 확인: `unmappedCount` 고정 0 + python 가드 제거 → 2건 FAIL, 원복 후 158/158.
### 2차 도그푸딩 + §12 ⑥ 종결 (2026-08-22, Spec 감사 후속)

- [x] **Spec §12 ⑥ 종결** — `supportedScannerRange: "0.x"` → `testedScannerVersions: ["4.8.3"]`.
  구 구현은 **우리가 전부 검증한 유일한 버전(4.8.3)을 "지원 범위 밖"이라고 경고**하고 있었다.
  범위(`4.x`)로 넓히지 않은 이유: 실측 버전이 하나뿐이라 근거가 없다 — 근거 없이 넓히는 것도
  거짓말이다. fixture 디렉터리도 `mcp-scanner-0.1.0/` → `mcp-scanner-4.8.3/` 개명.
  선언(package.json)과 코드 상수의 일치를 테스트로 고정했다.
- [x] **YARA 라이브 발화 검증** — `fixtures/servers/malicious-stdio-server.js` 신설
  (의존성 0 Node stdio MCP 서버. Cisco 예제는 python `fastmcp` 부재로 사용 불가).
  실제 CLI 로 스캔 → findings 40 · 미분류 0 · YARA 3종 발화. **taxonomy 매칭 경로가 실행
  경로에서 처음 검증됐다.**

| # | 등급 | 내용 | 조치 |
|--:|---|---|---|
| ⑤ | **높음** | yara 롤업이 threat_names 2개에 taxonomy 1개를 내는데, 파서가 그 하나를 **양쪽에 복사**했다. taxonomy 우선순위 탓에 `DATA EXFILTRATION` 이 `malicious_pattern` 아닌 **`secret_exposure`** 로 분류 — 소견서가 "데이터 반출"을 "시크릿 노출"로 잘못 말했다 | `resolveTaxonomy` 조건을 둘로(taxonomy 1개 **AND** threat_name 1개 이하). 라이브 캡처 fixture 로 회귀 고정 |
| ⑥ | 중간 | "스캔 0건" 회귀 테스트가 **"이 머신에 스캐너가 없다"는 우연**에 기대고 있어, 스캐너 설치 머신에서 FAIL | PATH 직접 통제(python 셰임만 있는 임시 디렉터리 + `process.execPath`). 스캐너 유/무 양쪽에서 GREEN 확인 |

⑤는 **등급이 아니라 종류가 틀린 오분류**라 읽는 쪽이 엉뚱한 곳을 조사하게 된다. 1차 도그푸딩의
①과 마찬가지로 **fixture 로는 절대 안 잡혔을 버그**다 — 실제 스캐너가 threat_names 와
mcp_taxonomies 개수를 다르게 내는 조합은 우리가 상상해서 만들 수 있는 입력이 아니었다.

- **현재**: `npm test` **164/164 GREEN** (스캐너 유/무 양쪽 확인)

### 배포 산출물 검증 (2026-08-22 — 하네스 갭 수리 후속)

**⚠️ 배포 차단 버그를 잡았다.** `dist/` 가 `.gitignore` 에 있어서 **npm 이 패키지에서 통째로 뺐다.**
`bin/agenttrust.js` 는 `../dist/src/cli.js` 를 import 하므로, 그대로 배포했다면
**모든 사용자에게서 첫 줄에 죽었다**:

```
$ npm pack && tar xzf *.tgz && node package/bin/agenttrust.js scan
Unexpected error: Cannot find module '.../package/dist/src/cli.js'
```

로컬 테스트 164건은 **전부 GREEN 이었다** — dist 가 내 머신에는 있었기 때문이다.
이 프로젝트가 계속 만나는 **"등록 ≠ 발효"의 배포판**이다. 로컬 GREEN 은 배포 GREEN 이 아니다.

- **조치**: `files` allowlist(`dist/src/`·`bin/`·`ontology.yaml`·`README.md`·`LICENSE`) +
  `prepublishOnly: build && test` + **`LICENSE` 파일 신설**(package.json 은 MIT 라고 선언해 놓고
  파일이 없었다).
- **실증**: 팩 → `npm install <tarball>` → `./node_modules/.bin/agenttrust scan` **정상 동작**
  (소견서 2종 생성 확인). 이게 `npx` 사용자가 겪는 실제 경로다.
- **회귀 고정**: `test/package-contents.test.ts` 4건 — 필수 파일 포함 · **bin 의 import 경로가
  패키지 안에 실재하는지**(경로가 바뀌어도 따라간다) · 테스트/소스/문서 미배포 · `files`+
  `prepublishOnly` 존재. 판별력 실증: `files` 제거 → **4건 FAIL**, 원복 후 168/168.
- **패키지 크기**: 121파일 350KB → **16파일 26.5KB**(문서·fixture·컴파일된 테스트 제외).

- 현재: `npm test` **168/168 GREEN**

## 원격 저장소 + CI 가동 (2026-08-23)

**이 프로젝트가 처음으로 내 머신 밖에서 검증됐다.** 그 전까지의 "168/168 GREEN"은 전부
한 대의 노트북에서 나 혼자 돌린 결과였다.

- 원격: `https://github.com/moongci38-oss/agenttrust` (**private**) · `main` 추적
- 첫 push 에서 forge 온보딩 템플릿 워크플로 7개가 발동 → **미적용 템플릿이라
  `.github/workflow-templates/` 로 격리**(지우지 않음 — 배포·롤백이 필요해지면 손봐서 되돌린다)
- 이 프로젝트용 `ci.yml` 신설: Node **20·22 매트릭스** · `npm ci` → `npm test` →
  **실제 tarball 을 만들어 설치하고 설치본 bin 으로 소견서 생성까지** 확인

### 🔴 CI 가 첫 실행에서 바로 잡은 것 — Node 20 에서 테스트가 0건 돌고 있었다

```
Node 22 ✓  /  Node 20 ✗
Could not find '.../dist/test/**/*.test.js'
```

`node --test` 의 `**` glob 지원은 **Node 21+ 부터**다. Node 20 은 그걸 리터럴로 받아
**테스트를 한 건도 실행하지 않은 채** exit 1 한다. 개발 머신이 Node 22 라 로컬은 계속
GREEN 이었고, `engines: ">=20"` 이라고 선언해 둔 하한은 **아무도 검증한 적이 없었다.**

교훈은 "glob 을 잘못 썼다"가 아니라 **선언과 검증이 따로 놀았다**는 쪽이다 —
이 프로젝트가 계속 잡아온 "등록 ≠ 발효"의 또 다른 형태다.
→ 셸이 확장하는 단일 `*` 로 교체. 문서 3곳(CLAUDE.md·IMPL-NOTES.md·SPEC §8) 동기화.

### 현재 CI 상태 (실측 로그)

| 잡 | 결과 | 테스트 |
|---|---|---|
| build + test (Node 20) | ✅ success (24s) | `# tests 168 / # pass 168 / # fail 0` |
| build + test (Node 22) | ✅ success (20s) | 동일 |

두 버전 모두에서 **설치본 실행 스텝까지 통과**했다 — `npx` 사용자가 겪는 경로가 실제로 검증된다.

⚠️ **Actions 는 한동안 아예 못 돌았다**: 계정 결제/지출한도 문제로 **잡이 시작조차 안 됐다**
(`The job was not started because recent account payments have failed...`).
그때 내가 그 실패를 "템플릿이 pnpm/develop 을 전제해서"라고 **근거 없이 단정**했고,
`badd7ca` 에서 정정했다. 로그를 못 읽었으면 못 읽었다고 적었어야 했다.

⚠️ 참고: **Node 20 은 2026-04-30 LTS 종료(EOL)**. `engines` 하한을 22 로 올릴지는 별도 판단 사항.

### 남은 미검증 / 미결

- **원격 대상 라이브 스캔** — 실제 원격 MCP 엔드포인트가 필요해 미실행(스파이 E2E 로만 검증)
- **정적 JSON/패키지 대상** — 스캐너는 `static --tools` 를 지원하나 우리 `buildScannerArgs` 는
  `config`/`remote` 두 형태만 만든다. v0 범위 확장 여부는 미결정
- **`vulnerable_package` 실발화** — 취약 의존성을 가진 대상 미확보
- **YARA `INJECTION ATTACK`·`TOOL POISONING` 의 taxonomy** — 발화 대상 미확보
- **Spec §12 ①** npm 배포명 — Human 승인 게이트(AI 결정 불가)
