# 갭 B PoC — 스캐너를 모듈로 부르면 막힌 3축이 열리는가

> 작성일 2026-08-24 · 배경: `2026-08-23-public-standard-mapping.md` §5 갭 B.
> 공개 표준 매핑에서 **후보가 가장 많은 세 축**(logging 37건·tool_permission 34건·sdlc 21건)이
> 전부 v0 신호 0 이었다. 원인은 분석기가 아니라 CLI 라는 창구였다 — 그 창구를 건너뛰어 봤다.

## 결론부터 (쉽게 요약)

**열립니다. 그리고 열어 보니 안에서 다른 문제가 하나 더 나왔습니다.**

1. **rule id 는 살아 있습니다.** CLI 는 `threat_type` 하나만 적어 주고 나머지를 버리는데,
   모듈로 직접 부르면 `HEUR-001`~`HEUR-020` 이 그대로 손에 잡힙니다. 게다가 `readiness_score`,
   `recommendation`, `location` 까지 딸려 옵니다 — 전부 CLI 경로에서는 잃어버리던 것들입니다.
2. **막혀 있던 세 축이 실제로 발화합니다.** HEUR-015(logging)·018(tool_permission)·019(auth_oauth)
   가 fixture 에서 전부 잡혔습니다. "이론상 가능"이 아니라 **실측**입니다.
3. **그런데 상류에 버그가 있습니다.** YARA 분석기를 함께 켜면 readiness 결과가 **왜곡됩니다.**
   우리 v0 은 YARA 를 항상 켭니다 — 즉 **지금 나가는 소견서의 readiness 건수가 이미 틀렸습니다.**

쉽게 말하면, 답을 아는 사람을 찾아갔더니 답도 알려 주고 **"그런데 지금 쓰는 창구가 답안지를
한 장 찢고 있어요"** 라는 말까지 들은 셈입니다.

---

## 1. 확인된 것 — rule id 는 모듈 경로에 살아 있다

`SecurityFinding.details` 에 그대로 담겨 있다. fixture 스캔에서 readiness finding **22건이
전부 rule_id 를 보유**했다.

| | CLI 경로(현행 v0) | 모듈 직접 호출 |
|---|---|---|
| rule_id (`HEUR-0NN`) | ❌ 유실 | ✅ 보존 |
| `readiness_score` | ❌ | ✅ |
| `recommendation` | ❌ | ✅ |
| `location` (`tool.<이름>`) | ❌ | ✅ |
| `threat_type` | ✅ | ✅ |

유실 지점은 이미 알고 있던 그곳이다 — `report_generator` 가 `details["threat_type"]` 만
직렬화한다(IMPL-NOTES §4). **분석기는 처음부터 다 알고 있었다.**

## 2. 막혀 있던 3축 — 발화 실측

fixture `fixtures/servers/readiness-gaps-stdio-server.js` 를 새로 만들어 실측했다.
기존 `malicious-stdio-server.js` 로는 HEUR-015 만 발화하고 018·019 는 잠잠했기 때문이다.

| 규칙 | 우리 축 | 발화 조건(4.8.3 소스 실측) | 결과 |
|---|---|---|---|
| HEUR-015 | logging | observability(로깅·메트릭·트레이싱) 설정 부재 | ✅ 3/3 도구 |
| HEUR-018 | tool_permission | 이름·설명에 delete·drop·exec·purge 등 위험 키워드 | ✅ `delete_stale_records` |
| HEUR-019 | auth_oauth | 설명에 api·endpoint·http 등 외부 지표 + auth 필드 없음 | ✅ `fetch_from_partner_api` |

fixture 에는 **대조군**을 넣었다. `read_cached_report` 는 위험 키워드도 외부 지표도 없어
018·019 가 붙으면 안 되고, 실제로 붙지 않았다 — 규칙이 아무 데나 붙는 게 아니라
**실제로 구분한다**는 증거다.

## 3. 발견한 상류 버그 — YARA 를 켜면 readiness 가 눈을 감는다

### 무슨 일이 벌어지나

`mcp-scanner` 4.8.3 `core/scanner.py` 의 YARA 파라미터 스캔 구간:

```python
# Remove description from the JSON as it is already analyzed
if "description" in tool_data:
    del tool_data["description"]        # ← 원본 dict 를 지운다
```

그 `tool_data` 는 **같은 함수 안에서 뒤이어** readiness 에 `tool_definition` 으로 넘어간다.
사본을 뜨지 않고 원본을 지웠기 때문에, **readiness 는 설명이 빈 도구를 보게 된다.**

빨래를 하려고 주머니를 비웠는데, 그 주머니를 다음 사람이 그대로 검사하는 셈이다.

### 실측 대조 (같은 fixture, 분석기 조합만 다름)

| 조합 | HEUR-009 "설명 없음" | HEUR-017 | HEUR-019 |
|---|---|---|---|
| READINESS 단독 | · 미발화 | ✅ | ✅ |
| READINESS + YARA | ❌ **3/3 도구에 발화** | · 사라짐 | · 사라짐 |
| 로컬 안전 4종 전부 | ❌ 3/3 발화 | · 사라짐 | · 사라짐 |

- **거짓 양성**: HEUR-009("이 도구는 설명이 없다")가 **설명이 멀쩡히 있는 도구 전부**에 붙는다.
- **거짓 음성**: 설명을 근거로 삼는 HEUR-017·019 가 조용히 사라진다.

### 우리에게 미치는 영향

우리 v0 은 `yara,readiness,vulnerable_package` 를 함께 켠다(`src/runner.ts` `LOCAL_SAFE_ANALYZERS`).
즉 **지금 이 왜곡을 그대로 받고 있다.** 다만 CLI 경로라 rule_id 가 없어 소견서에는
"readiness 몇 건"으로만 뭉뚱그려 나온다 — **틀린 건수가 조용히 섞여 있는 상태**다.

⚠️ 이것은 "축이 하나 막혔다"보다 무거운 문제다. 우리 제품의 차별축이 **커버리지 정직성**인데,
그 정직성을 떠받치는 숫자 자체가 왜곡돼 있었다.

## 4. 그래서 무엇을 할 것인가 (설계 판단 — 아직 결정 아님)

| 안 | 내용 | 장점 | 대가 |
|---|---|---|---|
| **A. 분석기 분리 실행** | readiness 를 YARA 와 **따로** 돌리고 결과를 합친다 | 상류를 안 건드린다. 지금 당장 가능 | 스캔이 2회로 늘어 느려진다 |
| **B. 모듈 직접 호출로 전환** | CLI 대신 Python 모듈을 부른다 | rule id·score·recommendation 전부 확보 → **3축이 열린다** | Node↔Python 경계 설계 변경. `runner.ts` 재작성 |
| **C. 상류 패치 기여** | `tool_data` 사본을 뜨도록 PR | 근본 해결 + 오픈소스 기여로 신뢰도 | 머지까지 대기. 우리 일정과 무관하게 흘러간다 |

**권고: A 를 즉시 + C 를 병행, B 는 AI-CAIQ 문항 분포를 보고 결정.**
A 는 오늘의 왜곡을 당장 멈추고, C 는 남들도 같은 함정에 빠지지 않게 한다. B 는 투자가 큰데
**어떤 축이 실제로 값어치가 있는지는 AI-CAIQ 320문항을 봐야 안다**(§공개 표준 매핑 §7).

### 4-1. 안 A 구현 후 실측 — **지금 당장의 이득은 0 이다** (2026-08-24 추가)

안 A(분리 실행)를 구현하고 나서 CLI 경로로 전후를 비교했더니, **출력이 한 글자도 달라지지
않았다.** 이 사실을 먼저 적는다.

| 항목 | 단일 실행 | 분리 실행 | 차이 |
|---|---|---|---|
| readiness `total_findings` (도구 3개) | 8 / 7 / 7 | 8 / 7 / 7 | **없음** |
| promptdefense `total_findings` | 12 / 12 / 12 | 12 / 12 / 12 | **없음** |
| yara `total_findings` | 0 / 0 / 0 | 0 / 0 / 0 | **없음** |
| `severity`·`threat_names`·`threat_summary` | — | — | **전부 동일** |
| **스캔 시간** | **6,252 ms** | **12,203 ms** | **+95%** |

왜 같은가: CLI raw 봉투는 **롤업 요약**만 담는다(개수·최고 심각도·요약문 한 줄). rule id 가
없으니 **어떤 규칙이 발화했는지가 바뀌어도 겉으로 안 드러난다.** 실제로 거짓 양성 HEUR-009 가
들어오고 HEUR-019·017 이 빠졌는데 총계는 22 로 같았다 — 들어온 수와 나간 수가 우연히 맞았다.

**그래서 지금 상태를 정확히 말하면 이렇다.**
- 고친 것: **원인**(readiness 가 온전한 도구 정의를 본다). 결과의 **내용**은 실제로 달라졌다.
- 안 고쳐진 것: **오늘 나가는 소견서 텍스트.** 한 글자도 안 바뀐다.
- 지금 치르는 값: **스캔 시간 +95%.**

이걸 감수할 이유는 하나다 — **모듈 전환(안 B) 시점에 이 분리가 없으면, 애써 살려낸 rule id
절반이 틀린 값이 된다.** 원인을 먼저 없애 두는 쪽을 택했다. 반대로 **모듈 전환을 안 하기로
하면 이 비용은 영영 회수되지 않으므로 분리를 되돌려야 한다.**

### 4-2. 안 C 진행 — 패치를 만들어 검증까지 마쳤다 (2026-08-26 추가)

상류 버그를 고치는 패치를 작성하고 **설치본에 적용해 red→green 을 확인**했다.
PR 은 아직 내지 않았다(외부 저장소 제출이라 사람 승인이 먼저다).

- 패치: `upstream/0001-preserve-tool-data-for-readiness.patch` · 경위·재현: `upstream/README.md`
- 상류 **main 에도 같은 버그가 그대로 있다**(2026-08-26 확인). 게다가 **프롬프트 경로에
  같은 패턴이 하나 더** 있어 함께 고쳤다 — 단 그쪽은 피해를 실증하지 못했다(방어적 수정).
- 패치 후 실측: **두 조합의 rule_id 집합이 완전히 일치**했다.
  `READINESS 단독에만 있는 규칙: (없음)` · `YARA 를 켜야 생기는 규칙: (없음)`.
  거짓 양성 HEUR-009 는 사라지고 HEUR-017·019 가 돌아왔다.

**이것이 §4 표의 안 A 를 언제 되돌릴 수 있는지도 정한다** — 이 패치가 상류에 들어가면
분리 실행을 폐기하고 스캔 시간 +95% 를 회수한다(`src/runner.ts` 폐기조건 ①).

## 5. 이 실험의 한계

1. **fixture 3개 도구가 전부다.** 실제 MCP 서버 생태계에서 이 규칙들이 얼마나 자주 발화하는지는
   모른다 — "잡힌다"와 "쓸모 있다"는 다른 주장이다.
2. **sdlc 축은 이번에 손대지 않았다.** 후보 21건짜리 축인데 대응 규칙을 아직 찾지 않았다.
3. **상류 버그는 4.8.3 한 버전에서만 확인**했다. 다른 버전에서 고쳐졌는지 확인하지 않았다.
4. 성능을 재지 않았다 — 안 A 의 "2회 실행" 비용이 실제로 얼마인지 모른다.

## 6. 재현

```bash
# 스캐너 설치 (모듈명은 cisco-ai-mcp-scanner 가 아니라 `mcpscanner` 다)
mkdir -p ~/.cache/mcp-disclosure-scanner && cd ~/.cache/mcp-disclosure-scanner
uv venv --python 3.12
uv pip install --python .venv/bin/python cisco-ai-mcp-scanner

# fixture 를 가리키는 MCP config 를 만들고(경로만 바꾸면 된다)
cat > /tmp/probe.json <<'JSON'
{"mcpServers":{"f":{"command":"node","args":["<repo>/fixtures/servers/readiness-gaps-stdio-server.js"]}}}
JSON

# 조합별 대조 실행
~/.cache/mcp-disclosure-scanner/.venv/bin/python \
  docs/research/scripts/probe-scanner-module.py /tmp/probe.json --combo
```

기대 출력: READINESS 단독에서 **HEUR-015·018·019 세 축 전부 ✅**,
`READINESS 단독에만 있는 규칙: ['HEUR-017', 'HEUR-019']`,
`YARA 를 켜야 생기는 규칙: ['HEUR-009']` + 상류 버그 경고.

⚠️ venv 위치를 `/tmp` 대신 `~/.cache/mcp-disclosure-scanner` 로 옮겼다 — 종전 경로는
**재부팅마다 사라져서** 세션마다 재설치했다(이번에도 사라져 있었다).

**관측일 2026-08-24 · mcp-scanner 4.8.3 · Python 3.12.**
