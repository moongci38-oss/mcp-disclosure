# 상류(mcp-scanner) 기여 — 준비된 패치

우리가 쓰는 스캐너 `cisco-ai-defense/mcp-scanner` 에서 찾은 버그와, 그것을 고치는 패치를 둔다.
**아직 PR 을 내지 않았다** — 외부 저장소에 내는 일이라 사람 승인이 먼저다.

## 0001 — YARA 파라미터 스캔이 도구 정의 원본을 지운다

| | |
|---|---|
| 파일 | `0001-preserve-tool-data-for-readiness.patch` |
| 대상 | `mcpscanner/core/scanner.py` (2곳) |
| 확인한 버전 | 설치본 **4.8.3** · 상류 **main**(2026-08-26 기준 둘 다 동일 코드) |
| 상태 | ⏳ **PR 미제출** — 승인 대기 |

### 무슨 일이 벌어지나

YARA 로 도구 **파라미터**를 스캔하기 직전, 설명은 이미 봤으니 빼려고 이렇게 한다.

```python
if "description" in tool_data:
    del tool_data["description"]      # ← 원본 dict 를 지운다
tool_json_str = json.dumps(tool_data)
```

그런데 그 `tool_data` 는 **같은 함수 안에서 몇 줄 뒤에** readiness 분석기로 넘어간다
(`readiness_context = {..., "tool_definition": tool_data}`). 그래서 **YARA 와 readiness 를
함께 켜면 readiness 는 설명이 사라진 도구를 보게 된다.**

빨래하려고 주머니를 비웠는데, 그 주머니를 다음 사람이 그대로 검사하는 셈이다.

### 무엇이 틀어지나 (실측)

fixture 3개 도구로 분석기 조합만 바꿔 대조했다.

| 조합 | HEUR-009 "설명 없음" | HEUR-017 | HEUR-019 |
|---|---|---|---|
| READINESS 단독 | · 미발화(정상) | ✅ | ✅ |
| READINESS + YARA | ❌ **3/3 거짓 양성** | · 사라짐 | · 사라짐 |

- **거짓 양성**: 설명이 멀쩡히 있는 도구 전부에 "설명이 없다"가 붙는다.
- **거짓 음성**: 설명을 근거로 삼는 규칙(HEUR-017·019)이 조용히 사라진다.
- ⚠️ 총 finding 수는 **22건으로 같다**(하나 들어오고 하나 나간다) — 그래서 개수만 보면 눈치채기 어렵다.

### 패치

원본을 지우는 대신 **파라미터 스캔용 사본**을 만든다. YARA 가 보는 내용은 그대로다.

```python
tool_params_only = {k: v for k, v in tool_data.items() if k != "description"}
tool_json_str = json.dumps(tool_params_only)
```

같은 패턴이 **프롬프트 경로**(`prompt_data`)에도 하나 더 있어 함께 고쳤다.
⚠️ **다만 프롬프트 쪽은 피해를 실증하지 못했다** — 그 경로에서 readiness 호출부를 찾지 못했다.
같은 위험 패턴이라 방어적으로 고친 것이고, PR 본문에도 그렇게 적는다.

### 검증 (red → green)

```bash
# 스캐너 설치
mkdir -p ~/.cache/mcp-disclosure-scanner && cd ~/.cache/mcp-disclosure-scanner
uv venv --python 3.12 && uv pip install --python .venv/bin/python cisco-ai-mcp-scanner

# fixture 를 가리키는 config 를 만든 뒤 (경로만 바꾸면 된다)
#   {"mcpServers":{"f":{"command":"node","args":["<repo>/fixtures/servers/readiness-gaps-stdio-server.js"]}}}

# RED — 패치 전
python docs/research/scripts/probe-scanner-module.py /tmp/probe.json --combo
#   → READINESS 단독에만 있는 규칙 : ['HEUR-017', 'HEUR-019']
#     YARA 를 켜야 생기는 규칙     : ['HEUR-009']

# 패치 적용 (설치본에 직접)
patch -p1 -d "$(python -c 'import mcpscanner,os;print(os.path.dirname(os.path.dirname(mcpscanner.__file__)))')" \
  < upstream/0001-preserve-tool-data-for-readiness.patch

# GREEN — 패치 후
python docs/research/scripts/probe-scanner-module.py /tmp/probe.json --combo
#   → READINESS 단독에만 있는 규칙 : (없음)
#     YARA 를 켜야 생기는 규칙     : (없음)
```

**실측 결과(2026-08-26)**: 패치 후 두 조합의 rule_id 집합이 완전히 일치했다 —
`HEUR-001×3, HEUR-003×3, HEUR-006×3, HEUR-013×3, HEUR-014×3, HEUR-015×3, HEUR-017×2, HEUR-018×1, HEUR-019×1`.
거짓 양성 HEUR-009 는 사라지고 HEUR-017·019 가 돌아왔다.

### 우리에게 주는 의미

이 패치가 상류에 들어가면 **우리 쪽 분리 실행(`SCANNER_PASSES`)을 되돌릴 수 있다** —
스캔 시간 +95% 를 그대로 회수한다(`src/runner.ts` 의 폐기조건 ①이 바로 이것이다).
그때까지는 분리 실행이 우리의 유일한 방어선이다.

### PR 을 낼 때 (승인 후)

- 대상: https://github.com/cisco-ai-defense/mcp-scanner (Apache-2.0, `CONTRIBUTING.md` 확인 필요)
- 본문에 넣을 것: 위 대조표 · fixture 서버 · red→green 재현 명령
- 프롬프트 경로는 **"같은 패턴이지만 피해 미실증"** 이라고 분명히 적는다 — 확인 안 한 것을
  확인한 것처럼 쓰지 않는다.
