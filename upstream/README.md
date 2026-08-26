# 상류(mcp-scanner) — 우리가 기다리는 PR 2건 + 로컬 백업 패치

우리가 쓰는 스캐너 `cisco-ai-defense/mcp-scanner` 관련 기록.

> ⚠️ **2026-08-26 정정**: 이 문서는 원래 "우리가 낼 PR"을 담고 있었다. 그런데 제출 전
> 중복 검색(상류 `CONTRIBUTING.md` 요구사항)을 돌렸더니 **우리가 발견한 두 문제가 이미 둘 다
> 보고돼 있었고 수정 PR 까지 올라와 있었다.** 그래서 **PR 을 내지 않는다** — 중복 PR 은
> 관리자 시간을 뺏는다. 대신 그 PR 들을 추적하고, 머지될 때까지 쓸 로컬 백업 패치만 남긴다.
>
> **교훈: 규약을 먼저 읽어서 중복 PR 을 안 냈다.** 순서를 바꿨으면 남의 저장소에 쓰레기를
> 하나 얹을 뻔했다.

## 우리가 기다리는 PR 2건

| | #228 | #206 |
|---|---|---|
| 제목 | stop YARA from stripping description off the shared `tool_data` | preserve all individual findings per analyzer in report output |
| 닫는 이슈 | #227 | #198 |
| 상태(2026-08-26) | **open · mergeable · 테스트 포함**(+74/−4) | **open** |
| 마지막 갱신 | 2026-08-07 (약 3주 정체) | 2026-06-25 (약 2개월 정체) |
| 우리에게 주는 것 | 분리 실행(`SCANNER_PASSES`) **폐기 → 스캔 시간 +95% 회수** | **CLI `--raw` 에 rule_id 가 실린다 → 모듈 전환(안 B) 불필요** |

### #228 — description 훼손 (우리 발견과 동일)

`_analyze_tool` 이 만든 `tool_data` 한 개를 여러 분석기가 공유하는데, YARA 파라미터 브랜치가
`del tool_data["description"]` 로 **원본을 지우고** readiness 가 그 dict 를 그대로 받는다.

- 이슈 #227(2026-07-30)이 **우리보다 한 달 먼저** 같은 진단을 냈다. 우리 실측(2026-08-24)은
  독립 재현이었던 셈이다.
- 관측이 조금 다르다: #227 은 **HEUR-009 거짓 양성 + HEUR-012 왜곡**을, 우리는
  **HEUR-009 거짓 양성 + HEUR-017·019 거짓 음성**을 봤다(fixture 차이).
- PR #228 의 수정 방향은 **우리 패치와 동일**하다(사본을 뜬다). 게다가 회귀 테스트까지 들어 있어
  우리 것보다 완성도가 높다.

### #206 — finding 세부정보 유실 (= 우리 갭 B 의 원인)

`results_to_json` 이 분석기당 **첫 finding 의 요약만** 남기고 나머지를 버린다. 그래서 readiness 의
HEUR-* 규칙이 7~9개씩 나와도 CLI 출력에는 하나로 뭉개진다 — **`rule_id` 가 사라지는 바로 그 지점**이다.

PR #206 은 `detailed_findings` 를 분석기마다 추가해 **severity·summary·threat_category·
full details(rule_id·recommendation·location)·mcp_taxonomy 를 전부 보존**하고,
**`--raw` 에 모든 finding 이 자동으로 실리게** 한다(기존 집계 필드는 하위호환 유지).

⚠️ **이것이 우리 로드맵을 바꾼다.** 이 PR 이 머지되면 `docs/research/2026-08-24-scanner-module-call-poc.md`
§4 의 **안 B(모듈 직접 호출 전환)가 통째로 불필요**해진다 — CLI 만으로 rule_id 를 받는다.
지금 안 B 에 투자하면 그 투자는 이 PR 하나로 무의미해질 수 있다.

## 로컬 백업 패치

| | |
|---|---|
| 파일 | `0001-preserve-tool-data-for-readiness.patch` |
| 대상 | `mcpscanner/core/scanner.py` (2곳) |
| 성격 | **PR 제출용 아님** — #228 이 오래 정체될 때 로컬에 직접 적용하기 위한 백업 |
| 검증 | `patch -p1` dry-run 이 설치본 4.8.3 과 상류 main 양쪽에 exit 0 (2026-08-26) |

우리 패치는 프롬프트 경로(`prompt_data`)의 같은 패턴도 함께 고친다 — **다만 그쪽은 피해를
실증하지 못했다**(그 경로에서 readiness 호출부를 찾지 못했다). #228 이 그 경로까지 다루는지는
확인하지 않았다.

### red → green 재현

```bash
mkdir -p ~/.cache/mcp-disclosure-scanner && cd ~/.cache/mcp-disclosure-scanner
uv venv --python 3.12 && uv pip install --python .venv/bin/python cisco-ai-mcp-scanner
# fixture 를 가리키는 config 를 만든 뒤:
#   {"mcpServers":{"f":{"command":"node","args":["<repo>/fixtures/servers/readiness-gaps-stdio-server.js"]}}}

# RED — 패치 전
python docs/research/scripts/probe-scanner-module.py /tmp/probe.json --combo
#   → READINESS 단독에만 있는 규칙 : ['HEUR-017', 'HEUR-019']
#     YARA 를 켜야 생기는 규칙     : ['HEUR-009']

patch -p1 -d "$(python -c 'import mcpscanner,os;print(os.path.dirname(os.path.dirname(mcpscanner.__file__)))')" \
  < upstream/0001-preserve-tool-data-for-readiness.patch

# GREEN — 패치 후
python docs/research/scripts/probe-scanner-module.py /tmp/probe.json --combo
#   → 양쪽 다 (없음)
```

**실측(2026-08-26)**: 패치 후 두 조합의 rule_id 집합이 완전히 일치했다 —
`HEUR-001×3, HEUR-003×3, HEUR-006×3, HEUR-013×3, HEUR-014×3, HEUR-015×3, HEUR-017×2, HEUR-018×1, HEUR-019×1`.

## 추적 — 상태 확인 명령

```bash
gh pr view 228 --repo cisco-ai-defense/mcp-scanner --json state,mergeable,updatedAt
gh pr view 206 --repo cisco-ai-defense/mcp-scanner --json state,mergeable,updatedAt
```

**둘 중 무엇이 머지되면 우리가 무엇을 하는가**

| 머지된 것 | 우리 조치 |
|---|---|
| #228 | `SCANNER_PASSES` 분리 실행 폐기 → 스캔 시간 +95% 회수(`src/runner.ts` 폐기조건 ①) |
| #206 | 안 B(모듈 전환) 폐기 → CLI 만으로 rule_id 확보, 막힌 3축이 열린다 |
| 둘 다 | 위 둘 다. 그러면 우리가 이 문제로 들인 코드가 전부 사라지고 CLI 경로가 정상이 된다 |

⚠️ **둘 다 몇 주~두 달 정체 중이다.** 언제 머지될지 우리가 통제할 수 없으므로,
"곧 고쳐질 테니 기다리자"는 계획을 세우지 않는다. 지금 우리 코드는 그 PR 들과 무관하게 동작한다.

## 우리가 상류에 남긴 것

**#228 에 독립 재현 결과를 코멘트했다**(2026-08-26, 사람 승인 후 게시).
→ https://github.com/cisco-ai-defense/mcp-scanner/pull/228#issuecomment-5423957234

무엇을 보탰나 — #227 이 안 다룬 **거짓 음성** 축이다.

- #227: HEUR-009 거짓 양성 + HEUR-012 왜곡
- 우리: 거기에 더해 **HEUR-017·019 가 통째로 사라진다**(둘 다 `description` 을 읽는다)
- **총 finding 수는 22 로 양쪽이 같다** — 하나 들어오고 둘 나가니 집계만 봐서는 안 보인다.
  이 버그가 오래 안 잡힌 이유의 일부일 수 있다는 점을 적었다.
- 왜 거짓 음성이 더 무거운가: 헛나온 HEUR-009 는 운영자가 무시하는 법을 배우면 되는 소음이지만,
  빠진 HEUR-019 는 **인증 문서화 없이 외부 API 를 부르는 도구가 깨끗하다고 보고되는 것**이다.
- 경쟁 PR 을 내지 않는다는 것과, 필요하면 fixture 서버를 테스트 스위트에 내주겠다는 것도 밝혔다.

⚠️ 코멘트는 **관측 보고이지 머지 요청이 아니다.** 답이 없어도 재촉하지 않는다.
