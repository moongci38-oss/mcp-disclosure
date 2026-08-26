#!/usr/bin/env python3
"""mcp-scanner 를 CLI 대신 **Python 모듈로 직접 호출**해 rule id 를 살릴 수 있는지 검증한다.

배경(IMPL-NOTES §4): CLI 는 `report_generator` 가 `details["threat_type"]` 하나만 직렬화해서
HEUR-001~020 rule id 를 통째로 버린다. 그 탓에 우리 15축 중 logging / tool_permission /
auth_oauth 가 v0 에서 "신호 0"이 됐다. 이 스크립트는 그 세 축이 모듈 경로로는 잡히는지 잰다.

쉽게 말하면 **분석기는 답을 알고 있는데 CLI 라는 창구가 그 답을 안 적어 주는 것**이라,
창구를 건너뛰고 분석기에게 직접 물어보는 실험이다.

선행:
  uv venv --python 3.12 && uv pip install cisco-ai-mcp-scanner   # 모듈명은 `mcpscanner`
사용:
  <venv>/bin/python probe-scanner-module.py <mcp-config.json> [--combo]

  --combo 를 주면 분석기 조합별로 돌려 **조합에 따라 결과가 달라지는 상류 버그**를 재현한다
  (§ 아래 KNOWN_UPSTREAM_BUG 참조).
"""
import asyncio
import json
import sys
from collections import Counter

from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum

# API 키 없이 도는 로컬 분석기만 — ADR-001/002(로컬 전용) 준수.
LOCAL_SAFE = [
    AnalyzerEnum.YARA,
    AnalyzerEnum.READINESS,
    AnalyzerEnum.VULNERABLE_PACKAGE,
    AnalyzerEnum.PROMPT_DEFENSE,
]

# 우리 15축 중 v0 에서 막혀 있던 세 축과 대응 규칙.
BLOCKED_AXES = {
    "HEUR-015": "logging",
    "HEUR-018": "tool_permission",
    "HEUR-019": "auth_oauth",
}

KNOWN_UPSTREAM_BUG = """\
⚠️ 상류 버그(mcp-scanner 4.8.3, 2026-08-24 실측)
   scanner.py 의 YARA 파라미터 스캔이 `del tool_data["description"]` 으로 **원본 dict 를 지운다.**
   그 dict 가 뒤이어 readiness 에 `tool_definition` 으로 그대로 넘어가므로,
   **YARA 를 함께 켜면 readiness 가 설명 없는 도구를 보게 된다.**
   결과: HEUR-009("설명 없음")가 모든 도구에 거짓 양성으로 붙고,
         설명 기반 규칙(HEUR-017·019)이 거짓 음성으로 사라진다.
   우리 v0 은 YARA 를 항상 켜므로 **지금 readiness 건수가 이미 왜곡돼 있다.**
"""


async def scan(config_path, analyzers):
    scanner = Scanner(Config())
    results = await scanner.scan_mcp_config_file(config_path, analyzers=analyzers)
    rows = []
    for r in results:
        for f in getattr(r, "findings", []) or []:
            details = getattr(f, "details", None) or {}
            rows.append({
                "tool": getattr(r, "tool_name", "?"),
                "analyzer": getattr(f, "analyzer", "?"),
                "severity": getattr(f, "severity", "?"),
                "rule_id": details.get("rule_id"),
                "summary": (getattr(f, "summary", "") or "")[:90],
            })
    return rows


def report(label, rows):
    with_id = [r for r in rows if r["rule_id"]]
    ids = Counter(r["rule_id"] for r in with_id)
    print(f"\n=== {label}")
    print(f"  finding {len(rows)}건 · rule_id 보유 {len(with_id)}건")
    print(f"  rule_id: {', '.join(f'{k}×{v}' for k, v in sorted(ids.items())) or '(없음)'}")
    for rid, axis in BLOCKED_AXES.items():
        mark = "✅ 발화" if rid in ids else "· 미발화"
        print(f"    {rid} → {axis:16s} {mark}")
    return set(ids)


async def main():
    config_path = sys.argv[1]
    combo = "--combo" in sys.argv

    if not combo:
        rows = await scan(config_path, LOCAL_SAFE)
        report("로컬 안전 분석기 4종", rows)
        print("\n" + KNOWN_UPSTREAM_BUG)
        print("조합별 차이를 직접 보려면 --combo 를 붙여 다시 실행하십시오.")
        return 0

    combos = {
        "READINESS 단독": [AnalyzerEnum.READINESS],
        "READINESS + YARA": [AnalyzerEnum.READINESS, AnalyzerEnum.YARA],
        "로컬 안전 4종 전부": LOCAL_SAFE,
    }
    seen = {}
    for label, analyzers in combos.items():
        seen[label] = report(label, await scan(config_path, analyzers))

    solo, withyara = seen["READINESS 단독"], seen["READINESS + YARA"]
    print("\n--- 조합 대조 ---")
    print(f"  READINESS 단독에만 있는 규칙 : {sorted(solo - withyara) or '(없음)'}")
    print(f"  YARA 를 켜야 생기는 규칙     : {sorted(withyara - solo) or '(없음)'}")
    if solo - withyara:
        print("\n" + KNOWN_UPSTREAM_BUG)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
