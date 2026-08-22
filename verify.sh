#!/bin/bash
# AgentTrust — 로컬 검증 게이트.
#
# ⚠️ **이건 CI 의 대용품이지 CI 가 아니다.** 2026-08-22 기준 이 저장소의 GitHub Actions 는
#    계정 결제 문제로 **잡이 시작조차 되지 않는다**("The job was not started because recent
#    account payments have failed or your spending limit needs to be increased").
#    그래서 지금 이 프로젝트의 유일한 검증 경로는 **사람이 이 스크립트를 돌리는 것**뿐이고,
#    그 말은 곧 "안 돌리면 아무도 안 잡는다"는 뜻이다. Actions 가 살아나면 ci.yml 이 대신한다.
#
# 쓰는 법:  bash verify.sh          (push 전에 돌린다)
set -euo pipefail

echo "▶ 1/3 빌드 + 테스트"
npm run build
npm test

echo
echo "▶ 2/3 배포 산출물 — 패키지에 실행에 필요한 것이 들어가는가"
# dist/ 가 .gitignore 라 npm 패키지에서 통째로 빠졌던 사고(2026-08-22)의 재발 방지.
# npm test 안에도 같은 검사가 있으나, 여기서는 **실제 tarball 을 만들어 설치까지** 해 본다.
TARBALL_DIR=$(mktemp -d)
npm pack --pack-destination "$TARBALL_DIR" >/dev/null
WORK=$(mktemp -d)
(
  cd "$WORK"
  npm init -y >/dev/null 2>&1
  npm install "$TARBALL_DIR"/agenttrust-*.tgz >/dev/null 2>&1
  TARGET=$(mktemp -d)
  printf '{"mcpServers":{"demo":{"command":"node","args":["x.js"]}}}' > "$TARGET/.mcp.json"
  ./node_modules/.bin/agenttrust scan --path "$TARGET" >/dev/null
  test -f "$TARGET/agenttrust-findings.md"
  test -f "$TARGET/agenttrust-findings.json"
)
echo "  설치본 실행 OK — 소견서 2종 생성 확인"

echo
echo "▶ 3/3 역변조 잔재 확인"
# 판별력 실증용 임시 변조가 남아 있으면 커밋되면 안 된다(model-routing.md §역변조 잔재 grep).
if grep -rnE 'TEMP-MUTATION-[0-9]{8}-' src/ test/ 2>/dev/null; then
  echo "  ⛔ 역변조 잔재가 남아 있다 — 원복하고 다시 돌려라."
  exit 1
fi
echo "  잔재 0건"

echo
echo "✅ 전부 통과 — push 해도 된다(단, 이건 사람이 돌린 로컬 검증이다)."
