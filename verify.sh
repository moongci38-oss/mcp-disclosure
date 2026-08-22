#!/bin/bash
# AgentTrust — 빌드+테스트 검증 스크립트 (Web/Node.js 템플릿, npm 기반으로 조정)
# lint 스크립트는 package.json에 아직 없다(2026-08-22 기준) — 추가되면 여기에 넣는다.
set -e
npm run build
npm test
