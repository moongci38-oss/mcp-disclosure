import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkScannerVersion, getScannerVersion, TESTED_SCANNER_VERSIONS } from '../src/version-check.js';

// 2026-08-22 Spec 감사: 구 구현은 "0.x = 지원 범위"였고, 그래서 우리가 전부 검증한 유일한
// 버전(4.8.3)을 "범위 밖"이라고 경고했다 — 자기가 지원하는 버전을 지원 안 한다고 말한 셈이다.
// 이제 범위가 아니라 **검증한 버전 목록**을 쓴다.
test('실제로 검증한 버전(4.8.3)은 경고하지 않는다', () => {
  const r = checkScannerVersion('4.8.3');
  assert.equal(r.tested, true);
  assert.equal(r.warning, undefined);
});

test('검증하지 않은 버전은 경고한다 — 위/아래 방향 모두', () => {
  for (const v of ['0.4.2', '4.8.2', '4.9.0', '5.0.0']) {
    const r = checkScannerVersion(v);
    assert.equal(r.tested, false, `${v} 를 검증했다고 주장하면 안 된다`);
    assert.match(r.warning!, /has not been tested/);
    assert.match(r.warning!, /4\.8\.3/, '무엇으로 검증했는지를 알려줘야 사용자가 판단한다');
  }
});

// 선언(package.json)과 코드가 갈라지는 것을 막는다 — 갈라지면 README 를 읽은 사용자와
// 실제 동작이 어긋난다.
test('package.json 의 testedScannerVersions 와 코드 상수가 일치한다', () => {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
  assert.deepEqual(pkg.agenttrust.testedScannerVersions, [...TESTED_SCANNER_VERSIONS]);
});

// 근거 없는 범위 선언을 막는 가드 — 목록이 늘어나려면 그 버전을 실제로 돌려봤어야 한다.
test('검증 목록은 실측한 것만 담는다(현재 1개)', () => {
  assert.equal(TESTED_SCANNER_VERSIONS.length, 1,
    '버전을 추가했다면 docs/scanner-exit-codes.md 에 그 버전의 실측 기록이 함께 있어야 한다');
});

// Task 8b 실측(2026-08-22): 실제 mcp-scanner(4.8.3)에는 --version 플래그가 없어
// exit 2(unrecognized arguments)로 거부된다 — getScannerVersion()이 이런 비정상 종료를
// 하드 실패시키지 않고 null로 안전하게 흡수하는지를 바이너리 부재 케이스로 대신 확인한다
// (실제 --version exit 2와 동일한 "status !== 0" 경로를 탄다).
test('getScannerVersion — 바이너리가 --version을 인식하지 못하거나 부재해도 null(하드실패 아님)', () => {
  assert.equal(getScannerVersion('/nonexistent/path/to/mcp-scanner-binary-that-does-not-exist'), null);
});
