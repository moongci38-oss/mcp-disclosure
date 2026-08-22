import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkScannerVersion, getScannerVersion } from '../src/version-check.js';

test('mcp-scanner 0.x는 지원 범위 내', () => {
  assert.equal(checkScannerVersion('0.4.2').withinRange, true);
});
test('mcp-scanner 2.x는 지원 범위 밖 → 경고 텍스트 존재', () => {
  const r = checkScannerVersion('2.0.0');
  assert.equal(r.withinRange, false);
  assert.ok(r.warning && r.warning.length > 0);
});

// Task 8b 실측(2026-08-22): 실제 mcp-scanner(4.8.3)에는 --version 플래그가 없어
// exit 2(unrecognized arguments)로 거부된다 — getScannerVersion()이 이런 비정상 종료를
// 하드 실패시키지 않고 null로 안전하게 흡수하는지를 바이너리 부재 케이스로 대신 확인한다
// (실제 --version exit 2와 동일한 "status !== 0" 경로를 탄다).
test('getScannerVersion — 바이너리가 --version을 인식하지 못하거나 부재해도 null(하드실패 아님)', () => {
  assert.equal(getScannerVersion('/nonexistent/path/to/mcp-scanner-binary-that-does-not-exist'), null);
});
