import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkScannerVersion } from '../src/version-check.js';

test('mcp-scanner 0.x는 지원 범위 내', () => {
  assert.equal(checkScannerVersion('0.4.2').withinRange, true);
});
test('mcp-scanner 2.x는 지원 범위 밖 → 경고 텍스트 존재', () => {
  const r = checkScannerVersion('2.0.0');
  assert.equal(r.withinRange, false);
  assert.ok(r.warning && r.warning.length > 0);
});
