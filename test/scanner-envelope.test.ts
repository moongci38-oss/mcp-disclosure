import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseScannerRawEnvelope } from '../src/scanner-envelope.js';

const FIXTURE = JSON.parse(readFileSync('fixtures/mcp-scanner-0.1.0/raw-envelope.json', 'utf8'));

test('실측 raw 봉투 fixture → scan_results 내 findings 전부 추출(AC-01h)', () => {
  const expectedCount = FIXTURE.scan_results.flatMap((r: any) => r.findings ?? []).length;
  const result = parseScannerRawEnvelope(FIXTURE, 'fallback-target');
  assert.equal(result.length, expectedCount);
  assert.ok(result.length > 0, '이 fixture는 findings가 0건이면 안 된다 — 빈 소견서 회귀 방지가 이 테스트의 목적');
  assert.ok(result.every(f => typeof f.rule === 'string' && f.rule.length > 0));
});

test('scan_results 배열이 없는 봉투 → 빈 배열(조용히 죽지 않음, fail-open)', () => {
  assert.deepEqual(parseScannerRawEnvelope({ server_url: 'x' }, 'target-x'), []);
});

test('scan_results 원소에 findings가 없으면 그 원소만 건너뛴다', () => {
  const partial = { scan_results: [{ target: 'a' }, { target: 'b', findings: [{ rule: 'r1' }] }] };
  const result = parseScannerRawEnvelope(partial, 'fallback');
  assert.equal(result.length, 1);
  assert.equal(result[0].target, 'b');
});
