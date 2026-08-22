import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseScannerRawEnvelope } from '../src/scanner-envelope.js';

// Task 8b 실측(2026-08-22)으로 fixture가 실제 cisco-ai-mcp-scanner 4.8.3 raw 출력 발췌본으로
// 교체됐다 — scan_results[]는 "도구 1개당 1개 원소"이고, findings는 배열이 아니라 분석기명을
// 키로 하는 롤업 요약 객체다(rule/rule_id 필드 없음). 상세 근거는 src/scanner-envelope.ts 상단
// 주석 참조.
const FIXTURE = JSON.parse(readFileSync('fixtures/mcp-scanner-0.1.0/raw-envelope.json', 'utf8'));

test('실측 raw 봉투 fixture → scan_results 내 non-SAFE 분석기 결과 전부 추출(AC-01h, 실측 스키마)', () => {
  // 이 fixture의 2개 tool 항목은 각각 readiness_analyzer만 total_findings>0(HIGH)이고
  // yara/vulnerable_package는 SAFE(0건)다 — 그러므로 기대 건수는 2(entry당 1개).
  const result = parseScannerRawEnvelope(FIXTURE, 'fallback-target');
  assert.equal(result.length, 2, '이 fixture는 findings가 0건이면 안 된다 — 빈 소견서 회귀 방지가 이 테스트의 목적');
  assert.ok(result.every(f => typeof f.rule === 'string' && f.rule.length > 0));
  assert.ok(result.every(f => f.rule.startsWith('readiness_analyzer')));
  assert.deepEqual(result.map(f => f.target), ['echo', 'get-annotated-message']);
});

test('SAFE(total_findings=0) 분석기 결과는 finding으로 나오지 않는다', () => {
  const result = parseScannerRawEnvelope(FIXTURE, 'fallback-target');
  assert.ok(!result.some(f => f.rule.startsWith('yara_analyzer')));
  assert.ok(!result.some(f => f.rule.startsWith('vulnerable_package_analyzer')));
});

test('scan_results 배열이 없는 봉투 → 빈 배열(조용히 죽지 않음, fail-open)', () => {
  assert.deepEqual(parseScannerRawEnvelope({ server_url: 'x' }, 'target-x'), []);
});

test('scan_results 원소에 findings가 없으면 그 원소는 기여분 0건', () => {
  const partial = { scan_results: [{ tool_name: 'a' }, { tool_name: 'b', findings: { yara_analyzer: { severity: 'HIGH', total_findings: 1, threat_names: ['bad'] } } }] };
  const result = parseScannerRawEnvelope(partial, 'fallback');
  assert.equal(result.length, 1);
  assert.equal(result[0].target, 'b');
  assert.equal(result[0].rule, 'yara_analyzer:bad');
});

test('rule 필드는 원본에 없다 — analyzer명+threat_names로 최선 근사 식별자를 합성한다', () => {
  const synthetic = { scan_results: [{ tool_name: 'x', findings: { readiness_analyzer: { severity: 'HIGH', total_findings: 3, threat_names: [] } } }] };
  const result = parseScannerRawEnvelope(synthetic, 'fallback');
  assert.equal(result[0].rule, 'readiness_analyzer', 'threat_names가 비어 있으면 analyzer명 단독을 rule로 쓴다');
});
