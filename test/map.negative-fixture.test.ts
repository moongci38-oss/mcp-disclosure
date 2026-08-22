// Task 16 — mapFindingsToClaims (FR-03/AC-03e/AC-03j)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import { mapFindingsToClaims } from '../src/map.js';
import { loadAxisTable, ALL_AXES } from '../src/ontology.js';
import { normalize } from '../src/normalize.js';

const AXIS_TABLE = loadAxisTable(yaml.load(readFileSync('ontology.yaml', 'utf8')));
const META = { name: 'cisco-mcp-scanner', version: '4.8.3', ruleset_hash: 'abc', scanned_at: '2026-08-22T00:00:00Z', target_hash: 'def', python_version: '3.12.0' };
const claimsFor = (raw: Parameters<typeof normalize>[0]) =>
  mapFindingsToClaims(normalize(raw, AXIS_TABLE, META).findings, AXIS_TABLE);

test('항상 정확히 15개 클레임(1축당 1개) 생성', () => {
  assert.equal(claimsFor([]).length, ALL_AXES.length);
});

test('축당 정확히 1개 — 중복도 누락도 없다', () => {
  const claims = claimsFor([]);
  assert.deepEqual([...new Set(claims.map(c => c.axis))].sort(), [...ALL_AXES].sort());
});

test('negative fixture — 무관 finding 만 → 무관 축에 기술통제 클레임 미생성(AC-03e)', () => {
  const raw = [{ analyzer: 'unknown_analyzer', threatName: 'NOPE', rule: 'unknown_analyzer:NOPE', target: 'srv-a', taxonomy: 'AISubtech-99.9.9', raw: {} }];
  const { findings } = normalize(raw, AXIS_TABLE, META);
  assert.equal(findings[0].axis, null);
  const c = mapFindingsToClaims(findings, AXIS_TABLE).find(x => x.axis === 'prompt_injection_defense')!;
  assert.equal((c as any).predicate, 'scanner_not_detected');
  assert.deepEqual((c as any).finding_ids, [], '미분류 finding 이 어떤 클레임에도 딸려가면 안 된다');
});

// AC-03j (개정안 #01) — 이 제품이 존재하는 이유가 바로 이 구분이다.
test('신호원 0인 축은 scanner_not_detected 가 아니라 scanner_cannot_detect + 사유(AC-03j)', () => {
  const claims = claimsFor([]);
  const unreachable = Object.entries(AXIS_TABLE)
    .filter(([, v]) => v.signal_status === 'unreachable_in_v0').map(([k]) => k);
  assert.equal(unreachable.length, 5, 'partial 5축이 대상이다');
  for (const axis of unreachable) {
    const c = claims.find(x => x.axis === axis)! as any;
    assert.equal(c.predicate, 'scanner_cannot_detect', `${axis}: "못 본 것"을 "깨끗한 것"으로 보고하면 안 된다`);
    assert.ok(c.unreachable_reason?.trim(), `${axis}: 사유 없이 못 본다고만 하면 읽는 쪽이 확인할 방법이 없다`);
  }
});

test('신호가 오는 기술축은 finding 유무로 detected/not_detected 가 갈린다', () => {
  const found = claimsFor([{ analyzer: 'yara_analyzer', threatName: 'CREDENTIAL HARVESTING', rule: 'yara_analyzer:CREDENTIAL HARVESTING', target: 'srv-a', raw: {} }]);
  const se = found.find(c => c.axis === 'secret_exposure')! as any;
  assert.equal(se.predicate, 'scanner_detected');
  assert.equal(se.finding_ids.length, 1);
  const mp = found.find(c => c.axis === 'malicious_pattern')! as any;
  assert.equal(mp.predicate, 'scanner_not_detected', '검사는 했고 못 찾았다 — cannot_detect 가 아니다');
});

test('not_scannable 5축은 policy_proof 클레임 + evidence_request', () => {
  const claims = claimsFor([]);
  const policy = claims.filter(c => c.type === 'policy_proof');
  assert.equal(policy.length, 5);
  assert.ok(policy.every(c => (c as any).evidence_request?.trim()), '증빙 요청문이 없으면 상대가 무엇을 보내야 할지 모른다');
  assert.ok(policy.every(c => !('predicate' in c)), '정책 축에는 스캐너 술어가 붙지 않는다');
});

test('finding_ids 는 그 축에 배정된 finding 만 담는다(오매핑 없음)', () => {
  const claims = claimsFor([
    { analyzer: 'yara_analyzer', threatName: 'CREDENTIAL HARVESTING', rule: 'a', target: 's', raw: {} },
    { analyzer: 'readiness_analyzer', threatName: 'unknown', rule: 'b', target: 's', raw: {} },
  ]);
  const se = claims.find(c => c.axis === 'secret_exposure')! as any;
  const or = claims.find(c => c.axis === 'operational_reliability')! as any;
  assert.equal(se.finding_ids.length, 1);
  assert.equal(or.finding_ids.length, 1);
  assert.notEqual(se.finding_ids[0], or.finding_ids[0]);
});
