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
  mapFindingsToClaims(normalize(raw, AXIS_TABLE, META).findings, AXIS_TABLE, { attempted: 1, scanned: 1 });

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
  const c = mapFindingsToClaims(findings, AXIS_TABLE, { attempted: 1, scanned: 1 }).find(x => x.axis === 'prompt_injection_defense')!;
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

// ============================================================
// 도그푸딩 Task 26 회귀 — "스캔이 아예 안 됐는데 깨끗하다고 말하는" 버그
// 실제로 있었던 버그다: 스캐너 바이너리가 없어 0건 스캔됐는데 소견서는 기술축 5개에
// "검사했지만 못 찾았다"를 찍었다. 이 제품이 존재하는 이유와 정확히 반대되는 출력이다.
// ============================================================
test('한 건도 스캔되지 않으면 기술축은 not_detected 가 아니라 cannot_detect 다', () => {
  const claims = mapFindingsToClaims([], AXIS_TABLE, { attempted: 1, scanned: 0 });
  const technical = claims.filter(c => c.type === 'technical_control') as any[];
  assert.equal(technical.length, 10);
  assert.ok(technical.every(c => c.predicate === 'scanner_cannot_detect'),
    '스캔이 일어나지 않았는데 "검사했고 못 찾았다"고 말하면 거짓 진술이다');
  assert.ok(technical.every(c => c.unreachable_reason?.trim()), '왜 확인 못 했는지가 반드시 있어야 한다');
});

test('스캔 실패 사유에 시도 대상 수와 다음 확인 지점이 들어간다', () => {
  const c = mapFindingsToClaims([], AXIS_TABLE, { attempted: 3, scanned: 0 })
    .find(x => x.axis === 'secret_exposure') as any;
  assert.match(c.unreachable_reason, /3 target\(s\)/);
  assert.match(c.unreachable_reason, /Unscanned items/);
});

test('일부라도 스캔됐으면 정상 판정으로 돌아간다(과잉 방어 금지)', () => {
  const claims = mapFindingsToClaims([], AXIS_TABLE, { attempted: 2, scanned: 1 });
  const se = claims.find(c => c.axis === 'secret_exposure') as any;
  assert.equal(se.predicate, 'scanner_not_detected', '1건이라도 스캔했으면 그 결과는 유효하다');
});

test('attempted 0(대상 없음)은 정상 경로로 둔다 — CLI 가 그 전에 exit 1 한다', () => {
  const se = mapFindingsToClaims([], AXIS_TABLE, { attempted: 0, scanned: 0 })
    .find(c => c.axis === 'secret_exposure') as any;
  assert.equal(se.predicate, 'scanner_not_detected');
});
