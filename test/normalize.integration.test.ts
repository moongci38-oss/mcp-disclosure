// Task 15 — normalize() 통합 + computeUnmatchedSignals
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import { normalize } from '../src/normalize.js';
import { parseScannerRawEnvelope } from '../src/scanner-envelope.js';
import { loadAxisTable } from '../src/ontology.js';

const AXIS_TABLE = loadAxisTable(yaml.load(readFileSync('ontology.yaml', 'utf8')));
const META = { name: 'cisco-mcp-scanner', version: '4.8.3', ruleset_hash: 'abc123', scanned_at: '2026-08-22T00:00:00Z', target_hash: 'def456', python_version: '3.12.0' };
const yara = (threatName: string, extra: Record<string, unknown> = {}) => ({
  analyzer: 'yara_analyzer', threatName, rule: `yara_analyzer:${threatName}`, target: 'srv-a', raw: extra,
});

test('raw finding → Finding[] 완전 변환(id/axis/raw 전부 채워짐)', () => {
  const fakeToken = 'sk-' + 'SECRETVALUE1234567890ABCDE'; // 테스트 전용 가짜 값(실제 키 아님)
  const { findings } = normalize([yara('CREDENTIAL HARVESTING', { matched_string: fakeToken })], AXIS_TABLE, META);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].axis, 'secret_exposure');
  assert.equal(findings[0].raw.fields.matched_string, '***REDACTED***');
  assert.equal(findings[0].id.length, 16);
  assert.equal(findings[0].scanner_meta.version, '4.8.3');
});

test('축 미매칭 finding 은 버리지 않고 axis:null 로 보존한다(AC-03i)', () => {
  const { findings } = normalize(
    [{ analyzer: 'unknown_analyzer', threatName: 'NOPE', rule: 'unknown_analyzer:NOPE', target: 'srv-a', raw: {} }],
    AXIS_TABLE, META);
  assert.equal(findings.length, 1, '분류를 못 했다고 버리면 "못 찾은 것"과 구분이 사라진다');
  assert.equal(findings[0].axis, null);
});

test('severity 가 없으면 info 로 기본값 처리', () => {
  const { findings } = normalize([yara('CODE EXECUTION')], AXIS_TABLE, META);
  assert.equal(findings[0].severity, 'info');
});

// A-4 codex 반영 — 종전엔 unmatchedSignals 가 하드코딩된 [] 였다(입력이 뭐든 항상 통과).
test('signal_map 신호 중 이번 스캔에서 0건 매칭된 것이 unmatchedSignals 에 노출된다', () => {
  const { unmatchedSignals } = normalize(
    [{ analyzer: 'unknown_analyzer', threatName: 'NOPE', rule: 'x', target: 'srv-a', raw: {} }], AXIS_TABLE, META);
  assert.ok(unmatchedSignals.length > 0);
  assert.ok(unmatchedSignals.some(g => g.includes('secret_exposure')));
});

test('실제로 매칭된 신호는 unmatchedSignals 에서 빠진다(hit-count 가 진짜 동작함을 확인)', () => {
  const { unmatchedSignals } = normalize([yara('CREDENTIAL HARVESTING')], AXIS_TABLE, META);
  assert.ok(!unmatchedSignals.some(g => g.includes('secret_exposure') && g.includes('CREDENTIAL HARVESTING')));
});

// '*' 배정은 "그 분석기가 이번에 아무것도 안 냈다"는 정상 결과라 오타 후보가 아니다.
test("'*' 배정은 unmatchedSignals 집계 대상이 아니다", () => {
  const { unmatchedSignals } = normalize([yara('CREDENTIAL HARVESTING')], AXIS_TABLE, META);
  assert.ok(!unmatchedSignals.some(g => g.includes('readiness_analyzer')), 'readiness 는 "*" 배정이라 목록에 없어야 한다');
  assert.ok(!unmatchedSignals.some(g => g.includes('promptdefense_analyzer')));
});

test('accepts_taxonomy 항목도 0건이면 노출된다(오타 taxonomy ID 탐지)', () => {
  const { unmatchedSignals } = normalize([yara('CREDENTIAL HARVESTING')], AXIS_TABLE, META);
  assert.ok(unmatchedSignals.some(g => g.includes('accepts_taxonomy')));
});

// --- 실측 fixture 전 구간 통합 (파서 → normalize) ---
test('실측 봉투 fixture 를 파서에 통과시킨 결과가 정상 분류된다(엔드투엔드)', () => {
  const envelope = JSON.parse(readFileSync('fixtures/mcp-scanner-4.8.3/raw-envelope-yara-fired.json', 'utf8'));
  const { findings } = normalize(parseScannerRawEnvelope(envelope, 'fallback'), AXIS_TABLE, META);
  assert.equal(findings.length, 17);
  const byAxis = findings.reduce<Record<string, number>>((a, f) => {
    const k = f.axis ?? 'null'; a[k] = (a[k] ?? 0) + 1; return a;
  }, {});
  assert.equal(byAxis.prompt_injection_defense, 13, 'promptdefense 12 + yara PROMPT INJECTION 1');
  assert.equal(byAxis.secret_exposure, 1);
  assert.equal(byAxis.malicious_pattern, 2, 'CODE EXECUTION + SYSTEM MANIPULATION');
  assert.equal(byAxis.operational_reliability, 1);
  assert.equal(byAxis.null, undefined, '실측 fixture 는 전건 분류돼야 한다 — 미분류가 있으면 온톨로지에 구멍이 있다');
});

test('실측 fixture 에서 신호원 0인 축에는 단 1건도 배정되지 않는다', () => {
  const envelope = JSON.parse(readFileSync('fixtures/mcp-scanner-4.8.3/raw-envelope-yara-fired.json', 'utf8'));
  const { findings } = normalize(parseScannerRawEnvelope(envelope, 'fallback'), AXIS_TABLE, META);
  const unreachable = new Set(Object.entries(AXIS_TABLE)
    .filter(([, v]) => v.signal_status !== 'reachable').map(([k]) => k));
  assert.ok(findings.every(f => !unreachable.has(f.axis as string)));
});

// 라이브 스캔 회귀(2026-08-22) — 실제 악성 fixture 서버를 스캔한 원본 봉투다.
// 스캐너 없이도 이 분류가 고정되도록 캡처해 둔다. 특히 sync_profile/yara 가
// threat_names 2개 + taxonomy 1개인 실사례라, taxonomy 를 빌려 쓰던 버그의 회귀를 막는다.
test('라이브 악성 fixture — YARA 3종이 각자 맞는 축으로 간다', () => {
  const envelope = JSON.parse(readFileSync('fixtures/mcp-scanner-4.8.3/raw-envelope-malicious-live.json', 'utf8'));
  const { findings } = normalize(parseScannerRawEnvelope(envelope, 'fallback'), AXIS_TABLE, META);
  const yara = findings.filter(f => f.rule.startsWith('yara_analyzer:'));
  const axisOf = (threat: string) => yara.find(f => f.rule === `yara_analyzer:${threat}`)?.axis;

  assert.equal(axisOf('PROMPT INJECTION'), 'prompt_injection_defense');
  assert.equal(axisOf('CREDENTIAL HARVESTING'), 'secret_exposure');
  assert.equal(axisOf('CODE EXECUTION'), 'malicious_pattern');
  assert.equal(axisOf('DATA EXFILTRATION'), 'malicious_pattern',
    'taxonomy 를 옆 finding 에서 빌려 쓰면 여기가 secret_exposure 로 새어 "데이터 반출"을 "시크릿 노출"로 보고한다');
});

test('라이브 악성 fixture — 미분류 0건(온톨로지에 구멍 없음)', () => {
  const envelope = JSON.parse(readFileSync('fixtures/mcp-scanner-4.8.3/raw-envelope-malicious-live.json', 'utf8'));
  const { findings } = normalize(parseScannerRawEnvelope(envelope, 'fallback'), AXIS_TABLE, META);
  assert.equal(findings.filter(f => f.axis === null).length, 0);
  assert.ok(findings.length >= 40, `라이브 캡처가 비었다(${findings.length}건) — fixture 가 깨졌는지 확인`);
});
