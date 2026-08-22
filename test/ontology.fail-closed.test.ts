// Task 10 — loadAxisTable fail-closed 검증 (C-3 codex + 개정안 #01)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import { loadAxisTable, OntologyError } from '../src/ontology.js';

const parse = () => yaml.load(readFileSync('ontology.yaml', 'utf8')) as any;

test('15축 중 1축(dpa) 제거 → throw', () => {
  const p = parse();
  delete p.axes.dpa;
  assert.throws(() => loadAxisTable(p), OntologyError);
});

test('coverage 값 불량 → throw', () => {
  const p = parse();
  p.axes.dpa.coverage = 'not_a_real_value';
  assert.throws(() => loadAxisTable(p), OntologyError);
});

test('claim_type 값 불량 → throw', () => {
  const p = parse();
  p.axes.dpa.claim_type = 'vibes';
  assert.throws(() => loadAxisTable(p), OntologyError);
});

// C-3 codex(개정안 #01로 키 공간 교체) — 동일 신호가 두 축에 등록되면 어느 축이 이기는지가
// YAML 선언 순서에 암묵적으로 좌우된다. "등록됐다 ≠ 차단한다" 재발 방지로 fail-closed.
test('동일 signal_map 신호가 두 축에 중복 등록되면 throw', () => {
  const p = parse();
  p.axes.malicious_pattern.signal_map.yara_analyzer.push('CREDENTIAL HARVESTING'); // secret_exposure 소유
  assert.throws(() => loadAxisTable(p), OntologyError);
});

test("동일 '*' 배정이 두 축에 중복 등록되면 throw", () => {
  const p = parse();
  p.axes.logging.signal_status = 'reachable';
  delete p.axes.logging.unreachable_reason;
  p.axes.logging.signal_map = { readiness_analyzer: '*' }; // operational_reliability 소유
  assert.throws(() => loadAxisTable(p), OntologyError);
});

test('동일 accepts_taxonomy 항목이 두 축에 중복 등록되면 throw', () => {
  const p = parse();
  p.axes.malicious_pattern.accepts_taxonomy.push('AISubtech-8.2.3'); // secret_exposure 소유
  assert.throws(() => loadAxisTable(p), OntologyError);
});

// --- 개정안 #01 신설 필드: 선언과 내용이 어긋나는 경우를 전부 막는다 ---
test('signal_status 값 불량 → throw', () => {
  const p = parse();
  p.axes.logging.signal_status = 'maybe';
  assert.throws(() => loadAxisTable(p), OntologyError);
});

test('unreachable_in_v0 인데 사유 없음 → throw', () => {
  const p = parse();
  delete p.axes.logging.unreachable_reason;
  assert.throws(() => loadAxisTable(p), OntologyError);
});

test('unreachable_in_v0 인데 사유가 공백 문자열 → throw', () => {
  const p = parse();
  p.axes.logging.unreachable_reason = '   ';
  assert.throws(() => loadAxisTable(p), OntologyError);
});

test('reachable 인데 신호원이 하나도 없음 → throw', () => {
  const p = parse();
  p.axes.secret_exposure.signal_map = {};
  p.axes.secret_exposure.accepts_taxonomy = [];
  assert.throws(() => loadAxisTable(p), OntologyError);
});

test('not_scannable 축에 not_applicable 아닌 signal_status → throw', () => {
  const p = parse();
  p.axes.dpa.signal_status = 'reachable';
  assert.throws(() => loadAxisTable(p), OntologyError);
});

test('기술 축(partial)에 not_applicable → throw', () => {
  const p = parse();
  p.axes.logging.signal_status = 'not_applicable';
  assert.throws(() => loadAxisTable(p), OntologyError);
});

test('not_scannable 축에 evidence_request 누락 → throw', () => {
  const p = parse();
  delete p.axes.dpa.evidence_request;
  assert.throws(() => loadAxisTable(p), OntologyError);
});

// 오류 메시지가 "어느 축이 문제인지"를 담아야 사람이 고칠 수 있다.
test('축 누락 에러 메시지에 누락된 축 이름이 들어간다', () => {
  const p = parse();
  delete p.axes.subprocessor;
  assert.throws(() => loadAxisTable(p), (e: unknown) => e instanceof OntologyError && /subprocessor/.test(e.message));
});
