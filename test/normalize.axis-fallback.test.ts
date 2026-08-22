// Task 13 — assignAxis 3단 폴백 (taxonomy → signal_map → null, 개정안 #01)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import { assignAxis } from '../src/normalize.js';
import { loadAxisTable } from '../src/ontology.js';
import type { AxisTable } from '../src/ontology.js';

const AXIS_TABLE = loadAxisTable(yaml.load(readFileSync('ontology.yaml', 'utf8')));

test('signal_map 매칭 — yara CREDENTIAL HARVESTING → secret_exposure', () => {
  assert.equal(assignAxis({ analyzer: 'yara_analyzer', threatName: 'CREDENTIAL HARVESTING' }, AXIS_TABLE), 'secret_exposure');
});

test("'*' 매칭 — readiness 는 threat_name 과 무관하게 operational_reliability", () => {
  assert.equal(assignAxis({ analyzer: 'readiness_analyzer', threatName: 'unknown' }, AXIS_TABLE), 'operational_reliability');
  assert.equal(assignAxis({ analyzer: 'readiness_analyzer' }, AXIS_TABLE), 'operational_reliability');
});

test('taxonomy 매칭 — AISubtech-9.1.1 → malicious_pattern', () => {
  assert.equal(assignAxis({ analyzer: 'yara_analyzer', threatName: 'CODE EXECUTION', taxonomy: 'AISubtech-9.1.1' }, AXIS_TABLE), 'malicious_pattern');
});

test('미매칭 → null(미분류, 버리지 않음)', () => {
  assert.equal(assignAxis({ analyzer: 'unknown_analyzer', threatName: 'NOPE', taxonomy: 'AISubtech-99.9.9' }, AXIS_TABLE), null);
});

test('신호원이 0인 축(unreachable_in_v0)에는 어떤 입력도 배정되지 않는다', () => {
  const unreachable = Object.entries(AXIS_TABLE)
    .filter(([, v]) => v.signal_status === 'unreachable_in_v0')
    .map(([k]) => k);
  for (const analyzer of ['yara_analyzer', 'readiness_analyzer', 'promptdefense_analyzer', 'vulnerable_package_analyzer']) {
    for (const threatName of ['unknown', 'CREDENTIAL HARVESTING', 'DATA_LEAKAGE', 'HEUR-015']) {
      const axis = assignAxis({ analyzer, threatName }, AXIS_TABLE);
      assert.ok(!unreachable.includes(axis as string), `${analyzer}/${threatName} 가 신호원 0인 축(${axis})에 배정됐다`);
    }
  }
});

// negative fixture 강화(codex 테스트보강 반영) — "무관한 신호"만으로는 부족하다.
// **실재하는** Cisco threat_name 이 엉뚱한 축으로 새지 않는지 직접 확인한다.
test('실제 threat_name(SYSTEM MANIPULATION)이 malicious_pattern 외 축으로 새지 않는다', () => {
  const axis = assignAxis({ analyzer: 'yara_analyzer', threatName: 'SYSTEM MANIPULATION' }, AXIS_TABLE);
  assert.equal(axis, 'malicious_pattern');
  assert.notEqual(axis, 'prompt_injection_defense');
  assert.notEqual(axis, 'secret_exposure');
});

// C-3 codex 반영 — taxonomy 매칭과 signal_map 매칭이 서로 다른 축을 가리키는 입력을 인위적으로
// 구성해, "충돌 시 taxonomy 가 이긴다"는 §5.3 설계 결정을 우연이 아니라 테스트로 고정한다.
test('taxonomy 매칭이 signal_map 매칭보다 우선한다(충돌 시 의도된 승자, §5.3)', () => {
  const conflicted = structuredClone(AXIS_TABLE) as AxisTable;
  // ⚠️ 충돌 fixture 로는 **아무 축도 소유하지 않은** taxonomy 를 써야 한다.
  // AISubtech-1.1.1 은 이미 prompt_injection_defense 소유라, 선언 순서상 그쪽이 먼저 이겨서
  // 이 테스트가 검증하려는 것과 다른 경로를 타게 된다(실제로 그렇게 한 번 틀렸다).
  conflicted.malicious_pattern.accepts_taxonomy = ['AISubtech-4.1.1'];
  const result = assignAxis({ analyzer: 'yara_analyzer', threatName: 'CREDENTIAL HARVESTING', taxonomy: 'AISubtech-4.1.1' }, conflicted);
  assert.equal(result, 'malicious_pattern', 'taxonomy 매칭이 signal_map 매칭보다 먼저 확인되어야 한다');
});

// 개정안 #01 §5.3 — promptdefense 는 "방어 결여" 보고이지 위협 탐지가 아니다. taxonomy 를
// 따라가면 DATA_LEAKAGE 방어결여가 secret_exposure(=실제 시크릿 노출)로 새어, 소견서가
// "시크릿이 노출됐다"고 잘못 말한다. 이 누수를 테스트로 고정해 막는다.
test('promptdefense 는 taxonomy 매칭을 건너뛰고 항상 prompt_injection_defense 로 간다', () => {
  const axis = assignAxis(
    { analyzer: 'promptdefense_analyzer', threatName: 'DATA_LEAKAGE', taxonomy: 'AISubtech-8.2.3' },
    AXIS_TABLE,
  );
  assert.equal(axis, 'prompt_injection_defense', 'AISubtech-8.2.3 은 secret_exposure 소유지만 promptdefense 에는 적용하지 않는다');
});

test('면제는 promptdefense 에만 적용된다 — 다른 분석기는 taxonomy 경로가 살아 있다', () => {
  assert.equal(assignAxis({ analyzer: 'some_other_analyzer', taxonomy: 'AISubtech-8.2.3' }, AXIS_TABLE), 'secret_exposure');
});

test('threatName 이 없으면 목록형 signal_map 은 매칭되지 않는다(추정 금지)', () => {
  assert.equal(assignAxis({ analyzer: 'yara_analyzer' }, AXIS_TABLE), null, 'yara 는 목록형이라 threat_name 없이는 축을 정할 수 없다');
});
