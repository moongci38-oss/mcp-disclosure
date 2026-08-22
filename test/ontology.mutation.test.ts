// Task 17 — 온톨로지 매핑 mutation test (AC-03g, 판별력 실증)
//
// 이 파일의 목적은 "매핑이 맞는지"가 아니라 **"매핑 검사에 판별력이 있는지"** 다.
// 온톨로지를 일부러 뒤집었는데도 결과가 그대로면, 그 매핑 검사는 아무것도 검증하지 않는 것이다.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import { loadAxisTable } from '../src/ontology.js';
import { assignAxis } from '../src/normalize.js';
import { mapFindingsToClaims } from '../src/map.js';
import { normalize } from '../src/normalize.js';

const parse = () => yaml.load(readFileSync('ontology.yaml', 'utf8')) as any;

test('mutation — yara CREDENTIAL HARVESTING 신호 제거 시 axis:null 로 전환되어야 함', () => {
  const base = parse();
  const input = { analyzer: 'yara_analyzer', threatName: 'CREDENTIAL HARVESTING' };
  assert.equal(assignAxis(input, loadAxisTable(base)), 'secret_exposure');

  const mutated = structuredClone(base);
  mutated.axes.secret_exposure.signal_map.yara_analyzer = ['__NEVER_MATCHES__'];
  assert.equal(assignAxis(input, loadAxisTable(mutated)), null,
    '뒤집힌 온톨로지에서 매핑이 실패하지 않으면 이 매핑 검사는 판별력이 없다(AC-03g)');
});

test('mutation — yara CODE EXECUTION 신호 제거 시 axis:null 로 전환되어야 함', () => {
  const base = parse();
  const input = { analyzer: 'yara_analyzer', threatName: 'CODE EXECUTION' };
  assert.equal(assignAxis(input, loadAxisTable(base)), 'malicious_pattern');

  const mutated = structuredClone(base);
  mutated.axes.malicious_pattern.signal_map.yara_analyzer =
    mutated.axes.malicious_pattern.signal_map.yara_analyzer.filter((n: string) => n !== 'CODE EXECUTION');
  assert.equal(assignAxis(input, loadAxisTable(mutated)), null,
    'CODE EXECUTION 매핑 삭제가 무해하다면 이 검사는 무용하다');
});

// 개정안 #01 §5.3 — promptdefense taxonomy 면제가 실제로 동작 중인지 확인한다.
// 면제가 사라지면 DATA_LEAKAGE(방어 결여)가 secret_exposure(실제 시크릿 노출)로 새어,
// 소견서가 "시크릿이 노출됐다"고 잘못 말하게 된다.
test('mutation — promptdefense taxonomy 면제가 실제로 무언가를 막고 있는지 확인', () => {
  const table = loadAxisTable(parse());
  const leaky = { analyzer: 'promptdefense_analyzer', threatName: 'DATA_LEAKAGE', taxonomy: 'AISubtech-8.2.3' };
  assert.equal(assignAxis(leaky, table), 'prompt_injection_defense', '면제가 동작 중이면 방어결여 축에 남는다');

  // 면제 목록에 없는 분석기로 같은 입력을 주면 taxonomy 경로가 살아나 secret_exposure 로 간다.
  // 이 누수가 재현되지 않는다면 면제 규칙은 아무것도 막고 있지 않은 것이다.
  assert.equal(assignAxis({ ...leaky, analyzer: 'some_other_analyzer' }, table), 'secret_exposure');
});

test('mutation — taxonomy 우선순위가 무너지면(signal_map 매칭만으로 후퇴) 이 검사가 잡아야 함', () => {
  const table = structuredClone(loadAxisTable(parse()));
  // 아무 축도 소유하지 않은 taxonomy 를 쓴다(AISubtech-1.1.1 은 prompt_injection_defense 소유).
  table.malicious_pattern.accepts_taxonomy = ['AISubtech-4.1.1'];
  const result = assignAxis(
    { analyzer: 'yara_analyzer', threatName: 'CREDENTIAL HARVESTING', taxonomy: 'AISubtech-4.1.1' }, table);
  assert.equal(result, 'malicious_pattern', 'taxonomy 매칭이 signal_map 매칭보다 먼저 확인되어야 한다(§5.3)');
});

// AC-03j 판별력 — signal_status 를 뒤집으면 술어가 바뀌어야 한다.
test('mutation — logging 을 reachable 로 뒤집으면 술어가 cannot_detect → not_detected 로 바뀐다', () => {
  const base = parse();
  const META = { name: 's', version: 'v', ruleset_hash: 'h', scanned_at: '2026-08-22T00:00:00Z', target_hash: 't', python_version: '3.12.0' };
  const predicateOf = (parsed: any) => {
    const table = loadAxisTable(parsed);
    const { findings } = normalize([], table, META);
    return (mapFindingsToClaims(findings, table, { attempted: 1, scanned: 1 }).find(c => c.axis === 'logging') as any).predicate;
  };
  assert.equal(predicateOf(base), 'scanner_cannot_detect');

  const mutated = structuredClone(base);
  mutated.axes.logging.signal_status = 'reachable';
  delete mutated.axes.logging.unreachable_reason;
  mutated.axes.logging.signal_map = { some_future_analyzer: ['SOMETHING'] };
  assert.equal(predicateOf(mutated), 'scanner_not_detected',
    'signal_status 를 뒤집었는데 술어가 그대로면, 그 술어는 signal_status 를 실제로 읽고 있지 않은 것이다');
});
