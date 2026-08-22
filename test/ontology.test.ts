// Task 9 — ontology.yaml v1 (개정안 #01 반영)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import { loadAxisTable } from '../src/ontology.js';
import { ALL_AXES } from '../src/types.js';

const parse = () => yaml.load(readFileSync('ontology.yaml', 'utf8')) as any;

test('ontology.yaml이 15축을 모두 포함하고 로딩된다', () => {
  const table = loadAxisTable(parse());
  assert.equal(Object.keys(table).length, ALL_AXES.length);
});

// 개정안 #01: 신호가 안 오는 축은 "빈칸"이 아니라 "사유가 적힌 칸"이어야 한다.
// 빈칸은 "검사했는데 깨끗함"으로 오독되지만, 사유가 적힌 칸은 오독되지 않는다.
test('unreachable_in_v0 축은 전부 unreachable_reason 을 갖는다', () => {
  const table = loadAxisTable(parse());
  const bad = Object.entries(table)
    .filter(([, v]) => v.signal_status === 'unreachable_in_v0' && !v.unreachable_reason?.trim())
    .map(([k]) => k);
  assert.deepEqual(bad, [], `사유 없는 unreachable 축: ${bad.join(', ')}`);
});

// 개정안 #01 §2.2 실측 함정: prompt_defense 를 요청하면 출력 키가 둘로 갈린다 —
// prompt_defense_analyzer(요청 이름으로 만들어진 빈 자리, 항상 total_findings=0)와
// promptdefense_analyzer(실제 finding). 유령 키를 signal_map 에 적으면 신호가 영원히 0이다.
test('signal_map 이 유령 분석기 키(prompt_defense_analyzer)를 쓰지 않는다', () => {
  const table = loadAxisTable(parse());
  for (const [axis, entry] of Object.entries(table)) {
    assert.ok(
      !Object.keys(entry.signal_map ?? {}).includes('prompt_defense_analyzer'),
      `${axis}: 실제 finding 은 promptdefense_analyzer 키로 온다(유령 키 사용 금지)`
    );
  }
});

// 개정안 #01 §5.3: AITech 상위 ID 로 잡으면 두 축이 충돌한다(AISubtech-8.2.1 vs 8.2.3 실측).
test('accepts_taxonomy 는 AISubtech 수준으로만 선언한다(AITech 상위 ID 금지)', () => {
  const table = loadAxisTable(parse());
  for (const [axis, entry] of Object.entries(table)) {
    for (const t of entry.accepts_taxonomy ?? []) {
      assert.ok(t.startsWith('AISubtech-'), `${axis}: "${t}" — AITech 상위 ID 는 축 충돌을 일으킨다`);
    }
  }
});

test('scannable 5축은 전부 reachable, partial 5축은 전부 unreachable_in_v0(실측 결과 고정)', () => {
  const table = loadAxisTable(parse());
  const by = (c: string) => Object.entries(table).filter(([, v]) => v.coverage === c);
  assert.deepEqual(by('scannable').map(([, v]) => v.signal_status), Array(5).fill('reachable'));
  assert.deepEqual(by('partial').map(([, v]) => v.signal_status), Array(5).fill('unreachable_in_v0'));
  assert.deepEqual(by('not_scannable').map(([, v]) => v.signal_status), Array(5).fill('not_applicable'));
});
