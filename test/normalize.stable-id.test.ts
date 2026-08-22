// Task 11 — canonicalStringify + 그룹핑/중복접기
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { groupAndAssignMatchIndex } from '../src/normalize.js';

// 개정안 #01: RawFinding 은 analyzer 를 필수로 갖는다(axis 분류 키). 아래 픽스처도 그에 맞춘다.
const base = { analyzer: 'yara_analyzer', threatName: 'CREDENTIAL HARVESTING', rule: 'yara_analyzer:CREDENTIAL HARVESTING', target: 'srv-a' };

test('byte-identical finding 2건 → 1건 + duplicate_count 2', () => {
  const dup = { ...base, raw: { snippet: 'x' } };
  const { grouped } = groupAndAssignMatchIndex([dup, { ...dup }]);
  assert.equal(grouped.length, 1);
  assert.equal(grouped[0].duplicate_count, 2);
});

test('서로 다른 raw 2건 → 2건, match_index 0/1 부여', () => {
  const { grouped } = groupAndAssignMatchIndex([
    { ...base, raw: { snippet: 'x' } },
    { ...base, raw: { snippet: 'y' } },
  ]);
  assert.equal(grouped.length, 2);
  assert.deepEqual(grouped.map(g => g.match_index).sort(), [0, 1]);
  assert.ok(grouped.every(g => g.duplicate_count === undefined), '중복이 아니면 duplicate_count 는 없다');
});

// 입력 순서가 달라도 같은 결과가 나와야 안정 ID 가 안정적이다(해시 정렬로 보장).
test('입력 순서를 바꿔도 match_index 배정이 동일하다(셔플 재현성)', () => {
  const a = { ...base, raw: { snippet: 'x' } };
  const b = { ...base, raw: { snippet: 'y' } };
  const forward = groupAndAssignMatchIndex([a, b]).grouped;
  const reverse = groupAndAssignMatchIndex([b, a]).grouped;
  assert.deepEqual(
    forward.map(g => [g.match_index, (g.raw as any).snippet]),
    reverse.map(g => [g.match_index, (g.raw as any).snippet]),
  );
});

// 셔플 재현성 우회경로 보강(codex 테스트보강 반영) — canonicalStringify 가 NaN/undefined 를
// null/문자열 "undefined" 와 같은 문자열로 만들면, 의미가 다른 두 finding 이 잘못 접힌다.
test('canonicalStringify 가 NaN 과 null 을 구분한다(다른 raw 는 접히면 안 됨)', () => {
  const { grouped } = groupAndAssignMatchIndex([
    { ...base, raw: { a: NaN } },
    { ...base, raw: { a: null } },
  ]);
  assert.equal(grouped.length, 2, 'NaN 과 null 은 서로 다른 raw 이므로 중복 접기 대상이 아니다');
});

test('canonicalStringify 가 undefined 값과 문자열 "undefined" 를 구분한다', () => {
  const { grouped } = groupAndAssignMatchIndex([
    { ...base, raw: { a: undefined } },
    { ...base, raw: { a: 'undefined' } },
  ]);
  assert.equal(grouped.length, 2);
});

test('키 순서만 다른 raw 는 같은 것으로 접힌다(정렬 직렬화)', () => {
  const { grouped } = groupAndAssignMatchIndex([
    { ...base, raw: { a: 1, b: 2 } },
    { ...base, raw: { b: 2, a: 1 } },
  ]);
  assert.equal(grouped.length, 1);
  assert.equal(grouped[0].duplicate_count, 2);
});

test('rule/target/line 이 다르면 다른 그룹 — match_index 는 그룹마다 0부터', () => {
  const { grouped } = groupAndAssignMatchIndex([
    { ...base, target: 'srv-a', raw: { s: 1 } },
    { ...base, target: 'srv-b', raw: { s: 1 } },
  ]);
  assert.equal(grouped.length, 2);
  assert.deepEqual(grouped.map(g => g.match_index), [0, 0]);
});

// Task 12 — computeStableId + 셔플 재현성
import { computeStableId } from '../src/normalize.js';

const idOf = (f: { rule: string; target: string; line?: number; match_index: number }) =>
  computeStableId('cisco-mcp-scanner', '4.8.3', f.rule, f.target, f.line, f.match_index);

test('셔플 재현성 — 같은 배열을 셔플해도 ID 집합 동일', () => {
  const raws = [
    { ...base, rule: 'r1', target: 't1', raw: { a: 1 } },
    { ...base, rule: 'r1', target: 't1', raw: { a: 2 } },
    { ...base, rule: 'r2', target: 't2', raw: { b: 1 } },
  ];
  const idsA = groupAndAssignMatchIndex(raws).grouped.map(idOf).sort();
  const idsB = groupAndAssignMatchIndex([...raws].reverse()).grouped.map(idOf).sort();
  assert.deepEqual(idsA, idsB);
  assert.equal(new Set(idsA).size, 3, '서로 다른 finding 3건은 ID 도 3개여야 한다');
});

test('computeStableId 는 sha256 앞 16자', () => {
  const id = computeStableId('s', 'v', 'r', 't', undefined, 0);
  assert.equal(id.length, 16);
  assert.match(id, /^[0-9a-f]{16}$/);
});

// 스캐너 버전이 바뀌면 ID 도 바뀐다 — 같은 룰이라도 다른 엔진의 판정은 다른 근거이기 때문이다.
test('스캐너명·버전이 다르면 다른 ID', () => {
  assert.notEqual(computeStableId('s', '1.0', 'r', 't', undefined, 0), computeStableId('s', '2.0', 'r', 't', undefined, 0));
  assert.notEqual(computeStableId('a', '1.0', 'r', 't', undefined, 0), computeStableId('b', '1.0', 'r', 't', undefined, 0));
});

// line 이 없는 경우와 있는 경우가 충돌하지 않아야 한다(구분자 '-' 사용).
test('line 유무가 ID 를 가른다', () => {
  assert.notEqual(computeStableId('s', 'v', 'r', 't', undefined, 0), computeStableId('s', 'v', 'r', 't', 1, 0));
});

test('match_index 가 다르면 다른 ID(같은 룰의 여러 매치 구분)', () => {
  assert.notEqual(computeStableId('s', 'v', 'r', 't', 1, 0), computeStableId('s', 'v', 'r', 't', 1, 1));
});
