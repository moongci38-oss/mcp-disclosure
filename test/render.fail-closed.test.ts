// Task 18 — render() fail-closed 검증 (AC-02b/AC-03b/c)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import { render, RenderError } from '../src/render.js';
import { mapFindingsToClaims } from '../src/map.js';
import { loadAxisTable } from '../src/ontology.js';
import { normalize } from '../src/normalize.js';

const ONTOLOGY: any = yaml.load(readFileSync('ontology.yaml', 'utf8'));
const AXIS_TABLE = loadAxisTable(ONTOLOGY);
const META = { name: 'cisco-mcp-scanner', version: '4.8.3', ruleset_hash: 'abc', scanned_at: '2026-08-22T00:00:00Z', target_hash: 'def', python_version: '3.12.0' };
const base = () => {
  const { findings } = normalize([], AXIS_TABLE, META);
  return { findings, claims: mapFindingsToClaims(findings, AXIS_TABLE, { attempted: 1, scanned: 1 }) };
};
const opts = { allowRemote: false, usedRemoteCount: 0 };

test('15축 중 1개 클레임 누락 → RenderError', () => {
  const { findings, claims } = base();
  assert.throws(() => render(claims.filter(c => c.axis !== 'dpa'), findings, META, [], [], opts, ONTOLOGY), RenderError);
});

test('축 누락 에러 메시지에 어느 축인지 들어간다', () => {
  const { findings, claims } = base();
  assert.throws(
    () => render(claims.filter(c => c.axis !== 'dpa'), findings, META, [], [], opts, ONTOLOGY),
    (e: unknown) => e instanceof RenderError && /dpa/.test(e.message),
  );
});

test('scanner_meta 1필드 결손 → RenderError', () => {
  const { findings, claims } = base();
  assert.throws(() => render(claims, findings, { ...META, python_version: '' } as any, [], [], opts, ONTOLOGY), RenderError);
});

test('메타 6필드 각각이 결손이면 전부 RenderError(하나라도 빠지면 재현 불가)', () => {
  const { findings, claims } = base();
  for (const f of ['name', 'version', 'ruleset_hash', 'scanned_at', 'target_hash', 'python_version']) {
    assert.throws(() => render(claims, findings, { ...META, [f]: '' } as any, [], [], opts, ONTOLOGY), RenderError, `${f} 결손이 통과했다`);
  }
});

// 술어가 늘었을 때 그 축이 조용히 사라지는 것을 막는 방어선(개정안 #01).
test('알 수 없는 술어의 클레임이 섞이면 RenderError(칸 배정 유실 방지)', () => {
  const { findings, claims } = base();
  const broken = claims.map(c =>
    c.axis === 'logging' ? { ...c, predicate: 'some_future_predicate' } as any : c);
  assert.throws(() => render(broken, findings, META, [], [], opts, ONTOLOGY), RenderError);
});

test('원격 스캔 수행 시에도 정상 렌더(배너 삽입 로직이 있으면 throw 안 함)', () => {
  const { findings, claims } = base();
  assert.doesNotThrow(() => render(claims, findings, META, [], [], { allowRemote: true, usedRemoteCount: 1 }, ONTOLOGY));
});

// 도그푸딩 Task 26 회귀 — 자리표시자가 게이트를 무사통과하던 fail-open.
// "가드가 있다"와 "가드가 막는다"는 다른 주장이다.
test('자리표시자 메타(unset/unknown)는 RenderError — 빈 문자열만 막는 게 아니다', () => {
  const { findings, claims } = base();
  for (const v of ['unset', 'unknown', 'N/A', 'TBD', '-']) {
    assert.throws(
      () => render(claims, findings, { ...META, ruleset_hash: v } as any, [], [], opts, ONTOLOGY),
      RenderError, `"${v}" 가 재현 메타로 통과했다`);
  }
});

test('"unavailable: <이유>" 는 통과한다 — 실측된 부재는 정직한 값이다', () => {
  const { findings, claims } = base();
  const meta = { ...META, ruleset_hash: 'unavailable: scanner does not expose a ruleset identifier' };
  assert.doesNotThrow(() => render(claims, findings, meta, [], [], opts, ONTOLOGY));
  const { markdown } = render(claims, findings, meta, [], [], opts, ONTOLOGY);
  assert.ok(markdown.includes('unavailable:'), '부재 사유가 소견서에 그대로 보여야 읽는 쪽이 안다');
});
