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
  return { findings, claims: mapFindingsToClaims(findings, AXIS_TABLE) };
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
