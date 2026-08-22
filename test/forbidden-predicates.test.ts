// Task 21 — 금지 술어 회귀 (AC-02c/AC-03f)
// PRD-v2 §1: "인증·감사 통과·컴플라이언스 완료" 류 표현을 제품 어디에도 쓰지 않는다
// (CPA 자격 영역 침범 금지, Delve 사례 반면교사).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import { render } from '../src/render.js';
import { mapFindingsToClaims } from '../src/map.js';
import { loadAxisTable } from '../src/ontology.js';
import { normalize } from '../src/normalize.js';
import { parseScannerRawEnvelope } from '../src/scanner-envelope.js';

const ONTOLOGY: any = yaml.load(readFileSync('ontology.yaml', 'utf8'));
const AXIS_TABLE = loadAxisTable(ONTOLOGY);
const META = { name: 'cisco-mcp-scanner', version: '4.8.3', ruleset_hash: 'abc', scanned_at: '2026-08-22T00:00:00Z', target_hash: 'def', python_version: '3.12.0' };

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function outputs(raw: Parameters<typeof normalize>[0]) {
  const { findings, unmatchedSignals } = normalize(raw, AXIS_TABLE, META);
  const claims = mapFindingsToClaims(findings, AXIS_TABLE, { attempted: 1, scanned: 1 });
  return render(claims, findings, META, [], unmatchedSignals, { allowRemote: true, usedRemoteCount: 1 }, ONTOLOGY,
    ['scanner version 9.9.9 is outside the supported range']);
}

const HEAVY = [
  { analyzer: 'yara_analyzer', threatName: 'PROMPT INJECTION', rule: 'yara_analyzer:PROMPT INJECTION', target: 'srv-a', raw: {} },
  { analyzer: 'yara_analyzer', threatName: 'CREDENTIAL HARVESTING', rule: 'yara_analyzer:CREDENTIAL HARVESTING', target: 'srv-b', raw: {} },
];

test('금지 술어 — 템플릿 전수에서 0건(AC-02c/AC-03f)', () => {
  const { markdown, json } = outputs(HEAVY);
  for (const word of ONTOLOGY.forbidden_predicates as string[]) {
    assert.ok(!markdown.includes(word), `forbidden word "${word}" found in markdown`);
    assert.ok(!json.includes(word), `forbidden word "${word}" found in json`);
  }
});

// 테스트보강 codex 반영 — 문자열 정확일치만으로는 대소문자/하이픈 변형/동의어를 놓친다.
test('금지 술어 — 대소문자/하이픈 변형/동의어까지 0건', () => {
  const { markdown, json } = outputs(HEAVY);
  const patterns = [
    ...(ONTOLOGY.forbidden_predicates as string[]).map(w => new RegExp(escapeRegex(w), 'i')),
    /audit[\s-]?passed/i,
    /certification[\s-]?ready/i,
    /fully\s+compliant/i,
    /100%\s*(safe|secure)/i,
  ];
  for (const re of patterns) {
    assert.ok(!re.test(markdown), `forbidden pattern ${re} found in markdown`);
    assert.ok(!re.test(json), `forbidden pattern ${re} found in json`);
  }
});

// 발견 0건일 때가 가장 위험하다 — "아무것도 안 나왔다"를 "안전하다"로 쓰고 싶은 유혹이 크다.
test('발견 0건 소견서에도 금지 술어가 없다(가장 유혹이 큰 경로)', () => {
  const { markdown, json } = outputs([]);
  for (const word of ONTOLOGY.forbidden_predicates as string[]) {
    assert.ok(!markdown.includes(word) && !json.includes(word), `"${word}" 노출`);
  }
  assert.ok(markdown.includes('No findings ≠ proof of safety'), '대신 반드시 이 면책이 있어야 한다');
});

// 실측 데이터 경로에서도 확인한다 — 스캐너가 준 문자열이 그대로 실려 금지어를 들여올 수 있다.
test('실측 fixture 경로에서도 금지 술어 0건(스캐너 문자열 유입 차단)', () => {
  const envelope = JSON.parse(readFileSync('fixtures/mcp-scanner-4.8.3/raw-envelope-yara-fired.json', 'utf8'));
  const { markdown, json } = outputs(parseScannerRawEnvelope(envelope, 'fallback'));
  for (const word of ONTOLOGY.forbidden_predicates as string[]) {
    assert.ok(!markdown.includes(word) && !json.includes(word), `"${word}" 가 스캐너 출력 경유로 유입됐다`);
  }
});
