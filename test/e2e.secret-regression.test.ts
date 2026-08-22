// Task 22 — 시크릿 회귀: 출력 2종 전문 grep (AC-05b)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import { render } from '../src/render.js';
import { mapFindingsToClaims } from '../src/map.js';
import { loadAxisTable } from '../src/ontology.js';
import { normalize } from '../src/normalize.js';

const ONTOLOGY: any = yaml.load(readFileSync('ontology.yaml', 'utf8'));
const AXIS_TABLE = loadAxisTable(ONTOLOGY);
const META = { name: 'cisco-mcp-scanner', version: '4.8.3', ruleset_hash: 'abc', scanned_at: '2026-08-22T00:00:00Z', target_hash: 'def', python_version: '3.12.0' };

function outputs(raw: Record<string, unknown>, target = 'srv-a') {
  const findingsRaw = [{ analyzer: 'yara_analyzer', threatName: 'CREDENTIAL HARVESTING', rule: 'yara_analyzer:CREDENTIAL HARVESTING', target, raw }];
  const { findings, unmatchedSignals } = normalize(findingsRaw, AXIS_TABLE, META);
  const claims = mapFindingsToClaims(findings, AXIS_TABLE);
  return render(claims, findings, META, [], unmatchedSignals, { allowRemote: false, usedRemoteCount: 0 }, ONTOLOGY);
}

test('AC-05b — 시크릿 심은 fixture → 출력 2종 전문에 0건', () => {
  const SECRET = 'sk-' + 'THISISASECRETVALUE1234567890'; // 테스트 전용 가짜 값(실제 키 아님)
  const { markdown, json } = outputs({ matched_string: SECRET, snippet: `token=${SECRET}` });
  assert.ok(!markdown.includes(SECRET), 'markdown 에 시크릿 원문 노출');
  assert.ok(!json.includes(SECRET), 'json 에 시크릿 원문 노출');
});

// 테스트보강 codex 반영 — sk- 프리픽스 형만으로는 부족하다.
test('AC-05b 확장 — 중첩객체/JWT/authorization 키도 출력 전문에 노출되지 않는다', () => {
  const JWT = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', 'dGVzdHNpZ25hdHVyZQ'].join('.');
  const NESTED_SECRET = 'sk-' + 'INNERVALUE1234567890AB';
  const { markdown, json } = outputs({ authorization: 'Bearer ' + JWT, nested: { inner_secret: NESTED_SECRET } }, 'srv-b');
  assert.ok(!markdown.includes(JWT) && !json.includes(JWT), 'JWT 가 출력에 노출됨');
  assert.ok(!markdown.includes(NESTED_SECRET) && !json.includes(NESTED_SECRET), '중첩 객체 내부 시크릿이 출력에 노출됨');
});

// 스캐너가 자유 텍스트로 주는 threat_summary 안에 시크릿이 섞여 올 수 있다 — 실측 raw 형태 그대로 검증.
test('AC-05b 확장 — 스캐너 롤업 raw(threat_summary 등) 경유 유출도 막힌다', () => {
  const SECRET = 'sk-' + 'SUMMARYLEAK1234567890ABCDE';
  const { markdown, json } = outputs({
    severity: 'HIGH', total_findings: 3,
    threat_summary: `Tool 'echo' exposes ${SECRET} in its description`,
    threat_names: ['CREDENTIAL HARVESTING'],
    mcp_taxonomies: [{ aisubtech: 'AISubtech-8.2.3' }],
  }, 'srv-c');
  assert.ok(!markdown.includes(SECRET) && !json.includes(SECRET), 'threat_summary 경유로 시크릿이 샜다');
});

// URL 자격증명 형태(user:pass@host)는 프리픽스 규칙에 안 걸리므로 별도 확인한다.
test('AC-05b 확장 — URL 자격증명부도 출력에 남지 않는다', () => {
  const CRED_URL = 'https://' + 'svcacct:hunter2hunter2@internal.example.com/mcp';
  const { markdown, json } = outputs({ endpoint: CRED_URL }, 'srv-d');
  assert.ok(!markdown.includes('hunter2hunter2') && !json.includes('hunter2hunter2'), 'URL 비밀번호가 노출됐다');
});
