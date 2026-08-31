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
  const claims = mapFindingsToClaims(findings, AXIS_TABLE, { attempted: 1, scanned: 1 });
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

// --- 설정 인벤토리 경로 (2026-08-31) ---------------------------------------
// ⚠️ 인벤토리 절은 **설정 원문을 소견서로 옮기는 유일한 경로**다. 위 케이스들은 전부
//    "스캐너가 준 raw" 경유였고, 이 경로는 그것과 별개로 새로 뚫린 구멍이다.
//    discover() → render() 전 구간을 실제 .mcp.json 으로 통과시켜 확인한다.
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discover } from '../src/discover.js';

/** 시크릿을 심은 .mcp.json 을 만들고 discover→render 를 통과시킨다. */
function inventoryOutputs(mcpServers: Record<string, unknown>) {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-disclosure-inv-'));
  writeFileSync(join(dir, '.mcp.json'), JSON.stringify({ mcpServers }));
  const { targets } = discover(dir);
  const { findings, unmatchedSignals } = normalize([], AXIS_TABLE, META);
  const claims = mapFindingsToClaims(findings, AXIS_TABLE, { attempted: targets.length, scanned: 0 });
  const out = render(claims, findings, META, [], unmatchedSignals,
    { allowRemote: false, usedRemoteCount: 0 }, ONTOLOGY, [], targets);
  return { ...out, targets };
}

test('인벤토리 — env 값은 소견서 어디에도 실리지 않는다(키 이름만)', () => {
  const SECRET = 'ghp_' + 'ENVLEAK0123456789ABCDEFGHIJKLMNOPQRS';
  const { markdown, json, targets } = inventoryOutputs({
    gh: { command: 'npx', args: ['-y', 'server-github'], env: { GITHUB_TOKEN: SECRET, PLAIN: 'hello' } },
  });
  assert.ok(!markdown.includes(SECRET) && !json.includes(SECRET), 'env 값이 소견서로 샜다');
  // 값은 애초에 담기지도 않아야 한다 — 마스킹 이전에 입구에서 막는다.
  assert.ok(!JSON.stringify(targets).includes(SECRET), 'env 값이 ScanTarget 에 담겼다(입구 차단 실패)');
  assert.ok(!markdown.includes('hello'), '평범해 보이는 env 값도 담지 않는다 — 값은 전부 안 싣는다');
  assert.match(markdown, /GITHUB_TOKEN/, '키 이름은 실려야 인벤토리가 쓸모 있다');
});

test('인벤토리 — args 에 섞인 토큰이 소견서에 노출되지 않는다', () => {
  const SECRET = 'sk-' + 'ARGSLEAK1234567890ABCDEFGH';
  const { markdown, json } = inventoryOutputs({
    svc: { command: 'npx', args: ['-y', 'some-server', '--api-key=' + SECRET] },
  });
  assert.ok(!markdown.includes(SECRET) && !json.includes(SECRET), 'args 경유로 시크릿이 샜다');
  assert.match(markdown, /--api-key=\*\*\*REDACTED\*\*\*/, '무엇이 가려졌는지는 보여야 한다');
});

test('인벤토리 — 짧아서 값 기반 규칙에 안 걸리는 시크릿도 플래그 문맥으로 잡힌다', () => {
  const SHORT = 'hunter2';
  const { markdown, json } = inventoryOutputs({
    svc: { command: 'node', args: ['s.js', '--password', SHORT] },
  });
  assert.ok(!markdown.includes(SHORT) && !json.includes(SHORT), '짧은 시크릿이 args 로 샜다');
});

test('인벤토리 — remote URL 에 박힌 자격증명도 노출되지 않는다', () => {
  const PW = 'hunter2hunter2';
  const { markdown, json } = inventoryOutputs({
    far: { url: 'https://' + 'svc:' + PW + '@remote.example.com/mcp' },
  });
  assert.ok(!markdown.includes(PW) && !json.includes(PW), 'remote URL 자격증명이 노출됐다');
});

test('인벤토리 — 목록은 판정이 아니다(평가 문구를 쓰지 않는다)', () => {
  const { markdown } = inventoryOutputs({ svc: { command: 'npx', args: ['-y', 'srv'] } });
  const section = markdown.slice(markdown.indexOf('## What is wired'), markdown.indexOf('## 1.'));
  assert.match(section, /A list, not an assessment/, '목록임을 명시해야 한다');
  for (const claimy of [/least[- ]privilege/i, /\bsecure\b/i, /\bsafe\b/i, /looks good/i, /no risk/i]) {
    assert.ok(!claimy.test(section), `판정 문구가 들어갔다: ${claimy}`);
  }
});

// ⚠️ 2026-08-31 실측으로 잡은 **기존 누출** 회귀 — 내 인벤토리 변경 이전부터 있던 구멍이다.
//    `unscanned[].target` 이 ScanTarget 원본이라 자격증명 박힌 remoteUrl 이 JSON 으로 나갔다.
//    기존 회귀 테스트가 전부 `unscanned: []` 로 렌더해서 이 경로를 한 번도 안 지났다.
test('unscanned 경유 — remote URL 자격증명이 JSON 으로 새지 않는다', () => {
  const PW = 'hunter2hunter2';
  const target = {
    kind: 'mcp_server' as const,
    sourcePath: '/tmp/x/.mcp.json',
    name: 'corp',
    transport: 'remote' as const,
    remoteUrl: 'https://' + 'svc:' + PW + '@mcp.corp.example.com/sse',
  };
  const { findings, unmatchedSignals } = normalize([], AXIS_TABLE, META);
  const claims = mapFindingsToClaims(findings, AXIS_TABLE, { attempted: 1, scanned: 0 });
  const { markdown, json } = render(
    claims, findings, META,
    [{ target, reason: 'remote_out_of_scope' as const }],
    unmatchedSignals, { allowRemote: false, usedRemoteCount: 0 }, ONTOLOGY, [], [target],
  );
  assert.ok(!json.includes(PW), 'unscanned[].target.remoteUrl 로 자격증명이 샜다');
  assert.ok(!markdown.includes(PW), 'markdown 으로도 새면 안 된다');
});
