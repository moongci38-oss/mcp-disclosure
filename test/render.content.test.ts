// Task 19 — render() 본체 내용 검증 (FR-04, A-3/A-4 codex + 개정안 #01)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import { render } from '../src/render.js';
import { mapFindingsToClaims } from '../src/map.js';
import { loadAxisTable } from '../src/ontology.js';
import { normalize } from '../src/normalize.js';
import { parseScannerRawEnvelope } from '../src/scanner-envelope.js';
import { checkScannerVersion } from '../src/version-check.js';

const ONTOLOGY: any = yaml.load(readFileSync('ontology.yaml', 'utf8'));
const AXIS_TABLE = loadAxisTable(ONTOLOGY);
const META = { name: 'cisco-mcp-scanner', version: '4.8.3', ruleset_hash: 'abc', scanned_at: '2026-08-22T00:00:00Z', target_hash: 'def', python_version: '3.12.0' };
const opts = { allowRemote: false, usedRemoteCount: 0 };

function reportOf(raw: Parameters<typeof normalize>[0] = [], extra: Partial<{ unmatched: string[]; warnings: string[]; usedRemoteCount: number }> = {}) {
  const { findings, unmatchedSignals } = normalize(raw, AXIS_TABLE, META);
  const claims = mapFindingsToClaims(findings, AXIS_TABLE, { attempted: 1, scanned: 1 });
  return render(
    claims, findings, META, [], extra.unmatched ?? unmatchedSignals,
    { allowRemote: false, usedRemoteCount: extra.usedRemoteCount ?? 0 }, ONTOLOGY, extra.warnings ?? [],
  );
}

test('발견 0건 → 면책 문구 필수 포함(AC-03d)', () => {
  assert.ok(reportOf().markdown.includes('No findings'));
});

test('장르 고지 문단 존재(AC-04a)', () => {
  assert.ok(reportOf().markdown.includes('Microsoft SSPA'));
});

test('자가진술 고지가 맨 위에 있다(제3자 감사로 오독 방지)', () => {
  assert.ok(reportOf().markdown.includes('self-attested'));
});

test('원격 스캔 수행 시 고지 배너 포함(AC-01e)', () => {
  assert.ok(reportOf([], { usedRemoteCount: 1 }).markdown.includes('remote endpoint'));
});

test('원격 미사용 시 배너가 없다(허위 경고 금지)', () => {
  assert.ok(!reportOf().markdown.includes('remote endpoint'));
});

// A-3 codex 반영 — 종전엔 checkScannerVersion 이 render 출력과 전혀 연결돼 있지 않았다(AC-02d 사망).
test('스캐너 버전 경고가 markdown 에 노출된다(AC-02d 배선 확인)', () => {
  const warning = checkScannerVersion('9.9.9').warning!;
  assert.ok(reportOf([], { warnings: [warning] }).markdown.includes(warning));
});

// A-4 codex 반영
test('unmatchedSignals 가 1건 이상이면 markdown 에 개수가 노출된다', () => {
  const md = reportOf([], { unmatched: ['secret_exposure.signal_map.yara_analyzer["CREDENTIAL HARVESTING"]'] }).markdown;
  assert.ok(md.includes('zero matches'));
  assert.ok(md.includes('1 '), '개수가 보여야 한다');
});

// --- 개정안 #01: "못 보는 것"이 소견서에서 사라지지 않는지 ---
test('신호원 0인 5축이 3a 칸에 사유와 함께 나온다(감추지 않는다)', () => {
  const md = reportOf().markdown;
  assert.ok(md.includes('3a. Technical axes this scanner cannot report on'));
  for (const axis of ['tool_permission', 'auth_oauth', 'data_flow', 'logging', 'sdlc']) {
    assert.ok(md.includes(`**${axis}**: Not observable via this scanner.`), `${axis} 가 소견서에서 사라졌다`);
  }
  assert.ok(md.includes('HEUR-015'), '사유에 근거(어느 rule_id 가 소실됐는지)가 있어야 확인 가능하다');
});

test('cannot_detect 축이 "검사했는데 못 찾음"(2칸)으로 새지 않는다', () => {
  const md = reportOf().markdown;
  const sec2 = md.slice(md.indexOf('## 2.'), md.indexOf('## 3.'));
  for (const axis of ['tool_permission', 'auth_oauth', 'data_flow', 'logging', 'sdlc']) {
    assert.ok(!sec2.includes(`**${axis}**`), `${axis} 가 2칸(검사했고 못 찾음)에 있다 — 거짓 진술이다`);
  }
});

test('15축이 소견서 본문에 빠짐없이 등장한다', () => {
  const md = reportOf().markdown;
  for (const axis of Object.keys(AXIS_TABLE)) {
    // 1·2·3a 절은 `**axis**`, 3b 절은 `#### axis` 소제목(Task 20 체크리스트) 형식이다.
    assert.ok(md.includes(`**${axis}**`) || md.includes(`#### ${axis}`), `${axis} 누락`);
  }
});

// --- 엔드투엔드: 실측 봉투 → 소견서 ---
test('실측 fixture 전 구간 → 소견서(발견 4축이 1칸에, 나머지가 각 칸에)', () => {
  const envelope = JSON.parse(readFileSync('fixtures/mcp-scanner-4.8.3/raw-envelope-yara-fired.json', 'utf8'));
  const { markdown, json } = reportOf(parseScannerRawEnvelope(envelope, 'fallback'));
  const sec1 = markdown.slice(markdown.indexOf('## 1.'), markdown.indexOf('## 2.'));
  for (const axis of ['prompt_injection_defense', 'secret_exposure', 'malicious_pattern', 'operational_reliability']) {
    assert.ok(sec1.includes(`**${axis}**`), `${axis} 가 1칸(찾은 것)에 없다`);
  }
  assert.ok(sec1.includes('13 finding(s)'), 'prompt_injection_defense 13건');
  assert.ok(markdown.includes('Unmapped findings: 0'));
  const parsed = JSON.parse(json);
  assert.equal(parsed.findings.length, 17);
  assert.equal(parsed.claims.length, 15);
});

test('JSON 산출물에 마스킹되지 않은 원문이 새지 않는다(FR-05.1)', () => {
  const fakeToken = 'sk-' + 'RENDERLEAKCHECK1234567890AB';
  const { json } = reportOf([{ analyzer: 'yara_analyzer', threatName: 'CREDENTIAL HARVESTING', rule: 'r', target: 't', raw: { matched_string: fakeToken } }]);
  assert.ok(!json.includes(fakeToken), '소견서 JSON 에 시크릿 원문이 남으면 안 된다');
  assert.ok(json.includes('***REDACTED***'));
});

// Task 20 — 증적 요청 폼 체크리스트화 (FR-04.2, AC-03b)
test('불가 5축 전부 증적 요청 텍스트를 체크박스로 포함(AC-03b)', () => {
  const md = reportOf().markdown;
  for (const axis of ['incident_response', 'data_retention', 'subprocessor', 'training_data', 'dpa']) {
    assert.ok(md.includes(`#### ${axis}`), `${axis} 소제목 누락`);
    const req = (AXIS_TABLE as any)[axis].evidence_request as string;
    assert.ok(md.includes(`- [ ] ${req}`), `${axis} 증적 요청이 체크박스 형식이 아니다`);
  }
});

// 3a 는 사람이 서류를 내서 해결할 항목이 아니다 — 체크박스를 달면 오독된다.
test('3a(도구 한계) 절에는 체크박스를 달지 않는다', () => {
  const md = reportOf().markdown;
  const sec3a = md.slice(md.indexOf('### 3a.'), md.indexOf('### 3b.'));
  assert.ok(!sec3a.includes('- [ ]'), '도구 한계에 체크박스를 달면 "서류 내면 되는 것"으로 읽힌다');
});

// 도그푸딩 Task 26 발견 — 실제 스캔에서 한 축에 154건이 나와 ID 나열이 해시 덩어리가 됐다.
test('finding ID 는 표본만 보여주고 전량은 JSON 으로 넘긴다(가독성)', () => {
  const many = Array.from({ length: 30 }, (_, i) => ({
    analyzer: 'yara_analyzer', threatName: 'CREDENTIAL HARVESTING',
    rule: 'yara_analyzer:CREDENTIAL HARVESTING', target: `srv-${i}`, raw: { i },
  }));
  const { markdown, json } = reportOf(many);
  const line = markdown.split('\n').find(l => l.includes('**secret_exposure**'))!;
  assert.ok(line.includes('30 finding(s)'), '개수는 정확히 보여야 한다');
  assert.ok(line.includes('(+25 more'), '나머지는 개수로만 알린다');
  assert.ok(line.length < 400, `1절 한 줄이 너무 길다(${line.length}자) — 읽히지 않는 정직함은 전달되지 않는다`);
  assert.equal(JSON.parse(json).findings.length, 30, '전량은 JSON 이 갖는다');
});

test('5건 이하면 생략 표기 없이 전부 보여준다', () => {
  const few = Array.from({ length: 3 }, (_, i) => ({
    analyzer: 'yara_analyzer', threatName: 'CREDENTIAL HARVESTING',
    rule: 'yara_analyzer:CREDENTIAL HARVESTING', target: `srv-${i}`, raw: { i },
  }));
  const line = reportOf(few).markdown.split('\n').find(l => l.includes('**secret_exposure**'))!;
  assert.ok(line.includes('3 finding(s)'));
  assert.ok(!line.includes('more'), '3건뿐인데 "더 있음"이라고 하면 안 된다');
});

// AC-02a — 재현 메타 6필드가 전부 소견서에 보여야 재현 주장이 성립한다.
test('AC-02a — self-attested 표기 + 메타 6필드 전부 markdown 에 존재', () => {
  const md = reportOf().markdown;
  assert.ok(md.includes('self-attested'));
  for (const v of Object.values(META)) {
    assert.ok(md.includes(v), `메타 값 "${v}" 이 소견서에 없다`);
  }
});

// AC-03a — 기술통제 클레임이 참조하는 ID 는 전부 실재해야 한다(허수 참조 금지, LLM 경유 0회).
test('AC-03a — 모든 technical_control finding_ids 가 실재 Finding.id 를 가리킨다', () => {
  const raw = Array.from({ length: 4 }, (_, i) => ({
    analyzer: 'yara_analyzer', threatName: 'CODE EXECUTION',
    rule: 'yara_analyzer:CODE EXECUTION', target: `srv-${i}`, raw: { i },
  }));
  const { json } = reportOf(raw);
  const parsed = JSON.parse(json);
  const known = new Set(parsed.findings.map((f: any) => f.id));
  const referenced = parsed.claims.filter((c: any) => c.type === 'technical_control').flatMap((c: any) => c.finding_ids);
  assert.ok(referenced.length > 0);
  for (const id of referenced) assert.ok(known.has(id), `실재하지 않는 finding id 참조: ${id}`);
});

// AC-04b — 미분류가 있으면 그 숫자가 보여야 한다. 0 만 확인하면 "항상 0" 버그를 못 잡는다.
test('AC-04b — 미분류 finding 이 있으면 실제 개수가 노출된다', () => {
  const raw = [
    { analyzer: 'unknown_analyzer', threatName: 'NOPE', rule: 'a', target: 's1', raw: {} },
    { analyzer: 'another_unknown', threatName: 'NOPE2', rule: 'b', target: 's2', raw: {} },
  ];
  const { markdown, json } = reportOf(raw);
  const actual = JSON.parse(json).findings.filter((f: any) => f.axis === null).length;
  assert.equal(actual, 2);
  assert.ok(markdown.includes(`Unmapped findings: ${actual}`), '미분류 건수가 실제와 달라졌다');
});

// AC-05a — markdown 이 건수를 축약 표기하게 됐으므로(Task 26), "행 수 일치"가 아니라
// "표기된 건수 합 == json findings 수"로 대조한다.
test('AC-05a — markdown 에 표기된 건수 합이 json findings 수와 일치한다', () => {
  const raw = Array.from({ length: 12 }, (_, i) => ({
    analyzer: i % 2 === 0 ? 'yara_analyzer' : 'readiness_analyzer',
    threatName: i % 2 === 0 ? 'CODE EXECUTION' : 'unknown',
    rule: `r${i}`, target: `srv-${i}`, raw: { i },
  }));
  const { markdown, json } = reportOf(raw);
  const counted = [...markdown.matchAll(/(\d+) finding\(s\)/g)].reduce((a, m) => a + Number(m[1]), 0);
  const parsed = JSON.parse(json);
  const classified = parsed.findings.filter((f: any) => f.axis !== null).length;
  assert.equal(counted, classified, 'markdown 표기 건수와 json 이 어긋난다');
  assert.equal(parsed.findings.length, 12);
});
