import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseScannerRawEnvelope } from '../src/scanner-envelope.js';

// Task 8b 실측(2026-08-22)으로 fixture가 실제 cisco-ai-mcp-scanner 4.8.3 raw 출력 발췌본으로
// 교체됐다 — scan_results[]는 "도구 1개당 1개 원소"이고, findings는 배열이 아니라 분석기명을
// 키로 하는 롤업 요약 객체다(rule/rule_id 필드 없음). 상세 근거는 src/scanner-envelope.ts 상단
// 주석 참조.
const FIXTURE = JSON.parse(readFileSync('fixtures/mcp-scanner-4.8.3/raw-envelope.json', 'utf8'));

test('실측 raw 봉투 fixture → scan_results 내 non-SAFE 분석기 결과 전부 추출(AC-01h, 실측 스키마)', () => {
  // 이 fixture의 2개 tool 항목은 각각 readiness_analyzer만 total_findings>0(HIGH)이고
  // yara/vulnerable_package는 SAFE(0건)다 — 그러므로 기대 건수는 2(entry당 1개).
  const result = parseScannerRawEnvelope(FIXTURE, 'fallback-target');
  assert.equal(result.length, 2, '이 fixture는 findings가 0건이면 안 된다 — 빈 소견서 회귀 방지가 이 테스트의 목적');
  assert.ok(result.every(f => typeof f.rule === 'string' && f.rule.length > 0));
  assert.ok(result.every(f => f.rule.startsWith('readiness_analyzer')));
  assert.deepEqual(result.map(f => f.target), ['echo', 'get-annotated-message']);
});

test('SAFE(total_findings=0) 분석기 결과는 finding으로 나오지 않는다', () => {
  const result = parseScannerRawEnvelope(FIXTURE, 'fallback-target');
  assert.ok(!result.some(f => f.rule.startsWith('yara_analyzer')));
  assert.ok(!result.some(f => f.rule.startsWith('vulnerable_package_analyzer')));
});

test('scan_results 배열이 없는 봉투 → 빈 배열(조용히 죽지 않음, fail-open)', () => {
  assert.deepEqual(parseScannerRawEnvelope({ server_url: 'x' }, 'target-x'), []);
});

test('scan_results 원소에 findings가 없으면 그 원소는 기여분 0건', () => {
  const partial = { scan_results: [{ tool_name: 'a' }, { tool_name: 'b', findings: { yara_analyzer: { severity: 'HIGH', total_findings: 1, threat_names: ['bad'] } } }] };
  const result = parseScannerRawEnvelope(partial, 'fallback');
  assert.equal(result.length, 1);
  assert.equal(result[0].target, 'b');
  assert.equal(result[0].rule, 'yara_analyzer:bad');
});

test('rule 필드는 원본에 없다 — analyzer명+threat_names로 최선 근사 식별자를 합성한다', () => {
  const synthetic = { scan_results: [{ tool_name: 'x', findings: { readiness_analyzer: { severity: 'HIGH', total_findings: 3, threat_names: [] } } }] };
  const result = parseScannerRawEnvelope(synthetic, 'fallback');
  assert.equal(result[0].rule, 'readiness_analyzer', 'threat_names가 비어 있으면 analyzer명 단독을 rule로 쓴다');
});

// ============================================================
// 개정안 #01 파생 (Spec §12 미결 ⑤) — analyzer/threatName 분리 · 팬아웃 · taxonomy 객체 파싱
// fixture 는 실측 발췌본이다: YARA 발화 4건(정적 입력) + 4분석기 조합 1건.
// 원본: docs/measurements/2026-08-22-signal-space/
// ============================================================
const FIRED = JSON.parse(readFileSync('fixtures/mcp-scanner-4.8.3/raw-envelope-yara-fired.json', 'utf8'));

test('analyzer 와 threatName 을 따로 싣는다 — assignAxis 가 둘을 분리해서 받는다', () => {
  const out = parseScannerRawEnvelope(FIRED, 'fallback');
  const pi = out.find(f => f.target === 't_pi');
  assert.ok(pi, 't_pi 항목이 있어야 한다');
  assert.equal(pi!.analyzer, 'yara_analyzer');
  assert.equal(pi!.threatName, 'PROMPT INJECTION');
  assert.equal(pi!.rule, 'yara_analyzer:PROMPT INJECTION', 'rule 은 사람이 읽는 합성 식별자로 유지한다');
});

test('threat_names N개 → RawFinding N건으로 펼친다(축 분류가 threat_name 단위이므로)', () => {
  const out = parseScannerRawEnvelope(FIRED, 'fallback');
  const pd = out.filter(f => f.analyzer === 'promptdefense_analyzer');
  assert.equal(pd.length, 12, '12종 카테고리가 1건으로 뭉쳐지면 축 분류가 불가능해진다');
  assert.ok(pd.some(f => f.threatName === 'INSTRUCTION_OVERRIDE'));
  assert.ok(pd.some(f => f.threatName === 'ABUSE_PREVENTION'));
  assert.equal(new Set(pd.map(f => f.threatName)).size, 12, '중복 없이 12종이어야 한다');
});

test('threat_names 가 비어도 total_findings>0 이면 1건은 남긴다(신호를 버리지 않는다)', () => {
  const synthetic = { scan_results: [{ tool_name: 'x', findings: { readiness_analyzer: { severity: 'HIGH', total_findings: 3, threat_names: [] } } }] };
  const out = parseScannerRawEnvelope(synthetic, 'fallback');
  assert.equal(out.length, 1);
  assert.equal(out[0].analyzer, 'readiness_analyzer');
  assert.equal(out[0].threatName, undefined);
  assert.equal(out[0].rule, 'readiness_analyzer');
});

test('유령 키(prompt_defense_analyzer, 항상 0건)는 finding 으로 나오지 않는다', () => {
  const out = parseScannerRawEnvelope(FIRED, 'fallback');
  assert.ok(!out.some(f => f.analyzer === 'prompt_defense_analyzer'),
    '요청 이름으로 만들어진 빈 자리는 total_findings=0 이라 걸러져야 한다');
  assert.ok(out.some(f => f.analyzer === 'promptdefense_analyzer'), '실제 finding 키는 남아야 한다');
});

test('taxonomy 는 객체가 아니라 aisubtech 문자열이어야 한다(Session 1 잠복 버그)', () => {
  const out = parseScannerRawEnvelope(FIRED, 'fallback');
  const cred = out.find(f => f.target === 't_cred');
  assert.equal(typeof cred!.taxonomy, 'string', 'mcp_taxonomies[] 원소는 객체다 — 그대로 넣으면 안 된다');
  assert.equal(cred!.taxonomy, 'AISubtech-8.2.3');
  const exec = out.find(f => f.target === 't_exec');
  assert.equal(exec!.taxonomy, 'AISubtech-9.1.1');
});

test('taxonomy 가 여러 개라 어느 threat_name 것인지 모르면 비운다(추정하지 않는다)', () => {
  const out = parseScannerRawEnvelope(FIRED, 'fallback');
  const pd = out.filter(f => f.analyzer === 'promptdefense_analyzer');
  assert.ok(pd.every(f => f.taxonomy === undefined),
    '12 threat_names 에 6 taxonomies — 짝을 알 수 없으므로 비운다(raw 에는 전량 보존)');
  assert.ok(pd.every(f => Array.isArray((f.raw as any).mcp_taxonomies)), 'raw 에는 원본 목록이 남아야 한다');
});

test('실측 fixture 전체 팬아웃 건수 — yara 4 + readiness 1 + promptdefense 12 = 17', () => {
  const out = parseScannerRawEnvelope(FIRED, 'fallback');
  assert.equal(out.length, 17);
});

// 라이브 스캔(2026-08-22) 회귀 — threat_name 이 여럿인데 taxonomy 가 1개면 짝을 알 수 없다.
// 실제 사례: yara 가 한 도구에서 CREDENTIAL HARVESTING + DATA EXFILTRATION 2건에
// AISubtech-8.2.3 하나만 냈고, 그 하나를 양쪽에 복사한 탓에 DATA EXFILTRATION 이
// taxonomy 우선순위를 타고 secret_exposure 로 분류됐다(malicious_pattern 이어야 한다).
test('threat_name 이 여럿이면 taxonomy 1개짜리도 빌려 쓰지 않는다', () => {
  const envelope = { scan_results: [{
    tool_name: 'sync_profile',
    findings: { yara_analyzer: {
      severity: 'HIGH', total_findings: 2,
      threat_names: ['CREDENTIAL HARVESTING', 'DATA EXFILTRATION'],
      mcp_taxonomies: [{ aisubtech: 'AISubtech-8.2.3' }],
    } },
  }] };
  const out = parseScannerRawEnvelope(envelope, 'fallback');
  assert.equal(out.length, 2);
  assert.ok(out.every(f => f.taxonomy === undefined),
    '짝을 모를 때 하나를 빌려 쓰면 그건 추정이지 관측이 아니다');
});

test('threat_name 이 하나면 taxonomy 를 정상 배정한다(과잉 방어 금지)', () => {
  const envelope = { scan_results: [{
    tool_name: 'run_report',
    findings: { yara_analyzer: {
      severity: 'HIGH', total_findings: 1,
      threat_names: ['CODE EXECUTION'],
      mcp_taxonomies: [{ aisubtech: 'AISubtech-9.1.1' }],
    } },
  }] };
  const out = parseScannerRawEnvelope(envelope, 'fallback');
  assert.equal(out.length, 1);
  assert.equal(out[0].taxonomy, 'AISubtech-9.1.1');
});
