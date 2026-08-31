// Task 14 — maskValue/redact 마스킹 파이프 (A-2/C-2/테스트보강 codex 반영)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact } from '../src/masking.js';

test('matched_string 키는 값 무관 항상 마스킹(키 기반 차단)', () => {
  assert.equal(redact({ matched_string: 'plain-text-not-secret-looking' }).fields.matched_string, '***REDACTED***');
});
test('sk- 프리픽스 토큰 마스킹(값 기반)', () => {
  const fakeToken = 'sk-' + 'TESTFIXTUREVALUE1234567890AB'; // 테스트 전용 가짜 값(실제 키 아님, §0 전제사항)
  assert.equal(redact({ note: fakeToken }).fields.note, '***REDACTED***');
});
test('URL 자격증명부 마스킹', () => {
  const fakeUrl = 'https://' + 'user:p4ssw0rd@example.com/x';
  assert.equal(redact({ url: fakeUrl }).fields.url, '***REDACTED***');
});
test('평범한 문자열은 보존', () => {
  assert.equal(redact({ rule: 'credential_harvesting' }).fields.rule, 'credential_harvesting');
});

// --- 아래 4개는 시크릿 회귀 테스트보강(codex 반영) ---
test('authorization 키는 값 무관 항상 마스킹(짧은/평범한 값이어도)', () => {
  assert.equal(redact({ authorization: 'Bearer plain-looking-value' }).fields.authorization, '***REDACTED***');
});
test('짧은 토큰도 위험 키 이름이면 마스킹(엔트로피/길이 검사 무관 — KEY_DENYLIST가 별도 방어)', () => {
  assert.equal(redact({ value: 'ab12' }).fields.value, '***REDACTED***'); // 4자, ENTROPY_MIN_LEN(20) 미만
});
test('JWT 형식 토큰 마스킹(값 기반)', () => {
  // 테스트 전용 가짜 JWT — 문자열을 조각으로 나눠 조립한다. 통짜로 쓰면 시크릿 스캐너가
  // 실 토큰으로 오탐해 커밋 자체가 막힌다. 실제 서명이 아니며 payload 는 RFC 예제값이다.
  const fakeJwt = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', 'dGVzdHNpZ25hdHVyZQ'].join('.');
  assert.equal(redact({ note: fakeJwt }).fields.note, '***REDACTED***');
});
test('중첩 객체 값은 무조건 마스킹된다(과다마스킹 우선, FR-05.1) — 내부에 시크릿이 있어도 새지 않음', () => {
  const nestedSecret = 'sk-' + 'NESTEDSECRETVALUE1234567890AB';
  const result = redact({ headers: { authorization: 'Bearer ' + nestedSecret } });
  assert.equal(result.fields.headers, '***UNSUPPORTED_TYPE***');
  assert.ok(!JSON.stringify(result).includes(nestedSecret));
});

// --- 실측 raw 페이로드 회귀 (개정안 #01) ---
test('스캐너 raw 의 mcp_taxonomies 배열은 통째로 마스킹된다(배열도 중첩 취급)', () => {
  const result = redact({ mcp_taxonomies: [{ aisubtech: 'AISubtech-8.2.3' }], severity: 'HIGH', total_findings: 7 });
  assert.equal(result.fields.mcp_taxonomies, '***UNSUPPORTED_TYPE***');
  assert.equal(result.fields.severity, 'HIGH', '평범한 스칼라는 보존해야 소견서가 읽힌다');
  assert.equal(result.fields.total_findings, 7);
});
test('null·boolean·number 는 타입을 유지한 채 보존된다', () => {
  const r = redact({ a: null, b: true, c: 0 }).fields;
  assert.equal(r.a, null); assert.equal(r.b, true); assert.equal(r.c, 0);
});
test('redacted 플래그가 항상 true 다(마스킹 여부와 무관 — 소비처가 원본으로 착각하지 않게)', () => {
  assert.equal(redact({}).redacted, true);
  assert.equal(redact({ rule: 'x' }).redacted, true);
});

// --- 설정 인벤토리 경로 (2026-08-31) ---------------------------------------
// 인벤토리 절은 설정 원문을 소견서로 옮기는 유일한 경로다 — 여기서 새는 것이 가장 아프다.
// ⚠️ 아래 값은 전부 테스트 전용 가짜다(실제 키 아님, §0 전제사항).
import { redactArgs, redactCommand } from '../src/masking.js';

test('args — `--api-key=<값>` 형태는 값만 마스킹하고 플래그 이름은 남긴다', () => {
  const secret = 'sk-' + 'ARGVALUE1234567890ABCDEF';
  const out = redactArgs(['--api-key=' + secret, '--verbose']);
  assert.equal(out[0], '--api-key=***REDACTED***', '플래그 이름은 남아야 무엇이 가려졌는지 안다');
  assert.equal(out[1], '--verbose', '평범한 플래그까지 가리면 목록이 쓸모없어진다');
  assert.ok(!out.join(' ').includes(secret));
});

test('args — `--token <값>` 처럼 다음 인자로 오는 값도 플래그 이름을 키로 삼아 마스킹', () => {
  // ⚠️ 이 값은 짧고 엔트로피가 낮아 **값 기반 규칙만으로는 안 걸린다** — 앞 플래그(token)가
  //    KEY_DENYLIST 에 있어서 잡히는 경로다. 그 경로가 살아 있는지 못 박는다.
  const out = redactArgs(['--token', 'hunter2']);
  assert.equal(out[0], '--token');
  assert.equal(out[1], '***REDACTED***', '플래그 문맥이 죽으면 짧은 시크릿이 그대로 실린다');
});

test('args — 하이픈 플래그도 KEY_DENYLIST 형태로 정규화된다(--api-key → api_key)', () => {
  assert.equal(redactArgs(['--api-key', 'short1'])[1], '***REDACTED***');
  assert.equal(redactArgs(['--Password', 'short2'])[1], '***REDACTED***', '대소문자도 정규화해야 한다');
});

test('args — 평범한 경로·패키지명은 그대로 남는다(과다마스킹으로 목록이 죽지 않게)', () => {
  const out = redactArgs(['-y', '@modelcontextprotocol/server-filesystem', '/tmp']);
  assert.deepEqual(out, ['-y', '@modelcontextprotocol/server-filesystem', '/tmp']);
});

test('args — 플래그 없이 떠 있는 토큰도 값 기반 규칙으로 잡힌다', () => {
  const secret = 'ghp_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  assert.equal(redactArgs([secret])[0], '***REDACTED***');
});

test('args — URL 자격증명이 인자로 들어와도 마스킹된다', () => {
  const url = 'https://' + 'svc:hunter2hunter2@internal.example.com/mcp';
  assert.equal(redactArgs([url])[0], '***REDACTED***');
});

test('redactCommand — 평범한 커맨드는 보존, 자격증명 박힌 것은 마스킹', () => {
  assert.equal(redactCommand('npx'), 'npx');
  assert.equal(redactCommand('/usr/bin/python3'), '/usr/bin/python3');
  assert.equal(redactCommand('https://' + 'u:p4ssw0rdp4ssw0rd@host/x'), '***REDACTED***');
});

// ⚠️ 과다마스킹 회귀 (2026-08-31 실측으로 발견) — 기본 엔트로피 문턱 4.0 은 스캐너 raw 값
//    기준이라 설정 인자에는 너무 낮았다. `@modelcontextprotocol/server-github`(4.09)가 통째로
//    가려져서 "무엇이 연결돼 있는가" 절이 무의미해졌다. 양방향으로 못 박는다.
test('args 과다마스킹 — 흔한 MCP 패키지 지정자는 가려지지 않는다', () => {
  for (const pkg of [
    '@modelcontextprotocol/server-github',
    '@modelcontextprotocol/server-filesystem',
    '@modelcontextprotocol/server-slack',
    '@modelcontextprotocol/server-memory',
  ]) {
    assert.equal(redactArgs(['-y', pkg])[1], pkg, `${pkg} 가 가려지면 인벤토리가 쓸모없어진다`);
  }
});

test('args 과다마스킹 완화가 실제 토큰까지 통과시키지는 않는다(양방향 확인)', () => {
  const real = 'ghp_' + 'FAKE0123456789ABCDEFGHIJKLMNOPQRSTUV'; // 테스트 전용 가짜 값
  assert.equal(redactArgs([real])[0], '***REDACTED***', '알려진 프리픽스는 문맥 없이도 잡혀야 한다');
  // 프리픽스 없는 고엔트로피 무작위 문자열도 완화된 문턱(4.5) 위면 잡힌다.
  const highEntropy = 'Xq7Zk2Rm9Tb4Wv6Yc1Nd8Fg3Hj5Ls0Pu';
  assert.equal(redactArgs([highEntropy])[0], '***REDACTED***');
});

test('args 과다마스킹 — 플래그 문맥이 있으면 완화가 적용되지 않는다(더 엄격한 쪽 유지)', () => {
  // 패키지명처럼 생겼어도 --token 뒤에 오면 가린다. 완화는 "문맥 없는 위치 인자"에만이다.
  assert.equal(redactArgs(['--token', '@modelcontextprotocol/server-github'])[1], '***REDACTED***');
});
