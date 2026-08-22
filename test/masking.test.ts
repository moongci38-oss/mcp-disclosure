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
