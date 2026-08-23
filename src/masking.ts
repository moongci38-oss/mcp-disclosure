// src/masking.ts — 마스킹 파이프 (FR-05.1/05.2)
// A-2 codex 반영 — 정의는 §5.1 types.ts, 여기선 import 후 재노출만 한다
import type { RedactedRaw } from './types.js';
export type { RedactedRaw };

// A-3/시크릿 회귀 테스트보강 codex 반영: authorization/password/token/api_key/secret 을
// KEY_DENYLIST 에 추가했다 — 이 키들은 값의 길이·엔트로피와 무관하게 항상 마스킹한다.
const KEY_DENYLIST = new Set([
  'matched_string', 'snippet', 'match', 'evidence_text', 'value',
  'authorization', 'password', 'token', 'api_key', 'apikey', 'secret',
]);

const TOKEN_PREFIX_RES = [
  /^sk-[A-Za-z0-9_-]{16,}$/, /^ghp_[A-Za-z0-9]{30,}$/, /^AKIA[A-Z0-9]{12,}$/,
  // 시크릿 회귀 테스트보강(codex 반영) — JWT(header.payload.signature, base64url 3파트)
  /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/,
];
const URL_CRED_RE = /:\/\/[^/\s:@]+:[^/\s@]+@/;

// ⚠️ 근거/영향/조정경로 (C-2 codex 반영 — 임의값이 아니라 트레이드오프 산출물이다):
// ENTROPY_THRESHOLD_BITS=4.0: 영어 자연어 텍스트의 문자당 엔트로피는 통상 4.0bits/char 미만,
//   base64/hex 같은 무작위 토큰은 ~4.5~6.0bits/char 다 — 4.0 을 컷라인으로 삼으면 자연어 오탐이 준다.
//   [빗나갈 때 영향] 낮추면(3.0) 평범한 식별자 문자열까지 마스킹돼 소견서 가독성이 떨어진다.
//   올리면(5.0) 약한 무작위성의 토큰(짧은 시크릿)을 놓친다.
//   [조정 경로] `MCP_DISCLOSURE_ENTROPY_BITS` 환경변수(v0 는 CLI 플래그 미제공, YAGNI).
// ENTROPY_MIN_LEN=20: ⚠️ **시크릿은 20자 미만도 흔하다**(8자리 PIN, 짧은 API 키 등) — 이
//   엔트로피 검사 *단독*으로는 짧은 시크릿을 놓친다. 그것이 이 검사의 유일한 방어선이 아닌
//   이유다: `KEY_DENYLIST`(위)는 값 길이·엔트로피와 무관하게 항상 마스킹한다 — 짧은 시크릿이
//   위험 키 이름(matched_string/authorization/token 등)으로 반환되면 여기서 잡힌다. 이
//   엔트로피 검사는 "임의 필드명으로 새어나온 긴 무작위 문자열"만 보완적으로 잡는 2차 방어선이다.
//   [조정 경로] `MCP_DISCLOSURE_ENTROPY_MIN_LEN` 환경변수.
const ENTROPY_THRESHOLD_BITS = Number(process.env.MCP_DISCLOSURE_ENTROPY_BITS) || 4.0; // bits/char
const ENTROPY_MIN_LEN = Number(process.env.MCP_DISCLOSURE_ENTROPY_MIN_LEN) || 20;

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

function shouldMask(key: string, value: unknown): boolean {
  if (KEY_DENYLIST.has(key)) return true;
  if (typeof value !== 'string') return false;
  if (TOKEN_PREFIX_RES.some(re => re.test(value))) return true;
  if (URL_CRED_RE.test(value)) return true;
  if (value.length >= ENTROPY_MIN_LEN && shannonEntropy(value) >= ENTROPY_THRESHOLD_BITS) return true;
  return false;
}

export function redact(raw: Record<string, unknown>): RedactedRaw {
  const fields: Record<string, string | number | boolean | null> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (shouldMask(key, value)) {
      fields[key] = '***REDACTED***';
    } else if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' || value === null) {
      fields[key] = value;
    } else {
      // 중첩 객체(및 배열)는 개별 필드 검사 없이 통째로 마스킹한다 — "과다마스킹이 과소마스킹보다
      // 안전"(FR-05.1) 원칙의 실제 적용 지점. 내부에 시크릿이 있어도 이 한 줄이 막는다.
      fields[key] = '***UNSUPPORTED_TYPE***';
    }
  }
  return { redacted: true, fields };
}
