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

// ── 설정 인벤토리 경로 (2026-08-31) ─────────────────────────────────────────────
// ⚠️ 인벤토리 절은 **설정 원문을 소견서로 옮기는 유일한 경로**라 시크릿 유출구가 새로 생긴다.
//    그래서 아래 두 함수는 **새 탐지 규칙을 만들지 않는다** — 위 `shouldMask()` 하나를 그대로
//    쓰고, "인자 배열"·"명령 문자열"이라는 모양을 그 판정이 먹을 수 있는 (키, 값) 쌍으로
//    바꿔주기만 한다. 탐지 규칙이 두 벌이 되면 한쪽만 고쳐지는 날이 온다.

/** `--api-key` → `api_key` 처럼, 플래그 이름을 KEY_DENYLIST 가 아는 형태로 맞춘다. */
function flagToKey(flag: string): string {
  return flag.replace(/^-+/, '').replace(/-/g, '_').toLowerCase();
}

// ⚠️ **문맥 없는 위치 인자**에만 쓰는 엔트로피 문턱. 기본 4.0 은 스캐너 raw 필드값을 기준으로
//    잡힌 값이라 설정 인자에는 너무 낮다 — 실측(2026-08-31):
//      @modelcontextprotocol/server-github     4.09  ← 4.0 을 넘어 통째로 가려졌다
//      @modelcontextprotocol/server-filesystem 3.92
//      @modelcontextprotocol/server-slack      3.89
//      ghp_FAKE...(실토큰 형태)                5.12
//    패키지명이 `***REDACTED***` 로 찍히면 "무엇이 연결돼 있는가"를 보여주려던 이 절이 무의미해지고,
//    사용자에겐 그냥 고장으로 보인다. 무작위 토큰(4.5~6.0)과 패키지명(~4.1) 사이에 선을 긋는다.
//    ⚠️ **이 완화가 무력화되는 입력**: 알려진 프리픽스(sk-/ghp_/AKIA/JWT)가 없고, 플래그
//    문맥도 없이 **맨 위치 인자로 놓인** 엔트로피 4.0~4.5 구간의 시크릿은 여기서 놓친다.
//    그 경우는 env 나 `--flag <값>` 형태로 오는 실제 설정 관행과 어긋나며, 그 두 경로는
//    각각 "값 자체를 안 읽음"·"KEY_DENYLIST" 로 따로 막힌다.
//    [조정 경로] `MCP_DISCLOSURE_ARGS_ENTROPY_BITS`
const ARGS_ENTROPY_THRESHOLD_BITS = Number(process.env.MCP_DISCLOSURE_ARGS_ENTROPY_BITS) || 4.5;

/** 플래그 문맥이 없는 위치 인자용 판정 — 값 기반 규칙은 그대로 쓰되 엔트로피 문턱만 올린다. */
function shouldMaskBareArg(value: string): boolean {
  if (TOKEN_PREFIX_RES.some(re => re.test(value))) return true;
  if (URL_CRED_RE.test(value)) return true;
  return value.length >= ENTROPY_MIN_LEN && shannonEntropy(value) >= ARGS_ENTROPY_THRESHOLD_BITS;
}

/**
 * 실행 인자 배열을 마스킹한다. 토큰·키가 args 로 넘어오는 형태가 실제로 흔하다:
 *   `["--api-key=sk-...."]`  (한 인자 안에 = 로 붙음)
 *   `["--api-key", "sk-..."]` (플래그 다음 인자가 값)
 * 두 모양 모두 **플래그 이름을 키로 삼아** shouldMask() 에 넘긴다 — 그래야 값 자체가
 * 엔트로피 문턱을 못 넘는 짧은 시크릿도 KEY_DENYLIST 로 잡힌다.
 */
export function redactArgs(args: readonly string[]): string[] {
  const out: string[] = [];
  let pendingFlag: string | undefined;
  for (const arg of args) {
    if (typeof arg !== 'string') { out.push('***UNSUPPORTED_TYPE***'); pendingFlag = undefined; continue; }

    if (arg.startsWith('-')) {
      const eq = arg.indexOf('=');
      if (eq > 0) {
        const flag = arg.slice(0, eq);
        const value = arg.slice(eq + 1);
        out.push(shouldMask(flagToKey(flag), value) ? `${flag}=***REDACTED***` : arg);
        pendingFlag = undefined;
        continue;
      }
      // 플래그 이름 자체는 값이 아니다 — 그대로 두고, 다음 인자의 키 문맥으로 기억한다.
      out.push(arg);
      pendingFlag = arg;
      continue;
    }

    // 위치 인자.
    // ⚠️ 앞선 플래그를 **무조건** 키 문맥으로 삼으면 안 된다 — `-y` 같은 불리언 플래그 뒤의
    //    패키지명까지 그 문맥으로 판정돼 통째로 가려진다(2026-08-31 실측: `npx -y @scope/pkg`).
    //    어느 플래그가 값을 받는지는 알 수 없으므로, **플래그 이름 자체가 시크릿을 가리킬 때만**
    //    문맥으로 인정한다(KEY_DENYLIST). 그 밖에는 값 자체 규칙으로 본다.
    const key = pendingFlag ? flagToKey(pendingFlag) : '';
    const masked = KEY_DENYLIST.has(key) ? true : shouldMaskBareArg(arg);
    out.push(masked ? '***REDACTED***' : arg);
    pendingFlag = undefined;
  }
  return out;
}

/** 실행 커맨드 한 개(`npx`, `/usr/bin/python` 등). 드물지만 여기에 자격증명이 박힌 경우가 있다. */
export function redactCommand(command: string): string {
  return shouldMask('', command) ? '***REDACTED***' : command;
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
