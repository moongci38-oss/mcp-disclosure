// src/runner.ts (1/2 — buildScannerArgs만, scanOne은 Task 7)
import { spawn as nodeSpawn } from 'node:child_process';
import type { ScanTarget, Unscanned, UnscannedReason } from './types.js';

// ⚠️ 실제 mcp-scanner CLI 플래그는 미실측(§0 전제사항) — Session 1 `mcp-scanner --help` 실측 후
// 이 함수만 교체한다. 그 외 어떤 모듈도 이 함수의 인자 형식에 의존하지 않는다.
export function buildScannerArgs(target: ScanTarget, opts: { allowRemote: boolean }): string[] | null {
  if (target.transport === 'remote' && !opts.allowRemote) {
    return null; // argv 에 절대 넣지 않는다 — ADR-006
  }
  if (target.transport === 'remote') {
    return ['--format', 'raw', '--remote', target.remoteUrl!];
  }
  return ['--format', 'raw', '--config', target.sourcePath];
}

// src/runner.ts (2/2 — scanOne 추가)
// ⚠️ spawn 은 **주입 가능**해야 한다 (codex 2회차 High 반영).
// 종전 설계는 테스트에서 `t.mock.method(cp, 'spawn', …)` 로 스파이하려 했으나,
// ESM namespace 의 property 는 재정의할 수 없어 `TypeError: Cannot redefine property: spawn`
// 이 난다. 게다가 named import 로 이미 바인딩된 참조는 사후 교체가 안 된다.
// → 즉 그 테스트는 **작성해도 실행되지 않는다**(존재하지만 작동하지 않는 방어).
// 해법은 mock 기법이 아니라 설계다: spawn 을 인자로 받아 테스트가 fake 를 넘긴다.
export type SpawnFn = typeof nodeSpawn;
export type ScanDeps = { spawn: SpawnFn };
const DEFAULT_DEPS: ScanDeps = { spawn: nodeSpawn };

// ⚠️ 근거/영향/조정경로 (C-2 codex 반영 — 임의값이 아니라 트레이드오프 산출물이다):
// DEFAULT_TIMEOUT_MS=120,000(120초): mcp-scanner 실제 스캔 소요시간 분포가 미실측(§0 전제사항)이라
//   "정상 스캔을 너무 짧게 잘라내는 실패"를 피하는 쪽으로 넉넉히 잡았다.
//   [빗나갈 때 영향] 너무 짧으면 느린 분석기(LLM/VirusTotal 등)가 정상인데 timeout으로 잘린다.
//   너무 길면 실제로 멈춘 스캐너를 오래 기다려 §3 NFR "10분 목표"를 해친다.
//   [조정 경로] CLI `--scan-timeout <ms>` 플래그(§2.1 FR-01 시그니처)로 사용자가 직접 조정.
// MAX_OUTPUT_BYTES=64MB: 정상적인 단일 설정 스캔 결과가 이 크기를 넘을 이유가 없다는 가정(미실측
//   추정치) — stdout 전체를 문자열로 누적하는 v0 구현(§6.2 "스트리밍 파싱 안 함")의 안전판이다.
//   [빗나갈 때 영향] 너무 작으면 findings가 많은 정당한 설정이 잘린다. 너무 크면 악성/버그 스캐너
//   출력이 메모리를 과다 점유한다.
//   [조정 경로] `AGENTTRUST_MAX_OUTPUT_BYTES` 환경변수(v0는 CLI 플래그 미제공, YAGNI).
const DEFAULT_TIMEOUT_MS = 120_000;                                              // 120초
const MAX_OUTPUT_BYTES = Number(process.env.AGENTTRUST_MAX_OUTPUT_BYTES) || 64 * 1024 * 1024; // 64MB(67,108,864바이트)
const MAX_STDERR_CHARS = 4096; // stderr는 진단용일 뿐 findings 소스가 아니므로 작게 캡

export type ScanOneOpts = {
  allowRemote: boolean;
  timeoutMs?: number;
  scannerBin?: string;          // 테스트 전용 오버라이드(기본 'mcp-scanner')
  scannerArgsOverride?: string[]; // 테스트 전용
};

// B-1 codex 반영: 종전엔 파싱 실패 시 원인 분류가 scanOne 안에 인라인으로 뭉개져 있었다.
// ADR-007이 요구하는 "Session 1 실측 exit code 표"가 들어갈 자리를 명시적인 별도 함수로
// 분리한다 — Task 8b가 EXIT_CODE_MEANING을 채운다.
// ⚠️ Task 8b 실측 확정 필요: 아래 표는 비어 있다(실제 mcp-scanner exit code 관행 미실측).
const EXIT_CODE_MEANING: Record<number, string> = {
  // 127: 'shell: command not found',  // 예시 — Task 8b가 실제 값으로 채운다
};

export function classifyScannerFailure(exitCode: number | null, stderr: string, stdout: string): { reason: UnscannedReason; detail: string } {
  // ADR-007: exit code는 참고용일 뿐 1차 판정이 아니다 — 이 함수는 stdout JSON 파싱이 이미
  // 실패한 뒤에만 호출된다.
  const meaning = exitCode !== null ? EXIT_CODE_MEANING[exitCode] : undefined;
  return {
    reason: 'scanner_error',
    detail: meaning ?? `unparsed stdout (exit=${exitCode ?? 'null'}): stderr=${stderr.slice(0, 200)} stdout=${stdout.slice(0, 200)}`,
  };
}

export async function scanOne(
  target: ScanTarget,
  opts: ScanOneOpts,
  deps: ScanDeps = DEFAULT_DEPS,   // ← 테스트가 fake spawn 을 넘기는 지점
): Promise<{ raw?: unknown; unscanned?: Unscanned }> {
  const spawn = deps.spawn;
  const args = opts.scannerArgsOverride ?? buildScannerArgs(target, opts);
  if (args === null) return { unscanned: { target, reason: 'remote_out_of_scope' } };

  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const bin = opts.scannerBin ?? 'mcp-scanner';

  return new Promise((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(bin, args);
    } catch (e) {
      // A-5 codex 반영: 동기 spawn 예외(권한 오류 등 플랫폼에 따라 여기로 온다)
      resolve({ unscanned: { target, reason: 'scanner_error', detail: `spawn threw synchronously: ${(e as Error).message}` } });
      return;
    }

    let stdout = '';
    let stderr = '';
    let bytes = 0;
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      resolve({ unscanned: { target, reason: 'timeout', detail: `>${timeoutMs}ms` } });
    }, timeoutMs);

    // A-5 codex 반영: 종전엔 'error' 핸들러가 없어 스캐너 미설치(ENOENT)·권한오류 시 Promise가
    // 영원히 pending 상태로 방치됐다(F-01g "설치 안내 1줄"과 정면 불일치).
    child.on('error', (err: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const detail = err.code === 'ENOENT'
        ? `scanner binary '${bin}' not found — install: pip install cisco-ai-mcp-scanner`
        : `spawn error (${err.code ?? 'unknown'}): ${err.message}`;
      resolve({ unscanned: { target, reason: 'scanner_error', detail } });
    });

    child.stdout!.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_OUTPUT_BYTES) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.kill('SIGKILL');
        resolve({ unscanned: { target, reason: 'output_too_large', detail: `>${MAX_OUTPUT_BYTES}bytes` } });
        return;
      }
      stdout += chunk.toString('utf8');
    });

    // A-5 codex 반영: stderr 미수집이었다 — classifyScannerFailure의 진단 정보 소스로 캡 후 수집.
    child.stderr!.on('data', (chunk: Buffer) => {
      if (stderr.length < MAX_STDERR_CHARS) stderr += chunk.toString('utf8');
    });

    child.on('close', (exitCode) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        resolve({ raw: JSON.parse(stdout) }); // ADR-007: exit code 무시, stdout 파싱 성공이 1차 판정
      } catch {
        const { reason, detail } = classifyScannerFailure(exitCode, stderr, stdout);
        resolve({ unscanned: { target, reason, detail } });
      }
    });
  });
}
