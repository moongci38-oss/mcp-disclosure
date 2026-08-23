// src/runner.ts (1/2 — buildScannerArgs만, scanOne은 Task 7)
import { spawn as nodeSpawn } from 'node:child_process';
import type { ScanTarget, Unscanned, UnscannedReason } from './types.js';

// Task 8b 실측(2026-08-22, `pip install cisco-ai-mcp-scanner`로 격리 venv 설치 후
// `mcp-scanner --help`/`config --help`/`remote --help` 직접 실행 — 버전 4.8.3):
// ①글로벌 플래그(--format/--analyzers 등)는 서브커맨드보다 **먼저** 와야 한다(argparse
//   subparsers 제약 — 뒤에 두면 "unrecognized arguments"로 즉시 실패, exit 2).
// ②로컬 설정 1개 파일 스캔은 `--config` 가 아니라 `config --config-path <path>` 서브커맨드다.
// ③원격 스캔은 `--remote <url>` 이 아니라 `remote --server-url <url>` 서브커맨드다.
// ④기본 --analyzers 값(api,yara,llm)은 MCP_SCANNER_API_KEY/MCP_SCANNER_LLM_API_KEY 미설정 시
//   대상 파일 존재 여부와 무관하게 항상 exit 1로 실패한다(실측 확인, stderr:
//   "API analyzer requested but MCP_SCANNER_API_KEY not configured"). ADR-001/002(로컬 전용,
//   외부 키 불요)를 지키려면 API/LLM/VirusTotal 키가 필요 없는 analyzer만 명시로 고정해야 한다
//   — yara(패턴탐지)·readiness(운영신뢰성 휴리스틱)·vulnerable_package(pip-audit 기반)는
//   키 없이 로컬 실행이 확인됐다(실측: 3종 조합으로 exit 0, 유효 JSON 수신).
//
// 개정안 #01(2026-08-22 승인) 추가 실측: **prompt_defense 도 키 불요다.** 4종 조합으로
// exit 0 · 62KB 유효 JSON · findings 154건을 확인했다. Session 1 이 이걸 빠뜨려서 제품
// 간판 축(prompt_injection_defense)의 주 신호원이 통째로 없었다.
// ⚠️ 출력에서 분석기 키가 **둘로 갈린다** — `prompt_defense_analyzer`(요청 이름으로 만들어진
//    빈 자리, 항상 total_findings=0)와 `promptdefense_analyzer`(실제 finding 이 담기는 곳).
//    스캐너 쪽 이름 불일치이며(report_generator.py:51 vs :65), ontology 의 signal_map 은
//    반드시 후자를 키로 써야 한다. 재현: 개정안 문서 §2.2.
const LOCAL_SAFE_ANALYZERS = ['yara', 'readiness', 'vulnerable_package', 'prompt_defense'];

export function buildScannerArgs(target: ScanTarget, opts: { allowRemote: boolean }): string[] | null {
  if (target.transport === 'remote' && !opts.allowRemote) {
    return null; // argv 에 절대 넣지 않는다 — ADR-006
  }
  const globalArgs = ['--format', 'raw', '--analyzers', LOCAL_SAFE_ANALYZERS.join(',')];
  if (target.transport === 'remote') {
    return [...globalArgs, 'remote', '--server-url', target.remoteUrl!];
  }
  return [...globalArgs, 'config', '--config-path', target.sourcePath];
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
//   [조정 경로] `MCP_DISCLOSURE_MAX_OUTPUT_BYTES` 환경변수(v0는 CLI 플래그 미제공, YAGNI).
const DEFAULT_TIMEOUT_MS = 120_000;                                              // 120초
const MAX_OUTPUT_BYTES = Number(process.env.MCP_DISCLOSURE_MAX_OUTPUT_BYTES) || 64 * 1024 * 1024; // 64MB(67,108,864바이트)
const MAX_STDERR_CHARS = 4096; // stderr는 진단용일 뿐 findings 소스가 아니므로 작게 캡

export type ScanOneOpts = {
  allowRemote: boolean;
  timeoutMs?: number;
  scannerBin?: string;          // 테스트 전용 오버라이드(기본 'mcp-scanner')
  scannerArgsOverride?: string[]; // 테스트 전용
};

// B-1 codex 반영: 종전엔 파싱 실패 시 원인 분류가 scanOne 안에 인라인으로 뭉개져 있었다.
// ADR-007이 요구하는 "Session 1 실측 exit code 표"가 들어갈 자리를 명시적인 별도 함수로
// 분리한다.
// Task 8b 실측(2026-08-22, cisco-ai-mcp-scanner 4.8.3, 격리 venv):
//   exit 0 — 정상 종료. stdout이 유효 JSON(봉투)이며 이 경우 위 close 핸들러가 이 함수 자체를
//     호출하지 않는다(ADR-007 1차 판정 성공 경로). 서버 연결 실패(예: MCP 핸드셰이크 불가)도
//     여기 해당 — 실패는 stderr 로그로만 남고 exit 0 + `scan_results: []`로 조용히 계속된다.
//   exit 1 — 스캐너 자체의 치명적 오류(설정 파일 파싱 실패 `FileNotFoundError`,
//     또는 요청한 analyzer에 필요한 API/LLM 키 미설정). stdout은 항상 비어 있다(0바이트) —
//     JSON.parse가 반드시 실패하므로 이 함수가 정확히 호출되는 경로다(실측 재현: 존재하지 않는
//     --config-path 지정 → exit 1, stdout 0바이트, stderr에 Python traceback).
//   exit 2 — argparse 인자 파싱 오류(예: 존재하지 않는 플래그, 서브커맨드 뒤에 온 글로벌 플래그).
//     실측 재현: `mcp-scanner --version`(존재하지 않는 플래그) → exit 2, "unrecognized arguments".
const EXIT_CODE_MEANING: Record<number, string> = {
  0: 'scanner completed (should not reach here — stdout parsed as JSON already)',
  1: 'scanner fatal error — invalid --config-path, or a requested analyzer is missing its required API/LLM key',
  2: 'argument parsing error — invalid/unrecognized CLI flag or flag ordering (global flags must precede the subcommand)',
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

// src/runner.ts (3/3 — runScanner 추가)
export type RunnerResult = {
  rawByTarget: Map<string, unknown>;
  unscanned: Unscanned[];
  usedRemoteTargets: ScanTarget[];
};

export async function runScanner(targets: ScanTarget[], opts: ScanOneOpts, deps: ScanDeps = DEFAULT_DEPS): Promise<RunnerResult> {
  const rawByTarget = new Map<string, unknown>();
  const unscanned: Unscanned[] = [];
  const usedRemoteTargets: ScanTarget[] = [];

  for (const target of targets) {
    const { raw, unscanned: u } = await scanOne(target, opts, deps);
    if (u) { unscanned.push(u); continue; }
    rawByTarget.set(target.sourcePath + '#' + target.name, raw);
    if (target.transport === 'remote') usedRemoteTargets.push(target);
  }
  return { rawByTarget, unscanned, usedRemoteTargets };
}
