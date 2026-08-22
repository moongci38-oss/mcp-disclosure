// src/runner.ts (1/2 — buildScannerArgs만, scanOne은 Task 7)
import type { ScanTarget } from './types.js';

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
