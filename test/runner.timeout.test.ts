import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanOne } from '../src/runner.js';
import type { ScanTarget } from '../src/types.js';

test('타임아웃 시 unscanned(timeout) 반환', async () => {
  const target: ScanTarget = { kind: 'mcp_server', sourcePath: '/x', name: 'slow', transport: 'local_stdio' };
  // scanOne 내부의 spawn 대상은 테스트 환경에서 'sleep 5' 등 지연 실행 바이너리로 대체
  const result = await scanOne(target, { allowRemote: false, timeoutMs: 50, scannerBin: 'sleep', scannerArgsOverride: ['5'] });
  assert.equal(result.unscanned?.reason, 'timeout');
});

// A-5 codex 반영 — 스캐너 미가용(바이너리 부재) 테스트. 실제로 존재하지 않는 경로를 spawn해
// Node의 진짜 ENOENT 'error' 이벤트를 트리거한다(모킹 불필요, 크로스플랫폼으로 재현 가능).
test('스캐너 바이너리 미설치(ENOENT) → unscanned(scanner_error) + 설치 안내 문구 포함', async () => {
  const target: ScanTarget = { kind: 'mcp_server', sourcePath: '/x', name: 'missing', transport: 'local_stdio' };
  const result = await scanOne(target, {
    allowRemote: false,
    scannerBin: '/nonexistent/path/to/mcp-scanner-binary-that-does-not-exist',
  });
  assert.equal(result.unscanned?.reason, 'scanner_error');
  assert.ok(result.unscanned?.detail?.toLowerCase().includes('not found'), `실제 detail: ${result.unscanned?.detail}`);
});
