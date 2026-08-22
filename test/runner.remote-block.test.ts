import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildScannerArgs } from '../src/runner.js';
import type { ScanTarget } from '../src/types.js';

const remoteTarget: ScanTarget = {
  kind: 'mcp_server', sourcePath: '/x/.mcp.json', name: 'remote-srv',
  transport: 'remote', remoteUrl: 'https://example.internal/mcp',
};
const localTarget: ScanTarget = {
  kind: 'mcp_server', sourcePath: '/x/.mcp.json', name: 'local', transport: 'local_stdio',
};

test('remote 대상 + allowRemote:false → argv 미생성(null)', () => {
  assert.equal(buildScannerArgs(remoteTarget, { allowRemote: false }), null);
});
test('remote 대상 + allowRemote:true → argv에 URL 포함 + 실측 CLI 형태(remote 서브커맨드 + --server-url)', () => {
  // Task 8b 실측(2026-08-22, cisco-ai-mcp-scanner 4.8.3): 글로벌 플래그(--format/--analyzers)는
  // 서브커맨드보다 먼저 와야 한다(argparse subparsers 제약, 뒤에 두면 "unrecognized arguments").
  // 원격 스캔은 `remote --server-url <url>` 서브커맨드이며, Task 6 초안의 `--remote <url>`은
  // 실제로 존재하지 않는 플래그였다.
  const args = buildScannerArgs(remoteTarget, { allowRemote: true });
  assert.ok(args && args.includes('https://example.internal/mcp'));
  assert.ok(args && args.includes('remote'));
  assert.ok(args && args.includes('--server-url'));
  const remoteIdx = args!.indexOf('remote');
  assert.equal(args![remoteIdx + 1], '--server-url', 'remote 서브커맨드 바로 다음에 --server-url이 와야 한다(argparse subparsers 순서 제약)');
  assert.equal(args![remoteIdx + 2], 'https://example.internal/mcp');
});
test('local 대상은 항상 argv 생성 — 실측 CLI 형태(config 서브커맨드 + --config-path + API키 불필요 analyzers)', () => {
  // Task 8b 실측: `mcp-scanner --config <path>`는 존재하지 않는 플래그다(실제는
  // `mcp-scanner config --config-path <path>` 서브커맨드). 또한 기본 --analyzers(api,yara,llm)는
  // MCP_SCANNER_API_KEY/MCP_SCANNER_LLM_API_KEY 미설정 시 exit 1로 항상 실패한다(실측 확인) —
  // ADR-001/002(로컬·키 불요) 준수를 위해 로컬 실행 가능한 analyzer만 명시로 고정한다.
  const args = buildScannerArgs(localTarget, { allowRemote: false });
  assert.ok(args && !args.includes('--config'), '--config는 실제 CLI에 존재하지 않는 플래그다');
  assert.ok(args && args.includes('config'));
  assert.ok(args && args.includes('--config-path'));
  assert.ok(args && args.includes(localTarget.sourcePath));
  assert.ok(args && args.includes('--analyzers'));
  const analyzerIdx = args!.indexOf('--analyzers');
  const analyzerValue = args![analyzerIdx + 1];
  for (const forbidden of ['api', 'llm', 'virustotal']) {
    assert.ok(!analyzerValue.split(',').includes(forbidden), `${forbidden} analyzer는 API/LLM 키를 요구해 로컬 전용 실행과 충돌한다`);
  }
});
