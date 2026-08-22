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
test('remote 대상 + allowRemote:true → argv에 URL 포함', () => {
  const args = buildScannerArgs(remoteTarget, { allowRemote: true });
  assert.ok(args && args.includes('https://example.internal/mcp'));
});
test('local 대상은 항상 argv 생성', () => {
  const args = buildScannerArgs(localTarget, { allowRemote: false });
  assert.ok(args && args.includes('--config'));
});
