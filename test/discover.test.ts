import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discover } from '../src/discover.js';

test('설정 파일 0건 → targets 0, scannedPaths 4개 이상', () => {
  const dir = mkdtempSync(join(tmpdir(), 'agenttrust-'));
  const result = discover(dir);
  assert.equal(result.targets.length, 0);
  assert.ok(result.scannedPaths.length >= 4);
});

test('.mcp.json의 remote 서버가 transport:remote로 분류됨', () => {
  const dir = mkdtempSync(join(tmpdir(), 'agenttrust-'));
  writeFileSync(join(dir, '.mcp.json'), JSON.stringify({
    mcpServers: {
      local: { command: 'node', args: ['server.js'] },
      cloud: { url: 'https://example.internal/mcp', type: 'sse' },
    },
  }));
  const result = discover(dir);
  const remote = result.targets.find(t => t.name === 'cloud');
  const local = result.targets.find(t => t.name === 'local');
  assert.equal(remote?.transport, 'remote');
  assert.equal(local?.transport, 'local_stdio');
});
