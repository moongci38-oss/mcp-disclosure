import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Unscanned, UnscannedReason } from '../src/types.js'; // 아직 미정의 → 컴파일 실패

test('Unscanned 타입이 존재한다(컴파일 스모크)', () => {
  const u: Unscanned = {
    target: { kind: 'mcp_server', sourcePath: '/x', name: 'y', transport: 'local_stdio' },
    reason: 'timeout' as UnscannedReason,
  };
  assert.equal(u.reason, 'timeout');
});
