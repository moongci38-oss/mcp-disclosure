import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { runScanner } from '../src/runner.js';
import type { ScanTarget } from '../src/types.js';
import type { ScanDeps, SpawnFn } from '../src/runner.js';

// 실제 child_process.spawn 을 흉내내는 fake — ScanDeps 주입 지점(Task 7 설계)을 그대로 사용한다.
// (스펙 §8.5 Task 7 주석: t.mock.method 로 ESM spawn 을 스파이하면 "Cannot redefine property"로
// 테스트 자체가 실행되지 않는다 — 그래서 설계가 spawn 을 인자로 받는다.)
test('target 3개 중 1개 실패 → unscanned 1건, 나머지 2건 성공', async () => {
  const targets: ScanTarget[] = [
    { kind: 'mcp_server', sourcePath: '/a', name: 'a', transport: 'local_stdio' },
    { kind: 'mcp_server', sourcePath: '/b', name: 'b', transport: 'local_stdio' },
    { kind: 'mcp_server', sourcePath: '/c', name: 'c', transport: 'local_stdio' },
  ];

  let call = 0;
  const spawn: SpawnFn = (() => {
    const child: any = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => {};
    const idx = call++;
    queueMicrotask(() => {
      if (idx === 1) {
        // 2번째 target(b)만 실패(파싱 불가 stdout + 비정상 exit code)
        child.stderr.emit('data', Buffer.from('boom'));
        child.emit('close', 1);
      } else {
        child.stdout.emit('data', Buffer.from(JSON.stringify({ server_url: 'x', scan_results: [] })));
        child.emit('close', 0);
      }
    });
    return child;
  }) as unknown as SpawnFn;

  const deps: ScanDeps = { spawn };
  const results = await runScanner(targets, { allowRemote: false }, deps);
  assert.equal(results.unscanned.length, 1);
  assert.equal(results.rawByTarget.size, 2);
});
