// Task 24 — 원격 차단 E2E: spawn 스파이 (AC-01d, B-2 codex 반영)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
// ⚠️ `SpawnFn` 을 함께 import 한다 — 빠지면 `Cannot find name 'SpawnFn'` 로 빌드가 깨진다.
//    `node:child_process` 는 import 하지 않는다: 주입 방식이라 mock 대상이 없다.
import { runScanner, type SpawnFn } from '../src/runner.js';
import type { ScanTarget } from '../src/types.js';

// ⚠️ **스파이는 mock 라이브러리가 아니라 주입으로 만든다**(codex 2회차 High).
// `t.mock.method(cp, 'spawn', …)` 방식은 실행 자체가 안 된다 — ESM namespace property 는
// 재정의 불가라 `TypeError: Cannot redefine property: spawn` 이 나고, named import 로 잡힌
// 바인딩은 사후 교체도 안 된다. "보강했다"고 적어놓고 돌지 않는 테스트가 이 프로젝트의
// 반복 실패 모드였다.
function makeSpawnSpy() {
  const calls: string[][] = [];
  const spawn = ((bin: string, args: string[]) => {
    calls.push([bin, ...args]);
    const fake = new EventEmitter() as any;
    fake.stdout = new EventEmitter();
    fake.stderr = new EventEmitter();
    process.nextTick(() => { fake.stdout.emit('data', Buffer.from('{}')); fake.emit('close', 0); });
    return fake;
  }) as unknown as SpawnFn;
  return { spawn, calls };
}

const remoteTarget: ScanTarget = {
  kind: 'mcp_server', sourcePath: '/x/.mcp.json', name: 'remote-srv',
  transport: 'remote', remoteUrl: 'https://example.internal/mcp',
};
const localTarget: ScanTarget = {
  kind: 'mcp_server', sourcePath: '/x/.mcp.json', name: 'local-srv', transport: 'local_stdio',
};

// B-2 codex 반영: 종전 테스트는 spawn 호출 여부를 확인하지 않아, remote 대상 1개뿐인 이
// 시나리오에서 "0-length array 순회"가 공허하게 통과했다. 메커니즘을 직접 본다.
test('E2E — remote target(allowRemote:false) → spawn 자체가 호출되지 않고 unscanned 로 남는다', async () => {
  const spy = makeSpawnSpy();
  const result = await runScanner([remoteTarget], { allowRemote: false }, { spawn: spy.spawn });

  assert.equal(spy.calls.length, 0, 'remote 대상은 spawn 에 도달하면 안 된다(argv 를 비우는 게 아니라 애초에 호출 안 함)');
  assert.equal(result.unscanned.length, 1);
  assert.equal(result.unscanned[0].reason, 'remote_out_of_scope');
  assert.equal(result.unscanned[0].target.name, 'remote-srv');
});

test('E2E — --allow-remote 시엔 spawn 이 정확히 1회 호출되고 argv 에 URL 포함', async () => {
  const spy = makeSpawnSpy();
  const result = await runScanner([remoteTarget], { allowRemote: true }, { spawn: spy.spawn });

  assert.equal(spy.calls.length, 1, '--allow-remote 면 spawn 이 정확히 1회 호출돼야 한다');
  assert.ok(spy.calls[0].join(' ').includes('example.internal'), 'allow-remote 시 argv 에 URL 이 있어야 한다');
  assert.equal(result.unscanned.length, 0);
});

// 혼합 입력이 실제 사용 형태다 — 하나 막혔다고 나머지가 통째로 멈추면 안 된다(AC-01c).
test('E2E — local+remote 혼합(allowRemote:false) → local 만 스캔되고 remote 는 unscanned', async () => {
  const spy = makeSpawnSpy();
  const result = await runScanner([localTarget, remoteTarget], { allowRemote: false }, { spawn: spy.spawn });

  assert.equal(spy.calls.length, 1, 'local 1건만 spawn 돼야 한다');
  const argv = spy.calls[0].join(' ');
  assert.ok(!argv.includes('example.internal'), '원격 URL 이 argv 에 절대 실리면 안 된다(ADR-006)');
  assert.ok(argv.includes('/x/.mcp.json'));
  assert.equal(result.unscanned.length, 1);
  assert.equal(result.unscanned[0].target.name, 'remote-srv');
});

// argv 전량 검사 — 원격 URL 의 어떤 조각도 프로세스 인자에 남지 않아야 한다.
test('E2E — 차단 시 spawn argv 전체에 원격 호스트 문자열이 0건', async () => {
  const spy = makeSpawnSpy();
  await runScanner([localTarget, remoteTarget], { allowRemote: false }, { spawn: spy.spawn });
  const allArgv = spy.calls.flat().join(' ');
  for (const frag of ['example.internal', 'https://', 'remote', '--server-url']) {
    assert.ok(!allArgv.includes(frag), `차단됐는데 argv 에 "${frag}" 가 남았다`);
  }
});
