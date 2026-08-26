// 분석기 분리 실행(2026-08-24) — 상류 버그 회피가 실제로 배선됐는지 검증한다.
//
// 무엇을 막는 테스트인가: mcp-scanner 4.8.3 은 YARA 파라미터 스캔에서
// `del tool_data["description"]` 으로 도구 정의 원본을 지우고 그 dict 를 readiness 에 넘긴다.
// 그래서 **두 분석기가 한 실행에 같이 들어가면** readiness 가 설명 없는 도구를 보게 되고,
// HEUR-009 가 거짓 양성으로 붙고 HEUR-017·019 가 거짓 음성으로 사라진다.
// 실측 대조표: docs/research/2026-08-24-scanner-module-call-poc.md §3
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import {
  SCANNER_PASSES,
  buildScannerPasses,
  buildScannerArgs,
  scanOne,
  type SpawnFn,
} from '../src/runner.js';
import { mergeScannerRawEnvelopes } from '../src/scanner-envelope.js';
import type { ScanTarget } from '../src/types.js';

const localTarget: ScanTarget = {
  kind: 'mcp_server', sourcePath: '/x/.mcp.json', name: 'local-srv', transport: 'local_stdio',
};

// ── pass 구성 ────────────────────────────────────────────────────────────────

test('readiness 와 yara 가 같은 pass 에 들어가면 안 된다 — 이 분리가 버그 회피의 전부다', () => {
  for (const pass of SCANNER_PASSES) {
    const hasReadiness = pass.analyzers.includes('readiness');
    const hasYara = pass.analyzers.includes('yara');
    assert.ok(
      !(hasReadiness && hasYara),
      `pass '${pass.name}' 에 readiness 와 yara 가 함께 있다 — YARA 가 도구 설명을 지우고 넘겨 readiness 결과가 왜곡된다`,
    );
  }
});

test('pass 를 다 합치면 키 불요 4종이 그대로 남는다 — 분리하느라 커버리지를 잃지 않았다', () => {
  const union = new Set(SCANNER_PASSES.flatMap((p) => p.analyzers));
  for (const need of ['yara', 'readiness', 'vulnerable_package', 'prompt_defense']) {
    assert.ok(union.has(need), `${need} 가 어느 pass 에도 없다 — 분리하면서 통째로 흘렸다`);
  }
  // API 키를 요구하는 분석기는 어느 pass 에도 들어가면 안 된다(ADR-001/002 로컬 전용).
  for (const forbidden of ['api', 'llm', 'virustotal']) {
    assert.ok(!union.has(forbidden), `${forbidden} 는 외부 키를 요구해 로컬 전용 실행과 충돌한다`);
  }
});

test('buildScannerPasses — pass 마다 자기 analyzer 만 argv 에 싣는다', () => {
  const passes = buildScannerPasses(localTarget, { allowRemote: false });
  assert.ok(passes);
  assert.equal(passes!.length, SCANNER_PASSES.length);
  for (const { pass, args } of passes!) {
    const value = args[args.indexOf('--analyzers') + 1].split(',');
    assert.deepEqual(value, pass.analyzers, `pass '${pass.name}' argv 의 analyzers 가 pass 정의와 다르다`);
  }
});

test('buildScannerArgs 기본값은 4종 유지 — 기존 호출부·테스트 하위호환', () => {
  const args = buildScannerArgs(localTarget, { allowRemote: false });
  const value = args![args!.indexOf('--analyzers') + 1].split(',');
  assert.deepEqual(value.sort(), ['prompt_defense', 'readiness', 'vulnerable_package', 'yara']);
});

// ── 봉투 병합 ────────────────────────────────────────────────────────────────

const envA = {
  requested_analyzers: ['readiness'],
  scan_results: [
    { item_type: 'tool', server_name: 's', tool_name: 'alpha', is_safe: true,
      findings: { readiness_analyzer: { severity: 'LOW', total_findings: 3, threat_names: [] } } },
  ],
};
const envB = {
  requested_analyzers: ['yara', 'prompt_defense'],
  scan_results: [
    { item_type: 'tool', server_name: 's', tool_name: 'alpha', is_safe: false,
      findings: { yara_analyzer: { severity: 'HIGH', total_findings: 1, threat_names: ['CODE EXECUTION'] } } },
    { item_type: 'tool', server_name: 's', tool_name: 'beta', is_safe: true,
      findings: { yara_analyzer: { severity: 'SAFE', total_findings: 0, threat_names: [] } } },
  ],
};

test('병합 — 같은 도구의 분석기 결과가 한 항목으로 합쳐진다', () => {
  const merged = mergeScannerRawEnvelopes([envA, envB]) as typeof envB;
  const alpha = merged.scan_results.find((e: any) => e.tool_name === 'alpha')! as any;
  assert.ok(alpha.findings.readiness_analyzer, 'readiness pass 결과가 사라졌다');
  assert.ok(alpha.findings.yara_analyzer, 'pattern pass 결과가 사라졌다');
  assert.equal(alpha.findings.readiness_analyzer.total_findings, 3);
  assert.equal(alpha.findings.yara_analyzer.threat_names[0], 'CODE EXECUTION');
});

test('병합 — 한쪽에만 있는 도구도 빠지지 않는다', () => {
  const merged = mergeScannerRawEnvelopes([envA, envB]) as typeof envB;
  assert.equal(merged.scan_results.length, 2, 'alpha·beta 둘 다 남아야 한다');
  assert.ok(merged.scan_results.some((e: any) => e.tool_name === 'beta'));
});

test('병합 — is_safe 는 낙관하지 않는다(하나라도 false 면 false)', () => {
  const merged = mergeScannerRawEnvelopes([envA, envB]) as any;
  const alpha = merged.scan_results.find((e: any) => e.tool_name === 'alpha');
  assert.equal(alpha.is_safe, false, 'readiness 가 safe 라고 해서 yara 의 HIGH 를 덮으면 안 된다');
});

test('병합 — requested_analyzers 는 합집합', () => {
  const merged = mergeScannerRawEnvelopes([envA, envB]) as any;
  assert.deepEqual(merged.requested_analyzers.sort(), ['prompt_defense', 'readiness', 'yara']);
});

test('병합 — 빈 입력에도 죽지 않고 빈 봉투를 준다', () => {
  const merged = mergeScannerRawEnvelopes([null, undefined, 'not-an-object']) as any;
  assert.deepEqual(merged.scan_results, []);
});

// ── scanOne 통합 ─────────────────────────────────────────────────────────────

function spawnSpy(perCall: (n: number) => { stdout: string; exit: number }) {
  const calls: string[][] = [];
  const spawn = ((bin: string, args: string[]) => {
    const n = calls.length;
    calls.push([bin, ...args]);
    const { stdout, exit } = perCall(n);
    const fake = new EventEmitter() as any;
    fake.stdout = new EventEmitter();
    fake.stderr = new EventEmitter();
    fake.kill = () => {};
    process.nextTick(() => { fake.stdout.emit('data', Buffer.from(stdout)); fake.emit('close', exit); });
    return fake;
  }) as unknown as SpawnFn;
  return { spawn, calls };
}

test('scanOne — pass 수만큼 스캐너를 부르고 결과를 합쳐서 돌려준다', async () => {
  const spy = spawnSpy((n) => ({ stdout: JSON.stringify(n === 0 ? envA : envB), exit: 0 }));
  const { raw, unscanned } = await scanOne(localTarget, { allowRemote: false }, { spawn: spy.spawn });

  assert.equal(unscanned, undefined);
  assert.equal(spy.calls.length, SCANNER_PASSES.length);
  const alpha = (raw as any).scan_results.find((e: any) => e.tool_name === 'alpha');
  assert.ok(alpha.findings.readiness_analyzer && alpha.findings.yara_analyzer,
    '두 pass 결과가 한 항목에 모여야 한다 — 합치지 않으면 뒤 pass 가 앞 pass 를 덮는다');
});

test('scanOne — pass 하나만 실패해도 대상 전체를 unscanned 로 돌린다(반쪽 결과 금지)', async () => {
  // 두 번째 pass 만 깨진 JSON 을 내보낸다.
  const spy = spawnSpy((n) => (n === 0
    ? { stdout: JSON.stringify(envA), exit: 0 }
    : { stdout: 'not json', exit: 1 }));
  const { raw, unscanned } = await scanOne(localTarget, { allowRemote: false }, { spawn: spy.spawn });

  assert.equal(raw, undefined, '반쪽 결과를 내보내면 읽는 사람이 "스캔했는데 안 나왔다"로 오해한다');
  assert.ok(unscanned, 'unscanned 로 남아야 한다');
  assert.ok(
    (unscanned!.detail ?? '').startsWith('[pass:'),
    `어느 pass 에서 무너졌는지 detail 에 남아야 한다 (실제: ${unscanned!.detail})`,
  );
});

test('scanOne — scannerArgsOverride 를 주면 단일 pass 로 실행된다(테스트 하위호환)', async () => {
  const spy = spawnSpy(() => ({ stdout: JSON.stringify(envA), exit: 0 }));
  await scanOne(
    localTarget,
    { allowRemote: false, scannerArgsOverride: ['--format', 'raw', 'config', '--config-path', '/x/.mcp.json'] },
    { spawn: spy.spawn },
  );
  assert.equal(spy.calls.length, 1, 'override 는 pass 분리를 거치지 않는다');
});
