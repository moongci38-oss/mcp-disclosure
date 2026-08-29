// D2 회귀 (2026-08-29 첫인상 QA) — 알 수 없는 인자를 조용히 삼키면 안 된다.
//
// 왜 이 파일이 있나: `scan --paht /other` 를 치면 종전에는 오타 플래그가 **버려지고** cwd 가
// 스캔된 뒤 exit 0 `Report written` 이 떴다. 사용자는 /other 를 스캔했다고 믿지만 실제로는
// 다른 디렉터리를 봤다. 커버리지 정직성이 차별축인 도구에서 "엉뚱한 것을 보고 성공을 알리는"
// 실패는 가장 비싼 종류다.
//
// 대조군은 이미 옳게 동작하던 `--scan-timeout abc`(exit 2 + 명확한 메시지)다. 그 패턴에 맞춘다.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CLI = 'dist/src/cli.js';
const runCli = (args: string[], opts: Record<string, unknown> = {}) =>
  spawnSync(process.execPath, [join(process.cwd(), CLI), ...args], { encoding: 'utf8', ...opts });

const emptyDir = (tag: string) => mkdtempSync(join(tmpdir(), `mcp-disclosure-arg-${tag}-`));

test('D2 — 오타 난 플래그는 exit 2 + usage 로 거부한다(조용한 무시 금지)', () => {
  const dir = emptyDir('typo');
  const r = runCli(['scan', '--paht', dir]);
  assert.equal(r.status, 2, `오타 플래그가 통과했다. stdout=${r.stdout} stderr=${r.stderr}`);
  assert.match(r.stderr, /--paht/, '무엇이 잘못됐는지 그 인자를 그대로 보여줘야 고칠 수 있다');
  assert.match(r.stderr, /USAGE/, 'usage 를 함께 내야 사용자가 올바른 철자를 바로 본다');
});

// ⚠️ 이 테스트가 D2 의 핵심이다 — exit code 만 고치고 "엉뚱한 곳을 스캔"이 남으면 의미가 없다.
test('D2 — 오타 플래그일 때 cwd 를 대신 스캔해 리포트를 쓰지 않는다', () => {
  const cwdDir = mkdtempSync(join(tmpdir(), 'mcp-disclosure-arg-cwd-'));
  const otherDir = mkdtempSync(join(tmpdir(), 'mcp-disclosure-arg-other-'));
  // cwd 에는 진짜 설정이 있다 — 종전 동작이라면 여기가 스캔돼 리포트가 생긴다.
  writeFileSync(join(cwdDir, '.mcp.json'), JSON.stringify({
    mcpServers: { demo: { command: 'node', args: ['nonexistent-server.js'] } },
  }));
  const r = runCli(['scan', '--paht', otherDir], { cwd: cwdDir });
  assert.equal(r.status, 2, `stdout=${r.stdout} stderr=${r.stderr}`);
  const written = readdirSync(cwdDir).filter(f => f.startsWith('mcp-disclosure-findings'));
  assert.deepEqual(written, [], `오타를 냈는데 cwd 가 스캔돼 리포트가 생겼다: ${written.join(', ')}`);
  assert.deepEqual(readdirSync(otherDir), [], '의도한 디렉터리에도 당연히 생기면 안 된다');
});

test('D2 — 알 수 없는 서브커맨드는 exit 2', () => {
  const r = runCli(['frobnicate']);
  assert.equal(r.status, 2, `stdout=${r.stdout} stderr=${r.stderr}`);
  assert.match(r.stderr, /frobnicate/);
});

test('D2 — 알 수 없는 짧은 플래그(-x)와 맨 대시(-)도 거부한다', () => {
  const a = runCli(['scan', '-x']);
  assert.equal(a.status, 2, `-x 가 통과했다: ${a.stderr}`);
  const b = runCli(['scan', '-']);
  assert.equal(b.status, 2, `맨 "-" 가 통과했다: ${b.stderr}`);
});

test('D2 — 위치 인자는 받지 않는다(경로는 --path 로만)', () => {
  const dir = emptyDir('pos');
  const r = runCli(['scan', dir]);
  assert.equal(r.status, 2, `위치 인자가 조용히 무시됐다: ${r.stderr}`);
  assert.match(r.stderr, /--path/, '올바른 방법(--path)을 알려줘야 한다');
});

test('D2 — `--` 이후의 인자도 무시하지 않는다(위치 인자로 보고 거부)', () => {
  const r = runCli(['scan', '--', 'leftover']);
  assert.equal(r.status, 2, `"--" 뒤가 조용히 버려졌다: ${r.stderr}`);
});

test('D2 — 값이 빠진 --path 는 조용히 cwd 로 넘어가지 않는다', () => {
  const r = runCli(['scan', '--path']);
  assert.equal(r.status, 2, `--path 에 값이 없는데 통과했다: ${r.stderr}`);
});

// 유효한 조합이 계속 동작해야 한다 — 검증을 더하다 정상 경로를 막으면 그게 더 큰 결함이다.
test('D2 — 유효한 플래그 조합은 그대로 통과한다(exit 2 가 아니다)', () => {
  const dir = emptyDir('valid');
  const r = runCli(['scan', '--path', dir, '--allow-remote', '--scan-timeout', '5000']);
  assert.equal(r.status, 1, `설정 0건이라 exit 1 이어야 한다(인자 오류 2 가 아니라). stderr=${r.stderr}`);
  assert.match(r.stderr, /No agent configuration found/);
});

test('D2 — `--` 만 붙은 스캔은 유효하다', () => {
  const dir = emptyDir('ddash');
  const r = runCli(['scan', '--path', dir, '--']);
  assert.equal(r.status, 1, `"--" 단독이 거부됐다: ${r.stderr}`);
});

// --help/--version 은 서브커맨드 없이도 살아 있어야 한다(2026-08-27 에 고친 회귀의 재발 방지).
test('D2 — 서브커맨드 없는 --help/--version 은 여전히 동작한다', () => {
  const h = runCli(['--help']);
  assert.equal(h.status, 0, `--help 가 인자 검증에 걸렸다: ${h.stderr}`);
  assert.match(h.stdout, /USAGE/);
  const v = runCli(['--version']);
  assert.equal(v.status, 0, `--version 이 인자 검증에 걸렸다: ${v.stderr}`);
});

test('D2 — 인자 0개면 usage 를 내고 exit 2(무엇을 하라는지 알려준다)', () => {
  const r = runCli([]);
  assert.equal(r.status, 2, `인자 0개가 조용히 스캔으로 흘렀다: ${r.stdout}`);
  assert.match(r.stderr, /USAGE/);
});
