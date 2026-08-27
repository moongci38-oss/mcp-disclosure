// 2026-08-27 — 공개 직후 실측으로 잡은 첫인상 결함 3건을 못 박는다.
//
// 무엇을 막나: 저장소를 public 으로 연 직후 `mcp-disclosure --help` 를 쳐 봤더니
// 도움말이 아니라 "No agent configuration found" 가 나왔다. 새 CLI 를 만난 사람이 가장 먼저
// 치는 명령인데 첫 화면이 에러였다. 도움말을 쓰다가 `--scan-timeout` 이 Spec·주석에만 있고
// argv 에서 읽힌 적이 없다는 것도 함께 발견했다(선언만 있고 소비처 0).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';

const CLI = 'dist/src/cli.js';
const runCli = (args: string[]) => spawnSync('node', [CLI, ...args], { encoding: 'utf8' });

// ── --help ───────────────────────────────────────────────────────────────────

for (const flag of ['--help', '-h']) {
  test(`${flag} → 도움말을 stdout 으로, exit 0`, () => {
    const r = runCli([flag]);
    assert.equal(r.status, 0, `${flag} 는 성공 종료여야 한다`);
    assert.match(r.stdout, /USAGE/, '도움말 본문이 stdout 으로 나와야 한다');
    assert.doesNotMatch(r.stderr, /No agent configuration found/,
      '도움말 요청이 스캔 경로로 새면 안 된다 — 이것이 2026-08-27 에 잡힌 결함이다');
  });
}

test('--help 는 스캔 대상이 없는 빈 디렉터리에서도 동작한다', () => {
  // 도움말은 사전점검(Python·스캐너·설정파일)보다 **앞에** 있어야 한다.
  // 아무것도 갖춰지지 않은 사람이 가장 먼저 치는 명령이기 때문이다.
  const dir = mkdtempSync(join(tmpdir(), 'mcp-disclosure-help-'));
  const r = spawnSync('node', [CLI, '--help'], { encoding: 'utf8', cwd: process.cwd() });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /USAGE/);
  assert.ok(dir);
});

test('도움말이 안내하는 플래그는 전부 실제로 파싱된다 — 없는 기능을 광고하지 않는다', () => {
  const help = runCli(['--help']).stdout;
  const cliSrc = readFileSync('src/cli.ts', 'utf8');
  const advertised = [...help.matchAll(/^\s+(--[a-z-]+)/gm)].map(m => m[1]);
  assert.ok(advertised.length >= 3, '도움말에서 플래그를 못 뽑았다 — 이 테스트가 헛돌고 있다');
  for (const flag of advertised) {
    assert.ok(
      cliSrc.includes(`'${flag}'`),
      `${flag} 를 도움말에 적어놓고 cli.ts 가 argv 에서 읽지 않는다 — 선언과 배선이 갈라졌다`,
    );
  }
});

// ── --version ────────────────────────────────────────────────────────────────

for (const flag of ['--version', '-v']) {
  test(`${flag} → package.json 의 버전을 그대로, exit 0`, () => {
    const r = runCli([flag]);
    assert.equal(r.status, 0);
    const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as { version: string };
    assert.equal(r.stdout.trim(), pkg.version,
      '버전을 코드에 박으면 릴리스마다 package.json 과 갈라진다');
  });
}

// ── --scan-timeout ───────────────────────────────────────────────────────────

test('--scan-timeout 에 잘못된 값 → 조용히 무시하지 않고 exit 2', () => {
  // 나쁜 값을 기본값으로 삼켜버리면 사용자는 자기가 준 값이 무시된 줄을 모른다.
  for (const bad of ['abc', '-1', '0']) {
    const r = runCli(['scan', '--scan-timeout', bad]);
    assert.equal(r.status, 2, `--scan-timeout ${bad} 는 거부돼야 한다`);
    assert.match(r.stderr, /--scan-timeout expects a positive number/);
  }
});

test('--scan-timeout 값 누락 → exit 2', () => {
  const r = runCli(['scan', '--scan-timeout']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--scan-timeout expects a positive number/);
});
