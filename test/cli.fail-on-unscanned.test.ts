// --fail-on-unscanned — CI 에서 "아무것도 못 본 스캔"을 실패로 만드는 옵트인 게이트.
//
// 왜 필요한가: 기본 계약은 exit 0 이고 그건 안 바꾼다(사용자 스크립트 호환). 그런데 그러면
// "전부 스캔됨"과 "한 건도 못 스캔함"이 CI 에서 **똑같이 초록불**이다. 커버리지 정직성이
// 차별축인 도구가 "아무것도 못 봤다"를 성공으로 보고하면 그 축이 무너진다.
//
// 의미(고른 것): **unscanned 가 1건이라도 있으면 실패한다.** 플래그 이름 그대로다.
// 버린 것 ①"전부 unscanned 일 때만 실패" — 10개 중 9개가 실패해도 통과시킨다. 부분 커버리지를
//   조용히 넘기는 것이 바로 이 게이트가 막으려던 그 문제다.
// 버린 것 ②"remote_out_of_scope 는 제외" — 편해 보이지만 플래그 동작이 문서에 없는 숨은
//   예외에 좌우된다. 이 코드베이스가 반복해서 데인 패턴이라(선언과 실제가 갈라짐) 택하지 않았다.
//   remote 를 스캔하려면 --allow-remote 를 주면 되고, 그러기 싫으면 이 플래그를 안 켜면 된다.
//
// exit code 는 **4**. 0/1/2/3 은 이미 쓰이고 있어 겹치면 호출자가 구분할 수 없다.
// ⚠️ 소견서는 **그대로 쓴다** — 실패로 끝내되 읽을 것은 남긴다. 그게 이 도구의 요점이다.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from '../src/cli.js';

const CLI = 'dist/src/cli.js';

/** mcp-scanner 를 못 찾는 PATH 를 만들어 unscanned 를 확실히 1건 이상으로 만든다. */
function scanWithoutScanner(extraArgs: string[] = []) {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-disclosure-fou-'));
  writeFileSync(join(dir, '.mcp.json'), JSON.stringify({
    mcpServers: { demo: { command: 'node', args: ['nonexistent-server.js'] } },
  }));
  const shimDir = mkdtempSync(join(tmpdir(), 'mcp-disclosure-fou-shim-'));
  writeFileSync(join(shimDir, 'python3'), '#!/bin/sh\necho "Python 3.12.0"\n', { mode: 0o755 });
  const r = spawnSync(process.execPath, [CLI, 'scan', '--path', dir, ...extraArgs], {
    encoding: 'utf8', env: { ...process.env, PATH: shimDir },
  });
  return { ...r, dir };
}

test('기본 동작은 그대로다 — 플래그 없으면 unscanned 가 있어도 exit 0', () => {
  const r = scanWithoutScanner();
  const parsed = JSON.parse(readFileSync(join(r.dir, 'mcp-disclosure-findings.json'), 'utf8'));
  assert.ok(parsed.unscanned.length > 0, '전제: 이 환경에서는 스캔이 실패해야 한다');
  assert.equal(r.status, 0, '기본 계약(exit 0)은 절대 바뀌면 안 된다 — 옵트인이라는 뜻이 이것이다');
});

test('--fail-on-unscanned + unscanned 1건 이상 → exit 4', () => {
  const r = scanWithoutScanner(['--fail-on-unscanned']);
  const parsed = JSON.parse(readFileSync(join(r.dir, 'mcp-disclosure-findings.json'), 'utf8'));
  assert.ok(parsed.unscanned.length > 0, '전제: 스캔이 실패해야 한다');
  assert.equal(r.status, 4, `exit 4 여야 한다. stdout=${r.stdout} stderr=${r.stderr}`);
});

// ⚠️ 이것이 이 기능의 핵심이다 — 실패로 끝내되 읽을 것은 남긴다.
test('--fail-on-unscanned 로 실패해도 소견서 2종은 그대로 쓴다', () => {
  const r = scanWithoutScanner(['--fail-on-unscanned']);
  assert.equal(r.status, 4);
  assert.ok(existsSync(join(r.dir, 'mcp-disclosure-findings.md')), 'md 가 없으면 왜 실패했는지 못 읽는다');
  assert.ok(existsSync(join(r.dir, 'mcp-disclosure-findings.json')));
  assert.match(r.stdout, /Report written/, '리포트를 썼다는 사실은 여전히 알린다');
});

test('--fail-on-unscanned 실패는 이유를 stderr 로 말한다', () => {
  const r = scanWithoutScanner(['--fail-on-unscanned']);
  assert.match(r.stderr, /--fail-on-unscanned/,
    '어떤 플래그 때문에 실패했는지 말해야 사용자가 끌 수 있다');
  assert.match(r.stderr, /could not be scanned/i, '몇 건이 왜 안 됐는지도 여전히 나와야 한다');
});

test('--fail-on-unscanned 는 다른 플래그와 함께 써도 파싱된다(미지 옵션으로 거부되지 않는다)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-disclosure-fou-combo-'));
  const r = spawnSync(process.execPath, [CLI, 'scan', '--path', dir, '--fail-on-unscanned', '--allow-remote'], { encoding: 'utf8' });
  assert.equal(r.status, 1, `설정 0건이라 exit 1 이어야 한다(인자오류 2 가 아니라). stderr=${r.stderr}`);
});

test('parseArgs — 플래그 유무가 그대로 반영된다', () => {
  const on = parseArgs(['scan', '--fail-on-unscanned']);
  assert.equal(on.kind, 'scan');
  assert.equal(on.kind === 'scan' && on.failOnUnscanned, true);
  const off = parseArgs(['scan']);
  assert.equal(off.kind === 'scan' && off.failOnUnscanned, false, '기본값은 꺼짐이어야 한다');
});

// D6 재발 방지 — --help / README / 실제 exit code 가 갈라지면 안 된다.
test('--help 와 README 가 새 플래그·exit 4 를 둘 다 안다', () => {
  const help = spawnSync(process.execPath, [CLI, '--help'], { encoding: 'utf8' }).stdout;
  assert.match(help, /--fail-on-unscanned/, '--help 가 플래그를 안내해야 한다');
  const exitSection = help.slice(help.indexOf('EXIT CODES'));
  assert.match(exitSection, /^\s+4\s+/m, '--help 의 EXIT CODES 에 4 가 있어야 한다');

  const readme = readFileSync('README.md', 'utf8');
  assert.match(readme, /--fail-on-unscanned/, 'README 가 플래그를 안내해야 한다');
  assert.match(readme, /`4`/, 'README exit code 목록에 4 가 있어야 한다');
});
