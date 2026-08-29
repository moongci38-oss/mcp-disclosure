// D1 회귀 (2026-08-29 첫인상 QA) — 스캔이 실패했을 때 신호가 닿는 곳까지 간다.
//
// 무엇이 이미 되고 있었나(총괄 재현으로 확인): md 리포트는 실패를 이미 눈에 띄게 알린다 —
// 맨 위 인용블록 "N target(s) could not be scanned", 3a 축 전부 "the scan did not complete",
// 그리고 "## Unscanned items" 섹션. 그래서 "사람이 읽는 곳에서 안 알려준다"는 과장이었다.
//
// 실제로 빠져 있던 것은 두 가지뿐이고, 이 파일은 그 둘만 못 박는다:
//  (a) 터미널이 침묵했다 — stdout 은 "Report written" 한 줄, stderr 0줄. 리포트를 열지 않은
//      사람에게는 신호가 0이었다.
//  (b) md 에 **고치는 법**이 없었다. 실행 가능한 안내("install: pip install cisco-ai-mcp-scanner")는
//      JSON 의 unscanned[].detail 에만 있었고, md 는 `reason: scanner_error` 라는 토큰만 보여줬다.
//
// ⚠️ exit code 는 일부러 0 그대로다 — 0 → 비0 은 사용자 스크립트를 깨는 계약 변경이라
//    별도 판단 대상이다. 이 파일은 그 계약이 조용히 바뀌지 않도록 **잠그는 역할**도 한다.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CLI = 'dist/src/cli.js';

/**
 * mcp-scanner 가 PATH 에 없는 상태를 **직접 만든다**.
 * "이 머신엔 원래 없다"는 우연에 기대면 스캐너를 설치한 머신에서 전제가 깨진다
 * (cli.exit-codes.test.ts 가 2026-08-22 에 실제로 겪은 일이다).
 */
function runWithoutScanner(): { status: number | null; stdout: string; stderr: string; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-disclosure-d1-'));
  writeFileSync(join(dir, '.mcp.json'), JSON.stringify({
    mcpServers: { demo: { command: 'node', args: ['nonexistent-server.js'] } },
  }));
  const shimDir = mkdtempSync(join(tmpdir(), 'mcp-disclosure-d1-shim-'));
  writeFileSync(join(shimDir, 'python3'), '#!/bin/sh\necho "Python 3.12.0"\n', { mode: 0o755 });
  const r = spawnSync(process.execPath, [CLI, 'scan', '--path', dir], {
    encoding: 'utf8', env: { ...process.env, PATH: shimDir },
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, dir };
}

test('D1(a) — 스캔 실패가 1건 이상이면 stderr 로 경고한다(터미널 침묵 금지)', () => {
  const r = runWithoutScanner();
  const parsed = JSON.parse(readFileSync(join(r.dir, 'mcp-disclosure-findings.json'), 'utf8'));
  assert.ok(parsed.unscanned.length > 0, '이 환경에서 스캔이 실패해야 이 테스트가 의미를 갖는다');

  assert.notEqual(r.stderr.trim(), '', 'stderr 가 비었다 — 리포트를 열지 않은 사람에게 신호가 0이다');
  assert.match(r.stderr, /could not be scanned/i, '무슨 일이 있었는지 말해야 한다');
  assert.match(r.stderr, /\b1\b/, '몇 건 실패했는지 숫자가 있어야 한다');
  assert.match(r.stderr, /scanner_error/, '왜 실패했는지(사유)가 있어야 한다');
});

test('D1(a) — 경고는 내되 exit code 계약은 0 그대로다(스크립트 호환)', () => {
  const r = runWithoutScanner();
  assert.equal(r.status, 0,
    'exit 0 → 비0 은 사용자 스크립트를 깨는 계약 변경이라 이번 범위가 아니다');
  assert.match(r.stdout, /Report written/, '리포트는 여전히 정상 생성된다');
});

test('D1(b) — md 의 Unscanned items 가 고치는 법을 싣는다(JSON detail 을 그대로)', () => {
  const r = runWithoutScanner();
  const md = readFileSync(join(r.dir, 'mcp-disclosure-findings.md'), 'utf8');
  const parsed = JSON.parse(readFileSync(join(r.dir, 'mcp-disclosure-findings.json'), 'utf8'));

  const detail: string = parsed.unscanned[0].detail;
  assert.ok(detail && detail.length > 0, 'JSON 에 detail 이 없으면 이 테스트가 헛돈다');

  // 종전에는 md 에 `pip install` 이 0건이었다 — 사용자가 다음에 뭘 해야 하는지 md 만 보고는 몰랐다.
  assert.match(md, /pip install cisco-ai-mcp-scanner/,
    'md 에 실행 가능한 설치 안내가 없다 — JSON 을 열어야만 알 수 있으면 안 된다');

  // 토큰(reason)만이 아니라 detail 본문이 md 에 실려야 한다.
  const section = md.slice(md.indexOf('## Unscanned items'));
  assert.ok(section.includes('mcp-scanner'),
    `Unscanned items 에 detail 이 안 실렸다:\n${section.slice(0, 400)}`);
  assert.match(section, /reason: scanner_error/, '기존 reason 표기는 유지한다');
});

test('D1(b) — detail 이 없는 항목도 md 렌더가 깨지지 않는다', () => {
  // remote_out_of_scope 처럼 detail 이 없을 수 있다. 그때 "detail: undefined" 가 찍히면
  // 그 자체가 새 결함이다.
  const dir = mkdtempSync(join(tmpdir(), 'mcp-disclosure-d1-remote-'));
  writeFileSync(join(dir, '.mcp.json'), JSON.stringify({
    mcpServers: { far: { url: 'https://example.invalid/mcp' } },
  }));
  const r = spawnSync(process.execPath, [CLI, 'scan', '--path', dir], { encoding: 'utf8' });
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  const md = readFileSync(join(dir, 'mcp-disclosure-findings.md'), 'utf8');
  assert.ok(!/undefined/.test(md), `md 에 undefined 가 새어 나왔다:\n${md.slice(0, 600)}`);
});
