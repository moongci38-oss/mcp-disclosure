// Task 25 — cli.ts 엔트리포인트 배선 + exit code
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CLI = 'dist/src/cli.js';
const runCli = (args: string[]) => spawnSync('node', [CLI, ...args], { encoding: 'utf8' });

test('설정 파일 0건 디렉토리 → exit 1', () => {
  const dir = mkdtempSync(join(tmpdir(), 'agenttrust-empty-'));
  assert.throws(() => execFileSync('node', [CLI, 'scan', '--path', dir], { stdio: 'pipe' }));
});

test('설정 0건일 때 stderr 에 "어디를 찾았는지"를 알려준다(막다른 에러 금지)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'agenttrust-empty2-'));
  const r = runCli(['scan', '--path', dir]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /No agent configuration found/);
  assert.match(r.stderr, /\.mcp\.json/, '탐색 경로를 보여줘야 사용자가 다음 행동을 정할 수 있다');
});

// ontology.yaml 은 패키지 동봉 자산이다 — cwd 와 무관하게 찾아야 `npx agenttrust scan` 이 산다.
test('임의 디렉토리에서 실행해도 ontology 를 찾는다(cwd 비의존)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'agenttrust-cwd-'));
  const r = spawnSync('node', [join(process.cwd(), CLI), 'scan', '--path', dir], { cwd: dir, encoding: 'utf8' });
  assert.ok(!/Ontology error|ENOENT.*ontology/.test(r.stderr), `ontology 해석 실패: ${r.stderr}`);
  assert.equal(r.status, 1, '설정 0건이므로 exit 1 이어야 한다(ontology 문제가 아니라)');
});

// 실제 대상이 있으면 소견서 2종이 실제로 생성돼야 한다 — 배선의 최종 증거다.
test('.mcp.json 이 있으면 소견서 md/json 2종을 실제로 쓴다', () => {
  const dir = mkdtempSync(join(tmpdir(), 'agenttrust-real-'));
  writeFileSync(join(dir, '.mcp.json'), JSON.stringify({
    mcpServers: { demo: { command: 'node', args: ['nonexistent-server.js'] } },
  }));
  const r = runCli(['scan', '--path', dir]);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  assert.ok(existsSync(join(dir, 'agenttrust-findings.md')));
  assert.ok(existsSync(join(dir, 'agenttrust-findings.json')));
  const md = readFileSync(join(dir, 'agenttrust-findings.md'), 'utf8');
  assert.ok(md.includes('# AgentTrust Findings Report'));
  assert.ok(md.includes('### 3a.'), '못 보는 축이 실제 산출물에도 나와야 한다');
  const parsed = JSON.parse(readFileSync(join(dir, 'agenttrust-findings.json'), 'utf8'));
  assert.equal(parsed.claims.length, 15, '실제 실행에서도 15축 전수');
});

// 도그푸딩 Task 26 회귀 — 실행 경로 전체에서 이 거짓 진술이 재발하지 않는지 확인한다.
// (이 테스트 환경에는 mcp-scanner 가 PATH 에 없으므로 스캔은 실패하는 것이 정상이다.)
test('스캐너가 없어 스캔 0건이면 소견서가 "검사했지만 못 찾았다"고 말하지 않는다', () => {
  const dir = mkdtempSync(join(tmpdir(), 'agenttrust-noscan-'));
  writeFileSync(join(dir, '.mcp.json'), JSON.stringify({
    mcpServers: { demo: { command: 'node', args: ['nonexistent-server.js'] } },
  }));
  const r = runCli(['scan', '--path', dir]);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  const md = readFileSync(join(dir, 'agenttrust-findings.md'), 'utf8');
  const parsed = JSON.parse(readFileSync(join(dir, 'agenttrust-findings.json'), 'utf8'));

  // 스캔이 실제로 실패했음을 먼저 확인한다(전제가 깨지면 이 테스트는 무의미하다)
  assert.ok(parsed.unscanned.length > 0, '이 환경에서는 스캔이 실패해야 이 테스트가 의미를 갖는다');

  const sec2 = md.slice(md.indexOf('## 2.'), md.indexOf('## 3.'));
  for (const axis of ['prompt_injection_defense', 'secret_exposure', 'vulnerable_deps', 'malicious_pattern', 'operational_reliability']) {
    assert.ok(!sec2.includes(`**${axis}**`), `${axis} 가 "검사했고 못 찾음"으로 보고됐다 — 스캔은 일어나지 않았다`);
  }
  // 그리고 그 사실이 맨 위에 보여야 한다
  const head = md.slice(0, md.indexOf('## 1.'));
  assert.match(head, /could not be scanned/, '스캔 실패는 문서 맨 아래가 아니라 맨 위에 있어야 한다');
});
