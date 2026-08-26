// 배포 산출물 검증 — "내 머신에서 되는 것"과 "설치한 사람에게서 되는 것"은 다르다.
//
// ⚠️ 실제로 있었던 버그(2026-08-22): `dist/` 가 .gitignore 에 있어서 npm 이 패키지에서
//    통째로 뺐다. `bin/mcp-disclosure.js` 는 `../dist/src/cli.js` 를 import 하므로,
//    배포했다면 **모든 사용자에게서 첫 줄에 죽었다**:
//      Cannot find module '.../package/dist/src/cli.js'
//    로컬 테스트 164건은 전부 GREEN 이었다 — dist 가 로컬에는 있었기 때문이다.
//    이 프로젝트가 계속 만나는 "등록 ≠ 발효" 패턴의 배포판이다.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

function packedFiles(): string[] {
  // --dry-run 이라 tarball 을 만들지 않는다(빠르다). pretest 가 이미 빌드해 둔 dist 를 본다.
  const out = execFileSync('npm', ['pack', '--dry-run', '--json'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
  return (JSON.parse(out)[0].files as { path: string }[]).map(f => f.path);
}

test('패키지에 실행에 필요한 것이 전부 들어간다', () => {
  const files = packedFiles();
  for (const need of ['dist/src/cli.js', 'bin/mcp-disclosure.js', 'ontology.yaml', 'README.md', 'LICENSE']) {
    assert.ok(files.includes(need), `배포 패키지에 ${need} 가 없다 — 설치한 사람에게서 실패한다`);
  }
});

test('bin 이 import 하는 경로가 패키지 안에 실재한다', () => {
  const bin = readFileSync('bin/mcp-disclosure.js', 'utf8');
  const m = bin.match(/import\(['"]\.\.\/(.+?)['"]\)/);
  assert.ok(m, 'bin 의 동적 import 경로를 못 찾았다 — 이 테스트를 먼저 고쳐라');
  assert.ok(packedFiles().includes(m![1]),
    `bin 은 ${m![1]} 를 부르는데 패키지에 그 파일이 없다`);
});

test('테스트 산출물과 소스는 배포하지 않는다(용량·노이즈)', () => {
  const files = packedFiles();
  assert.equal(files.filter(f => f.startsWith('dist/test/')).length, 0);
  assert.equal(files.filter(f => f.startsWith('src/')).length, 0, '컴파일 결과만 배포한다');
  // `upstream/` 은 상류에 낼 패치 보관소다 — 우리 배포물이 아니다(2026-08-26 신설).
  assert.equal(
    files.filter(f => f.startsWith('docs/') || f.startsWith('fixtures/') || f.startsWith('upstream/')).length,
    0,
  );
});

// files 필드가 사라지면 .gitignore 규칙이 되살아나 dist 가 다시 빠진다 — 그 회귀를 못 박는다.
test('package.json 에 files allowlist 와 prepublishOnly 가 있다', () => {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
  assert.ok(Array.isArray(pkg.files) && pkg.files.length > 0,
    'files 가 없으면 .gitignore 가 dist 를 빼서 빈 껍데기가 배포된다');
  assert.match(pkg.scripts.prepublishOnly ?? '', /build/,
    'prepublishOnly 가 빌드하지 않으면 낡은 dist 가 배포될 수 있다');
});
