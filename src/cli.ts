// src/cli.ts — 엔트리포인트: 전 모듈 배선 (§4.2)
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';
import { discover } from './discover.js';
import { runScanner } from './runner.js';
import { parseScannerRawEnvelope } from './scanner-envelope.js'; // A-1 codex 반영
import { normalize } from './normalize.js';
import { mapFindingsToClaims } from './map.js';
import { render, RenderError } from './render.js';
import { loadAxisTable, OntologyError } from './ontology.js';
import { checkPythonAvailable, getScannerVersion, checkScannerVersion } from './version-check.js'; // A-3 codex 반영

// ⚠️ ontology.yaml 은 **패키지에 동봉되는 자산**이지 사용자 작업 디렉터리의 파일이 아니다.
// Spec 초안은 `process.cwd()` 기준으로 읽었는데, 그러면 v0 의 유일한 배포 형태인
// `npx agenttrust scan`(임의 디렉터리에서 실행)이 첫 줄부터 죽는다 — 스캔 대상 폴더에
// ontology.yaml 이 있을 이유가 없기 때문이다. 모듈 위치 기준으로 올려 잡는다.
// dist/src/cli.js → dist/src → dist → <package root>/ontology.yaml
function ontologyPath(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'ontology.yaml');
}

export async function main(argv: string[]): Promise<void> {
  const pathIdx = argv.indexOf('--path');
  const rootDir = pathIdx >= 0 ? argv[pathIdx + 1] : process.cwd();
  const allowRemote = argv.includes('--allow-remote');

  const py = checkPythonAvailable();
  if (!py.ok) {
    process.stderr.write('Python not found. Install Python 3.11+ and `pip install cisco-ai-mcp-scanner`.\n');
    process.exit(1);
  }

  // A-3 codex 반영: 종전엔 이 호출 자체가 없어서 checkScannerVersion 이 실행경로에서 죽어 있었다.
  // 스캐너가 아예 없으면 hard-fail 하지 않는다 — 개별 scanOne 이 ENOENT 를 대상별로 처리한다(A-5).
  const scannerVersion = getScannerVersion();
  const scannerWarnings: string[] = [];
  if (scannerVersion) {
    const versionCheck = checkScannerVersion(scannerVersion);
    if (versionCheck.warning) scannerWarnings.push(versionCheck.warning);
  } else {
    // 실측(Session 1): 이 스캐너에는 --version 플래그가 아예 없다(argparse 가 exit 2 로 거부).
    // "일시적으로 못 읽었다"가 아니라 "원래 못 얻는다"라는 뜻이므로 그렇게 적는다.
    scannerWarnings.push(
      'Scanner version is unavailable: mcp-scanner exposes no --version flag, so the version-range ' +
      'check was skipped and the report cannot pin the exact scanner build. Ruleset identifier is ' +
      'unavailable for the same reason.',
    );
  }

  // ontology 는 **한 번만** 읽는다(Spec 초안은 두 번 읽었다) — 두 번 읽으면 그 사이에 파일이
  // 바뀌었을 때 검증한 표와 렌더에 넘긴 원본이 어긋난다.
  let ontologyRaw: unknown;
  let axisTable;
  try {
    ontologyRaw = yaml.load(readFileSync(ontologyPath(), 'utf8'));
    axisTable = loadAxisTable(ontologyRaw);
  } catch (e) {
    if (e instanceof OntologyError) {
      process.stderr.write(`Ontology error: ${e.message}\n`);
      process.exit(2);
    }
    throw e;
  }

  const { targets, scannedPaths } = discover(rootDir);
  if (targets.length === 0) {
    process.stderr.write(`No agent configuration found. Searched:\n${scannedPaths.join('\n')}\n`);
    process.exit(1);
  }

  const runnerResult = await runScanner(targets, { allowRemote });
  // A-1 codex 반영: 종전엔 `r.findings ?? []` 로 직접 읽어 findings 가 항상 0건이었다(raw 는
  // findings 배열이 아니라 봉투다). parseScannerRawEnvelope 하나로 이 계약을 강제한다.
  const rawFindings = [...runnerResult.rawByTarget.entries()]
    .flatMap(([targetKey, raw]) => parseScannerRawEnvelope(raw, targetKey));

  // 재현 메타 — 도그푸딩 Task 26 에서 전부 자리표시자('unset'/'unknown')로 나가는 것이 드러났다.
  // 소견서의 "재현 가능성"이 사실상 빈 약속이었다는 뜻이라, 얻을 수 있는 값은 실제로 계산하고
  // 못 얻는 값은 **왜 못 얻는지까지** 적는다(render 의 자리표시자 가드가 이걸 강제한다).
  //
  // target_hash: 실제로 읽은 설정 파일들의 내용 해시. 같은 설정을 다시 스캔했는지 확인하는
  //   유일한 수단이라 이건 반드시 실값이어야 한다.
  const targetHash = (() => {
    const h = createHash('sha256');
    for (const p of [...new Set(targets.map(t => t.sourcePath))].sort()) {
      try { h.update(p).update('\0').update(readFileSync(p)); } catch { h.update(p).update('\0<unreadable>'); }
    }
    return h.digest('hex').slice(0, 16);
  })();

  const meta = {
    name: 'cisco-mcp-scanner',
    // ⚠️ 실측(Session 1): 이 스캐너에는 `--version` 플래그가 아예 없다(argparse 가 exit 2 로 거부).
    //    그래서 이 값은 거의 항상 부재다 — 부재를 부재라고 적는다.
    version: scannerVersion ?? 'unavailable',
    ruleset_hash: 'unavailable',
    scanned_at: new Date().toISOString(),
    target_hash: targetHash,
    python_version: py.version ?? 'unavailable',
  };

  // A-4 codex 반영: 종전엔 normalize() 반환값에서 unmatchedSignals 를 버리고 render() 에 항상
  // [] 를 넘겼다 — computeUnmatchedSignals 가 계산해도 여기서 버리면 여전히 의미가 없다.
  const { findings, unmatchedSignals } = normalize(rawFindings, axisTable, meta);
  // 도그푸딩 Task 26 발견: 스캔 성사 여부를 넘기지 않으면, 스캐너가 아예 실행되지 않은 실행이
  // "5개 축 전부 깨끗함" 소견서를 내놓는다.
  const outcome = { attempted: targets.length, scanned: runnerResult.rawByTarget.size };
  const claims = mapFindingsToClaims(findings, axisTable, outcome);

  try {
    const { markdown, json } = render(
      claims, findings, meta, runnerResult.unscanned, unmatchedSignals,
      { allowRemote, usedRemoteCount: runnerResult.usedRemoteTargets.length },
      ontologyRaw, scannerWarnings,
    );
    writeFileSync(join(rootDir, 'agenttrust-findings.md'), markdown);
    writeFileSync(join(rootDir, 'agenttrust-findings.json'), json);
    process.stdout.write('Report written: agenttrust-findings.md, agenttrust-findings.json\n');
    process.exit(0);
  } catch (e) {
    if (e instanceof RenderError) {
      process.stderr.write(`Render failed (fail-closed): ${e.message}\n`);
      process.exit(2);
    }
    throw e;
  }
}

// 이 파일을 `node dist/src/cli.js` 로 **직접 실행**했을 때도 동작하게 한다.
// 없으면 모듈이 로드만 되고 아무 일도 일어나지 않는다(exit 0, 출력 0) — "조용히 성공한 것처럼
// 보이는 실패"라서 제일 나쁘다. bin/agenttrust.js 경유 실행은 main() 을 직접 부르므로 무관하다.
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main(process.argv.slice(2)).catch((e: unknown) => {
    process.stderr.write(`Unexpected error: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(3);
  });
}
