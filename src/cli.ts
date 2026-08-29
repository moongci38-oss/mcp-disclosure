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
// `npx mcp-disclosure scan`(임의 디렉터리에서 실행)이 첫 줄부터 죽는다 — 스캔 대상 폴더에
// ontology.yaml 이 있을 이유가 없기 때문이다. 모듈 위치 기준으로 올려 잡는다.
// dist/src/cli.js → dist/src → dist → <package root>/ontology.yaml
function ontologyPath(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'ontology.yaml');
}

// 패키지 버전은 package.json 에서 읽는다 — 코드에 박아두면 릴리스마다 갈라진다.
// 경로 규칙은 ontologyPath() 와 같다(dist/src/cli.js → <package root>).
export function readPackageVersion(): string {
  try {
    const p = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'package.json');
    const pkg = JSON.parse(readFileSync(p, 'utf8')) as { version?: unknown };
    return typeof pkg.version === 'string' ? pkg.version : 'unknown';
  } catch {
    return 'unknown';
  }
}

export const USAGE = `mcp-disclosure — a configuration disclosure CLI for AI agent / MCP setups.

It reports three things side by side: what it found, what it looked for and did not
find, and what it cannot check at all.

USAGE
  mcp-disclosure scan [options]

OPTIONS
  --path <dir>        Directory to scan (default: current directory)
  --allow-remote      Opt in to scanning remote MCP endpoints (off by default)
  --scan-timeout <ms> Per-scan timeout in milliseconds (default: 120000)
  -h, --help          Show this help
  -v, --version       Show version

OUTPUT
  Writes two files into the scanned directory:
    mcp-disclosure-findings.md    the report you read
    mcp-disclosure-findings.json  the same data, complete

REQUIREMENTS
  Python 3.11+ and the Cisco MCP scanner:
    pip install cisco-ai-mcp-scanner

EXIT CODES
  0  report written
  1  nothing to scan, or a prerequisite is missing
  2  ontology/config error

Docs: https://github.com/moongci38-oss/mcp-disclosure
`;

/** 이 CLI 가 받는 서브커맨드 전부. 여기 없는 낱말은 명령이 아니다. */
const KNOWN_COMMANDS = ['scan'] as const;

export type ParsedArgs =
  | { kind: 'help' }
  | { kind: 'version' }
  | { kind: 'scan'; rootDir: string; allowRemote: boolean; timeoutMs?: number }
  | { kind: 'error'; message: string };

/**
 * argv 를 **전수 해석**한다 — 모르는 것은 버리지 않고 에러로 만든다.
 *
 * ⚠️ D2 회귀 (2026-08-29 첫인상 QA). 종전 파서는 `indexOf`/`includes` 로 아는 플래그만 집어가고
 * 나머지는 조용히 버렸다. 그래서 `scan --paht /other` 가 **오타를 무시하고 cwd 를 스캔한 뒤**
 * exit 0 `Report written` 을 냈다. 사용자는 /other 를 봤다고 믿지만 실제로는 딴 곳을 봤다.
 * 아무것도 못 본 실행과 엉뚱한 것을 본 실행이 둘 다 성공처럼 보이면, 커버리지 정직성이라는
 * 이 제품의 차별축이 무너진다.
 *
 * 규칙(도움말과 같은 말을 하도록 여기 한 곳에만 적는다):
 *  - `-h/--help`, `-v/--version` 은 어디에 있든 가장 먼저 이긴다(사전점검보다도 앞).
 *  - 첫 낱말은 반드시 KNOWN_COMMANDS 중 하나여야 한다.
 *  - `--` 는 옵션 끝 표시다. 그 **뒤에 오는 것은 위치 인자**이고, 이 CLI 는 위치 인자를 받지 않는다.
 *  - `-` 로 시작하는 미지의 낱말 = 알 수 없는 옵션. 그 밖의 낱말 = 위치 인자. 둘 다 exit 2.
 */
export function parseArgs(argv: string[]): ParsedArgs {
  // ⚠️ --help/--version 은 **다른 무엇보다 먼저** 처리한다.
  // 2026-08-27 공개 직후 실측: 이 분기가 없어서 `mcp-disclosure --help` 가 스캔으로 흘러가
  // "No agent configuration found" 를 뱉었다 — 새 CLI 를 만난 사람이 가장 먼저 치는 명령인데
  // 첫 화면이 에러였다. Python·스캐너가 없어도 도움말은 나와야 하므로 사전점검보다 앞에 둔다.
  if (argv.includes('-h') || argv.includes('--help')) return { kind: 'help' };
  if (argv.includes('-v') || argv.includes('--version')) return { kind: 'version' };

  const command = argv[0];
  if (command === undefined) {
    return { kind: 'error', message: 'No command given.' };
  }
  if (!(KNOWN_COMMANDS as readonly string[]).includes(command)) {
    const looksLikeFlag = command.startsWith('-');
    return {
      kind: 'error',
      message: looksLikeFlag
        ? `Unknown option: ${command} (options come after a command, e.g. \`scan ${command}\`)`
        : `Unknown command: ${command}`,
    };
  }

  let rootDir = process.cwd();
  let allowRemote = false;
  let timeoutMs: number | undefined;

  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];

    if (arg === '--') {
      // 옵션 끝. 뒤에 남은 것은 전부 위치 인자인데 이 CLI 는 위치 인자를 받지 않는다.
      const rest = argv.slice(i + 1);
      if (rest.length > 0) {
        return { kind: 'error', message: `Unexpected argument after \`--\`: ${rest[0]} (this CLI takes no positional arguments — use --path <dir>)` };
      }
      break;
    }

    if (arg === '--path') {
      const value = argv[i + 1];
      // 값이 없는데 조용히 cwd 로 넘어가면, 사용자는 자기가 지정한 곳을 봤다고 믿는다.
      if (value === undefined || value === '--' || value.startsWith('-')) {
        return { kind: 'error', message: `--path expects a directory (got: ${value ?? '<missing>'})` };
      }
      rootDir = value;
      i++;
      continue;
    }

    if (arg === '--allow-remote') {
      allowRemote = true;
      continue;
    }

    // ⚠️ 2026-08-27 배선. `--scan-timeout` 은 Spec §2.1 FR-01 시그니처에도 있고 runner.ts 주석도
    //    "이 플래그로 조정한다"고 안내해 왔지만, **cli.ts 가 argv 에서 읽은 적이 한 번도 없었다** —
    //    선언만 있고 소비처가 0 인, 이 프로젝트가 반복해서 잡아온 그 패턴이다.
    //    도움말을 쓰다가 발견했다(없는 플래그를 안내할 뻔했다).
    if (arg === '--scan-timeout') {
      const raw = argv[i + 1];
      const parsed = Number(raw);
      // 잘못된 값을 조용히 기본값으로 삼키지 않는다 — 사용자는 자기가 준 값이 무시된 줄 모른다.
      if (raw === undefined || raw.trim() === '' || !Number.isFinite(parsed) || parsed <= 0) {
        return { kind: 'error', message: `--scan-timeout expects a positive number of milliseconds (got: ${raw ?? '<missing>'})` };
      }
      timeoutMs = parsed;
      i++;
      continue;
    }

    return {
      kind: 'error',
      message: arg.startsWith('-')
        ? `Unknown option: ${arg}`
        : `Unexpected argument: ${arg} (this CLI takes no positional arguments — use --path <dir>)`,
    };
  }

  return { kind: 'scan', rootDir, allowRemote, timeoutMs };
}

export async function main(argv: string[]): Promise<void> {
  const parsed = parseArgs(argv);
  if (parsed.kind === 'help') {
    process.stdout.write(USAGE);
    return;
  }
  if (parsed.kind === 'version') {
    process.stdout.write(`${readPackageVersion()}\n`);
    return;
  }
  if (parsed.kind === 'error') {
    // usage 를 함께 낸다 — 무엇이 틀렸는지만 알려주고 올바른 형태를 안 보여주면 한 번 더 틀린다.
    process.stderr.write(`${parsed.message}\n\n${USAGE}`);
    process.exit(2);
    return;
  }
  const { rootDir, allowRemote, timeoutMs } = parsed;

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

  const runnerResult = await runScanner(targets, { allowRemote, timeoutMs });
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
    // ⚠️ 2026-08-27 문구 정정: 종전에는 맨 `'unavailable'` 이었다. 헤더가
    //    `Scanner: ${name} ${version}` 형식이라 **"cisco-mcp-scanner unavailable"** 로 찍혔고,
    //    스캔이 성공했는데도 **"스캐너가 없어서 실패했다"로 읽혔다.** 부재의 대상(=버전)과
    //    사유를 값 안에 넣어 그 오독을 막는다. render.ts 가 요구하는 `unavailable: <why>` 계약과도
    //    이제 맞는다(맨 'unavailable' 은 그 계약의 의도를 절반만 지킨 값이었다).
    version: scannerVersion ?? '(version not reported by this scanner)',
    ruleset_hash: 'unavailable: not exposed by this scanner',
    scanned_at: new Date().toISOString(),
    target_hash: targetHash,
    python_version: py.version ?? 'unavailable: python version not readable',
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
    writeFileSync(join(rootDir, 'mcp-disclosure-findings.md'), markdown);
    writeFileSync(join(rootDir, 'mcp-disclosure-findings.json'), json);
    process.stdout.write('Report written: mcp-disclosure-findings.md, mcp-disclosure-findings.json\n');
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
// 보이는 실패"라서 제일 나쁘다. bin/mcp-disclosure.js 경유 실행은 main() 을 직접 부르므로 무관하다.
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main(process.argv.slice(2)).catch((e: unknown) => {
    process.stderr.write(`Unexpected error: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(3);
  });
}
