import { spawnSync } from 'node:child_process';

export function checkPythonAvailable(): { ok: boolean; version?: string } {
  for (const bin of ['python3', 'python']) {
    const r = spawnSync(bin, ['--version']);
    if (r.status === 0) {
      return { ok: true, version: (r.stdout?.toString() || r.stderr?.toString() || '').trim() };
    }
  }
  return { ok: false };
}

// ⚠️ **"지원 범위"가 아니라 "검증한 버전"이다.** 구 구현은 `0.x` 를 지원 범위로 박아 두고
// major 가 0 이 아니면 "범위 밖"이라고 경고했는데, 실제로 우리가 전부 검증한 버전은 **4.8.3** 이다
// — 즉 코드가 자기가 지원하는 유일한 버전을 "지원 안 함"이라고 말하고 있었다(2026-08-22 Spec 감사).
//
// 범위(`4.x` 같은)를 선언하지 않는 이유: **근거가 없다.** 실측한 버전이 하나뿐이라 어디까지
// 같은 동작을 하는지 알 수 없고, 근거 없이 넓히면 그것도 거짓말이다. 이 제품은 모르는 것을
// 아는 것처럼 쓰지 않는다. 두 번째 버전을 실측하는 날 목록에 추가한다.
//
// package.json 의 `agenttrust.testedScannerVersions` 와 값을 맞춰 둔다 —
// 어긋나면 `version-check.test.ts` 가 FAIL 한다(선언과 코드가 갈라지는 것을 테스트로 막는다).
export const TESTED_SCANNER_VERSIONS = ['4.8.3'] as const;

export function checkScannerVersion(
  actual: string,
  tested: readonly string[] = TESTED_SCANNER_VERSIONS,
): { tested: boolean; warning?: string } {
  if (tested.includes(actual)) return { tested: true };
  return {
    tested: false,
    warning:
      `mcp-scanner ${actual} has not been tested with this tool ` +
      `(tested: ${tested.join(', ')}). Continuing — output shape may differ.`,
  };
}

// A-3 codex 반영: 종전엔 이 함수 자체가 없어서 ScannerMeta.version이 '0.0.0-unset'으로
// 하드코딩됐고 checkScannerVersion이 실제 CLI 실행경로에서 한 번도 호출되지 않았다(AC-02d가
// 죽어 있었다). Task 25(cli.ts)가 이 함수의 반환값을 checkScannerVersion에 넘겨 배선한다.
// Task 8b 실측(2026-08-22): `mcp-scanner --version`은 **존재하지 않는 플래그**다 — argparse가
// "unrecognized arguments: --version"로 거부하며 exit code **2**를 반환한다(stdout 없음).
// 즉 `r.status !== 0` 분기가 실전에서 항상 타서 이 함수는 **항상 null을 반환**한다 — 이것은
// 버그가 아니라 안전 기본값이 의도대로 동작하는 것이다("버전 못 얻음 = unknown, 하드 실패 아님").
// CLI로 버전을 얻는 대체 경로(`pip show cisco-ai-mcp-scanner` 등)는 Node에서 pip 바이너리
// 위치를 추가로 알아야 해 이 함수의 책임 밖이다 — §12 미결(IMPL-NOTES.md), docs/scanner-exit-codes.md 참조.
export function getScannerVersion(bin = 'mcp-scanner'): string | null {
  const r = spawnSync(bin, ['--version']);
  if (r.error || r.status !== 0 || !r.stdout) return null; // 스캐너 미설치/실행실패 — 전역 하드실패 아님(개별 scanOne이 처리)
  const out = r.stdout.toString().trim();
  const match = out.match(/(\d+\.\d+\.\d+)/);
  return match ? match[1] : out;
}
