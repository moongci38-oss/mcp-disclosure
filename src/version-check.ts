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

function majorVersion(v: string): number {
  return parseInt(v.split('.')[0], 10);
}

// 지원 범위: mcp-scanner 0.x (조사일 2026-08-21 실측 기준, package.json의 agenttrust.supportedScannerRange와
// 값을 맞춰 둔다)
// ⚠️ Task 8b 실측(2026-08-22): 실제 설치 가능한 PyPI 최신판은 **4.8.3**이다 — "0.x"는 조사 시점
// 기준 낡은 가정이다. 다만 getScannerVersion()이 실전에서 버전 문자열을 절대 못 얻는다는 사실이
// 함께 확인됐으므로(아래 참조) 이 함수는 사실상 CLI 경로로는 호출되지 않는다. 지원범위 값 자체의
// 재정의는 Task 8b의 명시 책임 항목이 아니라 이 코멘트로만 남기고 §12 미결(IMPL-NOTES.md)로
// 넘긴다 — 상세: docs/scanner-exit-codes.md.
export function checkScannerVersion(actual: string): { withinRange: boolean; warning?: string } {
  const maj = majorVersion(actual);
  const withinRange = maj === 0;
  if (withinRange) return { withinRange: true };
  return {
    withinRange: false,
    warning: `mcp-scanner ${actual} is outside the tested range (0.x). Continuing — this may be a newer scanner version.`,
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
