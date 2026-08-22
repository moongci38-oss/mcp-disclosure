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
// 값을 맞춰 둔다) — Task 8b(Session 1 실측 게이트)에서 확정치로 갱신
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
export function getScannerVersion(bin = 'mcp-scanner'): string | null {
  const r = spawnSync(bin, ['--version']);
  if (r.error || r.status !== 0 || !r.stdout) return null; // 스캐너 미설치/실행실패 — 전역 하드실패 아님(개별 scanOne이 처리)
  const out = r.stdout.toString().trim();
  // ⚠️ 정확한 --version 출력 포맷 미실측(§0 전제사항) — 정규식으로 최선 추출, Task 8b에서 확정
  const match = out.match(/(\d+\.\d+\.\d+)/);
  return match ? match[1] : out;
}
