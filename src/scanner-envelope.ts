import type { RawFinding } from './types.js'; // §5.1 참조 — normalize.js가 아니다(A-2 파생 문제 회피)

export type ScannerRawEnvelope = {
  server_url?: string;
  scan_results?: RawScanResultEntry[];
  requested_analyzers?: string[];
};

// ⚠️ Session 1 Task 8b 실측 확정 필요: 조사 문서는 최상위 3개 키(server_url/scan_results/
// requested_analyzers)만 확인했고 `scan_results[]` 원소 내부 필드명은 실측하지 못했다. 아래는
// Cisco 소스(`mcpscanner/core/analyzers/`가 YARA 룰명·taxonomy·severity를 finding 단위로
// 반환한다는 설계 원칙, §1 6종 엔진 표)에 근거한 "최선 추정"이며 Task 8b에서 실제 필드명으로 교체한다.
export type RawScanResultEntry = {
  target?: string;
  analyzer?: string;
  findings?: RawScannerFindingEntry[];
  [key: string]: unknown;
};

export type RawScannerFindingEntry = {
  rule?: string;
  rule_id?: string;      // 실제 필드명이 rule/rule_id 둘 중 무엇인지 미확정 — 둘 다 시도
  taxonomy?: string;     // AITech-N.N
  severity?: string;
  target?: string;
  line?: number;
  [key: string]: unknown;
};

export function parseScannerRawEnvelope(raw: unknown, fallbackTarget: string): RawFinding[] {
  const envelope = raw as ScannerRawEnvelope;
  const scanResults = Array.isArray(envelope?.scan_results) ? envelope.scan_results : [];
  const out: RawFinding[] = [];
  for (const entry of scanResults) {
    const findings = Array.isArray(entry.findings) ? entry.findings : [];
    for (const f of findings) {
      const rule = f.rule ?? f.rule_id;
      if (!rule) continue; // 룰 식별자가 없는 항목은 스킵 — 조용히 죽지 않고 건너뛴다(fail-open, §0)
      out.push({
        rule: String(rule),
        target: (f.target ?? entry.target ?? fallbackTarget) as string,
        line: typeof f.line === 'number' ? f.line : undefined,
        taxonomy: typeof f.taxonomy === 'string' ? f.taxonomy : undefined,
        severity: typeof f.severity === 'string' ? f.severity : undefined,
        raw: f as Record<string, unknown>,
      });
    }
  }
  return out;
}
