import type { RawFinding } from './types.js'; // §5.1 참조 — normalize.js가 아니다(A-2 파생 문제 회피)

export type ScannerRawEnvelope = {
  server_url?: string;
  scan_results?: RawScanResultEntry[];
  requested_analyzers?: string[];
};

// Task 8b 실측(2026-08-22, cisco-ai-mcp-scanner 4.8.3 — 격리 venv에 `pip install`, 로컬
// stdio MCP 서버(`@modelcontextprotocol/server-everything`)를 대상으로
// `mcp-scanner --format raw --analyzers yara,readiness,vulnerable_package config
// --config-path <실제 .mcp.json>` 실행해 raw 출력 직접 확인, `fixtures/mcp-scanner-0.1.0/
// raw-envelope.json`이 그 실측 출력의 발췌본이다):
//
// Spec §5.1b가 "최선 추정"으로 적었던 스키마(`scan_results[].findings[]` = 개별 finding 객체의
// **배열**, 각 원소가 `rule`/`rule_id` 필드를 가짐)는 **구조 자체가 실제와 다르다** — 실측 결과는:
//   - `scan_results[]`는 "분석기 1회 실행당 1개 원소"가 아니라 **"스캔 대상 항목(도구/프롬프트/
//     리소스) 1개당 1개 원소"**다.
//   - 각 원소의 `findings`는 배열이 아니라 **분석기 이름을 키로 하는 객체**다
//     (`{ yara_analyzer: {...}, readiness_analyzer: {...}, ... }`).
//   - 각 분석기 결과는 개별 finding 목록이 아니라 **롤업 요약**이다: `severity`(단일값,
//     "SAFE"/"HIGH" 등 대문자) · `threat_names`(문자열 배열, 실측에서는 "unknown" 1개뿐이었다)
//     · `threat_summary`(자유 텍스트) · `total_findings`(개수) · (readiness만) `mcp_taxonomies`.
//   - `rule`/`rule_id` 필드 자체가 **존재하지 않는다**. 개별 finding을 식별할 안정적인 rule
//     식별자가 이 스캐너 버전의 raw 출력에는 없다.
//
// 이 사실은 §5.4 ontology.yaml 의 구 `rule_map` 설계(`HEUR-001`, `credential_harvesting`,
// `CVE-*`, `prompt_injection` 등 rule 이름 매칭)가 실제 finding 에는 **매칭 대상 필드가 없어
// 항상 미매칭(axis: null)**이 된다는 뜻이었다.
//
// → **해소(개정안 #01, 2026-08-22 승인)**: 키 공간을 `(분석기, threat_name)` + AISubtech
//   taxonomy 로 교체했다(`ontology.yaml` 작성 완료, `src/ontology.ts` 로더 구현 완료).
//
// ⚠️ **이 파일에 남은 후속 작업 2건**(Spec §12 미결 ⑤ — Task 12/15 착수 전 필수):
//   ①`RawFinding` 이 `analyzer`·`threatName` 을 **따로** 가져야 한다. 아래 구현은 두 값을
//     `rule` 문자열 하나로 합치는데(`"readiness_analyzer:unknown"`), 새 `assignAxis` 는
//     둘을 분리해서 받는다.
//   ②**실측 버그**: `taxonomy` 에 `summary.mcp_taxonomies[0]` 을 그대로 넣는데, 그 원소는
//     문자열이 아니라 `{aitech, aisubtech, ...}` **객체**다(아래 `RawAnalyzerSummary` 의
//     `mcp_taxonomies?: string[]` 선언 자체가 틀렸다). `aisubtech` 문자열만 뽑아야 한다.
//     Session 1 실측에서는 taxonomy 가 항상 빈 배열이라 드러나지 않았던 잠복 버그다 —
//     YARA 발화·prompt_defense 실측(개정안 #01 §2.3)에서 객체임이 확인됐다.
export type RawScanResultEntry = {
  status?: string;
  is_safe?: boolean;
  findings?: Record<string, RawAnalyzerSummary>; // 분석기명 → 롤업 요약(배열이 아니다)
  tool_name?: string;
  resource_name?: string;
  prompt_name?: string;
  item_type?: string;
  server_source?: string;
  server_name?: string;
  [key: string]: unknown;
};

export type RawAnalyzerSummary = {
  severity?: string;           // "SAFE" | "HIGH" | ... (대문자, §0 전제사항 소문자 Severity와 별개)
  threat_names?: string[];
  threat_summary?: string;
  total_findings?: number;
  mcp_taxonomies?: string[];   // readiness_analyzer에서만 관측(현재까지는 항상 빈 배열)
  [key: string]: unknown;
};

export function parseScannerRawEnvelope(raw: unknown, fallbackTarget: string): RawFinding[] {
  const envelope = raw as ScannerRawEnvelope;
  const scanResults = Array.isArray(envelope?.scan_results) ? envelope.scan_results : [];
  const out: RawFinding[] = [];
  for (const entry of scanResults) {
    const findingsByAnalyzer = entry.findings && typeof entry.findings === 'object' ? entry.findings : {};
    const target = (entry.tool_name ?? entry.resource_name ?? entry.prompt_name ?? entry.server_name ?? fallbackTarget) as string;
    for (const [analyzerKey, summary] of Object.entries(findingsByAnalyzer)) {
      const totalFindings = typeof summary?.total_findings === 'number' ? summary.total_findings : 0;
      if (totalFindings <= 0) continue; // "SAFE"(0건)는 finding이 아니다 — 조용히 건너뛴다
      const threatNames = Array.isArray(summary.threat_names) ? summary.threat_names : [];
      // rule 필드가 원본에 없으므로(위 주석 참조) analyzer명+threat_names로 최선 근사 식별자를 만든다.
      const rule = threatNames.length > 0 ? `${analyzerKey}:${threatNames.join('+')}` : analyzerKey;
      const taxonomy = Array.isArray(summary.mcp_taxonomies) && summary.mcp_taxonomies.length > 0
        ? summary.mcp_taxonomies[0]
        : undefined;
      out.push({
        rule,
        target,
        taxonomy,
        severity: typeof summary.severity === 'string' ? summary.severity : undefined,
        raw: { ...summary, analyzer: analyzerKey, tool_name: entry.tool_name, item_type: entry.item_type, server_name: entry.server_name },
      });
    }
  }
  return out;
}
