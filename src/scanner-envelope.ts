import type { RawFinding } from './types.js'; // §5.1 참조 — normalize.js가 아니다(A-2 파생 문제 회피)

export type ScannerRawEnvelope = {
  server_url?: string;
  scan_results?: RawScanResultEntry[];
  requested_analyzers?: string[];
};

// Task 8b 실측(2026-08-22, cisco-ai-mcp-scanner 4.8.3 — 격리 venv에 `pip install`, 로컬
// stdio MCP 서버(`@modelcontextprotocol/server-everything`)를 대상으로
// `mcp-scanner --format raw --analyzers yara,readiness,vulnerable_package config
// --config-path <실제 .mcp.json>` 실행해 raw 출력 직접 확인, `fixtures/mcp-scanner-4.8.3/
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

// mcp_taxonomies[] 의 원소는 **문자열이 아니라 객체**다. 구 선언(`string[]`)은 틀렸고,
// 그 탓에 `taxonomy` 문자열 필드에 객체가 대입되는 잠복 버그가 있었다 — Session 1 실측에서는
// 이 배열이 항상 비어 있어서(readiness 만 관측) 드러나지 않았다. 개정안 #01 §2.3 에서
// YARA 를 실제로 발화시켜 객체 구조를 확인했다.
export type RawMcpTaxonomy = {
  scanner_category?: string;
  aitech?: string;        // 예: "AITech-8.2" — 상위 ID(축 충돌 유발, 매칭에 쓰지 않는다)
  aitech_name?: string;
  aisubtech?: string;     // 예: "AISubtech-8.2.3" — 이것만 매칭 키로 쓴다(§5.3)
  aisubtech_name?: string;
  description?: string;
  [key: string]: unknown;
};

export type RawAnalyzerSummary = {
  severity?: string;           // "SAFE" | "HIGH" | ... (대문자, §0 전제사항 소문자 Severity와 별개)
  threat_names?: string[];
  threat_summary?: string;
  total_findings?: number;
  mcp_taxonomies?: RawMcpTaxonomy[];
  [key: string]: unknown;
};

/**
 * 스캐너가 이번 스캔에서 이 분석기에 대해 낸 taxonomy 를 정한다.
 *
 * ⚠️ **짝을 모르면 비운다 — 추정하지 않는다.** 롤업은 `threat_names` 와 `mcp_taxonomies` 를
 * 각각 중복 제거해 나열할 뿐, 둘 사이의 대응관계를 남기지 않는다. 실측 예: promptdefense 는
 * threat_names 12개에 taxonomies 6개다(개정안 #01 §2.2) — 어느 것이 어느 것의 짝인지 알 수
 * 없다. 원소가 정확히 1개일 때만 명확하므로 그때만 채우고, 나머지는 `raw` 에 전량 보존한다.
 * 이 제품은 못 보는 것을 본 것처럼 쓰지 않는다.
 */
function resolveTaxonomy(
  taxonomies: RawMcpTaxonomy[] | undefined,
  threatNameCount: number,
): string | undefined {
  // 조건이 **둘** 이다: taxonomy 가 1개이고, **threat_name 도 1개 이하**여야 한다.
  // ⚠️ 두 번째 조건은 2026-08-22 라이브 스캔에서 추가됐다. 그전에는 taxonomy 1개면 무조건
  //    채웠는데, 실제로 `yara_analyzer` 가 한 도구에서 threat_names 2개
  //    (`CREDENTIAL HARVESTING`, `DATA EXFILTRATION`)에 taxonomy 1개(`AISubtech-8.2.3`)를
  //    낸 사례가 나왔다. 그 하나를 **양쪽에 복사**하는 바람에 `DATA EXFILTRATION` 이
  //    taxonomy 우선순위(§5.3)를 타고 `malicious_pattern` 이 아니라 `secret_exposure` 로
  //    분류됐다 — 소견서가 "데이터 반출 패턴"을 "시크릿 노출"로 잘못 말한 것이다.
  //    짝을 모를 때 하나를 빌려 쓰면 그건 추정이지 관측이 아니다.
  if (threatNameCount > 1) return undefined;
  if (!Array.isArray(taxonomies) || taxonomies.length !== 1) return undefined;
  const sub = taxonomies[0]?.aisubtech;
  return typeof sub === 'string' && sub.length > 0 ? sub : undefined;
}

export function parseScannerRawEnvelope(raw: unknown, fallbackTarget: string): RawFinding[] {
  const envelope = raw as ScannerRawEnvelope;
  const scanResults = Array.isArray(envelope?.scan_results) ? envelope.scan_results : [];
  const out: RawFinding[] = [];

  for (const entry of scanResults) {
    const findingsByAnalyzer = entry.findings && typeof entry.findings === 'object' ? entry.findings : {};
    const target = (entry.tool_name ?? entry.resource_name ?? entry.prompt_name ?? entry.server_name ?? fallbackTarget) as string;

    for (const [analyzer, summary] of Object.entries(findingsByAnalyzer)) {
      const totalFindings = typeof summary?.total_findings === 'number' ? summary.total_findings : 0;
      // "SAFE"(0건)는 finding 이 아니다. 요청 이름으로 만들어지는 유령 키
      // (prompt_defense_analyzer — 항상 0건)도 여기서 함께 걸러진다.
      if (totalFindings <= 0) continue;

      const threatNames = Array.isArray(summary.threat_names) ? summary.threat_names : [];
      const uniqueThreatNames = [...new Set(threatNames)];
      const taxonomy = resolveTaxonomy(summary.mcp_taxonomies, uniqueThreatNames.length);
      const severity = typeof summary.severity === 'string' ? summary.severity : undefined;
      const rawPayload = {
        ...summary,
        analyzer,
        tool_name: entry.tool_name,
        item_type: entry.item_type,
        server_name: entry.server_name,
      };

      // threat_name 단위로 펼친다 — 축 분류가 (분석기, threat_name) 쌍을 키로 쓰기 때문이다.
      // 12종을 1건으로 뭉치면 그중 어느 축으로 갈지 정할 수 없다.
      // threat_names 가 비어 있어도(readiness 등) 신호 자체는 버리지 않고 1건 남긴다.
      const names: (string | undefined)[] = uniqueThreatNames.length > 0 ? uniqueThreatNames : [undefined];
      for (const threatName of names) {
        out.push({
          analyzer,
          threatName,
          rule: threatName === undefined ? analyzer : `${analyzer}:${threatName}`,
          target,
          taxonomy,
          severity,
          raw: rawPayload,
        });
      }
    }
  }
  return out;
}
