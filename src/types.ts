export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// --- 아래 4개는 원래 ontology.ts에 있었으나 A-2 codex 반영으로 이 파일로 이동했다.
// ontology.ts는 이 값들을 import한 뒤 재노출(re-export)만 한다(§5.2 참조) ---
export const ALL_AXES = [
  'prompt_injection_defense', 'secret_exposure', 'vulnerable_deps',
  'malicious_pattern', 'operational_reliability',                       // scannable (5)
  'tool_permission', 'auth_oauth', 'data_flow', 'logging', 'sdlc',      // partial (5)
  'incident_response', 'data_retention', 'subprocessor',
  'training_data', 'dpa',                                               // not_scannable (5)
] as const;

export type CoverageAxis = typeof ALL_AXES[number];
export type Coverage = 'scannable' | 'partial' | 'not_scannable';
export type ClaimType = 'technical_control' | 'operational_practice' | 'policy_proof';

// 아래 1개는 원래 masking.ts에 있었으나 A-2 codex 반영으로 이 파일로 이동했다.
// masking.ts는 이 타입을 import한 뒤 재노출만 한다(§5.6 참조)
export type RedactedRaw = { redacted: true; fields: Record<string, string | number | boolean | null> };

// 아래 1개는 원래 normalize.ts에 있었으나, scanner-envelope.ts(Task 8a, Session 1)가 normalize.ts
// (Task 11, 마찬가지로 Session 1이지만 시간상 더 뒤)보다 먼저 이 타입을 필요로 해서(A-1 codex 반영
// 파생 문제) 이 파일로 옮겼다. normalize.ts는 import한 뒤 재노출만 한다(§8.5 Task 11 참조)
// 개정안 #01(2026-08-22 승인) 반영: `analyzer`·`threatName` 을 **따로** 싣는다.
// 축 분류(assignAxis)가 (분석기, threat_name) 쌍을 키로 쓰기 때문이다 — 구 설계는 둘을
// `rule` 문자열 하나로 합쳐 놔서(`"readiness_analyzer:unknown"`) 분해가 불가능했다.
// `rule` 은 사람이 읽는 합성 식별자로 유지한다(안정 ID 계산·소견서 표기에 쓰인다).
export type RawFinding = {
  analyzer: string;      // 스캐너 출력의 분석기 키 그대로(예: 'yara_analyzer')
  threatName?: string;   // threat_names 원소 1개. 비어 있을 수 있다(readiness 등)
  rule: string;          // `${analyzer}:${threatName}` 또는 threatName 부재 시 `${analyzer}`
  target: string;
  line?: number;
  taxonomy?: string;     // AISubtech-N.N.N 문자열 — 짝을 알 수 없으면 undefined(추정 금지)
  severity?: string;
  raw: Record<string, unknown>;
};

export type Finding = {
  id: string;                 // 안정 ID — §5.1a
  severity: Severity;
  axis: CoverageAxis | null;  // null = 미분류(FR-03.4 ③) — 버리지 않는다
  rule: string;
  target: string;              // 대상 서버명/식별자 — 원본 설정 문자열 미포함(FR-01a)
  line?: number;
  match_index: number;         // §5.1a 그룹 내 순번
  duplicate_count?: number;    // byte-identical 중복 접힘 시에만 존재 (§5.1a, 개발계획 §3.1 누락분 보강)
  taxonomy?: string;           // AITech-N.N — 있으면 보존(v0는 대부분 미보유, §0 전제사항)
  scanner_meta: ScannerMeta;
  raw: RedactedRaw;            // 마스킹 후 값만 — 무마스킹 보존 금지(FR-05.1)
};

export type ScannerMeta = {
  name: string;
  version: string;
  ruleset_hash: string;
  scanned_at: string;      // ISO8601
  target_hash: string;
  python_version: string;
};

// --- §5.5 Claim ---
// 개정안 #01(2026-08-22 승인) 반영 — 술어가 3종이 됐다.
// **`scanner_not_detected` 와 `scanner_cannot_detect` 는 전혀 다른 말이다:**
//   not_detected  = 스캐너가 그 축을 **검사했고** 아무것도 못 찾았다
//   cannot_detect = 스캐너가 그 축을 **애초에 볼 수 없다**(signal_status: unreachable_in_v0)
// 둘을 한 술어로 뭉치면 "못 본 것"이 "깨끗한 것"으로 읽힌다 — 이 제품이 존재하는 이유가
// 정확히 그 혼동을 없애는 것이므로(PRD-v2 §1 커버리지 정직성), 타입 단계에서 갈라 둔다.
export type Claim =
  | { type: 'technical_control'; axis: CoverageAxis;
      predicate: 'scanner_detected' | 'scanner_not_detected' | 'scanner_cannot_detect';
      finding_ids: string[];
      unreachable_reason?: string; }   // predicate가 'scanner_cannot_detect'이면 필수
  | { type: 'operational_practice'; axis: CoverageAxis; evidence_request: string }
  | { type: 'policy_proof';        axis: CoverageAxis; evidence_request: string };

// --- §5.7 ScanTarget / Unscanned ---
export type Transport = 'local_stdio' | 'remote';
export type TargetKind = 'mcp_server' | 'agent_def' | 'hook' | 'permission';

export type ScanTarget = {
  kind: TargetKind;
  sourcePath: string;      // 로컬 파일 경로
  name: string;
  transport: Transport;
  remoteUrl?: string;      // transport==='remote'일 때만 — argv에는 조건부로만 전달(§8.3 ADR-006)
};

export type UnscannedReason = 'remote_out_of_scope' | 'timeout' | 'output_too_large' | 'scanner_error';
export type Unscanned = { target: ScanTarget; reason: UnscannedReason; detail?: string };
