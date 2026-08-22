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
export type RawFinding = { rule: string; target: string; line?: number; taxonomy?: string; severity?: string; raw: Record<string, unknown> };

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
export type Claim =
  | { type: 'technical_control'; axis: CoverageAxis;
      predicate: 'scanner_detected' | 'scanner_not_detected';
      finding_ids: string[]; }
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
