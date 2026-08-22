// src/ontology.ts — 커버리지 축 온톨로지 로더 (§5.2·§5.3)
//
// A-2 codex 반영: ALL_AXES/CoverageAxis/Coverage/ClaimType 은 types.ts 소유이고 여기서는
// import 후 재노출만 한다. 하위 모듈(map/normalize/render)이 './ontology.js' 경로로 계속
// import 할 수 있도록 경로를 보존하기 위한 재노출이다.
import { ALL_AXES } from './types.js';
import type { CoverageAxis, Coverage, ClaimType } from './types.js';

export { ALL_AXES };
export type { CoverageAxis, Coverage, ClaimType };

// 개정안 #01(2026-08-22 승인) 반영: 구 `rule_map`(rule ID 키)은 폐기했다 — mcp-scanner 4.8.3
// CLI 출력에 rule 식별자가 실리지 않는다(report_generator.py:82 가 details["threat_type"] 만
// 직렬화한다). 키 공간은 accepts_taxonomy(AISubtech ID) + signal_map((분석기, threat_name)) 다.
export type SignalStatus = 'reachable' | 'unreachable_in_v0' | 'not_applicable';

// '*' = 그 분석기의 모든 finding 을 이 축으로 배정(threat_name 세분화가 불가능할 때).
export type SignalMap = Record<string, string[] | '*'>;

export type AxisEntry = {
  coverage: Coverage;          // 원리적으로 스캔 가능한 성격인가 (성격 축)
  claim_type: ClaimType;
  signal_status: SignalStatus; // 지금 우리 파이프라인에 신호가 실제로 오는가 (도달 축)
  accepts_taxonomy?: string[];
  signal_map?: SignalMap;
  unreachable_reason?: string;
  evidence_request?: string;
};

export type AxisTable = Record<CoverageAxis, AxisEntry>;

export class OntologyError extends Error {}

const COVERAGE_VALUES = new Set<Coverage>(['scannable', 'partial', 'not_scannable']);
const CLAIM_TYPE_VALUES = new Set<ClaimType>(['technical_control', 'operational_practice', 'policy_proof']);
const SIGNAL_STATUS_VALUES = new Set<SignalStatus>(['reachable', 'unreachable_in_v0', 'not_applicable']);

// C-3 codex 반영(개정안 #01로 키 공간 교체): 동일 신호가 서로 다른 두 축에 등록되면 어느 축이
// 이기는지가 Object.entries() 순회 순서(=YAML 선언 순서)에 암묵적으로 좌우된다 — "우선순위가
// 조용히 의미를 바꾼다"는 지적의 핵심이다. fail-closed 로 아예 등록을 막는다.
//
// ⚠️ 이 방어가 무력화되는 입력: 두 축이 **의미상 겹치지만 문자열이 다른** 신호를 각각 등록하면
//    (예: 같은 위협을 가리키는 두 threat_name) 이 검사는 통과한다. 문자열 동일성만 본다.
function assertNoDuplicateSignals(axes: Record<string, AxisEntry>): void {
  const owner = new Map<string, string>();
  const claim = (key: string, axis: string, kind: string): void => {
    const prev = owner.get(key);
    if (prev && prev !== axis) {
      throw new OntologyError(
        `${kind} "${key}"이(가) 두 축("${prev}", "${axis}")에 중복 등록됨 — ` +
        `하나의 신호는 정확히 1개 축에만 배정해야 한다(§0 배타배정 원칙)`
      );
    }
    owner.set(key, axis);
  };
  for (const [axis, entry] of Object.entries(axes)) {
    for (const [analyzerKey, names] of Object.entries(entry.signal_map ?? {})) {
      if (names === '*') { claim(`${analyzerKey}::*`, axis, 'signal_map 항목'); continue; }
      for (const n of names) claim(`${analyzerKey}::${n}`, axis, 'signal_map 항목');
    }
    for (const t of entry.accepts_taxonomy ?? []) claim(`taxonomy::${t}`, axis, 'accepts_taxonomy 항목');
  }
}

/**
 * ontology.yaml 파싱 결과를 검증해 AxisTable 로 확정한다.
 *
 * ⚠️ 전수성은 타입이 아니라 이 함수가 보장한다 — `Record<CoverageAxis, …>` 타입 단언은
 * 런타임 외부 데이터(YAML)를 검사하지 못하고 빈 표도 통과시킨다. 이 제품이 경계하는
 * "등록됐다 ≠ 차단한다" 패턴이며, 실질 방어는 이 함수 하나뿐이다(§5.3).
 */
export function loadAxisTable(parsed: unknown): AxisTable {
  const axes = ((parsed as { axes?: Record<string, AxisEntry> })?.axes ?? {}) as Record<string, AxisEntry>;

  const missing = ALL_AXES.filter(a => !(a in axes));
  if (missing.length > 0) {
    throw new OntologyError(`ontology.yaml 축 누락: ${missing.join(', ')}`);
  }
  assertNoDuplicateSignals(axes);

  const result = {} as AxisTable;
  for (const axis of ALL_AXES) {
    const entry = axes[axis];
    if (!COVERAGE_VALUES.has(entry.coverage)) {
      throw new OntologyError(`${axis}.coverage 값 불량: ${String(entry.coverage)}`);
    }
    if (!CLAIM_TYPE_VALUES.has(entry.claim_type)) {
      throw new OntologyError(`${axis}.claim_type 값 불량: ${String(entry.claim_type)}`);
    }
    if (!SIGNAL_STATUS_VALUES.has(entry.signal_status)) {
      throw new OntologyError(`${axis}.signal_status 값 불량: ${String(entry.signal_status)}`);
    }
    // 개정안 #01: "신호가 안 온다"고 선언했으면 반드시 사유를 적는다. 사유 없는 unreachable 은
    // 소견서에서 빈칸으로 보이고, 빈칸은 "검사했는데 깨끗함"으로 오독된다.
    if (entry.signal_status === 'unreachable_in_v0' && !entry.unreachable_reason?.trim()) {
      throw new OntologyError(`${axis}.unreachable_reason 누락 — unreachable_in_v0 축은 사유가 필수다`);
    }
    // 반대 방향도 막는다: reachable 이라면서 신호원이 하나도 없으면 선언과 내용이 어긋난다.
    const hasSignal = Object.keys(entry.signal_map ?? {}).length > 0
      || (entry.accepts_taxonomy ?? []).length > 0;
    if (entry.signal_status === 'reachable' && !hasSignal) {
      throw new OntologyError(`${axis}: signal_status=reachable 인데 signal_map·accepts_taxonomy가 모두 비었다`);
    }
    // coverage(성격 축)와 signal_status(도달 축)가 서로 모순되지 않게 교차 검증한다.
    if (entry.coverage === 'not_scannable') {
      if (entry.signal_status !== 'not_applicable') {
        throw new OntologyError(`${axis}: not_scannable 축은 signal_status가 not_applicable 이어야 한다`);
      }
      if (!entry.evidence_request?.trim()) {
        throw new OntologyError(`${axis}.evidence_request 누락 — not_scannable 축은 증빙 요청문이 필수다`);
      }
    } else if (entry.signal_status === 'not_applicable') {
      throw new OntologyError(`${axis}: 기술 축(coverage=${entry.coverage})에 not_applicable 은 쓸 수 없다`);
    }
    result[axis] = entry;
  }
  return result;
}
