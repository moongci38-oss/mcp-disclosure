// src/map.ts — finding → claim 매핑 (FR-03)
import { ALL_AXES } from './ontology.js';
import type { AxisTable } from './ontology.js';
import type { Finding, Claim, ScanOutcome } from './types.js';

/**
 * 축마다 **정확히 1개**의 클레임을 만든다. 축이 15개면 클레임도 항상 15개다 —
 * "찾은 것만 보여주는" 리포트가 되지 않게 하려는 것이 이 고정 개수의 목적이다.
 *
 * `outcome` 은 **선택 인자가 아니다**(도그푸딩 Task 26 발견). 기본값을 두면 호출부가 깜빡했을 때
 * 조용히 "스캔했음"으로 처리돼, 스캔이 실패한 실행이 깨끗한 소견서를 내놓는다. 모든 호출부가
 * 스캔 성사 여부를 **명시적으로 밝히게** 강제한다(fail-closed).
 */
export function mapFindingsToClaims(findings: Finding[], axisTable: AxisTable, outcome: ScanOutcome): Claim[] {
  const claims: Claim[] = [];
  // 한 건도 스캔되지 않았다면 기술축에 대해 할 수 있는 정직한 말은 "못 찾았다"가 아니라
  // "확인하지 못했다"뿐이다.
  const nothingScanned = outcome.attempted > 0 && outcome.scanned === 0;
  for (const axis of ALL_AXES) {
    const table = axisTable[axis];
    const axisFindings = findings.filter(f => f.axis === axis);

    if (table.claim_type === 'technical_control') {
      // 개정안 #01: 신호가 애초에 안 오는 축은 "검사했는데 못 찾음"이 아니다 — 그렇게 쓰면
      // 거짓말이 된다. 사유와 함께 별도 술어로 낸다.
      if (table.signal_status === 'unreachable_in_v0') {
        claims.push({
          type: 'technical_control', axis, predicate: 'scanner_cannot_detect', finding_ids: [],
          unreachable_reason: table.unreachable_reason,
        });
      } else if (nothingScanned) {
        claims.push({
          type: 'technical_control', axis, predicate: 'scanner_cannot_detect', finding_ids: [],
          unreachable_reason:
            `Not evaluated — the scan did not complete: all ${outcome.attempted} target(s) failed to scan. ` +
            `See "Unscanned items" below for the per-target reason.`,
        });
      } else {
        claims.push(
          axisFindings.length > 0
            ? { type: 'technical_control', axis, predicate: 'scanner_detected', finding_ids: axisFindings.map(f => f.id) }
            : { type: 'technical_control', axis, predicate: 'scanner_not_detected', finding_ids: [] }
        );
      }
    } else {
      claims.push({
        type: table.claim_type,
        axis,
        evidence_request: table.evidence_request ?? `${axis}: policy document / organizational statement required`,
      });
    }
  }
  return claims;
}
