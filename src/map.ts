// src/map.ts — finding → claim 매핑 (FR-03)
import { ALL_AXES } from './ontology.js';
import type { AxisTable } from './ontology.js';
import type { Finding, Claim } from './types.js';

/**
 * 축마다 **정확히 1개**의 클레임을 만든다. 축이 15개면 클레임도 항상 15개다 —
 * "찾은 것만 보여주는" 리포트가 되지 않게 하려는 것이 이 고정 개수의 목적이다.
 */
export function mapFindingsToClaims(findings: Finding[], axisTable: AxisTable): Claim[] {
  const claims: Claim[] = [];
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
