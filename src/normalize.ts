// src/normalize.ts (1/3 — canonicalStringify + 그룹핑/중복접기, Task 11)
import { createHash } from 'node:crypto';
// A-1 codex 반영 파생 수정: RawFinding 은 §5.1 에서 types.ts 로 이동했다(scanner-envelope.ts 가
// normalize.ts 보다 먼저 이 타입을 필요로 하기 때문 — §5.0 참조). 여기서는 재노출만 한다.
import type { RawFinding } from './types.js';

export type { RawFinding };
export type RawFindingWithIndex = RawFinding & { match_index: number; duplicate_count?: number };

// ⚠️ 셔플 재현성 회귀 수정(codex 테스트보강 반영): JSON.stringify(undefined) 와
// JSON.stringify(NaN) 이 각각 undefined(값 자체)와 "null" 을 반환해, JSON.stringify(null) 의
// "null" 과 충돌한다 — 즉 raw:{a:NaN} 과 raw:{a:null} 이 같은 해시로 접혀버리는 실제 버그였다.
// 공백 접두 시그니처(' undefined' · ' NaN')는 정상 JSON.stringify 출력에 나타날 수 없으므로 안전하다.
//
// ⚠️ 이 방어가 무력화되는 입력: 순환 참조(circular reference)가 있는 raw 는 이 함수가 무한
//    재귀로 죽는다. 현재 입력원은 JSON.parse 결과뿐이라 순환이 생길 수 없어 방어하지 않는다 —
//    다른 입력원이 생기면 이 전제가 깨진다.
function canonicalStringify(value: unknown): string {
  if (value === undefined) return ' undefined';
  if (typeof value === 'number' && Number.isNaN(value)) return ' NaN';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(',')}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalStringify((value as Record<string, unknown>)[k])}`).join(',')}}`;
}

/**
 * 같은 (rule, target, line) 그룹 안에서 match_index 를 부여하고, byte-identical 중복을 접는다.
 *
 * 해시로 정렬하기 때문에 **입력 순서가 달라져도 같은 배정**이 나온다 — 안정 ID(§5.1a)가
 * 스캔마다 흔들리지 않으려면 이 성질이 필요하다.
 */
export function groupAndAssignMatchIndex(rawFindings: RawFinding[]): { grouped: RawFindingWithIndex[] } {
  const byKey = new Map<string, RawFinding[]>();
  for (const f of rawFindings) {
    const key = `${f.rule}|${f.target}|${f.line ?? '-'}`;
    const bucket = byKey.get(key) ?? [];
    bucket.push(f);
    byKey.set(key, bucket);
  }

  const result: RawFindingWithIndex[] = [];
  for (const group of byKey.values()) {
    const withHash = group.map(f => ({ f, hash: createHash('sha256').update(canonicalStringify(f.raw)).digest('hex') }));
    withHash.sort((a, b) => a.hash.localeCompare(b.hash));

    let idx = 0;
    let i = 0;
    while (i < withHash.length) {
      let j = i;
      while (j + 1 < withHash.length && withHash[j + 1].hash === withHash[i].hash) j++;
      const dupCount = j - i + 1;
      result.push({ ...withHash[i].f, match_index: idx, duplicate_count: dupCount > 1 ? dupCount : undefined });
      idx++;
      i = j + 1;
    }
  }
  return { grouped: result };
}

// --- src/normalize.ts (2/3 — computeStableId, Task 12) ---

/**
 * finding 의 안정 ID (§5.1a). 같은 스캔 대상·같은 스캐너 버전이면 실행할 때마다 같은 값이 나온다.
 *
 * 스캐너명·버전을 입력에 넣는 이유: 같은 룰 이름이라도 **다른 엔진·다른 버전의 판정은 다른
 * 근거**다. 버전이 올라 판정 기준이 바뀌었는데 ID 가 같으면, 소견서를 비교하는 쪽이 "같은
 * 지적이 그대로 남아 있다"고 잘못 읽는다.
 */
export function computeStableId(
  scanner: string, version: string, rule: string, target: string,
  line: number | undefined, matchIndex: number,
): string {
  const input = `${scanner}|${version}|${rule}|${target}|${line ?? '-'}|${matchIndex}`;
  return createHash('sha256').update(input).digest('hex').slice(0, 16);
}

// --- src/normalize.ts (3/3 — assignAxis, Task 13) ---
import type { AxisTable, CoverageAxis } from './ontology.js';

// 개정안 #01 §5.3: 이 분석기의 finding 은 전부 "이 방어가 없다"는 **결여 보고**이지 위협 탐지가
// 아니므로 taxonomy 를 따라가면 안 된다. 따라가면 DATA_LEAKAGE 방어결여가 secret_exposure
// (=실제 시크릿 노출)로 새어, 소견서가 "시크릿이 노출됐다"고 잘못 말한다.
// ⚠️ 스캐너가 내는 실제 키는 'promptdefense_analyzer' 다 — 요청 이름 'prompt_defense' 로
//    만들어지는 동명의 유령 키(항상 0건)와 다르다(개정안 #01 §2.2).
const TAXONOMY_EXEMPT_ANALYZERS = new Set(['promptdefense_analyzer']);

export type AxisInput = { analyzer: string; threatName?: string; taxonomy?: string };

/**
 * finding 을 커버리지 축에 배정한다. 3단 시도(FR-03.4):
 *   ① accepts_taxonomy — AISubtech 정확 일치 (최우선)
 *   ② signal_map — (분석기, threat_name) 정확 일치. '*' 는 분석기 전체 배정
 *   ③ 미분류 → null (버리지 않는다 — 호출부가 axis:null 로 보존한다)
 *
 * ⚠️ 글롭 매칭은 쓰지 않는다. 키 공간(분석기명·threat_name·AISubtech ID)이 전부 유한한
 *    열거값이라 글롭이 필요 없고, 없애면 "오타 패턴이 조용히 0건 매칭"되는 실패 모드도 사라진다.
 */
export function assignAxis(input: AxisInput, axisTable: AxisTable): CoverageAxis | null {
  const entries = Object.entries(axisTable) as [CoverageAxis, AxisTable[CoverageAxis]][];

  // ① taxonomy 매핑 (AISubtech 정확 일치 — 상위 AITech 는 두 축 충돌을 일으켜 쓰지 않는다)
  if (input.taxonomy && !TAXONOMY_EXEMPT_ANALYZERS.has(input.analyzer)) {
    for (const [axis, entry] of entries) {
      if (entry.accepts_taxonomy?.includes(input.taxonomy)) return axis;
    }
  }

  // ② signal_map 매핑
  for (const [axis, entry] of entries) {
    const names = entry.signal_map?.[input.analyzer];
    if (names === undefined) continue;
    if (names === '*') return axis;
    if (input.threatName !== undefined && names.includes(input.threatName)) return axis;
  }

  // ③ 미분류
  return null;
}
