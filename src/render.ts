// src/render.ts — 소견서 렌더 (FR-04)
import { ALL_AXES } from './ontology.js';
import type { Claim, Finding, ScannerMeta, Unscanned } from './types.js';

export class RenderError extends Error {}

const REQUIRED_META_FIELDS: (keyof ScannerMeta)[] = ['name', 'version', 'ruleset_hash', 'scanned_at', 'target_hash', 'python_version'];

/** 15축 전수성 — 한 축이라도 빠지면 렌더하지 않는다(AC-03b/c fail-closed). */
export function assertCoverageComplete(claims: Claim[]): void {
  const axesCovered = new Set(claims.map(c => c.axis));
  const missing = ALL_AXES.filter(a => !axesCovered.has(a));
  if (missing.length > 0) {
    throw new RenderError(`Coverage axes missing from claims: ${missing.join(', ')}`);
  }
}

/** 재현 메타 결손 — 재현할 수 없는 소견서는 소견서가 아니다(AC-02b). */
// ⚠️ 도그푸딩 Task 26 발견 — 종전 검사는 "빈 문자열이 아니면 통과"였다. 그래서 개발 중 자리표시자
// 'unset'/'unknown' 이 그대로 실린 소견서가 이 게이트를 **무사통과**했다. 가드가 있는데 아무것도
// 막지 않는, 이 프로젝트가 계속 경계해 온 바로 그 패턴이다.
// 구분을 강제한다: **'unset' = 개발자가 안 채운 것(실패)** / **'unavailable…' = 실측된 부재(통과)**.
// 후자는 소견서에 그대로 찍혀서 읽는 사람이 "이 값은 원래 못 얻는다"를 알게 된다.
const PLACEHOLDER_VALUES = new Set(['unset', 'unknown', 'n/a', 'tbd', '-']);

export function assertMetaComplete(meta: ScannerMeta): void {
  const missing = REQUIRED_META_FIELDS.filter(f => !meta[f]);
  if (missing.length > 0) {
    throw new RenderError(`Reproducibility metadata missing: ${missing.join(', ')}`);
  }
  const placeholders = REQUIRED_META_FIELDS.filter(f => PLACEHOLDER_VALUES.has(String(meta[f]).trim().toLowerCase()));
  if (placeholders.length > 0) {
    throw new RenderError(
      `Reproducibility metadata still holds placeholder values: ${placeholders.join(', ')} — ` +
      `use a real value, or "unavailable: <why>" if the scanner genuinely does not expose it`,
    );
  }
}

export type RenderOpts = { allowRemote: boolean; usedRemoteCount: number };

export function render(
  claims: Claim[], findings: Finding[], meta: ScannerMeta,
  unscanned: Unscanned[], unmatchedSignals: string[], opts: RenderOpts, ontology: any,
  scannerWarnings: string[] = [], // A-3 codex 반영 — 기본값으로 기존 7-인자 호출부 하위호환
): { markdown: string; json: string } {
  assertCoverageComplete(claims);
  assertMetaComplete(meta);

  const disclaimers = ontology.required_disclaimers;
  const noFindingText = disclaimers.no_finding
    .replace('{scanned_at}', meta.scanned_at).replace('{scanner}', meta.name).replace('{version}', meta.version);

  const scannableFound = claims.filter(c => c.type === 'technical_control' && c.predicate === 'scanner_detected');
  const scannableNotFound = claims.filter(c => c.type === 'technical_control' && c.predicate === 'scanner_not_detected');
  // 개정안 #01 — 신호가 애초에 안 오는 축. 이 줄이 없으면 5개 축이 소견서에서 **통째로 사라진다**.
  const cannotDetect = claims.filter(c => c.type === 'technical_control' && c.predicate === 'scanner_cannot_detect');
  const notScannable = claims.filter(c => c.type !== 'technical_control');

  // ⚠️ fail-closed — 모든 클레임은 정확히 한 칸에 들어가야 한다. 나중에 술어가 하나 더 늘었을 때
  // 위 filter 를 안 고치면 그 축이 조용히 소견서에서 사라지는데, 그것이 이 제품이 하지 말아야 할
  // 바로 그 일이다(못 본 것을 안 보이게 만들기). 개수로 막는다.
  const bucketed = scannableFound.length + scannableNotFound.length + cannotDetect.length + notScannable.length;
  if (bucketed !== claims.length) {
    throw new RenderError(`Claim bucketing lost ${claims.length - bucketed} claim(s) — every claim must appear in exactly one section`);
  }

  const unmappedCount = findings.filter(f => f.axis === null).length;

  let remoteBanner = '';
  if (opts.usedRemoteCount > 0) {
    remoteBanner = `\n> **Warning: This scan connected to a remote endpoint.** ${opts.usedRemoteCount} remote MCP server(s) were scanned with \`--allow-remote\`.\n`;
    if (!remoteBanner.includes('remote endpoint')) {
      throw new RenderError('Remote disclosure banner assembly failed'); // 방어적 재확인(역변조 대상, AC-01e)
    }
  }

  const lines: string[] = [];
  lines.push('# AgentTrust Findings Report');
  lines.push(`**${disclaimers.self_attested}**`);
  lines.push(`Scanner: ${meta.name} ${meta.version} · Ruleset: ${meta.ruleset_hash} · Scanned: ${meta.scanned_at} · Target: ${meta.target_hash} · Python: ${meta.python_version}`);
  lines.push(remoteBanner);
  // 스캔이 부분/전부 실패했다는 사실은 **맨 위**에 있어야 한다. 종전에는 "Unscanned items" 가
  // 문서 맨 아래에 한 줄로만 있었고, 그 위 2절은 태연히 "검사했지만 못 찾았다"고 말하고 있었다
  // (도그푸딩 Task 26 발견). 읽는 사람의 주의력에 정직성을 맡기지 않는다.
  if (unscanned.length > 0) {
    lines.push(`\n> **${unscanned.length} target(s) could not be scanned.** ` +
      `Axes below are reported only for targets that were actually scanned — see "Unscanned items".\n`);
  }
  // A-3 codex 반영 — 스캐너 버전이 지원 범위 밖일 때의 경고(cli.ts 가 채워 넘긴다)
  for (const w of scannerWarnings) lines.push(`> ⚠️ ${w}`);
  lines.push(`> ${disclaimers.genre}`);

  lines.push('\n## 1. What we scanned and found');
  // ⚠️ 도그푸딩 Task 26 발견: 실제 스캔에서 한 축에 154건이 나왔고, ID 를 전부 나열하니 소견서에서
  // 가장 중요한 절이 해시 덩어리 한 줄이 됐다. 사람이 못 읽는 정직함은 전달되지 않는다.
  // 전량은 JSON 이 갖고, markdown 은 개수 + 표본만 보여준다.
  const ID_SAMPLE = 5;
  for (const c of scannableFound) {
    if (c.type !== 'technical_control') continue;
    const n = c.finding_ids.length;
    const shown = c.finding_ids.slice(0, ID_SAMPLE).join(', ');
    const tail = n > ID_SAMPLE ? `, … (+${n - ID_SAMPLE} more — see JSON \`findings\`)` : '';
    lines.push(`- **${c.axis}**: ${n} finding(s) — ${shown}${tail}`);
  }

  lines.push('\n## 2. What we scanned but did not find');
  lines.push(noFindingText);
  for (const c of scannableNotFound) lines.push(`- **${c.axis}**: no findings`);

  lines.push('\n## 3. What this tool cannot scan');
  // 3a — 기술 축인데 이 스캐너 CLI 로는 신호를 못 받는 경우. **사유를 반드시 함께 적는다**:
  // 사유 없는 빈칸은 "검사했는데 깨끗함"으로 오독되지만, 사유가 적힌 칸은 오독되지 않는다.
  if (cannotDetect.length > 0) {
    lines.push('\n### 3a. Technical axes this scanner cannot report on');
    for (const c of cannotDetect) {
      if (c.type !== 'technical_control') continue;
      // 접두사를 고정하지 않는다 — 사유마다 종류가 다르기 때문이다(도구 한계 vs 스캔 실패).
      // 한 접두사로 묶으면 "not observable — the scan did not complete" 같은 어색한 이중 서술이 된다.
      const reason = (c.unreachable_reason?.trim() || 'Reason not recorded.').replace(/\s+/g, ' ');
      lines.push(`- **${c.axis}**: ${reason}`);
    }
  }
  lines.push('\n### 3b. Organizational / contractual evidence required');
  lines.push('Hand this section to whoever owns the answer — it is already a checklist.');
  // TS 5.5+ 는 위 filter 에서 타입을 좁혀 주므로 여기서 c.type 을 다시 검사하지 않는다
  // (다시 검사하면 "겹치지 않는 비교"로 컴파일 에러가 난다).
  for (const c of notScannable) {
    lines.push(`\n#### ${c.axis}`);
    lines.push(`- [ ] ${c.evidence_request}`);
  }

  if (unscanned.length > 0) {
    lines.push('\n## Unscanned items');
    for (const u of unscanned) lines.push(`- ${u.target.name} (${u.target.sourcePath}) — reason: ${u.reason}`);
  }

  lines.push(`\nUnmapped findings: ${unmappedCount}`);

  // A-4 codex 반영 — 종전엔 unmatchedSignals 를 json 에만 넣고 markdown 에는 아예 노출하지 않았다.
  if (unmatchedSignals.length > 0) {
    lines.push(`\nOntology patterns with zero matches this scan: ${unmatchedSignals.length} ` +
      `(see JSON \`unmatchedSignals\` for the full list — normal for patterns unrelated to this scan's ` +
      `findings; investigate only if a pattern is *always* zero across repeated scans)`);
  }

  const markdown = lines.join('\n');
  const json = JSON.stringify({ meta, findings, claims, unscanned, unmatchedSignals, scannerWarnings }, null, 2);
  return { markdown, json };
}
