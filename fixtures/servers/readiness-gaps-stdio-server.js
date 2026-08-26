#!/usr/bin/env node
/**
 * 테스트 전용 readiness 갭 MCP 서버 (stdio, 의존성 0).
 *
 * 왜 만들었나: 우리 15축 중 `logging`·`tool_permission`·`auth_oauth` 세 축이 v0 에서
 * "신호 0"이었다. 원인은 분석기가 못 보는 것이 아니라 **CLI 가 rule id 를 떨어뜨리는 것**이다
 * (report_generator 가 details["threat_type"] 하나만 직렬화 — IMPL-NOTES §4).
 * 모듈 직접 호출로 rule id 를 살리는 경로를 검증하려면 그 세 규칙이 **실제로 발화하는 대상**이
 * 있어야 하는데, 기존 `malicious-stdio-server.js` 로는 HEUR-015 만 발화하고 018·019 는 잠잠했다.
 *
 * ⚠️ **이 파일은 악성이 아니다.** 위험한 동작을 하나도 하지 않는다 — 스캐너가 읽는 것은
 * **도구 이름과 설명 문자열**뿐이고, 이 서버는 그 문자열에 발화 조건을 담아 두기만 한다.
 * 실제로 호출되면 고정 문자열을 돌려준다.
 *
 * 발화 조건(mcp-scanner 4.8.3 `readiness_analyzer.py` 실측):
 *   HEUR-018 = 이름/설명에 delete·drop·truncate·exec·eval·rm ·remove·destroy·purge·wipe 중 하나
 *   HEUR-019 = 설명에 외부 지표(api·service·endpoint·http·rest·request·external·remote·cloud·server)
 *              가 있으면서 tool_def 나 config 에 auth 계열 필드(auth·authentication·credentials·
 *              apiKey·api_key·token)가 **없을 때**
 *   HEUR-015 = observability(logging·metrics·tracing) 설정 부재 — 사실상 모든 도구에서 발화한다
 *
 * 세 번째 도구 `read_cached_report` 는 **대조군**이다. 위험 키워드도 없고 외부 지표도 없어
 * 018·019 가 발화하면 안 된다 — 규칙이 아무 데나 붙는 게 아니라 실제로 구분한다는 증거다.
 */
const TOOLS = [
  {
    name: 'delete_stale_records',
    // HEUR-018 발화: 'delete' + 'purge' 두 키워드.
    description: 'Permanently delete stale rows from the local table and purge the tombstones.',
    inputSchema: { type: 'object', properties: { olderThanDays: { type: 'number' } } },
  },
  {
    name: 'fetch_from_partner_api',
    // HEUR-019 발화: 설명에 'api'·'endpoint'·'http' 가 있는데 auth 계열 필드가 하나도 없다.
    description: 'Fetches records from the partner REST api endpoint over http and returns them.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } } },
  },
  {
    name: 'read_cached_report',
    // 대조군: 위험 키워드 없음 + 외부 지표 없음 → 018·019 미발화가 정상이다.
    // (HEUR-015 등 일반 readiness 규칙은 여기서도 발화한다 — 그건 별개 축이다.)
    description: 'Returns a previously computed report from the on-disk cache.',
    inputSchema: { type: 'object', properties: { key: { type: 'string' } } },
  },
];

function send(msg) { process.stdout.write(JSON.stringify(msg) + '\n'); }

function handle(req) {
  const { id, method } = req;
  if (method === 'initialize') {
    return send({
      jsonrpc: '2.0', id,
      result: {
        protocolVersion: req.params?.protocolVersion ?? '2024-11-05',
        capabilities: { tools: {}, prompts: {}, resources: {} },
        serverInfo: { name: 'mcp-disclosure-readiness-fixture', version: '1.0.0' },
      },
    });
  }
  if (method === 'tools/list') return send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
  if (method === 'prompts/list') return send({ jsonrpc: '2.0', id, result: { prompts: [] } });
  if (method === 'resources/list') return send({ jsonrpc: '2.0', id, result: { resources: [] } });
  if (method === 'tools/call') {
    return send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'fixture server: no real work performed' }] } });
  }
  if (id !== undefined) send({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
}

let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  buf += chunk;
  let nl;
  while ((nl = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (!line) continue;
    try { handle(JSON.parse(line)); } catch { /* 잘못된 줄은 무시 — 스캐너가 다음 줄을 보낸다 */ }
  }
});
