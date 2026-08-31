import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { ScanTarget } from './types.js';
import { redactArgs, redactCommand } from './masking.js';

export type DiscoverResult = { targets: ScanTarget[]; scannedPaths: string[] };

export function discover(rootDir: string): DiscoverResult {
  const scannedPaths: string[] = [];
  const targets: ScanTarget[] = [];

  const mcpJsonPath = join(rootDir, '.mcp.json');
  scannedPaths.push(mcpJsonPath);
  if (existsSync(mcpJsonPath)) {
    const parsed = JSON.parse(readFileSync(mcpJsonPath, 'utf8'));
    for (const [name, entry] of Object.entries(parsed.mcpServers ?? {})) {
      targets.push(classifyMcpServer(mcpJsonPath, name, entry as Record<string, unknown>));
    }
  }

  for (const rel of ['.claude/settings.json', '.claude/settings.local.json']) {
    const p = join(rootDir, rel);
    scannedPaths.push(p);
    if (!existsSync(p)) continue;
    const parsed = JSON.parse(readFileSync(p, 'utf8'));
    if (parsed.hooks) targets.push({ kind: 'hook', sourcePath: p, name: `${rel}#hooks`, transport: 'local_stdio' });
    if (parsed.permissions) targets.push({ kind: 'permission', sourcePath: p, name: `${rel}#permissions`, transport: 'local_stdio' });
  }

  const agentsDir = join(rootDir, '.claude/agents');
  scannedPaths.push(agentsDir);
  if (existsSync(agentsDir)) {
    for (const f of readdirSync(agentsDir).filter(f => f.endsWith('.md'))) {
      targets.push({ kind: 'agent_def', sourcePath: join(agentsDir, f), name: f, transport: 'local_stdio' });
    }
  }

  return { targets, scannedPaths };
}

function classifyMcpServer(sourcePath: string, name: string, entry: Record<string, unknown>): ScanTarget {
  const url = typeof entry.url === 'string' ? entry.url : undefined;
  const isRemote = !!url || entry.type === 'sse' || entry.type === 'http';

  // ⚠️ 2026-08-31: 종전에는 command/args/env 를 **파싱해놓고 그냥 버렸다**. 그래서 소견서가
  //    "이 설정에 무엇이 연결돼 있는지"를 한 줄도 말하지 못했다. 이제 싣는다.
  //    마스킹은 **여기(입구)에서** 한다 — 원문이 ScanTarget 에 들어가는 순간 이후 모든 소비처
  //    (JSON 출력·로그·다음 세션의 새 기능)가 전부 유출 경로가 되기 때문이다.
  const command = typeof entry.command === 'string' ? redactCommand(entry.command) : undefined;
  const args = Array.isArray(entry.args) ? redactArgs(entry.args.map(a => String(a))) : undefined;
  // ⚠️ env 는 **키 이름만** 담는다. 값은 어떤 마스킹도 거치지 않고 그냥 안 담는다 —
  //    마스킹 규칙이 놓칠 수 있는 짧은 시크릿이 가장 흔히 사는 곳이 바로 여기다.
  const envKeys = entry.env && typeof entry.env === 'object' && !Array.isArray(entry.env)
    ? Object.keys(entry.env as Record<string, unknown>).sort()
    : undefined;

  return {
    kind: 'mcp_server',
    sourcePath,
    name,
    transport: isRemote ? 'remote' : 'local_stdio',
    remoteUrl: isRemote ? url : undefined,
    command,
    args,
    envKeys,
  };
}
