import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { ScanTarget } from './types.js';

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
  return {
    kind: 'mcp_server',
    sourcePath,
    name,
    transport: isRemote ? 'remote' : 'local_stdio',
    remoteUrl: isRemote ? url : undefined,
  };
}
