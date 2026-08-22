#!/usr/bin/env node
// bin/agenttrust.js — npm bin 엔트리. 실제 로직은 dist/src/cli.js 가 갖는다.
// ⚠️ catch 가 반드시 있어야 한다. 없으면 예기치 못한 예외가 unhandled rejection 으로 새어
//    Node 기본 동작(exit 1 + 스택 덤프)에 맡겨지고, README 가 약속한 exit 3 과 어긋난다.
import('../dist/src/cli.js')
  .then(m => m.main(process.argv.slice(2)))
  .catch(e => {
    process.stderr.write(`Unexpected error: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(3);
  });
