#!/usr/bin/env node
// bin/agenttrust.js — npm bin 엔트리. 실제 로직은 dist/src/cli.js 가 갖는다.
import('../dist/src/cli.js').then(m => m.main(process.argv.slice(2)));
