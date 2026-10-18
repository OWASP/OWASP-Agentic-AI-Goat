'use strict';
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const result = spawnSync(process.execPath, ['--test', 'tests/workshopGraph.live.test.js'], {
  cwd: path.resolve(__dirname, '..'), stdio: 'inherit',
  env: { ...process.env, LIVE_OLLAMA_TEST: '1', OLLAMA_MODEL: 'llama3.1:8b' },
});
if (result.error) console.error(result.error.message);
process.exitCode = result.status ?? 1;
