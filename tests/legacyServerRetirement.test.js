'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const test = require('node:test');

const repoRoot = path.resolve(__dirname, '..');
const entrypoint = path.join(repoRoot, 'server', 'secureServer.js');
const expectedMessage = 'server/secureServer.js is retired';

test('direct legacy server execution fails before application startup', () => {
  const result = spawnSync(process.execPath, [entrypoint], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { PATH: process.env.PATH, NODE_ENV: 'test' },
  });

  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}\n${result.stderr}`, new RegExp(expectedMessage));
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /Connected to|Initializing secure database|SERVER STARTED/);
});

test('requiring the retired entrypoint loads no application modules or working data', () => {
  const script = `
    const Module = require('node:module');
    const fs = require('node:fs');
    const loads = [];
    const fileAccess = [];
    const originalLoad = Module._load;
    const originalFs = {};
    for (const name of ['open', 'openSync', 'readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'mkdir', 'mkdirSync']) {
      originalFs[name] = fs[name];
      fs[name] = (...args) => {
        // Node must read the source file itself to execute the target module;
        // every other filesystem operation is forbidden in this child.
        if (name === 'readFileSync' && String(args[0]) === ${JSON.stringify(entrypoint)}) {
          return originalFs[name](...args);
        }
        fileAccess.push(name);
        throw new Error('working-data access forbidden: ' + name);
      };
    }
    Module._load = function guardedLoad(request, parent, isMain) {
      if (request === ${JSON.stringify(entrypoint)}) return originalLoad.call(this, request, parent, isMain);
      loads.push(request);
      throw new Error('unexpected module load: ' + request);
    };
    let caught;
    try {
      require(${JSON.stringify(entrypoint)});
    } catch (error) {
      caught = { code: error.code, message: error.message };
    }
    Module._load = originalLoad;
    for (const [name, value] of Object.entries(originalFs)) fs[name] = value;
    if (!caught || caught.code !== 'ERR_OWASP_AI_GOAT_LEGACY_ENTRYPOINT_RETIRED' || !caught.message.includes(${JSON.stringify(expectedMessage)})) {
      console.error(JSON.stringify({ caught, loads, fileAccess }));
      process.exit(2);
    }
    if (loads.length || fileAccess.length) {
      console.error(JSON.stringify({ caught, loads, fileAccess }));
      process.exit(3);
    }
    process.stdout.write('retirement guard passed\\n');
  `;

  const result = spawnSync(process.execPath, ['-e', script], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { PATH: process.env.PATH, NODE_ENV: 'test' },
  });

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /retirement guard passed/);
});
