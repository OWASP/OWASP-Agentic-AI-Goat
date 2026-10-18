const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const read = (file) => fs.readFileSync(path.join(__dirname, file), 'utf8');

const guardedRunners = [
  ['adminExploitation.test.js', /SERVER_AVAILABLE === '1' && !!process\.env\.TEST_BASE_URL/],
  ['sensitiveInfoWorkshop.test.js', /SERVER_AVAILABLE === '1' && !!process\.env\.TEST_BASE_URL/],
  ['ssrfWorkshop.test.js', /SERVER_AVAILABLE === '1' && !!process\.env\.TEST_BASE_URL/],
  ['supplyChainWorkshop.test.js', /SERVER_AVAILABLE === '1' && !!process\.env\.TEST_BASE_URL/],
  ['ragHealth.test.js', /SERVER_AVAILABLE === '1' && !!process\.env\.BASE_URL/],
  ['progressAnalytics.smoke.test.js', /SERVER_AVAILABLE !== '1' \|\| !process\.env\.API_BASE/],
  ['ctfHintCost.smoke.test.js', /SERVER_AVAILABLE !== '1' \|\| !EXPLICIT_BASE/],
  ['promptInjection.test.js', /SERVER_AVAILABLE !== '1' \|\| !process\.env\.TEST_BASE_URL/],
  ['api.test.js', /SERVER_AVAILABLE !== '1' \|\| !process\.env\.TEST_BASE_URL/],
  ['solutions.test.js', /SERVER_AVAILABLE !== '1' \|\| !process\.env\.TEST_PORT/],
];

for (const [file, guard] of guardedRunners) {
  test(`${file} requires explicit HTTP opt-in and target`, () => {
    assert.match(read(file), guard);
  });
}

const unconditionalRunners = [
  ['ctfHintCost.smoke.test.js', []],
  ['promptInjection.test.js', ['--skip-llm']],
  ['api.test.js', []],
  ['solutions.test.js', []],
];

for (const [file, args] of unconditionalRunners) {
  test(`${file} refuses to start without explicit HTTP configuration`, () => {
    const env = { ...process.env };
    for (const key of ['SERVER_AVAILABLE', 'TEST_BASE_URL', 'TEST_PORT', 'CTF_TEST_URL']) {
      delete env[key];
    }
    const result = spawnSync(process.execPath, [path.join(__dirname, file), ...args], {
      env,
      encoding: 'utf8',
      timeout: 10000,
    });
    assert.notEqual(result.status, 0, `${file} unexpectedly succeeded`);
    assert.match(`${result.stdout}\n${result.stderr}`, /Refusing to (?:contact|mutate) a default server/);
  });
}

test('adminProductionBundle uses only an ephemeral loopback server', () => {
  const source = read('adminProductionBundle.test.js');
  assert.match(source, /server\.listen\(0, '127\.0\.0\.1'/);
  assert.doesNotMatch(source, /localhost:8081/);
});
