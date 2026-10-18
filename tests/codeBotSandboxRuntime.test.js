'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  REQUIRED_ISOLATION, sessionIdForOwner, executeTransform, resetOwner, resetOwnerBeforeProgress,
} = require('../server/services/supplyChain/codeBotSandboxRuntime');
// This suite reads pure argv construction, never starts the runner HTTP server.
const Module = require('node:module'), originalLoad = Module._load;
let runnerExports;
try {
  Module._load = function(id, parent, main) {
    if (['http','node:http'].includes(id) && parent?.filename === require.resolve('../sidecars/sandbox-runner/index')) {
      return { ...originalLoad.apply(this, arguments), createServer() {
        return { listening: false, listen() { throw Error('Native runner forbidden in unit test'); } };
      } };
    }
    return originalLoad.apply(this, arguments);
  };
  runnerExports = require('../sidecars/sandbox-runner/index');
} finally { Module._load = originalLoad; }
const { buildCodeBotBwrapArgv, CODEBOT_ISOLATION } = runnerExports;

test('CodeBot owner identity maps to a stable opaque runner session', () => {
  const session = sessionIdForOwner('student-42');
  assert.match(session, /^codebot-[a-f0-9]{32}$/);
  assert.equal(session, sessionIdForOwner('student-42'));
  assert.notEqual(session, sessionIdForOwner('student-43'));
  assert.equal(sessionIdForOwner(''), null);
});

test('CodeBot transform fails closed without an authenticated owner', async () => {
  let called = false;
  const result = await executeTransform({ ownerId: '', transform: '1+1', runner: async () => { called = true; } });
  assert.equal(called, false);
  assert.equal(result.security, 'unavailable');
  assert.equal(result.transform_executed, false);
});

test('CodeBot transform rejects generic or weak runner isolation', async () => {
  for (const isolation of ['plain', 'bwrap-netns', undefined]) {
    const result = await executeTransform({
      ownerId: 'student-1', transform: '1+1',
      runner: async () => ({ ok: true, executed: true, exitCode: 0, isolation, transformOutput: '2' }),
    });
    assert.equal(result.security, 'unavailable');
    assert.equal(result.transform_executed, false);
  }
});

test('CodeBot transform accepts only attested successful execution', async () => {
  const result = await executeTransform({
    ownerId: 'student-1', transform: '1+1',
    runner: async (path, body) => {
      assert.equal(path, '/codebot/transform');
      assert.match(body.sessionId, /^codebot-[a-f0-9]{32}$/);
      return { ok: true, executed: true, exitCode: 0, isolation: REQUIRED_ISOLATION, transformOutput: '2', durationMs: 8, observations: { javascriptEvaluated: true } };
    },
  });
  assert.equal(result.security, 'rce_executed');
  assert.equal(result.transform_executed, true);
  assert.equal(result.transform_output, '2');
  assert.deepEqual(result.runner, {
    source: 'sandbox_runner', session_id: sessionIdForOwner('student-1'),
    isolation: REQUIRED_ISOLATION, exit_code: 0, duration_ms: 8,
    observations: { env_file_read: false, ssh_file_read: false, javascript_evaluated: true },
  });
});

test('CodeBot timeout reports attempted failure rather than unavailability', async () => {
  const result = await executeTransform({
    ownerId: 'student-1', transform: 'while(true){}',
    runner: async () => ({ ok: false, executed: false, exitCode: 124, timedOut: true, isolation: REQUIRED_ISOLATION, error: 'transform timed out' }),
  });
  assert.equal(result.security, 'error');
  assert.equal(result.status, 'execution_timeout');
  assert.equal(result.execution_attempted, true);
  assert.equal(result.transform_executed, false);
});

test('CodeBot reset uses only the opaque owner session', async () => {
  const result = await resetOwner('student-1', async (path, body) => {
    assert.equal(path, '/codebot/reset');
    assert.equal(body.sessionId, sessionIdForOwner('student-1'));
    return { ok: true };
  });
  assert.equal(result.ok, true);
});

test('CodeBot reset failure leaves progress untouched', async () => {
  let progressReset = false;
  await assert.rejects(
    resetOwnerBeforeProgress('student-1', async () => { progressReset = true; }, async () => ({ ok: false, error: 'offline' })),
    error => error.code === 'CODEBOT_RESET_UNAVAILABLE',
  );
  assert.equal(progressReset, false);
});

test('CodeBot bwrap plan uses an allowlisted root and private mounts', () => {
  const argv = buildCodeBotBwrapArgv('wrapper', 'transform');
  assert.equal(CODEBOT_ISOLATION, 'bwrap-codebot-v1');
  assert.ok(argv.includes('--unshare-user'));
  assert.equal(argv.includes('--disable-userns'), false);
  assert.ok(argv.includes('--unshare-net'));
  assert.ok(argv.includes('--unshare-pid'));
  assert.ok(argv.includes('--clearenv'));
  assert.ok(argv.includes('--dev'));
  assert.equal(argv.includes('--proc'), false);
  assert.deepEqual(argv.slice(argv.indexOf('--dev'), argv.indexOf('--dev') + 4),
    ['--dev', '/dev', '--dir', '/proc']);
  assert.equal(argv.some((value, index) => value === '--ro-bind' && argv[index + 1] === '/'), false);
  assert.equal(argv.includes('/app'), true);
  assert.equal(argv.includes('/work'), true);
  assert.equal(argv.includes('/opt'), false);
  assert.equal(argv.some(value => String(value).includes('/sandbox/sessions')), false);
  assert.equal(argv.includes('--file'), true);
  assert.equal(argv.filter(value => value === '--tmpfs').length >= 2, true);
});
