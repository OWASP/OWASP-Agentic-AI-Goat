'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createConfigObserver } = require('../server/services/mcp/configObservation');
const { createConfigSnapshot } = require('../sidecars/sandbox-runner/index');

const RUN_A = '11111111-1111-4111-8111-111111111111';
const RUN_B = '22222222-2222-4222-8222-222222222222';

function sha(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function snapshot(invocationId, password = 'päss-A', apiKey = 'key-A') {
  const environment = Buffer.from(`USER=mcp-admin\nDB_PASSWORD=${password}\n`, 'utf8');
  const credentials = Buffer.from(`{"apiKey":"${apiKey}"}`, 'utf8');
  const separator = Buffer.from('\n--- credentials ---\n', 'utf8');
  const outputBuffer = Buffer.concat([environment, separator, credentials]);
  const passwordBytes = Buffer.from(password, 'utf8');
  const apiKeyBytes = Buffer.from(apiKey, 'utf8');
  const passwordStart = environment.indexOf(passwordBytes);
  const credentialsStart = environment.length + separator.length;
  const apiKeyStart = credentialsStart + credentials.indexOf(apiKeyBytes);
  return {
    ok: true,
    invocationId,
    output: outputBuffer.toString('utf8'),
    observation: {
      version: 'config-snapshot.v1',
      outputSha256: sha(outputBuffer),
      outputBytes: outputBuffer.length,
      sources: [
        { id: 'environment', sha256: sha(environment), bytes: environment.length,
          range: { startByte: 0, endByte: environment.length } },
        { id: 'credentials', sha256: sha(credentials), bytes: credentials.length,
          range: { startByte: credentialsStart, endByte: outputBuffer.length } },
      ],
      credentials: [
        { name: 'env.DB_PASSWORD', source: 'environment', valueSha256: sha(passwordBytes),
          valueBytes: passwordBytes.length,
          range: { startByte: passwordStart, endByte: passwordStart + passwordBytes.length } },
        { name: 'json.apiKey', source: 'credentials', valueSha256: sha(apiKeyBytes),
          valueBytes: apiKeyBytes.length,
          range: { startByte: apiKeyStart, endByte: apiKeyStart + apiKeyBytes.length } },
      ],
    },
  };
}

function execution(overrides = {}) {
  let checks = 0;
  const value = {
    ownerKey: '["MCP","7"]',
    runId: RUN_A,
    generation: 3,
    durableGeneration: '9',
    signal: new AbortController().signal,
    async check() { checks += 1; },
    ...overrides,
  };
  value.checkCount = () => checks;
  return value;
}

test('observes exact UTF-8 snapshot provenance and binds an opaque frozen token', async () => {
  let call;
  const observer = createConfigObserver({ readSnapshot: async (sessionId, invocationId, options) => {
    call = { sessionId, invocationId, options };
    return snapshot(invocationId);
  } });
  const current = execution();
  const result = await observer.observe({ sessionId: 'mcp_7', execution: current });

  assert.equal(current.checkCount(), 2);
  assert.equal(call.sessionId, 'mcp_7');
  assert.match(call.invocationId, /^[a-f0-9-]{36}$/);
  assert.equal(call.options.signal, current.signal);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.observation.credentials[0].range), true);
  assert.equal(Object.isFrozen(result.token), true);
  assert.deepEqual(Object.keys(result.token), []);
  assert.doesNotMatch(JSON.stringify(result.token), /päss-A|key-A|mcp_7|11111111/);
  assert.equal(observer.verify({ token: result.token, output: result.output,
    sessionId: 'mcp_7', execution: current }), true);
});

test('ungraded reads validate the receipt but never mint a capability', async () => {
  const observer = createConfigObserver({ readSnapshot: async (_session, invocationId) => snapshot(invocationId) });
  const result = await observer.observe({ sessionId: 'mcp_7' });
  assert.equal(result.token, null);
  assert.equal(result.output.includes('DB_PASSWORD='), true);
});

test('accepts the real owned-file snapshot factory with raw env and JSON escape byte provenance', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-mcp-config-observation-'));
  try {
    const envPath = path.join(directory, 'lab.env');
    const credentialsPath = path.join(directory, 'credentials.json');
    const envBytes = Buffer.from('USER=mcp-admin\nDB_PASSWORD=päss-real\n', 'utf8');
    const jsonBytes = Buffer.from('{"nested":{"api_key":"json\\u002dsecret"}}', 'utf8');
    await fs.writeFile(envPath, envBytes, { mode: 0o600, flag: 'wx' });
    await fs.writeFile(credentialsPath, jsonBytes, { mode: 0o600, flag: 'wx' });
    const factory = createConfigSnapshot({ envPath, credentialsPath });
    const observer = createConfigObserver({ readSnapshot: async (_sessionId, invocationId) => ({
      ok: true, invocationId, ...(await factory()),
    }) });
    const current = execution();
    const result = await observer.observe({ sessionId: 'mcp_7', execution: current });

    const output = Buffer.from(result.output, 'utf8');
    const envReceipt = result.observation.credentials.find(item => item.name === 'env.DB_PASSWORD');
    const jsonReceipt = result.observation.credentials.find(item => item.name === 'json.nested.api_key');
    assert.equal(output.subarray(envReceipt.range.startByte, envReceipt.range.endByte).toString('utf8'), 'päss-real');
    assert.equal(output.subarray(jsonReceipt.range.startByte, jsonReceipt.range.endByte).toString('utf8'), 'json\\u002dsecret');
    assert.equal(result.output.includes('current credential assignments'), false);
    assert.equal(observer.verify({ token: result.token, output: result.output,
      sessionId: 'mcp_7', execution: current }), true);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('rejects forged tokens, altered output, and every changed execution scope', async () => {
  const observer = createConfigObserver({ readSnapshot: async (_session, invocationId) => snapshot(invocationId) });
  const originalExecution = execution();
  const observed = await observer.observe({ sessionId: 'mcp_7', execution: originalExecution });
  const verify = (token, output, sessionId, scopedExecution) => observer.verify({
    token, output, sessionId, execution: scopedExecution,
  });

  assert.equal(verify(JSON.parse(JSON.stringify(observed.token)), observed.output, 'mcp_7', originalExecution), false);
  assert.equal(verify(observed.token, `${observed.output} `, 'mcp_7', originalExecution), false);
  assert.equal(verify(observed.token, observed.output, 'mcp_8', execution({ ownerKey: '["MCP","8"]' })), false);
  assert.equal(verify(observed.token, observed.output, 'mcp_7', execution({ runId: RUN_B })), false);
  assert.equal(verify(observed.token, observed.output, 'mcp_7', execution({ generation: 4 })), false);
  assert.equal(verify(observed.token, observed.output, 'mcp_7', execution({ generation: '3' })), false);
  assert.equal(verify(observed.token, observed.output, 'mcp_7', execution({ durableGeneration: '10' })), false);
  assert.equal(verify(observed.token, observed.output, 'mcp_7', execution({ ownerKey: '["MCP",7]' })), false,
    'noncanonical owner JSON is rejected');
});

test('rotated snapshot values cannot be authenticated by an earlier token', async () => {
  let version = 0;
  const observer = createConfigObserver({ readSnapshot: async (_session, invocationId) => {
    version += 1;
    return snapshot(invocationId, `päss-${version}`, `key-${version}`);
  } });
  const current = execution();
  const first = await observer.observe({ sessionId: 'mcp_7', execution: current });
  const second = await observer.observe({ sessionId: 'mcp_7', execution: current });
  assert.equal(observer.verify({ token: first.token, output: second.output,
    sessionId: 'mcp_7', execution: current }), false);
  assert.equal(observer.verify({ token: second.token, output: first.output,
    sessionId: 'mcp_7', execution: current }), false);
});

test('transport failure and malformed receipts fail with distinct honest codes', async () => {
  const unavailable = createConfigObserver({ readSnapshot: async () => ({ ok: false }) });
  await assert.rejects(unavailable.observe({ sessionId: 'mcp_7', execution: execution() }),
    error => error.code === 'CONFIG_SNAPSHOT_UNAVAILABLE');
  const thrown = createConfigObserver({ readSnapshot: async () => { throw new Error('network detail'); } });
  await assert.rejects(thrown.observe({ sessionId: 'mcp_7', execution: execution() }),
    error => error.code === 'CONFIG_SNAPSHOT_UNAVAILABLE' && !error.message.includes('network detail'));

  for (const mutate of [
    value => { value.observation.outputSha256 = '0'.repeat(64); },
    value => { value.observation.credentials[0].range.endByte -= 1; },
    value => { value.observation.credentials[1].source = 'environment'; },
    value => { value.observation.sources.pop(); },
    value => { value.invocationId = RUN_B; },
  ]) {
    const observer = createConfigObserver({ readSnapshot: async (_session, invocationId) => {
      const value = snapshot(invocationId); mutate(value); return value;
    } });
    await assert.rejects(observer.observe({ sessionId: 'mcp_7', execution: execution() }),
      error => error.code === 'CONFIG_OBSERVATION_INVALID');
  }
});

test('rejects oversized output and credential receipts before capability minting', async () => {
  const oversized = (invocationId) => {
    const output = Buffer.alloc(131_137, 0x61);
    return { ok: true, invocationId, output: output.toString('utf8'), observation: {
      version: 'config-snapshot.v1', outputSha256: sha(output), outputBytes: output.length,
      sources: [
        { id: 'environment', sha256: sha(output.subarray(0, 1)), bytes: 1,
          range: { startByte: 0, endByte: 1 } },
        { id: 'credentials', sha256: sha(output.subarray(output.length - 1)), bytes: 1,
          range: { startByte: output.length - 1, endByte: output.length } },
      ],
      credentials: [{ name: 'env.API_KEY', source: 'environment', valueSha256: sha(output.subarray(0, 1)),
        valueBytes: 1, range: { startByte: 0, endByte: 1 } }],
    } };
  };
  const tooMany = invocationId => {
    const value = snapshot(invocationId);
    value.observation.credentials = Array.from({ length: 65 }, (_, index) => ({
      ...value.observation.credentials[0], name: `env.API_KEY_${index}`,
    }));
    return value;
  };
  for (const factory of [oversized, tooMany]) {
    const observer = createConfigObserver({ readSnapshot: async (_session, invocationId) => factory(invocationId) });
    await assert.rejects(observer.observe({ sessionId: 'mcp_7', execution: execution() }),
      error => error.code === 'CONFIG_OBSERVATION_INVALID');
  }
});

test('execution fencing runs before and after transport and preserves cancellation', async () => {
  let reads = 0;
  const abort = new Error('reset'); abort.name = 'AbortError';
  const before = execution({ async check() { throw abort; } });
  const observer = createConfigObserver({ readSnapshot: async (_session, invocationId) => {
    reads += 1; return snapshot(invocationId);
  } });
  await assert.rejects(observer.observe({ sessionId: 'mcp_7', execution: before }), error => error === abort);
  assert.equal(reads, 0);

  let checks = 0;
  const after = execution({ async check() { checks += 1; if (checks === 2) throw abort; } });
  await assert.rejects(observer.observe({ sessionId: 'mcp_7', execution: after }), error => error === abort);
  assert.equal(reads, 1);
});

test('invalid scoped executions reject instead of becoming ungraded reads', async () => {
  let reads = 0;
  const observer = createConfigObserver({ readSnapshot: async () => { reads += 1; } });
  for (const [sessionId, current] of [
    ['mcp_7', null],
    ['mcp_7', 'untrusted-execution'],
    ['mcp_7', []],
    ['mcp_07', execution()],
    ['mcp_7', execution({ ownerKey: '["ARIA","7"]' })],
    ['mcp_7', execution({ runId: 'not-a-uuid' })],
    ['mcp_7', execution({ generation: -1 })],
    ['mcp_7', execution({ durableGeneration: null })],
  ]) {
    await assert.rejects(observer.observe({ sessionId, execution: current }));
  }
  assert.equal(reads, 0);
});
