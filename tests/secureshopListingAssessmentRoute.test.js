'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createBoundRoleChatRouter } = require('../server/routes/secureshop/boundRoleChat');

const launchBearer = 'g'.repeat(43);
const operationId = '10000000-0000-4000-8000-000000000091';
const launch = Object.freeze({
  launchId: '20000000-0000-4000-8000-000000000091',
  scenarioId: '30000000-0000-4000-8000-000000000091',
  generation: 4,
  platformOwnerId: 91,
  platformSessionId: 901,
});
const session = Object.freeze({
  sessionId: '40000000-0000-4000-8000-000000000091',
  authorityVersion: '2',
});

function runtime() {
  return Object.fromEntries([
    'createSession', 'run', 'readRequest', 'confirmInventory', 'confirmPricing',
    'confirmListing', 'readListing', 'confirmListingCreate', 'readListingCreate',
    'confirmMail', 'readMailOperation',
  ].map(name => [name, async () => ({})]));
}

async function fixture(t, rawListingAssessment) {
  const app = express();
  app.use(express.json());
  app.use('/api/secureshop', createBoundRoleChatRouter({
    role: 'merchant',
    launches: { async resolveCapability(value) { return value === launchBearer ? launch : null; } },
    authenticatePersona(req, res, next) {
      if (req.get('authorization') !== 'Bearer merchant-13') {
        return res.status(401).json({ error: 'Shop authentication required' });
      }
      req.ssUser = { id: 13, role: 'merchant' };
      req.ssPersonaSession = session;
      return next();
    },
    runtime: runtime(),
    rawListingAssessment,
  }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}/api/secureshop`;
}

function headers() {
  return {
    authorization: 'Bearer merchant-13',
    'x-dvaia-secureshop-launch': launchBearer,
  };
}

test('listing assessment routes pass only trusted operation scope and preserve exact outcome identity', async t => {
  const calls = [];
  const result = { operationId, completed: false, judgment: {
    evaluationId: '50000000-0000-4000-8000-000000000091', verdict: 'unavailable', canRetry: true,
    family: 'SecureShop', trace: { secret: 'must-not-cross-route' },
  }, replayed: false };
  const base = await fixture(t, {
    async runAttempt(input) { calls.push(['runAttempt', input]); return result; },
    async readOutcome(input) { calls.push(['readOutcome', input]); return { ...result, replayed: true }; },
  });
  const post = await fetch(`${base}/agents/merchant/assistant/listing-create/assess`, {
    method: 'POST', headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ operationId: operationId.toUpperCase() }),
  });
  assert.equal(post.status, 200);
  assert.deepEqual(await post.json(), { operationId, completed: false,
    judgment: { evaluationId: '50000000-0000-4000-8000-000000000091', verdict: 'unavailable', canRetry: true }, replayed: false });
  assert.equal(calls[0][0], 'runAttempt');
  assert.deepEqual(calls[0][1].scope, launch);
  assert.deepEqual(calls[0][1].persona, { id: 13, role: 'merchant' });
  assert.deepEqual(calls[0][1].personaSession, session);
  assert.equal(calls[0][1].operationId, operationId);
  assert.equal(typeof calls[0][1].signal.throwIfAborted, 'function');

  const get = await fetch(`${base}/agents/merchant/assistant/listing-create/assessment/${operationId}`, {
    headers: headers(),
  });
  assert.equal(get.status, 200);
  assert.deepEqual(await get.json(), { operationId, completed: false,
    judgment: { evaluationId: '50000000-0000-4000-8000-000000000091', verdict: 'unavailable', canRetry: true }, replayed: true });
  assert.equal(calls[1][0], 'readOutcome');
  assert.equal(calls[1][1].operationId, operationId);

  for (const body of [{ operationId, extra: 'trace' }, { operationId: 'invalid' }]) {
    const invalid = await fetch(`${base}/agents/merchant/assistant/listing-create/assess`, {
      method: 'POST', headers: { ...headers(), 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    assert.equal(invalid.status, 400);
  }
  const query = await fetch(`${base}/agents/merchant/assistant/listing-create/assessment/${operationId}?source=client`, {
    headers: headers(),
  });
  assert.equal(query.status, 400);
  assert.equal(calls.length, 2);
});

test('assessment routes fail closed when adapter is absent or returns another operation', async t => {
  const base = await fixture(t);
  const response = await fetch(`${base}/agents/merchant/assistant/listing-create/assess`, {
    method: 'POST', headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ operationId }),
  });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'Listing assessment unavailable', code: 'LISTING_ASSESSMENT_UNAVAILABLE' });

  const mismatchBase = await fixture(t, {
    async runAttempt() { return { operationId: '50000000-0000-4000-8000-000000000091' }; },
    async readOutcome() { return { operationId: '50000000-0000-4000-8000-000000000091' }; },
  });
  const mismatch = await fetch(`${mismatchBase}/agents/merchant/assistant/listing-create/assess`, {
    method: 'POST', headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ operationId }),
  });
  assert.equal(mismatch.status, 503);
  assert.deepEqual(await mismatch.json(), { error: 'Listing assessment unavailable', code: 'LISTING_ASSESSMENT_UNAVAILABLE' });

  const extraBase = await fixture(t, {
    async runAttempt() { return { operationId, completed: false, status: 'ineligible', modelEvaluated: false, trace: 'private' }; },
    async readOutcome() { return { operationId, completed: false, status: 'ineligible', modelEvaluated: false }; },
  });
  const extra = await fetch(`${extraBase}/agents/merchant/assistant/listing-create/assess`, {
    method: 'POST', headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ operationId }),
  });
  assert.equal(extra.status, 503);
  assert.deepEqual(await extra.json(), { error: 'Listing assessment unavailable', code: 'LISTING_ASSESSMENT_UNAVAILABLE' });

  const nestedBase = await fixture(t, {
    async runAttempt() { return { operationId, completed: false, judgment: {
      evaluationId: 'not-an-evaluation-id', verdict: 'unavailable', canRetry: true,
    }, replayed: false }; },
    async readOutcome() { return { operationId, completed: false, status: 'ineligible', modelEvaluated: false }; },
  });
  const nested = await fetch(`${nestedBase}/agents/merchant/assistant/listing-create/assess`, {
    method: 'POST', headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ operationId }),
  });
  assert.equal(nested.status, 503);
  assert.deepEqual(await nested.json(), { error: 'Listing assessment unavailable', code: 'LISTING_ASSESSMENT_UNAVAILABLE' });
});

test('assessment routes keep merchant authentication and launch fences', async t => {
  const base = await fixture(t, { async runAttempt(input) {
    assert.equal(input.persona.role, 'merchant');
    return { operationId };
  }, async readOutcome() { return { operationId }; } });
  const wrongRole = await fetch(`${base}/agents/merchant/assistant/listing-create/assess`, {
    method: 'POST', headers: { ...headers(), authorization: 'Bearer admin-13', 'content-type': 'application/json' },
    body: JSON.stringify({ operationId }),
  });
  assert.equal(wrongRole.status, 401);
  const stale = await fetch(`${base}/agents/merchant/assistant/listing-create/assess`, {
    method: 'POST', headers: { ...headers(), 'x-dvaia-secureshop-launch': 'x'.repeat(43), 'content-type': 'application/json' },
    body: JSON.stringify({ operationId }),
  });
  assert.equal(stale.status, 401);
});
