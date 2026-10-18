'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const util = require('node:util');

const {
  PAYLOAD_FIELDS,
  createOwnerCapabilityCodec,
} = require('../server/services/secureshop/ownerCapability');

const KEY_1 = Buffer.alloc(32, 0x11);
const KEY_2 = Buffer.alloc(32, 0x22);
let now = Date.UTC(2026, 8, 13, 12, 0, 0);

function codec(overrides = {}) {
  return createOwnerCapabilityCodec({
    keys: { 1: KEY_1, 2: KEY_2 },
    currentKeyVersion: 2,
    clock: () => now,
    allowedAudiences: ['secureshop-agent-host', 'secureshop-runner'],
    maxTtlSeconds: 60,
    ...overrides,
  });
}

function context(overrides = {}) {
  return {
    aud: 'secureshop-agent-host',
    launchId: 'launch-017',
    platformOwnerId: 'platform-user-41',
    scenarioId: 'scenario-a91',
    generation: 3,
    runId: 'run-72',
    agentSessionId: '94bf15e0-20f4-4ced-99df-10cf35f64bd2',
    shopPersonaId: 'customer-7',
    shopRole: 'customer',
    agent: 'cart',
    tool: 'add',
    args: { productId: 17, quantity: 2 },
    operationId: 'operation-551',
    nonce: 'nonce-a4c18f',
    ...overrides,
  };
}

function rejectsCode(fn, code) {
  assert.throws(fn, (error) => error && error.code === code);
}

test('issuance rejects expiry arithmetic overflow even with a valid current clock', () => {
  const service = codec({ clock: () => Number.MAX_SAFE_INTEGER * 1000 });
  rejectsCode(() => service.issue(context()), 'INVALID_TTL');
});

function tokenParts(token) {
  const [prefix, encoded, signature] = token.split('.');
  return { prefix, encoded, signature, payload: JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) };
}

function encodeUnsigned(prefix, payload, signature) {
  return `${prefix}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${signature}`;
}

test('issues canonical short-lived tokens and verifies only against complete trusted context', () => {
  const service = codec();
  const expected = context();
  const token = service.issue(expected, { ttlSeconds: 30 });
  const verified = service.verify(token, expected);

  assert.equal(verified.claims.v, 1);
  assert.equal(verified.claims.keyVersion, 2);
  assert.equal(verified.claims.iss, 'dvaia-backend');
  assert.equal(verified.claims.iat, Math.floor(now / 1000));
  assert.equal(verified.claims.exp, Math.floor(now / 1000) + 30);
  assert.equal(verified.claims.argsDigest, service.digestArguments(expected.args));
  assert.match(verified.capabilityDigest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(verified.onlineAuthorizationRequired, true);
  assert.equal(JSON.stringify(verified).includes(token), false);
  assert.deepEqual(Object.keys(verified.claims), [...PAYLOAD_FIELDS]);
});

test('argument canonicalization is order-independent while exact values remain bound', () => {
  const service = codec();
  const first = context({ args: { z: [1, { b: true, a: 'x' }], a: null } });
  const reordered = context({ args: { a: null, z: [1, { a: 'x', b: true }] } });
  assert.equal(service.digestArguments(first.args), service.digestArguments(reordered.args));
  assert.equal(service.issue(first, { ttlSeconds: 30 }), service.issue(reordered, { ttlSeconds: 30 }));
  const changed = context({ args: { a: null, z: [1, { a: 'x', b: false }] } });
  rejectsCode(() => service.verify(service.issue(first), changed), 'CONTEXT_MISMATCH');
});

test('tampering every signed payload field without resigning fails signature verification', () => {
  const service = codec();
  const token = service.issue(context());
  const parts = tokenParts(token);
  for (const field of PAYLOAD_FIELDS) {
    const payload = { ...parts.payload };
    payload[field] = typeof payload[field] === 'number' ? payload[field] + 1 : `${payload[field]}x`;
    assert.throws(
      () => service.verify(encodeUnsigned(parts.prefix, payload, parts.signature), context()),
      (error) => error.code === 'INVALID_SIGNATURE' || (field === 'keyVersion' && error.code === 'UNSUPPORTED_CAPABILITY'),
    );
  }
});

test('every trusted identity and operation field plus raw arguments must match', () => {
  const service = codec();
  const issued = context();
  const token = service.issue(issued);
  for (const field of Object.keys(issued)) {
    const replacement = field === 'generation'
      ? issued[field] + 1
      : field === 'args'
        ? { ...issued.args, quantity: 3 }
        : field === 'shopRole'
          ? 'merchant'
          : `${issued[field]}-other`;
    const expected = { ...issued, [field]: replacement };
    const code = field === 'aud' ? 'INVALID_AUDIENCE' : 'CONTEXT_MISMATCH';
    rejectsCode(() => service.verify(token, expected), code);
  }
  const missing = { ...issued };
  delete missing.platformOwnerId;
  rejectsCode(() => service.verify(token, missing), 'INVALID_CLAIMS');
  rejectsCode(() => service.verify(token, { ...issued, unexpected: true }), 'INVALID_CLAIMS');
});

test('wrong audience, dedicated key, key version, expiry and future issuance fail closed', () => {
  const service = codec();
  const expected = context();
  const token = service.issue(expected, { ttlSeconds: 10 });
  rejectsCode(() => service.issue(context({ aud: 'unknown-service' })), 'INVALID_AUDIENCE');
  rejectsCode(() => service.issue(expected, { ttlSeconds: 61 }), 'INVALID_TTL');

  const wrongKey = codec({ keys: { 2: Buffer.alloc(32, 0x99) } });
  rejectsCode(() => wrongKey.verify(token, expected), 'INVALID_SIGNATURE');
  const unsupported = codec({ keys: { 1: KEY_1 }, currentKeyVersion: 1 });
  rejectsCode(() => unsupported.verify(token, expected), 'UNSUPPORTED_CAPABILITY');

  now += 10_000;
  rejectsCode(() => service.verify(token, expected), 'EXPIRED_CAPABILITY');
  now -= 10_000;
  const future = service.issue(expected);
  now -= 1_000;
  rejectsCode(() => service.verify(future, expected), 'NOT_YET_VALID');
  now += 1_000;
});

test('previous configured key versions remain verifiable during a bounded rotation window', () => {
  const oldIssuer = codec({ currentKeyVersion: 1 });
  const token = oldIssuer.issue(context(), { ttlSeconds: 30 });
  const rotated = codec({ currentKeyVersion: 2 });
  assert.equal(rotated.verify(token, context()).claims.keyVersion, 1);
});

test('non-canonical, malformed, oversized, and structurally invalid inputs are rejected', () => {
  const service = codec({ maxArgumentBytes: 64 });
  rejectsCode(() => service.verify('not-a-capability', context()), 'MALFORMED_CAPABILITY');
  rejectsCode(() => service.verify(`ssoc1.${'a'.repeat(13 * 1024)}.x`, context()), 'MALFORMED_CAPABILITY');
  rejectsCode(() => service.issue({ ...context(), extra: 'field' }), 'INVALID_CLAIMS');
  rejectsCode(() => service.issue(context({ args: { body: 'x'.repeat(100) } })), 'ARGUMENTS_TOO_LARGE');
  const cyclic = {};
  cyclic.self = cyclic;
  rejectsCode(() => service.digestArguments(cyclic), 'INVALID_ARGUMENTS');
  rejectsCode(() => service.digestArguments({ value: Number.NaN }), 'INVALID_ARGUMENTS');
  rejectsCode(() => service.digestArguments({ _ss_owner_capability: 'forged' }), 'INVALID_ARGUMENTS');
  const nestedReserved = { document: { _ss_owner_capability: 'teaching data' } };
  assert.notEqual(
    service.digestArguments(nestedReserved),
    service.digestArguments({ document: { _ss_owner_capability: 'changed teaching data' } }),
  );
  const accessor = {};
  Object.defineProperty(accessor, 'value', { enumerable: true, get: () => { throw new Error('must not execute'); } });
  rejectsCode(() => service.digestArguments(accessor), 'INVALID_ARGUMENTS');
  rejectsCode(() => service.digestArguments(new Date()), 'INVALID_ARGUMENTS');
  rejectsCode(() => service.digestArguments({ [Symbol('hidden')]: true }), 'INVALID_ARGUMENTS');
  const sparse = [];
  sparse[1] = 'value';
  rejectsCode(() => service.digestArguments(sparse), 'INVALID_ARGUMENTS');
  const decorated = ['value'];
  decorated.extra = true;
  rejectsCode(() => service.digestArguments(decorated), 'INVALID_ARGUMENTS');
  const sparseHuge = [];
  sparseHuge.length = 10_000_000;
  rejectsCode(() => service.digestArguments(sparseHuge), 'ARGUMENTS_TOO_COMPLEX');
  const arrayAccessor = [];
  Object.defineProperty(arrayAccessor, '0', { enumerable: true, get: () => { throw new Error('must not execute'); } });
  arrayAccessor.length = 1;
  rejectsCode(() => service.digestArguments(arrayAccessor), 'INVALID_ARGUMENTS');
  const throwingProxy = new Proxy({}, {
    getPrototypeOf: () => { throw new Error('proxy trap must not execute'); },
    ownKeys: () => { throw new Error('proxy trap must not execute'); },
  });
  rejectsCode(() => service.digestArguments(throwingProxy), 'INVALID_ARGUMENTS');
  rejectsCode(() => service.issue(throwingProxy), 'INVALID_CLAIMS');

  const valid = service.issue(context());
  const parts = tokenParts(valid);
  const reordered = {};
  for (const key of [...PAYLOAD_FIELDS].reverse()) reordered[key] = parts.payload[key];
  const nonCanonicalBytes = Buffer.from(JSON.stringify(reordered)).toString('base64url');
  const signature = crypto.createHmac('sha256', KEY_2).update(`ssoc1.${nonCanonicalBytes}`).digest('base64url');
  rejectsCode(() => service.verify(`ssoc1.${nonCanonicalBytes}.${signature}`, context()), 'MALFORMED_CAPABILITY');
});

test('raw tokens and injected native details never appear in errors or inspection', () => {
  const service = codec();
  const token = service.issue(context());
  const broken = `${token.slice(0, -1)}${token.endsWith('a') ? 'b' : 'a'}`;
  assert.throws(() => service.verify(broken, context()), (error) => {
    const inspected = util.inspect(error);
    assert.equal(error.cause, undefined);
    assert.equal(inspected.includes(token), false);
    assert.equal(inspected.includes(broken), false);
    assert.equal(JSON.stringify(error).includes(token), false);
    return error.code === 'INVALID_SIGNATURE';
  });
});

test('an unkeyed session-role-user hash is not accepted as an authorization credential', () => {
  const service = codec();
  const attackerComputable = crypto.createHash('sha256')
    .update(`${context().agentSessionId}:${context().shopRole}:${context().shopPersonaId}`)
    .digest('hex');
  assert.match(attackerComputable, /^[a-f0-9]{64}$/);
  rejectsCode(() => service.verify(attackerComputable, context()), 'MALFORMED_CAPABILITY');
});

test('configuration requires injected clock, dedicated 256-bit keys and explicit audiences', () => {
  rejectsCode(() => createOwnerCapabilityCodec({ keys: { 1: KEY_1 }, currentKeyVersion: 1, allowedAudiences: ['x'] }), 'INVALID_CONFIGURATION');
  rejectsCode(() => createOwnerCapabilityCodec({ keys: { 1: 'shared-jwt-secret' }, currentKeyVersion: 1, clock: () => now, allowedAudiences: ['x'] }), 'INVALID_CONFIGURATION');
  rejectsCode(() => createOwnerCapabilityCodec({ keys: { 1: KEY_1 }, currentKeyVersion: 1, clock: () => now }), 'INVALID_CONFIGURATION');
  rejectsCode(() => createOwnerCapabilityCodec({ keys: { 1: { toString: () => { throw new Error('must not execute'); } } }, currentKeyVersion: 1, clock: () => now, allowedAudiences: ['x'] }), 'INVALID_CONFIGURATION');
  const mutableKey = Buffer.alloc(32, 0x44);
  const copied = codec({ keys: { 2: mutableKey } });
  const token = copied.issue(context());
  mutableKey.fill(0);
  assert.equal(copied.verify(token, context()).claims.keyVersion, 2);
  const brokenClock = codec({ clock: () => { throw new Error('native clock detail'); } });
  assert.throws(() => brokenClock.issue(context()), (error) => {
    assert.equal(error.code, 'CLOCK_FAILURE');
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(util.inspect(error), /native clock detail/);
    return true;
  });
  rejectsCode(() => codec({ clock: () => Number.MAX_VALUE }).issue(context()), 'CLOCK_FAILURE');
});
