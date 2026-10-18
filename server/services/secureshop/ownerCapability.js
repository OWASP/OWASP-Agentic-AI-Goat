'use strict';

/**
 * SecureShop internal owner-capability codec.
 *
 * This module proves only that a bounded operation envelope was issued by a
 * holder of a dedicated HMAC key and matches trusted expected context. It does
 * not authenticate HTTP callers, read durable launch state, revoke a launch,
 * fence a reset, or consume an operation/nonce. Every successful verification
 * must be followed by an online authorization/replay check before an effect.
 * The mandatory `expected` object must come from trusted launch/run state; a
 * receiver must never copy decoded token claims into it and call that ownership.
 * Raw tokens must remain outside prompts, tool results, traces, logs and UI.
 */

const crypto = require('node:crypto');
const { types: utilTypes } = require('node:util');

const TOKEN_PREFIX = 'ssoc1';
const VERSION = 1;
const DEFAULT_MAX_TTL_SECONDS = 60;
const DEFAULT_MAX_ARGUMENT_BYTES = 16 * 1024;
const MAX_CONFIGURED_TTL_SECONDS = 300;
const MAX_CONFIGURED_ARGUMENT_BYTES = 64 * 1024;
const MAX_TOKEN_BYTES = 12 * 1024;
const MAX_IDENTIFIER_BYTES = 256;
const MAX_NONCE_BYTES = 128;
const MAX_ARGUMENT_DEPTH = 12;
const MAX_ARGUMENT_NODES = 1024;

const PAYLOAD_FIELDS = Object.freeze([
  'v', 'keyVersion', 'iss', 'aud', 'launchId', 'platformOwnerId',
  'scenarioId', 'generation', 'runId', 'agentSessionId', 'shopPersonaId',
  'shopRole', 'agent', 'tool', 'argsDigest', 'operationId', 'iat', 'exp',
  'nonce',
]);
const ISSUE_FIELDS = Object.freeze([
  'aud', 'launchId', 'platformOwnerId', 'scenarioId', 'generation', 'runId',
  'agentSessionId', 'shopPersonaId', 'shopRole', 'agent', 'tool', 'args',
  'operationId', 'nonce',
]);
const EXPECTED_FIELDS = ISSUE_FIELDS;
const ROLES = new Set(['customer', 'merchant', 'admin']);
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;

class OwnerCapabilityError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'OwnerCapabilityError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new OwnerCapabilityError(code, message);
}

function exactKeys(value, fields, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(code, 'capability context must be an object');
  }
  if (utilTypes.isProxy(value)) fail(code, 'capability context proxies are not allowed');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail(code, 'capability context must use a plain object');
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== 'string')) fail(code, 'capability context fields are invalid');
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (ownKeys.length !== actual.length
      || actual.length !== expected.length
      || actual.some((entry, index) => entry !== expected[index])) {
    fail(code, 'capability context fields are invalid');
  }
  for (const field of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail(code, 'capability context fields are invalid');
    }
  }
}

function boundedString(value, name, maxBytes = MAX_IDENTIFIER_BYTES) {
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value) > maxBytes || /[\0\r\n]/.test(value)) {
    fail('INVALID_CLAIMS', `${name} is invalid`);
  }
  return value;
}

function canonicalizeArguments(value, maxBytes = DEFAULT_MAX_ARGUMENT_BYTES) {
  let nodes = 0;
  let bytes = 0;
  const ancestors = new Set();

  function emit(fragment) {
    bytes += Buffer.byteLength(fragment);
    if (bytes > maxBytes) fail('ARGUMENTS_TOO_LARGE', 'capability arguments exceed the byte limit');
    return fragment;
  }

  function encode(current, depth) {
    nodes += 1;
    if (nodes > MAX_ARGUMENT_NODES || depth > MAX_ARGUMENT_DEPTH) {
      fail('ARGUMENTS_TOO_COMPLEX', 'capability arguments exceed structural limits');
    }
    if (current === null) return emit('null');
    if (typeof current === 'string') {
      if (Buffer.byteLength(current) > maxBytes) fail('ARGUMENTS_TOO_LARGE', 'capability arguments exceed the byte limit');
      return emit(JSON.stringify(current));
    }
    if (typeof current === 'boolean') return emit(JSON.stringify(current));
    if (typeof current === 'number') {
      if (!Number.isFinite(current)) fail('INVALID_ARGUMENTS', 'capability arguments contain a non-finite number');
      return emit(JSON.stringify(current));
    }
    if (typeof current !== 'object') {
      fail('INVALID_ARGUMENTS', 'capability arguments must be JSON values');
    }
    if (utilTypes.isProxy(current)) fail('INVALID_ARGUMENTS', 'capability argument proxies are not allowed');
    if (ancestors.has(current)) fail('INVALID_ARGUMENTS', 'capability arguments must not be cyclic');
    ancestors.add(current);
    let encoded;
    if (Array.isArray(current)) {
      if (Object.getPrototypeOf(current) !== Array.prototype) {
        fail('INVALID_ARGUMENTS', 'capability argument arrays must use the standard prototype');
      }
      if (!Number.isSafeInteger(current.length) || current.length > MAX_ARGUMENT_NODES - nodes) {
        fail('ARGUMENTS_TOO_COMPLEX', 'capability argument array exceeds structural limits');
      }
      const ownKeys = Reflect.ownKeys(current);
      if (ownKeys.length !== current.length + 1) {
        fail('INVALID_ARGUMENTS', 'capability argument arrays must be dense and unmodified');
      }
      const expectedKeys = Array.from({ length: current.length }, (_, index) => String(index)).concat('length');
      if (ownKeys.length !== expectedKeys.length || ownKeys.some((key, index) => key !== expectedKeys[index])) {
        fail('INVALID_ARGUMENTS', 'capability argument arrays must be dense and unmodified');
      }
      emit('[');
      const entries = [];
      for (let index = 0; index < current.length; index += 1) {
        if (index > 0) emit(',');
        const descriptor = Object.getOwnPropertyDescriptor(current, String(index));
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
          fail('INVALID_ARGUMENTS', 'capability argument accessors are not allowed');
        }
        entries.push(encode(descriptor.value, depth + 1));
      }
      emit(']');
      encoded = `[${entries.join(',')}]`;
    } else {
      const prototype = Object.getPrototypeOf(current);
      if (prototype !== Object.prototype && prototype !== null) {
        fail('INVALID_ARGUMENTS', 'capability arguments must use plain objects');
      }
      const ownKeys = Reflect.ownKeys(current);
      if (ownKeys.length > MAX_ARGUMENT_NODES - nodes) {
        fail('ARGUMENTS_TOO_COMPLEX', 'capability argument object exceeds structural limits');
      }
      if (ownKeys.some((key) => typeof key !== 'string')) {
        fail('INVALID_ARGUMENTS', 'capability arguments must contain only enumerable string keys');
      }
      const keys = [...ownKeys].sort();
      emit('{');
      encoded = `{${keys.map((key) => {
        if (Buffer.byteLength(key) > MAX_IDENTIFIER_BYTES || key.includes('\0')) {
          fail('INVALID_ARGUMENTS', 'capability argument key is invalid');
        }
        if (depth === 0 && key.startsWith('_ss_')) {
          fail('INVALID_ARGUMENTS', 'reserved top-level capability argument key is not allowed');
        }
        const descriptor = Object.getOwnPropertyDescriptor(current, key);
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
          fail('INVALID_ARGUMENTS', 'capability argument accessors are not allowed');
        }
        if (keys.indexOf(key) > 0) emit(',');
        const encodedKey = JSON.stringify(key);
        emit(encodedKey);
        emit(':');
        return `${encodedKey}:${encode(descriptor.value, depth + 1)}`;
      }).join(',')}}`;
      emit('}');
    }
    ancestors.delete(current);
    return encoded;
  }

  return encode(value, 0);
}

function digestCanonical(canonical) {
  return `sha256:${crypto.createHash('sha256').update(canonical).digest('hex')}`;
}

function normalizeKeys(input) {
  if (!input || (typeof input !== 'object' && !(input instanceof Map))) {
    fail('INVALID_CONFIGURATION', 'dedicated capability keys are required');
  }
  const entries = input instanceof Map ? [...input.entries()] : Object.entries(input);
  const keys = new Map();
  for (const [rawVersion, rawKey] of entries) {
    const version = Number(rawVersion);
    if (!Number.isSafeInteger(version) || version < 1 || version > 9999 || keys.has(version)) {
      fail('INVALID_CONFIGURATION', 'capability key version is invalid');
    }
    if (!Buffer.isBuffer(rawKey) && typeof rawKey !== 'string') {
      fail('INVALID_CONFIGURATION', 'capability keys must be Buffers or strings');
    }
    const key = Buffer.isBuffer(rawKey) ? Buffer.from(rawKey) : Buffer.from(rawKey, 'utf8');
    if (key.length < 32) fail('INVALID_CONFIGURATION', 'each capability key must contain at least 32 bytes');
    keys.set(version, key);
  }
  if (keys.size === 0) fail('INVALID_CONFIGURATION', 'at least one capability key is required');
  return keys;
}

function integer(value, name, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) fail('INVALID_CLAIMS', `${name} is invalid`);
  return value;
}

function encodePayload(payload) {
  const ordered = {};
  for (const field of PAYLOAD_FIELDS) ordered[field] = payload[field];
  return JSON.stringify(ordered);
}

function decodeCanonicalPayload(encoded) {
  if (!BASE64URL_RE.test(encoded)) fail('MALFORMED_CAPABILITY', 'capability encoding is invalid');
  let bytes;
  let parsed;
  try {
    bytes = Buffer.from(encoded, 'base64url');
    if (bytes.toString('base64url') !== encoded) fail('MALFORMED_CAPABILITY', 'capability encoding is invalid');
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    if (error instanceof OwnerCapabilityError) throw error;
    fail('MALFORMED_CAPABILITY', 'capability payload is invalid');
  }
  exactKeys(parsed, PAYLOAD_FIELDS, 'MALFORMED_CAPABILITY');
  const canonical = encodePayload(parsed);
  if (!Buffer.from(canonical).equals(bytes)) fail('MALFORMED_CAPABILITY', 'capability payload is not canonical');
  return { payload: parsed, canonical };
}

function createOwnerCapabilityCodec(options = {}) {
  const keys = normalizeKeys(options.keys);
  const currentKeyVersion = Number(options.currentKeyVersion);
  if (!keys.has(currentKeyVersion)) fail('INVALID_CONFIGURATION', 'current capability key version is unavailable');
  if (typeof options.clock !== 'function') fail('INVALID_CONFIGURATION', 'an injected clock is required');
  if (!Array.isArray(options.allowedAudiences) || options.allowedAudiences.length === 0) {
    fail('INVALID_CONFIGURATION', 'allowed capability audiences are required');
  }
  const allowedAudiences = new Set(options.allowedAudiences.map((value) => boundedString(value, 'aud')));
  const issuer = options.issuer === undefined ? 'dvaia-backend' : boundedString(options.issuer, 'iss');
  const maxTtlSeconds = options.maxTtlSeconds === undefined ? DEFAULT_MAX_TTL_SECONDS : options.maxTtlSeconds;
  const maxArgumentBytes = options.maxArgumentBytes === undefined ? DEFAULT_MAX_ARGUMENT_BYTES : options.maxArgumentBytes;
  integer(maxTtlSeconds, 'maxTtlSeconds', 1);
  integer(maxArgumentBytes, 'maxArgumentBytes', 1);
  if (maxTtlSeconds > MAX_CONFIGURED_TTL_SECONDS || maxArgumentBytes > MAX_CONFIGURED_ARGUMENT_BYTES) {
    fail('INVALID_CONFIGURATION', 'capability limits exceed hard maximums');
  }

  function nowSeconds() {
    let milliseconds;
    try {
      milliseconds = options.clock();
    } catch (error) {
      fail('CLOCK_FAILURE', 'capability clock failed');
    }
    const seconds = Math.floor(milliseconds / 1000);
    if (!Number.isFinite(milliseconds) || milliseconds < 0 || !Number.isSafeInteger(seconds)) {
      fail('CLOCK_FAILURE', 'capability clock returned an invalid value');
    }
    return seconds;
  }

  function validateScope(input, fields) {
    exactKeys(input, fields, 'INVALID_CLAIMS');
    const scope = {};
    for (const field of fields) {
      if (field === 'args') continue;
      if (field === 'generation') scope[field] = integer(input[field], field, 1);
      else scope[field] = boundedString(input[field], field, field === 'nonce' ? MAX_NONCE_BYTES : MAX_IDENTIFIER_BYTES);
    }
    if (!allowedAudiences.has(scope.aud)) fail('INVALID_AUDIENCE', 'capability audience is not allowed');
    if (!ROLES.has(scope.shopRole)) fail('INVALID_CLAIMS', 'shopRole is invalid');
    scope.argsDigest = digestCanonical(canonicalizeArguments(input.args, maxArgumentBytes));
    return scope;
  }

  function signEncoded(encoded, keyVersion) {
    return crypto.createHmac('sha256', keys.get(keyVersion)).update(`${TOKEN_PREFIX}.${encoded}`).digest();
  }

  function issue(claims, issueOptions = {}) {
    const scope = validateScope(claims, ISSUE_FIELDS);
    const ttlSeconds = issueOptions.ttlSeconds === undefined ? maxTtlSeconds : issueOptions.ttlSeconds;
    integer(ttlSeconds, 'ttlSeconds', 1);
    if (ttlSeconds > maxTtlSeconds) fail('INVALID_TTL', 'capability TTL exceeds the configured maximum');
    const iat = nowSeconds();
    const exp = iat + ttlSeconds;
    if (!Number.isSafeInteger(exp)) fail('INVALID_TTL', 'capability expiry exceeds the supported clock range');
    const payload = {
      v: VERSION,
      keyVersion: currentKeyVersion,
      iss: issuer,
      aud: scope.aud,
      launchId: scope.launchId,
      platformOwnerId: scope.platformOwnerId,
      scenarioId: scope.scenarioId,
      generation: scope.generation,
      runId: scope.runId,
      agentSessionId: scope.agentSessionId,
      shopPersonaId: scope.shopPersonaId,
      shopRole: scope.shopRole,
      agent: scope.agent,
      tool: scope.tool,
      argsDigest: scope.argsDigest,
      operationId: scope.operationId,
      iat,
      exp,
      nonce: scope.nonce,
    };
    const canonical = encodePayload(payload);
    const encoded = Buffer.from(canonical).toString('base64url');
    const signature = signEncoded(encoded, payload.keyVersion).toString('base64url');
    return `${TOKEN_PREFIX}.${encoded}.${signature}`;
  }

  function verify(token, expected) {
    if (typeof token !== 'string' || token.length === 0 || Buffer.byteLength(token) > MAX_TOKEN_BYTES) {
      fail('MALFORMED_CAPABILITY', 'capability token is invalid');
    }
    const parts = token.split('.');
    if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX || !BASE64URL_RE.test(parts[2])) {
      fail('MALFORMED_CAPABILITY', 'capability token is invalid');
    }
    const { payload } = decodeCanonicalPayload(parts[1]);
    if (!Number.isSafeInteger(payload.keyVersion) || !keys.has(payload.keyVersion)) {
      fail('UNSUPPORTED_CAPABILITY', 'capability version is unsupported');
    }
    const suppliedSignature = Buffer.from(parts[2], 'base64url');
    if (suppliedSignature.length !== 32 || suppliedSignature.toString('base64url') !== parts[2]) {
      fail('INVALID_SIGNATURE', 'capability signature is invalid');
    }
    const expectedSignature = signEncoded(parts[1], payload.keyVersion);
    if (!crypto.timingSafeEqual(suppliedSignature, expectedSignature)) {
      fail('INVALID_SIGNATURE', 'capability signature is invalid');
    }
    if (payload.v !== VERSION) fail('UNSUPPORTED_CAPABILITY', 'capability version is unsupported');

    boundedString(payload.iss, 'iss');
    if (payload.iss !== issuer) fail('INVALID_ISSUER', 'capability issuer is invalid');
    if (!allowedAudiences.has(payload.aud)) fail('INVALID_AUDIENCE', 'capability audience is invalid');
    for (const field of PAYLOAD_FIELDS) {
      if (['v', 'keyVersion', 'generation', 'iat', 'exp'].includes(field)) continue;
      if (field === 'argsDigest') {
        if (typeof payload[field] !== 'string' || !DIGEST_RE.test(payload[field])) fail('INVALID_CLAIMS', 'argsDigest is invalid');
      } else {
        boundedString(payload[field], field, field === 'nonce' ? MAX_NONCE_BYTES : MAX_IDENTIFIER_BYTES);
      }
    }
    integer(payload.generation, 'generation', 1);
    integer(payload.iat, 'iat');
    integer(payload.exp, 'exp');
    if (payload.exp <= payload.iat || payload.exp - payload.iat > maxTtlSeconds) {
      fail('INVALID_TTL', 'capability validity window is invalid');
    }
    const now = nowSeconds();
    if (payload.iat > now) fail('NOT_YET_VALID', 'capability is not yet valid');
    if (payload.exp <= now) fail('EXPIRED_CAPABILITY', 'capability has expired');

    const trusted = validateScope(expected, EXPECTED_FIELDS);
    for (const field of EXPECTED_FIELDS) {
      if (field === 'args') continue;
      if (payload[field] !== trusted[field]) fail('CONTEXT_MISMATCH', 'capability does not match trusted context');
    }
    if (payload.argsDigest !== trusted.argsDigest) fail('CONTEXT_MISMATCH', 'capability does not match trusted arguments');

    const claims = Object.freeze({ ...payload });
    return Object.freeze({
      claims,
      capabilityDigest: digestCanonical(token),
      onlineAuthorizationRequired: true,
    });
  }

  function digestArguments(args) {
    return digestCanonical(canonicalizeArguments(args, maxArgumentBytes));
  }

  return Object.freeze({ digestArguments, issue, verify });
}

module.exports = {
  OwnerCapabilityError,
  PAYLOAD_FIELDS,
  createOwnerCapabilityCodec,
};
