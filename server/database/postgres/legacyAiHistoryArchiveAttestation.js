'use strict';

const { createHash } = require('node:crypto');

const DIGEST = /^[0-9a-f]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const INT4_MIN = -2147483648;
const INT4_MAX = 2147483647;
const MAX_ROWS = 100000;
const ENVELOPE_VERSION = 1;
const BINDING_PREFIX = 'legacy-ai-history-attestation-v1';

const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

function exactObject(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new TypeError(`Exact ${label} fields required`);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some(key => typeof key !== 'string')) throw new TypeError(`Exact ${label} fields required`);
  const actual = ownKeys.sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`Exact ${label} fields required`);
  }
  const copy = {};
  for (const key of expected) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field || !Object.hasOwn(field, 'value') || field.enumerable !== true) {
      throw new TypeError(`Plain ${label} fields required`);
    }
    copy[key] = field.value;
  }
  return Object.freeze(copy);
}

function exactArray(value, maximum, label) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
      || Object.getOwnPropertySymbols(value).length) {
    throw new TypeError(`Bounded ${label} required`);
  }
  const lengthField = Object.getOwnPropertyDescriptor(value, 'length');
  const length = lengthField && Object.hasOwn(lengthField, 'value') ? lengthField.value : null;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum) {
    throw new TypeError(`Bounded ${label} required`);
  }
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== length + 1 || names.at(-1) !== 'length') {
    throw new TypeError(`Plain ${label} required`);
  }
  const items = [];
  for (let index = 0; index < length; index += 1) {
    const field = Object.getOwnPropertyDescriptor(value, String(index));
    if (!field || !Object.hasOwn(field, 'value') || field.enumerable !== true) {
      throw new TypeError(`Plain ${label} required`);
    }
    items.push(field.value);
  }
  return items;
}

function uuid(value, label) {
  if (typeof value !== 'string' || !UUID_V4.test(value)) throw new TypeError(`Valid ${label} required`);
  return value.toLowerCase();
}

function hash(value, label) {
  if (typeof value !== 'string' || !DIGEST.test(value)) throw new TypeError(`Valid ${label} required`);
  return value;
}

function sourceIdentity(value) {
  if (typeof value !== 'string' || !Buffer.byteLength(value) || Buffer.byteLength(value) > 512
      || /[\0\r\n]/.test(value)) throw new TypeError('Valid source store identity required');
  return value;
}

function descriptor(value) {
  const input = exactObject(value, ['sourceRowId', 'sourceDigest'], 'source descriptor');
  if (!Number.isInteger(input.sourceRowId) || input.sourceRowId < INT4_MIN || input.sourceRowId > INT4_MAX) {
    throw new TypeError('Valid source row ID required');
  }
  return Object.freeze({ sourceRowId: input.sourceRowId,
    sourceDigest: hash(input.sourceDigest, 'source row digest') });
}

function canonicalDescriptors(rows) {
  const copied = exactArray(rows, MAX_ROWS, 'source descriptors')
    .map(descriptor).sort((a, b) => a.sourceRowId - b.sourceRowId);
  if (new Set(copied.map(row => row.sourceRowId)).size !== copied.length) {
    throw new TypeError('Unique source descriptors required');
  }
  return Object.freeze(copied);
}

function computeSourceStoreDigest(value) {
  return digest(Object.freeze({ version: ENVELOPE_VERSION, sourceStoreIdentity: sourceIdentity(value) }));
}

function canonicalManifest(value) {
  const input = exactObject(value, ['envelopeVersion', 'batchId', 'sourceStoreIdentity', 'sourceStoreDigest',
    'aggregateDigest', 'rows', 'claims'], 'archive manifest');
  if (input.envelopeVersion !== ENVELOPE_VERSION) throw new TypeError('Supported archive envelope required');
  const claims = exactArray(input.claims, MAX_ROWS, 'archive claims');
  if (claims.length !== 0) {
    throw Object.assign(new Error('Independent ownership attestation is unavailable'), {
      code: 'LEGACY_AI_OWNERSHIP_ATTESTATION_UNAVAILABLE',
    });
  }
  const identity = sourceIdentity(input.sourceStoreIdentity);
  const storeDigest = hash(input.sourceStoreDigest, 'source store digest');
  if (storeDigest !== computeSourceStoreDigest(identity)) {
    throw new TypeError('Source store digest differs from reviewed identity');
  }
  const rows = canonicalDescriptors(input.rows);
  const aggregateDigest = hash(input.aggregateDigest, 'aggregate digest');
  if (aggregateDigest !== digest(rows)) {
    throw new TypeError('Aggregate digest differs from reviewed source descriptors');
  }
  return Object.freeze({ envelopeVersion: ENVELOPE_VERSION,
    batchId: uuid(input.batchId, 'archive batch ID'), sourceStoreIdentity: identity,
    sourceStoreDigest: storeDigest, aggregateDigest, rows, claims: Object.freeze([]) });
}

function computeManifestDigest(value) {
  return digest(canonicalManifest(value));
}

function bindSourceStoreIdentity(value) {
  const input = exactObject(value, ['sourceStoreDigest', 'manifestDigest', 'claimsDigest',
    'attestationReceipt'], 'source store binding');
  return [BINDING_PREFIX, hash(input.sourceStoreDigest, 'source store digest'),
    hash(input.manifestDigest, 'manifest digest'), hash(input.claimsDigest, 'claims digest'),
    hash(input.attestationReceipt, 'attestation receipt')].join(':');
}

function createLegacyAiHistoryArchiveAttestation(options) {
  const input = exactObject(options, ['manifest', 'manifestDigest', 'attestationReceipt'],
    'archive attestation option');
  const manifest = canonicalManifest(input.manifest);
  const manifestDigest = hash(input.manifestDigest, 'manifest digest');
  // This is an opaque digest of the operator's reviewed record. It is not a
  // signature and proves no row ownership; this capability permits no claims.
  const attestationReceipt = hash(input.attestationReceipt, 'attestation receipt');
  if (digest(manifest) !== manifestDigest) throw new TypeError('Reviewed archive manifest digest differs');
  const claimsDigest = digest(manifest.claims);
  const boundSourceStoreIdentity = bindSourceStoreIdentity({ sourceStoreDigest: manifest.sourceStoreDigest,
    manifestDigest, claimsDigest, attestationReceipt });

  return Object.freeze({
    async attest(value) {
      const input = exactObject(value, ['batchId', 'sourceStoreIdentity', 'sourceStoreDigest',
        'aggregateDigest', 'rows'], 'archive attestation request');
      const request = Object.freeze({ batchId: uuid(input.batchId, 'archive batch ID'),
        sourceStoreIdentity: sourceIdentity(input.sourceStoreIdentity),
        sourceStoreDigest: hash(input.sourceStoreDigest, 'source store digest'),
        aggregateDigest: hash(input.aggregateDigest, 'aggregate digest'),
        rows: canonicalDescriptors(input.rows) });
      if (request.batchId !== manifest.batchId
          || request.sourceStoreIdentity !== manifest.sourceStoreIdentity
          || request.sourceStoreDigest !== manifest.sourceStoreDigest
          || request.aggregateDigest !== manifest.aggregateDigest
          || JSON.stringify(request.rows) !== JSON.stringify(manifest.rows)) {
        throw new Error('Reviewed archive manifest differs from source snapshot');
      }
      return Object.freeze({ envelopeVersion: ENVELOPE_VERSION, batchId: manifest.batchId,
        sourceStoreDigest: manifest.sourceStoreDigest, aggregateDigest: manifest.aggregateDigest,
        manifestDigest, claims: Object.freeze([]), claimsDigest, attestationReceipt,
        boundSourceStoreIdentity });
    },
  });
}

module.exports = {
  BINDING_PREFIX,
  ENVELOPE_VERSION,
  bindSourceStoreIdentity,
  canonicalManifest,
  computeManifestDigest,
  computeSourceStoreDigest,
  createLegacyAiHistoryArchiveAttestation,
};
