'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createLegacyAiHistoryDraftImporter, digest } = require(
  '../server/database/postgres/legacyAiHistoryDraftImporter');
const {
  BINDING_PREFIX,
  bindSourceStoreIdentity,
  computeManifestDigest,
  computeSourceStoreDigest,
  createLegacyAiHistoryArchiveAttestation,
} = require('../server/database/postgres/legacyAiHistoryArchiveAttestation');

const BATCH = '10000000-0000-4000-8000-000000000099';
const OTHER_BATCH = '20000000-0000-4000-8000-000000000099';
const SOURCE_IDENTITY = 'legacy-challenge://reviewed-installation/archive-only';
const RECEIPT = 'c'.repeat(64);
const ROWS = Object.freeze([
  Object.freeze({ id: -2147483648, userId: -9, prompt: '', response: null,
    modelUsed: null, createdAt: null, platformOwnerId: 2147483647 }),
  Object.freeze({ id: 0, userId: null, prompt: 'Unicode \u2603', response: '',
    modelUsed: '', createdAt: '-infinity', platformOwnerId: null }),
  Object.freeze({ id: 7, userId: 1, prompt: 'microsecond', response: 'exact',
    modelUsed: 'model', createdAt: '2026-09-15T01:02:03.123456Z', platformOwnerId: 99 }),
]);

function reviewedArchive(rows = ROWS, overrides = {}) {
  const descriptors = rows.map(row => ({ sourceRowId: row.id, sourceDigest: digest(row) }));
  const aggregateDigest = digest(descriptors);
  const sourceStoreDigest = computeSourceStoreDigest(SOURCE_IDENTITY);
  const manifest = { envelopeVersion: 1, batchId: BATCH, sourceStoreIdentity: SOURCE_IDENTITY,
    sourceStoreDigest, aggregateDigest, rows: descriptors, claims: [], ...overrides };
  return { descriptors, aggregateDigest, sourceStoreDigest, manifest,
    manifestDigest: computeManifestDigest(manifest) };
}

test('reviewed empty-claim manifest returns one immutable archive-only envelope', async () => {
  const reviewed = reviewedArchive();
  const capability = createLegacyAiHistoryArchiveAttestation({ manifest: reviewed.manifest,
    manifestDigest: reviewed.manifestDigest, attestationReceipt: RECEIPT });
  const result = await capability.attest({ batchId: BATCH.toUpperCase(),
    sourceStoreIdentity: SOURCE_IDENTITY, sourceStoreDigest: reviewed.sourceStoreDigest,
    aggregateDigest: reviewed.aggregateDigest, rows: reviewed.descriptors });
  const claimsDigest = digest([]);
  assert.deepEqual(result, { envelopeVersion: 1, batchId: BATCH,
    sourceStoreDigest: reviewed.sourceStoreDigest, aggregateDigest: reviewed.aggregateDigest,
    manifestDigest: reviewed.manifestDigest, claims: [], claimsDigest,
    attestationReceipt: RECEIPT,
    boundSourceStoreIdentity: bindSourceStoreIdentity({ sourceStoreDigest: reviewed.sourceStoreDigest,
      manifestDigest: reviewed.manifestDigest, claimsDigest, attestationReceipt: RECEIPT }) });
  assert.ok(Object.isFrozen(capability) && Object.isFrozen(result) && Object.isFrozen(result.claims));
  assert.match(result.boundSourceStoreIdentity, new RegExp(`^${BINDING_PREFIX}:`));
  assert.ok(Buffer.byteLength(result.boundSourceStoreIdentity) <= 512);
});

test('archive-only capability rejects claims and every manifest or snapshot binding mismatch', async t => {
  const reviewed = reviewedArchive();
  assert.throws(() => createLegacyAiHistoryArchiveAttestation({ manifest: {
    ...reviewed.manifest, claims: [{ sourceRowId: 7 }],
  }, manifestDigest: reviewed.manifestDigest, attestationReceipt: RECEIPT }),
  error => error.code === 'LEGACY_AI_OWNERSHIP_ATTESTATION_UNAVAILABLE');
  assert.throws(() => createLegacyAiHistoryArchiveAttestation({ manifest: reviewed.manifest,
    manifestDigest: '0'.repeat(64), attestationReceipt: RECEIPT }), /manifest digest differs/);
  assert.throws(() => createLegacyAiHistoryArchiveAttestation({ manifest: reviewed.manifest,
    manifestDigest: reviewed.manifestDigest, attestationReceipt: 'reviewed-by-caller' }),
  /attestation receipt/);
  assert.throws(() => createLegacyAiHistoryArchiveAttestation({ manifest: {
    ...reviewed.manifest, aggregateDigest: '4'.repeat(64),
  }, manifestDigest: reviewed.manifestDigest, attestationReceipt: RECEIPT }),
  /Aggregate digest differs/);
  const capability = createLegacyAiHistoryArchiveAttestation({ manifest: reviewed.manifest,
    manifestDigest: reviewed.manifestDigest, attestationReceipt: RECEIPT });
  const request = { batchId: BATCH, sourceStoreIdentity: SOURCE_IDENTITY,
    sourceStoreDigest: reviewed.sourceStoreDigest, aggregateDigest: reviewed.aggregateDigest,
    rows: reviewed.descriptors };
  const cases = [
    ['batch', { ...request, batchId: OTHER_BATCH }],
    ['store identity', { ...request, sourceStoreIdentity: `${SOURCE_IDENTITY}/other` }],
    ['store digest', { ...request, sourceStoreDigest: '0'.repeat(64) }],
    ['aggregate', { ...request, aggregateDigest: '1'.repeat(64) }],
    ['row digest', { ...request, rows: request.rows.map((row, index) => index
      ? row : { ...row, sourceDigest: '2'.repeat(64) }) }],
    ['unknown row', { ...request, rows: [...request.rows,
      { sourceRowId: 99, sourceDigest: '3'.repeat(64) }] }],
    ['injected field', { ...request, ownerId: 99 }],
  ];
  for (const [name, input] of cases) await t.test(name, async () => {
    await assert.rejects(capability.attest(input));
  });
});

test('accessors, prototypes and later caller mutation cannot alter reviewed bytes', async () => {
  const reviewed = reviewedArchive();
  const accessorManifest = { ...reviewed.manifest };
  Object.defineProperty(accessorManifest, 'batchId', { enumerable: true, get: () => BATCH });
  assert.throws(() => createLegacyAiHistoryArchiveAttestation({ manifest: accessorManifest,
    manifestDigest: reviewed.manifestDigest, attestationReceipt: RECEIPT }), /Plain archive manifest/);
  const accessorRow = { sourceRowId: ROWS[0].id };
  Object.defineProperty(accessorRow, 'sourceDigest', { enumerable: true, get: () => digest(ROWS[0]) });
  assert.throws(() => computeManifestDigest({ ...reviewed.manifest, rows: [accessorRow] }),
    /Plain source descriptor/);
  assert.throws(() => computeManifestDigest(Object.assign(Object.create({ inherited: true }),
    reviewed.manifest)), /Exact archive manifest/);

  const mutableRows = reviewed.descriptors.map(row => ({ ...row }));
  const mutableManifest = { ...reviewed.manifest, rows: mutableRows, claims: [] };
  const capability = createLegacyAiHistoryArchiveAttestation({ manifest: mutableManifest,
    manifestDigest: computeManifestDigest(mutableManifest), attestationReceipt: RECEIPT });
  mutableManifest.batchId = OTHER_BATCH;
  mutableRows[0].sourceDigest = '0'.repeat(64);
  mutableManifest.claims.push({ sourceRowId: ROWS[0].id });
  const result = await capability.attest({ batchId: BATCH, sourceStoreIdentity: SOURCE_IDENTITY,
    sourceStoreDigest: reviewed.sourceStoreDigest, aggregateDigest: reviewed.aggregateDigest,
    rows: reviewed.descriptors });
  assert.equal(result.batchId, BATCH);
  assert.deepEqual(result.claims, []);

  const request = { batchId: BATCH, sourceStoreIdentity: SOURCE_IDENTITY,
    sourceStoreDigest: reviewed.sourceStoreDigest, aggregateDigest: reviewed.aggregateDigest,
    rows: reviewed.descriptors };
  Object.defineProperty(request, 'batchId', { enumerable: true, get: () => BATCH });
  await assert.rejects(capability.attest(request), /Plain archive attestation request/);
});

test('array length is captured from its descriptor without invoking a Proxy getter', () => {
  const reviewed = reviewedArchive();
  let reads = 0;
  const rows = new Proxy(reviewed.descriptors, {
    get(target, key, receiver) {
      if (key === 'length') { reads += 1; return 100001; }
      return Reflect.get(target, key, receiver);
    },
  });
  assert.equal(computeManifestDigest({ ...reviewed.manifest, rows }), reviewed.manifestDigest);
  assert.equal(reads, 0);
  const oversized = new Proxy(new Array(100001), {
    get(target, key, receiver) { return key === 'length' ? 0 : Reflect.get(target, key, receiver); },
  });
  assert.throws(() => computeManifestDigest({ ...reviewed.manifest, rows: oversized }),
    /Bounded source descriptors/);
});

test('archive-only importer binds reviewed manifest into existing source identity and preserves every row byte', async () => {
  const reviewed = reviewedArchive();
  const capability = createLegacyAiHistoryArchiveAttestation({ manifest: reviewed.manifest,
    manifestDigest: reviewed.manifestDigest, attestationReceipt: RECEIPT });
  const source = Object.freeze({ readSnapshot: async () => ({ batchId: BATCH,
    sourceStoreIdentity: SOURCE_IDENTITY, rows: ROWS }) });
  const calls = [], archived = [];
  const target = Object.freeze({
    begin: async value => { calls.push(['begin', value]); return { state: 'copying' }; },
    archive: async value => { calls.push(['archive', value]); archived.push(value); },
    promote: async () => { throw new Error('Archive-only capability cannot promote'); },
    readArchived: async () => archived,
    readPromoted: async () => { throw new Error('Archive-only capability cannot read promotion'); },
    verify: async value => ({ batchId: value.batchId, sourceRemovalReceipt: value.aggregateDigest,
      verifiedAt: '2026-09-17T00:00:00.000Z' }),
  });
  const receipt = await createLegacyAiHistoryDraftImporter({ sourceSnapshotCapability: source,
    ownershipAttestationCapability: capability, targetImportCapability: target }).quarantine();
  assert.equal(calls.filter(([kind]) => kind === 'archive').length, ROWS.length);
  assert.equal(calls.some(([kind]) => kind === 'promote'), false);
  assert.deepEqual(archived.map(row => row.sourceRecord), ROWS);
  assert.deepEqual(archived.map(row => [row.classification, row.ownerId]),
    ROWS.map(() => ['unknown', null]));
  assert.deepEqual(archived.map(row => row.sourceDigest), ROWS.map(digest));
  assert.equal(receipt.batchId, BATCH);
  assert.equal(receipt.manifestDigest, reviewed.manifestDigest);
  assert.deepEqual(receipt.claims, []);
  assert.equal(receipt.targetReceipt.sourceRemovalReceipt, reviewed.aggregateDigest);
  assert.equal(calls[0][1].sourceStoreIdentity, receipt.boundSourceStoreIdentity);
  assert.notEqual(calls[0][1].sourceStoreIdentity, SOURCE_IDENTITY);
});

test('cross-batch response and legacy unbound target batch stop before archive writes', async t => {
  const reviewed = reviewedArchive();
  const source = Object.freeze({ readSnapshot: async () => ({ batchId: BATCH,
    sourceStoreIdentity: SOURCE_IDENTITY, rows: ROWS }) });
  const makeTarget = begin => {
    let writes = 0;
    return { target: Object.freeze({ begin, archive: async () => { writes += 1; },
      promote: async () => { writes += 1; }, readArchived: async () => [],
      readPromoted: async () => null, verify: async () => { writes += 1; } }),
    writes: () => writes };
  };
  await t.test('cross-batch attestation', async () => {
    const valid = await createLegacyAiHistoryArchiveAttestation({ manifest: reviewed.manifest,
      manifestDigest: reviewed.manifestDigest, attestationReceipt: RECEIPT }).attest({
      batchId: BATCH, sourceStoreIdentity: SOURCE_IDENTITY,
      sourceStoreDigest: reviewed.sourceStoreDigest, aggregateDigest: reviewed.aggregateDigest,
      rows: reviewed.descriptors });
    const capability = Object.freeze({ attest: async () => Object.freeze({ ...valid,
      batchId: OTHER_BATCH }) });
    const state = makeTarget(async () => ({ state: 'copying' }));
    await assert.rejects(createLegacyAiHistoryDraftImporter({ sourceSnapshotCapability: source,
      ownershipAttestationCapability: capability, targetImportCapability: state.target }).quarantine(),
    /attestation differs/);
    assert.equal(state.writes(), 0);
  });
  await t.test('pre-envelope batch identity', async () => {
    const capability = createLegacyAiHistoryArchiveAttestation({ manifest: reviewed.manifest,
      manifestDigest: reviewed.manifestDigest, attestationReceipt: RECEIPT });
    const state = makeTarget(async value => {
      assert.match(value.sourceStoreIdentity, /^legacy-ai-history-attestation-v1:/);
      throw new Error('Existing batch source identity differs');
    });
    await assert.rejects(createLegacyAiHistoryDraftImporter({ sourceSnapshotCapability: source,
      ownershipAttestationCapability: capability, targetImportCapability: state.target }).quarantine(),
    /Existing batch source identity differs/);
    assert.equal(state.writes(), 0);
  });
});
