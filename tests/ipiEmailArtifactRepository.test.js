'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createEmailArtifactRepository, normalizeArtifact, modelSlice,
  MAX_BODY_BYTES, MAX_MODEL_BYTES } = require('../server/database/postgres/emailArtifactRepository');

const RUN = '11111111-1111-4111-8111-111111111111';
const ARTIFACT = '22222222-2222-4222-8222-222222222222';
const ownerKey = id => JSON.stringify(['IndirectEmail', String(id)]);
const sha = value => createHash('sha256').update(value, 'utf8').digest('hex');

function poolFixture() {
  const rows = new Map();
  const state = { ownerCurrent:true, runCurrent:true, ready:true, missing:false, rows, queries:[] };
  return {
    state,
    async query(sql, params = []) {
      const compact = sql.replace(/\s+/g, ' ').trim();
      state.queries.push([compact, params]);
      if (state.missing) throw Object.assign(new Error('relation does not exist'), { code:'42P01' });
      if (compact.includes('INSERT INTO identity.ipi_email_artifacts')) {
        if (!state.ownerCurrent || !state.runCurrent) return { rowCount:0, rows:[] };
        const [ownerId, key, generation, runId, encoded] = params;
        const inserted = JSON.parse(encoded).map(record => ({ artifact_id:record.artifact_id,
          owner_id:ownerId, owner_key:key, generation, run_id:runId,
          ingestion_kind:record.ingestion_kind, provider:record.provider,
          provider_message_id:record.provider_message_id, sender:record.sender,
          recipient:record.recipient, subject:record.subject, body_text:record.body,
          body_bytes:record.body_bytes, body_sha256:record.body_sha256,
          model_body_text:record.model_body, model_body_bytes:record.model_body_bytes,
          model_body_sha256:record.model_body_sha256,
          model_body_truncated:record.model_body_truncated, created_at:'fixture', retired_at:null }));
        for (const row of inserted) rows.set(row.artifact_id, row);
        return { rowCount:inserted.length, rows:inserted };
      }
      if (compact.startsWith('SELECT * FROM identity.ipi_email_artifacts')) {
        const [id, ownerId, key, generation] = params;
        const row = rows.get(id);
        return { rows:row && row.owner_id === ownerId && row.owner_key === key
          && String(row.generation) === String(generation) && row.retired_at === null ? [row] : [] };
      }
      if (compact.startsWith('UPDATE identity.ipi_email_artifacts SET retired_at')) {
        const [ownerId, key] = params; let count = 0;
        for (const row of rows.values()) if (row.owner_id === ownerId && row.owner_key === key && row.retired_at === null) {
          row.retired_at = 'retired'; count += 1;
        }
        return { rowCount:count, rows:[] };
      }
      if (compact.startsWith('DELETE FROM identity.ipi_email_artifacts')) {
        const [ownerId, key] = params; let count = 0;
        for (const [id, row] of rows) if (row.owner_id === ownerId && row.owner_key === key) {
          rows.delete(id); count += 1;
        }
        return { rowCount:count, rows:[] };
      }
      if (compact.startsWith('SELECT to_regclass') || compact.startsWith('SELECT to_regclass(')) {
        return { rows:[{ table_ready:state.ready, run_table_ready:state.ready,
          privileges_ready:state.ready, immutable_ready:state.ready }] };
      }
      throw new Error(`Unexpected SQL: ${compact}`);
    },
  };
}

test('normalization retains exact manual bytes and unknown provenance with a bounded Unicode model slice', () => {
  const body = `  manual exact bytes\n${'😀'.repeat(6000)}\n`;
  const normalized = normalizeArtifact({ artifactId:ARTIFACT, ingestionKind:'manual_entry',
    provider:'manual_entry', providerMessageId:null, sentReceiptId:null, sender:'',
    recipient:'learner@sharklasers.com', subject:'Manual', body });
  assert.equal(normalized.body, body);
  assert.equal(normalized.bodyBytes, Buffer.byteLength(body));
  assert.equal(normalized.bodySha256, sha(body));
  assert.equal(normalized.providerMessageId, null);
  assert.equal(normalized.sender, '');
  assert.ok(normalized.modelBody.length <= 5000);
  assert.ok(normalized.modelBodyBytes <= MAX_MODEL_BYTES);
  assert.equal(normalized.modelBodySha256, sha(normalized.modelBody));
  assert.equal(normalized.modelBodyTruncated, true);
  assert.equal(modelSlice(body), normalized.modelBody);
  assert.throws(() => normalizeArtifact({ ...normalized, body:'x', extra:'caller' }), /Unexpected/);
  assert.throws(() => normalizeArtifact({ artifactId:ARTIFACT, ingestionKind:'manual_entry',
    provider:'manual_entry', providerMessageId:'forged', sender:'', recipient:'x', subject:'', body:'body' }),
  /provenance/);
  assert.throws(() => normalizeArtifact({ artifactId:ARTIFACT, ingestionKind:'inbox_provider',
    provider:'guerrillamail', providerMessageId:null, sender:'a', recipient:'x', subject:'', body:'body' }),
  /identity/);
  assert.throws(() => normalizeArtifact({ artifactId:ARTIFACT, ingestionKind:'manual_entry',
    provider:'manual_entry', sender:'', recipient:'x', subject:'', body:'x'.repeat(MAX_BODY_BYTES + 1) }), /body/);
  for (const artifactId of [[ARTIFACT], { toString:() => ARTIFACT }]) {
    assert.throws(() => normalizeArtifact({ artifactId, ingestionKind:'manual_entry',
      provider:'manual_entry', sender:'', recipient:'x', subject:'', body:'body' }), /artifact id/);
  }
});

test('normalization retains the actual controlled inbox provider identity', () => {
  const mailpit = normalizeArtifact({ artifactId:ARTIFACT, ingestionKind:'inbox_provider',
    provider:'mailpit', providerMessageId:'mailpit-message-7', sentReceiptId:null,
    sender:'attacker@owasp-ai-goat.invalid', recipient:'ipi-email-7@owasp-ai-goat.invalid',
    subject:'Controlled training email', body:'Exact controlled inbox bytes.' });
  assert.equal(mailpit.provider, 'mailpit');
  assert.equal(mailpit.providerMessageId, 'mailpit-message-7');
  assert.throws(() => normalizeArtifact({ artifactId:ARTIFACT, ingestionKind:'inbox_provider',
    provider:'mailpit', providerMessageId:'mailpit-message-7', sentReceiptId:99,
    sender:'attacker@owasp-ai-goat.invalid', recipient:'ipi-email-7@owasp-ai-goat.invalid',
    subject:'Controlled training email', body:'Exact controlled inbox bytes.' }), /not established/);
  assert.throws(() => normalizeArtifact({ artifactId:ARTIFACT, ingestionKind:'inbox_provider',
    provider:'invented-provider', providerMessageId:'mailpit-message-7', sentReceiptId:null,
    sender:'attacker@owasp-ai-goat.invalid', recipient:'ipi-email-7@owasp-ai-goat.invalid',
    subject:'Controlled training email', body:'Exact controlled inbox bytes.' }), /provider/);
});

test('artifact readback survives repository recreation and exact owner generation retirement fences siblings', async () => {
  const pool = poolFixture();
  const first = createEmailArtifactRepository(pool);
  const [created] = await first.createMany({ ownerId:7, ownerKey:ownerKey(7), generation:'3', runId:RUN,
    artifacts:[{ artifactId:ARTIFACT, ingestionKind:'manual_entry', provider:'manual_entry',
      providerMessageId:null, sentReceiptId:null, sender:'', recipient:'learner@sharklasers.com',
      subject:'Manual', body:' exact body\n' }] });
  assert.equal(created.body, ' exact body\n');
  assert.equal(created.runId, RUN);
  const reopened = createEmailArtifactRepository(pool);
  assert.equal((await reopened.resolveCurrent({ artifactId:ARTIFACT, ownerId:7,
    ownerKey:ownerKey(7), generation:3 })).bodySha256, sha(' exact body\n'));
  for (const scope of [
    { artifactId:ARTIFACT, ownerId:8, ownerKey:ownerKey(8), generation:3 },
    { artifactId:ARTIFACT, ownerId:7, ownerKey:ownerKey(7), generation:4 },
    { artifactId:'33333333-3333-4333-8333-333333333333', ownerId:7, ownerKey:ownerKey(7), generation:3 },
  ]) await assert.rejects(reopened.resolveCurrent(scope), { code:'EMAIL_ARTIFACT_UNAVAILABLE', statusCode:409 });
  assert.equal(await reopened.retireOwner({ ownerId:7, ownerKey:ownerKey(7) }), 1);
  assert.equal(await reopened.retireOwner({ ownerId:7, ownerKey:ownerKey(7) }), 0);
  await assert.rejects(reopened.resolveCurrent({ artifactId:ARTIFACT, ownerId:7,
    ownerKey:ownerKey(7), generation:3 }), { code:'EMAIL_ARTIFACT_UNAVAILABLE' });
  assert.equal(pool.state.rows.get(ARTIFACT).body_text, ' exact body\n');
  assert.equal(await reopened.destroyOwner({ ownerId:8, ownerKey:ownerKey(8) }), 0);
  assert.equal(pool.state.rows.has(ARTIFACT), true);
  assert.equal(await reopened.destroyOwner({ ownerId:7, ownerKey:ownerKey(7) }), 1);
});

test('creation is gated by the exact running ledger row and readiness fails closed', async () => {
  const pool = poolFixture();
  const repository = createEmailArtifactRepository(pool);
  pool.state.runCurrent = false;
  await assert.rejects(repository.createMany({ ownerId:7, ownerKey:ownerKey(7), generation:3, runId:RUN,
    artifacts:[{ artifactId:ARTIFACT, ingestionKind:'manual_entry', provider:'manual_entry', sender:'',
      recipient:'x', subject:'', body:'body' }] }), { code:'EMAIL_ARTIFACT_RUN_STALE', statusCode:409 });
  assert.equal(pool.state.rows.size, 0);
  pool.state.ready = false;
  await assert.rejects(repository.assertReady(), { code:'EMAIL_ARTIFACT_STORAGE_NOT_READY', statusCode:503 });
  await assert.rejects(repository.resolveCurrent({ artifactId:ARTIFACT, ownerId:7,
    ownerKey:ownerKey(8), generation:3 }), /scope mismatch/);
});

test('creation locks and requires the current owner generation even while the old run remains running', async () => {
  const pool = poolFixture();
  const repository = createEmailArtifactRepository(pool);
  pool.state.ownerCurrent = false;
  await assert.rejects(repository.createMany({ ownerId:7, ownerKey:ownerKey(7), generation:3, runId:RUN,
    artifacts:[{ artifactId:ARTIFACT, ingestionKind:'manual_entry', provider:'manual_entry', sender:'',
      recipient:'x', subject:'', body:'body' }] }),
  { code:'EMAIL_ARTIFACT_RUN_STALE', statusCode:409 });
  assert.equal(pool.state.rows.size, 0);
  const write = pool.state.queries.find(([sql]) => sql.includes('INSERT INTO identity.ipi_email_artifacts'))[0];
  assert.match(write, /FROM graph_runtime\.owners WHERE owner_key=\$2 AND generation=\$3 FOR NO KEY UPDATE/);
  assert.match(write, /JOIN graph_runtime\.runs r ON r\.owner_key=o\.owner_key AND r\.generation=o\.generation/);
});

test('unsafe numeric generations are rejected before PostgreSQL coercion', async () => {
  const repository=createEmailArtifactRepository(poolFixture());
  await assert.rejects(repository.createMany({ownerId:7,ownerKey:ownerKey(7),generation:Number.MAX_SAFE_INTEGER+1,
    runId:RUN,artifacts:[{artifactId:ARTIFACT,ingestionKind:'manual_entry',provider:'manual_entry',
      sender:'',recipient:'x',subject:'',body:'body'}]}),/generation/);
});

test('an unregistered artifact migration is consistently reported as unavailable', async () => {
  const pool=poolFixture();pool.state.missing=true;
  const repository=createEmailArtifactRepository(pool);
  const artifact={artifactId:ARTIFACT,ingestionKind:'manual_entry',provider:'manual_entry',
    sender:'',recipient:'x',subject:'',body:'body'};
  await assert.rejects(repository.assertReady(), {code:'EMAIL_ARTIFACT_STORAGE_NOT_READY',statusCode:503});
  await assert.rejects(repository.createMany({ownerId:7,ownerKey:ownerKey(7),generation:3,
    runId:RUN,artifacts:[artifact]}), {code:'EMAIL_ARTIFACT_STORAGE_NOT_READY',statusCode:503});
  await assert.rejects(repository.resolveCurrent({artifactId:ARTIFACT,ownerId:7,
    ownerKey:ownerKey(7),generation:3}), {code:'EMAIL_ARTIFACT_STORAGE_NOT_READY',statusCode:503});
});

test('0065 v2 candidate is forward-only, immutable, least-privilege, and serialized with owner reset', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const sql = fs.readFileSync(path.join(__dirname,
    '../docs/modernization/drafts/0065_ipi_email_artifacts_v2.sql'), 'utf8');
  assert.match(sql, /REFERENCES graph_runtime\.runs\(run_id\)/);
  assert.match(sql, /BEFORE INSERT ON identity\.ipi_email_artifacts/);
  assert.match(sql, /graph_runtime\.owners o[\s\S]*o\.owner_key=NEW\.owner_key[\s\S]*o\.generation=NEW\.generation[\s\S]*FOR NO KEY UPDATE OF o/);
  assert.match(sql, /r\.owner_key=o\.owner_key[\s\S]*r\.generation=o\.generation[\s\S]*r\.status='running'/);
  assert.match(sql, /ingestion_kind='inbox_provider'[\s\S]*sent_receipt_id IS NULL/);
  assert.match(sql, /BEFORE UPDATE ON identity\.ipi_email_artifacts/);
  assert.match(require('../server/database/postgres/emailArtifactRepository').createEmailArtifactRepository.toString(), /tgenabled='O'/);
  assert.match(sql, /REVOKE ALL ON identity\.ipi_email_artifacts FROM PUBLIC/);
  assert.match(sql, /GRANT SELECT,INSERT,UPDATE,DELETE ON identity\.ipi_email_artifacts TO dvaia_identity_runtime/);
  assert.doesNotMatch(sql, /^\s*(?:DROP TABLE|TRUNCATE\b)/im);
});
