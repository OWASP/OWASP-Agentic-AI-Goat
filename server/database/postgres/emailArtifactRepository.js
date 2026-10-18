'use strict';

const { createHash, randomUUID } = require('node:crypto');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_BODY_BYTES = 32768;
const MAX_MODEL_BYTES = 20000;
// The existing comparison graph uses a 5,000 UTF-16-unit prompt boundary.
// Build the stored model view to that same boundary without splitting a
// surrogate pair, so its persisted digest remains the exact bytes shown to it.
const MAX_MODEL_CODE_UNITS = 5000;

function failure(code, message, statusCode = 500) {
  return Object.assign(new Error(message), { code, statusCode });
}
function unavailable(error) {
  if (['42P01', '42501', '42703', '42883'].includes(error?.code)) {
    return failure('EMAIL_ARTIFACT_STORAGE_NOT_READY', 'Email artifact storage is not ready', 503);
  }
  return error;
}
function exactOwner(ownerId, ownerKey) {
  if (!Number.isSafeInteger(ownerId) || ownerId < 1 || ownerId > 2147483647) {
    throw new TypeError('Valid email artifact owner required');
  }
  const expected = JSON.stringify(['IndirectEmail', String(ownerId)]);
  if (ownerKey !== expected) throw new TypeError('Email artifact owner scope mismatch');
  return { ownerId, ownerKey };
}
function exactGeneration(value) {
  if ((typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'bigint')
      || (typeof value === 'number' && !Number.isSafeInteger(value))
      || !/^(0|[1-9][0-9]*)$/.test(String(value))) throw new TypeError('Valid email artifact generation required');
  const generation = BigInt(value);
  if (generation > 9223372036854775807n) throw new TypeError('Valid email artifact generation required');
  return generation.toString();
}
function text(value, label, maximumBytes, { empty = true } = {}) {
  if (typeof value !== 'string' || value.includes('\0')) throw new TypeError(`Valid ${label} required`);
  const bytes = Buffer.byteLength(value, 'utf8');
  if ((!empty && bytes === 0) || bytes > maximumBytes) throw new TypeError(`Valid ${label} required`);
  return value;
}
function digest(value) { return createHash('sha256').update(value, 'utf8').digest('hex'); }
function modelSlice(value) {
  let output = '', codeUnits = 0, bytes = 0;
  for (const character of value) {
    const size = Buffer.byteLength(character, 'utf8');
    if (codeUnits + character.length > MAX_MODEL_CODE_UNITS || bytes + size > MAX_MODEL_BYTES) break;
    output += character; codeUnits += character.length; bytes += size;
  }
  if (!output) throw new TypeError('Valid email artifact body required');
  return output;
}
function normalizeArtifact(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Valid email artifact required');
  const allowed = ['artifactId', 'body', 'ingestionKind', 'provider', 'providerMessageId', 'recipient', 'sender', 'sentReceiptId', 'subject'];
  if (Object.keys(value).some(key => !allowed.includes(key))) throw new TypeError('Unexpected email artifact field');
  const artifactId = value.artifactId || randomUUID();
  if (typeof artifactId !== 'string' || !UUID.test(artifactId)) throw new TypeError('Valid email artifact id required');
  const ingestionKind = value.ingestionKind;
  const provider = value.provider;
  if (!['inbox_provider', 'manual_entry'].includes(ingestionKind)) throw new TypeError('Valid email artifact ingestion kind required');
  if ((ingestionKind === 'manual_entry' && provider !== 'manual_entry')
      || (ingestionKind === 'inbox_provider' && !['guerrillamail', 'mailpit'].includes(provider))) throw new TypeError('Valid email artifact provider required');
  const providerMessageId = value.providerMessageId == null ? null : text(String(value.providerMessageId), 'provider message id', 256, { empty: false });
  const sentReceiptId = value.sentReceiptId == null ? null : value.sentReceiptId;
  // Provider APIs used by this component do not expose an identity that can be
  // joined safely to the SMTP submission receipt. Keep that relationship
  // unknown instead of accepting a caller-supplied or similarity-based link.
  if (sentReceiptId !== null) throw new TypeError('Sent receipt identity is not established');
  const sender = text(value.sender ?? '', 'email sender', 512);
  const recipient = text(value.recipient, 'email recipient', 512, { empty: false });
  const subject = text(value.subject ?? '', 'email subject', 2048);
  const body = text(value.body, 'email artifact body', MAX_BODY_BYTES, { empty: false });
  if (ingestionKind === 'manual_entry' && (providerMessageId !== null || sentReceiptId !== null || sender !== '')) throw new TypeError('Manual email provenance must remain unknown');
  if (ingestionKind === 'inbox_provider' && providerMessageId === null) throw new TypeError('Provider email identity required');
  const modelBody = modelSlice(body);
  return Object.freeze({ artifactId: artifactId.toLowerCase(), ingestionKind, provider, providerMessageId,
    sentReceiptId, sender, recipient, subject, body, bodyBytes: Buffer.byteLength(body, 'utf8'),
    bodySha256: digest(body), modelBody, modelBodyBytes: Buffer.byteLength(modelBody, 'utf8'),
    modelBodySha256: digest(modelBody), modelBodyTruncated: modelBody !== body });
}
function publicArtifact(row) {
  return Object.freeze({ artifactId: row.artifact_id, ingestionKind: row.ingestion_kind,
    provider: row.provider, providerMessageId: row.provider_message_id, sender: row.sender,
    recipient: row.recipient, subject: row.subject, body: row.body_text,
    bodyBytes: row.body_bytes, bodySha256: row.body_sha256, modelBody: row.model_body_text,
    modelBodyBytes: row.model_body_bytes, modelBodySha256: row.model_body_sha256,
    modelBodyTruncated: row.model_body_truncated, runId: row.run_id,
    generation: String(row.generation), createdAt: row.created_at });
}

function validUuid(value) {
  return typeof value === 'string' && UUID.test(value);
}

function createEmailArtifactRepository(pool) {
  if (!pool || typeof pool.query !== 'function') throw new TypeError('Email artifact database required');
  return Object.freeze({
    async createMany({ ownerId, ownerKey, generation, runId, artifacts }) {
      const owner = exactOwner(ownerId, ownerKey);
      const exact = exactGeneration(generation);
      if (!validUuid(runId) || !Array.isArray(artifacts) || artifacts.length < 1 || artifacts.length > 25) {
        throw new TypeError('Valid email artifact run required');
      }
      const values = artifacts.map(normalizeArtifact);
      const records = values.map(value => ({
        artifact_id:value.artifactId, ingestion_kind:value.ingestionKind, provider:value.provider,
        provider_message_id:value.providerMessageId, sent_receipt_id:value.sentReceiptId,
        sender:value.sender, recipient:value.recipient, subject:value.subject, body:value.body,
        body_bytes:value.bodyBytes, body_sha256:value.bodySha256, model_body:value.modelBody,
        model_body_bytes:value.modelBodyBytes, model_body_sha256:value.modelBodySha256,
        model_body_truncated:value.modelBodyTruncated,
      }));
      try {
        const result = await pool.query(`
          WITH current_owner AS MATERIALIZED (
            SELECT owner_key,generation FROM graph_runtime.owners
            WHERE owner_key=$2 AND generation=$3
            FOR NO KEY UPDATE
          )
          INSERT INTO identity.ipi_email_artifacts(
            artifact_id,owner_id,owner_key,generation,run_id,ingestion_kind,provider,
            provider_message_id,sent_receipt_id,sender,recipient,subject,body_text,
            body_bytes,body_sha256,model_body_text,model_body_bytes,model_body_sha256,model_body_truncated)
          SELECT x.artifact_id,$1,$2,$3,r.run_id,x.ingestion_kind,x.provider,
            x.provider_message_id,x.sent_receipt_id,x.sender,x.recipient,x.subject,x.body,
            x.body_bytes,x.body_sha256,x.model_body,x.model_body_bytes,x.model_body_sha256,x.model_body_truncated
          FROM current_owner o
          JOIN graph_runtime.runs r ON r.owner_key=o.owner_key AND r.generation=o.generation
          CROSS JOIN jsonb_to_recordset($5::jsonb) AS x(
            artifact_id uuid,ingestion_kind text,provider text,provider_message_id text,sent_receipt_id integer,
            sender text,recipient text,subject text,body text,body_bytes integer,body_sha256 text,
            model_body text,model_body_bytes integer,model_body_sha256 text,model_body_truncated boolean)
          WHERE r.run_id=$4 AND r.owner_key=$2 AND r.generation=$3 AND r.status='running'
          RETURNING *`, [owner.ownerId, owner.ownerKey, exact, runId, JSON.stringify(records)]);
        if (result.rowCount !== values.length) throw failure('EMAIL_ARTIFACT_RUN_STALE', 'Email artifact run is no longer current', 409);
        const byId = new Map(result.rows.map(row => [row.artifact_id, publicArtifact(row)]));
        return values.map(value => byId.get(value.artifactId));
      } catch (error) {
        if (error?.code === '55000') throw failure('EMAIL_ARTIFACT_RUN_STALE', 'Email artifact run is no longer current', 409);
        throw unavailable(error);
      }
    },
    async resolveCurrent({ artifactId, ownerId, ownerKey, generation }) {
      exactOwner(ownerId, ownerKey); const exact = exactGeneration(generation);
      if (!validUuid(artifactId)) throw failure('EMAIL_ARTIFACT_UNAVAILABLE', 'Email artifact is unavailable', 409);
      try {
        const row = (await pool.query(`SELECT * FROM identity.ipi_email_artifacts
          WHERE artifact_id=$1 AND owner_id=$2 AND owner_key=$3 AND generation=$4 AND retired_at IS NULL`,
        [artifactId, ownerId, ownerKey, exact])).rows[0];
        if (!row) throw failure('EMAIL_ARTIFACT_UNAVAILABLE', 'Email artifact is unavailable', 409);
        return publicArtifact(row);
      } catch (error) { throw unavailable(error); }
    },
    async retireOwner({ ownerId, ownerKey }) {
      exactOwner(ownerId, ownerKey);
      try {
        return (await pool.query(`UPDATE identity.ipi_email_artifacts SET retired_at=clock_timestamp()
          WHERE owner_id=$1 AND owner_key=$2 AND retired_at IS NULL`, [ownerId, ownerKey])).rowCount;
      } catch (error) { throw unavailable(error); }
    },
    async destroyOwner({ ownerId, ownerKey }) {
      exactOwner(ownerId, ownerKey);
      try { return (await pool.query('DELETE FROM identity.ipi_email_artifacts WHERE owner_id=$1 AND owner_key=$2', [ownerId, ownerKey])).rowCount; }
      catch (error) { throw unavailable(error); }
    },
    async assertReady() {
      try {
        const row = (await pool.query(`SELECT
          to_regclass('identity.ipi_email_artifacts') IS NOT NULL AS table_ready,
          to_regclass('graph_runtime.runs') IS NOT NULL AS run_table_ready,
          CASE WHEN to_regclass('identity.ipi_email_artifacts') IS NULL THEN false
            ELSE has_table_privilege(current_user,to_regclass('identity.ipi_email_artifacts'),'SELECT')
              AND has_table_privilege(current_user,to_regclass('identity.ipi_email_artifacts'),'INSERT')
              AND has_table_privilege(current_user,to_regclass('identity.ipi_email_artifacts'),'UPDATE')
              AND has_table_privilege(current_user,to_regclass('identity.ipi_email_artifacts'),'DELETE') END AS privileges_ready,
          CASE WHEN to_regclass('identity.ipi_email_artifacts') IS NULL THEN false ELSE (
            SELECT array_agg(tgname ORDER BY tgname)=ARRAY['ipi_email_artifact_current_run','ipi_email_artifact_immutable']::name[]
            FROM pg_trigger WHERE tgrelid=to_regclass('identity.ipi_email_artifacts')
              AND tgname IN ('ipi_email_artifact_current_run','ipi_email_artifact_immutable')
              AND tgenabled='O' AND NOT tgisinternal) END AS immutable_ready`)).rows[0];
        if (!row || row.table_ready !== true || row.run_table_ready !== true
            || row.privileges_ready !== true || row.immutable_ready !== true) {
          throw failure('EMAIL_ARTIFACT_STORAGE_NOT_READY', 'Email artifact storage is not ready', 503);
        }
        return true;
      } catch (error) { throw unavailable(error); }
    },
  });
}

module.exports = { createEmailArtifactRepository, normalizeArtifact, modelSlice, MAX_BODY_BYTES, MAX_MODEL_BYTES };
