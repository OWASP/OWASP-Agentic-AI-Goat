'use strict';
// Unmounted draft. Uses a REVIEW transaction under the cross-store persona fence.
const { prepareListingRecovery, prepareListingAdmission, rewriteReceipt, importReceipt, publicationReceipt, declineReceipt, optimizeReceipt, optimizeDenialReceipt, assertListingTransition, hash, fail, UUID } = require('../../services/secureshopListingJournalContract');
const { createHmac } = require('node:crypto');
const {resolveListingTarget,withListingTarget,assertListingTarget,assertListingOperation}=require('../../services/secureshopListingsTargetBinding');
const T = 'secureshop_review.owned_listing_';
function createListingJournalRepository({ pool, personaAuthority, validateImportReceipt, capabilityKey, resolveTarget } = {}) {
  if (!Buffer.isBuffer(capabilityKey) || capabilityKey.length !== 32) throw new TypeError('Private listing journal capability key required');
  const privateKey = Buffer.from(capabilityKey);
  const capability = x => createHmac('sha256', privateKey).update(JSON.stringify([x.request.operationId,x.bindingSha256,x.requestSha256])).digest('hex');
  if (typeof pool?.connect !== 'function' || typeof personaAuthority?.capture !== 'function'
      || (resolveTarget !== undefined && typeof resolveTarget !== 'function')
      || (validateImportReceipt !== undefined && typeof validateImportReceipt !== 'function')) throw new TypeError('Listing journal dependencies required');
  async function tx(x, mutation, work) {
    const b = x.binding, target = await resolveListingTarget(resolveTarget,b), expected = { ...b.scope, personaId: b.persona.id, role: 'merchant', ...b.personaSession };
    const fence = await personaAuthority.capture({ scope: b.scope, personaId: b.persona.id, role: 'merchant', ...b.personaSession });
    if (!fence?.binding || Object.keys(expected).some(k => expected[k] !== fence.binding[k])
        || typeof fence.assertRemoteAdmission !== 'function' || typeof fence.withCrossStoreEffect !== 'function') throw fail('SHOP_AUTH_INVALID');
    await fence.assertRemoteAdmission();
    let commitAttempted = false;
    const readFailure = Symbol(); let readError;
    try {
      const result = await fence.withCrossStoreEffect(async () => withListingTarget(target,async () => {
        const client = await pool.connect(); let damaged = false;
        try {
          await client.query('BEGIN');
          await client.query("SET LOCAL statement_timeout='3000ms'");
          await client.query("SET LOCAL lock_timeout='3000ms'");
          await client.query("SELECT pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||$1::text,0))", [b.scope.platformOwnerId]);
          await client.query("SELECT pg_advisory_xact_lock(hashtextextended('owned-listing:'||$1::text,0))", [x.request.operationId]);
          await assertListingTarget(client,target);
          const value = await work(client,target);
          await assertListingTarget(client,target);
          // The outer cross-store fence holds the agents lease and validates
          // before/after this callback. Re-entering admission here deadlocks
          // against that lease on a second agents connection.
          commitAttempted = true; await client.query('COMMIT');
          return value;
        } catch (error) {
          try { await client.query('ROLLBACK'); } catch { damaged = true; }
          // A read has no separate-store effect to reconcile. Complete the
          // authority fence before exposing its absence/conflict result.
          if (!mutation && !commitAttempted) { readError = error; return readFailure; }
          throw error;
        } finally { client.release(damaged); }
      }));
      await fence.assertRemoteAdmission();
      if (result === readFailure) throw readError;
      return result;
    } catch (error) {
      if (mutation && commitAttempted) throw fail('LISTING_OUTCOME_UNCERTAIN');
      throw error;
    }
  }
  function verify(row, x) {
    if (!row) throw fail('LISTING_NOT_FOUND');
    if (row.redacted_at || row.request_json === null) throw fail('LISTING_RETIRED');
    if (row.binding_json !== x.bindingJson || row.request_json !== x.requestJson
        || row.binding_sha256 !== x.bindingSha256 || row.request_sha256 !== x.requestSha256) throw fail('LISTING_OPERATION_CONFLICT');
    if (hash(row.binding_json) !== row.binding_sha256 || hash(row.request_json) !== row.request_sha256) throw fail('LISTING_INTEGRITY_UNAVAILABLE');
  }
  async function read(client, x, target) {
    const row = (await client.query(`SELECT * FROM ${T}admissions WHERE operation_id=$1`, [x.request.operationId])).rows[0];
    verify(row, x);
    if(target&&row.target_id!==target.targetId)throw fail('LISTING_TARGET_UNAVAILABLE');
    await assertListingOperation(client,target,x.request.operationId,x.bindingSha256);
    const events = (await client.query(`SELECT * FROM ${T}events WHERE operation_id=$1 ORDER BY sequence ASC LIMIT 17`, [x.request.operationId])).rows;
    if (events.length > 16) throw fail('LISTING_INTEGRITY_UNAVAILABLE');
    let current = Object.freeze({ operationId: x.request.operationId, state: 'admitted', sequence: 0, receipt: null });
    const eventIds = new Set();
    for (const event of events) {
      if (event.redacted_at) throw fail('LISTING_RETIRED');
      if (!UUID.test(event.event_id) || eventIds.has(event.event_id) || Number(event.sequence) !== current.sequence + 1) throw fail('LISTING_INTEGRITY_UNAVAILABLE');
      eventIds.add(event.event_id);
      try { assertListingTransition(current.state, event.state, x.request.action); } catch { throw fail('LISTING_INTEGRITY_UNAVAILABLE'); }
      let payload = null;
      if (event.payload_json !== null) {
        if (typeof event.payload_json !== 'string' || hash(event.payload_json) !== event.payload_sha256) throw fail('LISTING_INTEGRITY_UNAVAILABLE');
        try { payload = JSON.parse(event.payload_json); } catch { throw fail('LISTING_INTEGRITY_UNAVAILABLE'); }
      } else if (event.payload_sha256 !== null) throw fail('LISTING_INTEGRITY_UNAVAILABLE');
      if (['running','unknown'].includes(event.state) && payload !== null) throw fail('LISTING_INTEGRITY_UNAVAILABLE');
      if (event.state === 'failed' && (!payload || Object.keys(payload).length !== 1
          || !['INVALID_DECISION','MODEL_UNAVAILABLE','ADMISSION_REJECTED'].includes(payload.code)
          || (x.request.action === 'import' && current.state !== 'admitted'))) throw fail('LISTING_INTEGRITY_UNAVAILABLE');
      if(event.state==='declined')payload=declineReceipt(payload,x,current.receipt);
      if(event.state==='denied')payload=optimizeDenialReceipt(payload,x);
      if (['effect_received', 'completed'].includes(event.state)) {
        if (x.request.action === 'rewrite') payload = rewriteReceipt(payload, x);
        else if (x.request.action === 'optimize') payload = optimizeReceipt(payload,x);
        else if (event.state === 'completed') payload = publicationReceipt(payload,x,current.receipt);
        else payload = importReceipt(payload,x);
        if (event.state === 'completed' && ['rewrite','optimize'].includes(x.request.action) && JSON.stringify(current.receipt) !== JSON.stringify(payload)) throw fail('LISTING_INTEGRITY_UNAVAILABLE');
      }
      current = Object.freeze({ operationId: x.request.operationId, state: event.state, sequence: Number(event.sequence), receipt: payload });
    }
    return current;
  }
  async function recoverOwned(raw,includeAdmission=false) {
      const captured = prepareListingRecovery(raw);
      return tx(captured, false, async (client,target) => {
        const row = (await client.query(`SELECT * FROM ${T}admissions WHERE operation_id=$1`, [captured.request.operationId])).rows[0];
        if (!row) throw fail('LISTING_NOT_FOUND');
        if (row.redacted_at || row.request_json === null) throw fail('LISTING_RETIRED');
        let stored;
        try { stored = prepareListingAdmission({ ...JSON.parse(row.binding_json), request: JSON.parse(row.request_json) }); }
        catch { throw fail('LISTING_INTEGRITY_UNAVAILABLE'); }
        for (const key of ['scope', 'persona', 'personaSession']) {
          if (JSON.stringify(stored.binding[key]) !== JSON.stringify(captured.binding[key])) throw fail('LISTING_NOT_FOUND');
        }
        const operation=await read(client, stored,target);
        return includeAdmission?Object.freeze({...stored.binding,request:stored.request}):operation;
      });
    }
  return Object.freeze({
    async admit(raw) {
      const x = prepareListingAdmission(raw);
      return tx(x, true, async (client,target) => {
        const b = x.binding;
        const scene=target?.scene;
        const inserted = await client.query(scene
          ?`SELECT newly_admitted FROM secureshop_review.admit_owned_listing_scene_operation($1,$2,$3,$4,$5,$6,$7,$8,$9)`
          :`SELECT newly_admitted FROM secureshop_review.admit_owned_listing_operation($1,$2,$3,$4,$5,$6,$7,$8)`,
        [x.request.operationId, b.targetId, x.bindingJson, x.bindingSha256, x.requestJson, x.requestSha256, x.request.action, capability(x),...(scene?[scene.grantId]:[])]);
        return Object.freeze({ ...(await read(client, x,target)), newlyAdmitted: inserted.rows[0]?.newly_admitted === true });
      });
    },
    async get(raw) { const x = prepareListingAdmission(raw); return tx(x, false, (client,target) => read(client, x,target)); },
    recover:raw=>recoverOwned(raw),
    recoverAdmission:raw=>recoverOwned(raw,true),
    async publishImport(raw, {eventId,expectedSequence}={}) {
      const x=prepareListingAdmission(raw);
      if(x.request.action!=='import'||!UUID.test(eventId||'')||!Number.isSafeInteger(expectedSequence)||expectedSequence<1)throw fail('INVALID_ARGUMENT');
      return tx(x,true,async (client,target)=>{
        const current=await read(client,x,target);
        if(current.state==='completed')return current;
        if(current.state!=='effect_received'||current.sequence!==expectedSequence)throw fail('LISTING_STATE_CONFLICT');
        await client.query('SELECT secureshop_review.publish_owned_listing_import($1,$2,$3,$4)',
          [x.request.operationId,eventId,expectedSequence,capability(x)]);
        return read(client,x,target);
      });
    },
    async transition(raw, { eventId, expectedSequence, state, receipt = null } = {}) {
      // Snapshot before any asynchronous authority/provider validation.
      const x = prepareListingAdmission(raw); const copiedReceipt = structuredClone(receipt);
      if (!UUID.test(eventId || '') || !Number.isSafeInteger(expectedSequence) || expectedSequence < 0) throw fail('INVALID_ARGUMENT');
      let payload = copiedReceipt;
      if (['effect_received', 'completed'].includes(state)) {
        if (x.request.action === 'rewrite') payload = rewriteReceipt(copiedReceipt, x);
        else if (x.request.action === 'optimize') payload = optimizeReceipt(copiedReceipt,x);
        else if (state === 'effect_received' && typeof validateImportReceipt === 'function') payload = importReceipt(await validateImportReceipt(copiedReceipt, x),x);
        else throw fail('LISTING_PUBLICATION_UNAVAILABLE');
      } else if(state==='denied'){
        payload=optimizeDenialReceipt(copiedReceipt,x);
      } else if (state === 'declined') {
        // Validate against the stored observation under the transaction below.
        if(!payload||typeof payload!=='object')throw fail('INVALID_ARGUMENT');
      } else if (state === 'failed') {
        // A transport timeout belongs to unknown, never failed. Callers must supply a definite local failure.
        if (!payload || Object.keys(payload).length !== 1 || !['INVALID_DECISION', 'MODEL_UNAVAILABLE', 'ADMISSION_REJECTED'].includes(payload.code)) throw fail('INVALID_ARGUMENT');
      } else if (!['running', 'unknown'].includes(state) || payload !== null) throw fail('INVALID_ARGUMENT');
      const payloadJson = payload === null ? null : JSON.stringify(payload), payloadSha256 = payloadJson === null ? null : hash(payloadJson);
      return tx(x, true, async (client,target) => {
        const current = await read(client, x,target);
        const prior = (await client.query(`SELECT * FROM ${T}events WHERE operation_id=$1 AND event_id=$2`, [x.request.operationId, eventId])).rows[0];
        if (prior) {
          if (Number(prior.sequence) !== expectedSequence + 1 || prior.state !== state || prior.payload_json !== payloadJson || prior.payload_sha256 !== payloadSha256) throw fail('LISTING_OPERATION_CONFLICT');
          return current;
        }
        if(state==='declined')declineReceipt(payload,x,current.receipt);
        if(state==='denied')optimizeDenialReceipt(payload,x);
        if (current.sequence !== expectedSequence) throw fail('LISTING_STATE_CONFLICT');
        assertListingTransition(current.state, state, x.request.action);
        if (state === 'completed' && ['rewrite','optimize'].includes(x.request.action) && JSON.stringify(current.receipt) !== payloadJson) throw fail('LISTING_RECEIPT_MISMATCH');
        if (state === 'failed' && x.request.action === 'import' && current.state !== 'admitted') throw fail('LISTING_STATE_CONFLICT');
        await client.query(`SELECT secureshop_review.append_owned_listing_event($1,$2,$3,$4,$5,$6,$7)`, [x.request.operationId, eventId, expectedSequence + 1, state, payloadJson, payloadSha256, capability(x)]);
        return read(client, x,target);
      });
    },
  });
}
module.exports = { createListingJournalRepository };
