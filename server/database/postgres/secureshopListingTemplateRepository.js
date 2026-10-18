'use strict';

const { createHmac, createHash, randomUUID } = require('node:crypto');
const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const { executionScope, isSceneMerchant, withSceneLease, assertSceneGrant } = require('../../services/secureshopSceneBinding');
const { normalizeListingTemplateRequest, listingTemplateRequestDigest } = require('../../services/secureshopListingTemplateContract');
const { captureFeatureMode, guardFeatureFence } = require('../../services/secureshopFeatureModeAuthority');
const { normalizeListingTemplateExecution, listingTemplateExecutionDigest,
  validateListingTemplateExecutionResult } = require('../../services/secureshopListingTemplateExecutorContract');

const fail = code => Object.assign(new Error('Owned listing template unavailable'), { code });
const HEX = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const sha = value => createHash('sha256').update(value).digest('hex');
const same = (a,b) => JSON.stringify(a) === JSON.stringify(b);
function exact(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function model(value) {
  return exact(value,['provider','model','mocked','fallback','callId'])
    && typeof value.provider === 'string' && value.provider.trim() !== ''
    && typeof value.model === 'string' && value.model.trim() !== ''
    && !/^(mock|fixture|scripted|fallback|unavailable)$/i.test(value.provider)
    && !/^(mock|fixture|scripted|fallback|unavailable)$/i.test(value.model)
    && value.mocked === false && value.fallback === false
    && typeof value.callId === 'string' && UUID.test(value.callId);
}
function executionRequest(operation) {
  const c = operation.context;
  return normalizeListingTemplateExecution({version:1,operationId:operation.operationId,
    productId:operation.productId,sourceSha256:operation.sourceSha256,
    templateSource:c.templateSource,title:c.title,description:c.description,price:Number(c.price)});
}
function credential(input) {
  const scope = createLaunchScope(input?.scope);
  const persona = input?.persona;
  const session = input?.personaSession;
  if (persona?.role !== 'merchant' || !Number.isSafeInteger(persona.id) || persona.id < 1000000000
      || typeof session?.sessionId !== 'string' || typeof session?.authorityVersion !== 'string'
      || !/^[1-9][0-9]*$/.test(session.authorityVersion)) throw fail('SHOP_AUTH_INVALID');
  return { scope, personaId: persona.id, personaSession: session };
}
function expectFence(fence, x) {
  const expected = { ...x.scope, personaId: x.personaId, role: 'merchant', ...x.personaSession };
  if (!fence?.binding || Object.keys(expected).some(key => fence.binding[key] !== expected[key])
      || typeof fence.assertRemoteAdmission !== 'function' || typeof fence.withCrossStoreEffect !== 'function') {
    throw fail('SHOP_AUTH_INVALID');
  }
  return fence;
}
function capability(key, operationId, targetId, grantId, requestSha256) {
  return createHmac('sha256', key).update(JSON.stringify(['listing-template.v1', operationId,
    targetId, grantId, requestSha256])).digest('hex');
}
function projection(row, events, key) {
  if (!row || !HEX.test(row.request_sha256) || !HEX.test(row.context_sha256)
      || !HEX.test(row.source_sha256) || row.context_hash_actual !== row.context_sha256
      || row.grant_current !== true || (row.redacted_at !== null && row.redacted_at !== undefined)
      || row.capability_sha256 !== sha(capability(key,row.operation_id,row.target_id,row.grant_id,row.request_sha256))) {
    throw fail('LISTING_TEMPLATE_INTEGRITY');
  }
  let state = 'admitted', sequence = 0, receipt = null, priorPayload = null;
  const operation = {operationId:row.operation_id,productId:Number(row.product_id),
    sourceSha256:row.source_sha256,context:row.context_json};
  if (!Number.isSafeInteger(operation.productId) || operation.productId < 1
      || !exact(operation.context,['templateSource','title','description','price'])
      || sha(operation.context.templateSource) !== row.source_sha256) throw fail('LISTING_TEMPLATE_INTEGRITY');
  let execution;
  try { execution = executionRequest(operation); } catch { throw fail('LISTING_TEMPLATE_INTEGRITY'); }
  for (const event of events) {
    if (Number(event.sequence) !== sequence + 1 || event.redacted_at != null
        || !['running','declined','denied','unknown','effect_received','completed'].includes(event.state)
        || (event.payload_json === null ? event.payload_sha256 !== null
          : event.payload_sha256 !== event.payload_hash_actual)) {
      throw fail('LISTING_TEMPLATE_INTEGRITY');
    }
    const p=event.payload_json;
    const transition=(state==='admitted'&&['running','declined','denied'].includes(event.state))
      ||(state==='running'&&['unknown','denied','effect_received'].includes(event.state))
      ||(state==='effect_received'&&event.state==='completed');
    if (!transition) throw fail('LISTING_TEMPLATE_INTEGRITY');
    if (['running','declined','denied'].includes(event.state)) {
      const keys=['operationId','productId','requestSha256','decision','model',
        ...(event.state==='running'?['executorRequestSha256']:event.state==='denied'?['code']:[])];
      if (!exact(p,keys) || p.operationId!==operation.operationId || p.productId!==operation.productId
          || p.requestSha256!==row.request_sha256 || !model(p.model)
          || (event.state==='running'&&(p.decision!=='listing.render_template'
            || p.executorRequestSha256!==listingTemplateExecutionDigest(execution)))
          || (event.state==='denied'&&(row.mode!=='fixed'||p.decision!=='listing.render_template'
            ||p.code!=='LISTING_TEMPLATE_FIXED_DENIED'))
          || (event.state==='declined'&&p.decision!=='declined')) throw fail('LISTING_TEMPLATE_INTEGRITY');
    } else if (event.state==='effect_received'||event.state==='completed') {
      if (!exact(p,['operationId','productId','sourceSha256','contextSha256','requestSha256','model','effect'])
          || p.operationId!==operation.operationId || p.productId!==operation.productId
          || p.sourceSha256!==row.source_sha256 || p.contextSha256!==row.context_sha256
          || p.requestSha256!==row.request_sha256 || !model(p.model)) throw fail('LISTING_TEMPLATE_INTEGRITY');
      try { validateListingTemplateExecutionResult(execution,p.effect); }
      catch { throw fail('LISTING_TEMPLATE_INTEGRITY'); }
      if (event.state==='effect_received'&&(row.mode!=='vuln'||!same(p.model,priorPayload?.model)))
        throw fail('LISTING_TEMPLATE_INTEGRITY');
      if (event.state==='completed'&&!same(p,priorPayload))throw fail('LISTING_TEMPLATE_INTEGRITY');
    } else if(p!==null)throw fail('LISTING_TEMPLATE_INTEGRITY');
    if (p != null) {
      receipt = p;
    }
    state = event.state; sequence++;priorPayload=p;
  }
  return Object.freeze({ operationId: row.operation_id, productId: Number(row.product_id),
    targetId: row.target_id, grantId: row.grant_id, mode: row.mode,
    scope:createLaunchScope({launchId:row.launch_id,scenarioId:row.scenario_id,
      generation:Number(row.generation),platformOwnerId:Number(row.platform_owner_id),
      platformSessionId:Number(row.platform_session_id)}),
    merchantId:Number(row.merchant_id),personaSessionId:row.persona_session_id,
    authorityVersion:String(row.authority_version),
    requestSha256: row.request_sha256, sourceSha256: row.source_sha256,
    contextSha256: row.context_sha256, context: Object.freeze(row.context_json),
    state, sequence, receipt });
}

function createListingTemplateRepository({ pool, catalog, personaAuthority, launches, modeAuthority,
  capabilityKey, makeId = randomUUID } = {}) {
  if (typeof pool?.connect !== 'function' || typeof catalog?.prepareTarget !== 'function'
      || typeof personaAuthority?.capture !== 'function' || typeof launches?.assertCurrent !== 'function'
      || !Buffer.isBuffer(capabilityKey) || capabilityKey.length !== 32 || typeof makeId !== 'function') {
    throw new TypeError('Private listing template repository dependencies required');
  }
  const key = Buffer.from(capabilityKey);
  const authorize = async raw => {
    const x = credential(raw);
    const token = await captureFeatureMode(modeAuthority, x.scope, 'listings');
    const fence = expectFence(guardFeatureFence(await personaAuthority.capture({ scope: x.scope,
      personaId: x.personaId, role: 'merchant', ...x.personaSession }), token), x);
    await launches.assertCurrent(x.scope);
    await fence.assertRemoteAdmission();
    return { ...x, token, fence };
  };
  async function rows(client, x, operationId) {
    const values = [operationId, x.scope.launchId, x.scope.scenarioId, x.scope.generation,
      x.scope.platformOwnerId, x.scope.platformSessionId, x.personaId,
      x.personaSession.sessionId, x.personaSession.authorityVersion];
    const result = await client.query(`SELECT o.*,
      encode(sha256(convert_to(o.context_json::text,'UTF8')),'hex') AS context_hash_actual,
      secureshop_review.assert_scene_execution_grant(o.grant_id,g.scene_id,g.scene_generation,
       o.target_id,o.launch_id,o.scenario_id,o.generation,o.platform_owner_id,o.platform_session_id) AS grant_current
      FROM secureshop_review.owned_listing_template_operations o
      JOIN secureshop_review.scene_execution_grants g ON g.grant_id=o.grant_id
      WHERE o.operation_id=$1 AND o.launch_id=$2 AND o.scenario_id=$3 AND o.generation=$4
       AND o.platform_owner_id=$5 AND o.platform_session_id=$6 AND o.merchant_id=$7
       AND o.persona_session_id=$8 AND o.authority_version=$9`, values);
    if (result.rows.length !== 1) throw fail('LISTING_TEMPLATE_NOT_FOUND');
    const row = result.rows[0];
    if (row.mode !== x.token.snapshot.mode) throw fail('LISTING_MODE_TARGET_CONFLICT');
    const events = (await client.query(`SELECT sequence,state,payload_json,payload_sha256,redacted_at,
      CASE WHEN payload_json IS NULL THEN NULL ELSE
       encode(sha256(convert_to(payload_json::text,'UTF8')),'hex') END AS payload_hash_actual
      FROM secureshop_review.owned_listing_template_events WHERE operation_id=$1 ORDER BY sequence`,
    [operationId])).rows;
    return projection(row, events, key);
  }
  const withClient = async work => {
    const client = await pool.connect();
    try { return await work(client); } finally { client.release(); }
  };
  async function read(raw) {
    const request = normalizeListingTemplateRequest(raw.request);
    const x = await authorize(raw);
    const result = await withClient(async client => rows(client, x, request.operationId));
    if (result.productId !== request.productId
        || result.requestSha256 !== listingTemplateRequestDigest(request)) throw fail('LISTING_TEMPLATE_CONFLICT');
    await x.fence.assertRemoteAdmission();
    return result;
  }
  async function readById(raw) {
    if (typeof raw?.operationId !== 'string' || !UUID.test(raw.operationId)) throw fail('INVALID_ARGUMENT');
    const x = await authorize(raw);
    const result = await withClient(client => rows(client, x, raw.operationId));
    await x.fence.assertRemoteAdmission();
    return result;
  }
  async function admit(raw) {
    const request = normalizeListingTemplateRequest(raw.request);
    const x = await authorize(raw);
    const target = await catalog.prepareTarget({ scope: x.scope, persona: { id: x.personaId, role: 'merchant' },
      personaSession: x.personaSession });
    if (!target?.scene || !isSceneMerchant(target, x.personaId)
        || Object.keys(x.scope).some(k => executionScope(target)[k] !== x.scope[k])) {
      throw fail('LISTING_TEMPLATE_TARGET_UNAVAILABLE');
    }
    const requestSha256 = listingTemplateRequestDigest(request);
    const secret = capability(key, request.operationId, target.targetId, target.scene.grantId, requestSha256);
    let committed = false;
    try {
      return await x.fence.withCrossStoreEffect(async () => withSceneLease(target, () => withClient(async client => {
        await client.query('BEGIN');
        try {
          await client.query("SET LOCAL statement_timeout='3000ms'");
          await client.query("SET LOCAL lock_timeout='3000ms'");
          await assertSceneGrant(client, target);
          const result = await client.query(`SELECT secureshop_review.admit_owned_listing_template(
            $1::uuid,$2::uuid,$3::uuid,$4::integer,$5::integer,$6::uuid,$7::uuid,$8::bigint,
            $9::integer,$10::integer,$11::uuid,$12::bigint,$13::text,$14::text,$15::text) AS admission`,
          [request.operationId, target.targetId, target.scene.grantId, request.productId,
            x.personaId, x.scope.launchId, x.scope.scenarioId, x.scope.generation,
            x.scope.platformOwnerId, x.scope.platformSessionId, x.personaSession.sessionId,
            x.personaSession.authorityVersion, x.token.snapshot.mode, requestSha256, secret]);
          const admission = result.rows[0]?.admission;
          if (!admission || typeof admission.newlyAdmitted !== 'boolean'
              || admission.contextSha256?.length !== 64 || admission.sourceSha256?.length !== 64) {
            throw fail('LISTING_TEMPLATE_INTEGRITY');
          }
          const operation = await rows(client, x, request.operationId);
          await client.query('COMMIT'); committed = true;
          return Object.freeze({ operation, newlyAdmitted: admission.newlyAdmitted });
        } catch (error) { try { await client.query('ROLLBACK'); } catch {} throw error; }
      })));
    } catch (error) {
      if (committed) throw fail('LISTING_TEMPLATE_OUTCOME_UNCERTAIN');
      throw error;
    }
  }
  async function advance(raw, state, payload = null) {
    const request = normalizeListingTemplateRequest(raw.request);
    const x = await authorize(raw);
    const previous = await read(raw);
    const secret = capability(key, request.operationId, previous.targetId, previous.grantId,
      previous.requestSha256);
    let attempted = false;
    try {
      return await x.fence.withCrossStoreEffect(async () => withClient(async client => {
        await client.query('BEGIN');
        try {
          await client.query("SET LOCAL statement_timeout='3000ms'");
          await client.query("SET LOCAL lock_timeout='3000ms'");
          attempted = true;
          await client.query(`SELECT secureshop_review.append_owned_listing_template_event(
            $1::uuid,$2::uuid,$3::integer,$4::text,$5::jsonb,$6::text)`,
          [request.operationId, makeId(), previous.sequence, state,
            payload === null ? null : JSON.stringify(payload), secret]);
          const operation = await rows(client, x, request.operationId);
          await client.query('COMMIT');
          return operation;
        } catch (error) { try { await client.query('ROLLBACK'); } catch {} throw error; }
      }));
    } catch (error) {
      if (attempted) {
        const uncertain = fail('LISTING_TEMPLATE_OUTCOME_UNCERTAIN');
        Object.defineProperty(uncertain, 'cause', { value: error });
        throw uncertain;
      }
      throw error;
    }
  }
  async function withBoundExecution(raw, work) {
    if (typeof work !== 'function') throw new TypeError('Bound template executor callback required');
    const request = normalizeListingTemplateRequest(raw.request);
    const x = await authorize(raw);
    const operation = await read(raw);
    const target = await catalog.prepareTarget({ scope:x.scope,
      persona:{id:x.personaId,role:'merchant'},personaSession:x.personaSession });
    if (!target?.scene || !isSceneMerchant(target,x.personaId)
        || target.targetId!==operation.targetId || target.scene.grantId!==operation.grantId
        || Object.keys(x.scope).some(k=>executionScope(target)[k]!==x.scope[k])
        || operation.productId!==request.productId) throw fail('LISTING_TEMPLATE_TARGET_UNAVAILABLE');
    return x.fence.withCrossStoreEffect(()=>withSceneLease(target,async()=>{
      // The outer effect fence holds the persona authority transaction and
      // checks it before and after this callback. Opening another admission
      // transaction here would wait on its own held advisory locks.
      await launches.assertCurrent(x.scope);
      const result=await work();
      await launches.assertCurrent(x.scope);
      return result;
    }));
  }
  return Object.freeze({ admit, read, readById, advance, withBoundExecution });
}

module.exports = { createListingTemplateRepository };
