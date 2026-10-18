'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { createHash } = require('node:crypto');
const { createConversationBinding, createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');
const { capture } = require('../database/postgres/secureshopCustomerChatBindingRepository');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { customerSelection, cards } = require('./secureshopBoundCustomerCommerceTools');
const { isQualifiedSecureShopModelTrace } = require('./secureshopRealModelTrace');
const { canonicalDigest } = require('./mcp/protocolContext');
const { SECURESHOP_CONVERSATION_PURPOSES } = require('./secureshopConversationPurpose');

const PURPOSE = SECURESHOP_CONVERSATION_PURPOSES.customerChat;
const VERSION = 'secureshop-search-echo-original-v1';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const hash = text => createHash('sha256').update(text).digest('hex');
const exact = (v, keys) => v && Object.getPrototypeOf(v) === Object.prototype
  && equal(Reflect.ownKeys(v).sort(), [...keys].sort());
const fail = () => Object.assign(Error('Original search echo unavailable'),
  { code: 'SEARCH_ECHO_ORIGINAL_UNAVAILABLE' });
const need = ok => { if (!ok) throw fail(); };
const parse = text => { try { return JSON.parse(text); } catch { throw fail(); } };
const COLUMNS = Object.freeze({ session_id: 'sessionId', request_id: 'requestId', launch_id: 'launchId',
  scenario_id: 'scenarioId', generation: 'generation', owner_id: 'ownerId', execution_session_id: 'executionSessionId',
  persona_id: 'personaId', persona_session_id: 'personaSessionId', authority_version: 'authorityVersion',
  scene_id: 'sceneId', scene_generation: 'sceneGeneration', grant_id: 'grantId', target_id: 'targetId',
  envelope_sha256: 'envelopeSha256', request_hash: 'requestHash' });
const PROOF_KEYS = ['version','binding','personaSession','scene','execution','source','envelope',
  'boundTurn','turn','traces','run','preparationEffect'];
const TRACE_KEYS = ['id','event_id','session_id','step','actor','kind','agent_ns','tool_name',
  'provider','params_json','result_json','policy_violation'];
const positive = value => typeof value === 'string' && /^[1-9]\d*$/.test(value)
  && BigInt(value) <= 9223372036854775807n;
const generation = value => typeof value === 'string' && /^(0|[1-9]\d*)$/.test(value)
  && BigInt(value) <= 9223372036854775807n;
function modeValid(value, binding) {
  return exact(value, ['version','featureId','policyVersion','mode','generation','modeStamp','scope'])
    && value.version === 1 && value.featureId === 'customer_chat'
    && value.policyVersion === 'owned-catalog-and-cart-read-v1'
    && ['vuln','fixed'].includes(value.mode) && Number.isSafeInteger(value.generation)
    && value.generation >= 0 && SHA.test(value.modeStamp || '')
    && equal(value.scope, createLaunchScope(binding));
}
function expectedBinding(p) {
  const b = p.binding, s = p.scene, source = p.source;
  const expected = { sessionId: source.sessionId, requestId: source.requestId,
    launchId: b.launchId, scenarioId: b.scenarioId, generation: b.generation,
    ownerId: b.platformOwnerId, executionSessionId: b.platformSessionId, personaId: b.shopUserId,
    personaSessionId: p.personaSession.sessionId, authorityVersion: p.personaSession.authorityVersion,
    sceneId: s.sceneId, sceneGeneration: s.sceneGeneration, grantId: s.grantId, targetId: s.targetId };
  expected.envelopeSha256 = hash(JSON.stringify(['customer-chat-v1', expected, p.envelope]));
  expected.requestHash = createTurnRequest({ ...source, binding: b, message: p.envelope }).hash;
  return expected;
}

// This checks the immutable proof again for packet reconstruction. Current
// authority is separately checked by the reader/service at every async boundary.
function validateSearchEchoOriginalProof(p, qualifyModel) {
  try {
    need(exact(p, PROOF_KEYS) && p.version === VERSION && typeof qualifyModel === 'function'
      && p.binding?.role === 'customer' && equal(p.binding, createConversationBinding(p.binding,
        { id: p.binding.shopUserId, role: 'customer' }))
      && exact(p.personaSession, ['sessionId','authorityVersion'])
      && UUID.test(p.personaSession.sessionId || '') && positive(p.personaSession.authorityVersion)
      && exact(p.scene, ['sceneId','sceneGeneration','grantId','targetId'])
      && [p.scene.sceneId,p.scene.grantId,p.scene.targetId].every(v => UUID.test(v || ''))
      && Number.isSafeInteger(p.scene.sceneGeneration) && p.scene.sceneGeneration >= 1
      && modeValid(p.execution, p.binding) && exact(p.source, ['sessionId','requestId','step'])
      && UUID.test(p.source.sessionId || '') && UUID.test(p.source.requestId || '')
      && Number.isSafeInteger(p.source.step) && p.source.step >= 1 && p.source.step <= 4
      && typeof p.envelope === 'string' && p.envelope.isWellFormed()
      && Buffer.byteLength(p.envelope) <= 16384);
    const envelope = parse(p.envelope), hasSelection = Object.hasOwn(envelope, 'selection');
    need(exact(envelope, ['version','sceneId','sceneGeneration','targetId','requestId','message',
      ...(hasSelection ? ['selection'] : [])]) && envelope.version === 1
      && envelope.sceneId === p.scene.sceneId && envelope.sceneGeneration === p.scene.sceneGeneration
      && envelope.targetId === p.scene.targetId && envelope.requestId === p.source.requestId
      && typeof envelope.message === 'string' && envelope.message.isWellFormed()
      && !!envelope.message.trim() && !envelope.message.includes('\0') && Buffer.byteLength(envelope.message) <= 8192);
    if (hasSelection) {
      const selection = envelope.selection;
      need(['product','cart_item','order','address','payment_method'].includes(selection?.kind));
      const { kind, ...input } = selection;
      need(equal(input, customerSelection(input))
        && (!input.intent || kind === 'product' && ['details','cart_add'].includes(input.intent)
          || kind === 'cart_item' && ['cart_update','cart_remove'].includes(input.intent)
          || kind === 'order' && input.intent === 'order_details'
          || kind === 'address' && ['address_checkout','address_edit'].includes(input.intent)));
    }
    const expected = expectedBinding(p), turn = p.turn, result = turn?.result_json;
    need(exact(p.boundTurn, Object.keys(COLUMNS))
      && Object.entries(COLUMNS).every(([db, js]) => String(p.boundTurn[db]) === String(expected[js]))
      && exact(turn, ['session_id','request_id','request_version','request_hash','status','result_json'])
      && turn.session_id === p.source.sessionId && turn.request_id === p.source.requestId
      && turn.request_version === 1 && turn.status === 'completed' && turn.request_hash === expected.requestHash
      && result?.stopReason === 'end_turn' && Array.isArray(result.hops)
      && Number.isSafeInteger(result.steps) && result.steps >= 1 && result.steps <= 4
      && equal(result.modeCapability, { version: 1, featureId: 'customer_chat',
        policyVersion: p.execution.policyVersion, effectiveMode: p.execution.mode,
        scope: { kind: 'launch_feature', id: 'customer_chat' } }));
    const meta = result.taskMetadata?.customerChat, origin = result.taskMetadata?.searchEcho;
    need(meta?.version === 1 && meta.sceneId === p.scene.sceneId
      && meta.sceneGeneration === p.scene.sceneGeneration && meta.targetId === p.scene.targetId
      && meta.envelopeSha256 === expected.envelopeSha256
      && exact(origin, ['version','runId','execution','traceEventIds']) && origin.version === 1
      && UUID.test(origin.runId || '') && equal(origin.execution, p.execution)
      && equal(meta.traceEventIds, origin.traceEventIds));
    const ids = origin.traceEventIds, rows = p.traces;
    need(Array.isArray(ids) && ids.length >= 4 && ids.length <= 4096
      && ids.every(id => UUID.test(id || '')) && new Set(ids).size === ids.length
      && Array.isArray(rows) && rows.length === ids.length && equal(rows.map(r => r.event_id), ids)
      && rows.every((r, i) => exact(r, TRACE_KEYS) && r.session_id === p.source.sessionId && positive(String(r.id))
        && (!i || BigInt(r.id) > BigInt(rows[i-1].id))));
    const decisions = rows.filter(r => r.kind === 'model_decision' && r.actor === 'supervisor'
      && r.step === p.source.step && parse(r.params_json || 'null')?.decision === 'tool_use');
    need(decisions.length === 1 && isQualifiedSecureShopModelTrace(decisions[0], qualifyModel));
    const decision = decisions[0], calls = parse(decision.params_json).toolCalls;
    // The supported graph executes only one local call per step.
    need(Array.isArray(calls) && calls.length === 1 && exact(calls[0], ['id','name','args'])
      && calls[0].name === 'catalog.search' && typeof calls[0].id === 'string'
      && !!calls[0].id && Buffer.byteLength(calls[0].id) <= 128 && exact(calls[0].args, ['search']));
    const query = calls[0].args.search, echoHtml = `<p>Results for: <b>${query}</b></p>`;
    need(typeof query === 'string' && query.isWellFormed() && !!query.trim()
      && !query.includes('\0') && Buffer.byteLength(query) <= 128 && Buffer.byteLength(echoHtml) <= 256);
    const callRows = rows.filter(r => r.kind === 'local_tool_call' && r.actor === 'supervisor→task'
      && r.step === p.source.step && r.agent_ns === 'catalog' && r.tool_name === 'search');
    const resultRows = rows.filter(r => r.kind === 'local_tool_result' && r.actor === 'task→supervisor'
      && r.step === p.source.step && r.agent_ns === 'catalog' && r.tool_name === 'search');
    need(callRows.length === 1 && resultRows.length === 1
      && callRows[0].policy_violation === null && resultRows[0].policy_violation === null
      && equal(parse(callRows[0].params_json), calls[0].args)
      && BigInt(callRows[0].id) > BigInt(decision.id) && BigInt(resultRows[0].id) > BigInt(callRows[0].id));
    const observation = parse(resultRows[0].result_json);
    need(exact(observation, ['content']) && Array.isArray(observation.content) && observation.content.length === 1
      && exact(observation.content[0], ['type','text']) && observation.content[0].type === 'text');
    const value = parse(observation.content[0].text);
    need(exact(value, ['total','products','cards','echo_html']) && Number.isSafeInteger(value.total)
      && value.total >= 0 && Array.isArray(value.products) && value.products.length <= 12
      && equal(value.cards, cards(value.cards)) && value.echo_html === echoHtml);
    const hops = result.hops.filter(h => h.tool === 'catalog.search' && h.step === p.source.step);
    need(hops.length === 1 && hops[0].error === null && hops[0].policyViolation === null
      && equal(hops[0].params, calls[0].args) && equal(hops[0].result, observation));
    const terminal = rows.at(-1), terminalMeta = parse(terminal.result_json || 'null');
    need(rows.filter(r => r.kind === 'terminal').length === 1 && terminal.kind === 'terminal'
      && terminal.actor === 'supervisor' && isQualifiedSecureShopModelTrace(terminal, qualifyModel)
      && BigInt(terminal.id) > BigInt(resultRows[0].id) && terminal.step >= p.source.step
      && terminalMeta.stopReason === 'end_turn' && terminalMeta.steps === result.steps
      && terminalMeta.hops === result.hops.length && terminal.provider === decision.provider
      && terminalMeta.model === parse(decision.result_json).model);
    const owner = JSON.stringify(['SecureShopBoundConversation', p.source.sessionId]);
    const effectKey = `${p.source.requestId}:${JSON.stringify([p.source.step,calls[0].id,'catalog.search'])}`;
    need(exact(p.run, ['run_id','owner_key','generation','status']) && p.run.run_id === origin.runId
      && p.run.owner_key === owner && generation(String(p.run.generation)) && p.run.status === 'completed'
      && exact(p.preparationEffect, ['run_id','owner_key','generation','effect_key','status'])
      && p.preparationEffect.run_id === p.run.run_id && p.preparationEffect.owner_key === owner
      && String(p.preparationEffect.generation) === String(p.run.generation)
      && p.preparationEffect.effect_key === effectKey && p.preparationEffect.status === 'completed');
    need(Buffer.byteLength(JSON.stringify(p)) <= 20000);
    return Object.freeze({ source: Object.freeze({ ...p.source }), echoHtml,
      sourceSha256: hash(echoHtml), sourceDigest: canonicalDigest(p), message: envelope.message,
      selected: Object.freeze({ step: p.source.step, callId: calls[0].id, query, echoHtml,
        decisionEventId: decision.event_id, callEventId: callRows[0].event_id,
        resultEventId: resultRows[0].event_id, terminalEventId: terminal.event_id }),
      proof: Object.freeze(structuredClone(p)) });
  } catch { throw fail(); }
}

function createSearchEchoOriginalReader({ bindingRepository, journal, conversations, identityPool, qualifyModel } = {}) {
  for (const fn of [bindingRepository?.read, journal?.readBoundRequest, conversations?.getBoundSession,
    conversations?.getMessages, conversations?.getTraceEvents, identityPool?.query, qualifyModel])
    if (typeof fn !== 'function') throw TypeError('Search echo original reader dependencies required');
  return async function readOriginal({ binding, scope = binding, persona = binding && { id: binding.shopUserId, role: binding.role },
    personaSession, target, execution, modeExecution = execution, sessionId, requestId, step, check, signal } = {}) {
    try {
      const b = createConversationBinding(scope, persona), credential = {
        sessionId: personaSession?.sessionId?.toLowerCase(), authorityVersion: personaSession?.authorityVersion };
      need(b.role === 'customer' && typeof check === 'function' && UUID.test(sessionId || '')
        && UUID.test(requestId || '') && Number.isSafeInteger(step) && step >= 1 && step <= 4
        && equal(executionScope(target), createLaunchScope(b)) && modeValid(modeExecution, b));
      const checked = async work => { signal?.throwIfAborted(); await check();
        const result = await work(); signal?.throwIfAborted(); await check(); return result; };
      const session = await checked(() => conversations.getBoundSession(sessionId));
      need(session?.id === sessionId && session.state === 'active' && session.purpose === PURPOSE && equal(session.binding, b));
      const bound = await checked(() => bindingRepository.read({ sessionId, requestId, scope: b, persona }));
      const turn = await checked(() => journal.readBoundRequest({ sessionId, requestId, binding: b, purpose: PURPOSE }));
      const messages = await checked(() => conversations.getMessages(sessionId, b, PURPOSE));
      need(bound && turn && Array.isArray(messages));
      need(turn.request_id === undefined || turn.request_id === requestId);
      const originals = messages.filter(row => row?.role === 'user' && typeof row.content === 'string'
        && (() => { try { return parse(row.content).requestId === requestId; } catch { return false; } })());
      need(originals.length === 1);
      need(equal(originals[0].modeCapability, turn.result_json?.modeCapability));
      const envelope = originals[0].content;
      const captured = capture({ sessionId, requestId, scope: b, persona,
        personaSession: credential, target, message: envelope });
      const ids = turn.result_json?.taskMetadata?.searchEcho?.traceEventIds;
      need(Array.isArray(ids) && ids.length >= 4 && ids.length <= 4096 && ids.every(id => UUID.test(id || '')));
      const rawTraces = await checked(() => conversations.getTraceEvents(sessionId, b, ids, PURPOSE));
      need(Array.isArray(rawTraces));
      const traces = rawTraces.map(row => Object.fromEntries(TRACE_KEYS.map(key =>
        [key, key === 'id' ? String(row[key]) : row[key] ?? null])));
      const source = { sessionId, requestId, step };
      const scene = { sceneId: target.scene.sceneId, sceneGeneration: target.scene.sceneGeneration,
        grantId: target.scene.grantId, targetId: target.targetId };
      const selected = traces?.filter(r => r.kind === 'model_decision' && r.step === step
        && parse(r.params_json || 'null')?.decision === 'tool_use');
      need(selected?.length === 1);
      const callId = parse(selected[0].params_json).toolCalls?.[0]?.id;
      const runId = turn.result_json.taskMetadata.searchEcho.runId;
      need(UUID.test(runId || ''));
      const owner = JSON.stringify(['SecureShopBoundConversation', sessionId]);
      const runs = await checked(() => identityPool.query(`SELECT r.run_id,r.owner_key,r.generation::text AS generation,r.status
        FROM graph_runtime.runs r JOIN graph_runtime.owners o ON o.owner_key=r.owner_key AND o.generation=r.generation
        WHERE r.run_id=$1 AND r.owner_key=$2 AND r.status='completed'`, [runId, owner]));
      need(runs.rows.length === 1);
      const key = `${requestId}:${JSON.stringify([step,callId,'catalog.search'])}`;
      const effects = await checked(() => identityPool.query(`SELECT run_id,owner_key,generation::text AS generation,effect_key,status
        FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 AND generation=$3 AND effect_key=$4 AND status='completed'`,
      [runId,owner,runs.rows[0].generation,key]));
      need(effects.rows.length === 1);
      const p = { version: VERSION, binding: b, personaSession: credential, scene, execution: modeExecution, source, envelope,
        boundTurn: Object.fromEntries(Object.keys(COLUMNS).map(k => [k, bound[k]])),
        turn: { session_id: turn.session_id, request_id: requestId, request_version: turn.request_version,
          request_hash: turn.request_hash, status: turn.status, result_json: turn.result_json },
        traces, run: runs.rows[0], preparationEffect: effects.rows[0] };
      need(Object.entries(COLUMNS).every(([db, js]) => String(bound[db]) === String(captured[js])));
      return validateSearchEchoOriginalProof(p, qualifyModel);
    } catch (error) { if (signal?.aborted) signal.throwIfAborted(); throw error; }
  };
}

module.exports = { VERSION, PURPOSE, createSearchEchoOriginalReader, validateSearchEchoOriginalProof, modeValid };
