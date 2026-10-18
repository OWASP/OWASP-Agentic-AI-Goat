'use strict';

const { isDeepStrictEqual: equal } = require('node:util');
const { createHash } = require('node:crypto');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { createConversationBinding, createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');
const { isQualifiedSecureShopModelTrace } = require('./secureshopRealModelTrace');
const { canonicalDigest } = require('./mcp/protocolContext');
const fail = () => Object.assign(Error('Product summary source unavailable'), { code: 'PRODUCT_SUMMARY_SOURCE_INVALID' });
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && equal(Reflect.ownKeys(value).sort(), [...keys].sort());

// Resolve the original successful MCP observation, never mutable catalog data.
// This establishes byte custody only; instruction adoption remains a Judge decision.
function resolveProductSummaryObservation(metadata, result) {
  if (!exact(metadata, ['version','operation','productId','provider','model','observationHop'])
      || metadata.version !== 2 || metadata.operation !== 'summary'
      || !Number.isSafeInteger(metadata.productId) || metadata.productId < 1
      || !exact(metadata.observationHop, ['step','observationSha256'])
      || !Number.isSafeInteger(metadata.observationHop.step) || metadata.observationHop.step < 1
      || metadata.observationHop.step > 4 || !/^[a-f0-9]{64}$/.test(metadata.observationHop.observationSha256 || '')
      || !Array.isArray(result?.hops)) throw fail();
  const hops = result.hops.filter(h => h.tool === 'summarizer.summarize_product');
  if (hops.length !== 1 || hops[0].step !== metadata.observationHop.step || hops[0].error !== null
      || hops[0].policyViolation !== null || !exact(hops[0].params, ['product_id'])
      || hops[0].params.product_id !== metadata.productId) throw fail();
  const mcp = hops[0].result;
  if (!exact(mcp, ['content']) || !Array.isArray(mcp.content) || mcp.content.length !== 1
      || !exact(mcp.content[0], ['type','text']) || mcp.content[0].type !== 'text'
      || typeof mcp.content[0].text !== 'string'
      || canonicalDigest(mcp) !== metadata.observationHop.observationSha256) throw fail();
  let value;
  try { value = JSON.parse(mcp.content[0].text); } catch { throw fail(); }
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || value.product_id !== metadata.productId) throw fail();
  return value;
}

const VERSION = 'secureshop-product-summary-source-v1';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const need = value => { if (!value) throw fail(); };
const sha = value => createHash('sha256').update(value,'utf8').digest('hex');
const text = (value,max) => typeof value === 'string' && !!value && value.isWellFormed() && !value.includes('\0') && Buffer.byteLength(value) <= max;
const decimal = (value,zero=false) => typeof value === 'string' && (zero ? /^(0|[1-9]\d*)$/ : /^[1-9]\d*$/).test(value) && BigInt(value)<=9223372036854775807n;
const parse = value => { try { return JSON.parse(value); } catch { throw fail(); } };
function original(side, tool, productId, qualifyModel) {
  const o = side.original;
  need(exact(o, ['binding','personaSession','sessionId','requestId','message','requestVersion','requestHash',
    'status','traceEventIds','traces','result','run','effect'])
    && equal(o.binding, side.binding) && equal(o.personaSession, side.personaSession)
    && UUID.test(o.sessionId || '') && UUID.test(o.requestId || '') && o.requestVersion === 1
    && o.status === 'completed' && text(o.message, 65536)
    && o.requestHash === createTurnRequest({ ...o, binding: side.binding, version: o.requestVersion }).hash);
  const rows = o.traces, ids = o.traceEventIds, result = o.result;
  need(Array.isArray(rows) && rows.length >= 4 && rows.length <= 4096 && Array.isArray(ids)
    && equal(rows.map(r => r.event_id), ids) && new Set(ids).size === ids.length
    && ids.every(id => UUID.test(id || '')) && rows.every((r, i) => r.session_id === o.sessionId
      && decimal(String(r.id)) && (!i || BigInt(r.id) > BigInt(rows[i-1].id)))
    && result?.stopReason === 'end_turn' && text(result.text, 16384)
    && Number.isSafeInteger(result.steps) && result.steps >= 1 && result.steps <= 4 && Array.isArray(result.hops)
    && Buffer.byteLength(JSON.stringify(result)) <= 262144);
  const hops = result.hops.filter(h => h.tool === tool);
  need(hops.length === 1 && hops[0].error === null && hops[0].policyViolation === null
    && exact(hops[0].params, ['product_id']) && hops[0].params.product_id === productId);
  const hop = hops[0], [ns, name] = tool.split('.');
  const decisions = rows.filter(r => r.kind === 'model_decision' && r.actor === 'supervisor'
    && r.step === hop.step && parse(r.params_json || 'null')?.decision === 'tool_use');
  const calls = rows.filter(r => r.kind === 'local_tool_call' && r.actor === 'supervisor→task'
    && r.step === hop.step && r.agent_ns === ns && r.tool_name === name);
  const results = rows.filter(r => r.kind === 'local_tool_result' && r.actor === 'task→supervisor'
    && r.step === hop.step && r.agent_ns === ns && r.tool_name === name);
  need(decisions.length === 1 && calls.length === 1 && results.length === 1
    && isQualifiedSecureShopModelTrace(decisions[0], qualifyModel));
  const selected = parse(decisions[0].params_json).toolCalls;
  need(Array.isArray(selected) && selected.length === 1 && exact(selected[0], ['id','name','args'])
    && text(selected[0].id, 128) && selected[0].name === tool && equal(selected[0].args, hop.params)
    && calls[0].policy_violation === null && results[0].policy_violation === null
    && equal(parse(calls[0].params_json), hop.params) && equal(parse(results[0].result_json), hop.result)
    && BigInt(decisions[0].id) < BigInt(calls[0].id) && BigInt(calls[0].id) < BigInt(results[0].id));
  const terminal = rows.at(-1), terminalMeta = parse(terminal.result_json || 'null');
  const finals = rows.filter(r => r.kind === 'model_decision' && parse(r.result_json || 'null')?.decision === 'final');
  need(finals.length === 1 && isQualifiedSecureShopModelTrace(finals[0], qualifyModel)
    && parse(finals[0].result_json).text === result.text && BigInt(finals[0].id) > BigInt(results[0].id)
    && BigInt(finals[0].id) < BigInt(terminal.id) && rows.filter(r => r.kind === 'terminal').length === 1
    && terminal.kind === 'terminal' && terminal.actor === 'supervisor'
    && isQualifiedSecureShopModelTrace(terminal, qualifyModel) && terminalMeta.stopReason === 'end_turn'
    && terminalMeta.steps === result.steps && terminalMeta.hops === result.hops.length
    && [finals[0], terminal].every(r => r.provider === decisions[0].provider
      && parse(r.result_json).model === parse(decisions[0].result_json).model));
  const run = o.run, effect = o.effect, ownerKey = JSON.stringify(['SecureShopBoundConversation', o.sessionId]);
  need(exact(run, ['run_id','owner_key','generation','status']) && UUID.test(run.run_id || '')
    && run.owner_key === ownerKey && decimal(run.generation, true) && run.status === 'completed'
    && exact(effect, ['run_id','owner_key','generation','effect_key','status'])
    && effect.run_id === run.run_id && effect.owner_key === ownerKey && effect.generation === run.generation
    && effect.status === 'completed'
    && effect.effect_key === `${o.requestId}:${JSON.stringify([hop.step,selected[0].id,tool])}`);
  const mcp = hop.result;
  need(exact(mcp, ['content']) && Array.isArray(mcp.content) && mcp.content.length === 1
    && exact(mcp.content[0], ['type','text']) && mcp.content[0].type === 'text');
  return { value: parse(mcp.content[0].text), mcp, reference: { sessionId: o.sessionId, requestId: o.requestId,
    requestHash: o.requestHash, runId: run.run_id, step: hop.step, callId: selected[0].id,
    traceEventIds: [...ids], chainDigest:canonicalDigest({traces:rows,result,run,effect}), observationSha256: sha(JSON.stringify(mcp)), responseSha256: sha(result.text) } };
}


function validateProductSummarySourceContract({target,origin,original:proof,qualifyModel} = {}) {
  need(typeof qualifyModel==='function' && target?.scene
    && exact(origin,['version','binding','personaSession','source','runId','traceEventIds','execution','productId','target'])
    && origin.version===1 && equal(origin.target,JSON.parse(JSON.stringify(target)))
    && equal(createLaunchScope(origin.binding),executionScope(target))
    && origin.binding.role==='customer' && equal(origin.binding,createConversationBinding(origin.binding,{id:origin.binding.shopUserId,role:'customer'}))
    && exact(origin.personaSession,['sessionId','authorityVersion']) && UUID.test(origin.personaSession.sessionId||'') && decimal(origin.personaSession.authorityVersion)
    && exact(origin.source,['sessionId','requestId']) && UUID.test(origin.source.sessionId||'') && UUID.test(origin.source.requestId||'')
    && Number.isSafeInteger(origin.productId) && origin.productId>0 && origin.productId<=2147483647
    && origin.execution?.featureId==='product_assist' && ['vuln','fixed'].includes(origin.execution.mode)
    && equal(origin.execution.scope,createLaunchScope(origin.binding))
    && proof?.sessionId===origin.source.sessionId && proof.requestId===origin.source.requestId
    && proof.run?.run_id===origin.runId && equal(proof.traceEventIds,origin.traceEventIds)
    && proof.message===`Summarize product ${origin.productId}.`);
  const captured=original({binding:origin.binding,personaSession:origin.personaSession,original:proof},
    'summarizer.summarize_product',origin.productId,qualifyModel);
  const observed=resolveProductSummaryObservation(proof.result.taskMetadata?.productAssist,proof.result);
  need(equal(observed,captured.value) && equal(proof.result.taskMetadata?.productSummaryOrigin,origin)
    && typeof observed.name==='string' && ['description','description_html'].every(key=>observed[key]===null||typeof observed[key]==='string'));
  const lineage={version:VERSION,productId:origin.productId,
    scene:{targetId:target.targetId,sceneId:target.scene.sceneId,sceneGeneration:target.scene.sceneGeneration},
    consumer:{binding:origin.binding,personaSession:origin.personaSession,execution:origin.execution,grantId:target.scene.grantId,original:captured.reference}};
  return {sourceDigest:canonicalDigest(lineage),lineage,semantic:{version:1,task:{kind:'server_original_request',text:proof.message},
    response:{text:proof.result.text,sha256:captured.reference.responseSha256},
    observation:{mcp:captured.mcp,sha256:captured.reference.observationSha256}}};
}
module.exports = { VERSION, resolveProductSummaryObservation, validateProductSummarySourceContract };

