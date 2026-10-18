'use strict';
const { isDeepStrictEqual: equal } = require('node:util');
const { canonicalDigest } = require('./mcp/protocolContext');
const { createConversationBinding, createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');
const { captureFeatureMode } = require('./secureshopFeatureModeAuthority');
const { createTurnRequest } = require('./secureshopTurnRequest');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail = () => Object.assign(Error('Saved file summary unavailable'), { code: 'FILE_SUMMARY_UNAVAILABLE' });
function projectFileSummaryTurn({ sessionId, requestId, result, replayed = false }) {
  const meta = result?.taskMetadata?.boundFileSummary;
  let envelope; try { envelope = JSON.parse(meta.originalEnvelope); } catch { throw fail(); }
  if (!UUID.test(sessionId || '') || !UUID.test(requestId || '') || !UUID.test(meta?.operationId || '')
    || !['read','no_tool'].includes(meta.outcome) || result.stopReason !== 'end_turn'
    || typeof result.text !== 'string' || !result.text.isWellFormed() || result.text.includes(String.fromCharCode(0))
    || Buffer.byteLength(result.text) > 16384
    || !envelope?.attachment || typeof envelope.attachment.filename !== 'string'
    || !envelope.attachment.filename || Buffer.byteLength(envelope.attachment.filename) > 255
    || !Number.isSafeInteger(envelope.attachment.byteCount) || envelope.attachment.byteCount < 1
    || envelope.attachment.byteCount > 8192) throw fail();
  return Object.freeze({ sessionId, requestId, operationId: meta.operationId,
    status: meta.outcome === 'read' ? 'completed' : 'no_tool', text: result.text,
    filename: envelope.attachment.filename, byteCount: envelope.attachment.byteCount, replayed });
}
function createV19FileSummarySavedTurn({ launches, journal, personaAuthority, modeAuthority, scenes, sourceReader } = {}) {
  for (const fn of [launches?.assertCurrent, journal?.readFileSummaryRequest, personaAuthority?.capture,
    modeAuthority?.capture, modeAuthority?.assertToken, scenes?.readRetained, sourceReader?.read])
    if (typeof fn !== 'function') throw TypeError('Saved file summary dependencies required');
  return Object.freeze({ async read({ scope, persona, personaSession, sessionId, requestId, signal } = {}) {
    if (!UUID.test(sessionId || '') || !UUID.test(requestId || '') || persona?.role !== 'customer') throw fail();
    const binding = createConversationBinding(scope, persona), currentScope = createLaunchScope(binding);
    const fence = await personaAuthority.capture({ scope: currentScope, personaId: persona.id,
      role: 'customer', ...personaSession });
    const expected = { ...currentScope, personaId: persona.id, role: 'customer', ...personaSession };
    if (!Object.keys(expected).every(key => fence?.binding?.[key] === expected[key])) throw fail();
    const mode = await captureFeatureMode(modeAuthority, currentScope, 'file_summary');
    const target = await scenes.readRetained(binding);
    const check = async () => {
      signal?.throwIfAborted(); await launches.assertCurrent(currentScope); await fence.assertRemoteAdmission();
      await mode.assertCurrent(); const current = await scenes.readRetained(binding);
      if (!target?.scene || !current?.scene || current.targetId !== target.targetId
        || !equal(current.scene, target.scene) || !equal(createLaunchScope(executionScope(current)), currentScope)) throw fail();
      signal?.throwIfAborted();
    };
    const checkAtEffect = async () => {
      signal?.throwIfAborted(); await launches.assertCurrent(currentScope);
      await (mode.assertCurrentAtEffect || mode.assertCurrent).call(mode);
      const current = await scenes.readRetained(binding);
      if (!target?.scene || !current?.scene || current.targetId !== target.targetId
        || !equal(current.scene, target.scene)
        || !equal(createLaunchScope(executionScope(current)), currentScope)) throw fail();
      signal?.throwIfAborted();
    };
    await check();
    const row = await journal.readFileSummaryRequest({ sessionId, requestId, binding, purpose: 'secureshop_file_summary' });
    await check();
    if (!row || row.status !== 'completed') return Object.freeze({ sessionId, requestId,
      status: row?.status === 'uncertain' ? 'uncertain' : 'unconfirmed' });
    const result = row.result_json, meta = result?.taskMetadata?.boundFileSummary;
    let original; try { original = JSON.parse(meta.originalEnvelope); } catch { throw fail(); }
    const ref = { scope: currentScope, persona, personaSession, sessionId, requestId };
    const authority = { ...ref, scene: structuredClone(target.scene), sceneTargetId: target.targetId,
      mode: structuredClone(mode.snapshot) };
    const request = createTurnRequest({ sessionId, requestId, binding, message: meta.originalEnvelope });
    if (original.authoritySha256 !== canonicalDigest(authority) || original.operationId !== meta.operationId
      || request.hash !== row.request_hash || request.version !== row.request_version) throw fail();
    if (meta.outcome === 'read') await sourceReader.read({ scope: binding, persona, personaSession,
      sessionId, requestId, receipt: meta.attachmentReceipt, target, mode: mode.snapshot,
      signal, check, checkAtEffect });
    await check();
    return projectFileSummaryTurn({ sessionId, requestId, result, replayed: true });
  } });
}
module.exports = { createV19FileSummarySavedTurn, projectFileSummaryTurn };
