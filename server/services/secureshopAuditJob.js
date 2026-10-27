'use strict';
const { createConversationBinding } = require('./secureshopConversationBinding');
const { spoolAuditObservation } = require('./secureshopAuditObservationSpool');
const { runSecureShopAuditWorker } = require('./secureshopAuditWorkerHost');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const {fixedAuditRows,assertFixedAuditCount,FIXED_AUDIT_MAX_BYTES}=require('./secureshopAuditFixedProjection');
const NODE = 'audit-summary-job';

// Internal operation for an already admitted parent turn. The caller must use
// requestId as its coordinator idempotencyKey and retain the conversation lease.
// Creating this closure has no effects. It is not an HTTP or grading endpoint.
function createSecureShopAuditJob({ snapshot, repository, reader, consumeEvidence, root, baseUrl, model, mode='vuln',
  spoolObservation = spoolAuditObservation, runWorker = runSecureShopAuditWorker, admitTool, capturePromptPolicy,
  sceneSource, sceneBinding, checkScene, taskRequestVersion = 1 } = {}) {
  if ([snapshot?.rows,repository?.publish,reader?.open,consumeEvidence,spoolObservation,runWorker].some(fn => typeof fn !== 'function')
      || typeof root !== 'string' || typeof baseUrl !== 'string' || typeof model !== 'string') {
    throw new TypeError('Owned audit job dependencies required');
  }
  if (![1, 2].includes(taskRequestVersion)) throw new TypeError('Invalid audit task request version');
  if(!['vuln','fixed'].includes(mode))throw new TypeError('Invalid audit mode');
  if (admitTool !== undefined && typeof admitTool !== 'function') throw new TypeError('Invalid audit policy admission');
  if(capturePromptPolicy!==undefined&&typeof capturePromptPolicy!=='function')throw new TypeError('Invalid audit prompt policy capture');
  if (sceneSource !== undefined && (typeof sceneSource?.rows !== 'function' || !sceneBinding?.scene
      || typeof checkScene !== 'function')) throw new TypeError('Retained scene audit source required');
  return async function execute({ scope, persona, requestId, requestedCount, boundary, assessment, includeChatEvidence = false, workerBudget } = {}) {
    const binding = createConversationBinding(scope,persona);
    const identity = boundary?.identity;
    if (binding.role !== 'admin' || !UUID.test(requestId) || !UUID.test(identity?.runId)
        || typeof identity.ownerKey !== 'string' || !identity.ownerKey
        || !/^(0|[1-9][0-9]*)$/.test(String(identity.durableGeneration))
        || !Number.isSafeInteger(requestedCount) || requestedCount < 1
        || typeof boundary.check !== 'function' || typeof boundary.effectWithReceipt !== 'function') {
      throw new TypeError('Admitted audit parent run required');
    }
    if(mode==='fixed')assertFixedAuditCount(requestedCount);
    if(taskRequestVersion===2&&typeof workerBudget!=='function')throw new TypeError('Unbounded audit worker budget required');
    requestId = requestId.toLowerCase();
    const execution = Object.freeze({ runId:identity.runId,ownerKey:identity.ownerKey,
      durableGeneration:String(identity.durableGeneration) });
    const trustedPersona = Object.freeze({ id:binding.shopUserId,role:binding.role });
    const effectKey = `${requestId}:${NODE}`;
    const check = async () => { boundary.signal?.throwIfAborted(); await boundary.check(); boundary.signal?.throwIfAborted(); };
    const checkPublication = async () => { await check(); if (checkScene) await checkScene(); await check(); };
    await checkPublication();
    const completed = await boundary.effectWithReceipt(NODE,async () => {
      await check();
      let promptPolicySnapshot;
      if(capturePromptPolicy){
        promptPolicySnapshot=require('./secureshopPromptPolicySnapshot').validatePolicySnapshot(await capturePromptPolicy(execution));
        if(promptPolicySnapshot.role!=='admin')throw new TypeError('Audit administrator policy snapshot required');
        await check();
      }
      await checkPublication();
      const ordinary=snapshot.rows({ scope:binding,requestedCount,checkCurrent:check,signal:boundary.signal });
      const rawRows=sceneSource ? require('../database/postgres/secureshopSceneProductAuditSource').mergeAuditRows({
        ordinary,scene:sceneSource.rows({scope:binding,sceneBinding,requestedCount,checkCurrent:check,signal:boundary.signal}),
        requestedCount,checkCurrent:check,signal:boundary.signal}) : ordinary;
      const spool = await spoolObservation({ root,scope:binding,runId:execution.runId,requestedCount,
        checkCurrent:check,signal:boundary.signal,
        ...(mode==='fixed'?{maxBytes:FIXED_AUDIT_MAX_BYTES}:{}),
        rows:mode==='fixed'?fixedAuditRows(rawRows,check):rawRows });
      try {
        // Both source iterators have closed before reacquiring the scene lease.
        await checkPublication();
        const timeoutMs=taskRequestVersion===2?workerBudget():undefined;
        if(taskRequestVersion===2&&(!Number.isSafeInteger(timeoutMs)||timeoutMs<20000||timeoutMs>190000))
          throw new TypeError('Invalid unbounded audit worker budget');
        const result = await runWorker({ spool,baseUrl,model,persona:trustedPersona,
          checkCurrent:checkPublication,signal:boundary.signal,taskRequestVersion,
          ...(timeoutMs===undefined?{}:{timeoutMs}),
          ...(promptPolicySnapshot?{promptPolicySnapshot}:{}),...(admitTool?{admitTool}: {}) });
        await checkPublication();
        const published = await repository.publish({ scope:binding,persona:trustedPersona,requestId,
          execution,effectKey,spool,result,signal:boundary.signal });
        await checkPublication();
        if (published?.runId !== execution.runId || published.requestId !== requestId
            || published.published !== true || published.objectiveCredit !== false) {
          throw new Error('Audit publication identity mismatch');
        }
        return published;
      } finally {
        // A cleanup failure keeps the outer effect uncertain; do not silently
        // leave sensitive teaching source files while reporting job success.
        await spool.dispose();
      }
    });
    await checkPublication();
    const receipt = completed?.receipt;
    if (receipt?.status !== 'completed' || receipt.runId !== execution.runId
        || receipt.ownerKey !== execution.ownerKey || String(receipt.generation) !== execution.durableGeneration
        || receipt.effectKey !== effectKey) {
      throw Object.assign(new Error('Audit parent effect is unverified'),{code:'AUDIT_RUN_EFFECT_UNVERIFIED'});
    }
    // The reader performs an independent ledger lookup; the transient receipt
    // above and the worker's local receipts are never substitutes for it.
    const evidence = await reader.open({ scope:binding,persona:trustedPersona,runId:execution.runId,signal:boundary.signal });
    await checkPublication();
    // Consumption must finish before the enclosing coordinator releases its
    // lease. Never return a lazy evidence iterator from a completed run.
    const verified=await consumeEvidence(evidence,Object.freeze({ binding,execution,check:checkPublication,signal:boundary.signal }));
    await checkPublication();
    if(assessment){
      if(typeof assessment.consume!=='function')throw new TypeError('Invalid audit assessment');
      await assessment.consume(evidence);await checkPublication();
    }
    return Object.freeze({ runId:execution.runId,summary:evidence.summary,provider:evidence.provider,
      model:evidence.model,requestedCount:evidence.requestedCount,rowCount:evidence.rowCount,objectiveCredit:false,
      ...(includeChatEvidence?{evidence:{version:1,modelProvenance:verified?.modelChainVerified===true,
        logSha256:verified?.logSha256,sourcesSha256:verified?.sourcesSha256,
        summarySha256:verified?.summarySha256,observationSha256:verified?.observationSha256,
        artifacts:evidence.artifacts,trace:verified?.trace}}:{}) });
  };
}
module.exports = { createSecureShopAuditJob };
