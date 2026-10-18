'use strict';
const { respondForged } = require('./csrfForgedResponse');

// Shared production action implementation for ordinary and managed requests.
function createCsrfActionHandler({ getUserKey, getUserId, sessionIdFor, victimSandbox, tabOf, detectForgedVector, csrfAgent, recordActivity, getCompleted, creditObjective, pushCsrfEvent, syncWorkshopStarted, canonicalMode=()=> 'vuln', assertCanonicalMode=async()=>{}, workshopKey = 'csrf_workshop' }) {
return async function handleAgentAction(req, res) {
  await assertCanonicalMode();
  const mode=canonicalMode();
  if(!['vuln','fixed'].includes(mode))throw new TypeError('Canonical CSRF mode required');
  const userKey = getUserKey(req);
  const userId = getUserId(req);
  const sessionId = sessionIdFor(req);
  const sandbox = victimSandbox.getOrCreateSandbox(sessionId);
  const tabId = tabOf(req);

  const body = { ...(req.query || {}), ...(req.body || {}) };
  const message = String(body.message || body.msg || body.instruction || '').trim();
  const document = body.document ? String(body.document) : null;
  const chain = body.chain ? String(body.chain) : null;
  const suppliedToken = body.csrfToken || body.csrf_token || null;
  const vector = detectForgedVector(req, body, tabId);
  const vectorLabel = victimSandbox.VECTORS[vector]?.label || vector;

  if (!message && !document) return respondForged(req, res, { ok: false, reason: 'missing message parameter' });

  const crossSite = victimSandbox.VECTORS[vector]?.crossSite;
  const blockedDecision = await require('../agent-runtime/csrfSelectedEffect').withCsrfTeachingEffect(
    require('../agent-runtime/ownerWorkflowRoutes').getOwnerExecution(), sandbox, async () => {
      const t = sandbox.tab(tabId);
      const tokenOk = suppliedToken && suppliedToken === t.csrfToken;
      const tokenDefense=Boolean(t.defenses.csrfToken&&crossSite&&!tokenOk);
      if(mode!=='fixed'&&!tokenDefense)return null;
      const outcome = tokenDefense ? 'Rejected (HTTP 403): missing/invalid anti-CSRF token.' : 'Rejected (HTTP 403): fixed mode does not execute forged agent actions.';
      const toolResult = { kind: 'attack', blocked: true, executed:false, stateChanged:false, vector, vectorLabel, outcome, defenses: { ...t.defenses } };
      t.attackLog.push({ ts: new Date().toISOString(), tab: tabId, vector, vectorLabel, action: 'n/a', blocked: true, outcome });
      const victimState = structuredClone(sandbox.getTabState(tabId));
      await sandbox.flush?.();
      return { outcome, toolResult, victimState, tokenDefense };
    });
  if (blockedDecision) {
    await assertCanonicalMode();
    const { outcome, toolResult, victimState } = blockedDecision;
    const objectivesHit = blockedDecision.tokenDefense
      ? (csrfAgent._internals
        ? csrfAgent._internals.resolveObjectives(tabId, { vector, blocked: true, defensesOn: true })
        : (tabId === 'get' ? ['csrf_g3'] : tabId === 'post' ? ['csrf_p3'] : []))
      : [];
    await recordActivity(userKey, tabId, `CSRF ${req.method} /agent-action`, { vector, message }, toolResult);
    const already = await getCompleted(userKey);
    const newlyCompleted = [];
    for (const oid of objectivesHit) {
      if (await creditObjective(userKey, oid, userId, already)) newlyCompleted.push(oid);
    }
    pushCsrfEvent(userKey, { tab: tabId, vector, vectorLabel, blocked: true, forgedMessage: message,
      agentReply: `### Forged request BLOCKED\n- **Vector:** ${vectorLabel}\n- **Reason:** ${outcome}`,
      toolResult, victimState, objectivesHit: newlyCompleted });
    return respondForged(req, res, { ok: true, blocked: true });
  }

  // Phase 1 — push the forged REQUEST to the chat immediately (deterministic,
  // no LLM wait), so the learner sees the CSRF land in <200ms.
  pushCsrfEvent(userKey, {
    phase: 'request', tab: tabId, vector, vectorLabel,
    forgedMessage: document ? `[document] ${document}\n\n[message] ${message}` : message,
  });

  await syncWorkshopStarted(userId, workshopKey);
  const result = await csrfAgent.chat(sessionId, tabId, message || 'check my balance', { forgedVia: vector, document, chain });

  await recordActivity(userKey, tabId, `CSRF ${req.method} /agent-action`, { vector, message, document: !!document, chain }, result.toolResult);

  const already = await getCompleted(userKey);
  const newlyCompleted = [];
  for (const oid of result.objectivesHit || []) {
    if (await creditObjective(userKey, oid, userId, already)) newlyCompleted.push(oid);
  }

  // Phase 2 — push the agent's REPLY + state + objective credit.
  pushCsrfEvent(userKey, {
    phase: 'reply', tab: tabId, vector: result.vector || vector, vectorLabel,
    blocked: !!(result.toolResult && result.toolResult.blocked),
    refused: !!(result.toolResult && result.toolResult.refused),
    forgedMessage: document ? `[document] ${document}\n\n[message] ${message}` : message,
    agentReply: result.response, toolResult: result.toolResult,
    victimState: result.victimState, objectivesHit: newlyCompleted,
  });

  return respondForged(req, res, { ok: true, blocked: !!(result.toolResult && result.toolResult.blocked) });
}
;
}
module.exports = { createCsrfActionHandler };
