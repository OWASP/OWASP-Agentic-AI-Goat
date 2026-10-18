'use strict';
const { isDeepStrictEqual: equal } = require('node:util');
const { createConversationBinding } = require('./secureshopConversationBinding');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { validateMailChatResult } = require('./secureshopRoleMailRead');
const { isQualifiedSecureShopModelTrace } = require('./secureshopRealModelTrace');
const PURPOSE = require('./secureshopConversationPurpose').SECURESHOP_CONVERSATION_PURPOSES.merchantAssistant;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail = () => Object.assign(new Error('Original agent mailbox read unavailable'),
  { code: 'MAIL_AGENT_READ_ORIGINAL_UNAVAILABLE' });
const need = value => { if (!value) throw fail(); };
const parse = value => { try { return JSON.parse(value); } catch { throw fail(); } };
// This reads an existing completed RoleChat detail. It cannot create a read,
// invoke an actor/Judge, or convert the separate manual IDOR receipt into credit.
function createMailAgentReadOriginalReader({ journal, conversations, identityPool,
  readRequest, qualifyModel } = {}) {
  for (const fn of [journal?.readBoundRequest, conversations?.getBoundSession,
    conversations?.getMessages, conversations?.getTraceEvents, identityPool?.query,
    readRequest, qualifyModel]) if (typeof fn !== 'function') throw TypeError('Agent mailbox evidence dependencies required');
  return Object.freeze({ async read({ scope, persona, personaSession,
    sessionId, requestId, check, signal } = {}) {
    try {
      need(UUID.test(sessionId || '') && UUID.test(requestId || '') && typeof check === 'function');
      const binding = createConversationBinding(scope, persona);
      need(binding.role === 'merchant' && UUID.test(personaSession?.sessionId || '')
        && /^[1-9][0-9]*$/.test(personaSession?.authorityVersion || ''));
      const checked = async work => { signal?.throwIfAborted(); await check();
        const value = await work(); signal?.throwIfAborted(); await check(); return value; };
      // Production readRequest revalidates retained scene, exact persona/session,
      // both modes, selected-choice ancestry, receipt and current message bytes.
      const saved = await checked(() => readRequest(scope, persona, personaSession, sessionId, requestId));
      need(saved?.sessionId === sessionId && saved.requestId === requestId
        && saved.status === 'completed' && saved.stopReason === 'end_turn' && saved.replayed === true);
      const packet = validateMailChatResult(saved.mailRead?.result);
      need(packet.kind === 'detail' && packet.status === 'complete' && packet.message
        && packet.recipient.id !== persona.id && packet.mailModeCapability.effectiveMode === 'vuln'
        && saved.modeCapability?.effectiveMode === 'vuln');
      const session = await checked(() => conversations.getBoundSession(sessionId));
      need(session?.id === sessionId && session.state === 'active' && session.purpose === PURPOSE
        && equal(session.binding, binding));
      const turn = await checked(() => journal.readBoundRequest({ sessionId, requestId, binding, purpose: PURPOSE }));
      need(turn?.session_id === sessionId && (turn.request_id === undefined || turn.request_id === requestId)
        && turn.status === 'completed' && turn.request_version === 1);
      const result = turn.result_json, meta = result?.taskMetadata?.roleChat;
      need(result?.stopReason === 'end_turn' && result.text === saved.text
        && equal(result.hops, saved.hops) && equal(result.modeCapability, saved.modeCapability)
        && equal(meta?.mailRead, saved.mailRead) && meta.mailSelection?.intent === 'mail_detail'
        && meta.mailSelection.choiceId === saved.mailRead.choiceId && meta.mailContinuation === null
        && UUID.test(meta.mailReadRunId || ''));
      const origin = meta.mailOrigin;
      need(Number.isSafeInteger(origin?.step) && origin.step > 0 && typeof origin.callId === 'string');
      const args = { choiceId: meta.mailSelection.choiceId };
      const messages = await checked(() => conversations.getMessages(sessionId, binding, PURPOSE));
      // The persisted original call ID identifies this turn's message sequence.
      // Identical learner text in another turn cannot supply its user message.
      const callIndexes = messages?.flatMap((row, index) => row?.role === 'assistant'
        && row.tool_calls?.some(call => call?.id === origin.callId) ? [index] : []);
      need(callIndexes?.length === 1 && callIndexes[0] > 0);
      const callIndex = callIndexes[0];
      let userIndex = callIndex - 1;
      // Earlier selected steps may precede this detail in the same turn. Cross
      // only complete tool pairs; a prior final assistant is a turn boundary.
      while (userIndex >= 0 && messages[userIndex]?.role !== 'user') {
        const tool = messages[userIndex], assistant = messages[userIndex - 1];
        need(tool?.role === 'tool' && assistant?.role === 'assistant'
          && Array.isArray(assistant.tool_calls) && assistant.tool_calls.length === 1
          && typeof assistant.tool_calls[0]?.id === 'string'
          && tool.tool_call_id === assistant.tool_calls[0].id);
        userIndex -= 2;
      }
      const original = messages[userIndex];
      need(equal(messages[callIndex].tool_calls, [{ id: origin.callId, type: 'function',
        function: { name: 'merchant.mail_detail', arguments: JSON.stringify(args) } }])
        && original?.role === 'user' && typeof original.content === 'string'
        && createTurnRequest({ sessionId, requestId, binding, message: original.content,
          version: turn.request_version }).hash === turn.request_hash);
      const envelope = parse(original.content);
      need(envelope.role === 'merchant' && envelope.message === meta.mailSourceMessage
        && equal(envelope.selection, meta.mailSelection));
      const ids = meta.mailReadTraceEventIds;
      need(Array.isArray(ids) && ids.length >= 4 && ids.length <= 4096
        && ids.every(id => UUID.test(id || '')) && new Set(ids).size === ids.length);
      const traces = await checked(() => conversations.getTraceEvents(sessionId, binding, ids, PURPOSE));
      need(Array.isArray(traces) && equal(traces.map(row => row.event_id), ids)
        && traces.every((row, i) => row.session_id === sessionId && /^[1-9][0-9]*$/.test(String(row.id))
          && (!i || BigInt(row.id) > BigInt(traces[i - 1].id))));
      const one = predicate => { const rows = traces.filter(predicate); need(rows.length === 1); return rows[0]; };
      const decision = one(row => row.kind === 'model_decision' && row.step === origin.step);
      const selected = parse(decision.params_json);
      need(selected.decision === 'tool_use' && equal(selected.toolCalls,
        [{ id: origin.callId, name: 'merchant.mail_detail', args }])
        && isQualifiedSecureShopModelTrace(decision, qualifyModel));
      const call = one(row => row.kind === 'local_tool_call' && row.step === origin.step
        && row.agent_ns === 'merchant' && row.tool_name === 'mail_detail');
      const returned = one(row => row.kind === 'local_tool_result' && row.step === origin.step
        && row.agent_ns === 'merchant' && row.tool_name === 'mail_detail');
      need(call.actor === 'supervisor→task' && returned.actor === 'task→supervisor'
        && call.policy_violation === null && returned.policy_violation === null
        && equal(parse(call.params_json), args) && BigInt(decision.id) < BigInt(call.id)
        && BigInt(call.id) < BigInt(returned.id));
      const observation = parse(returned.result_json);
      need(equal(Object.keys(observation || {}), ['content']) && Array.isArray(observation.content)
        && observation.content.length === 1 && equal(Object.keys(observation.content[0]).sort(), ['text', 'type'])
        && observation.content[0].type === 'text' && typeof observation.content[0].text === 'string'
        && Buffer.byteLength(observation.content[0].text) <= 16384
        && equal(parse(observation.content[0].text), { mail: packet, origin }));
      need(messages[callIndex + 1]?.role === 'tool'
        && messages[callIndex + 1].tool_call_id === origin.callId
        && messages[callIndex + 1].content === observation.content[0].text);
      let finalIndex = callIndex + 2;
      while (messages[finalIndex]?.role === 'assistant' && messages[finalIndex].tool_calls) {
        const assistant = messages[finalIndex], tool = messages[finalIndex + 1];
        need(Array.isArray(assistant.tool_calls) && assistant.tool_calls.length === 1
          && typeof assistant.tool_calls[0]?.id === 'string' && tool?.role === 'tool'
          && tool.tool_call_id === assistant.tool_calls[0].id);
        finalIndex += 2;
      }
      need(messages[finalIndex]?.role === 'assistant'
        && messages[finalIndex].content === result.text && !messages[finalIndex].tool_calls
        && messages.slice(userIndex, finalIndex + 1)
          .every(row => equal(row.modeCapability, saved.modeCapability)));
      const hops = result.hops?.filter(hop => hop.tool === 'merchant.mail_detail' && hop.step === origin.step);
      need(hops?.length === 1 && !hops[0].error && !hops[0].policyViolation
        && equal(hops[0].params, args) && equal(hops[0].result, observation));
      const final = one(row => row.kind === 'model_decision' && parse(row.result_json)?.decision === 'final');
      const terminal = one(row => row.kind === 'terminal');
      need(decision.actor === 'supervisor' && final.actor === 'supervisor' && terminal.actor === 'supervisor'
        && final.step > origin.step && final.step === terminal.step && final.step === result.steps
        && parse(final.result_json).stopReason === 'end_turn'
        && parse(terminal.result_json).steps === result.steps
        && parse(terminal.result_json).hops === result.hops.length
        && BigInt(returned.id) < BigInt(final.id) && BigInt(final.id) < BigInt(terminal.id)
        && traces.at(-1) === terminal && [final, terminal].every(row => isQualifiedSecureShopModelTrace(row, qualifyModel))
        && parse(final.result_json).text === result.text && parse(terminal.result_json).stopReason === 'end_turn'
        && [final, terminal].every(row => row.provider === decision.provider
          && parse(row.result_json).model === parse(decision.result_json).model));
      const owner = JSON.stringify(['SecureShopBoundConversation', sessionId]);
      const run = await checked(() => identityPool.query(`SELECT r.run_id,r.owner_key,r.generation::text AS generation,r.status
        FROM graph_runtime.runs r JOIN graph_runtime.owners o ON o.owner_key=r.owner_key AND o.generation=r.generation
        WHERE r.run_id=$1 AND r.owner_key=$2 AND r.status='completed'`, [meta.mailReadRunId, owner]));
      need(run.rows.length === 1 && run.rows[0].run_id === meta.mailReadRunId
        && run.rows[0].owner_key === owner && run.rows[0].status === 'completed'
        && /^(0|[1-9][0-9]*)$/.test(run.rows[0].generation)
        && BigInt(run.rows[0].generation) <= 9223372036854775807n);
      const effectKey = `${requestId}:${JSON.stringify([origin.step, origin.callId, 'merchant.mail_detail'])}`;
      const effect = await checked(() => identityPool.query(`SELECT run_id,owner_key,generation::text AS generation,effect_key,status
        FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2 AND generation=$3
          AND effect_key=$4 AND status='completed'`, [meta.mailReadRunId, owner, run.rows[0].generation, effectKey]));
      need(effect.rows.length === 1 && effect.rows[0].run_id === meta.mailReadRunId
        && effect.rows[0].owner_key === owner && effect.rows[0].generation === run.rows[0].generation
        && effect.rows[0].effect_key === effectKey && effect.rows[0].status === 'completed');
      const reread = await checked(() => readRequest(scope, persona, personaSession, sessionId, requestId));
      need(equal(reread, saved));
      return Object.freeze({ sessionId, requestId, envelope: original.content,
        mail: structuredClone(packet), origin: structuredClone(origin), text: result.text,
        turn: structuredClone(turn), traces: structuredClone(traces),
        run: structuredClone(run.rows[0]), effect: structuredClone(effect.rows[0]) });
    } catch (error) { if (signal?.aborted) signal.throwIfAborted(); throw fail(); }
  } });
}
module.exports = { PURPOSE, createMailAgentReadOriginalReader };
