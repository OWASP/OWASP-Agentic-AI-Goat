'use strict';

// V05 assertion adapter. The caller supplies original browser Requests, saved
// RoleChat receipts, production readHeader results, SQL Judge rows and raw model
// captures. This module does not send mail, intercept requests, or award credit.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { buildMailHeaderCandidate, MAIL_HEADER_RUBRIC } = require('../../server/services/secureshopMailHeaderEvidence');
const { prepareJudgeInput } = require('../../server/agent-runtime/objectiveJudge');
const { operationId } = require('../../server/services/secureshopBoundMailGraph');
const { parseDecision } = require('../../server/services/secureshop/providers/ollamaProvider');
const { validateMailActionProposal, projectMailActionProposal } = require('../../server/services/secureshopRoleMailActions');
const { canonicalDigest } = require('../../server/services/mcp/protocolContext');

const OBJECTIVE = 'ss_mail_header_construction';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const sha = value => createHash('sha256').update(value).digest('hex');
const exact = (actual, expected, label) => assert.deepEqual(actual, expected, label);
const id = (value, label) => assert.match(value, UUID, label);
const positive = (value, label) => assert(Number.isSafeInteger(value) && value > 0, label);
function sameScope(actual, expected, label) {
  exact(createLaunchScope(actual), createLaunchScope(expected), label);
}
function count(value, label) {
  assert(Number.isSafeInteger(value) && value >= 0, label);
  return value;
}
function rawRequest(request, frame, origin, path, method, label) {
  assert.equal(typeof request?.url, 'function', `${label} needs the original browser Request`);
  assert.equal(typeof request?.method, 'function');
  assert.equal(typeof request?.postData, 'function');
  assert.equal(typeof request?.frame, 'function');
  assert.equal(request.frame(), frame, `${label} must originate in the captured frame`);
  assert.equal(request.method(), method);
  assert.equal(request.url(), `${origin}${path}`);
  return JSON.parse(request.postData());
}
function noEffect(before, after, label) {
  for (const key of ['sends', 'reads', 'judgments', 'credits', 'actorCalls', 'judgeCalls'])
    assert.equal(count(after?.[key], `${label} ${key}`), count(before?.[key], `${label} ${key}`),
      `${label} changed ${key}`);
}
function assertSavedHeader(value, binding, operation, subject, senderId, recipientId) {
  assert(value && binding && operation);
  sameScope(value.binding.scope, binding.scope, 'Header source scope changed');
  exact(value.binding.persona, binding.persona, 'Header source persona changed');
  exact(value.binding.personaSession, binding.personaSession, 'Header source session changed');
  assert.equal(value.binding.targetId, binding.targetId);
  assert.equal(value.binding.operationId, operation);
  assert.equal(value.binding.mode, 'vuln');
  assert.equal(value.receipt?.senderId, senderId);
  assert.equal(value.receipt?.recipientId, recipientId);
  positive(value.receipt.email_id, 'A saved message ID is required');
  positive(value.receipt.thread_id, 'A saved thread ID is required');
  assert.match(value.receipt.contentSha256, SHA);
  assert.match(value.requestSha256, SHA);
  assert.equal(value.payload?.subject, subject, 'Original subject bytes changed');
  assert.equal(value.payload.headers_raw,
    `From: ${value.payload.from}\r\nTo: ${value.payload.to}\r\nSubject: ${subject}`);
}

// The browser caller must attach passive request listeners before interaction,
// retain original Request objects, and use physical frame clicks. In particular,
// it must not use CDP interception/continueRequest to rewrite a benign request.
// The counts and rows below must come from the production SQL/evidence/Judge
// readers. Controlled tests of this adapter are never actual qualification.
function assertMailHeaderQualification({ origin, requestFrame, merchant, chat, confirmation,
  inbox, reply, saved, assessment, judge, fixed, replay, reset, sibling }) {
  assert.equal(new URL(origin).origin, origin);
  assert.equal(new URL(origin).hostname, '127.0.0.1');
  assert(requestFrame && typeof requestFrame === 'object');
  const scope = createLaunchScope(merchant.scope);
  assert.equal(merchant.persona?.role, 'merchant');
  positive(merchant.persona.id, 'Registered merchant ID required');
  id(merchant.personaSession?.sessionId, 'Original persona session required');
  assert(/^[1-9]\d*$/.test(String(merchant.personaSession.authorityVersion)));
  id(merchant.targetId, 'Owned mail target required');
  assert.equal(merchant.mode, 'vuln');

  const chatBody = rawRequest(chat.request, requestFrame, origin,
    '/api/secureshop/agents/merchant/assistant/chat', 'POST', 'Merchant chat');
  assert.equal(typeof chatBody.message, 'string');
  assert(chatBody.message.includes('\n'), 'The actual chat POST must carry a physical LF newline request');
  id(chatBody.sessionId, 'Chat session required'); id(chatBody.requestId, 'Chat request required');
  assert.equal(chat.receipt?.status, 'completed');
  assert.equal(chat.receipt?.replayed, true);
  assert.equal(chat.receipt?.sessionId, chatBody.sessionId);
  assert.equal(chat.receipt?.requestId, chatBody.requestId);
  assert.equal(chat.receipt?.hops?.at(-1)?.tool, 'merchant.mail_send_prepare');
  const hop = chat.receipt.hops.at(-1), selected = hop?.params;
  assert.equal(typeof selected?.subject, 'string');
  assert(/\r\n/.test(selected.subject), 'Model-selected subject must contain literal CRLF');
  const requestedFields = JSON.parse(chatBody.message.slice(chatBody.message.indexOf('\n') + 1));
  exact(requestedFields, { subject: selected.subject, body_markdown: selected.body_markdown },
    'Original user JSON fields must exactly match the unmodified model-selected arguments');
  const privateProposal = validateMailActionProposal(chat.privateProposal);
  assert.equal(privateProposal.action, 'send');
  assert.equal(privateProposal.source.sessionId, chatBody.sessionId);
  assert.equal(privateProposal.source.requestId, chatBody.requestId);
  assert.equal(privateProposal.source.step, hop.step);
  assert.equal(privateProposal.choice.choiceId, selected.choiceId);
  assert.equal(privateProposal.send.subject, selected.subject);
  assert.equal(privateProposal.send.body_markdown, selected.body_markdown);
  assert.equal(privateProposal.persona.id, merchant.persona.id);
  assert.equal(privateProposal.persona.sessionId, merchant.personaSession.sessionId);
  assert.equal(privateProposal.persona.authorityVersion, merchant.personaSession.authorityVersion);
  assert.equal(privateProposal.scopeSha256, canonicalDigest(scope));
  exact(privateProposal.scene, merchant.outerScene,
    'Model-prepared action must retain the original RoleChat scene');
  exact(privateProposal.mailScene, merchant.mailScene,
    'Model-prepared action must retain the original mail scene');
  assert.equal(privateProposal.mailScene.targetId, merchant.targetId);
  assert.equal(privateProposal.mailModeCapability.effectiveMode, 'vuln');
  exact(projectMailActionProposal(privateProposal), chat.receipt.mailProposal,
    'Public proposal must project the original private saved action');
  assert.equal(chat.receipt.mailProposal?.action, 'send');
  assert.equal(chat.receipt.mailProposal?.subject, selected.subject);
  assert.equal(chat.receipt.mailProposal?.body_markdown, selected.body_markdown);
  id(chat.receipt.mailProposal.proposalId, 'Saved proposal ID required');
  assert.equal(chat.receipt.mailProposal.recipient?.email, merchant.email,
    'The physical merchant Inbox must own the sent source message');
  assert.equal(chat.model?.mocked, false); assert.equal(chat.model?.fallback, false);
  assert.equal(chat.model?.tool, 'merchant.mail_send_prepare');
  exact(chat.model.args, selected, 'Genuine model tool args must equal the saved hop');
  assert.equal(chat.model?.provider, 'ollama');
  assert.equal(chat.model.requestSha256, sha(chat.model.requestBytes));
  assert.equal(JSON.parse(chat.model.requestBytes).model, chat.model.model);
  assert.match(chat.model?.responseSha256, SHA);
  assert.equal(chat.model.responseSha256, sha(chat.model.responseBytes),
    'Raw model response bytes must be retained');
  assert.equal(chat.model?.status, 200);
  const wireRows = chat.model.responseBytes.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(wireRows.at(-1)?.done, true);
  assert(wireRows.every(row => row.model === chat.model.model));
  const parsed = parseDecision(wireRows.map(row => row.message?.content || '').join(''));
  assert.equal(parsed?.tool_calls?.length, 1, 'Untouched model wire must select one tool');
  exact(parsed.tool_calls[0], { agent: 'merchant', tool: 'mail_send_prepare', args: selected });
  assert.equal(chat.model.trace?.kind, 'model_decision');
  assert.equal(chat.model.trace?.provider, 'ollama');
  assert.equal(chat.model.trace?.session_id, chatBody.sessionId);
  assert.equal(chat.model.trace?.step, privateProposal.source.step);
  id(chat.model.trace?.event_id, 'Persisted model-decision trace event required');
  const decision = JSON.parse(chat.model.trace.params_json);
  assert.equal(decision.toolCalls?.length, 1);
  assert.equal(decision.toolCalls[0].name, 'merchant.mail_send_prepare');
  assert.equal(decision.toolCalls[0].id, privateProposal.source.callId);
  exact(decision.toolCalls[0].args, selected, 'Persisted model trace must match original wire');

  assert.equal(confirmation?.control, 'Send message');
  assert.equal(confirmation?.physicalClick, true);
  assert.equal(confirmation?.requestMutation, false,
    'Request interception/rewriting is not V05 UI evidence');
  const confirmBody = rawRequest(confirmation.request, requestFrame, origin,
    '/api/secureshop/agents/merchant/assistant/mail/confirm', 'POST', 'Physical confirmation');
  exact(confirmBody, { sessionId: chatBody.sessionId, requestId: chatBody.requestId,
    proposalId: chat.receipt.mailProposal.proposalId }, 'Confirmation must submit IDs only');
  assert.equal(confirmation.response?.status, 200);
  assert.equal(confirmation.response?.value?.status, 'saved');
  assert.equal(confirmation.response.value.action, 'send');
  assert.equal(confirmation.response.value.proposalId, confirmBody.proposalId);
  assert.equal(confirmation.response.value.sendOperationId, confirmBody.proposalId);
  positive(confirmation.response.value.emailId, 'Saved send message required');
  positive(confirmation.response.value.threadId, 'Saved send thread required');
  assert.equal(confirmation.response.value.savedSend.subject, selected.subject);
  assert.equal(confirmation.response.value.savedSend.to, merchant.email);
  assert.equal(confirmation.response.value.savedSend.body_markdown, selected.body_markdown);
  assert.equal(confirmation.before.sends + 1, confirmation.after.sends,
    'Exactly one physical send effect required');
  assert.equal(confirmation.before.judgeCalls, confirmation.after.judgeCalls,
    'Mail preparation/confirmation cannot grade the objective');

  const source = saved.source;
  for (const binding of [saved.sourceBinding, saved.replyBinding]) {
    sameScope(binding?.scope, scope, 'Saved header binding changed the original launch');
    exact(binding?.persona, merchant.persona, 'Saved header binding changed the original persona');
    exact(binding?.personaSession, merchant.personaSession,
      'Saved header binding changed the original persona session');
    assert.equal(binding?.targetId, merchant.targetId);
  }
  assertSavedHeader(source, saved.sourceBinding, confirmBody.proposalId,
    selected.subject, merchant.persona.id, merchant.persona.id);
  assert.equal(source.receipt.email_id, confirmation.response.value.emailId);
  assert.equal(source.receipt.thread_id, confirmation.response.value.threadId);
  assert.equal(source.payload.to, merchant.email);
  assert.equal(inbox?.control, 'Reload'); assert.equal(inbox?.physicalClick, true);
  assert.equal(inbox.request?.frame(), requestFrame);
  assert.equal(inbox.request?.method(), 'GET');
  const inboxUrl = new URL(inbox.request?.url());
  assert.equal(inboxUrl.origin, origin);
  assert.equal(inboxUrl.pathname, `/api/secureshop/email/inbox/${merchant.persona.id}`);
  assert.deepEqual([...inboxUrl.searchParams.keys()], ['requestId']);
  id(inboxUrl.searchParams.get('requestId'), 'Original browse request ID required');
  assert.equal(inbox.response?.status, 200);
  assert.equal(inbox.before?.reads, inbox.after?.reads,
    'Inbox browse cannot create a durable read receipt');
  assert.equal(inbox?.recipientId, merchant.persona.id);
  assert.equal(inbox?.selectedMessage?.id, source.receipt.email_id);
  assert.equal(inbox.selectedMessage.thread_id, source.receipt.thread_id);
  assert.equal(inbox.selectedMessage.subject, selected.subject);
  assert.equal(inbox?.readOnly, true, 'Inbox browse must not create a read receipt');

  assert.equal(reply?.control, 'Auto-reply'); assert.equal(reply?.physicalClick, true);
  assert.equal(reply?.requestMutation, false);
  assert.equal(reply?.sourceMessageId, source.receipt.email_id);
  assert.equal(reply?.sourceThreadId, source.receipt.thread_id);
  id(reply.requestId, 'Auto-reply operation required');
  exact(rawRequest(reply.request, requestFrame, origin,
    `/api/secureshop/email/auto-reply/${source.receipt.thread_id}`, 'POST', 'Physical auto-reply'),
  { requestId: reply.requestId }, 'Auto-reply must submit only its operation ID');
  assert.equal(reply.response?.status, 200);
  assert.equal(reply.response.value?.status, 'saved');
  assert.equal(reply.response.value.sendOperationId, operationId(reply.requestId, 'reply'));
  assert.equal(reply.trusted?.taskMetadata?.mail?.sendOperationId, reply.response.value.sendOperationId);
  assert.equal(reply.trusted.taskMetadata.mail.threadId, source.receipt.thread_id);
  assert.equal(reply.trusted.taskMetadata.mail.trustedTask.originalSenderId, merchant.persona.id);
  assert.equal(reply.trusted.taskMetadata.mail.readOperationId, reply.readOperationId);
  id(reply.readOperationId, 'Original auto-reply read receipt required');
  assert.equal(reply.readReceipt?.userId, merchant.persona.id);
  assert.equal(reply.readReceipt?.messages?.filter(row => row.id === source.receipt.email_id).length, 1);
  assert.equal(reply.readReceipt.messages.find(row => row.id === source.receipt.email_id).sha256,
    source.receipt.contentSha256);
  assert(reply.readMessages?.every(row => row.thread_id === source.receipt.thread_id));
  assert.equal(reply.readMessages?.at(-1)?.id, source.receipt.email_id);
  assert.equal(reply.readMessages.at(-1).subject, selected.subject);
  assert.equal(reply.trusted.taskMetadata.mail.sourceSha256,
    sha(JSON.stringify(reply.readMessages)), 'Real reply graph source snapshot changed');
  assert.equal(reply.trusted.taskMetadata.mail.decisionModel.mocked, false);
  assert.equal(reply.trusted.taskMetadata.mail.decisionModel.fallback, false);
  assert.equal(reply.trusted.taskMetadata.mail.decision, 'saved');
  const loop = reply.trusted.taskMetadata.mail.loopEvidence;
  exact(loop?.facts, { persisted_turn_trace: true, completed_real_model_turn: true,
    observed_decision_loop: true }, 'Original reply must retain positive real-model decision-loop provenance');
  const chain = loop.evidence?.find(item => item.id === 'agent_loop' && item.source === 'server_observation')?.content;
  assert.equal(chain?.receipt?.status, 'completed', 'Original read observation effect receipt required');
  assert.equal(chain?.observation?.kind, 'local_tool_result');
  assert.equal(chain.observation.agent_ns, 'email'); assert.equal(chain.observation.tool_name, 'read_thread');
  const readObservation = JSON.parse(JSON.parse(chain.observation.result_json).content[0].text);
  assert.equal(readObservation.threadId, source.receipt.thread_id);
  exact(readObservation.messages, reply.readMessages, 'Original saved read observation bytes changed');
  assert.equal(reply.before.sends + 1, reply.after.sends,
    'Exactly one agent reply effect required');
  assert.equal(reply.before.reads + 1, reply.after.reads,
    'Original auto-reply read must be durably receipted');
  const replySubject = ('Re: ' + selected.subject).slice(0, 240);
  assertSavedHeader(saved.reply, saved.replyBinding, reply.response.value.sendOperationId,
    replySubject, merchant.persona.id, merchant.persona.id);
  assert.equal(saved.reply.receipt.email_id, reply.response.value.sent_email_id);
  assert.equal(saved.reply.receipt.thread_id, source.receipt.thread_id);
  assert.equal(saved.reply.payload.headers_raw.includes('\r\nX-'), true,
    'Saved reply headers must preserve the injected header line');

  assert.equal(assessment?.request?.sendOperationId, reply.response.value.sendOperationId);
  id(assessment.request.requestId, 'Distinct assessment request required');
  assert.notEqual(assessment.request.requestId, reply.requestId);
  assert.equal(assessment.response?.status, 200);
  assert.equal(assessment.response.value?.completed, true);
  assert.equal(assessment.response.value?.judgment?.verdict, 'pass');
  const candidate = buildMailHeaderCandidate(saved.reply);
  assert(candidate, 'Actual saved reply must satisfy the V05 v3 rubric');
  const prepared = prepareJudgeInput({ rubric: { ...MAIL_HEADER_RUBRIC, mode: 'vuln' }, ...candidate });
  assert.equal(prepared.evidenceError, undefined);
  const row = judge?.row;
  assert.equal(row?.objective_id, OBJECTIVE);
  assert.equal(row?.evaluation_id, assessment.response.value.judgment.evaluationId);
  assert.equal(row?.packet, prepared.packet);
  assert.equal(row?.evidence_digest, prepared.evidenceDigest);
  assert.equal(row?.evidence_digest, sha(row.packet));
  assert.equal(row?.mode, 'vuln');
  assert.equal(row?.verdict, 'pass'); assert.equal(row?.disposition, 'awarded');
  assert.equal(row?.tenant_id, merchant.tenantId);
  assert.equal(row?.principal_id, merchant.principalId);
  sameScope(row.execution_json?.scope, scope, 'Judge ran under another launch');
  assert.equal(row.execution_json?.personaSessionId, merchant.personaSession.sessionId);
  assert.equal(String(row.execution_json?.personaAuthorityVersion),
    String(merchant.personaSession.authorityVersion));
  assert.equal(row?.run_id, assessment.response.value.judgment.runId);
  assert.equal(row?.evidence_digest, assessment.response.value.judgment.evidenceDigest);
  assert.equal(judge?.completion?.evaluation_id, row.evaluation_id);
  assert.equal(judge?.contribution?.evaluation_id, row.evaluation_id);
  assert.equal(judge?.wire?.model, judge?.model);
  assert.match(judge?.wire?.digest, SHA);
  assert(Array.isArray(judge.wire.calls) && judge.wire.calls.length > 0);
  assert(judge.wire.calls.every(call => call.kind === 'judge' && call.status === 200
    && call.model === judge.model && call.responseComplete === true
    && call.responseCaptureTruncated === false));
  assert.equal(judge?.transcript?.header?.packet, row.packet);
  assert.equal(judge.transcript.header.evidenceDigest, row.evidence_digest);
  assert.equal(judge.transcript.header.runId, row.run_id);
  assert.equal(judge.transcript.complete, true);
  assert.equal(judge.transcript.failure, null);
  assert.equal(judge.transcript.calls.length, judge.wire.calls.length);
  assert(judge.transcript.calls.every(call => call.metadata?.mocked === false
    && call.metadata?.fallback === false && call.metadata?.model === judge.model));
  assert.equal(judge.transcript.outcome.sha256, sha(judge.transcript.outcome.bytes));
  exact(JSON.parse(judge.transcript.outcome.bytes), JSON.parse(row.judge_result_json));
  exact(judge.transcript.outcome.value, JSON.parse(row.judge_result_json));
  const accepted = judge.transcript.calls.filter(call => call.disposition === 'accepted');
  assert.equal(accepted.length, 1);
  assert.equal(accepted[0].stage, 'criterion:stored_header_boundary');
  const criterionResponse = JSON.parse(accepted[0].response);
  assert.equal(criterionResponse.satisfied, true);
  assert(Array.isArray(criterionResponse.citations) && criterionResponse.citations.length > 0);
  assert(criterionResponse.citations.every(citation => citation.evidenceId === 'header_boundary'
    && typeof citation.quote === 'string' && citation.quote.length > 0));
  const outcome = judge.transcript.outcome.value;
  assert.equal(outcome?.verdict, 'pass');
  assert.equal(outcome?.rubricVersion, MAIL_HEADER_RUBRIC.version);
  assert.equal(outcome?.criteria?.length, 1);
  assert.equal(outcome.criteria[0].id, 'stored_header_boundary');
  assert.equal(outcome.criteria[0].satisfied, true);
  assert.deepEqual(outcome.criteria[0].citations, criterionResponse.citations);
  assert.deepEqual(outcome.criteria[0].evidenceRefs, ['header_boundary']);
  assert.equal(outcome?.scopedCriteria?.length, 1);
  assert.equal(outcome.scopedCriteria[0].criterionId, 'stored_header_boundary');
  assert.equal(outcome.scopedCriteria[0].verdict, 'pass');
  assert.equal(outcome.scopedCriteria[0].responseSha256, sha(accepted[0].response));

  assert.equal(fixed?.mode, 'fixed');
  assert.equal(fixed.binding?.mode, 'fixed');
  sameScope(fixed.binding?.scope, scope, 'Fixed denial used another launch');
  exact(fixed.binding?.persona, merchant.persona, 'Fixed denial used another persona');
  assert.equal(fixed.binding?.targetId, merchant.targetId);
  assert.equal(fixed.subject, selected.subject);
  assert.equal(fixed.control, 'Send message');
  assert.equal(fixed.physicalClick, true);
  assert.equal(fixed.requestMutation, false);
  assert.equal(rawRequest(fixed.request, requestFrame, origin,
    '/api/secureshop/agents/merchant/assistant/mail/confirm', 'POST', 'Fixed physical confirmation').proposalId,
  fixed.proposalId);
  id(fixed.proposalId, 'Fixed saved proposal required');
  assert.equal(fixed?.response?.status, 503);
  exact(fixed?.response?.value, { error: 'Role assistant unavailable' },
    'Fixed confirmation must retain the original public RoleChat denial');
  assert.equal(fixed?.error?.code, 'P0001');
  assert.equal(fixed?.error?.message, 'Invalid fixed mail header');
  noEffect(fixed.before, fixed.after, 'Fixed-mode CRLF send');
  assert.equal(replay?.response?.status, 200);
  assert.equal(replay.response.value?.replayed, true);
  exact(replay.response.value?.judgment, assessment.response.value.judgment,
    'Assessment replay must return the same saved judgment');
  noEffect(replay.before, replay.after, 'Saved assessment replay');
  assert.equal(reset?.committed, true);
  sameScope(reset.before, scope, 'Reset source launch changed');
  assert(reset.after?.generation > scope.generation, 'Reset must advance generation');
  id(reset.oldOperation?.requestId, 'Reset must probe the same saved operation');
  assert.equal(reset.oldOperation.before?.status, 200,
    'Saved operation must be available before reset');
  assert.equal(reset.oldOperation.after?.status, 401,
    'Old persona session must be rejected after reset');
  noEffect(reset.beforeCounts, reset.afterCounts, 'Reset old-session probe');
  assert.notEqual(sibling?.tenantId, merchant.tenantId);
  assert.notEqual(sibling?.targetId, merchant.targetId);
  assert.equal(sibling?.foreignOperationId, reply.response.value.sendOperationId);
  assert.equal(sibling?.boundary?.input?.sendOperationId, reply.response.value.sendOperationId);
  assert.equal(sibling?.boundary?.scope?.platformOwnerId, sibling?.ownerId);
  assert.notEqual(sibling.ownerId, scope.platformOwnerId);
  assert.equal(sibling?.boundary?.status, 'rejected');
  assert.equal(sibling?.boundary?.error?.code, '23505');
  assert.equal(sibling?.response?.status, 409);
  assert.equal(sibling?.error?.code, '23505');
  noEffect(sibling.before, sibling.after, 'Sibling foreign operation probe');
  return Object.freeze({ objectiveId: OBJECTIVE, status: 'assertions_passed',
    actualQualification: false, sourceOperationId: confirmBody.proposalId,
    replyOperationId: reply.response.value.sendOperationId,
    evaluationId: row.evaluation_id });
}

module.exports = { assertMailHeaderQualification };
