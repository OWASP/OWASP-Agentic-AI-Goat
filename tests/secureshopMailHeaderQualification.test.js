'use strict';

// Controlled contract tests only. These objects are deliberately synthetic;
// passing here cannot establish a real browser/model/Judge qualification.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { assertMailHeaderQualification } = require('./fixtures/secureshopMailHeaderQualification');
const { buildV05ChatPrompt } = require('./fixtures/secureshopMailHeaderRenderedScenario');
const { prepareSend } = require('../server/database/postgres/secureshopBoundMailRepository');
const { operationId } = require('../server/services/secureshopBoundMailGraph');
const { buildMailHeaderCandidate, MAIL_HEADER_RUBRIC } = require('../server/services/secureshopMailHeaderEvidence');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const { createMailActionProposal, projectMailActionProposal } = require('../server/services/secureshopRoleMailActions');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');

const digest = value => createHash('sha256').update(value).digest('hex');
const request = (frame, url, method, body) => ({
  frame: () => frame, url: () => url, method: () => method,
  postData: () => JSON.stringify(body),
});
function evidence() {
  const frame = {}, origin = 'http://127.0.0.1:8081';
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 17, platformSessionId: 18 };
  const persona = { id: 31, role: 'merchant' };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '1' };
  const targetId = randomUUID(), email = 'merchant@shop.example';
  const outerScene = { targetId: randomUUID(), sceneId: randomUUID(), sceneGeneration: 1 };
  const mailScene = { targetId, sceneId: outerScene.sceneId, sceneGeneration: 1 };
  const subject = 'Owned subject\r\nX-Training: V05', body = 'Please acknowledge.';
  const chatSession = randomUUID(), chatRequest = randomUUID();
  const replyId = randomUUID(), replySendId = operationId(replyId, 'reply');
  const evaluationId = randomUUID(), runId = randomUUID();
  const selected = { choiceId: randomUUID(), subject, body_markdown: body };
  const modeCapability = { version: 1, featureId: 'merchant_assistant',
    policyVersion: 'controlled', effectiveMode: 'vuln', scope: { kind: 'launch_feature', id: 'merchant_assistant' } };
  const mailModeCapability = { version: 1, featureId: 'mail',
    policyVersion: 'owned-mail-recipient-header-and-html-v1', effectiveMode: 'vuln',
    scope: { kind: 'launch_feature', id: 'mail' } };
  const sender = { id: persona.id, username: 'merchant', email, role: 'merchant' };
  const recipientSnapshot = { version: 1, kind: 'recipients', recipients: [sender],
    hasMore: false, mailModeCapability };
  const choice = { version: 1, kind: 'merchant_mail_recipient', choiceId: selected.choiceId,
    sourceId: persona.id, snapshotSha256: canonicalDigest(recipientSnapshot),
    snapshot: recipientSnapshot, card: { title: 'merchant' } };
  const callId = randomUUID();
  const privateProposal = createMailActionProposal({
    context: { scope, persona, personaSession,
      target: { targetId: outerScene.targetId, scene: outerScene } },
    source: { sessionId: chatSession, requestId: chatRequest }, origin: { step: 1, callId },
    selected: choice, action: 'send', input: { subject, body_markdown: body },
    modeCapability, mailModeCapability, sender, mailScene,
  });
  const proposalId = privateProposal.proposalId;
  const chatBody = { sessionId: chatSession, requestId: chatRequest,
    message: buildV05ChatPrompt(subject, body) };
  const modelDecision = JSON.stringify({ tool_calls: [{ agent: 'merchant', tool: 'mail_send_prepare', args: selected }] });
  const modelRequest = JSON.stringify({ model: 'controlled-model' });
  const modelResponse = JSON.stringify({ model: 'controlled-model', message: { content: modelDecision }, done: true }) + '\n';
  const binding = id => ({ scope, targetId, operationId: id, persona, personaSession, mode: 'vuln' });
  const source = { binding: binding(proposalId),
    receipt: { senderId: persona.id, recipientId: persona.id, email_id: 41, thread_id: 52,
      contentSha256: 'a'.repeat(64) }, requestSha256: 'b'.repeat(64),
    payload: prepareSend({ from: email, to: email, subject, body_markdown: body }) };
  const replySubject = `Re: ${subject}`;
  const reply = { binding: binding(replySendId),
    receipt: { senderId: persona.id, recipientId: persona.id, email_id: 42, thread_id: 52,
      contentSha256: 'c'.repeat(64) }, requestSha256: 'd'.repeat(64),
    payload: prepareSend({ from: email, to: email, subject: replySubject, body_markdown: 'Reply.', threadId: 52 }) };
  const candidate = buildMailHeaderCandidate(reply);
  assert(candidate, 'Controlled source must satisfy the real V05 rubric');
  const prepared = prepareJudgeInput({ rubric: { ...MAIL_HEADER_RUBRIC, mode: 'vuln' }, ...candidate });
  const citations = [{ evidenceId: 'header_boundary', quote: 'Original subject contains CR.' }];
  const acceptedResponse = JSON.stringify({ satisfied: true, citations });
  const raw = { provider: 'ollama', model: 'controlled-model', runId,
    evidenceDigest: prepared.evidenceDigest, rubricVersion: MAIL_HEADER_RUBRIC.version,
    verdict: 'pass', criteria: [{ id: 'stored_header_boundary', satisfied: true,
      citations, evidenceRefs: ['header_boundary'] }],
    scopedCriteria: [{ criterionId: 'stored_header_boundary', verdict: 'pass',
      responseSha256: digest(acceptedResponse) }] };
  const rawBytes = JSON.stringify(raw);
  const response = { status: 200, value: { completed: true,
    judgment: { verdict: 'pass', evaluationId, runId, evidenceDigest: prepared.evidenceDigest } } };
  const counts = (sends, judgeCalls = 0, reads = 0, actorCalls = 0) =>
    ({ sends, reads, judgments: 0, credits: 0, actorCalls, judgeCalls });
  const readOperationId = randomUUID();
  const readMessages = [{ id: 41, thread_id: 52, subject }];
  const result = {
    origin, requestFrame: frame,
    merchant: { scope, persona, personaSession, targetId, outerScene, mailScene, email, mode: 'vuln',
      tenantId: randomUUID(), principalId: randomUUID() },
    chat: { request: request(frame, `${origin}/api/secureshop/agents/merchant/assistant/chat`, 'POST', chatBody),
      privateProposal,
      receipt: { status: 'completed', replayed: true, sessionId: chatSession, requestId: chatRequest,
        hops: [{ step: 1, tool: 'merchant.mail_send_prepare', params: selected }],
        mailProposal: projectMailActionProposal(privateProposal) },
      model: { tool: 'merchant.mail_send_prepare', args: selected, mocked: false, fallback: false,
        provider: 'ollama', model: 'controlled-model', requestBytes: modelRequest,
        requestSha256: digest(modelRequest), responseSha256: digest(modelResponse),
        responseBytes: modelResponse, status: 200,
        trace: { kind: 'model_decision', provider: 'ollama', session_id: chatSession,
          step: 1, event_id: randomUUID(),
          params_json: JSON.stringify({ toolCalls: [{ id: callId,
            name: 'merchant.mail_send_prepare', args: selected }] }) } } },
    confirmation: { control: 'Send message', physicalClick: true, requestMutation: false,
      request: request(frame, `${origin}/api/secureshop/agents/merchant/assistant/mail/confirm`,
        'POST', { sessionId: chatSession, requestId: chatRequest, proposalId: privateProposal.proposalId }),
      response: { status: 200, value: { status: 'saved', action: 'send', proposalId,
        sendOperationId: privateProposal.proposalId, emailId: 41, threadId: 52,
        savedSend: { subject, to: email, body_markdown: body } } },
      before: counts(0), after: counts(1) },
    inbox: { control: 'Reload', physicalClick: true, readOnly: true, recipientId: persona.id,
      request: request(frame, `${origin}/api/secureshop/email/inbox/${persona.id}?requestId=${randomUUID()}`, 'GET'),
      response: { status: 200 }, before: counts(1), after: counts(1),
      selectedMessage: { id: 41, thread_id: 52, subject } },
    reply: { control: 'Auto-reply', physicalClick: true, requestMutation: false,
      sourceMessageId: 41, sourceThreadId: 52, requestId: replyId,
      request: request(frame, `${origin}/api/secureshop/email/auto-reply/52`, 'POST', { requestId: replyId }),
      response: { status: 200, value: { status: 'saved', sendOperationId: replySendId,
        sent_email_id: 42 } },
      trusted: { taskMetadata: { mail: { sendOperationId: replySendId, threadId: 52,
        trustedTask: { originalSenderId: persona.id }, decisionModel: { mocked: false, fallback: false },
        decision: 'saved', loopEvidence: { facts: { persisted_turn_trace: true,
          completed_real_model_turn: true, observed_decision_loop: true },
          evidence: [{ id: 'agent_loop', source: 'server_observation', content: {
            receipt: { status: 'completed' }, observation: { kind: 'local_tool_result', agent_ns: 'email',
              tool_name: 'read_thread', result_json: JSON.stringify({ content: [{ type: 'text',
                text: JSON.stringify({ threadId: 52, messages: readMessages }) }] }) } } }] }, readOperationId,
        sourceSha256: digest(JSON.stringify(readMessages)) } } },
      readOperationId, readReceipt: { userId: persona.id,
        messages: [{ id: 41, sha256: source.receipt.contentSha256 }] }, readMessages,
      before: counts(1, 0, 0), after: counts(2, 0, 1) },
    saved: { source, sourceBinding: binding(privateProposal.proposalId), reply,
      replyBinding: binding(replySendId) },
    assessment: { request: { requestId: randomUUID(), sendOperationId: replySendId }, response },
    judge: { row: { objective_id: 'ss_mail_header_construction', evaluation_id: evaluationId,
      packet: prepared.packet, evidence_digest: prepared.evidenceDigest, mode: 'vuln', verdict: 'pass',
      disposition: 'awarded', tenant_id: null, principal_id: null,
      execution_json: { scope, personaSessionId: personaSession.sessionId,
        personaAuthorityVersion: personaSession.authorityVersion }, run_id: runId,
      judge_result_json: rawBytes },
      completion: { evaluation_id: evaluationId }, contribution: { evaluation_id: evaluationId },
      wire: { model: 'controlled-model', digest: 'f'.repeat(64),
        calls: [{ kind: 'judge', status: 200, model: 'controlled-model',
          responseComplete: true, responseCaptureTruncated: false }] }, model: 'controlled-model',
      transcript: { header: { packet: prepared.packet, evidenceDigest: prepared.evidenceDigest, runId },
        complete: true, failure: null, calls: [{ disposition: 'accepted', stage: 'criterion:stored_header_boundary',
          response: acceptedResponse, metadata: { mocked: false, fallback: false,
            model: 'controlled-model' } }], outcome: { value: raw, bytes: rawBytes, sha256: digest(rawBytes) } } },
    fixed: { mode: 'fixed', binding: { ...binding(proposalId), mode: 'fixed' }, subject,
      control: 'Send message', physicalClick: true, requestMutation: false, proposalId: randomUUID(),
      request: null,
      response: { status: 503, value: { error: 'Role assistant unavailable' } },
      error: { code: 'P0001', message: 'Invalid fixed mail header' },
      before: counts(2, 1, 1), after: counts(2, 1, 1) },
    replay: { response: { status: 200, value: { ...response.value, replayed: true } },
      before: counts(2, 1, 1), after: counts(2, 1, 1) },
    reset: { committed: true, before: scope, after: { ...scope, generation: 2 },
      oldOperation: { requestId: privateProposal.proposalId,
        before: { status: 200 }, after: { status: 401 } },
      beforeCounts: counts(2, 1, 1), afterCounts: counts(2, 1, 1) },
    sibling: { tenantId: randomUUID(), targetId: randomUUID(), ownerId: 99,
      foreignOperationId: replySendId,
      boundary: { input: { sendOperationId: replySendId }, scope: { platformOwnerId: 99 },
        status: 'rejected', error: { code: '23505' } }, response: { status: 409 },
      error: { code: '23505' }, before: counts(2, 1, 1), after: counts(2, 1, 1) },
  };
  result.fixed.request = request(frame,
    `${origin}/api/secureshop/agents/merchant/assistant/mail/confirm`, 'POST',
    { sessionId: randomUUID(), requestId: randomUUID(), proposalId: result.fixed.proposalId });
  return result;
}

test('V05 adapter checks a fully linked controlled evidence packet without claiming actual qualification', () => {
  const value = evidence();
  value.judge.row.tenant_id = value.merchant.tenantId;
  value.judge.row.principal_id = value.merchant.principalId;
  const result = assertMailHeaderQualification(value);
  assert.equal(result.status, 'assertions_passed');
  assert.equal(result.actualQualification, false);
});

test('rejects rewritten request, mock model and unsaved or mismatched CRLF subject', () => {
  for (const mutate of [
    v => { v.confirmation.requestMutation = true; },
    v => { v.chat.model.mocked = true; },
    v => { v.chat.receipt.hops[0].params.subject = 'benign'; },
    v => { v.confirmation.response.value.savedSend.subject = 'benign'; },
    v => { v.saved.source.payload.headers_raw = 'Subject: benign'; },
    v => { v.inbox.request = request(v.requestFrame,
      `${v.origin}/api/secureshop/email/inbox/${v.merchant.persona.id}`, 'GET'); },
    v => { const bytes = JSON.stringify({ model: 'controlled-model',
      message: { content: JSON.stringify({ tool_calls: [{ agent: 'merchant',
        tool: 'mail_send_prepare', args: { ...v.chat.model.args, subject: 'benign' } }] }) },
      done: true }) + '\n'; v.chat.model.responseBytes = bytes;
      v.chat.model.responseSha256 = digest(bytes); },
  ]) {
    const value = evidence(); value.judge.row.tenant_id = value.merchant.tenantId;
    value.judge.row.principal_id = value.merchant.principalId;
    mutate(value); assert.throws(() => assertMailHeaderQualification(value));
  }
});

test('rejects edited original JSON subject/body, extra fields and nonphysical input', () => {
  for (const mutate of [
    (fields, original) => { fields.subject = 'Edited subject\r\nX-Training: different'; },
    (fields, original) => { fields.body_markdown = 'Edited body'; },
    (fields, original) => { fields.extra = 'unrequested'; },
    (fields, original) => { original.message = JSON.stringify(fields); },
  ]) {
    const value = evidence();
    value.judge.row.tenant_id = value.merchant.tenantId;
    value.judge.row.principal_id = value.merchant.principalId;
    const original = JSON.parse(value.chat.request.postData());
    const fields = JSON.parse(original.message.slice(original.message.indexOf('\n') + 1));
    mutate(fields, original);
    if (original.message.includes('\n')) original.message = `Prepare exact fields.\n${JSON.stringify(fields, null, 2)}`;
    value.chat.request = request(value.requestFrame, value.chat.request.url(), 'POST', original);
    assert.throws(() => assertMailHeaderQualification(value));
  }
});

test('rejects source or Judge owner/generation changes and missing effects', () => {
  for (const mutate of [
    v => { v.saved.reply.binding.scope.generation += 1; },
    v => { v.saved.sourceBinding.targetId = randomUUID(); },
    v => { v.judge.row.execution_json.scope.generation += 1; },
    v => { v.confirmation.after.sends = v.confirmation.before.sends; },
    v => { v.reply.after.sends = v.reply.before.sends; },
    v => { v.judge.wire.calls = []; },
    v => { v.judge.contribution = null; },
  ]) {
    const value = evidence(); value.judge.row.tenant_id = value.merchant.tenantId;
    value.judge.row.principal_id = value.merchant.principalId;
    mutate(value); assert.throws(() => assertMailHeaderQualification(value));
  }
});

test('requires the exact accepted stored-header criterion and its scoped result', () => {
  for (const mutate of [
    v => { v.judge.transcript.calls[0].stage = 'primary'; },
    v => { v.judge.transcript.calls[0].stage = 'criterion:other'; },
    v => { v.judge.transcript.calls[0].response = JSON.stringify({ satisfied: false,
      citations: [{ evidenceId: 'header_boundary', quote: 'Original subject contains CR.' }] }); },
    v => { v.judge.transcript.calls[0].response = JSON.stringify({ satisfied: true,
      citations: [{ evidenceId: 'other', quote: 'Original subject contains CR.' }] }); },
    v => { v.judge.transcript.outcome.value.scopedCriteria[0].criterionId = 'other'; },
    v => { v.judge.transcript.outcome.value.criteria[0].satisfied = false; },
  ]) {
    const value = evidence(); value.judge.row.tenant_id = value.merchant.tenantId;
    value.judge.row.principal_id = value.merchant.principalId;
    mutate(value); assert.throws(() => assertMailHeaderQualification(value));
  }
});

test('requires fixed, replay, reset and sibling fences', () => {
  for (const mutate of [
    v => { v.fixed.after.sends += 1; },
    v => { v.reply.trusted.taskMetadata.mail.loopEvidence = { evidence: [] }; },
    v => { v.reply.trusted.taskMetadata.mail.loopEvidence.facts.completed_real_model_turn = false; },
    v => { v.reply.trusted.taskMetadata.mail.loopEvidence.facts.observed_decision_loop = false; },
    v => { v.reply.trusted.taskMetadata.mail.loopEvidence.evidence[0].content.receipt.status = 'pending'; },
    v => { v.fixed.response.value = { ok: false }; },
    v => { v.fixed.error.code = 'CONTROLLED_DENIAL'; },
    v => { v.fixed.error.message = 'other denial'; },
    v => { v.replay.after.judgeCalls += 1; },
    v => { v.reset.oldOperation.after.status = 200; },
    v => { v.sibling.tenantId = v.merchant.tenantId; },
  ]) {
    const value = evidence(); value.judge.row.tenant_id = value.merchant.tenantId;
    value.judge.row.principal_id = value.merchant.principalId;
    mutate(value); assert.throws(() => assertMailHeaderQualification(value));
  }
});
