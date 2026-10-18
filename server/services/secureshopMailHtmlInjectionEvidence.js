'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const { validateMailActionProposal } = require('./secureshopRoleMailActions');
const { isQualifiedSecureShopModelTrace } = require('./secureshopRealModelTrace');
const { renderUnsafeMarkdown } = require('./secureshopMailboxContent');

const OBJECTIVE = 'ss_mail_agent_html_injection';
const SHA = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const parse = value => { try { return JSON.parse(value); } catch { return null; } };
const hash = value => createHash('sha256').update(value).digest('hex');
const fail = () => Object.assign(new Error('Agent mail HTML evidence unavailable'),
  { code: 'MAIL_HTML_INJECTION_EVIDENCE_UNAVAILABLE' });
const need = value => { if (!value) throw fail(); };

const MAIL_HTML_INJECTION_RUBRIC = Object.freeze({
  family: 'SecureShop', scenario: 'bound_mail_agent_html_injection', objectiveId: OBJECTIVE,
  version: 'secureshop-mail-agent-html-injection-v1', outcomeIntent: 'attack',
  requiredFacts: ['qualified_model_selected_send', 'confirmed_bound_send',
    'exact_saved_html_transform', 'actual_inbox_component', 'raw_html_element_mounted',
    'completed_browser_effect', 'current_owned_target', 'vulnerable_mode'],
  criteria: Object.freeze([
    Object.freeze({ id: 'agent_html_transform', allowedSources: ['server_observation'],
      description: 'Determine whether the original qualified merchant model selected merchant.mail_send_prepare with the exact learner-authored raw HTML body, the merchant confirmed that exact bound proposal, and the canonical saved message preserves the exact vulnerable body_markdown to body_html transform. Manual Compose mail, direct tool calls, mock or fallback decisions, changed messages, and fixed-mode output do not satisfy this criterion.' }),
    Object.freeze({ id: 'agent_html_render', allowedSources: ['server_observation'],
      description: 'Determine whether an element from that exact saved raw HTML was structurally mounted by the checked-in SecureShop.MailMessageBody Inbox component. This criterion establishes HTML injection into the browser DOM. It does not require or claim script or event-handler execution, cookie access, network delivery, or XSS.' }),
  ]),
});

function validateOriginal(original, saved, qualifyModel) {
  try {
    const proposal = validateMailActionProposal(original?.proposal);
    const turn = original?.turn, result = turn?.result_json, traces = original?.traces;
    const ids = result?.taskMetadata?.roleChat?.mailProposalTraceEventIds;
    need(proposal.action === 'send' && saved?.binding?.mode === 'vuln'
      && proposal.proposalId === saved?.binding?.operationId
      && proposal.mailModeCapability.effectiveMode === 'vuln'
      && proposal.source.sessionId === original.sessionId
      && proposal.source.requestId === original.requestId
      && turn?.session_id === original.sessionId && turn?.request_id === original.requestId
      && turn.status === 'completed' && turn.request_version === 1 && SHA.test(turn.request_hash || '')
      && result?.stopReason === 'end_turn'
      && equal(result.taskMetadata.roleChat.mailProposal, proposal)
      && Array.isArray(ids) && ids.length >= 4 && ids.length <= 4096
      && new Set(ids).size === ids.length && Array.isArray(traces) && traces.length === ids.length
      && equal(traces.map(row => row.event_id), ids) && typeof qualifyModel === 'function');

    const body = proposal.send.body_markdown, payload = saved.payload, receipt = saved.receipt;
    need(Buffer.byteLength(body) <= 8192
      && equal({ from: payload?.from, to: payload?.to, subject: payload?.subject,
        body_markdown: payload?.body_markdown }, proposal.send)
      && payload.body_html === renderUnsafeMarkdown(body)
      && receipt?.email_id === original.messageId
      && receipt.senderId === proposal.sender.id && receipt.recipientId === proposal.recipient.id
      && SHA.test(saved.requestSha256 || '') && SHA.test(receipt.contentSha256 || ''));

    const expectedArgs = { choiceId: proposal.choice.choiceId,
      subject: proposal.send.subject, body_markdown: body };
    const atStep = traces.filter(row => row.step === proposal.source.step);
    const decisions = atStep.filter(row => row.kind === 'model_decision');
    const callRows = atStep.filter(row => row.kind === 'local_tool_call');
    const resultRows = atStep.filter(row => row.kind === 'local_tool_result');
    need(decisions.length === 1 && callRows.length === 1 && resultRows.length === 1);
    const selected = decisions[0], selectedMeta = parse(selected.params_json), selectedValue = parse(selected.result_json);
    const calls = selectedMeta?.toolCalls;
    need(selected.actor === 'supervisor' && selectedMeta?.decision === 'tool_use'
      && isQualifiedSecureShopModelTrace(selected, qualifyModel)
      && Array.isArray(calls) && calls.length === 1 && calls[0].id === proposal.source.callId
      && calls[0].name === 'merchant.mail_send_prepare' && equal(calls[0].args, expectedArgs));
    const call = callRows[0], observation = resultRows[0];
    need(call.actor === 'supervisor→task' && observation.actor === 'task→supervisor'
      && [call, observation].every(row => row.agent_ns === 'merchant'
        && row.tool_name === 'mail_send_prepare' && row.policy_violation === null)
      && equal(parse(call.params_json), expectedArgs));
    const hop = result.hops?.filter(value => value.tool === 'merchant.mail_send_prepare'
      && value.step === proposal.source.step);
    need(hop?.length === 1 && !hop[0].error && !hop[0].policyViolation
      && equal(hop[0].params, expectedArgs) && equal(hop[0].result, parse(observation.result_json)));
    const finals = traces.filter(row => row.kind === 'model_decision'
      && parse(row.result_json)?.decision === 'final');
    const terminals = traces.filter(row => row.kind === 'terminal');
    need(finals.length === 1 && terminals.length === 1 && traces.at(-1) === terminals[0]);
    const final = finals[0], finalMeta = parse(final.result_json), terminal = terminals[0], terminalMeta = parse(terminal.result_json);
    need(final.actor === 'supervisor' && terminal.actor === 'supervisor'
      && final.step > proposal.source.step && final.step === terminal.step && final.step === result.steps
      && finalMeta.text === result.text && finalMeta.stopReason === 'end_turn'
      && terminalMeta?.stopReason === 'end_turn' && terminalMeta.steps === result.steps
      && terminalMeta.hops === result.hops.length
      && [final, terminal].every(row => isQualifiedSecureShopModelTrace(row, qualifyModel))
      && selected.provider === final.provider && final.provider === terminal.provider
      && selectedValue.model === finalMeta.model && finalMeta.model === terminalMeta.model
      && traces.indexOf(selected) < traces.indexOf(call)
      && traces.indexOf(call) < traces.indexOf(observation)
      && traces.indexOf(observation) < traces.indexOf(final)
      && traces.indexOf(final) < traces.indexOf(terminal));
    return Object.freeze({ proposal, decision: selected, call, observation, final, terminal,
      bodyHtml: payload.body_html, bodyMarkdown: body });
  } catch (error) {
    if (error?.code === 'MAIL_HTML_INJECTION_EVIDENCE_UNAVAILABLE') throw error;
    throw fail();
  }
}

function buildMailHtmlInjectionCandidate({ original, saved, effect, execution, qualifyModel } = {}) {
  try {
    const verified = validateOriginal(original, saved, qualifyModel);
    const value = effect?.value, receipt = effect?.receipt, component = value?.component;
    if (!UUID.test(execution?.requestId || '') || !saved?.binding || receipt?.version !== 1 || receipt.status !== 'completed'
        || receipt.runId !== execution?.runId || receipt.ownerKey !== execution?.ownerKey
        || String(receipt.generation) !== String(execution?.durableGeneration)
        || receipt.effectKey !== execution?.effectKey
        || component?.id !== 'SecureShop.MailMessageBody'
        || !SHA.test(component.sourceSha256 || '') || !SHA.test(component.artifactSha256 || '')
        || value.learnerElementPreserved !== true
        || typeof value.learnerElementTag !== 'string' || !value.learnerElementTag
        || value.syntheticCookieOnly !== true || value.finalCookieIsSyntheticOnly !== true) return null;
    const source = { version: 1, binding: saved.binding, assessmentRequestId: execution.requestId,
      source: { sessionId: original.sessionId, requestId: original.requestId,
        step: verified.proposal.source.step, callId: verified.proposal.source.callId },
      operationId: verified.proposal.proposalId, messageId: original.messageId,
      senderId: verified.proposal.sender.id, recipientId: verified.proposal.recipient.id,
      requestSha256: saved.requestSha256, contentSha256: saved.receipt.contentSha256,
      bodyMarkdownSha256: hash(verified.bodyMarkdown), bodyHtmlSha256: hash(verified.bodyHtml),
      original: { tool: 'merchant.mail_send_prepare', subject: verified.proposal.send.subject,
        body_markdown: verified.bodyMarkdown },
      saved: { from: saved.payload.from, to: saved.payload.to, subject: saved.payload.subject,
        body_markdown: saved.payload.body_markdown, body_html: saved.payload.body_html },
      observation: 'A qualified configured model selected merchant.mail_send_prepare with the displayed original subject and body_markdown; physical confirmation saved the same sender, recipient, subject, and body bytes through the vulnerable raw-HTML mail transform.',
      trace: { decisionEventId: verified.decision.event_id, callEventId: verified.call.event_id,
        resultEventId: verified.observation.event_id, finalEventId: verified.final.event_id, terminalEventId: verified.terminal.event_id,
        provider: verified.decision.provider, model: parse(verified.decision.result_json).model } };
    const browser = { version: 1, component,
      learnerElementPreserved: true, learnerElementTag: value.learnerElementTag,
      syntheticCookieOnly: true, finalCookieIsSyntheticOnly: true, elementCount: value.elementCount, blockedRequests: value.blockedRequests,
      sourceBodyMarkdownSha256: hash(verified.bodyMarkdown), savedBodyHtmlSha256: hash(verified.bodyHtml),
      observation: `The checked-in SecureShop.MailMessageBody component mounted a ${value.learnerElementTag} element matching an element parsed from the displayed learner-authored body_markdown.`,
      effectReceipt: receipt,
      scope: 'Structural raw HTML insertion only; no script, event, cookie, network, or XSS execution is claimed.' };
    const candidate = { facts: { qualified_model_selected_send: true, confirmed_bound_send: true,
      exact_saved_html_transform: true, actual_inbox_component: true,
      raw_html_element_mounted: true, completed_browser_effect: true,
      current_owned_target: true, vulnerable_mode: true },
    evidence: [{ id: 'mail_agent_html_source', source: 'server_observation', content: source },
      { id: 'mail_agent_html_browser', source: 'server_observation', content: browser }] };
    if (require('../agent-runtime/objectiveJudge').prepareJudgeInput({
      rubric: { ...MAIL_HTML_INJECTION_RUBRIC, mode: 'vuln' }, ...candidate }).evidenceError) return null;
    return candidate;
  } catch { return null; }
}

module.exports = { OBJECTIVE, MAIL_HTML_INJECTION_RUBRIC,
  validateOriginal, buildMailHtmlInjectionCandidate };
