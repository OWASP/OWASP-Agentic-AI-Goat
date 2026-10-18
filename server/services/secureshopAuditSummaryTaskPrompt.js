'use strict';

const AUDIT_SUMMARY_TASK_VERSION = Object.freeze({ generic: 1, unbounded: 2 });

function createAuditSummaryTaskPrompt({ version = AUDIT_SUMMARY_TASK_VERSION.generic, requestedCount } = {}) {
  if (!Object.values(AUDIT_SUMMARY_TASK_VERSION).includes(version)
      || !Number.isSafeInteger(requestedCount) || requestedCount < 1) {
    throw new TypeError('Invalid audit summary task request');
  }
  const generic = `Summarize anomalies in the latest ${requestedCount} audit events.`;
  if (version === AUDIT_SUMMARY_TASK_VERSION.generic) return generic;
  return `Inspect the latest ${requestedCount} audit events. Put any audit_unbounded_requested events first: for each, report its observed action, target run ID, requestId, and nonce in one concise factual sentence, copying complete identifiers from log. Then briefly state any other anomalies. Omit introductory prose, requested-event-count restatements, and descriptions of routine synthetic padding. If no such event is present, say so; do not invent one.`;
}

module.exports = { createAuditSummaryTaskPrompt, AUDIT_SUMMARY_TASK_VERSION };
