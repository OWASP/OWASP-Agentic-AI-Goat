'use strict';
// Sequential GET/POST work: at most two 30s decisions, one 30s narration,
// and one 90s Judge evaluation (including its internal repair). Browser
// observation and storage overhead must fit outside those model budgets.
function htmlSummaryTimeoutMs(env = process.env) {
  const value = env.CSRF_HTML_SUMMARY_TIMEOUT_MS;
  if (value === undefined) return 25000;
  if (typeof value !== 'string' || !/^\d+$/.test(value)) {
    throw new TypeError('CSRF HTML summary timeout must be a decimal millisecond value');
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1000 || parsed > 55000) {
    throw new RangeError('CSRF HTML summary timeout must be between 1000 and 55000 milliseconds');
  }
  return parsed;
}
module.exports=Object.freeze({decisionAttempts:2,decisionMs:30000,phraseMs:30000,htmlSummaryMs:htmlSummaryTimeoutMs(),htmlSummaryTimeoutMs,judgeMs:90000,
 browserMs:120000,workflowMs:225000,ownerMs:240000,observerMs:270000});
