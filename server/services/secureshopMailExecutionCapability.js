'use strict';

// These single-use capabilities are issued only at the runner's known stages.
// Request data and an error's code or message cannot create a receipt.
const issued = new WeakMap();
const stages = new Set(['thread_admission','thread_admission_rejected',
  'prompt_policy_admission_rejected']);
function issueMailExecutionCapability(stage, value) {
  if (!stages.has(stage) || !value || typeof value !== 'object') throw TypeError('Mail stage unavailable');
  const token = Object.freeze({});
  issued.set(token, Object.freeze({ stage, ...value }));
  return token;
}
function consumeMailExecutionCapability(token, stage) {
  const value = issued.get(token);
  if (!value || value.stage !== stage) throw TypeError('Mail stage unavailable');
  issued.delete(token);
  return value;
}
module.exports = { issueMailExecutionCapability, consumeMailExecutionCapability };
