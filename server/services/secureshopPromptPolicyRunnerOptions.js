'use strict';

// Trusted composition adapter; no request body can supply the repository or
// replace the current-persona authority required by the bound runner.
function promptPolicyRunnerOptions(repository, personaAuthority, taskOptions) {
  let recipient;
  if (taskOptions !== undefined) {
    const { RECIPIENTS } = require('./secureshopPromptPolicyTaskSnapshot');
    if (!taskOptions || typeof taskOptions !== 'object' || Array.isArray(taskOptions)
      || Object.keys(taskOptions).join(',') !== 'recipient'
      || (taskOptions.recipient !== null && (typeof taskOptions.recipient !== 'string'
        || !Object.hasOwn(RECIPIENTS, taskOptions.recipient)))) throw new TypeError('Trusted policy recipient required');
    recipient = taskOptions.recipient;
  }
  if (repository === undefined) return Object.freeze({});
  if (typeof repository?.admitRunSnapshot !== 'function' || typeof personaAuthority?.capture !== 'function') {
    throw new TypeError('Prompt policy repository and persona authority required');
  }
  return Object.freeze({ promptPolicyAdmission: input => repository.admitRunSnapshot(structuredClone(input)),
    ...(taskOptions === undefined ? {} : { promptPolicyRecipient: recipient }) });
}

module.exports = { promptPolicyRunnerOptions };
