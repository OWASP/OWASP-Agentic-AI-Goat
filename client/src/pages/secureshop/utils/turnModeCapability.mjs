export function trustedTurnMode(value) {
  if (value?.version !== 1 || !['vuln', 'fixed'].includes(value.effectiveMode)
    || typeof value.featureId !== 'string' || !/^[a-z][a-z0-9_]*$/.test(value.featureId)
    || typeof value.policyVersion !== 'string' || !value.policyVersion
    || value.scope?.kind !== 'launch_feature' || value.scope.id !== value.featureId) return null;
  return value;
}

export function isFixedTurn(value) { return trustedTurnMode(value)?.effectiveMode === 'fixed'; }
