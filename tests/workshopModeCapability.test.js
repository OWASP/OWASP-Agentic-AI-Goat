'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { projectWorkshopModeCapability, rawModeForUi } = require('../server/services/workshopModeCapability');

test('mode projection preserves canonical values and gives the UI a normalized label', () => {
  const finflow = projectWorkshopModeCapability('sensitive_info_disclosure', 'vulnerable');
  assert.equal(finflow.mode, 'vulnerable');
  assert.equal(finflow.effectiveMode, 'vuln');
  assert.deepEqual(finflow.allowedModes, ['fixed', 'vulnerable']);
  assert.deepEqual(finflow.selectableModes, ['fixed', 'vuln']);
  assert.equal(rawModeForUi('sensitive_info_disclosure', 'vuln'), 'vulnerable');
  assert.equal(rawModeForUi('sql_injection_workshop', 'vuln'), 'vuln');
  assert.deepEqual(projectWorkshopModeCapability('csrf_workshop', null).supportedObjectiveIds, require('../server/services/csrfVictimSandbox').ALL_OBJECTIVES);
});

test('fixed capability is scoped to the implemented lesson surface', () => {
  const dpi = projectWorkshopModeCapability('direct_prompt_injection', 'vuln');
  assert.deepEqual(dpi.scope, { kind: 'workshop', id: 'direct_prompt_injection' });
  assert.deepEqual(dpi.supportedObjectiveIds,
    ['interact','system_prompt','jailbreak','multi_language','virtualization','role_playing','side_stepping','obfuscation']);
  for (const key of ['xss_workshop', 'xss_email_builder', 'indirect_prompt_injection', 'mcp_workshop', 'legacy_sensitive_file_ssi']) {
    const result = projectWorkshopModeCapability(key, null);
    assert.equal(result.effectiveMode, 'vuln');
    assert.equal(result.fixedSupported, true);
    assert.deepEqual(result.selectableModes, ['vuln', 'fixed']);
    assert.deepEqual(result.allowedModes, ['vuln', 'fixed']);
    assert.equal(result.reason, null);
  }
  assert.deepEqual(projectWorkshopModeCapability('mcp_workshop', 'fixed').scope,
    { kind: 'chat', id: 'mcp_assistant' });
  assert.deepEqual(projectWorkshopModeCapability('indirect_prompt_injection', null).supportedObjectiveIds,
    ['rag_injected_doc', 'email_understand_defense']);
  const shop = projectWorkshopModeCapability('secureshop_agent_security', 'vuln');
  assert.equal(shop.fixedSupported, false);
  assert.deepEqual(shop.scope, { kind: 'registered_feature', id: 'secureshop_v2' });
  assert.deepEqual(shop.selectableModes, ['vuln']);
  assert.equal(rawModeForUi('mcp_workshop', 'fixed'), 'fixed');
});
