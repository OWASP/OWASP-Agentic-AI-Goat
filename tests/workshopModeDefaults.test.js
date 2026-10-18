'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

test('catalog preserves exact defaults and allowed modes including staged SecureShop', () => {
  const { WORKSHOP_MODE_CATALOG, resolveWorkshopModeConfig } = require('../server/services/workshopModeService');
  assert.deepEqual(Object.keys(WORKSHOP_MODE_CATALOG).sort(), [
    'csrf_workshop',
    'direct_prompt_injection',
    'excessive_agency',
    'indirect_prompt_injection',
    'legacy_sensitive_file_ssi',
    'mcp_workshop',
    'nosql_injection_workshop',
    'secureshop_agent_security',
    'sensitive_info_disclosure',
    'sql_injection_workshop',
    'supply_chain_rce',
    'xss_email_builder',
    'xss_workshop',
  ]);
  assert.deepEqual(resolveWorkshopModeConfig('csrf_workshop'), {defaultMode:null,allowedModes:['vuln','fixed'],fixedObjectiveIds:require('../server/services/csrfVictimSandbox').ALL_OBJECTIVES});
  assert.deepEqual(resolveWorkshopModeConfig('direct_prompt_injection'), {defaultMode:'vuln',allowedModes:['vuln','fixed'],
    fixedObjectiveIds:['interact','system_prompt','jailbreak','multi_language','virtualization','role_playing','side_stepping','obfuscation']});
  assert.deepEqual(resolveWorkshopModeConfig('sql_injection_workshop'), { defaultMode: 'fixed', allowedModes: ['fixed', 'vuln'] });
  assert.deepEqual(resolveWorkshopModeConfig('nosql_injection_workshop'), { defaultMode: 'fixed', allowedModes: ['fixed', 'vuln'] });
  assert.deepEqual(resolveWorkshopModeConfig('sensitive_info_disclosure'), { defaultMode: 'vulnerable', allowedModes: ['fixed', 'vulnerable'] });
  assert.deepEqual(resolveWorkshopModeConfig('supply_chain_rce'), { defaultMode: 'vulnerable', allowedModes: ['fixed', 'vulnerable'] });
  assert.deepEqual(resolveWorkshopModeConfig('excessive_agency'), { defaultMode: 'fixed', allowedModes: ['fixed', 'vuln'] });
  assert.deepEqual(resolveWorkshopModeConfig('secureshop_agent_security'), { defaultMode: 'vuln', allowedModes: ['fixed', 'vuln'] });
  for (const key of ['xss_workshop', 'xss_email_builder', 'mcp_workshop', 'legacy_sensitive_file_ssi']) {
    assert.deepEqual(resolveWorkshopModeConfig(key), { defaultMode: null, allowedModes: ['vuln', 'fixed'] });
  }
  assert.deepEqual(resolveWorkshopModeConfig('indirect_prompt_injection'), {
    defaultMode: null, allowedModes: ['vuln', 'fixed'],
    fixedObjectiveIds: ['rag_injected_doc', 'email_understand_defense'] });
  assert.throws(() => resolveWorkshopModeConfig('made_up'), /Unsupported workshop/);
  assert.ok(Object.isFrozen(WORKSHOP_MODE_CATALOG));
});

test('a transient initialization failure is retried on the next request', async () => {
  const { createWorkshopModeService } = require('../server/services/workshopModeService');
  let attempts = 0;
  const service = createWorkshopModeService({
    async initialize() {
      attempts += 1;
      if (attempts === 1) throw new Error('temporary database lock');
    },
    async getMode({ defaultMode }) { return defaultMode; },
    async setMode() {},
  });

  await assert.rejects(
    service.getMode({ userId: 1, workshopKey: 'sql_injection_workshop' }),
    /temporary database lock/
  );
  assert.equal(await service.getMode({ userId: 1, workshopKey: 'sql_injection_workshop' }), 'fixed');
  assert.equal(attempts, 2);
});

test('setting an effective fixed default does not require a persisted mode row', async () => {
  const { createWorkshopModeService } = require('../server/services/workshopModeService');
  const rows = new Map(); const writes = [];
  const service = createWorkshopModeService({
    async initialize() {},
    async getMode({ userId, workshopKey, defaultMode }) { return rows.get(`${userId}/${workshopKey}`) ?? defaultMode; },
    async setMode({ userId, workshopKey, mode }) { writes.push(mode); rows.set(`${userId}/${workshopKey}`, mode); },
  });
  const owner = { userId: 19, workshopKey: 'sql_injection_workshop' };
  assert.equal(await service.setMode({ ...owner, mode: 'fixed' }), 'fixed');
  assert.equal(rows.size, 0); assert.deepEqual(writes, []);
  assert.equal(await service.setMode({ ...owner, mode: 'vuln' }), 'vuln');
  assert.equal(await service.setMode({ ...owner, mode: 'fixed' }), 'fixed');
  assert.equal(await service.getMode(owner), 'fixed'); assert.deepEqual(writes, ['vuln', 'fixed']);
});

test('newly selectable families preserve null canonical scope until first selection', async () => {
  const { createWorkshopModeService } = require('../server/services/workshopModeService');
  const persisted=[];
  const service = createWorkshopModeService({
    async initialize() {},
    async getMode({ defaultMode }) { return defaultMode; },
    async setMode(input) { persisted.push(input); },
  });
  for (const workshopKey of ['xss_workshop', 'xss_email_builder', 'indirect_prompt_injection', 'mcp_workshop', 'legacy_sensitive_file_ssi']) {
    assert.equal(await service.getMode({ userId: 7, workshopKey }), null);
    await service.setMode({ userId: 7, workshopKey, mode: 'fixed' });
    await service.setMode({ userId: 7, workshopKey, mode: 'vuln' });
  }
  assert.equal(persisted.length, 10);
});
