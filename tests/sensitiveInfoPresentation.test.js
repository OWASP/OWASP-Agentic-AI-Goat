'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readSensitiveInfoPresentation } = require('../server/services/sensitiveInfoPresentation');

test('canonical progress returns solution-gated SSRF metadata without initialization side effects', async () => {
  const calls = [];
  const result = await readSensitiveInfoPresentation({
    platformStores: {
      progress: { getWorkshopProgress: async (user, key) => {
        calls.push(['progress', user, key]);
        return { objectives: [{ id: 'ssrf_internal', label: 'Internal', completed: false }] };
      } },
      config: { getSnapshot: async () => ({ exercises: { sensitive_info_disclosure: { objectives: {
        ssrf_internal: { solutionVisible: true }, ssrf_ollama: { solutionVisible: false },
      } } } }) },
    },
    userId: 'owner-1', workshopKey: 'sensitive_info_disclosure',
    objectives: [{ id: 'ssrf_internal', desc: 'canonical description' }],
    getSsrfExamples: gates => ({ target: gates }),
  });
  assert.deepEqual(calls, [['progress', 'owner-1', 'sensitive_info_disclosure']]);
  assert.deepEqual(result.solutionStatus, { ssrf_internal: true, ssrf_ollama: false });
  assert.deepEqual(result.ssrfExamples, { target: result.solutionStatus });
  assert.equal(result.progress[0].desc, 'canonical description');
});
