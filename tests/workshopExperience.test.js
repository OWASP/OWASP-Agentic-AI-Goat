'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const load = () => import('../client/src/components/workshop/experience.mjs');

test('two template definitions distinguish scenarios from canonical objectives', async () => {
  const { defineWorkshop, directPromptInjectionExperience: dpi, indirectPromptInjectionExperience: ipi } = await load();
  assert.equal(dpi.scenarios.length, 1);
  assert.equal(ipi.scenarios.length, 2);
  assert.throws(() => defineWorkshop({ ...dpi, scenarios: ipi.scenarios }), /Scenario count/);
  assert.throws(() => defineWorkshop({ ...ipi, scenarios: [ipi.scenarios[0], ipi.scenarios[0]] }), /unique/);
  assert.throws(() => defineWorkshop({ ...dpi, scenarios: [{ ...dpi.scenarios[0], objectiveSource: 'hardcoded' }] }), /Canonical/);
  assert.equal(Object.isFrozen(ipi.scenarios[0]), true);
});

test('scenario reset invalidates stale completion without touching sibling or another attendee', async () => {
  const { createScenarioFence } = await load();
  const fence = createScenarioFence();
  const rag = { attendeeId: 1, workshopKey: 'ipi', scenarioId: 'document' };
  const stale = fence.capture(rag);
  const email = fence.capture({ ...rag, scenarioId: 'email' });
  const other = fence.capture({ ...rag, attendeeId: 2 });
  fence.invalidate(rag);
  assert.equal(stale.isCurrent(), false);
  assert.equal(fence.capture(rag).isCurrent(), true);
  assert.equal(email.isCurrent(), true);
  assert.equal(other.isCurrent(), true);
});
