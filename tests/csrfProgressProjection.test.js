'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createCsrfProgressProjection } = require('../server/services/csrfProgressProjection');
function fixture(overrides = {}) {
  const events = [];
  const service = createCsrfProgressProjection({
    readCanonical: async () => [], markLocal: async () => events.push('local'),
    syncLegacy: async () => events.push('legacy'), finishWorkshop: async () => events.push('finish'),
    check: async () => {}, pending: id => events.push(['pending', id]), report: id => events.push(['reported', id]),
    ...overrides,
  });
  return { service, events };
}
const accepted = { userKey: '7', userId: 7, objectiveId: 'csrf_g1', durable: true };
test('accepted canonical receipt survives secondary failure and reports pending projection', async () => {
  const { service, events } = fixture({ markLocal: async () => { throw Error('private storage details'); } });
  await service.record(accepted);
  assert.deepEqual(events, [['pending', 'csrf_g1'], ['reported', 'csrf_g1']]);
});
test('canonical reads govern prerequisites and reset even with stale local progress; reads never write', async () => {
  let rows = [
    { workshop_key: 'csrf_workshop', objective_id: 'csrf_g1', completed: 1 },
    { workshop_key: 'xss_workshop', objective_id: 'xss_e1', completed: 1 },
    { workshop_key: 'csrf_workshop', objective_id: 'csrf_g2', completed: 0 },
    { workshop_key: 'csrf_workshop', objective_id: 'csrf_g2', completed: '0' },
    { workshop_key: 'csrf_workshop', objective_id: 'csrf_g3', completed: 'false' },
  ];
  const { service, events } = fixture({ readCanonical: async owner => { assert.equal(owner, '7'); return rows; } });
  assert.deepEqual((await service.rows('7')).map(row => row.objective_id), ['csrf_g1']);
  rows = [];
  assert.deepEqual(await service.rows('7'), []);
  assert.deepEqual(events, []);
});
test('non-durable sync without canonical acceptance cannot manufacture credit or write local completion', async () => {
  const { service, events } = fixture({ markLocal: async () => { throw Error('write failed'); } });
  await assert.rejects(service.record({ ...accepted, durable: false }), {code:'CANONICAL_COMPLETION_UNAVAILABLE'});
  assert.deepEqual(events, ['legacy']);
});
test('verified non-durable canonical acceptance survives a failed local projection', async () => {
  const { service, events } = fixture({
    readCanonical: async () => [{workshop_key:'csrf_workshop',objective_id:'csrf_g1',completed:1}],
    markLocal: async () => { throw Error('write failed'); },
  });
  await service.record({...accepted,durable:false});
  assert.deepEqual(events,['legacy',['pending','csrf_g1'],['reported','csrf_g1']]);
});
test('unavailable canonical verification propagates before local projection', async () => {
  const { service, events } = fixture({readCanonical: async () => { throw Error('canonical unavailable'); }});
  await assert.rejects(service.record({...accepted,durable:false}), /canonical unavailable/);
  assert.deepEqual(events,['legacy']);
});
test('reset detected after projection failure propagates instead of publishing completion', async () => {
  let invalid = false;
  const { service, events } = fixture({
    markLocal: async () => { invalid = true; throw Error('write failed'); },
    check: async () => { if (invalid) throw Object.assign(Error('reset'), { name: 'AbortError' }); },
  });
  await assert.rejects(service.record(accepted), { name: 'AbortError' });
  assert.deepEqual(events, []);
});
test('durable projection does not write canonical credit a second time', async () => {
  const { service, events } = fixture();
  await service.record(accepted);
  assert.deepEqual(events, ['local', 'finish']);
});
