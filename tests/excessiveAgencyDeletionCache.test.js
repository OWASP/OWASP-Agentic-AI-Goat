'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createPostgresExcessiveAgencyAttendeeLabStore } = require('../server/services/excessiveAgencyAttendeeLabStore');
test('deletion drains pending initialization, evicts cache and prevents local recreation', async () => {
  let finish;
  const pending = new Promise(resolve => { finish = resolve; });
  const calls = [];
  const store = createPostgresExcessiveAgencyAttendeeLabStore({
    manager: {
      forAttendee: async key => ({ ensureSeeded: async () => { calls.push(['seed',key]); if(key==='1')await pending; }, conversations:{} }),
      destroyAttendee: async key => { calls.push(['destroy',key]); return {removed:1}; },
    }, createToolRouter: () => ({}),
  });
  await store.getOrCreate('2');
  const loading = store.getOrCreate('1');
  const rejected = assert.rejects(loading, {code:'ATTENDEE_DELETED'});
  const deleted = store.destroyAttendee('1');
  await assert.rejects(store.getOrCreate('1'), {code:'ATTENDEE_DELETED'});
  assert.ok(!calls.some(([name])=>name==='destroy'));
  finish(); await rejected; await deleted;
  assert.equal(store.attendeeCount,1);
  assert.equal((await store.getOrCreate('2')).platformUserId,'2');
  await assert.rejects(store.getOrCreate('1'), {code:'ATTENDEE_DELETED'});
  assert.deepEqual(calls.at(-1),['destroy','1']);
});

test('bulk reset drains pending seeding and prevents stale cache publication', async () => {
  let finish;
  const pending = new Promise(resolve => { finish = resolve; });
  let resets = 0, seeds = 0;
  const store = createPostgresExcessiveAgencyAttendeeLabStore({
    manager: {
      forAttendee: async () => ({ ensureSeeded: async () => { seeds++; await pending; }, conversations:{} }),
      resetAll: async () => { resets++; },
    }, createToolRouter: () => ({}),
  });
  const first = store.getOrCreate('1');
  const checked = assert.rejects(first, {code:'LAB_RESET_PENDING'});
  const reset = store.resetAll();
  const duplicate = store.resetAll();
  await assert.rejects(store.getOrCreate('2'), {code:'LAB_RESET_PENDING'});
  assert.equal(resets,0);
  finish();
  await Promise.all([checked,reset,duplicate]);
  assert.equal(resets,1);
  assert.equal(store.attendeeCount,0);
  await store.getOrCreate('1');
  assert.equal(seeds,2);
  assert.equal(store.attendeeCount,1);
});

test('unknown session lookup and logout never seed an attendee or populate cache', async () => {
  const calls = [];
  const store = createPostgresExcessiveAgencyAttendeeLabStore({
    manager: { forAttendee: async key => ({
      ensureSeeded: async () => { throw Error('Session lookup must not create teaching fixtures'); },
      resolveSession: async token => { calls.push(['lookup',key,token]); return null; },
      deleteSession: async token => { calls.push(['logout',key,token]); },
    }) }, createToolRouter: () => { throw Error('No router needed for a missing session'); },
  });
  assert.equal(await store.resolveSession('missing','17'),null);
  await store.deleteSession('missing','17');
  assert.equal(store.attendeeCount,0);
  assert.deepEqual(calls,[['lookup','17','missing'],['logout','17','missing']]);
});
