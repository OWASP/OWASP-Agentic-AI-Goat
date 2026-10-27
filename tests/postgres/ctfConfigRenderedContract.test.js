'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { KEYS, FACTS, EXCLUDED, LIMITS, proposedValue, configRow,
  waitConfigRow, assertConfigDatabaseName, assertConfigTransition,
  assertCtfConfigReceipt } = require('./support/ctfConfigRenderedCases');

const id = n => `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
function operation(index) {
  return { originalStatus: 200, resolvedStatus: 200, sameIdGets: 0,
    operationId: id(index), sequence: String(index), browserAckOperationId: null,
    ackMessage: 'Configuration updated successfully' };
}
function receipt() {
  return { version: 1, profile: 'ctf-config-q05', mountedActorId: '1002',
    mountedSessionId: '3002', keys: [...KEYS],
    cases: KEYS.map((key, index) => ({ key, previous: index < 5 ? 'true' : '10',
      proposed: index < 5 ? 'false' : '11',
      cancel: { noPost: true, unchanged: true },
      dialogTimeAba: { eventsObserved: 2, noPost: true, unchanged: true },
      confirmed: operation(index * 2 + 1),
      durable: { canonicalProjectionApplied: true, actorSessionBound: true,
        dbValueMatches: true, adminGetMatches: true, publicGetMatches: true },
      restore: { scope: 'content-equivalence-only', contentEquivalent: true,
        ...operation(index * 2 + 2) }, siblingPreserved: true })),
    facts: Object.fromEntries(FACTS.map(key => [key, true])),
    excluded: [...EXCLUDED], unexpectedApiPaths: [], browserActions: 120,
    apiRequests: 300, stage: 'complete', modelCalls: 0, judgeCalls: 0 };
}
const tamper = change => { const value = receipt(); change(value); assert.throws(() => assertCtfConfigReceipt(value)); };

test('Config receipt covers the exact fifteen source keys with ordered independent operations', () => {
  assert.equal(KEYS.length, 15);
  assert.equal(new Set(KEYS).size, KEYS.length);
  assert.deepEqual(KEYS, require('../../server/data/ctfDefaults').configs.map(row => row.key));
  assert.equal(assertCtfConfigReceipt(receipt()), true);
  assert.equal(proposedValue('ctf_enabled', 'true'), 'false');
  assert.equal(proposedValue('ctf_hint_cost_3', '40'), '41');
  assert.throws(() => proposedValue('ctf_hint_cost_3', '2147483647'));
  assert.throws(() => proposedValue('ctf_enabled', 'unknown'));
  assert.equal(LIMITS.browserActions, 1200);
  assert.equal(LIMITS.apiRequests, 1200);
  assert.equal(LIMITS.deadlineMs, 360000);
});

test('Config receipt rejects omitted, extra, reordered, vacuous, and false facets', () => {
  tamper(r => r.cases.pop());
  tamper(r => r.cases.reverse());
  tamper(r => { r.cases[0].key = 'unexpected'; });
  tamper(r => { r.cases[0].extra = true; });
  tamper(r => { delete r.facts.noPreview; });
  tamper(r => { r.facts.noPreview = false; });
  tamper(r => { r.excluded.pop(); });
  tamper(r => { r.unexpectedApiPaths.push('/api/ctf/admin/stages/2/preview'); });
  tamper(r => { r.browserActions = 1201; });
  tamper(r => { r.apiRequests = 1201; });
  tamper(r => { r.modelCalls = 1; });
  tamper(r => { r.judgeCalls = 1; });
  tamper(r => { r.stage = 'postflight'; });
});

test('Config receipt rejects duplicate, out-of-order, absent, or falsely recovered operations', () => {
  tamper(r => { r.cases[0].restore.operationId = r.cases[0].confirmed.operationId; });
  tamper(r => { r.cases[1].confirmed.sequence = '1'; });
  tamper(r => { r.cases[0].confirmed.operationId = 'not-an-operation'; });
  tamper(r => { r.cases[0].confirmed.sameIdGets = 1; });
  tamper(r => { r.cases[0].confirmed.browserAckOperationId = id(1); });
  tamper(r => { r.cases[0].confirmed.originalStatus = 202; });
  tamper(r => { r.cases[0].confirmed.originalStatus = 202;
    r.cases[0].confirmed.sameIdGets = 33;
    r.cases[0].confirmed.browserAckOperationId = id(1);
    r.cases[0].confirmed.ackMessage = null; });
  tamper(r => { r.cases[0].restore.scope = 'byte-identical-undo'; });
  tamper(r => { r.cases[0].cancel.noPost = false; });
  tamper(r => { r.cases[0].dialogTimeAba.eventsObserved = 1; });
  tamper(r => { r.cases[0].durable.actorSessionBound = false; });
  tamper(r => { r.cases[0].siblingPreserved = false; });
  const recovered = receipt();
  recovered.cases[0].confirmed = { ...operation(1), originalStatus: 202,
    sameIdGets: 1, browserAckOperationId: id(1), ackMessage: null };
  assert.equal(assertCtfConfigReceipt(recovered), true);
});

test('Config row evaluator closes over only browser-provided arguments', () => {
  const row = { querySelectorAll: selector => selector === 'button[role="switch"]'
    ? [{ getClientRects: () => [1], disabled: false }] : [] };
  const label = { children: [], textContent: 'ctf_enabled', getClientRects: () => [1],
    parentElement: { parentElement: row } };
  const context = { document: { querySelectorAll: () => [label] } };
  assert.equal(vm.runInNewContext(`(${configRow.toString()})('ctf_enabled', true)`, context), row);
  assert.equal(vm.runInNewContext(`(${configRow.toString()})('ctf_enabled', false)`, context), null);
});

test('Config row readiness waits for delayed exact rendered control and fails closed when absent', async () => {
  const control={ getClientRects: () => [1], disabled: false };
  const row={ querySelectorAll: selector => selector==='button[role="switch"]'?[control]:[] };
  const label={ children: [], textContent:'ctf_enabled', getClientRects: () => [1],
    parentElement:{ parentElement:row } };
  let polls=0, physicalActions=0;
  const page={ waitForFunction: async (predicate, options, key, isBoolean) => {
    assert.deepEqual(options,{polling:100,timeout:15000});
    assert.equal(key,'ctf_enabled');assert.equal(isBoolean,true);
    const context={document:{querySelectorAll:()=>polls++===0?[]:[label]}};
    assert.equal(vm.runInNewContext(`(${predicate.toString()})("ctf_enabled", true)`,context),null);
    const value=vm.runInNewContext(`(${predicate.toString()})("ctf_enabled", true)`,context);
    assert.equal(value,row);
    return {asElement:()=>value};
  }};
  const action=async fn=>{physicalActions++;return fn();};
  assert.equal((await waitConfigRow(page,'ctf_enabled',true,action)).asElement(),row);
  assert.equal(physicalActions,1,'readiness is one bounded observation, not a mutation retry');
  const absent={waitForFunction:async (_predicate,options)=>{
    assert.equal(options.timeout,15000);throw Error('Waiting failed: 15000ms exceeded');
  }};
  await assert.rejects(waitConfigRow(absent,'ctf_enabled',true,action),/15000ms exceeded/);
  assert.equal(physicalActions,2);
});

test('each confirmed save changes exactly its key and supported restore returns all fifteen values', () => {
  const before=Object.fromEntries(KEYS.map(key=>[key,'10']));
  const confirmed={...before,ctf_hint_cost_2:'11'};
  assert.equal(assertConfigTransition(before,confirmed,'ctf_hint_cost_2','11'),true);
  assert.equal(assertConfigTransition(before,before,'ctf_hint_cost_2','10'),true);
  assert.throws(()=>assertConfigTransition(before,{...confirmed,ctf_hint_cost_1:'11'},'ctf_hint_cost_2','11'));
  assert.throws(()=>assertConfigTransition(before,{...confirmed,ctf_hint_cost_1:'11'},'ctf_hint_cost_2','10'));
  const missing={...confirmed};delete missing.ctf_hint_cost_1;
  assert.throws(()=>assertConfigTransition(before,missing,'ctf_hint_cost_2','11'));
});

test('Config fixture admits only the two exact Python-provisioned owned database pairs', () => {
  const nonce='a1b2c3d4e5f6';
  for (const state of ['FRESH','POPULATED']) for (const kind of ['IDENTITY','CTF']) {
    const name=`/dvaia_test_ctf_config_${state[0].toLowerCase()}_${kind[0].toLowerCase()}_${nonce}`;
    assert.equal(assertConfigDatabaseName(name,state,kind,nonce),nonce);
    assert.throws(()=>assertConfigDatabaseName(name,state==='FRESH'?'POPULATED':'FRESH',kind,nonce));
    assert.throws(()=>assertConfigDatabaseName(name,state,kind==='CTF'?'IDENTITY':'CTF',nonce));
    assert.throws(()=>assertConfigDatabaseName(name,state,kind,'ffffffffffff'));
    assert.throws(()=>assertConfigDatabaseName(name+'x',state,kind,nonce));
    assert.throws(()=>assertConfigDatabaseName(name.replace('_config_','_app_'),state,kind,nonce));
  }
});
