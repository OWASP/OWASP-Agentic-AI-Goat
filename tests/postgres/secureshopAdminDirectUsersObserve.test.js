'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Destination: tests/postgres/secureshopAdminDirectUsersObserve.test.js.
// Exercise the helper in the actual applied browser fixture, not a task-only copy.
const fixture = fs.readFileSync(path.join(__dirname,
  'secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
const first = fixture.indexOf('  const observe = async (predicate, action) => {');
const last = fixture.indexOf('  const select = `select[aria-label=', first);
assert.ok(first >= 0 && last > first, 'applied direct-panel fixture owns the bounded observation helper');
const source = fixture.slice(first, last);
assert.match(source, /controller\.abort\(\); await pending;/);
const makeObserve = page => Function('page', `${source}\nreturn observe;`)(page);

function fakePage() {
  let waiting = null;
  let fail = null;
  let active = 0;
  let aborted = 0;
  return {
    waitForResponse(predicate, { signal }) {
      assert.equal(active, 0, 'only one bounded response waiter');
      active += 1;
      return new Promise((resolve, reject) => {
        const finish = (value, error) => {
          if (!waiting) return;
          waiting = null;
          fail = null;
          active -= 1;
          if (error) reject(error); else resolve(value);
        };
        waiting = value => { if (predicate(value)) finish(value); };
        fail = error => finish(null, error);
        signal.addEventListener('abort', () => {
          aborted += 1;
          finish(null, new Error('aborted'));
        }, { once: true });
      });
    },
    fire(value) { waiting?.(value); },
    fail(error) { fail?.(error); },
    get active() { return active; },
    get aborted() { return aborted; },
  };
}

test('delayed exact response wins over an unrelated response and waiter retires', async () => {
  const page = fakePage();
  const observe = makeObserve(page);
  const exact = { kind: 'exact' };
  const result = await observe(value => value.kind === 'exact', async () => {
    page.fire({ kind: 'other' });
    await new Promise(resolve => setTimeout(() => { page.fire(exact); resolve(); }, 5));
  });
  assert.equal(result, exact);
  assert.equal(page.active, 0);
  assert.equal(page.aborted, 1);
});

test('click or type failure aborts and joins the pending waiter', async () => {
  const page = fakePage();
  const observe = makeObserve(page);
  const primary = new Error('physical action failed');
  await assert.rejects(observe(() => true, async () => { throw primary; }),
    error => error === primary);
  assert.equal(page.active, 0);
  assert.equal(page.aborted, 1);
});

test('response-wait failure is surfaced without leaving a waiter', async () => {
  const page = fakePage();
  const observe = makeObserve(page);
  const failure = new Error('response stream closed');
  const task = observe(() => true, async () => {});
  queueMicrotask(() => page.fail(failure));
  await assert.rejects(task, error => error === failure);
  assert.equal(page.active, 0);
});

const diagnosticStart=fixture.indexOf('async function observeDirectUsersSelection(');
const diagnosticEnd=fixture.indexOf('async function qualifyDirectAdminUsersPanel(',diagnosticStart);
assert.ok(diagnosticStart>=0&&diagnosticEnd>diagnosticStart);
const diagnose=Function(fixture.slice(diagnosticStart,diagnosticEnd)+';return observeDirectUsersSelection;')();
test('diagnostics preserve exact action order and sanitize bounded selection output',async()=>{const d={},calls=[];await diagnose(d,async()=>{calls.push('select');return ['customer','SECRET','admin'];},async()=>{calls.push('wait');});assert.deepEqual(calls,['select','wait']);assert.deepEqual(d,{stage:'dialog-observed',selectedRoles:['customer','unknown']});});
test('selection error is identical and dialog wait is never invoked',async()=>{const d={},error=Error('SECRET');let waits=0;await assert.rejects(diagnose(d,async()=>{throw error;},async()=>{waits++;}),e=>e===error);assert.equal(waits,0);assert.deepEqual(d,{stage:'select',failed:true});});
test('original dialog timeout is identical with no retry',async()=>{const d={},error=Error('SECRET');let selections=0,waits=0;await assert.rejects(diagnose(d,async()=>{selections++;return ['customer'];},async()=>{waits++;throw error;}),e=>e===error);assert.equal(selections,1);assert.equal(waits,1);assert.deepEqual(d,{stage:'dialog-wait',selectedRoles:['customer'],failed:true});});
test('malformed selection results do not add errors or disclose values',async()=>{const d={};await diagnose(d,async()=>({secret:'SECRET'}),async()=>{});assert.deepEqual(d.selectedRoles,[]);assert.ok(!JSON.stringify(d).includes('SECRET'));});
test('no observer calls timers listeners or replacement events',()=>{const body=fixture.slice(diagnosticStart,diagnosticEnd);assert.doesNotMatch(body,/evaluate|dispose|addEventListener|dispatchEvent|setTimeout|Promise/);});
