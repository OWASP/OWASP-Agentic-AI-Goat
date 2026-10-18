'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Execute the actual nested browser helper without loading its native suite.
const source = fs.readFileSync(path.join(__dirname, 'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
const start = source.indexOf('  const choose = async (choice, label) => {', source.indexOf('async function qualifyMerchantMail('));
const end = source.indexOf('\n  assert.equal(seed.owned.sent.length', start);
assert(start > 0 && end > start);
const helper = source.slice(start, end);
const label = 'View mailbox for student_customer';
const choice = { choiceId: '11111111-1111-4111-8111-111111111111' };

function setup(states) {
  let state, clicks = 0, polls = 0;
  const node = { getAttribute: () => label, get disabled() { return state.disabled; },
    getClientRects: () => state.hidden ? [] : [{}], scrollIntoView() {},
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 10, height: 10 }), contains: () => false };
  const document = { querySelectorAll: () => state.duplicate ? [node, node] : [node],
    elementFromPoint: () => state.obstructed ? {} : node };
  const frame = { async waitForFunction(predicate, options, text) {
    assert.equal(options.timeout, 20000);
    assert.equal(options.polling, 'raf');
    for (state of states) {
      polls++;
      const found = predicate(text);
      if (found) return { asElement: () => ({ async click() { assert.equal(found, node); clicks++; } }) };
    }
    throw new Error('Controlled readiness timeout');
  } };
  const choose = vm.runInNewContext(`${helper}\nchoose`, { assert, frame, document });
  return { run: () => choose(choice, label), counts: () => ({ clicks, polls }) };
}

test('mail choice waits through pending rendering before a physical click', async () => {
  const fixture = setup([{ hidden: true }, { disabled: true }, { obstructed: true }, {}]);
  await fixture.run();
  assert.deepEqual(fixture.counts(), { clicks: 1, polls: 4 });
});

for (const state of [{ disabled: true }, { hidden: true }, { duplicate: true }, { obstructed: true }]) {
  test(`mail choice fails closed for ${Object.keys(state)[0]}`, async () => {
    const fixture = setup([state, state]);
    await assert.rejects(fixture.run(), /readiness timeout/);
    assert.equal(fixture.counts().clicks, 0);
  });
}
