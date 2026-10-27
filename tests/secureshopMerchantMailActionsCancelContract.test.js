'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname,
  'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');

test('launcher requires the same mail action evidence flags as the rendered fixture', () => {
  const launcher = fs.readFileSync(path.join(__dirname,
    'postgres/run-secureshop-agent-host-transport-main.py'), 'utf8');
  const fixtureFlags = source.match(/const MERCHANT_MAIL_ACTIONS_FLAGS = Object\.freeze\(\[([\s\S]*?)\]\);/);
  const launcherFlags = launcher.match(/MERCHANT_MAIL_ACTIONS_FLAGS = \(([\s\S]*?)\)/);
  assert.ok(fixtureFlags);
  assert.ok(launcherFlags);
  const names = text => [...text.matchAll(/'([^']+)'/g)].map(match => match[1]);
  assert.deepEqual(names(launcherFlags[1]), names(fixtureFlags[1]));
  assert.ok(names(launcherFlags[1]).includes('cancelProposalNoEffect'));
});

test('merchant mail Cancel remains a physical no-effect facet of the original five-turn cohort', () => {
  const prepared = source.indexOf("status.namedSendSelected = true; status.sendProposalNoEffect = true;");
  const cancelled = source.indexOf("await clickConfirmation('Cancel proposal');", prepared);
  const reload = source.indexOf("await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);", cancelled);
  const confirmed = source.indexOf("await clickConfirmation('Send message');", reload);
  const replied = source.indexOf("await clickConfirmation('Run reply agent');", confirmed);
  assert.ok(prepared > 0 && cancelled > prepared && reload > cancelled
    && confirmed > reload && replied > confirmed);
  assert.match(source, /cancelProposalNoEffect.*physicalSendConfirmed/);
  assert.match(source.slice(prepared, confirmed), /confirmPosts\(\)\.length, beforeCancel\.confirms/);
  assert.match(source.slice(prepared, confirmed), /sendOperation\(sendProposal\.proposalId\), beforeCancel\.operation/);
  assert.match(source.slice(prepared, confirmed), /restored\.at\(-1\)\.value, preparedSend\.receipt/);
  assert.match(source.slice(prepared, confirmed), /getDispatches\(\), beforeCancel\.actorCalls/);
  assert.match(source.slice(prepared, confirmed), /getModelCalls\(\)\.length, beforeCancel\.modelCalls/);
  assert.match(source.slice(prepared, confirmed), /Mail proposal dismissed\. No confirmation was sent\./);
  assert.match(source.slice(prepared, confirmed), /node\.querySelector\('pre'\)\?\.textContent === expectedBody/);
  assert.match(source.slice(confirmed, replied), /recoverAfterFault\(preparedSend, sendProposal, sendCalls, 2\)/);
  assert.match(source.slice(replied), /assert\.equal\(chats\(\)\.length, 5\)/);
});
