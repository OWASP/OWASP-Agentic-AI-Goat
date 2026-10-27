'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const source = file => readFileSync(path.join(root, file), 'utf8');

test('enabled Users fixture cancels a staged role before either physical mutation', () => {
  const code = source('tests/fixtures/secureshopEnabledUsersBrowser.js');
  assert.match(code, /await frame\.select\(selector, 'merchant'\);\s*await frame\.waitForSelector\('\[aria-label="Confirm user change"\]'\);/);
  assert.match(code, /assert\.equal\(mutationRequests\.length, 0, 'role selection must have no effect before confirmation'\);\s*await frame\.click\('\[aria-label="Confirm user change"\] button:first-of-type'\);/);
  assert.match(code, /assert\.equal\(mutationRequests\.length, 0, 'cancel must not submit a user operation'\)/);
  assert.match(code, /assert\.equal\(mutationRequests\.length, 0, 'restaged role remains pre-effect'\);[\s\S]*?await frame\.click\('\[aria-label="Confirm user change"\] button:last-of-type'\)/);
  assert.match(code, /assert\.equal\(mutationRequests\.length, 1, 'ban selection must not submit before confirmation'\);\s*await frame\.click\('\[aria-label="Confirm user change"\] button:last-of-type'\)/);
});

test('full-commerce lost-ack fixture arms the drop only for a confirmed original action', () => {
  const code = source('tests/postgres/secureshopStandaloneCommerceRendered.integration.test.js');
  assert.match(code, /const loss = await dropOneCommittedOperationResponse\(page, endpoint\)/);
  assert.match(code, /assert\.equal\(mutationRequests\.length, 0, 'staging must not submit a role or ban operation'\)/);
  assert.match(code, /await clickMailButton\(adminMutationFrame, 'Cancel', true\)/);
  assert.match(code, /assert\.equal\(mutationRequests\.length, 0, 'cancel must not submit a role operation'\)/);
  assert.match(code, /await clickMailButton\(adminMutationFrame, 'Confirm user change', true\);\s*captured = await loss\.waitCaptured/);
  assert.match(code, /assert\.equal\(mutationRequests\.length, 1, 'one physical confirmed mutation required'\)/);
});

test('candidate opaque Users fixture confirms both role and ban after pre-effect checks', () => {
  const code = source('tests/postgres/secureshopUserAdministrationRendered.integration.test.js');
  assert.match(code, /assert\.equal\(mutationRequests\.length,0,'role selection must not submit before confirmation'\)/);
  assert.match(code, /assert\.equal\(mutationRequests\.length,0,'cancel must not create an operation'\)/);
  assert.match(code, /await frame\.click\('\[aria-label="Confirm user change"\] button:last-of-type'\);\s*await frame\.waitForFunction\(\(\)=>document\.querySelector\('\[role="alert"\]'\)/);
  assert.match(code, /await frame\.type\('\[aria-label="Ban reason \(audit-log\)"\]','Owned candidate ban reason'\)/);
  assert.match(code, /assert\.equal\(mutationRequests\.length,1,'ban selection must not submit before confirmation'\);\s*await frame\.click\('\[aria-label="Confirm user change"\] button:last-of-type'\)/);
});
