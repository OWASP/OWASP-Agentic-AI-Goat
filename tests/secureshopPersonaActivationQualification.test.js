'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = name => fs.readFileSync(path.join(ROOT, name), 'utf8');

test('persona activation qualifier uses real platform JWT and live catalog authority without a model', () => {
  const source = read('tests/postgres/secureshopPersonaActivation.integration.test.js');
  assert.match(source, /getPostgresIdentityAdapter/);
  assert.match(source, /createSession/);
  assert.match(source, /authorization: `Bearer \$\{platformSession\.token\}`/);
  assert.match(source, /api\/auth\/secureshop-launch/);
  assert.match(source, /student_merchant/);
  assert.match(source, /persona-inbox\/readiness/);
  assert.match(source, /UPDATE workshop_platform\.objectives SET is_enabled=false/);
  assert.match(source, /UPDATE workshop_platform\.exercises SET is_visible=false/);
  assert.match(source, /partial persona schema was accepted/);
  assert.match(source, /initializeSecureShopAgentsDb/);
  assert.match(source, /initializeSecureShopReviewDb/);
  assert.match(source, /initializeSecureShopCommerceDb/);
  assert.match(source, /activation qualifier must not call a model/);
  assert.doesNotMatch(source, /LIVE_OLLAMA_TEST|OllamaProvider|createObjectiveJudge/);
});

test('single-use launcher copies reviewed candidate bytes and current promoted migrations', () => {
  const source = read('tests/postgres/run-secureshop-persona-activation-isolated.py');
  assert.match(source, /EXPECTED_DOCKER = 'unix:\/\/\/Users\/averma5\/\.colima\/owasp-ai-goat-pg-verify\/docker\.sock'/);
  assert.match(source, /registered\.get\('ownerHandle'\)/);
  assert.match(source, /handle != os\.getpid\(\)/);
  assert.match(source, /try:\n    register_owner\(\)\n    prepare_workspace\(\)/);
  assert.match(source, /server\/services\/secureshop\*\.js/);
  assert.match(source, /db\/postgres\/identity-migrations\/\*\.sql/);
  assert.match(source, /exact_container_absence\(\)/);
  assert.match(source, /containerCreationAttempted/);
  assert.match(source, /secureshopPersonaInboxActivationCandidate/);
  assert.match(source, /secureshopPersonaInboxActivationPolicy\.candidate\.js/);
  assert.doesNotMatch(source, /docs\/modernization\/drafts\/secureshop-persona-inbox-(identity|agents)\.sql/);
  assert.doesNotMatch(source, /LIVE_OLLAMA_TEST|OLLAMA_BASE_URL/);
});
