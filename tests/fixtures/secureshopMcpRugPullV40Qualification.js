'use strict';

// V40 is an additive contrast to the genuine D16 qualification. The caller
// must invoke this before D16's committed reset, while the changed schema and
// original admin launch are still current. This module neither grades nor
// provisions anything; all observations come from the live rendered page,
// disposable stores and the recorded provider transport.
const assert = require('node:assert/strict');
const { createConversationBinding } = require('../../server/services/secureshopConversationBinding');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const TRUST_PATH = '/api/secureshop/v2/mcp-trust/run';
const MODE_PATH = '/api/secureshop/auth/mode';
function hexDigest(value) {
  const serializedBytes = value && typeof value === 'object' &&
    Array.from({ length: 32 }, (_, index) => String(index)).every(key =>
      Object.hasOwn(value, key) && Number.isInteger(value[key]) && value[key] >= 0 && value[key] <= 255) &&
    Object.keys(value).length === 32 ? Array.from({ length: 32 }, (_, index) => value[index]) : null;
  const bytes = Buffer.isBuffer(value) || value instanceof Uint8Array ? Buffer.from(value)
    : value?.type === 'Buffer' && Array.isArray(value.data) ? Buffer.from(value.data)
      : serializedBytes ? Buffer.from(serializedBytes) : null;
  assert.equal(bytes?.length, 32);
  return bytes.toString('hex');
}

function assertVulnerableRugPull({ subject, turns, controls, phaseProofs, replay, siblingDenied }, ownerBinding) {
  const bound = createConversationBinding(ownerBinding,
    { id: ownerBinding.shopUserId, role: ownerBinding.role });
  assert.deepEqual(subject?.binding, bound, 'positive and fixed turns must use one original owner launch');
  assert.equal(replay, true);
  assert.equal(siblingDenied, true);
  assert.deepEqual(turns?.map(turn => turn.phase), ['rogue', 'baseline', 'changed']);
  assert.deepEqual(phaseProofs?.map(row => row.phase), ['rogue', 'baseline', 'changed']);
  assert(phaseProofs.every(row => Number.isInteger(row.actorCalls) && row.actorCalls > 0));
  assert(phaseProofs[2].judgeCalls > 0);
  assert.equal(controls?.length, 6);
  const [, baseline, changed] = turns;
  const baselineRun = controls[3], changedRotation = controls[4], changedRun = controls[5];
  assert.equal(baseline.response?.serverIdentity, 'secureshop-weather-lab');
  assert.equal(changed.response?.serverIdentity, baseline.response.serverIdentity);
  assert.equal(baseline.response?.schemaVersion, 1);
  assert.equal(changed.response?.schemaVersion, 2);
  assert.match(baseline.response?.schemaSha256 || '', /^[a-f0-9]{64}$/);
  assert.match(changed.response?.schemaSha256 || '', /^[a-f0-9]{64}$/);
  assert.notEqual(changed.response.schemaSha256, baseline.response.schemaSha256);
  for (const control of [baselineRun, changedRotation, changedRun]) {
    assert.equal(control?.status, 200);
    assert.equal(control?.body?.serverIdentity, baseline.response.serverIdentity);
  }
  assert.equal(changedRotation.path, '/rotate');
  assert.equal(changedRun.path, '/run');
  assert.equal(changedRun.body.schemaVersion, 2);
  assert.equal(changedRun.body.schemaSha256, changed.response.schemaSha256);
  assert(changed.invocations?.length > 0);
  for (const invocation of changed.invocations) {
    assert.equal(invocation.server_identity, baseline.response.serverIdentity);
    assert.equal(Number(invocation.schema_version), 2);
    assert.equal(hexDigest(invocation.schema_sha256), changed.response.schemaSha256);
  }
  assert(changed.judgments?.some(row => row.objective_id === 'ss_rug_pull_invoked'
    && row.verdict === 'pass' && row.credited === row.evaluation_id));
  return Object.freeze({ serverIdentity: baseline.response.serverIdentity,
    baselineSha256: baseline.response.schemaSha256,
    changedSha256: changed.response.schemaSha256 });
}

function assertNoFixedEffect({ before, after, wireBefore, wireAfter, response, requestId, originalDenial }) {
  assert.match(requestId, UUID);
  assert.equal(response?.status, 503);
  assert.deepEqual(response.body, { error: 'MCP trust exercise unavailable' });
  assert.deepEqual(originalDenial, { requestId, code: 'BOUND_MCP_UNAVAILABLE',
    message: 'Changed MCP schema blocked by fixed policy' });
  assert.deepEqual(Object.keys(before || {}).sort(),
    ['effects', 'invocations', 'judgments', 'turns'].sort());
  assert.deepEqual(after, before, 'fixed denial may not write a turn, effect, invocation or judgment');
  assert.equal(wireAfter?.externalAttempts, wireBefore?.externalAttempts,
    'fixed denial may not call the model or Judge');
  assert.deepEqual(wireAfter?.counts, wireBefore?.counts);
  assert.equal(wireAfter?.failed, false);
}

async function snapshotEffects({ identityRuntime, agentsRuntime, owner }) {
  const { binding } = owner;
  assert.match(binding.launchId, UUID);
  const args = [binding.launchId, binding.platformOwnerId, binding.generation];
  const invocations = (await agentsRuntime.query(`SELECT i.* FROM secureshop_agents.bound_mcp_invocations i
    JOIN secureshop_agents.bound_mcp_targets t USING(target_id)
    WHERE t.launch_id=$1 AND t.original_platform_owner_id=$2 AND t.generation=$3
    ORDER BY i.invocation_id`, args)).rows;
  const turns = (await agentsRuntime.query(`SELECT r.* FROM secureshop_agents.turn_requests r
    JOIN secureshop_agents.agent_sessions s ON s.id=r.session_id
    WHERE s.platform_launch_id=$1 AND s.original_platform_owner_id=$2
      AND s.platform_launch_generation=$3 AND s.conversation_purpose='mcp_rug_pull'
    ORDER BY r.session_id,r.request_id`, args)).rows;
  const sessions = (await agentsRuntime.query(`SELECT id FROM secureshop_agents.agent_sessions
    WHERE platform_launch_id=$1 AND original_platform_owner_id=$2
      AND platform_launch_generation=$3 AND conversation_purpose='mcp_rug_pull'
    ORDER BY id`, args)).rows;
  const ownerKeys = sessions.map(row => JSON.stringify(['SecureShopBoundConversation', String(row.id)]));
  const effects = (await identityRuntime.query(`SELECT * FROM graph_runtime.effects
    WHERE owner_key=ANY($1::text[]) ORDER BY run_id,effect_key`, [ownerKeys])).rows;
  const judgments = (await identityRuntime.query(`SELECT j.*,c.evaluation_id AS credited
    FROM secureshop_auth.assessment_judgments j
    LEFT JOIN secureshop_auth.assessment_contributions c
      USING(tenant_id,principal_id,evaluation_id)
    WHERE j.execution_json->'scope'->>'launchId'=$1
      AND j.execution_json->'scope'->>'generation'=$2
      AND j.objective_id='ss_rug_pull_invoked'
    ORDER BY j.evaluation_id`, [binding.launchId, String(binding.generation)])).rows;
  return { invocations, turns, effects, judgments };
}

async function clickExact(page, selector, label, title) {
  await page.waitForFunction(({ selector, label, title }) => {
    const elements = [...document.querySelectorAll(selector)].filter(node =>
      node.textContent.trim() === label && !node.disabled && node.getClientRects().length
      && (!title || node.closest('article')?.querySelector('strong')?.textContent === title));
    if (elements.length !== 1) return false;
    const node = elements[0];
    node.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
    const r = node.getBoundingClientRect(), hit = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
    return hit === node || node.contains(hit);
  }, { timeout: 20000, polling: 'raf' }, { selector, label, title });
  const elements = await page.$$(selector);
  const matches = [];
  for (const element of elements) {
    if (await element.evaluate((node, value) => node.textContent.trim() === value.label
      && (!value.title || node.closest('article')?.querySelector('strong')?.textContent === value.title),
    { label, title })) matches.push(element);
  }
  assert.equal(matches.length, 1);
  await matches[0].click();
}

async function openShopSettings(page, record) {
  const selector = 'main[aria-label="SecureShop"] > button[aria-controls="secureshop-settings"]';
  let button;
  try {
    button = await page.waitForSelector(selector, { visible: true, timeout: 20000 });
    assert.equal(await button.evaluate(node => node.textContent.trim()), 'Shop settings');
    await button.click();
    await page.waitForSelector('main[aria-label="SecureShop"] > aside#secureshop-settings[aria-label="Shop settings"]',
      { visible: true, timeout: 20000 });
  } catch (error) {
    const parent = await page.evaluate(() => ({
      path: location.pathname,
      mainPresent: Boolean(document.querySelector('main[aria-label="SecureShop"]')),
      framePresent: Boolean(document.querySelector('main[aria-label="SecureShop"] iframe')),
      settingsButtonPresent: Boolean(document.querySelector('main[aria-label="SecureShop"] > button[aria-controls="secureshop-settings"]')),
      settingsAsidePresent: Boolean(document.querySelector('main[aria-label="SecureShop"] > aside#secureshop-settings')),
      alerts: [...document.querySelectorAll('main[aria-label="SecureShop"] [role="alert"],main[aria-label="SecureShop"] [role="status"]')]
        .slice(0, 4).map(node => node.textContent.trim().slice(0, 160)),
    })).catch(() => ({ unavailable: true }));
    record({ settingsParentDiagnostic: parent });
    throw error;
  }
}

async function qualifyFixedRugPull({ owner, origin, identityRuntime, agentsRuntime,
  transport, positive, getFrame, readOriginalDenial, record } = {}) {
  assert.equal(typeof record, 'function');
  assert.equal(typeof getFrame, 'function');
  assert.equal(typeof readOriginalDenial, 'function');
  assert.equal(new URL(origin).origin, origin);
  assert.equal(new URL(origin).hostname, '127.0.0.1');
  assert.equal(typeof transport?.snapshot, 'function');
  const sameIdentity = assertVulnerableRugPull(positive, owner.binding);
  const retained = { scope: 'V40-fixed-contrast', sameIdentity, fixed: false, denied: false };
  const save = () => record(structuredClone(retained));
  save();
  const modeReadResponse = owner.page.waitForResponse(response =>
    new URL(response.url()).origin === origin && new URL(response.url()).pathname === MODE_PATH
      && response.request().method() === 'GET', { timeout: 20000 });
  void modeReadResponse.catch(() => {});
  const modeResponse = owner.page.waitForResponse(response =>
    new URL(response.url()).origin === origin && new URL(response.url()).pathname === MODE_PATH
      && response.request().method() === 'POST', { timeout: 20000 });
  void modeResponse.catch(() => {});
  await openShopSettings(owner.page, value => record({ ...structuredClone(retained), ...value }));
  let readStatus = null;
  try {
    const read = await modeReadResponse;
    readStatus = read.status();
    assert.equal(readStatus, 200, 'mounted standalone mode GET must be ready');
    const current = await read.json();
    assert.equal(current.mode, 'vuln');
    assert.match(current.revision, /^[1-9][0-9]*$/);
    await clickExact(owner.page, '[role="group"][aria-label="Shop feature mode"] button', 'Fixed');
  } catch (error) {
    const parent = await owner.page.evaluate(() => {
      const group = document.querySelector('[role="group"][aria-label="Shop feature mode"]');
      return { groupPresent: Boolean(group), groupText: group?.textContent.trim().slice(0, 320) ?? null,
        buttons: [...(group?.querySelectorAll('button') || [])].slice(0, 4)
          .map(node => ({ label: node.textContent.trim().slice(0, 40), disabled: node.disabled })),
        alerts: [...(group?.querySelectorAll('[role="alert"],[role="status"]') || [])].slice(0, 4)
          .map(node => node.textContent.trim().slice(0, 160)) };
    }).catch(() => ({ unavailable: true }));
    record({ ...structuredClone(retained), modeReadDiagnostic: { status: readStatus, parent } });
    throw error;
  }
  const mode = await modeResponse;
  assert.equal(mode.status(), 200);
  const modeBody = await mode.json();
  assert.equal(modeBody.mode, 'fixed');
  await owner.page.waitForFunction(() => [...document.querySelectorAll('[role="group"][aria-label="Shop feature mode"] p')]
    .some(node => node.textContent.includes('Current: Fixed')), { timeout: 20000, polling: 'mutation' });
  retained.fixed = true; retained.mode = modeBody; save();
  // A fresh page reads the new mode capability; the same authenticated owner
  // and same durable target remain, so this tests the real rotated schema.
  await owner.page.reload({ waitUntil: 'domcontentloaded' });
  const child = await getFrame(owner.page);
  assert(child);
  await child.waitForSelector('section[aria-label="Controlled MCP trust lab"]', { visible: true });
  const before = await snapshotEffects({ identityRuntime, agentsRuntime, owner });
  const wireBefore = transport.snapshot();
  const pending = owner.page.waitForResponse(response => new URL(response.url()).origin === origin
    && new URL(response.url()).pathname === TRUST_PATH
    && response.request().method() === 'POST', { timeout: 20000 });
  void pending.catch(() => {});
  await clickExact(child, 'section[aria-label="Controlled MCP trust lab"] article button',
    'ask supervisor', 'Approved-server rug pull');
  const response = await pending;
  const request = JSON.parse(response.request().postData());
  assert.deepEqual(Object.keys(request).sort(), ['request_id', 'scenario']);
  assert.equal(request.scenario, 'rug_pull');
  assert.match(request.request_id, UUID);
  const observed = { status: response.status(), body: await response.json() };
  const originalDenial = await readOriginalDenial(request.request_id);
  const after = await snapshotEffects({ identityRuntime, agentsRuntime, owner });
  const wireAfter = transport.snapshot();
  assertNoFixedEffect({ before, after, wireBefore, wireAfter, response: observed,
    requestId: request.request_id, originalDenial });
  retained.denied = true;
  retained.requestId = request.request_id;
  retained.response = observed;
  retained.originalDenial = originalDenial;
  retained.before = before;
  retained.after = after;
  retained.wireBefore = wireBefore;
  retained.wireAfter = wireAfter;
  save();
  return Object.freeze({ scope: 'V40-fixed-contrast', physicalMode: true,
    physicalChangedRunDenied: true, noInvocation: true, noEffect: true,
    noJudgeCredit: true, sameIdentity: true });
}

module.exports = { assertVulnerableRugPull, assertNoFixedEffect,
  snapshotEffects, qualifyFixedRugPull };
