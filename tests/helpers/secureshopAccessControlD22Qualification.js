'use strict';

// D22 joins the rendered Access Control controls to the real owned audit-query
// flow.  The launcher supplies a disposable browser, stores, model and target;
// this helper deliberately owns neither resource allocation nor cleanup.
const assert = require('node:assert/strict');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function assertReceipt(receipt, { kind, expectedVersion, registrySha256, enabled } = {}) {
  assert.equal(receipt?.change?.kind, kind);
  assert.equal(receipt?.version, expectedVersion);
  assert.equal(receipt?.registrySha256, registrySha256);
  assert.match(receipt?.operationId || '', UUID);
  if (kind === 'permission') {
    assert.equal(receipt?.change?.toolKey, 'audit.search_by_user');
    assert.equal(receipt?.change?.role, 'admin');
    assert.equal(receipt?.change?.allowed, enabled);
  } else {
    assert.equal(receipt?.change?.enabled, enabled);
    assert.equal(receipt?.enforcement, enabled);
  }
}

function assertAdmittedContext(context) {
  assert.match(context?.launchId || '', UUID);
  assert.match(context?.scenarioId || '', UUID);
  assert.match(context?.platformOwnerId || '', /^[1-9][0-9]*$/);
  assert.match(context?.platformSessionId || '', /^[1-9][0-9]*$/);
  assert.match(context?.personaId || '', /^[1-9][0-9]*$/);
  assert.match(context?.personaSessionId || '', UUID);
  assert.match(context?.authorityVersion || '', /^[1-9][0-9]*$/);
  assert.match(context?.generation || '', /^[0-9]+$/);
  assert.match(context?.policyVersion || '', /^[1-9][0-9]*$/);
  assert.match(context?.registrySha256 || '', /^[0-9a-f]{64}$/);
  assert.match(context?.runId || '', UUID);
  assert.match(context?.invocationId || '', /^1:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
}

function assertActualOutcome(value, { denied } = {}) {
  assert.equal(value?.provider, 'ollama');
  assert.equal(value?.model, 'llama3.1:8b');
  assert.equal(value?.replayed, true);
  assert.equal(value?.admission?.allowed, !denied);
  assert.equal(value?.admission?.action, denied ? 'block' : 'dispatch');
  assert.equal(value?.admission?.toolKey, 'audit.search_by_user');
  assertAdmittedContext(value?.context);
  if (denied) {
    assert.equal(value?.noServiceDispatch, true);
    assert.equal(value?.noQueryEffect, true);
    assert.equal(value?.noJudgment, true);
    assert.equal(value?.noCredit, true);
    assert.equal(value?.actorFinalResponse, true);
  } else {
    assert.equal(value?.effectPersisted, true);
    assert.equal(value?.auditReadback, true);
  }
}

function assertSameActorContext(allowed, denied) {
  for (const key of ['launchId', 'scenarioId', 'platformOwnerId', 'platformSessionId', 'personaId', 'personaSessionId', 'authorityVersion'])
    assert.equal(denied.context[key], allowed.context[key], `same rendered actor ${key}`);
  assert.equal(denied.context.registrySha256, allowed.context.registrySha256);
  assert.equal(BigInt(denied.context.policyVersion), BigInt(allowed.context.policyVersion) + 2n);
}

async function frameFetch(frame, path, { method = 'GET', body } = {}) {
  return frame.evaluate(async ({ path: target, method: verb, body: payload }) => {
    const response = await fetch(target, {
      method: verb,
      headers: payload === undefined ? undefined : { 'content-type': 'application/json' },
      body: payload === undefined ? undefined : JSON.stringify(payload),
    });
    let value = null;
    try { value = await response.json(); } catch { /* Checked by the caller. */ }
    return { status: response.status, body: value };
  }, { path, method, body });
}

async function clickAndReadReceipt({ page, frame, origin, selector, kind, expectedVersion, registrySha256, enabled }) {
  const endpoint = `${origin}/api/secureshop/admin/access-control/${kind}`;
  await frame.waitForFunction(({ selector: target, kind: selected, enabled: expected }) => {
    const control = document.querySelector(target);
    if (!control || control.disabled || control.getAttribute('aria-disabled') === 'true') return false;
    if (selected === 'permission') return control.getAttribute('data-allowed') === String(!expected);
    return control.getAttribute('aria-checked') === String(!expected);
  }, { timeout: 30000 }, { selector, kind, enabled });
  const control = await frame.$(selector);
  assert.ok(control, `rendered D22 control ${selector} is present`);
  const pending = page.waitForResponse(response => response.url() === endpoint
    && response.request().method() === 'POST', { timeout: 30000 });
  // The response promise is armed before the physical click; attach a handler
  // immediately so an earlier click/selector assertion cannot leave it unhandled.
  pending.catch(() => {});
  try {
    await control.evaluate(node => node.scrollIntoView({ block: 'center', inline: 'center' }));
    await control.click();
  } finally { await control.dispose(); }
  const response = await pending;
  assert.equal(response.status(), 200);
  const result = await response.json();
  assert.equal(result?.ok, true);
  assertReceipt(result.receipt, { kind, expectedVersion, registrySha256, enabled });
  const saved = await frameFetch(frame,
    `/api/secureshop/admin/access-control/operations/${result.receipt.operationId}`);
  assert.equal(saved.status, 200);
  assert.deepEqual(saved.body, { ok: true, receipt: result.receipt });
  await frame.waitForFunction(({ selector: target, kind: selected, enabled: expected }) => {
    const control = document.querySelector(target);
    return !!control && !control.disabled && control.getAttribute('aria-disabled') !== 'true'
      && control.getAttribute(selected === 'permission' ? 'data-allowed' : 'aria-checked') === String(expected);
  }, { timeout: 30000 }, { selector, kind, enabled });
  return result.receipt;
}

/**
 * Executes the narrow D22 sequence after the fixture has mounted its actual
 * owned-audit application and authenticated a standalone administrator.
 *
 * `invokeActualAudit` must use that same administrator's rendered session. It
 * returns an intentionally small proof object so this helper never receives
 * credentials, model prompts, raw SQL, target data, or an API key.
 */
async function qualifyRenderedD22({ page, frame, origin, invokeActualAudit, readSibling, readAudit } = {}) {
  assert.ok(page && typeof page.waitForResponse === 'function');
  assert.ok(frame && typeof frame.evaluate === 'function' && typeof frame.$ === 'function');
  assert.equal(new URL(origin).hostname, '127.0.0.1');
  assert.equal(typeof invokeActualAudit, 'function');
  assert.equal(typeof readSibling, 'function');
  assert.equal(typeof readAudit, 'function');

  const siblingBefore = await readSibling();
  const initial = await frameFetch(frame, '/api/secureshop/admin/access-control');
  assert.equal(initial.status, 200);
  assert.equal(initial.body?.ok, true);
  assert.equal(initial.body?.administration?.versionedPolicy, true);
  assert.equal(initial.body?.enforcement_enabled, false);
  assert.match(initial.body?.version || '', /^[1-9][0-9]*$/);
  assert.match(initial.body?.registrySha256 || '', /^[0-9a-f]{64}$/);
  const tool = initial.body.tools?.find(row => row?.tool_name === 'audit.search_by_user');
  assert.equal(tool?.admin, true);

  const allowed = await invokeActualAudit({ phase: 'allowed' });
  assertActualOutcome(allowed, { denied: false });

  const cell = '[data-testid="acl-cell-audit.search_by_user-admin"]';
  const toggle = '[data-testid="acl-enforcement-toggle"]';
  const deny = await clickAndReadReceipt({ page, frame, origin, selector: cell, kind: 'permission',
    expectedVersion: String(BigInt(initial.body.version) + 1n), registrySha256: initial.body.registrySha256,
    enabled: false });
  const enforce = await clickAndReadReceipt({ page, frame, origin, selector: toggle, kind: 'enforcement',
    expectedVersion: String(BigInt(deny.version) + 1n), registrySha256: initial.body.registrySha256,
    enabled: true });
  const changed = await frameFetch(frame, '/api/secureshop/admin/access-control');
  assert.equal(changed.status, 200);
  assert.equal(changed.body?.enforcement_enabled, true);
  assert.equal(changed.body?.tools?.find(row => row?.tool_name === 'audit.search_by_user')?.admin, false);

  const denied = await invokeActualAudit({ phase: 'denied' });
  assertActualOutcome(denied, { denied: true });
  assertSameActorContext(allowed, denied);
  assert.deepEqual(await readSibling(), siblingBefore);
  const audit = await readAudit({ allowed, denied, deny, enforce });
  assert.equal(audit?.allowedEffectReadback, true);
  assert.equal(audit?.deniedAdmissionReadback, true);
  assert.equal(audit?.deniedNoEffect, true);

  return Object.freeze({ allowed, denied, receipts: Object.freeze({ deny, enforce }), audit });
}

module.exports = { qualifyRenderedD22, _internals: { assertReceipt, assertActualOutcome, assertAdmittedContext, assertSameActorContext, frameFetch } };
