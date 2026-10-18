'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

// This table is consumed by the disposable PostgreSQL route fixture.  It is
// intentionally small: one existing confirmation terminal from each selected
// Q05 family, not a claim that these five terminals close Q07 globally.
const TERMINALS = Object.freeze([
  Object.freeze({
    family: 'customer-ticket', role: 'customer',
    confirmPath: '/agents/customer/tickets/confirm', effect: 'support_ticket',
    prepareTool: 'support.ticket_prepare', proposalKey: 'ticketProposal', controlledOnly: false,
  }),
  Object.freeze({
    family: 'merchant-listing', role: 'merchant',
    confirmPath: '/agents/merchant/assistant/listing-create/confirm', effect: 'listing',
    prepareTool: 'merchant.listing_create_prepare', proposalKey: 'listingCreateProposal', controlledOnly: true,
  }),
  Object.freeze({
    family: 'merchant-inventory', role: 'merchant',
    confirmPath: '/agents/merchant/assistant/inventory/confirm', effect: 'inventory_operation',
    prepareTool: 'merchant.inventory_prepare', proposalKey: 'inventoryProposal', controlledOnly: false,
  }),
  Object.freeze({
    family: 'admin-policy', role: 'admin',
    confirmPath: '/agents/admin/assistant/policies/confirm', effect: 'policy_revision',
    prepareTool: 'admin.policy_create_prepare', proposalKey: 'policyProposal', controlledOnly: true,
  }),
  Object.freeze({
    family: 'admin-acl', role: 'admin',
    confirmPath: '/agents/admin/assistant/acl/confirm', effect: 'acl_revision',
    prepareTool: 'admin.acl_permission_prepare', proposalKey: 'aclProposal', controlledOnly: true,
  }),
]);

const DENIALS = Object.freeze([
  'wrong_role',
  'foreign_tenant',
  'revoked_persona_session',
  'stale_generation',
  'platform_launch_substitution',
]);

// This is deliberately separate from TERMINALS.  These rows prove current
// customer HTTP admission before a provider or effect is reached; they do not
// turn the five selected confirmation positives above into a global Q07 claim.
// `foreign_tenant` is an exact owner-filtered outcome. `stale_generation`
// reaches the five commerce handlers after customer authentication; the
// gateway deliberately closes its unlisted stale-target error as 503. Refund
// turns a missing retained scene into SHOP_SCENE_STALE after committing SSE,
// so its router emits the closed fallback packet without changing HTTP 200.
const COMMERCE_STALE_GENERATION = Object.freeze({ status: 503,
  error: 'Bound SecureShop operation unavailable' });
const REFUND_STALE_GENERATION = Object.freeze({ status: 200,
  sseError: 'Refund service unavailable' });
const CUSTOMER_PRE_ADMISSION_TERMINALS = Object.freeze([
  Object.freeze({ family: 'cart', path: '/customer/commerce/cart/confirm', kind: 'cart',
    foreign: Object.freeze({ status: 503, error: 'Bound SecureShop operation unavailable' }),
    denials: Object.freeze({ stale_generation: COMMERCE_STALE_GENERATION }) }),
  Object.freeze({ family: 'address', path: '/customer/commerce/addresses', kind: 'address',
    foreign: Object.freeze({ status: 503, error: 'Bound SecureShop operation unavailable' }),
    denials: Object.freeze({ stale_generation: COMMERCE_STALE_GENERATION }) }),
  Object.freeze({ family: 'payment', path: '/customer/commerce/payment-methods', kind: 'payment',
    foreign: Object.freeze({ status: 503, error: 'Bound SecureShop operation unavailable' }),
    denials: Object.freeze({ stale_generation: COMMERCE_STALE_GENERATION }) }),
  Object.freeze({ family: 'checkout', path: '/customer/commerce/checkout/confirm', kind: 'checkout',
    foreign: Object.freeze({ status: 503, error: 'Bound SecureShop operation unavailable' }),
    denials: Object.freeze({ stale_generation: COMMERCE_STALE_GENERATION }) }),
  Object.freeze({ family: 'profile', path: '/customer/commerce/profile', kind: 'profile',
    foreign: Object.freeze({ status: 503, error: 'Bound SecureShop operation unavailable' }),
    denials: Object.freeze({ stale_generation: COMMERCE_STALE_GENERATION }) }),
  Object.freeze({ family: 'refund', path: '/agents/customer/refund/chat', kind: 'refund',
    foreign: Object.freeze({ status: 200, sseError: 'SecureShop launch unavailable' }),
    denials: Object.freeze({ stale_generation: REFUND_STALE_GENERATION }) }),
]);

const CUSTOMER_PRE_ADMISSION_DENIALS = Object.freeze([
  'wrong_role', 'foreign_tenant', 'revoked_persona_session', 'stale_generation',
  'platform_launch_substitution',
]);

// Native cross-store authority deliberately hides arbitrary nested storage
// errors from callers. The disposable fixture may retain this fixed diagnostic
// only when its own healthy checkout preflight fails.
const Q07_PREFLIGHT_CODES = new Set([
  'PERSONA_EFFECT_OUTCOME_UNCERTAIN', 'COMMERCE_CHOICE_DENIED',
  'COMMERCE_CHOICE_STALE', 'COMMERCE_OPERATION_CONFLICT',
  'COMMERCE_STATE_INVALID', 'CART_EMPTY', 'INSUFFICIENT_STOCK',
  'SHOP_AUTH_INVALID', 'PRODUCT_TARGET_UNAVAILABLE', 'SERVICE_UNAVAILABLE',
  'INVALID_ARGUMENT',
]);
const Q07_PREFLIGHT_MESSAGES = new Set([
  'Separate-store effect outcome requires authoritative readback',
  'Conversational commerce unavailable', 'Commerce effect requires authoritative readback',
  'Commerce authority unavailable', 'Existing product target unavailable',
]);
function diagnosticCode(value) { return Q07_PREFLIGHT_CODES.has(value) ? value : null; }
function diagnosticMessage(value) {
  return typeof value === 'string' && value.length <= 512 && Q07_PREFLIGHT_MESSAGES.has(value) ? value : null;
}
function checkoutPreflightDiagnostic(error) {
  const causes = []; let current = error?.cause;
  for (let index = 0; index < 3 && current && typeof current === 'object'; index += 1) {
    causes.push(Object.freeze({ code: diagnosticCode(current.code), message: diagnosticMessage(current.message) }));
    current = current.cause;
  }
  return Object.freeze({ version: 1, stage: 'checkout.prepare',
    code: diagnosticCode(error?.code), message: diagnosticMessage(error?.message),
    effectCallbackCompleted: error?.effectCallbackCompleted === true,
    causes: Object.freeze(causes) });
}

// Importing this finite data table into the native fixture must not register a
// second TAP test. The contract remains executable directly with node --test.
if (require.main === module) test('Q07 selected terminal matrix is finite, route-backed, and covers all five authority substitutions', () => {
  assert.deepEqual(TERMINALS.map(row => row.family), [
    'customer-ticket', 'merchant-listing', 'merchant-inventory', 'admin-policy', 'admin-acl',
  ]);
  assert.equal(new Set(TERMINALS.map(row => row.confirmPath)).size, TERMINALS.length);
  assert.equal(new Set(TERMINALS.map(row => row.effect)).size, TERMINALS.length);
  for (const terminal of TERMINALS) {
    assert.match(terminal.confirmPath, /^\/agents\/(customer|merchant|admin)\//);
    assert.ok(['customer', 'merchant', 'admin'].includes(terminal.role));
    assert.match(terminal.prepareTool, /^(support|merchant|admin)\./);
    assert.match(terminal.proposalKey, /Proposal$/);
    assert.equal(terminal.controlledOnly, !['customer-ticket', 'merchant-inventory'].includes(terminal.family),
      'Ticket and inventory ordinary confirmations require genuine provenance; other rows are controlled');
  }
  assert.deepEqual(DENIALS, [
    'wrong_role', 'foreign_tenant', 'revoked_persona_session', 'stale_generation',
    'platform_launch_substitution',
  ]);
  assert.equal(TERMINALS.length * DENIALS.length, 25);
  assert.deepEqual(CUSTOMER_PRE_ADMISSION_TERMINALS.map(row => row.family), [
    'cart', 'address', 'payment', 'checkout', 'profile', 'refund',
  ]);
  assert.equal(new Set(CUSTOMER_PRE_ADMISSION_TERMINALS.map(row => row.path)).size,
    CUSTOMER_PRE_ADMISSION_TERMINALS.length);
  for (const row of CUSTOMER_PRE_ADMISSION_TERMINALS) {
    assert.match(row.path, /^\/(customer\/commerce|agents\/customer)\//);
    assert.ok(['cart', 'address', 'payment', 'checkout', 'profile', 'refund'].includes(row.kind));
    assert.ok(Number.isInteger(row.foreign.status));
    assert.ok(typeof row.foreign.error === 'string' || typeof row.foreign.sseError === 'string');
    if (row.denials) {
      assert.deepEqual(Object.keys(row.denials), ['stale_generation']);
      const stale = row.denials.stale_generation;
      assert.ok(Number.isInteger(stale.status));
      assert.ok(typeof stale.error === 'string' || typeof stale.sseError === 'string');
    }
  }
  for (const row of CUSTOMER_PRE_ADMISSION_TERMINALS.filter(row => row.kind !== 'refund')) {
    assert.equal(row.denials.stale_generation, COMMERCE_STALE_GENERATION,
      `${row.family} shares the bound gateway stale projection`);
  }
  assert.equal(CUSTOMER_PRE_ADMISSION_TERMINALS.at(-1).denials.stale_generation,
    REFUND_STALE_GENERATION);
  assert.deepEqual(CUSTOMER_PRE_ADMISSION_DENIALS, DENIALS);
  assert.equal(CUSTOMER_PRE_ADMISSION_TERMINALS.length * CUSTOMER_PRE_ADMISSION_DENIALS.length, 30);
  const fourth = Object.assign(new Error('Commerce authority unavailable'), { code: 'SHOP_AUTH_INVALID' });
  const root = Object.assign(new Error('Separate-store effect outcome requires authoritative readback'), {
    code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', effectCallbackCompleted: false, cause: fourth,
  });
  const nested = Object.assign(new Error('Conversational commerce unavailable'), { code: 'CART_EMPTY', cause: root });
  const diagnostic = checkoutPreflightDiagnostic(Object.assign(new Error('untrusted'), {
    code: 'UNLISTED', effectCallbackCompleted: true, cause: nested,
  }));
  assert.deepEqual(diagnostic, { version: 1, stage: 'checkout.prepare', code: null, message: null,
    effectCallbackCompleted: true, causes: [
      { code: 'CART_EMPTY', message: 'Conversational commerce unavailable' },
      { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', message: 'Separate-store effect outcome requires authoritative readback' },
      { code: 'SHOP_AUTH_INVALID', message: 'Commerce authority unavailable' },
    ] });
});

module.exports = Object.freeze({ TERMINALS, DENIALS, CUSTOMER_PRE_ADMISSION_TERMINALS,
  CUSTOMER_PRE_ADMISSION_DENIALS, checkoutPreflightDiagnostic });
