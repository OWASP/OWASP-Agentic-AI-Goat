'use strict';

// Closed V25 composition seam, not a launcher or a native qualification.
// Repository-local output requires the parent's inherited, privately bound
// V25 grant; disposable store/activation admission and owner retirement remain
// separate, unqualified prerequisites. Never replace those with V33/V34 authority.
const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const LIVE_ENABLED = false;
const FIXTURE_MS = 840000, HELPER_MS = 780000;
const TARGET = 'original-v25-pricing-manual-private-consumer-v1';
const ORIGINAL = '../fixtures/secureshopPricingActual';
const EXECUTOR = './secureshopCustomerPricingActual.integration.test';
const KEYS = ['identity','im','agents','review','launches','conversations',
  'conversationRepository','turns','journal','coordinator','catalog','products',
  'authority','owner','auth'];
const fail = code => Object.assign(new Error(code), { code });

function contract() {
  const budget = require(ORIGINAL).actualPricingBudget(true, false, 'baseline').budget;
  assert.deepEqual(budget, { actor:20, judge:12, total:32,
    actorPerPhase:{manual_clean:8,manual_override:8,manual_upload:4},
    judgePerPhase:{manual_clean:6,manual_override:6} });
  return Object.freeze({ version:1, target:TARGET, liveEnabled:LIVE_ENABLED,
    fixtureMs:FIXTURE_MS, helperMs:HELPER_MS, budget,
    originalFixture:'tests/postgres/secureshopPricingJournal.integration.test.js',
    originalHelper:'tests/fixtures/secureshopPricingActual.js',
    acceptance:'tests/postgres/pricing_runtime_pins.py:require_manual_acceptance',
    qualificationComplete:false, builderReleaseAllowed:false,
    blockers:Object.freeze(['private-owner-v25-profile-not-admitted',
      'disposable-manual-store-admission-not-integrated',
      'composed-v25-native-qualification-not-run']) });
}

function run() { throw fail('V25_MANUAL_NOT_ADMITTED'); }

// Internal composition for controlled checks and later reviewed fixed owner
// wiring. A DTO, a returned observation, or local client closure is not resource
// ownership/absence proof. No generic lesson callback or caller-set duration.
async function _consume({ descriptorPath, descriptorSha256, expected,
  dependencies, startedAt, signal, admitted }) {
  contract();
  if (process.env.SECURESHOP_PRICING_V25_MANUAL_NATIVE === '1' && admitted === undefined)
    throw fail('V25_MANUAL_OWNER_ADMISSION');
  if (admitted !== undefined) {
    const output = require('../fixtures/pricingOwnedOutput');
    if (!output.isV25Admission(admitted) || descriptorPath !== admitted.descriptorPath
        || descriptorSha256 !== admitted.descriptorSha256 || expected !== admitted.expected
        || startedAt !== admitted.startedAt) throw fail('V25_MANUAL_OWNER_ADMISSION');
  }
  if (!Number.isFinite(startedAt) || startedAt < 0 || startedAt > performance.now()
      || !signal || typeof signal.throwIfAborted !== 'function')
    throw fail('V25_MANUAL_DEADLINE');
  if (!dependencies || Object.keys(dependencies).sort().join(',') !== [...KEYS].sort().join(',')
      || KEYS.some(key => dependencies[key] == null)) throw fail('V25_MANUAL_DEPENDENCIES');
  // Do not mutate process-wide selectors, accept a legacy mode, or choose a new
  // payload. The original helper remains the sole lesson implementation.
  if (process.env.PERSONA_PRICING_MANUAL_ONLY !== '1'
      || process.env.PERSONA_PRICING_ACTUAL_REMAINING !== '0'
      || process.env.PERSONA_PRICING_COHORT !== 'baseline') throw fail('V25_MANUAL_SELECTOR');
  const deadline = admitted === undefined ? startedAt + FIXTURE_MS
    : Math.min(startedAt + FIXTURE_MS, admitted.deadline);
  const active = () => { signal.throwIfAborted();
    if (performance.now() >= deadline) throw fail('V25_MANUAL_EXPIRED'); };
  active();
  const controller = new AbortController();
  const combined = AbortSignal.any([signal, controller.signal]);
  const timer = setTimeout(() => controller.abort(fail('V25_MANUAL_EXPIRED')),
    Math.max(1, deadline - performance.now()));
  let executor, observation, primary, failed = false;
  const receipt = { version:1, target:TARGET, helperStarted:false,
    helperJoined:false, localClientClosed:false,
    transportRetirementProven:false,
    executorRetirementOwnedByLauncher:true, qualificationComplete:false,
    builderReleaseAllowed:false, cleanupErrors:[] };
  try {
    executor = await require(EXECUTOR).openAdmittedPricingExecutor({
      descriptorPath, descriptorSha256, expected, signal:combined });
    active(); combined.throwIfAborted();
    // Startup consumes the same 840-second endpoint; never restart the clock
    // after readiness. The untouched helper owns its original 780-second timer.
    if (deadline - performance.now() <= HELPER_MS) throw fail('V25_MANUAL_HELPER_RESERVE');
    receipt.helperStarted = true;
    // This is deliberately not Promise.race: the original helper does not
    // accept our AbortSignal for its model work. The future owning process must
    // enforce the 840-second wall and prove child absence before teardown.
    // Locally we await the actual helper/finally, even after an external abort.
    try { observation = await require(ORIGINAL)({ ...dependencies, client:executor.client }); }
    finally { receipt.helperJoined = true; }
    active(); combined.throwIfAborted();
  } catch (error) { primary = error; failed = true; }
  finally {
    clearTimeout(timer); controller.abort();
    if (executor) {
      try {
        await executor.close();
        assert.deepEqual(executor.retirement(), {
          localClientClosed:true, executorRetirementOwnedByLauncher:true });
        receipt.localClientClosed = true;
        // This is exactly the reused client's API-promise observation, not
        // proof that an abort-unresponsive fetch/socket or remote service died.
        // The owning process and private runtime must separately prove that.
      } catch (error) {
        receipt.cleanupErrors.push('private-client');
        if (!failed) { primary = error; failed = true; }
      }
    } else {
      // A rejected open may carry unresolved validation/transport work. Do not
      // manufacture an absence statement merely because no handle returned.
      receipt.cleanupErrors.push('private-client-open-unproven');
    }
    // Joining close does not renew the original endpoint. Preserve any earlier
    // helper/retirement failure, but never return an otherwise successful result
    // when close finishes late (or the caller aborts while it is joining).
    if (!failed) {
      try { active(); }
      catch (error) { primary = error; failed = true; }
    }
  }
  if (failed) {
    // No descriptor, Authorization token, arbitrary exception message or stack
    // is copied into the diagnostic receipt. Preserve the actual primary error.
    try { Object.defineProperty(primary, 'manualConsumer', { value:receipt }); } catch {}
    throw primary;
  }
  return { observation, receipt };
}

module.exports = { LIVE_ENABLED, contract, run, _consume };
