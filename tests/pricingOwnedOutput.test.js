'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { pricingOwnedOutputRoot } = require('./fixtures/pricingOwnedOutput');
test('V25 output root rejects environment-only authority without inherited parent grant', t => {
  const previous = process.env.SECURESHOP_PRICING_V25_MANUAL_NATIVE;
  process.env.SECURESHOP_PRICING_V25_MANUAL_NATIVE = '1';
  t.after(() => { if(previous === undefined) delete process.env.SECURESHOP_PRICING_V25_MANUAL_NATIVE;
    else process.env.SECURESHOP_PRICING_V25_MANUAL_NATIVE = previous; });
  assert.throws(pricingOwnedOutputRoot, /inherited owner admission required/);
});
const { writePricingActivationDiagnostic } = require('./fixtures/secureshopPricingAssembled');

test('pricing output stays in an owned private directory outside current source', () => {
  const parent = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'pricing-output-test-'));
  const source = path.join(parent, 'source');
  const output = path.join(parent, 'output');
  fs.mkdirSync(source, { mode: 0o700 });
  fs.mkdirSync(output, { mode: 0o700 });
  const priorRoot = process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT;
  const priorSource = process.env.DVAIA_ISOLATED_TEST_WORKSPACE;
  try {
    process.env.DVAIA_ISOLATED_TEST_WORKSPACE = source;
    process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT = output;
    assert.equal(pricingOwnedOutputRoot(), output);
    process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT = source;
    assert.throws(pricingOwnedOutputRoot, /outside source/);
    process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT = path.join(source, 'nested');
    fs.mkdirSync(process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT, { mode: 0o700 });
    assert.throws(pricingOwnedOutputRoot, /outside source/);
    fs.chmodSync(output, 0o755);
    process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT = output;
    assert.throws(pricingOwnedOutputRoot, /permissions mismatch/);
    fs.chmodSync(output, 0o700);
    const link = path.join(parent, 'link');
    fs.symlinkSync(output, link);
    process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT = link;
    assert.throws(pricingOwnedOutputRoot, /exact absolute directory/);
  } finally {
    if (priorRoot === undefined) delete process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT;
    else process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT = priorRoot;
    if (priorSource === undefined) delete process.env.DVAIA_ISOLATED_TEST_WORKSPACE;
    else process.env.DVAIA_ISOLATED_TEST_WORKSPACE = priorSource;
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test('assembled Pricing diagnostic writes only to its private output root', () => {
  const parent = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'pricing-assembled-output-'));
  const source = path.join(parent, 'source');
  const output = path.join(parent, 'output');
  fs.mkdirSync(source, { mode: 0o700 });
  fs.mkdirSync(output, { mode: 0o700 });
  const priorCwd = process.cwd();
  const priorRoot = process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT;
  const priorSource = process.env.DVAIA_ISOLATED_TEST_WORKSPACE;
  try {
    process.chdir(source);
    process.env.DVAIA_ISOLATED_TEST_WORKSPACE = source;
    process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT = output;
    const diagnostics = [{ kind: 'managed', identity: 'synthetic' }];
    writePricingActivationDiagnostic(diagnostics);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(output, 'pricing-activation-diagnostic.json'), 'utf8')), diagnostics);
    assert.equal(fs.existsSync(path.join(source, 'pricing-activation-diagnostic.json')), false);
  } finally {
    process.chdir(priorCwd);
    if (priorRoot === undefined) delete process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT;
    else process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT = priorRoot;
    if (priorSource === undefined) delete process.env.DVAIA_ISOLATED_TEST_WORKSPACE;
    else process.env.DVAIA_ISOLATED_TEST_WORKSPACE = priorSource;
    fs.rmSync(parent, { recursive: true, force: true });
  }
});
