'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { ensureReviewRenderer, ensureProductDescriptionRenderer, prepareInstalledRuntime } = require('../scripts/setup-application');

test('setup builds then loads and renders the exact application artifact', async () => {
  const calls = [], root = path.resolve('/owned/setup-fixture'), env = { NODE_ENV: 'development' };
  const result = await ensureReviewRenderer({ root, env,
    runCommand: async (command, args, cwd, environment) => {
      calls.push('build'); assert.match(command, /^npm(?:\.cmd)?$/);
      assert.deepEqual(args, ['run', 'build:review-renderer']);
      assert.equal(cwd, path.join(root, 'client')); assert.equal(environment, env);
    },
    loadRenderer: options => {
      calls.push('load'); assert.equal(options.root, path.join(root, 'client/build/secureshop-review-renderer'));
      return { sourceSha256: 'source', artifactSha256: 'artifact',
        renderReviewCard: async review => { calls.push('render'); return `<article>${review.body}</article>`; } };
    },
  });
  assert.deepEqual(calls, ['build', 'load', 'render']);
  assert.equal(result.ready, true);
});

test('setup stops on failed builds, missing artifacts and incorrect renderer output', async () => {
  await assert.rejects(ensureReviewRenderer({ root: '/owned',
    runCommand: async () => { throw new Error('build failed'); },
    loadRenderer: () => assert.fail('must not load after failed build'),
  }), /build failed/);
  await assert.rejects(ensureReviewRenderer({ root: '/owned', runCommand: async () => {},
    loadRenderer: () => { throw new Error('artifact unavailable'); },
  }), /artifact unavailable/);
  await assert.rejects(ensureReviewRenderer({ root: '/owned', runCommand: async () => {},
    loadRenderer: () => ({ renderReviewCard: async () => '' }),
  }), /renderer verification failed/);
});

for (const [kind, key, ensure, loader] of [
  ['review', 'SECURESHOP_REVIEW_RENDERER_ROOT', ensureReviewRenderer, 'loadRenderer'],
  ['product', 'SECURESHOP_PRODUCT_DESCRIPTION_RENDERER_ROOT', ensureProductDescriptionRenderer, 'loadProductRenderer'],
]) {
  const artifact = () => ({ componentId: 'SecureShop.Product.Description', sourceSha256: 'a'.repeat(64),
    artifactSha256: 'b'.repeat(64), renderReviewCard: async value => value.body,
    renderProductDescription: async value => value.description_html });
  test(`${kind} setup validates the effective absolute override and preserves environment bytes`, async () => {
    const root = path.resolve('/owned/setup'), configured = path.join(root, 'retained', '..', 'custom-artifact');
    const env = Object.freeze({ [key]: configured, PRIVATE_SETTING: 'unchanged\nvalue' });
    const before = JSON.stringify(env), calls = [];
    await ensure({ root, env, runCommand: async (_cmd, _args, cwd, received) => {
      calls.push('build'); assert.equal(cwd, path.join(root, 'client')); assert.equal(received, env);
    }, [loader]: options => { calls.push('load'); assert.equal(options.root, path.resolve(configured)); return artifact(); } });
    assert.deepEqual(calls, ['build', 'load']); assert.equal(JSON.stringify(env), before);
  });
  test(`${kind} setup uses the default artifact for an empty override`, async () => {
    const root = path.resolve('/owned/setup');
    await ensure({ root, env: { [key]: '' }, runCommand: async () => {}, [loader]: options => {
      assert.equal(options.root, path.join(root, 'client/build', kind === 'review' ? 'secureshop-review-renderer' : 'secureshop-product-description-renderer'));
      return artifact();
    } });
  });
  for (const invalid of ['relative/artifact', 42]) test(`${kind} setup rejects invalid override ${JSON.stringify(invalid)} before readiness`, async () => {
    await assert.rejects(prepareInstalledRuntime({ root: path.resolve('/owned/setup'), install: false,
      env: Object.freeze({ [key]: invalid }), runCommand: async () => {},
      loadRenderer: artifact, loadMailRenderer: () => ({ component: { id: 'SecureShop.MailMessageBody',
        sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }), loadProductRenderer: artifact,
      [loader]: () => assert.fail('invalid configured root must not be loaded'),
      verifyRuntime: () => assert.fail('must not reach readiness'),
    }), new RegExp(`${key} must be an absolute renderer directory`));
  });
  test(`${kind} setup does not fall back when the selected override is unavailable`, async () => {
    const selected = path.resolve('/owned/missing-artifact'), env = Object.freeze({ [key]: selected });
    let calls = 0;
    await assert.rejects(prepareInstalledRuntime({ root: path.resolve('/owned/setup'), install: false,
      env, runCommand: async () => {}, loadRenderer: artifact,
      loadMailRenderer: () => ({ component: { id: 'SecureShop.MailMessageBody', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64) } }),
      loadProductRenderer: artifact, [loader]: options => {
        calls++; assert.equal(options.root, selected); throw new Error('selected artifact unavailable');
      }, verifyRuntime: () => assert.fail('must not reach readiness'),
    }), /selected artifact unavailable/);
    assert.equal(calls, 1); assert.equal(env[key], selected);
  });
}
