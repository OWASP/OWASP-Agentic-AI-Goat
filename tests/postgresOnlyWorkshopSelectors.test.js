'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const databaseRoot = path.join(__dirname, '..', 'server', 'database');

const directSelectors = [
  'sqlWorkshopDb',
  'nosqlWorkshopDb',
  'xssWorkshopDb',
  'csrfWorkshopDb',
  'mcpWorkshopDb',
  'supplyChainWorkshopDb',
  'sensitiveInfoDb',
  'sensitiveInfoWorkshopDb'
];

const legacyChallengeMethods = [
  'getVulnerabilitySetting',
  'listVulnerabilitySettings',
  'saveConversation',
  'readConversations',
  'searchProducts',
  'searchCommerceProducts',
  'readDemoUser',
  'readProduct',
  'readReviews',
  'addComment',
  'listComments',
  'addFile',
  'addManagedFile',
  'addReview',
  'readCart',
  'countCart',
  'addCart',
  'createOrder',
  'moveOrderItems',
  'clearCart',
  'readOrders',
  'updateDemoProfile',
  'executeAiSql',
  'executeNoSqlSimulation'
];

function withStubbedModule(modulePath, exports, callback) {
  const resolved = require.resolve(modulePath);
  const selectorPaths = [
    require.resolve('../server/database/legacyChallengeConfigStore'),
    require.resolve('../server/database/legacyChallengeStore')
  ];
  const previous = require.cache[resolved];
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports };
  selectorPaths.forEach(selectorPath => delete require.cache[selectorPath]);

  return Promise.resolve()
    .then(callback)
    .finally(() => {
      selectorPaths.forEach(selectorPath => delete require.cache[selectorPath]);
      if (previous) require.cache[resolved] = previous;
      else delete require.cache[resolved];
    });
}

test('workshop selectors are unconditional PostgreSQL module exports', () => {
  for (const name of directSelectors) {
    const selector = require(`../server/database/${name}`);
    const postgres = require(`../server/database/postgres/${name}`);
    assert.strictEqual(selector, postgres, name);
  }

  for (const name of [...directSelectors, 'legacyChallengeConfigStore', 'legacyChallengeStore']) {
    const source = fs.readFileSync(path.join(databaseRoot, `${name}.js`), 'utf8');
    assert.doesNotMatch(source, /(?:sqlite3|better-sqlite3|\.\/init|DATABASE_ENGINE)/, name);
  }
});

test('legacy challenge config keeps its PostgreSQL forwarding API', async () => {
  const calls = [];
  await withStubbedModule('../server/database/postgres/xssWorkshopDb', {
    getSolutionsEnabled: async () => { calls.push(['get']); return true; },
    setSolutionsEnabled: async value => { calls.push(['set', value]); return value; }
  }, async () => {
    const store = require('../server/database/legacyChallengeConfigStore');
    assert.deepEqual(Object.keys(store).sort(), ['getSolutionsEnabled', 'setSolutionsEnabled']);
    assert.equal(await store.getSolutionsEnabled(), true);
    assert.equal(await store.setSolutionsEnabled(false), false);
    assert.deepEqual(calls, [['get'], ['set', false]]);
  });
});

test('legacy challenge store keeps Promise and callback compatibility over PostgreSQL', async () => {
  const calls = [];
  const postgres = Object.fromEntries(legacyChallengeMethods.map(name => [name, async (...args) => {
    calls.push([name, ...args]);
    return name === 'addComment' ? { lastID: 41, changes: 1 } : { name, args };
  }]));

  await withStubbedModule('../server/database/postgres/legacyChallengeDb', postgres, async () => {
    const store = require('../server/database/legacyChallengeStore');
    assert.equal(store.engine, 'postgres');
    assert.deepEqual(Object.keys(store).sort(), ['engine', ...legacyChallengeMethods].sort());
    assert.deepEqual(await store.searchProducts('needle'), {
      name: 'searchProducts',
      args: ['needle']
    });

    await new Promise((resolve, reject) => {
      store.addComment(7, 'hello', function (error, value) {
        try {
          assert.ifError(error);
          assert.deepEqual(value, { lastID: 41, changes: 1 });
          assert.equal(this.lastID, 41);
          assert.equal(this.changes, 1);
          resolve();
        } catch (assertionError) {
          reject(assertionError);
        }
      });
    });

    assert.deepEqual(calls, [
      ['searchProducts', 'needle'],
      ['addComment', 7, 'hello']
    ]);
  });
});
