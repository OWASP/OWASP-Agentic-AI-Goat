'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { withPostgresRepositoryDoubles } = require('../../fixtures/postgresRepositoryDoubles');

function fixture() {
  return {
    state: {
      nextId: 2,
      products: [{ id: 1, name: 'Existing', image_url: 'thing.jpg', price: 1, category: 'Old' }],
    },
    methods: {
      async listing_create_1({ state }, name, description, descriptionHtml, templateSource, price, imageUrl, retailerId) {
        const row = { id: state.nextId++, name, description, description_html: descriptionHtml,
          template_source: templateSource, price, image_url: imageUrl, retailer_id: retailerId };
        state.products.push(row);
        return { lastInsertRowid: row.id };
      },
      async updateProduct({ state }, productId, patch) {
        const row = state.products.find(product => product.id === productId);
        if (!row) return { changes: 0 };
        Object.assign(row, patch);
        return { changes: 1 };
      },
      async listing_optimize_images_1({ state }, productId) {
        const row = state.products.find(product => product.id === productId);
        return row ? { ...row } : null;
      },
      async listing_import_bulk_1({ state }, name, description, price) {
        const row = { id: state.nextId++, name, description, price };
        state.products.push(row);
        return { lastInsertRowid: row.id };
      },
    },
  };
}

test('listing create stores rewritten HTML and exact product fields', async () => {
  await withPostgresRepositoryDoubles({ commerce: fixture() }, async scope => {
    const { create } = scope.loadFresh('agent-host/agents/listing/tools/create.js');
    const description = '<img src=x onerror=alert(1)>';
    const result = await create({ title: 'Widget', description, price: 9.99, images: ['raw.png'], retailer_id: 8 });
    assert.equal(result.ok, true);
    assert.match(result.description_html, /onerror=alert\(1\)/);
    const saved = scope.commerceState.products.at(-1);
    assert.equal(saved.description, description);
    assert.equal(saved.description_html, result.description_html);
    assert.deepEqual(scope.calls[0].args, ['Widget', description, result.description_html, null, 9.99, 'raw.png', 8]);
  });
});

test('listing update passes only allowed fields to the repository', async () => {
  await withPostgresRepositoryDoubles({ commerce: fixture() }, async scope => {
    const { update } = scope.loadFresh('agent-host/agents/listing/tools/update.js');
    assert.deepEqual(await update({ product_id: 1, patch: { price: 42.42, category: 'Home', owner_id: 999 } }),
      { ok: true, changed: 1, product_id: 1 });
    assert.deepEqual(scope.calls[0].args, [1, { price: 42.42, category: 'Home' }]);
    assert.equal(scope.commerceState.products[0].price, 42.42);
  });
});

test('listing optimize_images exposes the raw shell command without execution', async () => {
  const previous = process.env.SS_LISTING_ALLOW_EXEC;
  process.env.SS_LISTING_ALLOW_EXEC = 'false';
  try {
    await withPostgresRepositoryDoubles({ commerce: fixture() }, async scope => {
      const { optimize_images } = scope.loadFresh('agent-host/agents/listing/tools/optimize_images.js');
      const result = await optimize_images({ product_id: 1 });
      assert.equal(result.executed, false);
      assert.equal(result.cmd, 'convert thing.jpg -strip -quality 82 thing.jpg.opt.jpg');
      assert.deepEqual(scope.calls[0].args, [1]);
    });
  } finally {
    if (previous === undefined) delete process.env.SS_LISTING_ALLOW_EXEC;
    else process.env.SS_LISTING_ALLOW_EXEC = previous;
  }
});

test('listing import_bulk reads an unrestricted file URL and persists exact decoded values', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-listing-import-'));
  const input = path.join(dir, 'catalog.json');
  fs.writeFileSync(input, JSON.stringify([{ name: 'Import1', description: 'imp', price: 1.11 }]));
  try {
    await withPostgresRepositoryDoubles({ commerce: fixture() }, async scope => {
      const { import_bulk } = scope.loadFresh('agent-host/agents/listing/tools/import_bulk.js');
      const result = await import_bulk({ json_url: pathToFileURL(input).href });
      assert.deepEqual(result, { ok: true, inserted: [2], errors: [] });
      assert.deepEqual(scope.calls[0].args, ['Import1', 'imp', 1.11]);
      assert.deepEqual(scope.commerceState.products.at(-1), { id: 2, name: 'Import1', description: 'imp', price: 1.11 });
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
