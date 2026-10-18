'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const assetPath = path.join(root, 'client/public/secureshop/product-placeholder.svg');
const seedPath = path.join(root, 'db/postgres/seeds/secureshop.json');
const migrationPath = path.join(root, 'db/postgres/workshop-migrations/secureshop/0003_local_product_assets.sql');
const legacyDefaultsPath = path.join(root, 'client/src/pages/secureshop/utils/legacyProductImageDefaults.json');
const localAsset = '/secureshop/product-placeholder.svg';

test('bundled SecureShop product image is inert, local, and used by every shipped PostgreSQL default', () => {
  const svg = fs.readFileSync(assetPath, 'utf8');
  assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.doesNotMatch(svg, /<(?:script|foreignObject)\b|\b(?:href|src)\s*=/i);

  const seed = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
  assert.equal(seed.products.length, 125);
  assert.equal(seed.product_images.length, 375);
  assert(seed.products.every(row => row.image_url === localAsset));
  assert(seed.product_images.every(row => row.path === localAsset && row.mime === 'image/svg+xml'));
  assert.doesNotMatch(JSON.stringify({ products: seed.products, product_images: seed.product_images }), /picsum\.photos/);
});

test('persisted-default migration is exact, import-safe, custom-safe, and registered', () => {
  const sql = fs.readFileSync(migrationPath, 'utf8');
  assert.doesNotMatch(sql, /(^|\n)\s*(?:BEGIN|COMMIT)\s*;/i,
    'the production migration loader owns the transaction boundary');
  const productSection = /WITH product_defaults\(id,prior_url\) AS \(VALUES\n([\s\S]*?)\n\),\nchanged_products/.exec(sql);
  const imageSection = /image_defaults\(id,product_id,prior_path,prior_mime\) AS \(VALUES\n([\s\S]*?)\n\)\nUPDATE/.exec(sql);
  assert(productSection && imageSection);

  const products = [...productSection[1].matchAll(/\((\d+),'([^']+)'\)/g)]
    .map(match => ({ id: Number(match[1]), value: match[2] }));
  const images = [...imageSection[1].matchAll(/\((\d+),(\d+),'([^']+)','([^']+)'\)/g)]
    .map(match => ({ id: Number(match[1]), productId: Number(match[2]), value: match[3], mime: match[4] }));
  assert.equal(products.length, 125);
  assert.equal(images.length, 375);
  assert.equal(new Set(products.map(row => row.id)).size, 125);
  assert.equal(new Set(images.map(row => row.id)).size, 375);
  assert(products.every(row => row.value === localAsset || row.value.startsWith('/images/')
    || /^https:\/\/picsum\.photos\/seed\/ss_/.test(row.value)));
  assert(images.every(row => row.value.startsWith('/images/')
    || /^https:\/\/picsum\.photos\/seed\/ss_/.test(row.value)));

  assert.match(sql, /product\.id=shipped\.id AND product\.image_url=shipped\.prior_url/);
  assert.match(sql, /image\.id=shipped\.id AND image\.product_id=shipped\.product_id/);
  assert.match(sql, /image\.path=shipped\.prior_path AND image\.mime IS NOT DISTINCT FROM shipped\.prior_mime/);
  assert.equal((sql.match(/NOT EXISTS\(SELECT 1 FROM secureshop\.import_batches\)/g) || []).length, 2);
  assert.doesNotMatch(sql, /\b(?:DELETE|TRUNCATE|DROP|ALTER)\b/i);
  assert.equal(fs.existsSync(migrationPath), true);

  const custom = { id: 6, image_url: 'https://merchant.example/custom.png' };
  const shipped = products.find(row => row.id === custom.id);
  assert.notEqual(custom.image_url, shipped.value, 'exact prior-value guard preserves a customized row');
});

test('runtime fallbacks use the bundled asset without weakening foreign URL handling', async () => {
  const policy = await import('../client/src/pages/secureshop/utils/assetUrl.mjs');
  assert.equal(policy.BUNDLED_PRODUCT_IMAGE, localAsset);
  assert.equal(policy.isRenderableSecureShopImageUrl(localAsset), true);
  assert.equal(policy.isRenderableSecureShopImageUrl('https://merchant.example/custom.png'), true);
  assert.equal(policy.isRenderableSecureShopImageUrl('https://picsum.photos/seed/ss_7_a/600/800'), false);
  assert.equal(policy.isRenderableSecureShopImageUrl('https://picsum.photos/seed/ss_custom_import/600/800'), true);
  assert.equal(policy.isRenderableSecureShopImageUrl('//picsum.photos/seed/ss_7_a/600/800'), false);

  for (const relative of [
    'client/src/pages/secureshop/components/ProductCard.jsx',
    'client/src/pages/secureshop/pages/Product.jsx',
    'agent-host/agents/product-search/tools/similar.postgres.js',
  ]) {
    const source = fs.readFileSync(path.join(root, relative), 'utf8');
    assert.match(source, /BUNDLED_PRODUCT_IMAGE/);
    assert.doesNotMatch(source, /`https:\/\/picsum\.photos|return ['"]https:\/\/picsum\.photos/);
    if (relative.includes('/tools/similar')) {
      assert.match(source, /legacyProductImageDefaults\.json/);
      assert.match(source, /LEGACY_DEFAULT_IMAGES\.has\(src\)/);
      assert.doesNotMatch(source, /LEGACY_DEFAULT_IMAGE\s*=\s*\//);
    }
  }
  const compatibilityWrapper = fs.readFileSync(path.join(root,
    'agent-host/agents/product-search/tools/similar.js'), 'utf8');
  assert.match(compatibilityWrapper, /module\.exports\s*=\s*require\(['"]\.\/similar\.postgres\.js['"]\)/,
    'the retained entry point delegates to the PostgreSQL implementation');
  assert.doesNotMatch(compatibilityWrapper, /better-sqlite3|sqlite3|SS_DB_PATH|picsum\.photos/);
});

test('legacy runtime substitution is limited to the exact reviewed shipped URL set', () => {
  const sql = fs.readFileSync(migrationPath, 'utf8');
  const fromCandidate = [...new Set([...sql.matchAll(/'(https:\/\/picsum\.photos\/seed\/ss_[^']+)'/g)]
    .map(match => match[1]))].sort();
  const allowlist = JSON.parse(fs.readFileSync(legacyDefaultsPath, 'utf8'));
  assert.deepEqual(allowlist, [...allowlist].sort());
  assert.equal(new Set(allowlist).size, allowlist.length);
  assert.deepEqual(allowlist, fromCandidate);
  assert.equal(allowlist.includes('https://picsum.photos/seed/ss_custom_import/600/800'), false);
});
