'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const express = require('express');
const { createPool } = require('../../server/database/postgres');
const { initializeSecureShopCommerceDb } = require('../../server/database/postgres/secureshopInitialization');
const { createSecureShopPublicCatalogRepository } = require('../../server/database/postgres/secureshopPublicCatalogRepository');
const { createSecureShopPublicCatalogRouter } = require('../../server/routes/secureshop/publicCatalog');

const PREFIX = 'PG_SECURESHOP_PUBLIC_CATALOG_TEST';
function admitDisposableCommerce() {
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes', 'Explicit disposable PostgreSQL admission required');
  const urls = ['RUNTIME', 'MIGRATION'].map(kind => {
    let url;
    try { url = new URL(process.env[`${PREFIX}_${kind}_URL`]); }
    catch { throw Error('Explicit disposable public catalog database pair required'); }
    assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
    assert.equal(url.hostname, '127.0.0.1', 'Only explicit loopback disposable commerce admitted');
    assert.match(url.port, /^[0-9]+$/); assert.ok(Number(url.port) > 0 && Number(url.port) <= 65535);
    assert.match(url.pathname, /^\/owasp_ai_goat_test_[a-z0-9_]+$/);
    assert.equal(url.search, ''); assert.equal(url.hash, '');
    assert.equal(url.username, `dvaia_secureshop_${kind.toLowerCase()}`);
    return url;
  });
  assert.equal(urls[0].host, urls[1].host); assert.equal(urls[0].pathname, urls[1].pathname);
}

test('native public catalog uses literal search, approved active projections and static related reads', {
  skip: process.env.PG_TEST_DISPOSABLE !== 'yes', timeout: 60000,
}, async () => {
  // Admission precedes all pool creation and all fixture writes. Application
  // URLs, arbitrary cluster names and application runtime roles cannot opt in.
  admitDisposableCommerce();
  const runtime = createPool(process.env, `${PREFIX}_RUNTIME_URL`);
  const migration = createPool(process.env, `${PREFIX}_MIGRATION_URL`);
  let server;
  try {
    await initializeSecureShopCommerceDb({ runtimePool: runtime, migrationPool: migration });
    const marker = randomUUID(), category = `Public catalog ${marker}`, otherCategory = `Other ${marker}`;
    await migration.query('INSERT INTO secureshop.categories(name,description) VALUES($1,$2),($3,$2)',
      [category, 'Owned disposable public catalog fixture', otherCategory]);
    const privateCanary = `private-${marker}`;
    const author = (await migration.query(`INSERT INTO secureshop.shop_users
      (username,email,password,api_key,session_token,pii_json)
      VALUES($1,$2,$3,$3,$3,$3) RETURNING id`,
    [`public-review-${marker}`, `${marker}@public-catalog.invalid`, privateCanary])).rows[0].id;
    const fixtures = [
      ['Percent%', 30, 'active', category], ['Underscore_', 10, 'active', category],
      ['Backslash\\', 20, 'active', category], ['Plain', 40, 'active', category],
      ['Hidden%', 5, 'inactive', category], ['Other', 4, 'active', otherCategory],
    ];
    const ids = [];
    for (const [index, [name, price, status, group]] of fixtures.entries()) {
      ids.push((await migration.query(`INSERT INTO secureshop.products
        (name,description,description_html,price,category,image_url,stock_quantity,status,retailer_id,template_source,created_at)
        VALUES($1,$2,$3,$4,$5,$6,7,$7,$8,$9,$10) RETURNING id`,
      [`Guest ${marker} ${name}`, 'Literal public fixture', '<strong>Public teaching HTML</strong>',
        price, group, '/secureshop/product-placeholder.svg', status, author, privateCanary,
        `2026-01-0${index + 1}T00:00:00.000Z`])).rows[0].id);
    }
    const [percent, underscore, backslash, plain, hidden, other] = ids;
    await migration.query(`INSERT INTO secureshop.product_images(product_id,path,mime,uploaded_by)
      VALUES($1,$2,'image/svg+xml',$3)`, [percent, '/secureshop/product-placeholder.svg', author]);
    const reviewIds = [];
    for (const [status, body, rating] of [['approved', 'Approved public review', 4],
      ['pending', 'Pending private review', 1], ['rejected', 'Rejected private review', 2]]) {
      reviewIds.push((await migration.query(`INSERT INTO secureshop.reviews
        (product_id,author_id,body,rating,status,moderator_notes)
        VALUES($1,$2,$3,$4,$5,$6) RETURNING id`, [percent, author, body, rating, status, privateCanary])).rows[0].id);
    }
    const before = (await runtime.query(`SELECT
      (SELECT count(*)::integer FROM secureshop.shop_users) AS users,
      (SELECT count(*)::integer FROM secureshop.products) AS products,
      (SELECT count(*)::integer FROM secureshop.reviews) AS reviews,
      (SELECT count(*)::integer FROM secureshop.cart_items) AS cart,
      (SELECT count(*)::integer FROM secureshop.orders) AS orders`)).rows[0];
    const repository = createSecureShopPublicCatalogRepository(runtime);
    const app = express();
    app.use('/api/secureshop/public', createSecureShopPublicCatalogRouter({
      getRepository: () => repository, isAvailable: async () => true,
    }));
    server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    const request = async suffix => {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/public${suffix}`);
      return { status: response.status, body: await response.json() };
    };
    const browse = async options => {
      const response = await request('/products?' + new URLSearchParams({ category, ...options }));
      assert.equal(response.status, 200); return response.body;
    };
    // Native LIKE execution must treat each wildcard/escape character literally.
    for (const [search, expectedId] of [['%', percent], ['_', underscore], ['\\', backslash], ['PLAIN', plain]]) {
      const found = await browse({ search });
      assert.equal(found.total, 1); assert.deepEqual(found.products.map(row => row.id), [expectedId]);
    }
    assert.deepEqual((await browse({ search: "%' OR 1=1 --" })).products, []);
    const ascending = await browse({ sort: 'price_asc' });
    assert.equal(ascending.total, 4); assert.equal(ascending.count, 4);
    assert.deepEqual(ascending.products.map(row => row.id), [underscore, backslash, percent, plain]);
    assert.deepEqual((await browse({ sort: 'price_desc' })).products.map(row => row.id), [plain, percent, backslash, underscore]);
    assert.deepEqual((await browse({ sort: 'newest' })).products.map(row => row.id), [plain, backslash, underscore, percent]);
    assert.deepEqual((await browse({ sort: 'price_asc', limit: '2', offset: '2' })).products.map(row => row.id), [percent, plain]);
    assert.deepEqual((await browse({ sort: 'price_asc', limit: '2', page: '2' })).products.map(row => row.id), [percent, plain]);
    const beyond = await browse({ offset: '500' });
    assert.equal(beyond.total, 4); assert.equal(beyond.count, 0); assert.deepEqual(beyond.products, []);
    assert.deepEqual((await browse({ category: otherCategory })).products.map(row => row.id), [other]);
    const detail = await request(`/products/${percent}`);
    assert.equal(detail.status, 200); assert.equal(detail.body.product.price, 30);
    assert.equal(detail.body.product.avg_rating, 4); assert.equal(detail.body.product.review_count, 1);
    assert.equal(detail.body.product.description_html, '<strong>Public teaching HTML</strong>');
    assert.deepEqual(detail.body.product.images, ['/secureshop/product-placeholder.svg']);
    for (const field of ['retailer_id', 'template_source', 'password', 'api_key', 'session_token', 'pii_json']) {
      assert.equal(Object.hasOwn(detail.body.product, field), false, field);
      for (const product of ascending.products) assert.equal(Object.hasOwn(product, field), false, field);
    }
    const reviews = await request(`/products/${percent}/reviews?limit=1`);
    assert.equal(reviews.status, 200); assert.equal(reviews.body.total, 1);
    assert.deepEqual(reviews.body.reviews.map(row => row.id), [reviewIds[0]]);
    assert.equal(reviews.body.reviews[0].author_name, 'Customer');
    assert.equal(reviews.body.reviews[0].status, 'approved');
    assert.equal(JSON.stringify(reviews.body).includes(privateCanary), false);
    for (const field of ['author_id', 'moderator_notes', 'password', 'api_key', 'pii_json']) {
      assert.equal(Object.hasOwn(reviews.body.reviews[0], field), false, field);
    }
    const related = await request(`/products/${percent}/related?limit=2`);
    assert.equal(related.status, 200); assert.equal(related.body.recommendation, '');
    assert.deepEqual(related.body.results.map(row => row.id), [underscore, backslash]);
    assert(related.body.results.every(row => row.id !== percent && row.id !== hidden && row.id !== other));
    const categories = await request('/categories'); assert.equal(categories.status, 200);
    assert(categories.body.categories.some(row => row.name === category));
    for (const id of [hidden, 2147483647]) for (const suffix of ['', '/reviews', '/related']) {
      assert.equal((await request(`/products/${id}${suffix}`)).status, 404);
    }
    for (const id of ['0', '-1', '1.5', 'not-a-product', '2147483648']) {
      assert.equal((await request(`/products/${id}`)).status, 400);
    }
    // Qualify actual seeded asset URLs without replacing them with fixture data.
    const seeded = await request('/products/1'); assert.equal(seeded.status, 200);
    for (const asset of [seeded.body.product.image_url, ...seeded.body.product.images]) {
      assert.equal(asset, '/secureshop/product-placeholder.svg');
      assert(fs.statSync(path.join(__dirname, '../../client/public', asset.slice(1))).isFile());
    }
    const after = (await runtime.query(`SELECT
      (SELECT count(*)::integer FROM secureshop.shop_users) AS users,
      (SELECT count(*)::integer FROM secureshop.products) AS products,
      (SELECT count(*)::integer FROM secureshop.reviews) AS reviews,
      (SELECT count(*)::integer FROM secureshop.cart_items) AS cart,
      (SELECT count(*)::integer FROM secureshop.orders) AS orders`)).rows[0];
    assert.deepEqual(after, before, 'Guest reads create no user, commerce or review mutations');
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await Promise.allSettled([runtime.end(), migration.end()]);
  }
});
