'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const { createSecureShopPublicCatalogRepository } = require('../server/database/postgres/secureshopPublicCatalogRepository');
const { createSecureShopPublicCatalogRouter } = require('../server/routes/secureshop/publicCatalog');
const { createSecureShopBoundDispatch } = require('../server/middleware/secureshopBoundDispatch');

const productRow = { id: 4, name: 'Synthetic product', description: 'Public description',
  description_html: '<strong>Teaching HTML</strong>', price: '12.50', category: 'Books',
  image_url: '/images/books.jpg', stock_quantity: 8, status: 'active', avg_rating: '4.25',
  review_count: '2', images: [], retailer_id: 19, password: 'must-never-be-projected', template_source: 'private' };

function poolFixture({ exists = true } = {}) {
  const calls = [];
  const client = {
    release() { calls.push({ sql: 'RELEASE' }); },
    async query(sql, values = []) {
      calls.push({ sql, values });
      if (/^SELECT id FROM secureshop.products/.test(sql)) return { rows: exists ? [{ id: 4 }] : [] };
      if (/count\(\*\)::integer AS total/.test(sql)) return { rows: [{ total: 23 }] };
      if (/FROM secureshop.categories c/.test(sql)) return { rows: [{ id: 2, name: 'Books', description: 'Public category', private: 'omit' }] };
      if (/FROM secureshop.products p/.test(sql)) return { rows: exists ? [productRow] : [] };
      if (/FROM secureshop.reviews r/.test(sql)) return { rows: [{ id: 1, body: 'Public review', rating: 4,
        status: 'approved', author_name: 'Customer', created_at: '2026-10-09T00:00:00Z', author_id: 17, moderator_notes: 'private' }] };
      if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql) || sql.startsWith('SET TRANSACTION')) return { rows: [] };
      throw Error('Unexpected public catalog query');
    },
  };
  return { calls, pool: { query: client.query, connect: async () => client } };
}

test('public commerce browse is parameterized, consistent and restricted to public fields', async () => {
  const fixture = poolFixture();
  const result = await createSecureShopPublicCatalogRepository(fixture.pool).browse({
    search: "' OR 1=1--%_\\", category: 'Books', minRating: 4, maxPrice: 20,
    sort: 'price_desc', limit: 3, offset: 6,
  });
  assert.equal(result.total, 23); assert.equal(result.count, 1);
  assert.equal(result.products[0].price, 12.5); assert.equal(result.products[0].avg_rating, 4.25);
  assert.deepEqual(result.products[0].images, ['/images/books.jpg']);
  assert.equal(result.products[0].description_html, productRow.description_html);
  assert.equal(Object.hasOwn(result.products[0], 'password'), false);
  assert.equal(Object.hasOwn(result.products[0], 'retailer_id'), false);
  assert.equal(Object.hasOwn(result.products[0], 'template_source'), false);
  assert.equal(fixture.calls[0].sql, 'BEGIN');
  assert.equal(fixture.calls[1].sql, 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
  for (const { sql } of fixture.calls.filter(call => call.sql.startsWith('SELECT'))) {
    assert.match(sql, /p.status='active'/); assert.doesNotMatch(sql, /OR 1=1|shop_users|owner|snapshot/i);
  }
  const count = fixture.calls.find(call => call.sql.includes('count(*)::integer AS total'));
  const select = fixture.calls.find(call => call.sql.includes('LIMIT $5 OFFSET $6'));
  assert.deepEqual(count.values, ['Books', "%' OR 1=1--\\%\\_\\\\%", 4, 20]);
  assert.deepEqual(select.values, [...count.values, 3, 6]);
  assert.match(count.sql, /avg\(r.rating\)[\s\S]*r.status='approved'[\s\S]*>= \$3/);
  assert.match(count.sql, /p.price <= \$4/);
  assert.match(select.sql, /avg\(r.rating\)[\s\S]*r.status='approved'[\s\S]*>= \$3/);
  assert.match(select.sql, /p.price <= \$4/);
  assert.match(select.sql, /ORDER BY p.price DESC,p.id ASC/);
  assert.match(select.sql, /r.status='approved'/); assert.match(select.sql, /LIMIT 12/);
});

test('public detail, reviews, categories and static related reads never touch user or owner state', async () => {
  const fixture = poolFixture(), repository = createSecureShopPublicCatalogRepository(fixture.pool);
  assert.equal((await repository.product(4)).product.id, 4);
  const reviews = await repository.reviews(4, { limit: 2, offset: 1 });
  assert.equal(reviews.reviews[0].author_name, 'Customer');
  assert.equal(Object.hasOwn(reviews.reviews[0], 'author_id'), false);
  assert.equal(Object.hasOwn(reviews.reviews[0], 'moderator_notes'), false);
  const related = await repository.related(4, { limit: 3 });
  assert.equal(related.results[0].id, 4); assert.equal(related.recommendation, '');
  assert.deepEqual(await repository.categories(), { categories: [{ id: 2, name: 'Books', description: 'Public category' }] });
  const selects = fixture.calls.filter(call => call.sql.startsWith('SELECT'));
  for (const { sql } of selects) assert.doesNotMatch(sql, /shop_users|owned_|snapshot|persona|INSERT|UPDATE|DELETE/i);
  assert.match(selects.find(call => call.sql.includes("'Customer'::text")).sql, /r.status='approved'/);
  assert.deepEqual(selects.find(call => call.sql.includes('p.id<>$1')).values, [4, 3]);
  assert.match(selects.find(call => call.sql.includes('categories c')).sql, /p.status='active'/);
});

test('hidden or missing products deny detail, reviews and related without secondary reads', async () => {
  const fixture = poolFixture({ exists: false }), repository = createSecureShopPublicCatalogRepository(fixture.pool);
  assert.equal(await repository.product(4), null);
  assert.equal(await repository.reviews(4), null); assert.equal(await repository.related(4), null);
  assert.equal(fixture.calls.some(call => /FROM secureshop.reviews|p.id<>/.test(call.sql)), true,
    'detail contains approved rating subqueries but reviews and related do not run secondary reads');
  assert.equal(fixture.calls.some(call => /SELECT r.id|ORDER BY p.id LIMIT/.test(call.sql)), false);
});

async function httpFixture(t) {
  let available = true, fail = false, legacy = 0;
  const calls = [], app = express();
  const repository = {
    browse: async options => { calls.push(['browse', options]); if (fail) throw Error('private database detail'); return { products: [productRow], count: 1, total: 23 }; },
    product: async id => { calls.push(['product', id]); return id === 4 ? { product: productRow } : null; },
    reviews: async (id, options) => { calls.push(['reviews', id, options]); return { reviews: [], total: 0 }; },
    related: async (id, options) => { calls.push(['related', id, options]); return { results: [], recommendation: '' }; },
    categories: async () => { calls.push(['categories']); return { categories: [] }; },
  };
  app.use('/api/secureshop', createSecureShopBoundDispatch({ getGateway: () => null }));
  app.use('/api/secureshop/public', createSecureShopPublicCatalogRouter({
    getRepository: () => repository, isAvailable: async () => available,
  }));
  app.use('/api/secureshop', (_req, res) => { legacy++; res.status(418).json({ legacy: true }); });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { calls, setAvailable: value => { available = value; }, setFailure: () => { fail = true; },
    legacy: () => legacy, request: (suffix, options) => fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/public${suffix}`, options) };
}

test('all five public endpoints are reachable without platform token or a shop launch', async t => {
  const fixture = await httpFixture(t);
  for (const [url, key] of [['/products?search=book&sort=price_asc&page=2&limit=3', 'products'],
    ['/products/4', 'product'], ['/products/4/reviews?limit=5&offset=2', 'reviews'],
    ['/products/4/related?limit=2', 'results'], ['/categories', 'categories']]) {
    const response = await fixture.request(url);
    assert.equal(response.status, 200, url); assert.equal(response.headers.get('cache-control'), 'no-store');
    assert(Object.hasOwn(await response.json(), key));
  }
  assert.deepEqual(fixture.calls[0], ['browse', { category: null, search: 'book', minRating: null,
    maxPrice: null, sort: 'price_asc', limit: 3, offset: 3 }]);
  assert.equal(fixture.legacy(), 0);
});

test('rating and price filters reach the repository before public pagination', async t => {
  const fixture = await httpFixture(t);
  const response = await fixture.request('/products?minRating=5&maxPrice=2000&page=2&limit=12');
  assert.equal(response.status, 200);
  assert.deepEqual(fixture.calls[0], ['browse', { category: null, search: null,
    minRating: 5, maxPrice: 2000, sort: 'default', limit: 12, offset: 12 }]);
});

test('public visibility and missing products fail closed without falling through to customer routes', async t => {
  const fixture = await httpFixture(t);
  fixture.setAvailable(false); assert.equal((await fixture.request('/products')).status, 404); assert.equal(fixture.calls.length, 0);
  fixture.setAvailable(true); assert.equal((await fixture.request('/products/99')).status, 404);
  assert.equal((await fixture.request('/cart')).status, 404); assert.equal((await fixture.request('/recommended')).status, 404);
  assert.equal(fixture.legacy(), 0);
});

test('malformed, excess and authority query parameters cause 400 without catalog reads', async t => {
  const fixture = await httpFixture(t);
  for (const url of ['/products?limit=101', '/products?limit=-1', '/products?offset=100001', '/products?page=90000',
    '/products?limit=1.5', '/products?limit=2&limit=3', '/products?page=2&offset=0', '/products?sort=raw_sql',
    '/products?search=' + 'x'.repeat(201), '/products?category=' + 'x'.repeat(101), '/products?user_id=1',
    '/products?minRating=0', '/products?minRating=6', '/products?minRating=4.5',
    '/products?maxPrice=-1', '/products?maxPrice=200000', '/products?maxPrice=1.234',
    '/products?maxPrice=2&maxPrice=3',
    '/products?scenario_id=one', '/products/0', '/products/2147483648', '/products/4?includePrivate=true',
    '/products/4/reviews?limit=51', '/products/4/related?limit=13', '/categories?limit=2']) {
    assert.equal((await fixture.request(url)).status, 400, url);
  }
  assert.deepEqual(fixture.calls, []); assert.equal(fixture.legacy(), 0);
});

test('public writes, HEAD, and forged launch selection cannot use the guest boundary', async t => {
  const fixture = await httpFixture(t);
  for (const method of ['POST', 'PATCH', 'PUT', 'DELETE', 'HEAD']) {
    const response = await fixture.request('/products/4/reviews', { method });
    assert.equal(response.status, 405); assert.equal(response.headers.get('allow'), 'GET');
  }
  assert.equal((await fixture.request('/products', { headers: { 'x-dvaia-secureshop-launch': 'forged' } })).status, 503);
  assert.deepEqual(fixture.calls, []); assert.equal(fixture.legacy(), 0);
});

test('provider/database errors are unavailable without leaking internal details', async t => {
  const fixture = await httpFixture(t); fixture.setFailure();
  const response = await fixture.request('/products');
  assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: 'Public catalog unavailable' });
});

test('production mount precedes teaching routers and uses independent shop readiness', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../server/applicationServer.js'), 'utf8');
  const dispatch = source.indexOf("require('./middleware/secureshopBoundDispatch')");
  const mount = source.indexOf("app.use('/api/secureshop/public'");
  const customer = source.indexOf('const r = app.locals.secureshopV2Router');
  assert(dispatch >= 0 && mount > dispatch && customer > mount);
  assert.match(source.slice(mount, customer), /Boolean\(app.locals.secureshopPublicCatalog\)/);
  assert.doesNotMatch(source.slice(mount, customer), /getPostgresPlatformStores|secureshop_agent_security|isVisible/);
});
