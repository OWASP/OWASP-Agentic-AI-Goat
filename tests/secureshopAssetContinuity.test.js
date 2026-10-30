'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const express = require('express');
const jwt = require('jsonwebtoken');

const {
  DEFAULT_UPLOAD_ROOT,
  getSecureShopUploadRoot,
  productWithMountedAssetUrls,
  storedSecureShopAssetReferenceToRuntimeTarget,
  toMountedSecureShopAssetUrl,
  toSecureShopAssetRelativePath,
} = require('../server/services/secureshop/assetPaths');

test('upload root requires an absolute configured path and retains the existing default', () => {
  assert.equal(getSecureShopUploadRoot({}), DEFAULT_UPLOAD_ROOT);
  assert.equal(getSecureShopUploadRoot({ SECURESHOP_UPLOAD_ROOT: '/tmp/owasp-ai-goat-assets/../active' }), '/tmp/active');
  assert.throws(
    () => getSecureShopUploadRoot({ SECURESHOP_UPLOAD_ROOT: 'relative/uploads' }),
    (error) => error.code === 'INVALID_SECURESHOP_UPLOAD_ROOT',
  );
});

test('only known upload references become runtime-relative paths and mounted URLs', () => {
  const root = path.resolve('/private/owasp-ai-goat-assets');
  assert.equal(
    toSecureShopAssetRelativePath('server/uploads/secureshop/product_images/7/a b.svg'),
    'product_images/7/a b.svg',
  );
  assert.equal(toSecureShopAssetRelativePath('avatars/3/me.png'), 'avatars/3/me.png');
  assert.equal(
    storedSecureShopAssetReferenceToRuntimeTarget('server/uploads/secureshop/product_images/7/a b.svg'),
    'product_images/7/a b.svg',
  );
  assert.equal(storedSecureShopAssetReferenceToRuntimeTarget('product_images/7/a.svg'), null);
  assert.equal(
    toSecureShopAssetRelativePath(path.join(root, 'product_manuals/9/manual.pdf'), { uploadRoot: root }),
    'product_manuals/9/manual.pdf',
  );
  for (const rejected of ['/images/seed.jpg', 'product_images/../secret', '../avatars/x', 'https://example.test/x.png']) {
    assert.equal(toSecureShopAssetRelativePath(rejected, { uploadRoot: root }), null);
  }
  assert.equal(
    toMountedSecureShopAssetUrl('server/uploads/secureshop/product_images/7/a b.svg'),
    '/api/secureshop/uploads/static/product_images/7/a%20b.svg',
  );
  assert.equal(toMountedSecureShopAssetUrl('https://example.test/x.png'), 'https://example.test/x.png');
});

test('product DTO mapping is non-mutating and preserves unknown source paths', () => {
  const raw = {
    id: 7,
    image_url: 'server/uploads/secureshop/product_images/7/cover.svg',
    images: ['product_images/7/detail.png', '/images/legacy-seed.jpg'],
  };
  const mapped = productWithMountedAssetUrls(raw);
  assert.notEqual(mapped, raw);
  assert.equal(raw.image_url, 'server/uploads/secureshop/product_images/7/cover.svg');
  assert.deepEqual(mapped, {
    id: 7,
    image_url: '/api/secureshop/uploads/static/product_images/7/cover.svg',
    images: ['/api/secureshop/uploads/static/product_images/7/detail.png', '/images/legacy-seed.jpg'],
  });
});

test('MCP upload/download and mounted HTTP serving share the configured temporary root', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-secureshop-assets-'));
  const previous = process.env.SECURESHOP_UPLOAD_ROOT;
  process.env.SECURESHOP_UPLOAD_ROOT = root;
  t.after(async () => {
    if (previous === undefined) delete process.env.SECURESHOP_UPLOAD_ROOT;
    else process.env.SECURESHOP_UPLOAD_ROOT = previous;
    await fs.rm(root, { recursive: true, force: true });
  });

  const uploads = require('../agent-host/agents/uploads/tools');
  const body = '<svg onload="fixture()"/>';
  const written = uploads.upload_avatar({
    user_id: 41,
    filename: 'continuity.svg',
    mime: 'image/svg+xml',
    file_bytes_base64: Buffer.from(body).toString('base64'),
  });
  assert.equal(uploads.UPLOAD_ROOT, root);
  assert.equal(written.written_path.startsWith(`${root}${path.sep}`), true);

  const relative = path.relative(root, written.written_path).replaceAll(path.sep, '/');
  assert.equal(written.relative_path, `server/uploads/secureshop/${relative}`);
  assert.equal(storedSecureShopAssetReferenceToRuntimeTarget(written.relative_path), relative);
  assert.equal(
    toMountedSecureShopAssetUrl(written.relative_path),
    `/api/secureshop/uploads/static/${relative}`,
  );
  const downloaded = uploads.download({ id: relative });
  assert.equal(Buffer.from(downloaded.body_base64, 'base64').toString(), body);

  const app = express();
  app.use('/api/secureshop', require('../server/routes/secureshop/uploads')({ uploadRoot: root }));
  const server = http.createServer(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/api/secureshop/uploads/static/${relative}`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'image/svg+xml');
  assert.equal(await response.text(), body);
});

test('frontend image policy accepts mounted restored assets without accepting arbitrary local paths', async () => {
  const { BUNDLED_PRODUCT_IMAGE, isLegacySecureShopDefaultImageUrl,
    isRenderableSecureShopImageUrl } = await import('../client/src/pages/secureshop/utils/assetUrl.mjs');
  assert.equal(isRenderableSecureShopImageUrl('/api/secureshop/uploads/static/product_images/7/a.svg'), true);
  assert.equal(isRenderableSecureShopImageUrl(BUNDLED_PRODUCT_IMAGE), true);
  assert.equal(isRenderableSecureShopImageUrl('https://example.test/a.png'), true);
  assert.equal(isLegacySecureShopDefaultImageUrl('https://picsum.photos/seed/ss_books_2/600/800'), true);
  assert.equal(isLegacySecureShopDefaultImageUrl('https://picsum.photos/seed/ss_7_a/600/800'), true);
  assert.equal(isRenderableSecureShopImageUrl('https://picsum.photos/seed/ss_books_2/600/800'), false);
  assert.equal(isLegacySecureShopDefaultImageUrl('https://picsum.photos/seed/custom/600/800'), false);
  assert.equal(isRenderableSecureShopImageUrl('https://picsum.photos/seed/custom/600/800'), true);
  assert.equal(isRenderableSecureShopImageUrl('/images/unbound.png'), false);
  assert.equal(isRenderableSecureShopImageUrl('/secureshop/%70roduct-placeholder.svg'), false);
  assert.equal(isRenderableSecureShopImageUrl('server/uploads/secureshop/product_images/7/a.svg'), false);
});

test('PostgreSQL customer and merchant HTTP DTOs expose mounted URLs without changing repository rows', async (t) => {
  const previousEngine = process.env.PLATFORM_DATABASE_ENGINE;
  const previousSecret = process.env.JWT_SECRET;
  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  process.env.JWT_SECRET = 'asset-continuity-fixture-secret';
  t.after(() => {
    if (previousEngine === undefined) delete process.env.PLATFORM_DATABASE_ENGINE;
    else process.env.PLATFORM_DATABASE_ENGINE = previousEngine;
    if (previousSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = previousSecret;
  });

  const customerRow = { id: 8, image_url: 'server/uploads/secureshop/product_images/8/card.png' };
  const detailRow = {
    id: 8,
    image_url: 'server/uploads/secureshop/product_images/8/card.png',
    images: ['server/uploads/secureshop/product_images/8/detail.png'],
  };
  const merchantRow = { id: 9, image_url: 'server/uploads/secureshop/product_images/9/card.png' };
  const customerRepository = {
    browse: async () => ({ products: [customerRow], count: 1, total: 1 }),
    product: async () => ({ product: detailRow, reviews: [] }),
  };
  const merchantRepository = {
    listProducts: async () => ({ rows: [merchantRow], total: 1, categories: [] }),
  };
  const app = express();
  app.use(require('../server/routes/secureshop/postgres/customer')({ repository: customerRepository }));
  app.use(require('../server/routes/secureshop/postgres/merchant')({ repository: merchantRepository }));
  const server = http.createServer(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  const products = await (await fetch(`${base}/products`)).json();
  assert.equal(products.products[0].image_url, '/api/secureshop/uploads/static/product_images/8/card.png');
  const detail = await (await fetch(`${base}/products/8`)).json();
  assert.equal(detail.product.images[0], '/api/secureshop/uploads/static/product_images/8/detail.png');

  const token = jwt.sign({ id: 2, role: 'merchant' }, process.env.JWT_SECRET, { algorithm: 'HS256' });
  const merchant = await (await fetch(`${base}/merchant/products`, {
    headers: { authorization: `Bearer ${token}` },
  })).json();
  assert.equal(merchant.products[0].image_url, '/api/secureshop/uploads/static/product_images/9/card.png');

  assert.equal(customerRow.image_url, 'server/uploads/secureshop/product_images/8/card.png');
  assert.equal(detailRow.images[0], 'server/uploads/secureshop/product_images/8/detail.png');
  assert.equal(merchantRow.image_url, 'server/uploads/secureshop/product_images/9/card.png');
});
