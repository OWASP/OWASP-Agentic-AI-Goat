'use strict';

const express = require('express');
const { productWithMountedAssetUrls } = require('../../services/secureshop/assetPaths');

function invalid() { return Object.assign(new Error('Invalid public catalog request'), { statusCode: 400 }); }
function integer(value, fallback, min, max) {
  if (value === undefined) return fallback;
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) throw invalid();
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < min || number > max) throw invalid();
  return number;
}
function text(value, maximum) {
  if (value === undefined) return null;
  if (typeof value !== 'string' || Buffer.byteLength(value) > maximum || /[\x00-\x1f\x7f]/.test(value)) throw invalid();
  return value.trim() || null;
}
function price(value) {
  if (value === undefined) return null;
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,5})(?:\.[0-9]{1,2})?$/.test(value)) throw invalid();
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount > 100000) throw invalid();
  return amount;
}
function query(req, fields) {
  if (Object.keys(req.query).some(key => !fields.includes(key))) throw invalid();
}
function pagination(req, max = 100, fallback = 24, allowPage = false) {
  const limit = integer(req.query.limit, fallback, 1, max);
  if (req.query.page !== undefined && req.query.offset !== undefined) throw invalid();
  const page = allowPage ? integer(req.query.page, 1, 1, 100001) : 1;
  const offset = integer(req.query.offset, (page - 1) * limit, 0, 100000);
  if (offset > 100000) throw invalid();
  return { limit, offset };
}
function mapped(result) {
  if (result.product) return { ...result, product: productWithMountedAssetUrls(result.product) };
  if (result.products) return { ...result, products: result.products.map(product => productWithMountedAssetUrls(product)) };
  if (result.results) return { ...result, results: result.results.map(product => productWithMountedAssetUrls(product)) };
  return result;
}

function createSecureShopPublicCatalogRouter({ getRepository, isAvailable } = {}) {
  if (typeof getRepository !== 'function' || typeof isAvailable !== 'function') throw new TypeError('Public catalog dependencies required');
  const router = express.Router();
  router.use(async (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.method !== 'GET') { res.set('Allow', 'GET'); return res.status(405).json({ error: 'Public catalog is read-only' }); }
    try {
      if (await isAvailable() !== true) return res.status(404).json({ error: 'Public catalog unavailable' });
      next();
    } catch { res.status(503).json({ error: 'Public catalog unavailable' }); }
  });
  const route = operation => async (req, res) => {
    try {
      const result = await operation(req, getRepository());
      if (!result) return res.status(404).json({ error: 'Product unavailable' });
      res.json(mapped(result));
    } catch (error) {
      res.status(error?.statusCode === 400 ? 400 : 503).json({ error: error?.statusCode === 400
        ? 'Invalid public catalog request' : 'Public catalog unavailable' });
    }
  };
  router.get('/products', route((req, repository) => {
    query(req, ['category', 'search', 'sort', 'minRating', 'maxPrice', 'limit', 'offset', 'page']);
    const sort = req.query.sort === undefined || req.query.sort === '' ? 'default' : req.query.sort;
    if (typeof sort !== 'string' || !['default', 'price_asc', 'price_desc', 'newest', 'deals'].includes(sort)) throw invalid();
    return repository.browse({ category: text(req.query.category, 100), search: text(req.query.search, 200),
      minRating: req.query.minRating === undefined ? null : integer(req.query.minRating, null, 1, 5),
      maxPrice: price(req.query.maxPrice), sort,
      ...pagination(req, 100, 24, true) });
  }));
  router.get('/categories', route((req, repository) => { query(req, []); return repository.categories(); }));
  router.get('/products/:id', route((req, repository) => {
    query(req, []); return repository.product(integer(req.params.id, null, 1, 2147483647));
  }));
  router.get('/products/:id/reviews', route((req, repository) => {
    query(req, ['limit', 'offset']); return repository.reviews(integer(req.params.id, null, 1, 2147483647), pagination(req, 50, 10));
  }));
  router.get('/products/:id/related', route((req, repository) => {
    query(req, ['limit']); return repository.related(integer(req.params.id, null, 1, 2147483647),
      { limit: integer(req.query.limit, 4, 1, 12) });
  }));
  // No public request can fall through into the teaching customer router.
  router.use((_req, res) => res.status(404).json({ error: 'Public catalog operation unavailable' }));
  return router;
}

module.exports = { createSecureShopPublicCatalogRouter };
