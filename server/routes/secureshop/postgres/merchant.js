'use strict';

const express = require('express');
const { merchantSupervisor } = require('../../../services/secureshop/supervisors/merchantSupervisor.js');
const { runChatTurn } = require('../../../services/secureshop/streaming.js');
const { requireRole } = require('../_ssAuthMiddleware.js');
const { agentSessionControl } = require('../_agentSessionControl.js');
const { getCommercePool, getAgentsPool } = require('../../../database/postgres/secureshopPools.js');
const { createSecureShopMerchantRepository } = require('../../../database/postgres/secureshopMerchantRepository.js');
const { productWithMountedAssetUrls } = require('../../../services/secureshop/assetPaths.js');

function pctDelta(current, previous) {
  if (!previous) return null;
  return +(((current - previous) / previous) * 100).toFixed(1);
}

module.exports = function buildPostgresMerchantRouter({ pool, manifest, provider, repository } = {}) {
  const router = express.Router();
  const agentSession = agentSessionControl('merchant');
  const merchant = repository || createSecureShopMerchantRepository({
    commercePool: getCommercePool(),
    agentsPool: getAgentsPool(),
  });

  router.use('/merchant', requireRole('merchant'));
  router.use('/agents/merchant', requireRole('merchant'));

  router.get('/merchant/products', async (req, res) => {
    const page = Math.max(1, Number(req.query.page) || 1);
    const perPage = Math.min(100, Math.max(1, Number(req.query.per_page) || 20));
    const result = await merchant.listProducts({
      retailerId: req.query.retailer_id ? Number(req.query.retailer_id) : null,
      status: req.query.status || null,
      category: req.query.category || null,
      search: req.query.search || null,
      sort: req.query.sort || 'updated_desc',
      limit: perPage,
      offset: (page - 1) * perPage,
    });
    res.json({
      products: result.rows.map((product) => productWithMountedAssetUrls(product)),
      count: result.rows.length,
      total: result.total,
      page,
      per_page: perPage,
      pages: Math.max(1, Math.ceil(result.total / perPage)),
      categories: result.categories,
    });
  });

  router.post('/merchant/products', async (req, res) => {
    const { title, description = '', price = 0, images = [], template_source = null, retailer_id = null, category = null } = req.body || {};
    if (!title) return res.status(400).json({ error: 'title required' });
    try {
      const { create } = require('../../../../agent-host/agents/listing/tools/create.js');
      const result = await create({ title, description, price, images, template_source, retailer_id });
      if (result.ok && category) await merchant.setProductCategory(result.product_id, category);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  router.put('/merchant/products/:id', async (req, res) => {
    const { update } = require('../../../../agent-host/agents/listing/tools/update.js');
    res.json(await update({ product_id: Number(req.params.id), patch: req.body || {} }));
  });

  router.delete('/merchant/products/:id', async (req, res) => {
    const productId = Number(req.params.id);
    const changes = await merchant.archiveProduct(productId);
    res.json({ ok: changes > 0, product_id: productId });
  });

  router.post('/merchant/listings/assist-write', async (req, res) => {
    const { title = 'Untitled', description = '' } = req.body || {};
    try {
      const { rewriteDescription } = require('../../../../agent-host/agents/listing/tools/_llmRewrite.js');
      const html = await rewriteDescription({ title, description });
      res.json({ ok: true, title, description, description_html: html });
    } catch (error) {
      res.status(500).json({ ok: false, error: error.message });
    }
  });

  router.post('/merchant/listings/import-bulk', async (req, res) => {
    try {
      const { import_bulk } = require('../../../../agent-host/agents/listing/tools/import_bulk.js');
      res.json(await import_bulk(req.body || {}));
    } catch (error) {
      res.status(500).json({ ok: false, error: error.message });
    }
  });

  router.get('/merchant/reviews', async (req, res) => {
    const page = Math.max(1, Number(req.query.page) || 1);
    const perPage = Math.min(100, Math.max(1, Number(req.query.per_page) || 25));
    const result = await merchant.listReviews({
      status: req.query.status || null,
      productId: req.query.product_id ? Number(req.query.product_id) : null,
      minRating: req.query.min_rating ? Number(req.query.min_rating) : null,
      maxRating: req.query.max_rating ? Number(req.query.max_rating) : null,
      limit: perPage,
      offset: (page - 1) * perPage,
    });
    res.json({ reviews: result.rows, count: result.rows.length, total: result.total, page, per_page: perPage, counts: result.counts });
  });

  async function moderate(req, res, fallbackLimit) {
    const { moderate_pending } = require('../../../../agent-host/agents/review-moderator/tools/index.js');
    res.json(await moderate_pending({ limit: req.body?.limit || fallbackLimit }));
  }
  router.post('/merchant/reviews/moderate', (req, res) => moderate(req, res, 50));
  router.post('/merchant/reviews/moderate-all', (req, res) => moderate(req, res, 100));
  router.post('/merchant/reviews/:id/approve', async (req, res) => {
    const { approve } = require('../../../../agent-host/agents/review-moderator/tools/index.js');
    res.json(await approve({ review_id: Number(req.params.id) }));
  });
  router.post('/merchant/reviews/:id/reject', async (req, res) => {
    const { reject } = require('../../../../agent-host/agents/review-moderator/tools/index.js');
    res.json(await reject({ review_id: Number(req.params.id), reason: req.body?.reason || null }));
  });

  router.get('/merchant/inventory', async (_req, res) => {
    const { stock_levels } = require('../../../../agent-host/agents/inventory/tools/index.js');
    res.json(await stock_levels());
  });
  router.post('/merchant/inventory/set', async (req, res) => {
    const { set_stock } = require('../../../../agent-host/agents/inventory/tools/index.js');
    const { product_id, qty } = req.body || {};
    res.json(await set_stock({ product_id, qty }));
  });

  router.post('/merchant/pricing/suggest', async (req, res) => {
    const { suggest_price } = require('../../../../agent-host/agents/pricing-strategy/tools/index.js');
    res.json(await suggest_price({ product_id: req.body?.product_id }));
  });
  router.post('/merchant/pricing/experiment', async (req, res) => {
    const { run_pricing_experiment } = require('../../../../agent-host/agents/pricing-strategy/tools/index.js');
    res.json(await run_pricing_experiment({ product_id: req.body?.product_id, strategy: req.body?.strategy }));
  });
  router.post('/merchant/pricing/compare', async (req, res) => {
    try {
      const productId = Number(req.query.product_id || req.body?.product_id);
      const competitorUrl = req.query.url || req.body?.url;
      if (!productId || !competitorUrl) return res.status(400).json({ ok: false, error: 'product_id and url required' });
      const { compareCompetitor } = require('../../../../agent-host/agents/price-advisor/tools/index.js');
      res.json(await compareCompetitor({ product_id: productId, competitor_url: competitorUrl }));
    } catch (error) {
      res.status(500).json({ ok: false, error: error.message });
    }
  });
  router.get('/merchant/pricing/history', async (req, res) => {
    const productId = Number(req.query.product_id);
    if (!productId) return res.status(400).json({ ok: false, error: 'product_id required' });
    const { priceHistory } = require('../../../../agent-host/agents/price-advisor/tools/index.js');
    res.json(await priceHistory({ product_id: productId }));
  });

  router.post('/merchant/analytics/query', async (req, res) => {
    try {
      const { nl_query } = require('../../../../agent-host/agents/analytics/tools/index.js');
      res.json(await nl_query({ question: req.body?.question }));
    } catch (error) {
      res.status(500).json({ ok: false, error: error.message });
    }
  });
  router.get('/merchant/analytics/top-products', async (req, res) => {
    const { top_products } = require('../../../../agent-host/agents/analytics/tools/index.js');
    res.json(await top_products({ limit: req.query.limit ? Number(req.query.limit) : 10, period: req.query.period || '30d' }));
  });
  router.get('/merchant/analytics/revenue', async (_req, res) => {
    const { revenue_breakdown } = require('../../../../agent-host/agents/analytics/tools/index.js');
    res.json(await revenue_breakdown());
  });

  router.get('/merchant/overview/kpis', async (req, res) => {
    const retailerId = req.query.retailer_id ? Number(req.query.retailer_id) : null;
    const cutoff = new Date(Date.now() - 30 * 86400000).toISOString();
    const previousCutoff = new Date(Date.now() - 60 * 86400000).toISOString();
    const data = await merchant.overview({ retailerId, cutoff, previousCutoff });
    const revenue = Number(data.current.revenue || 0);
    const orders = Number(data.current.orders || 0);
    const previousRevenue = Number(data.previous.revenue || 0);
    const previousOrders = Number(data.previous.orders || 0);
    const aov = orders > 0 ? revenue / orders : 0;
    const previousAov = previousOrders > 0 ? previousRevenue / previousOrders : 0;
    const dayMap = new Map(data.days.map((row) => [row.day, row]));
    const spark = [];
    for (let i = 29; i >= 0; i -= 1) {
      const day = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
      const row = dayMap.get(day);
      spark.push({ day, revenue: Number(row?.revenue || 0), orders: Number(row?.orders || 0) });
    }
    res.json({
      ok: true,
      retailer_id: retailerId,
      revenue: { value: revenue, delta_pct: pctDelta(revenue, previousRevenue), spark: spark.map((point) => point.revenue) },
      orders: { value: orders, delta_pct: pctDelta(orders, previousOrders), spark: spark.map(point => point.orders) },
      aov: { value: aov, delta_pct: pctDelta(aov, previousAov) },
      top_product: data.top?.id ? { id: data.top.id, name: data.top.name, revenue: Number(data.top.revenue || 0) } : null,
    });
  });

  router.get('/merchant/overview/sales-chart', async (req, res) => {
    const retailerId = req.query.retailer_id ? Number(req.query.retailer_id) : null;
    const days = Math.min(365, Math.max(7, Number(req.query.days) || 30));
    const cutoff = new Date(Date.now() - days * 86400000).toISOString();
    const rows = await merchant.salesChart({ retailerId, cutoff });
    const dayMap = new Map(rows.map((row) => [row.day, row]));
    const series = [];
    for (let i = days - 1; i >= 0; i -= 1) {
      const day = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
      const row = dayMap.get(day);
      series.push({ day, revenue: row ? Number(row.revenue || 0) : 0, orders: row ? Number(row.orders || 0) : 0 });
    }
    res.json({ ok: true, retailer_id: retailerId, days, series });
  });

  router.post('/agents/merchant/session', agentSession.create);
  router.post('/agents/merchant/chat', agentSession.requireOwned, async (req, res) => {
    const { sessionId, message } = req.body || {};
    if (!sessionId || !message) return res.status(400).json({ error: 'sessionId and message required' });
    await runChatTurn(req, res, {
      sessionId, message, agentSession, supervisor: merchantSupervisor,
      provider, pool, manifest,
    });
  });

  router.get('/agents/merchant/trace/latest', async (req, res) => {
    const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 10));
    try {
      const ownedRows = await agentSession.getLatestOwned(req, limit, (owner) => merchant.latestMerchantTrace(owner));
      res.json({ ok: true, rows: ownedRows, count: ownedRows.length });
    } catch (error) {
      res.json({ ok: true, rows: [], count: 0, degraded: error.message });
    }
  });
  router.get('/agents/merchant/trace/:sessionId', agentSession.requireOwned, async (req, res) => {
    const rows = await merchant.merchantTrace(req.params.sessionId);
    res.json({ session_id: req.params.sessionId, rows });
  });

  return router;
};
