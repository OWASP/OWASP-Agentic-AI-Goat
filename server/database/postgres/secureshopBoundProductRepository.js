'use strict';

const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { withTransaction } = require('./index');
const { copySceneBinding, executionScope, assertSceneGrant, withSceneLease } = require('../../services/secureshopSceneBinding');
const edit = require('../../services/secureshopListingEditContract');
const create = require('../../services/secureshopListingCreateContract');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_PRODUCTS = 256;
const SORTS = Object.freeze({
  '': 'product_id ASC', newest: 'source_created_at DESC NULLS LAST,product_id DESC',
  price_asc: 'price ASC,product_id ASC', price_desc: 'price DESC,product_id ASC',
  deals: 'price ASC,product_id ASC', updated_desc: 'source_updated_at DESC NULLS LAST,product_id DESC',
  updated_asc: 'source_updated_at ASC NULLS LAST,product_id ASC', name_asc: 'name ASC,product_id ASC',
  stock_desc: 'stock_quantity DESC,product_id DESC', stock_asc: 'stock_quantity ASC,product_id ASC',
});

function failure(code, message) { return Object.assign(new Error(message), { code }); }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value.toLowerCase();
}
function integer(value, label, min = 1, max = 2147483647) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return value;
}
function bounded(value, label, max, nullable = true) {
  if (value === null || value === undefined) {
    if (nullable) return null;
    throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  }
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > max) {
    throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  }
  return value;
}
function timestamp(value, label) {
  if (value === null || value === undefined) return null;
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw failure('INVALID_ARGUMENT', `${label} is invalid`);
  return parsed.toISOString();
}
function listing(input, { patch = false } = {}) {
  if (!plain(input)) throw failure('INVALID_ARGUMENT', 'merchant listing is invalid');
  const allowed = patch
    ? ['name', 'description', 'price', 'category', 'templateSource', 'imageUrl']
    : ['name', 'description', 'price', 'category', 'templateSource', 'images'];
  if (Object.keys(input).some(key => !allowed.includes(key))
      || (!patch && allowed.some(key => !Object.hasOwn(input, key)))
      || (patch && Object.keys(input).length === 0)) {
    throw failure('INVALID_ARGUMENT', 'merchant listing is invalid');
  }
  const output = {};
  if (Object.hasOwn(input, 'name')) output.name = bounded(input.name, 'name', 4096, false);
  if (Object.hasOwn(input, 'description')) output.description = bounded(input.description, 'description', 65536);
  if (Object.hasOwn(input, 'price')) {
    if (typeof input.price !== 'number' || !Number.isFinite(input.price)
        || input.price < 0 || input.price > 99999999.99) throw failure('INVALID_ARGUMENT', 'price is invalid');
    output.price = Number(input.price.toFixed(2));
  }
  if (Object.hasOwn(input, 'category')) output.category = bounded(input.category, 'category', 1024);
  if (Object.hasOwn(input, 'templateSource')) output.templateSource = bounded(input.templateSource, 'templateSource', 65536);
  if (Object.hasOwn(input, 'imageUrl')) output.imageUrl = bounded(input.imageUrl, 'imageUrl', 8192);
  if (Object.hasOwn(input, 'images')) {
    if (!Array.isArray(input.images) || input.images.length > 16
        || Object.keys(input.images).length !== input.images.length) throw failure('INVALID_ARGUMENT', 'images are invalid');
    output.images = input.images.map(value => bounded(value, 'image', 8192, false));
  }
  return Object.freeze(output);
}
function scope(input) {
  if (!plain(input)) throw failure('INVALID_ARGUMENT', 'product target scope is invalid');
  return copySceneBinding(input, { targetId: uuid(input.targetId, 'targetId'), launchId: uuid(input.launchId, 'launchId'),
    scenarioId: uuid(input.scenarioId, 'scenarioId'), generation: integer(input.generation, 'generation', 1, 9007199254740991),
    platformOwnerId: integer(input.platformOwnerId, 'platformOwnerId'),
    platformSessionId: integer(input.platformSessionId, 'platformSessionId') });
}
function scopeValues(value) {
  return [value.targetId, value.launchId, value.scenarioId, value.generation,
    value.platformOwnerId, value.platformSessionId];
}
function normalizeProduct(input) {
  if (!plain(input)) throw failure('INVALID_ARGUMENT', 'source product is invalid');
  const images = input.images ?? [];
  if (!Array.isArray(images) || images.length > 16 || Object.keys(images).length !== images.length) {
    throw failure('INVALID_ARGUMENT', 'product images are invalid');
  }
  const price = Number(input.price);
  if (!Number.isFinite(price) || price < 0 || price > 99999999.99) throw failure('INVALID_ARGUMENT', 'price is invalid');
  const product = Object.freeze({
    id: integer(Number(input.id), 'productId'),
    sourceRetailerId: integer(Number(input.sourceRetailerId), 'sourceRetailerId'),
    retailerId: integer(Number(input.retailerId), 'retailerId'),
    name: bounded(input.name, 'name', 4096, false),
    description: bounded(input.description, 'description', 65536),
    descriptionHtml: bounded(input.descriptionHtml, 'descriptionHtml', 65536),
    price: Number(price.toFixed(2)), category: bounded(input.category, 'category', 1024),
    imageUrl: bounded(input.imageUrl, 'imageUrl', 8192),
    images: Object.freeze(images.map(value => bounded(value, 'image', 8192, false))),
    stockQuantity: integer(Number(input.stockQuantity), 'stockQuantity', -2147483648, 2147483647),
    status: bounded(input.status, 'status', 64, false),
    templateSource: bounded(input.templateSource, 'templateSource', 65536),
    createdAt: timestamp(input.createdAt, 'createdAt'), updatedAt: timestamp(input.updatedAt, 'updatedAt'),
  });
  const sourceSha256 = crypto.createHash('sha256').update(JSON.stringify([
    product.id, product.sourceRetailerId, product.retailerId, product.name, product.description,
    product.descriptionHtml, product.price.toFixed(2), product.category, product.imageUrl,
    product.images, product.stockQuantity, product.status, product.templateSource,
    product.createdAt, product.updatedAt,
  ])).digest();
  return Object.freeze({ ...product, sourceSha256 });
}
function normalizeProducts(input) {
  if (!Array.isArray(input) || input.length < 1 || input.length > MAX_PRODUCTS
      || Object.keys(input).length !== input.length) throw failure('INVALID_ARGUMENT', 'source products are invalid');
  const rows = input.map(normalizeProduct).sort((a, b) => a.id - b.id);
  if (new Set(rows.map(row => row.id)).size !== rows.length) throw failure('INVALID_ARGUMENT', 'source products are invalid');
  const digest = crypto.createHash('sha256');
  for (const row of rows) digest.update(row.sourceSha256);
  return Object.freeze({ rows: Object.freeze(rows), digest: digest.digest() });
}
function rowProduct(row) {
  return Object.freeze({ id: Number(row.product_id), name: row.name, description: row.description,
    description_html: row.description_html, price: Number(row.price), category: row.category,
    image_url: row.image_url, images: Object.freeze(Array.isArray(row.images) ? row.images : []),
    avg_rating: Number(row.avg_rating || 0), review_count: Number(row.review_count || 0),
    stock_quantity: Number(row.stock_quantity), retailer_id: Number(row.retailer_id), status: row.status,
    template_source: row.template_source, created_at: row.source_created_at, updated_at: row.source_updated_at });
}
const TARGET_WHERE = `target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4
  AND original_platform_owner_id=$5 AND original_platform_session_id=$6`;
async function target(client, binding, lock = 'FOR SHARE') {
  const row = (await client.query(`SELECT * FROM secureshop_review.product_targets
    WHERE ${TARGET_WHERE} ${lock}`, scopeValues(binding))).rows[0];
  if (!row || row.lifecycle !== 'active') throw failure('PRODUCT_TARGET_UNAVAILABLE', 'product target is unavailable');
  return row;
}
function receiptDigest(binding, operationId, count, sourceSha256) {
  return crypto.createHash('sha256').update(JSON.stringify({ version: 1, operationId,
    targetId: binding.targetId, kind: 'products', launchId: binding.launchId,
    scenarioId: binding.scenarioId, generation: binding.generation,
    platformOwnerId: binding.platformOwnerId, platformSessionId: binding.platformSessionId,
    deletedProductCount: count, sourceSha256: sourceSha256.toString('hex') })).digest();
}
function listingReceiptDigest(binding, operationId, created, overlays) {
  return crypto.createHash('sha256').update(JSON.stringify({ version: 1, operationId,
    targetId: binding.targetId, kind: 'product_listings', launchId: binding.launchId,
    scenarioId: binding.scenarioId, generation: binding.generation,
    platformOwnerId: binding.platformOwnerId, platformSessionId: binding.platformSessionId,
    deletedCreatedCount: created, deletedOverlayCount: overlays })).digest();
}
function refundReceiptDigest(binding, operationId, count) {
  return crypto.createHash('sha256').update(JSON.stringify({ version: 1, operationId,
    targetId: binding.targetId, kind: 'product_refunds', launchId: binding.launchId,
    scenarioId: binding.scenarioId, generation: binding.generation,
    platformOwnerId: binding.platformOwnerId, platformSessionId: binding.platformSessionId,
    deletedTicketCount: count })).digest();
}
async function assertTargetEmpty(client, targetId) {
  const retained = Number((await client.query(`SELECT
    (SELECT count(*) FROM secureshop_review.product_target_products WHERE target_id=$1)+
    (SELECT count(*) FROM secureshop_review.product_target_cart_items WHERE target_id=$1)+
    (SELECT count(*) FROM secureshop_review.product_target_orders WHERE target_id=$1)+
    (SELECT count(*) FROM secureshop_review.product_target_order_items WHERE target_id=$1)+
    (SELECT count(*) FROM secureshop_review.product_target_profile_overlays WHERE target_id=$1)+
    (SELECT count(*) FROM secureshop_review.product_target_addresses WHERE target_id=$1)+
    (SELECT count(*) FROM secureshop_review.product_target_refund_requests WHERE target_id=$1)+
    (SELECT count(*) FROM secureshop_review.product_target_retrieval_documents WHERE target_id=$1)+
    (SELECT count(*) FROM secureshop_review.product_target_merchant_listings WHERE target_id=$1)+
    (SELECT count(*) FROM secureshop_review.product_target_listing_overlays WHERE target_id=$1) AS count`,
  [targetId])).rows[0].count);
  if (retained !== 0) throw failure('PRODUCT_CLEANUP_MISMATCH', 'product cleanup receipt has retained target state');
  const inventoryRelation=(await client.query("SELECT to_regclass('secureshop_review.owned_inventory_operations') AS relation")).rows[0]?.relation;
  if(inventoryRelation){const remaining=Number((await client.query("SELECT count(*) AS count FROM secureshop_review.owned_inventory_operations WHERE target_id=$1 AND (state<>'redacted' OR request_json IS NOT NULL OR result_json IS NOT NULL)",[targetId])).rows[0].count);if(remaining!==0)throw failure('PRODUCT_CLEANUP_MISMATCH','product cleanup retained inventory state');}
  const couponRelation=(await client.query("SELECT to_regclass('secureshop_review.bound_commerce_operations') AS relation")).rows[0]?.relation;
  if(couponRelation){const remaining=Number((await client.query("SELECT (SELECT count(*) FROM secureshop_review.product_target_cart_coupons WHERE target_id=$1)+(SELECT count(*) FROM secureshop_review.bound_commerce_operations WHERE target_id=$1 AND (state<>'redacted' OR request_json IS NOT NULL OR result_json IS NOT NULL)) AS count",[targetId])).rows[0].count);if(remaining!==0)throw failure('PRODUCT_CLEANUP_MISMATCH','product cleanup retained coupon state');}
  const chatRelation=(await client.query("SELECT to_regclass('secureshop_review.chat_commerce_operations') AS relation")).rows[0]?.relation;
  if(chatRelation){
    const remaining=Number((await client.query(`SELECT
      (SELECT count(*) FROM secureshop_review.practice_payment_methods WHERE target_id=$1)+
      (SELECT count(*) FROM secureshop_review.chat_commerce_choices WHERE target_id=$1
        AND (state<>'redacted' OR context_json IS NOT NULL OR snapshot_json IS NOT NULL))+
      (SELECT count(*) FROM secureshop_review.chat_commerce_operations WHERE target_id=$1
        AND (state<>'redacted' OR context_json IS NOT NULL OR request_json IS NOT NULL OR proposal_json IS NOT NULL OR result_json IS NOT NULL)) AS count`,[targetId])).rows[0].count);
    if(remaining!==0)throw failure('PRODUCT_CLEANUP_MISMATCH','product cleanup retained conversational commerce state');
  }
}

const EFFECTIVE_REVIEW_TARGET_JOIN = `LEFT JOIN secureshop_review.scene_review_targets srt
    ON srt.product_target_id=t.target_id
  LEFT JOIN secureshop_review.review_targets rt
    ON rt.target_id=COALESCE(srt.review_target_id,(
      SELECT legacy.target_id FROM secureshop_review.review_targets legacy
      WHERE srt.scene_id IS NULL AND legacy.launch_id=t.launch_id
        AND legacy.scenario_id=t.scenario_id AND legacy.generation=t.generation
        AND legacy.original_platform_owner_id=t.original_platform_owner_id
        AND legacy.original_platform_session_id=t.original_platform_session_id
        AND legacy.lifecycle='active')) AND rt.lifecycle='active'`;
const EFFECTIVE_PRODUCTS = `SELECT p.target_id,p.product_id,p.source_retailer_id,p.retailer_id,
  p.source_product_sha256,CASE WHEN o.product_id IS NULL THEN p.name ELSE o.name END AS name,
  CASE WHEN o.product_id IS NULL THEN p.description ELSE o.description END AS description,
  CASE WHEN o.product_id IS NULL THEN p.description_html ELSE o.description_html END AS description_html,
  CASE WHEN o.product_id IS NULL THEN p.price ELSE o.price END AS price,
  CASE WHEN o.product_id IS NULL THEN p.category ELSE o.category END AS category,
  CASE WHEN o.product_id IS NULL THEN p.image_url ELSE o.image_url END AS image_url,
  CASE WHEN o.product_id IS NULL THEN p.images ELSE o.images END AS images,
  CASE WHEN o.product_id IS NULL THEN p.stock_quantity ELSE o.stock_quantity END AS stock_quantity,
  CASE WHEN o.product_id IS NULL THEN p.status ELSE o.status END AS status,
  CASE WHEN o.product_id IS NULL THEN p.template_source ELSE o.template_source END AS template_source,
  p.source_created_at,COALESCE(o.updated_at,p.source_updated_at) AS source_updated_at,
  COALESCE(ratings.avg_rating,0) AS avg_rating_raw,
  COALESCE(round(ratings.avg_rating,2),0) AS avg_rating,
  COALESCE(ratings.review_count,0)::integer AS review_count,
  o.archived_at FROM secureshop_review.product_target_products p
  JOIN secureshop_review.product_targets t ON t.target_id=p.target_id AND t.lifecycle='active'
  LEFT JOIN secureshop_review.product_target_listing_overlays o
    ON o.target_id=p.target_id AND o.product_id=p.product_id
  ${EFFECTIVE_REVIEW_TARGET_JOIN}
  LEFT JOIN LATERAL (SELECT avg(r.rating) AS avg_rating,count(*) AS review_count
    FROM secureshop_review.reviews r WHERE r.target_id=rt.target_id
      AND r.product_id=p.product_id AND r.status='approved') ratings ON TRUE`;

function effectiveEdit(row) {
  if (!row || !Buffer.isBuffer(row.source_product_sha256)
      || row.source_product_sha256.length !== 32 || !Array.isArray(row.images)
      || !Number.isSafeInteger(Number(row.stock_quantity))) throw failure('LISTING_EDIT_STALE', 'listing snapshot unavailable');
  const before = edit.listingEditView({ name: row.name, description: row.description,
    descriptionHtml: row.description_html, price: Number(row.price), category: row.category,
    templateSource: row.template_source, imageUrl: row.image_url });
  const updatedAt = timestamp(row.source_updated_at, 'sourceUpdatedAt');
  return Object.freeze({ before, snapshotSha256: edit.listingEditDigest([
    1, Number(row.product_id), Number(row.retailer_id), row.source_product_sha256.toString('hex'),
    before, row.images, Number(row.stock_quantity), row.status, updatedAt,
    timestamp(row.archived_at, 'archivedAt'),
  ]) });
}
async function editRevision(client, targetId) {
  const row = (await client.query(`SELECT revision::text AS revision
    FROM secureshop_review.owned_listing_catalog_revisions WHERE target_id=$1`, [targetId])).rows[0];
  const revision = row?.revision ?? '0';
  if (!/^(0|[1-9][0-9]{0,15})$/.test(revision) || BigInt(revision) > 9007199254740991n)
    throw failure('LISTING_EDIT_STALE', 'catalog revision unavailable');
  return revision;
}
function editReceiptHash(row) {
  return edit.listingEditDigest([1, row.operation_id, row.target_id, row.launch_id, row.scenario_id,
    String(row.generation), Number(row.original_platform_owner_id), Number(row.original_platform_session_id),
    row.scene_id, String(row.scene_generation), row.grant_id, Number(row.merchant_id),
    row.persona_session_id, String(row.authority_version), Number(row.product_id),
    row.scope_key.toString('hex'), String(row.catalog_revision), row.request_sha256.toString('hex'),
    row.before_sha256.toString('hex'), row.after_sha256.toString('hex')]);
}
function editReceipt(row, binding, actor, session, scopeKey, requestSha256 = null) {
  if (!row || !binding.scene || row.target_id !== binding.targetId
      || row.launch_id !== binding.launchId || row.scenario_id !== binding.scenarioId
      || Number(row.generation) !== binding.generation
      || Number(row.original_platform_owner_id) !== binding.platformOwnerId
      || Number(row.original_platform_session_id) !== binding.platformSessionId
      || row.scene_id !== binding.scene.sceneId
      || Number(row.scene_generation) !== binding.scene.sceneGeneration
      || row.grant_id !== binding.scene.grantId || Number(row.merchant_id) !== actor
      || row.persona_session_id !== session.sessionId.toLowerCase()
      || String(row.authority_version) !== session.authorityVersion
      || ![row.scope_key, row.request_sha256, row.before_sha256, row.after_sha256,
        row.receipt_sha256].every(value => Buffer.isBuffer(value) && value.length === 32)
      || row.scope_key.toString('hex') !== scopeKey
      || (requestSha256 && row.request_sha256.toString('hex') !== requestSha256)
      || row.receipt_sha256.toString('hex') !== editReceiptHash(row)) {
    throw failure('LISTING_EDIT_RECEIPT_INVALID', 'listing edit receipt does not match');
  }
  return Object.freeze({ version: 1, operationId: row.operation_id, productId: Number(row.product_id),
    status: 'completed', scopeKey, catalogRevision: String(row.catalog_revision),
    requestSha256: row.request_sha256.toString('hex'), beforeSha256: row.before_sha256.toString('hex'),
    afterSha256: row.after_sha256.toString('hex'), receiptSha256: row.receipt_sha256.toString('hex') });
}
function merchantCreateSourceHash(binding, actor, productId, item, source = null) {
  const fields = [binding.targetId, productId, actor, item.name, item.description, item.price.toFixed(2),
    item.category, item.images, item.templateSource];
  return crypto.createHash('sha256').update(JSON.stringify(source
    ? [2, ...fields, create.listingCreateSourceDigest(source)] : fields)).digest();
}
function createReceiptHash(row) {
  const legacy = create.listingCreateDigest([1, row.operation_id, row.target_id, row.launch_id, row.scenario_id,
    String(row.generation), Number(row.original_platform_owner_id), Number(row.original_platform_session_id),
    row.scene_id, String(row.scene_generation), row.grant_id, Number(row.merchant_id),
    row.persona_session_id, String(row.authority_version), Number(row.product_id),
    row.scope_key.toString('hex'), row.request_sha256.toString('hex'), row.source_sha256.toString('hex')]);
  if (row.receipt_version === 2) return create.listingCreateDigest([2, legacy,
    create.listingCreateSourceDigest(row.source_document)]);
  if (row.receipt_version != null && row.receipt_version !== 1 || row.source_document != null)
    throw failure('LISTING_CREATE_RECEIPT_INVALID', 'listing source version is invalid');
  return legacy;
}
function createReceipt(row, binding, actor, session, scopeKey, requestSha256 = null) {
  if (!row || !binding.scene || row.target_id !== binding.targetId
      || row.launch_id !== binding.launchId || row.scenario_id !== binding.scenarioId
      || Number(row.generation) !== binding.generation
      || Number(row.original_platform_owner_id) !== binding.platformOwnerId
      || Number(row.original_platform_session_id) !== binding.platformSessionId
      || row.scene_id !== binding.scene.sceneId
      || Number(row.scene_generation) !== binding.scene.sceneGeneration
      || row.grant_id !== binding.scene.grantId || Number(row.merchant_id) !== actor
      || row.persona_session_id !== session.sessionId.toLowerCase()
      || String(row.authority_version) !== session.authorityVersion
      || ![row.scope_key, row.request_sha256, row.source_sha256, row.receipt_sha256]
        .every(value => Buffer.isBuffer(value) && value.length === 32)
      || row.scope_key.toString('hex') !== scopeKey
      || (requestSha256 && row.request_sha256.toString('hex') !== requestSha256)
      || row.receipt_sha256.toString('hex') !== createReceiptHash(row))
    throw failure('LISTING_CREATE_RECEIPT_INVALID', 'listing create receipt does not match');
  const source = row.receipt_version === 2 ? create.validateListingCreateSource(row.source_document) : null;
  if (source && (!merchantCreateSourceHash(binding, actor, Number(row.product_id),
        { ...source.listing, images: [], templateSource: null }, source).equals(row.source_sha256)
      || !isDeepStrictEqual(source.execution.scope, executionScope(binding))
      || create.listingCreateRequestDigest({ version: 2, listing: source.listing, source,
        scopeKey, currency: 'USD', initialStock: 0, status: 'active' }) !== row.request_sha256.toString('hex')))
    throw failure('LISTING_CREATE_RECEIPT_INVALID', 'listing source does not match');
  return Object.freeze({ version: source ? 2 : 1, operationId: row.operation_id, productId: Number(row.product_id),
    status: 'completed', scopeKey, requestSha256: row.request_sha256.toString('hex'),
    sourceSha256: row.source_sha256.toString('hex'), receiptSha256: row.receipt_sha256.toString('hex'),
    ...(source ? { source, sourceDocumentSha256: create.listingCreateSourceDigest(source) } : {}) });
}

function accountReceiptDigest(binding, operationId, profileCount, addressCount) {
  return crypto.createHash('sha256').update(JSON.stringify({ version: 1, operationId,
    targetId: binding.targetId, kind: 'product_account', launchId: binding.launchId,
    scenarioId: binding.scenarioId, generation: binding.generation,
    platformOwnerId: binding.platformOwnerId, platformSessionId: binding.platformSessionId,
    deletedProfileCount: profileCount, deletedAddressCount: addressCount })).digest();
}
function verifiedAccountReceipt(row, binding, operation) {
  if (!row) return null; // Pre-0006 product receipts remain replayable after zero-state verification.
  const profiles = Number(row.deleted_profile_count), addresses = Number(row.deleted_address_count);
  if (row.operation_id !== operation || row.target_id !== binding.targetId
      || row.launch_id !== binding.launchId || row.scenario_id !== binding.scenarioId
      || Number(row.generation) !== binding.generation
      || Number(row.original_platform_owner_id) !== binding.platformOwnerId
      || Number(row.original_platform_session_id) !== binding.platformSessionId
      || !Number.isSafeInteger(profiles) || profiles < 0 || profiles > 3
      || !Number.isSafeInteger(addresses) || addresses < 0 || addresses > 96
      || !Buffer.isBuffer(row.receipt_sha256) || row.receipt_sha256.length !== 32
      || !crypto.timingSafeEqual(row.receipt_sha256,
        accountReceiptDigest(binding, operation, profiles, addresses))) {
    throw failure('PRODUCT_CLEANUP_MISMATCH', 'account cleanup receipt does not match');
  }
  return Object.freeze({ deletedProfileCount: profiles, deletedAddressCount: addresses,
    receiptSha256: row.receipt_sha256.toString('hex') });
}
function verifiedListingReceipt(row, binding, operation) {
  if (!row) return null; // Pre-0007 product receipts remain replayable after zero-state verification.
  const created = Number(row.deleted_created_count), overlays = Number(row.deleted_overlay_count);
  if (row.operation_id !== operation || row.target_id !== binding.targetId
      || !Number.isSafeInteger(created) || created < 0 || created > 256
      || !Number.isSafeInteger(overlays) || overlays < 0 || overlays > 512
      || !Buffer.isBuffer(row.receipt_sha256) || row.receipt_sha256.length !== 32
      || !crypto.timingSafeEqual(row.receipt_sha256,
        listingReceiptDigest(binding, operation, created, overlays))) {
    throw failure('PRODUCT_CLEANUP_MISMATCH', 'listing cleanup receipt does not match');
  }
  return Object.freeze({ deletedCreatedCount: created, deletedOverlayCount: overlays,
    receiptSha256: row.receipt_sha256.toString('hex') });
}
function receipt(row, accountCleanup = null, listingCleanup = null, refundCleanup = null) {
  return Object.freeze({ version: 1, operationId: row.operation_id, targetId: row.target_id,
    kind: 'products', launchId: row.launch_id, scenarioId: row.scenario_id,
    generation: Number(row.generation), platformOwnerId: Number(row.original_platform_owner_id),
    platformSessionId: Number(row.original_platform_session_id),
    deletedProductCount: Number(row.deleted_product_count), sourceCount: Number(row.source_count),
    sourceSha256: row.source_sha256.toString('hex'), receiptSha256: row.receipt_sha256.toString('hex'),
    completedAt: row.completed_at, ...(accountCleanup ? { accountCleanup } : {}),
    ...(listingCleanup ? { listingCleanup } : {}),
    ...(refundCleanup ? { refundCleanup } : {}) });
}
function verifiedRefundReceipt(row, binding, operation) {
  // Targets cleaned before the forward-only 0009 migration have no refund
  // receipt; their zero-state is still verified by assertTargetEmpty.
  if (!row) return null;
  const count = Number(row.deleted_ticket_count);
  if (row.operation_id !== operation || row.target_id !== binding.targetId
      || !Number.isSafeInteger(count) || count < 0 || count > 256
      || !Buffer.isBuffer(row.receipt_sha256) || row.receipt_sha256.length !== 32
      || !crypto.timingSafeEqual(row.receipt_sha256, refundReceiptDigest(binding, operation, count))) {
    throw failure('PRODUCT_CLEANUP_MISMATCH', 'refund cleanup receipt does not match');
  }
  return Object.freeze({ deletedTicketCount: count, receiptSha256: row.receipt_sha256.toString('hex') });
}
function verifiedReceipt(row, binding, operation, accountRow = null, listingRow = null, refundRow = null) {
  if (!row || row.operation_id !== operation || row.target_id !== binding.targetId
      || row.launch_id !== binding.launchId || row.scenario_id !== binding.scenarioId
      || Number(row.generation) !== binding.generation
      || Number(row.original_platform_owner_id) !== binding.platformOwnerId
      || Number(row.original_platform_session_id) !== binding.platformSessionId
      || Number(row.deleted_product_count) !== Number(row.source_count)
      || !Buffer.isBuffer(row.source_sha256) || row.source_sha256.length !== 32
      || !Buffer.isBuffer(row.receipt_sha256) || row.receipt_sha256.length !== 32) {
    throw failure('PRODUCT_CLEANUP_MISMATCH', 'product cleanup receipt does not match');
  }
  const expected = receiptDigest(binding, operation, Number(row.deleted_product_count), row.source_sha256);
  if (!crypto.timingSafeEqual(row.receipt_sha256, expected)) {
    throw failure('PRODUCT_CLEANUP_MISMATCH', 'product cleanup receipt does not match');
  }
  return receipt(row, verifiedAccountReceipt(accountRow, binding, operation),
    verifiedListingReceipt(listingRow, binding, operation), verifiedRefundReceipt(refundRow, binding, operation));
}

function createSecureShopBoundProductRepository(pool, { checkCurrent, checkCleanup, auditStore, modeAuthority } = {}) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function'
      || typeof checkCurrent !== 'function' || typeof checkCleanup !== 'function') {
    throw failure('INVALID_CONFIGURATION', 'bound product repository dependencies are invalid');
  }
  if (auditStore && typeof auditStore.append !== 'function') {
    throw failure('INVALID_CONFIGURATION', 'audit dependency invalid');
  }
  function rawModeToken(token, binding, expected) {
    if (typeof modeAuthority?.assertToken !== 'function') throw failure('LISTING_CREATE_MODE_INVALID');
    const trusted = modeAuthority.assertToken(token);
    const snapshot = create.validateListingCreateExecution(trusted.snapshot);
    if (!isDeepStrictEqual(snapshot.scope, executionScope(binding))
        || expected && !isDeepStrictEqual(snapshot, expected)
        || typeof trusted.assertCurrentAtEffect !== 'function') throw failure('LISTING_CREATE_MODE_INVALID');
    return trusted;
  }
  async function auditListing(client, binding, actor, action, productId, params) {
    if (!auditStore) return; // Candidate wiring is enabled only after journal/deletion qualification.
    await auditStore.append(client, {
      eventId: crypto.randomUUID(), scope: executionScope(binding), persona: { id: actor, role: 'merchant' },
      actor: 'merchant', action, target: String(productId), paramsJson: JSON.stringify(binding.scene ? { ...params, storage: { targetId: binding.targetId, sceneId: binding.scene.sceneId, birthLaunchId: binding.launchId, birthGeneration: binding.generation } } : params),
      outcome: 'completed', sourceKind: 'product', sourceId: String(productId),
    });
  }
  async function online(binding, work, { repeatable = false } = {}) {
    return withSceneLease(binding, () => withTransaction(pool, async client => {
      if (repeatable) await client.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
      await assertSceneGrant(client, binding);
      const result = await work(client);
      await assertSceneGrant(client, binding);
      await checkCurrent(executionScope(binding));
      return result;
    }));
  }
  async function insertMerchantListing(client, binding, actor, item, source = null) {
    const nextId = Number((await client.query(`SELECT COALESCE(max(product_id),0)+1 AS product_id
      FROM secureshop_review.product_target_products WHERE target_id=$1`, [binding.targetId])).rows[0].product_id);
    integer(nextId, 'productId');
    const imageUrl = item.images[0] || null;
    const sourceSha256 = merchantCreateSourceHash(binding, actor, nextId, item, source);
    await client.query(`INSERT INTO secureshop_review.product_target_products
      (target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,
       name,description,description_html,price,category,image_url,images,stock_quantity,status,
       template_source,source_created_at,source_updated_at)
      VALUES($1,$2,$3,$3,$4,$5,$6,${source ? '$12' : 'NULL'},$7,$8,$9,$10,0,'active',$11,clock_timestamp(),clock_timestamp())`,
    [binding.targetId, nextId, actor, sourceSha256, item.name, item.description, item.price,
      item.category, imageUrl, JSON.stringify(item.images), item.templateSource, ...(source ? [source.storedHtml] : [])]);
    await client.query(`INSERT INTO secureshop_review.product_target_merchant_listings
      (target_id,product_id,shop_user_id) VALUES($1,$2,$3)`, [binding.targetId, nextId, actor]);
    return Object.freeze({ productId: nextId, sourceSha256 });
  }
  return Object.freeze({
    async open(input) {
      const binding = scope(input); await checkCurrent(executionScope(binding));
      return online(binding, async client => {
      const row = (await client.query(`SELECT * FROM secureshop_review.product_targets
        WHERE target_id=$1 FOR SHARE`, [binding.targetId])).rows[0];
      if (!row) return null;
      if (row.launch_id !== binding.launchId || row.scenario_id !== binding.scenarioId
          || Number(row.generation) !== binding.generation
          || Number(row.original_platform_owner_id) !== binding.platformOwnerId
          || Number(row.original_platform_session_id) !== binding.platformSessionId
          || row.lifecycle !== 'active') throw failure('PRODUCT_TARGET_MISMATCH', 'product target binding does not match');
      await checkCurrent(executionScope(binding));
      return Object.freeze({ ...binding, ownMerchantId: Number(row.own_merchant_id),
        sourceCount: Number(row.source_count), sourceSha256: row.source_sha256.toString('hex') });
      });
    },
    async provision(input, { ownMerchantId, products } = {}, {effectTimeoutMs}={}) {
      const binding = scope(input); const owner = integer(ownMerchantId, 'ownMerchantId');
      const source = normalizeProducts(products); await checkCurrent(executionScope(binding));
      if(effectTimeoutMs!==undefined&&(!Number.isSafeInteger(effectTimeoutMs)||effectTimeoutMs<100||effectTimeoutMs>10000))throw failure('INVALID_ARGUMENT','Invalid effect timeout');
      return online(binding, async client => {
        if(effectTimeoutMs!==undefined)await client.query("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",[String(effectTimeoutMs)]);
        const inserted = await client.query(`INSERT INTO secureshop_review.product_targets
          (target_id,launch_id,scenario_id,generation,original_platform_owner_id,
           original_platform_session_id,own_merchant_id,source_count,source_sha256)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(target_id) DO NOTHING`,
        [...scopeValues(binding), owner, source.rows.length, source.digest]);
        const current = await target(client, binding, 'FOR UPDATE');
        if (Number(current.own_merchant_id) !== owner || Number(current.source_count) !== source.rows.length
            || !Buffer.isBuffer(current.source_sha256) || !current.source_sha256.equals(source.digest)) {
          throw failure('PRODUCT_TARGET_MISMATCH', 'product target source does not match');
        }
        if (inserted.rowCount === 1) {
          for (const row of source.rows) {
            await client.query(`INSERT INTO secureshop_review.product_target_products
              (target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,
               name,description,description_html,price,category,image_url,images,stock_quantity,
               status,template_source,source_created_at,source_updated_at)
              VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
            [binding.targetId, row.id, row.sourceRetailerId, row.retailerId, row.sourceSha256,
              row.name, row.description, row.descriptionHtml, row.price, row.category, row.imageUrl,
              JSON.stringify(row.images), row.stockQuantity, row.status, row.templateSource,
              row.createdAt, row.updatedAt]);
          }
        } else {
          const count = Number((await client.query(`SELECT count(*)::integer AS count
            FROM secureshop_review.product_target_products WHERE target_id=$1`, [binding.targetId])).rows[0].count);
          if (count !== source.rows.length) throw failure('PRODUCT_TARGET_PARTIAL', 'product target is incomplete');
        }
        await checkCurrent(executionScope(binding));
        return Object.freeze({ ...binding, ownMerchantId: owner, sourceCount: source.rows.length,
          sourceSha256: source.digest.toString('hex') });
      });
    },
    async list(input, options = {}) {
      const binding = scope(input); const limit = integer(options.limit, 'limit', 1, 100);
      const offset = integer(options.offset, 'offset', 0, 2147483647);
      const minRating = options.minRating == null ? null : integer(options.minRating, 'minRating', 1, 5);
      const maxPrice = options.maxPrice == null ? null : options.maxPrice;
      if (maxPrice !== null && (typeof maxPrice !== 'number' || !Number.isFinite(maxPrice)
          || maxPrice < 0 || maxPrice > 100000
          || Math.abs(maxPrice * 100 - Math.round(maxPrice * 100)) > 1e-8)) {
        throw failure('INVALID_ARGUMENT', 'maxPrice is invalid');
      }
      const category = bounded(options.category, 'category', 1024);
      const search = bounded(options.search, 'search', 1024);
      const status = bounded(options.status, 'status', 64);
      const retailerId = options.retailerId == null ? null : integer(options.retailerId, 'retailerId');
      if (!Object.hasOwn(SORTS, options.sort)) throw failure('INVALID_ARGUMENT', 'sort is invalid');
      await checkCurrent(executionScope(binding));
      return online(binding, async client => {
        await target(client, binding);
        const values = [binding.targetId, retailerId, status, category,
          search === null ? null : `%${search}%`, minRating, maxPrice, limit, offset];
        const where = `target_id=$1
          AND (($3::text='archived' AND archived_at IS NOT NULL)
            OR ($3::text IS DISTINCT FROM 'archived' AND archived_at IS NULL))
          AND ($2::integer IS NULL OR retailer_id=$2)
          AND ($3::text IS NULL OR status=$3) AND ($4::text IS NULL OR category=$4)
          AND ($5::text IS NULL OR name ILIKE $5 OR description ILIKE $5)
          AND ($6::integer IS NULL OR avg_rating_raw >= $6)
          AND ($7::numeric IS NULL OR price <= $7)`;
        const rows = (await client.query(`WITH effective AS (${EFFECTIVE_PRODUCTS}) SELECT * FROM effective
          WHERE ${where} ORDER BY ${SORTS[options.sort]} LIMIT $8 OFFSET $9`, values)).rows.map(rowProduct);
        const total = Number((await client.query(`WITH effective AS (${EFFECTIVE_PRODUCTS})
          SELECT count(*)::integer AS count FROM effective WHERE ${where}`, values.slice(0, 7))).rows[0].count);
        const categories = retailerId === null ? [] : (await client.query(`WITH effective AS (${EFFECTIVE_PRODUCTS})
          SELECT DISTINCT category FROM effective WHERE target_id=$1 AND retailer_id=$2
            AND archived_at IS NULL
            AND category IS NOT NULL ORDER BY category`, [binding.targetId, retailerId])).rows.map(row => row.category);
        await checkCurrent(executionScope(binding));
        return Object.freeze({ rows: Object.freeze(rows), total, categories: Object.freeze(categories) });
      }, { repeatable: true });
    },
    async listMerchantChoices(input, options = {}) {
      const binding=scope(input),retailerId=integer(options.retailerId,'retailerId');
      const search=bounded(options.search,'search',128);
      const status=options.status;
      if(!['active','inactive','all'].includes(status))throw failure('INVALID_ARGUMENT','status is invalid');
      const after=options.afterProductId===undefined?null:integer(options.afterProductId,'afterProductId');
      await checkCurrent(executionScope(binding));
      return online(binding,async client=>{
        await target(client,binding);
        const result=(await client.query(`WITH effective AS (${EFFECTIVE_PRODUCTS}),
          catalog_matches AS (SELECT * FROM effective WHERE target_id=$1 AND retailer_id=$2
           AND archived_at IS NULL AND ($3::text='all' OR status=$3)
           AND ($4::text IS NULL OR name ILIKE $4 OR description ILIKE $4))
          SELECT page.*, (SELECT count(*)::integer FROM catalog_matches) AS matched_total
          FROM (SELECT 1) singleton LEFT JOIN LATERAL
           (SELECT * FROM catalog_matches WHERE ($5::integer IS NULL OR product_id>$5)
            ORDER BY product_id LIMIT 6) page ON true ORDER BY page.product_id`,
        [binding.targetId,retailerId,status,search===null?null:`%${search}%`,after])).rows;
        const total=Number(result[0]?.matched_total);
        if(!Number.isSafeInteger(total)||total<0)throw failure('PRODUCT_DATA_INVALID','catalog count unavailable');
        const page=result.filter(row=>row.product_id!==null).slice(0,5).map(({matched_total,...row})=>rowProduct(row));
        await checkCurrent(executionScope(binding));
        return Object.freeze({rows:Object.freeze(page),total,
          nextProductId:result.filter(row=>row.product_id!==null).length>5?page.at(-1).id:null});
      },{repeatable:true});
    },
    async get(input, productId) {
      const binding = scope(input); const id = integer(productId, 'productId'); await checkCurrent(executionScope(binding));
      return online(binding, async client => {
        await target(client, binding);
        const row = (await client.query(`WITH effective AS (${EFFECTIVE_PRODUCTS}) SELECT * FROM effective
          WHERE target_id=$1 AND product_id=$2 AND archived_at IS NULL`, [binding.targetId, id])).rows[0];
        await checkCurrent(executionScope(binding)); return row ? rowProduct(row) : null;
      });
    },
    async categories(input) {
      const binding = scope(input); await checkCurrent(executionScope(binding));
      return online(binding, async client => {
        await target(client, binding);
        const rows = (await client.query(`WITH effective AS (${EFFECTIVE_PRODUCTS}) SELECT DISTINCT category
          FROM effective WHERE target_id=$1 AND archived_at IS NULL
            AND category IS NOT NULL ORDER BY category`, [binding.targetId])).rows;
        await checkCurrent(executionScope(binding));
        return Object.freeze(rows.map(row => row.category));
      });
    },
    async createListing(input, actorId, value, {effectTimeoutMs}={}) {
      const binding = scope(input); const actor = integer(actorId, 'actorId');
      const item = listing(value); await checkCurrent(executionScope(binding));
      if(effectTimeoutMs!==undefined&&effectTimeoutMs!==3000)throw failure('INVALID_ARGUMENT','Invalid effect timeout');
      return online(binding, async client => {
        if(effectTimeoutMs)await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");
        const current = await target(client, binding, 'FOR UPDATE');
        if (Number(current.own_merchant_id) !== actor && !require('../../services/secureshopSceneBinding').isSceneMerchant(binding, actor)) throw failure('OWNER_MISMATCH', 'merchant listing owner does not match');
        const inserted = await insertMerchantListing(client, binding, actor, item);
        await auditListing(client, binding, actor, 'listing_create', inserted.productId, item);
        await checkCurrent(executionScope(binding));
        return inserted.productId;
      });
    },
    async previewListingCreate(input, actorId, value, scopeKey, { preparation, modeToken } = {}) {
      const binding = scope(input), actor = integer(actorId, 'actorId');
      const item = create.normalizeListingCreateInput(value);
      if (!binding.scene || !create.LISTING_CREATE_SHA.test(scopeKey || ''))
        throw failure('SHOP_AUTH_INVALID', 'scene-bound merchant required');
      await checkCurrent(executionScope(binding));
      return online(binding, async client => {
        const current = await target(client, binding);
        if (Number(current.own_merchant_id) !== actor
            && !require('../../services/secureshopSceneBinding').isSceneMerchant(binding, actor))
          throw failure('OWNER_MISMATCH', 'merchant listing owner does not match');
        let source;
        if (item.presentation === 'html') {
          const token = rawModeToken(modeToken, binding);
          await token.assertCurrent();
          source = create.validateListingCreateSource({ version: 1, kind: 'merchant_authored_html',
            listing: item, authoredHtml: item.description,
            storedHtml: token.snapshot.mode === 'vuln' ? item.description : create.escapeListingHtml(item.description),
            preparation, execution: token.snapshot });
        }
        const body = { version: source ? 2 : 1, listing: item, currency: 'USD', initialStock: 0,
          status: 'active', scopeKey, ...(source ? { source } : {}) };
        return create.validateListingCreatePreview(Object.freeze({ ...body,
          requestSha256: create.listingCreateRequestDigest(body) }));
      });
    },
    async confirmListingCreate(input, actorId, { operationId, preview, personaSession, modeToken } = {}, { effectTimeoutMs } = {}) {
      const binding = scope(input), actor = integer(actorId, 'actorId');
      const operation = uuid(operationId, 'operationId');
      const saved = create.validateListingCreatePreview(preview);
      const key = create.listingCreateScopeKey(binding, actor, personaSession);
      if (saved.scopeKey !== key) throw failure('SHOP_AUTH_INVALID', 'listing create scope changed');
      if (effectTimeoutMs !== undefined && effectTimeoutMs !== 3000)
        throw failure('INVALID_ARGUMENT', 'Invalid effect timeout');
      await checkCurrent(executionScope(binding));
      return online(binding, async client => {
        if (effectTimeoutMs) await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");
        const current = await target(client, binding, 'FOR UPDATE');
        if (Number(current.own_merchant_id) !== actor
            && !require('../../services/secureshopSceneBinding').isSceneMerchant(binding, actor))
          throw failure('OWNER_MISMATCH', 'merchant listing owner does not match');
        const existing = (await client.query(`SELECT * FROM secureshop_review.owned_merchant_listing_create_receipts
          WHERE operation_id=$1`, [operation])).rows[0];
        if (existing) return Object.freeze({ ...createReceipt(existing, binding, actor, personaSession,
          key, saved.requestSha256), replayed: true });
        const token = saved.version === 2 ? rawModeToken(modeToken, binding, saved.source.execution) : null;
        await token?.assertCurrentAtEffect();
        const item = listing({ name: saved.listing.name, description: saved.listing.description,
          price: saved.listing.price, category: saved.listing.category,
          templateSource: null, images: [] });
        // @intentional-vulnerability xss-stored-listing
        // Exact merchant-authored HTML is published only inside the owned scene;
        // fixed mode retains its escaped literal counterpart.
        const inserted = await insertMerchantListing(client, binding, actor, item, saved.source || null);
        await auditListing(client, binding, actor, 'listing_create_confirm', inserted.productId,
          { operationId: operation, requestSha256: saved.requestSha256,
            sourceSha256: inserted.sourceSha256.toString('hex') });
        const record = { operation_id: operation, target_id: binding.targetId, launch_id: binding.launchId,
          scenario_id: binding.scenarioId, generation: binding.generation,
          original_platform_owner_id: binding.platformOwnerId,
          original_platform_session_id: binding.platformSessionId,
          scene_id: binding.scene.sceneId, scene_generation: binding.scene.sceneGeneration,
          grant_id: binding.scene.grantId, merchant_id: actor,
          persona_session_id: personaSession.sessionId.toLowerCase(),
          authority_version: personaSession.authorityVersion, product_id: inserted.productId,
          scope_key: Buffer.from(key, 'hex'), request_sha256: Buffer.from(saved.requestSha256, 'hex'),
          source_sha256: inserted.sourceSha256, ...(saved.version === 2
            ? { receipt_version: 2, source_document: saved.source } : {}) };
        record.receipt_sha256 = Buffer.from(createReceiptHash(record), 'hex');
        const savedRow = (await client.query(`INSERT INTO secureshop_review.owned_merchant_listing_create_receipts
          (operation_id,target_id,launch_id,scenario_id,generation,original_platform_owner_id,
           original_platform_session_id,scene_id,scene_generation,grant_id,merchant_id,persona_session_id,
           authority_version,product_id,scope_key,request_sha256,source_sha256,receipt_sha256
           ${saved.version === 2 ? ',receipt_version,source_document' : ''})
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18
           ${saved.version === 2 ? ',2,$19::jsonb' : ''})
          RETURNING *`, [record.operation_id, record.target_id, record.launch_id, record.scenario_id,
          record.generation, record.original_platform_owner_id, record.original_platform_session_id,
          record.scene_id, record.scene_generation, record.grant_id, record.merchant_id,
          record.persona_session_id, record.authority_version, record.product_id, record.scope_key,
          record.request_sha256, record.source_sha256, record.receipt_sha256,
          ...(saved.version === 2 ? [JSON.stringify(saved.source)] : [])])).rows[0];
        await token?.assertCurrentAtEffect();
        await checkCurrent(executionScope(binding));
        return Object.freeze({ ...createReceipt(savedRow, binding, actor, personaSession, key), replayed: false });
      });
    },
    async readListingCreate(input, actorId, { operationId, personaSession } = {}) {
      const binding = scope(input), actor = integer(actorId, 'actorId');
      const operation = uuid(operationId, 'operationId');
      const key = create.listingCreateScopeKey(binding, actor, personaSession);
      await checkCurrent(executionScope(binding));
      return online(binding, async client => {
        const current = await target(client, binding);
        if (Number(current.own_merchant_id) !== actor
            && !require('../../services/secureshopSceneBinding').isSceneMerchant(binding, actor))
          throw failure('OWNER_MISMATCH', 'merchant listing owner does not match');
        const row = (await client.query(`SELECT * FROM secureshop_review.owned_merchant_listing_create_receipts
          WHERE operation_id=$1 AND target_id=$2 AND merchant_id=$3 AND persona_session_id=$4
            AND scope_key=$5`, [operation, binding.targetId, actor,
          personaSession.sessionId.toLowerCase(), Buffer.from(key, 'hex')])).rows[0];
        return row ? Object.freeze({ ...createReceipt(row, binding, actor, personaSession, key), replayed: true })
          : Object.freeze({ operationId: operation, status: 'not_found', scopeKey: key });
      });
    },
    async readListingCreateSource(input, actorId, { operationId, personaSession } = {}) {
      const binding = scope(input), actor = integer(actorId, 'actorId');
      const operation = uuid(operationId, 'operationId');
      const key = create.listingCreateScopeKey(binding, actor, personaSession);
      await checkCurrent(executionScope(binding));
      return online(binding, async client => {
        const current = await target(client, binding);
        if (Number(current.own_merchant_id) !== actor
            && !require('../../services/secureshopSceneBinding').isSceneMerchant(binding, actor))
          throw failure('OWNER_MISMATCH', 'merchant listing owner does not match');
        const row = (await client.query(`SELECT * FROM secureshop_review.owned_merchant_listing_create_receipts
          WHERE operation_id=$1 AND target_id=$2 AND merchant_id=$3 AND persona_session_id=$4
            AND scope_key=$5`, [operation, binding.targetId, actor,
          personaSession.sessionId.toLowerCase(), Buffer.from(key, 'hex')])).rows[0];
        if (!row || Number(row.receipt_version) !== 2)
          throw failure('LISTING_CREATE_SOURCE_UNAVAILABLE', 'raw listing source is unavailable');
        const receipt = Object.freeze({ ...createReceipt(row, binding, actor, personaSession, key), replayed: true });
        const product = (await client.query(`WITH effective AS (${EFFECTIVE_PRODUCTS}) SELECT * FROM effective
          WHERE target_id=$1 AND product_id=$2 AND retailer_id=$3 AND archived_at IS NULL AND status='active'`,
        [binding.targetId, receipt.productId, actor])).rows[0];
        if (!product || product.description_html !== receipt.source.storedHtml
            || !Buffer.isBuffer(product.source_product_sha256)
            || product.source_product_sha256.toString('hex') !== receipt.sourceSha256)
          throw failure('LISTING_CREATE_SOURCE_UNAVAILABLE', 'raw listing source has changed');
        return Object.freeze({ receipt, product: Object.freeze({ productId: receipt.productId,
          descriptionHtml: product.description_html, sourceSha256: receipt.sourceSha256 }) });
      }, { repeatable: true });
    },
    async updateListing(input, actorId, productId, value, {effectTimeoutMs}={}) {
      const binding = scope(input); const actor = integer(actorId, 'actorId');
      const id = integer(productId, 'productId'); const changes = listing(value, { patch: true });
      await checkCurrent(executionScope(binding));
      if(effectTimeoutMs!==undefined&&effectTimeoutMs!==3000)throw failure('INVALID_ARGUMENT','Invalid effect timeout');
      return online(binding, async client => {
        if(effectTimeoutMs)await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");
        const current = await target(client, binding, 'FOR UPDATE');
        if (Number(current.own_merchant_id) !== actor && !require('../../services/secureshopSceneBinding').isSceneMerchant(binding, actor)) throw failure('OWNER_MISMATCH', 'merchant listing owner does not match');
        const base = (await client.query(`WITH effective AS (${EFFECTIVE_PRODUCTS}) SELECT * FROM effective
          WHERE target_id=$1 AND product_id=$2 AND retailer_id=$3 AND archived_at IS NULL`,
        [binding.targetId, id, actor])).rows[0];
        if (!base) return null;
        const merged = { name: changes.name ?? base.name,
          description: Object.hasOwn(changes, 'description') ? changes.description : base.description,
          price: changes.price ?? Number(base.price),
          category: Object.hasOwn(changes, 'category') ? changes.category : base.category,
          imageUrl: Object.hasOwn(changes, 'imageUrl') ? changes.imageUrl : base.image_url,
          templateSource: Object.hasOwn(changes, 'templateSource') ? changes.templateSource : base.template_source };
        await client.query(`INSERT INTO secureshop_review.product_target_listing_overlays
          (target_id,product_id,shop_user_id,name,description,description_html,price,category,
           image_url,images,stock_quantity,status,template_source)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
          ON CONFLICT(target_id,product_id) DO UPDATE SET name=EXCLUDED.name,
           description=EXCLUDED.description,description_html=EXCLUDED.description_html,
           price=EXCLUDED.price,category=EXCLUDED.category,image_url=EXCLUDED.image_url,
           images=EXCLUDED.images,stock_quantity=EXCLUDED.stock_quantity,status=EXCLUDED.status,
           template_source=EXCLUDED.template_source`,
        [binding.targetId, id, actor, merged.name, merged.description, base.description_html,
          merged.price, merged.category, merged.imageUrl, JSON.stringify(base.images),
          Number(base.stock_quantity), base.status, merged.templateSource]);
        await auditListing(client, binding, actor, 'listing_update', id, changes);
        await checkCurrent(executionScope(binding));
        return id;
      });
    },
    async previewListingEdit(input, actorId, productId, patch, scopeKey) {
      const binding = scope(input), actor = integer(actorId, 'actorId');
      const id = integer(productId, 'productId'), changes = edit.normalizeListingEditPatch(patch);
      if (!binding.scene || !edit.LISTING_EDIT_SHA.test(scopeKey || '')) throw failure('SHOP_AUTH_INVALID', 'scene-bound merchant required');
      await checkCurrent(executionScope(binding));
      return online(binding, async client => {
        const current = await target(client, binding);
        if (Number(current.own_merchant_id) !== actor
            && !require('../../services/secureshopSceneBinding').isSceneMerchant(binding, actor))
          throw failure('OWNER_MISMATCH', 'merchant listing owner does not match');
        const row = (await client.query(`WITH effective AS (${EFFECTIVE_PRODUCTS}) SELECT * FROM effective
          WHERE target_id=$1 AND product_id=$2 AND retailer_id=$3 AND archived_at IS NULL`,
        [binding.targetId, id, actor])).rows[0];
        if (!row) throw failure('OWNER_MISMATCH', 'owned listing unavailable');
        const { before, snapshotSha256 } = effectiveEdit(row);
        const provenance = (await client.query(`SELECT source_name,source_description,html_sha256
          FROM secureshop_review.owned_listing_generated_products WHERE target_id=$1 AND product_id=$2`,
        [binding.targetId, id])).rows[0];
        const merged = edit.listingEditMergedView(before, changes);
        const invalidatesGeneratedHtml = Boolean(provenance
          && (merged.name !== provenance.source_name || merged.description !== provenance.source_description)
          && crypto.createHash('sha256').update(before.descriptionHtml || '').digest('hex') === provenance.html_sha256);
        const after = edit.listingEditMergedView(before, changes, invalidatesGeneratedHtml);
        const catalogRevision = await editRevision(client, binding.targetId);
        const requestSha256 = edit.listingEditRequestDigest({ productId: id, scopeKey,
          catalogRevision, expectedSnapshotSha256: snapshotSha256, patch: changes,
          invalidatesGeneratedHtml, after });
        return edit.validateListingEditPreview(Object.freeze({ version: 1, productId: id,
          before, after, patch: changes, catalogRevision, expectedSnapshotSha256: snapshotSha256,
          invalidatesGeneratedHtml, requestSha256, scopeKey }));
      }, { repeatable: true });
    },
    async confirmListingEdit(input, actorId, { operationId, preview, personaSession } = {}, { effectTimeoutMs } = {}) {
      const binding = scope(input), actor = integer(actorId, 'actorId');
      const operation = uuid(operationId, 'operationId');
      const saved = edit.validateListingEditPreview(preview);
      const key = edit.listingEditScopeKey(binding, actor, personaSession);
      if (saved.scopeKey !== key) throw failure('SHOP_AUTH_INVALID', 'listing edit scope changed');
      if (effectTimeoutMs !== undefined && effectTimeoutMs !== 3000) throw failure('INVALID_ARGUMENT', 'Invalid effect timeout');
      await checkCurrent(executionScope(binding));
      return online(binding, async client => {
        if (effectTimeoutMs) await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");
        const current = await target(client, binding, 'FOR UPDATE');
        if (Number(current.own_merchant_id) !== actor
            && !require('../../services/secureshopSceneBinding').isSceneMerchant(binding, actor))
          throw failure('OWNER_MISMATCH', 'merchant listing owner does not match');
        const existing = (await client.query(`SELECT * FROM secureshop_review.owned_merchant_listing_edit_receipts
          WHERE operation_id=$1`, [operation])).rows[0];
        if (existing) {
          if (existing.target_id !== binding.targetId || Number(existing.product_id) !== saved.productId)
            throw failure('LISTING_EDIT_OPERATION_CONFLICT', 'listing edit operation differs');
          return Object.freeze({ ...editReceipt(existing, binding, actor, personaSession, key, saved.requestSha256), replayed: true });
        }
        const revision = await editRevision(client, binding.targetId);
        if (revision !== saved.catalogRevision) throw failure('LISTING_EDIT_STALE', 'listing catalog changed');
        const row = (await client.query(`WITH effective AS (${EFFECTIVE_PRODUCTS}) SELECT * FROM effective
          WHERE target_id=$1 AND product_id=$2 AND retailer_id=$3 AND archived_at IS NULL`,
        [binding.targetId, saved.productId, actor])).rows[0];
        if (!row) throw failure('LISTING_EDIT_STALE', 'owned listing changed');
        const observed = effectiveEdit(row);
        if (observed.snapshotSha256 !== saved.expectedSnapshotSha256
            || JSON.stringify(observed.before) !== JSON.stringify(saved.before))
          throw failure('LISTING_EDIT_STALE', 'listing snapshot changed');
        const next = edit.listingEditMergedView(observed.before, saved.patch);
        await client.query(`INSERT INTO secureshop_review.product_target_listing_overlays
          (target_id,product_id,shop_user_id,name,description,description_html,price,category,
           image_url,images,stock_quantity,status,template_source)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
          ON CONFLICT(target_id,product_id) DO UPDATE SET name=EXCLUDED.name,
           description=EXCLUDED.description,description_html=EXCLUDED.description_html,
           price=EXCLUDED.price,category=EXCLUDED.category,image_url=EXCLUDED.image_url,
           images=EXCLUDED.images,stock_quantity=EXCLUDED.stock_quantity,status=EXCLUDED.status,
           template_source=EXCLUDED.template_source`,
        [binding.targetId, saved.productId, actor, next.name, next.description,
          observed.before.descriptionHtml, next.price, next.category, next.imageUrl,
          JSON.stringify(row.images), Number(row.stock_quantity), row.status, next.templateSource]);
        const appliedRow = (await client.query(`WITH effective AS (${EFFECTIVE_PRODUCTS}) SELECT * FROM effective
          WHERE target_id=$1 AND product_id=$2 AND retailer_id=$3 AND archived_at IS NULL`,
        [binding.targetId, saved.productId, actor])).rows[0];
        const applied = effectiveEdit(appliedRow);
        if (JSON.stringify(applied.before) !== JSON.stringify(saved.after))
          throw failure('LISTING_EDIT_STALE', 'listing edit result changed');
        await auditListing(client, binding, actor, 'listing_edit_confirm', saved.productId,
          { operationId: operation, requestSha256: saved.requestSha256,
            beforeSha256: saved.expectedSnapshotSha256, afterSha256: applied.snapshotSha256 });
        const record = { operation_id: operation, target_id: binding.targetId, launch_id: binding.launchId,
          scenario_id: binding.scenarioId, generation: binding.generation,
          original_platform_owner_id: binding.platformOwnerId,
          original_platform_session_id: binding.platformSessionId,
          scene_id: binding.scene.sceneId, scene_generation: binding.scene.sceneGeneration,
          grant_id: binding.scene.grantId, merchant_id: actor,
          persona_session_id: personaSession.sessionId.toLowerCase(),
          authority_version: personaSession.authorityVersion, product_id: saved.productId,
          scope_key: Buffer.from(key, 'hex'), catalog_revision: saved.catalogRevision,
          request_sha256: Buffer.from(saved.requestSha256, 'hex'),
          before_sha256: Buffer.from(saved.expectedSnapshotSha256, 'hex'),
          after_sha256: Buffer.from(applied.snapshotSha256, 'hex') };
        record.receipt_sha256 = Buffer.from(editReceiptHash(record), 'hex');
        const inserted = (await client.query(`INSERT INTO secureshop_review.owned_merchant_listing_edit_receipts
          (operation_id,target_id,launch_id,scenario_id,generation,original_platform_owner_id,
           original_platform_session_id,scene_id,scene_generation,grant_id,merchant_id,persona_session_id,
           authority_version,product_id,scope_key,catalog_revision,request_sha256,before_sha256,
           after_sha256,receipt_sha256)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
          RETURNING *`, [record.operation_id, record.target_id, record.launch_id, record.scenario_id,
          record.generation, record.original_platform_owner_id, record.original_platform_session_id,
          record.scene_id, record.scene_generation, record.grant_id, record.merchant_id,
          record.persona_session_id, record.authority_version, record.product_id, record.scope_key,
          record.catalog_revision, record.request_sha256, record.before_sha256, record.after_sha256,
          record.receipt_sha256])).rows[0];
        await checkCurrent(executionScope(binding));
        return Object.freeze({ ...editReceipt(inserted, binding, actor, personaSession, key), replayed: false });
      });
    },
    async readListingEdit(input, actorId, { operationId, personaSession } = {}) {
      const binding = scope(input), actor = integer(actorId, 'actorId');
      const operation = uuid(operationId, 'operationId');
      const key = edit.listingEditScopeKey(binding, actor, personaSession);
      await checkCurrent(executionScope(binding));
      return online(binding, async client => {
        const current = await target(client, binding);
        if (Number(current.own_merchant_id) !== actor
            && !require('../../services/secureshopSceneBinding').isSceneMerchant(binding, actor))
          throw failure('OWNER_MISMATCH', 'merchant listing owner does not match');
        const row = (await client.query(`SELECT * FROM secureshop_review.owned_merchant_listing_edit_receipts
          WHERE operation_id=$1 AND target_id=$2 AND merchant_id=$3 AND persona_session_id=$4
            AND scope_key=$5`, [operation, binding.targetId, actor,
          personaSession.sessionId.toLowerCase(), Buffer.from(key, 'hex')])).rows[0];
        return row ? Object.freeze({ ...editReceipt(row, binding, actor, personaSession, key), replayed: true })
          : Object.freeze({ operationId: operation, status: 'not_found', scopeKey: key });
      });
    },
    async archiveListing(input, actorId, productId, {effectTimeoutMs}={}) {
      const binding = scope(input); const actor = integer(actorId, 'actorId');
      const id = integer(productId, 'productId'); await checkCurrent(executionScope(binding));
      if(effectTimeoutMs!==undefined&&effectTimeoutMs!==3000)throw failure('INVALID_ARGUMENT','Invalid effect timeout');
      return online(binding, async client => {
        if(effectTimeoutMs)await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");
        const current = await target(client, binding, 'FOR UPDATE');
        if (Number(current.own_merchant_id) !== actor && !require('../../services/secureshopSceneBinding').isSceneMerchant(binding, actor)) throw failure('OWNER_MISMATCH', 'merchant listing owner does not match');
        const base = (await client.query(`WITH effective AS (${EFFECTIVE_PRODUCTS}) SELECT * FROM effective
          WHERE target_id=$1 AND product_id=$2 AND retailer_id=$3 AND archived_at IS NULL`,
        [binding.targetId, id, actor])).rows[0];
        if (!base) return 0;
        await client.query(`INSERT INTO secureshop_review.product_target_listing_overlays
          (target_id,product_id,shop_user_id,name,description,description_html,price,category,
           image_url,images,stock_quantity,status,template_source,archived_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'archived',$12,clock_timestamp())
          ON CONFLICT(target_id,product_id) DO UPDATE SET status='archived',archived_at=clock_timestamp()`,
        [binding.targetId, id, actor, base.name, base.description, base.description_html,
          Number(base.price), base.category, base.image_url, JSON.stringify(base.images),
          Number(base.stock_quantity), base.template_source]);
        await auditListing(client, binding, actor, 'listing_archive', id, {});
        await checkCurrent(executionScope(binding));
        return 1;
      });
    },
    async readCleanupReceipt(input, { operationId } = {}) {
      const binding = scope(input); const operation = uuid(operationId, 'operationId');
      await checkCleanup(Object.freeze({ ...binding, targetKind: 'products', operationId: operation,
        fromGeneration: binding.generation }));
      return withTransaction(pool, async client => {
        const target = (await client.query(`SELECT lifecycle FROM secureshop_review.product_targets
          WHERE ${TARGET_WHERE} FOR SHARE`, scopeValues(binding))).rows[0];
        if (!target || target.lifecycle !== 'retired') {
          throw failure('PRODUCT_CLEANUP_MISMATCH', 'cleanup target is not retired');
        }
        const row = (await client.query(`SELECT * FROM secureshop_review.product_cleanup_receipts
          WHERE target_id=$1`, [binding.targetId])).rows[0];
        if (!row) throw failure('PRODUCT_CLEANUP_RECEIPT_UNAVAILABLE', 'product cleanup receipt is unavailable');
        await assertTargetEmpty(client, binding.targetId);
        const accountRow = (await client.query(`SELECT * FROM secureshop_review.product_account_cleanup_receipts
          WHERE target_id=$1`, [binding.targetId])).rows[0];
        const listingRow = (await client.query(`SELECT * FROM secureshop_review.product_listing_cleanup_receipts
          WHERE target_id=$1`, [binding.targetId])).rows[0];
        const refundRow = (await client.query(`SELECT * FROM secureshop_review.product_target_refund_cleanup_receipts
          WHERE target_id=$1`, [binding.targetId])).rows[0];
        await checkCleanup(Object.freeze({ ...binding, targetKind: 'products', operationId: operation,
          fromGeneration: binding.generation }));
        return verifiedReceipt(row, binding, operation, accountRow, listingRow, refundRow);
      });
    },
    async cleanup(input, { operationId } = {}) {
      const binding = scope(input); const operation = uuid(operationId, 'operationId');
      const authority = Object.freeze({ ...binding, targetKind: 'products', operationId: operation,
        fromGeneration: binding.generation });
      await checkCleanup(authority);
      return withTransaction(pool, async client => {
        const current = (await client.query(`SELECT * FROM secureshop_review.product_targets
          WHERE ${TARGET_WHERE} FOR UPDATE`, scopeValues(binding))).rows[0];
        if (!current) throw failure('PRODUCT_TARGET_UNAVAILABLE', 'product target is unavailable');
        const existing = (await client.query(`SELECT * FROM secureshop_review.product_cleanup_receipts
          WHERE target_id=$1 FOR UPDATE`, [binding.targetId])).rows;
        if (existing.length) {
          if (existing.length !== 1 || existing[0].operation_id !== operation
              || existing[0].target_id !== binding.targetId) throw failure('PRODUCT_CLEANUP_MISMATCH', 'product cleanup receipt does not match');
          await assertTargetEmpty(client, binding.targetId);
          const replayRetrieval = (await client.query(`SELECT c.lifecycle,r.*,
            r.receipt_sha256=secureshop_review.product_retrieval_cleanup_digest(
              r.operation_id,r.target_id,r.launch_id,r.scenario_id,r.generation,
              r.original_platform_owner_id,r.original_platform_session_id,r.deleted_document_count) AS receipt_valid
            FROM secureshop_review.product_target_retrieval_config c
            LEFT JOIN secureshop_review.product_target_retrieval_cleanup_receipts r
              ON r.target_id=c.target_id AND r.operation_id=$1 WHERE c.target_id=$2`,
          [operation, binding.targetId])).rows[0];
          if (replayRetrieval && (!replayRetrieval.lifecycle || replayRetrieval.lifecycle !== 'retired'
              || replayRetrieval.receipt_valid !== true
              || replayRetrieval.launch_id !== binding.launchId
              || replayRetrieval.scenario_id !== binding.scenarioId
              || Number(replayRetrieval.generation) !== binding.generation
              || Number(replayRetrieval.original_platform_owner_id) !== binding.platformOwnerId
              || Number(replayRetrieval.original_platform_session_id) !== binding.platformSessionId)) {
            throw failure('PRODUCT_CLEANUP_MISMATCH', 'retrieval cleanup receipt does not match');
          }
          const accountRow = (await client.query(`SELECT * FROM secureshop_review.product_account_cleanup_receipts
            WHERE target_id=$1`, [binding.targetId])).rows;
          if (accountRow.length > 1) throw failure('PRODUCT_CLEANUP_MISMATCH', 'account cleanup receipt does not match');
          const listingRow = (await client.query(`SELECT * FROM secureshop_review.product_listing_cleanup_receipts
            WHERE target_id=$1`, [binding.targetId])).rows;
          const refundRows = (await client.query(`SELECT * FROM secureshop_review.product_target_refund_cleanup_receipts
            WHERE target_id=$1`, [binding.targetId])).rows;
          if (refundRows.length > 1) throw failure('PRODUCT_CLEANUP_MISMATCH', 'refund cleanup receipt does not match');
          if (listingRow.length > 1) throw failure('PRODUCT_CLEANUP_MISMATCH', 'listing cleanup receipt does not match');
          await checkCleanup(authority);
          return verifiedReceipt(existing[0], binding, operation, accountRow[0] || null,
            listingRow[0] || null, refundRows[0] || null);
        }
        const counts = (await client.query(`SELECT
          (SELECT count(*)::integer FROM secureshop_review.product_target_products WHERE target_id=$1) AS products,
          (SELECT count(*)::integer FROM secureshop_review.product_target_merchant_listings WHERE target_id=$1) AS created,
          (SELECT count(*)::integer FROM secureshop_review.product_target_listing_overlays WHERE target_id=$1) AS overlays`,
        [binding.targetId])).rows[0];
        const count = Number(counts.products), createdCount = Number(counts.created), overlayCount = Number(counts.overlays);
        if (count - createdCount !== Number(current.source_count) || !Buffer.isBuffer(current.source_sha256)) {
          throw failure('PRODUCT_TARGET_PARTIAL', 'product target cannot produce a cleanup receipt');
        }
        if (current.lifecycle === 'active') await client.query(`UPDATE secureshop_review.product_targets
          SET lifecycle='retired',retired_at=clock_timestamp() WHERE target_id=$1`, [binding.targetId]);
        else if (current.lifecycle !== 'retired') throw failure('PRODUCT_TARGET_UNAVAILABLE', 'product target is unavailable');
        const retrievalConfig = (await client.query(`SELECT * FROM secureshop_review.product_target_retrieval_config
          WHERE target_id=$1`, [binding.targetId])).rows[0];
        if (retrievalConfig) {
          await client.query('SELECT * FROM secureshop_review.retire_product_target_retrieval($1,$2,$3,$4,$5,$6,$7)',
            [operation, binding.targetId, binding.launchId, binding.scenarioId, binding.generation,
              binding.platformOwnerId, binding.platformSessionId]);
        }

        const deletedAddresses = await client.query(`DELETE FROM secureshop_review.product_target_addresses WHERE target_id=$1`, [binding.targetId]);
        const deletedProfiles = await client.query(`DELETE FROM secureshop_review.product_target_profile_overlays WHERE target_id=$1`, [binding.targetId]);
        const deletedRefunds = await client.query(`DELETE FROM secureshop_review.product_target_refund_requests WHERE target_id=$1`, [binding.targetId]);
        const refundSha256 = refundReceiptDigest(binding, operation, deletedRefunds.rowCount);
        const refundRow = (await client.query(`INSERT INTO secureshop_review.product_target_refund_cleanup_receipts
          (operation_id,target_id,deleted_ticket_count,receipt_sha256) VALUES($1,$2,$3,$4) RETURNING *`,
        [operation, binding.targetId, deletedRefunds.rowCount, refundSha256])).rows[0];
        await client.query(`DELETE FROM secureshop_review.product_target_order_items WHERE target_id=$1`, [binding.targetId]);
        await client.query(`DELETE FROM secureshop_review.product_target_orders WHERE target_id=$1`, [binding.targetId]);
        await client.query(`DELETE FROM secureshop_review.product_target_cart_items WHERE target_id=$1`, [binding.targetId]);
        const removedCreated = await client.query(`DELETE FROM secureshop_review.product_target_products p
          WHERE p.target_id=$1 AND EXISTS (SELECT 1 FROM secureshop_review.product_target_merchant_listings m
            WHERE m.target_id=p.target_id AND m.product_id=p.product_id)`, [binding.targetId]);
        if (removedCreated.rowCount !== createdCount) {
          throw failure('PRODUCT_CLEANUP_INCOMPLETE', 'merchant listing cleanup is incomplete');
        }
        const listingSha256 = listingReceiptDigest(binding, operation, createdCount, overlayCount);
        await client.query(`INSERT INTO secureshop_review.product_listing_cleanup_receipts
          (operation_id,target_id,deleted_created_count,deleted_overlay_count,receipt_sha256)
          VALUES($1,$2,$3,$4,$5)`, [operation, binding.targetId, createdCount, overlayCount, listingSha256]);
        const removed = await client.query(`DELETE FROM secureshop_review.product_target_products WHERE target_id=$1`, [binding.targetId]);
        if (removed.rowCount !== Number(current.source_count)) throw failure('PRODUCT_CLEANUP_INCOMPLETE', 'product cleanup is incomplete');
        const accountSha256 = accountReceiptDigest(binding, operation,
          deletedProfiles.rowCount, deletedAddresses.rowCount);
        const accountRow = (await client.query(`INSERT INTO secureshop_review.product_account_cleanup_receipts
          (operation_id,target_id,launch_id,scenario_id,generation,original_platform_owner_id,
           original_platform_session_id,deleted_profile_count,deleted_address_count,receipt_sha256)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
        [operation, ...scopeValues(binding), deletedProfiles.rowCount, deletedAddresses.rowCount,
          accountSha256])).rows[0];
        const receiptSha256 = receiptDigest(binding, operation, Number(current.source_count), current.source_sha256);
        const row = (await client.query(`INSERT INTO secureshop_review.product_cleanup_receipts
          (operation_id,target_id,launch_id,scenario_id,generation,original_platform_owner_id,
           original_platform_session_id,deleted_product_count,source_count,source_sha256,receipt_sha256)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
        [operation, ...scopeValues(binding), Number(current.source_count), Number(current.source_count), current.source_sha256, receiptSha256])).rows[0];
        const listingRow = { operation_id: operation, target_id: binding.targetId,
          deleted_created_count: createdCount, deleted_overlay_count: overlayCount,
          receipt_sha256: listingSha256 };
        await checkCleanup(authority); return verifiedReceipt(row, binding, operation, accountRow, listingRow, refundRow);
      });
    },
  });
}

module.exports = { createSecureShopBoundProductRepository, MAX_PRODUCTS,
  EFFECTIVE_PRODUCTS, EFFECTIVE_REVIEW_TARGET_JOIN };
