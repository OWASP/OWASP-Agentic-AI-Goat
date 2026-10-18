'use strict';

const { withTransaction } = require('./index');
const { randomUUID, createHash } = require('node:crypto');
const { copySceneBinding, executionScope, assertSceneGrant, withSceneLease } =
  require('../../services/secureshopSceneBinding');

// Private in-process result: only the locked, pre-write cart limit branch emits it.
const CART_QUANTITY_LIMIT_REJECTED = Symbol('cart quantity limit rejected');
const EMPTY_CART_REJECTED = Symbol('empty cart rejected');
const CART_STOCK_REJECTED = Symbol('cart stock unavailable');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function fail(message) {
  throw Object.assign(new Error(message), { code: 'INVALID_ARGUMENT' });
}
function integer(value, label, min = 1, max = 2147483647) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(`${label} is invalid`);
  return value;
}
function text(value, label, maximum) {
  if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value, 'utf8') > maximum) {
    fail(`${label} is invalid`);
  }
  return value;
}
function normalizeOrderProductName(value) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') fail('productName is invalid');
  const name = value.trim();
  if (!name || name.includes('\0') || Buffer.byteLength(name, 'utf8') > 128) fail('productName is invalid');
  return name;
}
function binding(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('scope is invalid');
  for (const key of ['targetId', 'launchId', 'scenarioId']) {
    if (typeof input[key] !== 'string' || !UUID.test(input[key])) fail(`${key} is invalid`);
  }
  return copySceneBinding(input, Object.freeze({
    targetId: input.targetId.toLowerCase(),
    launchId: input.launchId.toLowerCase(),
    scenarioId: input.scenarioId.toLowerCase(),
    generation: integer(input.generation, 'generation', 1, Number.MAX_SAFE_INTEGER),
    platformOwnerId: integer(input.platformOwnerId, 'platformOwnerId'),
    platformSessionId: integer(input.platformSessionId, 'platformSessionId'),
  }));
}
function values(value) {
  return [value.targetId, value.launchId, value.scenarioId, value.generation,
    value.platformOwnerId, value.platformSessionId];
}
async function target(client, value) {
  const row = (await client.query(`SELECT lifecycle FROM secureshop_review.product_targets
    WHERE target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4
      AND original_platform_owner_id=$5 AND original_platform_session_id=$6 FOR SHARE`,
  values(value))).rows[0];
  if (!row || row.lifecycle !== 'active') {
    throw Object.assign(new Error('commerce target unavailable'), { code: 'PRODUCT_TARGET_UNAVAILABLE' });
  }
}
async function lockCart(client, targetId, shopUserId) {
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text,$2::bigint))',
    [targetId, shopUserId]);
}
function cents(value) {
  const match = /^(\d{1,10})(?:\.(\d{1,2}))?$/.exec(String(value));
  if (!match) throw new Error('invalid stored product price');
  const amount = Number(match[1]) * 100 + Number((match[2] || '').padEnd(2, '0'));
  if (!Number.isSafeInteger(amount)) throw new Error('invalid stored product price');
  return amount;
}
function cart(row) {
  return Object.freeze({
    id: Number(row.cart_item_id), product_id: Number(row.product_id), quantity: Number(row.quantity),
    name: row.name, price: Number(row.price), image_url: row.image_url,
  });
}
function order(row) {
  return Object.freeze({
    id: Number(row.order_id), user_id: Number(row.shop_user_id), total_amount: Number(row.total_amount),
    status: row.status, payment_method: row.payment_method, payment_status: row.payment_status,
    shipping_address: row.shipping_address, order_date: row.order_date, updated_at: row.updated_at,
    ...(row.subtotal_amount===undefined?{}:{subtotal_amount:Number(row.subtotal_amount),discount_amount:Number(row.discount_amount),coupon_code:row.coupon_code,coupon_percent:row.coupon_percent===null?null:Number(row.coupon_percent)}),
  });
}
function merchantOrderCursor(value) {
  if (value === undefined) return [null, null];
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,160}$/.test(value)) fail('order cursor invalid');
  let tuple; try { tuple = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')); } catch { fail('order cursor invalid'); }
  if (!Array.isArray(tuple) || tuple.length !== 2 || typeof tuple[0] !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(tuple[0])
      || !Number.isFinite(Date.parse(tuple[0])) || new Date(tuple[0]).toISOString().slice(0,19)!==tuple[0].slice(0,19)
      || !Number.isSafeInteger(tuple[1]) || tuple[1] < 1 || tuple[1] > 2147483647
      || Buffer.from(JSON.stringify(tuple)).toString('base64url') !== value) fail('order cursor invalid');
  return tuple;
}
function importItems(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 50) fail('items are invalid');
  const items = value.map(row => {
    if (!row || typeof row !== 'object' || Array.isArray(row)
        || Object.keys(row).sort().join(',') !== 'productId,quantity') fail('items are invalid');
    return Object.freeze({ productId: integer(row.productId, 'productId'),
      quantity: integer(row.quantity, 'quantity', 1, 99) });
  }).sort((a, b) => a.productId - b.productId);
  if (new Set(items.map(row => row.productId)).size !== items.length) fail('items are invalid');
  return Object.freeze(items);
}
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }

function createSecureShopBoundCommerceRepository(pool, { checkCurrent, auditStore, effectTimeoutMs, couponRepository } = {}) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function'
      || typeof checkCurrent !== 'function') fail('dependencies invalid');

  if (effectTimeoutMs !== undefined && effectTimeoutMs !== 3000) throw new TypeError('Bounded commerce timeout required');

  async function guarded(input, work) {
    const value = binding(input);
    const execution = executionScope(value);
    await checkCurrent(execution);
    return withSceneLease(value, () => withTransaction(pool, async client => {
      if (effectTimeoutMs) await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");
      await assertSceneGrant(client, value);
      await target(client, value);
      const result = await work(client, value);
      await checkCurrent(execution);
      await assertSceneGrant(client, value);
      return result;
    }));
  }

  async function merchantOrdersWithClient(client, value, merchant, orderId, cursor, productName) {
    const [beforeDate, beforeId] = merchantOrderCursor(cursor);
    const { rows } = await client.query(`WITH owned AS (
      SELECT o.order_id,o.status,o.order_date,oi.order_item_id,oi.product_id,oi.product_name,
        oi.quantity,oi.price,COALESCE((to_jsonb(oi)->>'discount_amount')::numeric,0) AS discount_amount
      FROM secureshop_review.product_target_orders o
      JOIN secureshop_review.product_target_order_items oi
        ON oi.target_id=o.target_id AND oi.order_id=o.order_id
      JOIN secureshop_review.product_target_products p
        ON p.target_id=oi.target_id AND p.product_id=oi.product_id
      WHERE o.target_id=$1 AND p.retailer_id=$2 AND ($3::bigint IS NULL OR o.order_id=$3)
        AND ($4::timestamptz IS NULL OR (o.order_date,o.order_id)<($4::timestamptz,$5::bigint))
    ), picked AS (
      SELECT order_id,order_date FROM owned GROUP BY order_id,order_date
      ${productName === undefined ? '' : 'HAVING bool_or(strpos(lower(product_name),lower($6::text)) > 0)'}
      ORDER BY order_date DESC,order_id DESC LIMIT 6
    ) SELECT x.order_id,x.status,x.order_date,
      to_char(x.order_date AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_date,
      jsonb_agg(jsonb_build_object('product_id',x.product_id,'product_name',x.product_name,
        'quantity',x.quantity,'price',x.price::text,'discount_amount',x.discount_amount::text)
        ORDER BY x.order_item_id) AS items
      FROM owned x JOIN picked p USING(order_id)
      GROUP BY x.order_id,x.status,x.order_date ORDER BY x.order_date DESC,x.order_id DESC`,
    [value.targetId, merchant, orderId, beforeDate, beforeId,
      ...(productName === undefined ? [] : [productName])]);
    const visible = rows.slice(0,5);
    const orders = Object.freeze(visible.map(row => {
      if (!Array.isArray(row.items) || !row.items.length || row.items.length > 256) fail('merchant order lines unavailable');
      let subtotal = 0;
      const items = row.items.map(line => {
        const quantity = integer(Number(line.quantity), 'quantity'), price = cents(line.price), discount = cents(line.discount_amount);
        const lineTotal = quantity * price - discount;
        if (!Number.isSafeInteger(lineTotal) || lineTotal < 0) fail('merchant order total unavailable');
        subtotal += lineTotal;
        return Object.freeze({ productId: integer(Number(line.product_id), 'productId'),
          name: text(line.product_name, 'product name', 4096), quantity, price: price / 100,
          discountAmount: discount / 100, lineTotal: lineTotal / 100 });
      });
      if (!Number.isSafeInteger(subtotal)) fail('merchant order total unavailable');
      const date = new Date(row.order_date); if (!Number.isFinite(date.getTime())) fail('order date unavailable');
      return Object.freeze({ orderId: integer(Number(row.order_id), 'orderId'),
        status: text(row.status, 'status', 64), orderDate: date.toISOString(),
        merchantSubtotal: subtotal / 100, items: Object.freeze(items) });
    }));
    const last = visible.at(-1);
    const nextCursor = rows.length > 5 ? Buffer.from(JSON.stringify([last.cursor_date,orders.at(-1).orderId])).toString('base64url') : null;
    if (nextCursor) merchantOrderCursor(nextCursor);
    return Object.freeze({ orders, nextCursor, ...(productName === undefined ? {} : { productName }) });
  }

  if (auditStore && typeof auditStore.append !== 'function') fail('audit dependency invalid');
  async function audit(client, value, owner, action, targetId, params) {
    if (!auditStore) return; // Candidate wiring is enabled only after journal/deletion qualification.
    const provenance = value.scene ? { storageTargetId: value.targetId,
      sceneId: value.scene.sceneId, sceneGeneration: value.scene.sceneGeneration } : {};
    await auditStore.append(client, { eventId: randomUUID(), scope: executionScope(value),
      persona: { id: owner, role: 'customer' }, actor: 'customer', action,
      target: String(targetId), paramsJson: JSON.stringify({ ...params, ...provenance }), outcome: 'completed',
      sourceKind: action === 'checkout' ? 'order' : 'cart', sourceId: String(targetId) });
  }

  async function listCartWithClient(client, value, owner, mode) {
        if(couponRepository)await lockCart(client,value.targetId,owner);
        const rows = (await client.query(`SELECT c.cart_item_id,c.product_id,c.quantity,
            CASE WHEN o.product_id IS NULL THEN p.name ELSE o.name END AS name,
            CASE WHEN o.product_id IS NULL THEN p.price ELSE o.price END AS price,
            CASE WHEN o.product_id IS NULL THEN p.image_url ELSE o.image_url END AS image_url
          FROM secureshop_review.product_target_cart_items c
          JOIN secureshop_review.product_target_products p
            ON p.target_id=c.target_id AND p.product_id=c.product_id
          LEFT JOIN secureshop_review.product_target_listing_overlays o
            ON o.target_id=p.target_id AND o.product_id=p.product_id
          WHERE c.target_id=$1 AND c.shop_user_id=$2 ORDER BY c.cart_item_id`,
        [value.targetId, owner])).rows.map(cart);
        const subtotal = rows.reduce((sum, row) => sum + cents(row.price) * row.quantity, 0) / 100;
        if(couponRepository){const coupon=await couponRepository.currentWithClient(client,value.targetId,owner,mode),quote=require('../../services/secureshopCouponContract').money(rows.map(row=>cents(row.price)*row.quantity),coupon?.discount_percent||0);return Object.freeze({items:Object.freeze(rows),subtotal:quote.subtotalCents/100,discount:quote.discountCents/100,total:quote.totalCents/100,coupon:coupon?{code:coupon.code,discount_percent:coupon.discount_percent,applied_amount:quote.discountCents/100}:null});}
        return Object.freeze({ items: Object.freeze(rows), subtotal });
  }
  async function addCartWithClient(client, value, owner, product, requested) {
        await lockCart(client, value.targetId, owner);
        const existing = (await client.query(`SELECT cart_item_id,quantity
          FROM secureshop_review.product_target_cart_items
          WHERE target_id=$1 AND shop_user_id=$2 AND product_id=$3 FOR UPDATE`,
        [value.targetId, owner, product])).rows[0];
        if (existing && Number(existing.quantity) + requested > 99) return CART_QUANTITY_LIMIT_REJECTED;
        const row = existing
          ? (await client.query(`UPDATE secureshop_review.product_target_cart_items SET quantity=quantity+$4
              WHERE target_id=$1 AND shop_user_id=$2 AND product_id=$3 RETURNING cart_item_id`,
          [value.targetId, owner, product, requested])).rows[0]
          : (await client.query(`INSERT INTO secureshop_review.product_target_cart_items
              (target_id,shop_user_id,product_id,quantity) VALUES($1,$2,$3,$4) RETURNING cart_item_id`,
          [value.targetId, owner, product, requested])).rows[0];
        await audit(client, value, owner, 'cart_add', row.cart_item_id, { productId: product, quantity: requested });
        return Object.freeze({ id: Number(row.cart_item_id) });
  }
  async function updateCartWithClient(client, value, owner, id, requested) {
        await lockCart(client, value.targetId, owner);
        const result = await client.query(`UPDATE secureshop_review.product_target_cart_items SET quantity=$4
          WHERE target_id=$1 AND shop_user_id=$2 AND cart_item_id=$3`,
        [value.targetId, owner, id, requested]);
        if (result.rowCount) await audit(client, value, owner, 'cart_update', id, { quantity: requested });
        return result.rowCount;
  }
  async function removeCartWithClient(client, value, owner, id) {
        await lockCart(client, value.targetId, owner);
        const result = await client.query(`DELETE FROM secureshop_review.product_target_cart_items
          WHERE target_id=$1 AND shop_user_id=$2 AND cart_item_id=$3`,
        [value.targetId, owner, id]);
        if (result.rowCount) await audit(client, value, owner, 'cart_remove', id, {});
        return result.rowCount;
  }
  async function checkoutWithClient(client, value, owner, shipping, payment, operationId, persona, personaSession, mode) {
        await lockCart(client, value.targetId, owner);
        // Reservation and any stock preparation remain inside this rollback scope.
        // Only a confirmed pre-write cart denial may return a known rejection.
        await client.query('SAVEPOINT empty_cart_checkout');
        const rejectCart = async (result) => {
          await client.query('ROLLBACK TO SAVEPOINT empty_cart_checkout');
          await client.query('RELEASE SAVEPOINT empty_cart_checkout');
          return result;
        };
        const checkoutContext={target:value,persona,personaSession,operationId,mode,shippingAddress:shipping,paymentMethod:payment};
        if(couponRepository){const prior=await couponRepository.beginCheckoutWithClient(client,checkoutContext);if(prior.state==='completed')return prior.result;}
        let stock;
        if(couponRepository){const ids=(await client.query('SELECT product_id FROM secureshop_review.product_target_cart_items WHERE target_id=$1 AND shop_user_id=$2 ORDER BY product_id',[value.targetId,owner])).rows.map(row=>Number(row.product_id));if(!ids.length)return rejectCart(EMPTY_CART_REJECTED);stock=await require('./secureshopOwnedStock').lockStock(client,value.targetId,ids);}
        const rows = (await client.query(`SELECT c.product_id,c.quantity,
            CASE WHEN o.product_id IS NULL THEN p.name ELSE o.name END AS name,
            CASE WHEN o.product_id IS NULL THEN p.price ELSE o.price END AS price,
            (o.archived_at IS NOT NULL) AS archived
          FROM secureshop_review.product_target_cart_items c
          JOIN secureshop_review.product_target_products p
            ON p.target_id=c.target_id AND p.product_id=c.product_id
          LEFT JOIN secureshop_review.product_target_listing_overlays o
            ON o.target_id=p.target_id AND o.product_id=p.product_id
          WHERE c.target_id=$1 AND c.shop_user_id=$2
          ORDER BY c.cart_item_id FOR UPDATE OF c`,
        [value.targetId, owner])).rows;
        if (!rows.length) return rejectCart(EMPTY_CART_REJECTED);
        if (rows.some(row => row.archived)) return rejectCart(CART_STOCK_REJECTED);
        if (couponRepository && !require('./secureshopOwnedStock').stockAvailable(stock, rows)) return rejectCart(CART_STOCK_REJECTED);
        const coupon=couponRepository?await couponRepository.currentWithClient(client,value.targetId,owner,mode):null;
        const quote=require('../../services/secureshopCouponContract').money(rows.map(row=>cents(row.price)*Number(row.quantity)),coupon?.discount_percent||0);
        const total = quote.totalCents / 100;
        if(couponRepository)await require('./secureshopOwnedStock').consumeStock(client,value.targetId,stock,rows);
        const header = (await client.query(couponRepository?`INSERT INTO secureshop_review.product_target_orders
          (target_id,shop_user_id,total_amount,payment_method,shipping_address,subtotal_amount,discount_amount,coupon_code,coupon_percent)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING order_id`:`INSERT INTO secureshop_review.product_target_orders
          (target_id,shop_user_id,total_amount,payment_method,shipping_address)
          VALUES($1,$2,$3,$4,$5) RETURNING order_id`,
        [value.targetId, owner, total, payment, shipping,...(couponRepository?[quote.subtotalCents/100,quote.discountCents/100,coupon?.code||null,coupon?.discount_percent??null]:[])])).rows[0];
        for (const [index,row] of rows.entries()) {
          await client.query(couponRepository?`INSERT INTO secureshop_review.product_target_order_items
            (target_id,order_id,product_id,product_name,quantity,price,discount_amount) VALUES($1,$2,$3,$4,$5,$6,$7)`:`INSERT INTO secureshop_review.product_target_order_items
            (target_id,order_id,product_id,product_name,quantity,price) VALUES($1,$2,$3,$4,$5,$6)`,
          [value.targetId, header.order_id, row.product_id, row.name, row.quantity, row.price,...(couponRepository?[quote.lineDiscountCents[index]/100]:[])]);
        }
        const removed = await client.query(`DELETE FROM secureshop_review.product_target_cart_items
          WHERE target_id=$1 AND shop_user_id=$2`, [value.targetId, owner]);
        if (removed.rowCount !== rows.length) throw new Error('cart changed during checkout');
        await audit(client, value, owner, 'checkout', header.order_id, { total, shippingAddress: shipping, paymentMethod: payment });
        const result=Object.freeze({orderId:Number(header.order_id),total,...(couponRepository?{subtotal:quote.subtotalCents/100,discount:quote.discountCents/100}: {})});
        if(couponRepository)await couponRepository.finishCheckoutWithClient(client,checkoutContext,result);
        return result;
  }
  const checkoutHistory = require('./secureshopCheckoutHistoryRepository').createCheckoutHistoryRepository({ pool, checkCurrent });
  const conversation = require('./secureshopConversationalCommerceRepository').createConversationalCommerceRepository({
    guarded, listCartWithClient, addCartWithClient, updateCartWithClient, removeCartWithClient, checkoutWithClient,
    durableCheckout: !!couponRepository, couponRepository, auditStore,
  });
  return Object.freeze({
    conversation,
    checkoutHistory: checkoutHistory.list,
    checkoutReceipt: checkoutHistory.read,
    importGuestCart(input, { shopUserId, requestId, items, personaSession }) {
      const owner = integer(shopUserId, 'shopUserId');
      if (typeof requestId !== 'string' || !UUID.test(requestId)) fail('requestId is invalid');
      const operationId = requestId.toLowerCase();
      const lines = importItems(items);
      const intentJson = JSON.stringify(lines);
      const intentSha256 = sha256(intentJson);
      if (typeof personaSession?.sessionId !== 'string' || !UUID.test(personaSession.sessionId)
          || typeof personaSession?.authorityVersion !== 'string'
          || !/^[1-9]\d*$/.test(personaSession.authorityVersion)) fail('personaSession is invalid');
      return guarded(input, async (client, value) => {
        // This lock serializes one request ID even when submitted by two owners.
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))',
          [`guest-cart-import:${operationId}`]);
        const prior = (await client.query(`SELECT target_id,shop_user_id,intent_sha256,state,result_json,result_sha256
          FROM secureshop_review.guest_cart_imports WHERE request_id=$1`, [operationId])).rows[0];
        if (prior) {
          if (prior.state !== 'completed' || prior.target_id !== value.targetId
              || Number(prior.shop_user_id) !== owner || prior.intent_sha256 !== intentSha256
              || sha256(prior.result_json || '') !== prior.result_sha256) {
            throw Object.assign(new Error('Guest cart import request conflicts'), { code: 'CART_IMPORT_CONFLICT' });
          }
          return Object.freeze({ ...JSON.parse(prior.result_json), replayed: true });
        }
        await lockCart(client, value.targetId, owner);
        const ids = lines.map(row => row.productId);
        // Checkout stock writers use this lock namespace. The target SHARE lock
        // excludes listing publishers while prices and listing state are read.
        for (const id of ids) await client.query(
          'SELECT pg_advisory_xact_lock(hashtextextended($1::text,$2::bigint))',
          [`stock:${value.targetId}`, id]);
        const productRows = (await client.query(`SELECT p.product_id,
            CASE WHEN o.product_id IS NULL THEN p.name ELSE o.name END AS name,
            CASE WHEN o.product_id IS NULL THEN p.price ELSE o.price END AS price,
            CASE WHEN o.product_id IS NULL THEN p.stock_quantity ELSE o.stock_quantity END AS stock_quantity,
            CASE WHEN o.product_id IS NULL THEN p.status ELSE o.status END AS status,
            (o.archived_at IS NOT NULL) AS archived
          FROM secureshop_review.product_target_products p
          LEFT JOIN secureshop_review.product_target_listing_overlays o
            ON o.target_id=p.target_id AND o.product_id=p.product_id
          WHERE p.target_id=$1 AND p.product_id=ANY($2::integer[]) ORDER BY p.product_id`,
        [value.targetId, ids])).rows;
        const products = new Map(productRows.map(row => [Number(row.product_id), row]));
        const existingRows = (await client.query(`SELECT product_id,quantity
          FROM secureshop_review.product_target_cart_items
          WHERE target_id=$1 AND shop_user_id=$2 AND product_id=ANY($3::integer[])
          ORDER BY product_id FOR UPDATE`, [value.targetId, owner, ids])).rows;
        const existing = new Map(existingRows.map(row => [Number(row.product_id), Number(row.quantity)]));
        const issues = [];
        for (const line of lines) {
          const product = products.get(line.productId);
          if (!product || product.archived || product.status !== 'active') {
            issues.push({ productId: line.productId, code: 'UNAVAILABLE' });
          } else if ((existing.get(line.productId) || 0) + line.quantity > 99) {
            issues.push({ productId: line.productId, code: 'CART_QUANTITY_LIMIT' });
          } else if (Number(product.stock_quantity) < (existing.get(line.productId) || 0) + line.quantity) {
            issues.push({ productId: line.productId, code: 'INSUFFICIENT_STOCK',
              availableQuantity: Math.max(0, Number(product.stock_quantity)) });
          } else {
            cents(product.price); // Fail closed on an invalid authoritative price.
          }
        }
        if (issues.length) return Object.freeze({ requestId: operationId, imported: false,
          replayed: false, issues: Object.freeze(issues) });
        const receiptLines = [];
        let subtotalCents = 0;
        for (const line of lines) {
          const product = products.get(line.productId);
          const priceCents = cents(product.price);
          subtotalCents += priceCents * line.quantity;
          await client.query(`INSERT INTO secureshop_review.product_target_cart_items
            (target_id,shop_user_id,product_id,quantity) VALUES($1,$2,$3,$4)
            ON CONFLICT (target_id,shop_user_id,product_id)
            DO UPDATE SET quantity=secureshop_review.product_target_cart_items.quantity+EXCLUDED.quantity`,
          [value.targetId, owner, line.productId, line.quantity]);
          receiptLines.push(Object.freeze({ productId: line.productId, quantity: line.quantity,
            price: priceCents / 100, name: product.name }));
        }
        if (!Number.isSafeInteger(subtotalCents)) throw new Error('import subtotal unavailable');
        const receipt = Object.freeze({ requestId: operationId, imported: true,
          replayed: false, items: Object.freeze(receiptLines), subtotal: subtotalCents / 100 });
        const resultJson = JSON.stringify(receipt);
        const executionJson = JSON.stringify({ scope: executionScope(value),
          personaSession: { sessionId: personaSession.sessionId.toLowerCase(),
            authorityVersion: personaSession.authorityVersion } });
        await client.query(`INSERT INTO secureshop_review.guest_cart_imports
          (request_id,target_id,shop_user_id,intent_sha256,execution_json,request_json,result_json,result_sha256)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
        [operationId, value.targetId, owner, intentSha256, executionJson, intentJson,
          resultJson, sha256(resultJson)]);
        await audit(client, value, owner, 'cart_import', value.targetId,
          { requestId: operationId, items: lines, subtotal: receipt.subtotal });
        return receipt;
      });
    },
    // A single SQL snapshot selects only lines belonging to this merchant.
    // No checkout-wide total, customer identifier, address or payment is read.
    listMerchantOrders(input, merchantId, cursor, productName) {
      const merchant = integer(merchantId, 'merchantId');
      const name = normalizeOrderProductName(productName);
      return guarded(input, (client, value) => merchantOrdersWithClient(client, value, merchant, null, cursor, name));
    },
    getMerchantOrder(input, { merchantId, orderId }) {
      const merchant = integer(merchantId, 'merchantId'), id = integer(orderId, 'orderId');
      return guarded(input, async (client, value) => (await merchantOrdersWithClient(client, value, merchant, id)).orders[0] || null);
    },
    merchantOverview(input, merchantId, window, topLimit = 8) {
      const merchant = integer(merchantId, 'merchantId');
      integer(topLimit, 'topLimit', 1, 50);
      if (!window || !['cutoff', 'previousCutoff', 'until'].every(key =>
        typeof window[key] === 'string' && Number.isFinite(Date.parse(window[key])))
        || !(Date.parse(window.previousCutoff) < Date.parse(window.cutoff)
          && Date.parse(window.cutoff) < Date.parse(window.until))) fail('reporting window is invalid');
      return guarded(input, async (client, value) => {
        // One SQL snapshot keeps totals, per-day counts and top product aligned.
        // Merchant ownership is immutable on the launch's base product records;
        // archived listings retain their historical order-line attribution.
        const { rows } = await client.query(`WITH lines AS (
          SELECT o.order_id,o.order_date,oi.product_id,oi.product_name,
            oi.quantity * oi.price - COALESCE((to_jsonb(oi)->>'discount_amount')::numeric,0) AS revenue
          FROM secureshop_review.product_target_orders o
          JOIN secureshop_review.product_target_order_items oi
            ON oi.target_id=o.target_id AND oi.order_id=o.order_id
          JOIN secureshop_review.product_target_products p
            ON p.target_id=oi.target_id AND p.product_id=oi.product_id
          WHERE o.target_id=$1 AND p.retailer_id=$2 AND o.order_date >= $4::timestamptz
            AND o.order_date < $5::timestamptz AND o.status <> 'cancelled'
            AND o.payment_status NOT IN ('declined','refunded')
        ), current_lines AS (SELECT * FROM lines WHERE order_date >= $3::timestamptz),
        previous_lines AS (SELECT * FROM lines WHERE order_date < $3::timestamptz),
        daily AS (SELECT to_char(order_date AT TIME ZONE 'UTC','YYYY-MM-DD') AS day,
          sum(revenue) AS revenue,count(DISTINCT order_id)::integer AS orders
          FROM current_lines GROUP BY day),
        top_products AS (SELECT product_id AS id,min(product_name) AS name,sum(revenue) AS revenue
          FROM current_lines GROUP BY product_id ORDER BY revenue DESC,product_id LIMIT $6),
        top_product AS (SELECT * FROM top_products ORDER BY revenue DESC,id LIMIT 1)
        SELECT (SELECT jsonb_build_object('revenue',COALESCE(sum(revenue),0),
          'orders',count(DISTINCT order_id)) FROM current_lines) AS current,
          (SELECT jsonb_build_object('revenue',COALESCE(sum(revenue),0),
          'orders',count(DISTINCT order_id)) FROM previous_lines) AS previous,
          COALESCE((SELECT jsonb_agg(to_jsonb(daily) ORDER BY day) FROM daily),'[]'::jsonb) AS days,
          (SELECT to_jsonb(top_product) FROM top_product) AS top,
          COALESCE((SELECT jsonb_agg(to_jsonb(top_products) ORDER BY revenue DESC,id)
            FROM top_products),'[]'::jsonb) AS products`,
        [value.targetId, merchant, window.cutoff, window.previousCutoff, window.until, topLimit]);
        return rows[0];
      });
    },
    recommendations(input, shopUserId) {
      const owner = integer(shopUserId, 'shopUserId');
      return guarded(input, async (client, value) => {
        // Every signal is confined to this launch target and authenticated customer.
        // This deterministic read is not a model decision or cross-customer profiling.
        const rows = (await client.query(`WITH effective AS (
          SELECT p.product_id,
            CASE WHEN o.product_id IS NULL THEN p.name ELSE o.name END AS name,
            CASE WHEN o.product_id IS NULL THEN p.price ELSE o.price END AS price,
            CASE WHEN o.product_id IS NULL THEN p.category ELSE o.category END AS category,
            CASE WHEN o.product_id IS NULL THEN p.image_url ELSE o.image_url END AS image_url,
            CASE WHEN o.product_id IS NULL THEN p.stock_quantity ELSE o.stock_quantity END AS stock_quantity,
            CASE WHEN o.product_id IS NULL THEN p.status ELSE o.status END AS status,
            o.archived_at
          FROM secureshop_review.product_target_products p
          LEFT JOIN secureshop_review.product_target_listing_overlays o
            ON o.target_id=p.target_id AND o.product_id=p.product_id
          WHERE p.target_id=$1
        ), signals AS (
          SELECT c.product_id, 1 AS weight FROM secureshop_review.product_target_cart_items c
            WHERE c.target_id=$1 AND c.shop_user_id=$2
          UNION ALL
          SELECT DISTINCT i.product_id, 2 AS weight
            FROM secureshop_review.product_target_order_items i
            JOIN secureshop_review.product_target_orders h
              ON h.target_id=i.target_id AND h.order_id=i.order_id
            WHERE h.target_id=$1 AND h.shop_user_id=$2
              AND h.status <> 'cancelled' AND h.payment_status='approved'
        ), affinity AS (
          SELECT e.category, sum(s.weight) AS score FROM signals s
            JOIN effective e ON e.product_id=s.product_id GROUP BY e.category
        ) SELECT e.product_id AS id,e.name,e.price,e.category,e.image_url,
            COALESCE(a.score,0)::text AS affinity_score
          FROM effective e LEFT JOIN affinity a ON a.category=e.category
          WHERE e.archived_at IS NULL AND e.status='active' AND e.stock_quantity>0
            AND NOT EXISTS (SELECT 1 FROM secureshop_review.product_target_cart_items c
              WHERE c.target_id=$1 AND c.shop_user_id=$2 AND c.product_id=e.product_id)
          ORDER BY COALESCE(a.score,0) DESC,e.product_id ASC LIMIT 6`,
        [value.targetId, owner])).rows;
        return Object.freeze({ feed: Object.freeze(rows.map(row => Object.freeze({
          id: Number(row.id), name: row.name, price: Number(row.price),
          category: row.category, image_url: row.image_url,
          recommendation_reason: Number(row.affinity_score) > 0 ? 'owned_category_affinity' : 'catalog_fallback',
        }))), provenance: Object.freeze({ algorithm: 'local-category-affinity-v1',
          modelUsed: false, scope: 'launch_customer',
          signals: ['approved_non_cancelled_purchases', 'current_cart'],
          weights: { purchasedProduct: 2, cartProduct: 1 }, tieBreak: 'product_id_ascending' }) });
      });
    },
    adminSummary(input) {
      return guarded(input, async (client, value) => {
        const row = (await client.query(`SELECT
          (SELECT count(*)::integer FROM secureshop_review.product_target_products WHERE target_id=$1) AS total_products,
          count(*)::integer AS total_orders, COALESCE(sum(total_amount),0)::text AS total_revenue
          FROM secureshop_review.product_target_orders WHERE target_id=$1`, [value.targetId])).rows[0];
        const revenue = Number(row.total_revenue);
        if (!Number.isFinite(revenue) || revenue < 0) throw new Error('Invalid stored order totals');
        return Object.freeze({ total_products: row.total_products, total_orders: row.total_orders,
          total_revenue: revenue, revenue_basis: 'gross_order_total' });
      });
    },
    listCart(input, shopUserId,mode='vuln') {
      const owner = integer(shopUserId, 'shopUserId');
      return guarded(input, (client, value) => listCartWithClient(client, value, owner, mode));
    },
    addCart(input, { shopUserId, productId, quantity }) {
      const owner = integer(shopUserId, 'shopUserId');
      const product = integer(productId, 'productId');
      const requested = integer(quantity, 'quantity', 1, 99);
      return guarded(input, (client, value) => addCartWithClient(client, value, owner, product, requested));
    },
    updateCart(input, { shopUserId, cartItemId, quantity }) {
      const owner = integer(shopUserId, 'shopUserId');
      const id = integer(cartItemId, 'cartItemId');
      const requested = integer(quantity, 'quantity', 1, 99);
      return guarded(input, (client, value) => updateCartWithClient(client, value, owner, id, requested));
    },
    removeCart(input, { shopUserId, cartItemId }) {
      const owner = integer(shopUserId, 'shopUserId');
      const id = integer(cartItemId, 'cartItemId');
      return guarded(input, (client, value) => removeCartWithClient(client, value, owner, id));
    },
    checkout(input, { shopUserId, shippingAddress, paymentMethod,operationId,persona,personaSession,mode='vuln' }) {
      const owner = integer(shopUserId, 'shopUserId');
      if(couponRepository&&persona?.id!==owner)fail('checkout owner mismatch');
      const shipping = text(shippingAddress, 'shippingAddress', 4096);
      const payment = text(paymentMethod, 'paymentMethod', 256);
      return guarded(input, (client, value) => checkoutWithClient(client, value, owner, shipping, payment, operationId, persona, personaSession, mode));
    },
    listOrders(input, shopUserId, productName) {
      const owner = integer(shopUserId, 'shopUserId');
      const name = normalizeOrderProductName(productName);
      return guarded(input, async (client, value) => Object.freeze((await client.query(`SELECT *
        FROM secureshop_review.product_target_orders WHERE target_id=$1 AND shop_user_id=$2
        ${name === undefined ? '' : `AND EXISTS (SELECT 1 FROM secureshop_review.product_target_order_items oi
          WHERE oi.target_id=product_target_orders.target_id AND oi.order_id=product_target_orders.order_id
            AND strpos(lower(oi.product_name),lower($3::text)) > 0)`}
        ORDER BY order_date DESC,order_id DESC`, [value.targetId, owner,
          ...(name === undefined ? [] : [name])])).rows.map(order)));
    },
    getOrder(input, { shopUserId, orderId }) {
      const owner = integer(shopUserId, 'shopUserId');
      const id = integer(orderId, 'orderId');
      return guarded(input, async (client, value) => {
        const row = (await client.query(`SELECT * FROM secureshop_review.product_target_orders
          WHERE target_id=$1 AND shop_user_id=$2 AND order_id=$3`,
        [value.targetId, owner, id])).rows[0];
        if (!row) return null;
        const items = (await client.query(`SELECT order_item_id AS id,product_id,quantity,price,
            product_name AS name,COALESCE((to_jsonb(product_target_order_items)->>'discount_amount')::numeric,0) AS discount_amount FROM secureshop_review.product_target_order_items
          WHERE target_id=$1 AND order_id=$2 ORDER BY order_item_id`,
        [value.targetId, id])).rows.map(item => Object.freeze({
          ...item, id: Number(item.id), product_id: Number(item.product_id),
          quantity: Number(item.quantity), price: Number(item.price),
          discount_amount:Number(item.discount_amount||0),total_amount:(cents(item.price)*Number(item.quantity)-cents(item.discount_amount||0))/100,
        }));
        return Object.freeze({ order: order(row), items: Object.freeze(items) });
      });
    },
  });
}

module.exports = { createSecureShopBoundCommerceRepository, normalizeOrderProductName, CART_QUANTITY_LIMIT_REJECTED, EMPTY_CART_REJECTED, CART_STOCK_REJECTED };
