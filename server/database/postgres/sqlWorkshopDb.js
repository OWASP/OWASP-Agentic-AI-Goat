'use strict';
const { randomUUID } = require('node:crypto');
const { createPool, withTransaction } = require('./index');
const { helpers, singleton, initialize } = require('./workshopSupport');
const fixtures = require('../../../db/postgres/sqlWorkshopFixtures');
function deletionOwner(value) { const id=String(value);if(!/^[1-9][0-9]{0,9}$/.test(id)||Number(id)>2147483647)throw new TypeError('Valid platform owner required');return id; }

async function seed(client) {
  if ((await client.query("SELECT version FROM aria.seed_state WHERE version=1")).rowCount) return;
  for (const p of fixtures.PRODUCTS) await client.query('INSERT INTO aria.products (product_id,name,category,price,description,stock) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (product_id) DO NOTHING', [p.product_id,p.name,p.category,p.price,p.description,p.stock]);
  for (const o of fixtures.ORDERS) await client.query('INSERT INTO aria.orders (order_number,user_id,product_name,quantity,unit_price,total_amount,shipping_address,status,payment_method,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (order_number) DO NOTHING', [o.order_number,o.user_id,o.product_name,o.quantity,o.unit_price,o.total_amount,o.shipping_address,o.status,o.payment_method,o.created_at+'Z']);
  for (const r of fixtures.RECEIPTS) await client.query('INSERT INTO aria.receipts (order_number,receipt_number,amount,payment_method,issued_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (receipt_number) DO NOTHING', [r.order_number,r.receipt_number,r.amount,r.payment_method,r.issued_at+'Z']);
  // Demo cart is initial-only: do not replenish it after checkout on each server restart.
  {
    for (const c of fixtures.CART) await client.query('INSERT INTO aria.cart (user_id,product_name,quantity,unit_price) VALUES ($1,$2,$3,$4) ON CONFLICT (user_id,product_name) DO NOTHING', [c.user_id,c.product_name,c.quantity,c.unit_price]);
    await client.query('INSERT INTO aria.seed_state (version) VALUES (1)');
  }
}

function createSqlWorkshopDb(pool) {
  const { all, get, run } = helpers(pool);
  // Serialize a user's cart/checkout mutations on one transaction connection.
  const mutate = (userId, work) => withTransaction(pool, async client => {
    await client.query('SELECT pg_advisory_xact_lock(1886610805, hashtext($1))', [String(userId)]);
    return work(helpers(client));
  });
  const api = {
    async initializeSqlWorkshopDb(migrationPool) {
      const owned = !migrationPool;
      migrationPool ||= createPool(process.env, 'SQL_WORKSHOP_MIGRATION_DATABASE_URL');
      try { await initialize(pool, migrationPool, 'aria', seed); }
      finally { if (owned) await migrationPool.end(); }
    },
    lookupOrder: (orderNumber,userId) => all('SELECT * FROM aria.orders WHERE order_number=$1 AND user_id=$2', [orderNumber,userId]),
    listOrders: userId => all('SELECT * FROM aria.orders WHERE user_id=$1 ORDER BY created_at DESC,id DESC', [userId]),
    getReceipt: (orderNumber,userId) => all('SELECT o.order_number,o.product_name,o.total_amount,o.status,r.receipt_number,r.amount,r.payment_method,r.issued_at FROM aria.orders o LEFT JOIN aria.receipts r ON o.order_number=r.order_number WHERE o.order_number=$1 AND o.user_id=$2', [orderNumber,userId]),
    searchProducts(searchTerm,maxPrice,mode='fixed') {
      if (!searchTerm || !searchTerm.trim()) return maxPrice == null
        ? all('SELECT * FROM aria.products WHERE available=1 ORDER BY category,name')
        : all('SELECT * FROM aria.products WHERE price <= $1 AND available=1 ORDER BY category,name', [maxPrice]);
      // Intentional teaching sink: raw UNION/boolean SQL injection, confined to the lab database role.
      if (mode === 'vuln') return pool.query({ text: `SELECT id,product_id,name,category,price,description,stock,available FROM aria.products WHERE name LIKE '%${searchTerm}%'`, queryMode: 'extended' }).then(result => result.rows);
      const pattern = `%${searchTerm.toLowerCase()}%`;
      return all('SELECT * FROM aria.products WHERE (LOWER(name) LIKE $1 OR LOWER(category) LIKE $1 OR LOWER(description) LIKE $1) AND available=1'+(maxPrice == null ? '' : ' AND price <= $2'), maxPrice == null ? [pattern] : [pattern,maxPrice]);
    },
    viewCart: userId => all('SELECT * FROM aria.cart WHERE user_id=$1 ORDER BY added_at DESC,id DESC', [userId]),
    addToCart(userId,productName,quantity=1) {
      return mutate(userId, async db => {
        const product = await db.get('SELECT * FROM aria.products WHERE LOWER(name) LIKE $1 AND available=1 ORDER BY id LIMIT 1', [`%${productName.toLowerCase()}%`]);
        if (!product) return { success:false,message:`Product not found: ${productName}` };
        await db.run('INSERT INTO aria.cart (user_id,product_name,quantity,unit_price) VALUES ($1,$2,$3,$4) ON CONFLICT (user_id,product_name) DO UPDATE SET quantity=aria.cart.quantity+EXCLUDED.quantity', [userId,product.name,quantity,product.price]);
        return { success:true,product,quantity };
      });
    },
    removeFromCart: (userId,productName) => mutate(userId, async db => {
      const result=await db.run('DELETE FROM aria.cart WHERE user_id=$1 AND LOWER(product_name) LIKE $2', [userId,`%${productName.toLowerCase()}%`]);
      return { success:result.changes>0,removed:result.changes };
    }),
    checkout: (userId,shippingAddress) => mutate(userId, async db => {
      const items=await db.all('SELECT * FROM aria.cart WHERE user_id=$1 ORDER BY id FOR UPDATE', [userId]);
      if (!items.length) return { success:false,message:'Your cart is empty.' };
      const orders=[];
      for (const item of items) {
        const orderNumber=`ORD-${new Date().getUTCFullYear()}-${BigInt("0x"+randomUUID().replace(/-/g,""))}`;
        const receiptNumber=`RCP-${randomUUID()}`;
        const total=(item.unit_price*item.quantity).toFixed(2);
        await db.run("INSERT INTO aria.orders (order_number,user_id,product_name,quantity,unit_price,total_amount,shipping_address,status,payment_method) VALUES ($1,$2,$3,$4,$5,$6,$7,'processing','credit_card')", [orderNumber,userId,item.product_name,item.quantity,item.unit_price,total,shippingAddress]);
        await db.run("INSERT INTO aria.receipts (order_number,receipt_number,amount,payment_method) VALUES ($1,$2,$3,'credit_card')", [orderNumber,receiptNumber,total]);
        orders.push({ orderNumber,total,receiptNumber });
      }
      await db.run('DELETE FROM aria.cart WHERE user_id=$1', [userId]);
      return { success:true,orders,itemsOrdered:items.length };
    }),
    returnRefund: (orderNumber,userId) => mutate(userId, async db => {
      const order=await db.get('SELECT * FROM aria.orders WHERE order_number=$1 AND user_id=$2 FOR UPDATE', [orderNumber,userId]);
      if (!order) return { success:false,message:`Order ${orderNumber} not found.` };
      if (order.status==='refunded') return { success:false,message:'Order already refunded.' };
      await db.run("UPDATE aria.orders SET status='refunded' WHERE order_number=$1 AND user_id=$2", [orderNumber,userId]);
      return { success:true,orderNumber,refundAmount:order.total_amount };
    }),
    updateAddress: (orderNumber,userId,newAddress) => mutate(userId, async db => {
      const order=await db.get('SELECT * FROM aria.orders WHERE order_number=$1 AND user_id=$2 FOR UPDATE', [orderNumber,userId]);
      if (!order) return { success:false,message:`Order ${orderNumber} not found.` };
      if (['delivered','refunded'].includes(order.status)) return { success:false,message:`Cannot update address — order is already ${order.status}.` };
      await db.run('UPDATE aria.orders SET shipping_address=$1 WHERE order_number=$2 AND user_id=$3', [newAddress,orderNumber,userId]);
      return { success:true,orderNumber,newAddress };
    }),
    getOrderStatus: async (orderNumber,userId) => (await get('SELECT order_number,product_name,quantity,total_amount,status,shipping_address,created_at FROM aria.orders WHERE order_number=$1 AND user_id=$2', [orderNumber,userId])) ?? null,
    saveMessage: (userId,messageType,message) => run('INSERT INTO aria.chat_history (user_id,message_type,message) VALUES ($1,$2,$3) RETURNING id', [userId,messageType,message]),
    getHistory: async (userId,limit=20) => (await all('SELECT message_type,message FROM aria.chat_history WHERE user_id=$1 ORDER BY id DESC LIMIT $2', [userId,limit])).reverse(),
    clearHistory: userId => run('DELETE FROM aria.chat_history WHERE user_id=$1', [userId]),
    clearCart: userId => mutate(userId,db=>db.run('DELETE FROM aria.cart WHERE user_id=$1', [userId])),
    destroyOwner(userId) {
      const id=deletionOwner(userId);
      return withTransaction(pool, async client => {
      await client.query('SELECT pg_advisory_xact_lock(1886610805, hashtext($1))', [id]);
      const receipts = await client.query(`DELETE FROM aria.receipts r USING aria.orders o
        WHERE r.order_number=o.order_number AND o.user_id=$1`, [id]);
      const orders = await client.query('DELETE FROM aria.orders WHERE user_id=$1', [id]);
      const cart = await client.query('DELETE FROM aria.cart WHERE user_id=$1', [id]);
      const history = await client.query('DELETE FROM aria.chat_history WHERE user_id=$1', [id]);
        return { removed: receipts.rowCount + orders.rowCount + cart.rowCount + history.rowCount };
      });
    },
  };
  return api;
}
const method=singleton(createSqlWorkshopDb,'SQL_WORKSHOP_DATABASE_URL');
module.exports={ createSqlWorkshopDb,...Object.fromEntries(['initializeSqlWorkshopDb','lookupOrder','listOrders','getReceipt','searchProducts','viewCart','addToCart','removeFromCart','checkout','returnRefund','updateAddress','getOrderStatus','saveMessage','getHistory','clearHistory','clearCart','destroyOwner'].map(name=>[name,method(name)])) };
