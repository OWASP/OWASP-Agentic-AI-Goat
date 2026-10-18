'use strict';
const {withTransaction}=require('./index');
function rows(result){return result.rows.map(row=>Object.fromEntries(Object.entries(row).map(([key,value])=>{const field=result.fields.find(f=>f.name===key);return [key,value!==null&&[20,1700].includes(field?.dataTypeID)&&Number.isFinite(Number(value))?Number(value):value];})));}
function createSecureShopCommerceDb(pool){
 const all=async(sql,params=[])=>rows(await pool.query(sql,params));
 const one=async(sql,params)=>(await all(sql,params))[0];
 const run=async(sql,params)=>{const result=await pool.query(sql,params);return{changes:result.rowCount,lastInsertRowid:result.rows[0]?.id};};
 return {
  async readTeachingQuery(sql,kind='all'){
   return withTransaction(pool,async client=>{
    await client.query('SET TRANSACTION READ ONLY');await client.query('SET LOCAL search_path TO secureshop,pg_catalog');
    const result=rows(await client.query({text:sql,values:[],queryMode:'extended'}));return kind==='get'?result[0]:result;
   });
  },
    product_search_personalizedFeed_1: (...params) => all("\n    SELECT id, name, description, price, category, image_url, stock_quantity\n    FROM secureshop.products\n    WHERE status = 'active'\n    ORDER BY RANDOM()\n    LIMIT 12\n  ",params),
    product_search_similar_1: (...params) => one("SELECT id, name, description, category FROM secureshop.products WHERE id = $1",params),
    product_search_similar_2: (...params) => all("SELECT id, name, description, price, category, image_url FROM secureshop.products WHERE status='active' LIMIT 200",params),
    summarizer_summarizeProduct_1: (...params) => one("\n    SELECT id, name, description, price, category, stock_quantity, description_html\n    FROM secureshop.products WHERE id = $1\n  ",params),
    summarizer_summarizeReviews_1: (...params) => all("\n    SELECT id, product_id, author_id, body, rating, status, created_at\n    FROM secureshop.reviews\n    WHERE product_id = $1\n    ORDER BY created_at DESC\n    LIMIT $2\n  ",params),
    price_advisor_priceHistory_1: (...params) => one("SELECT id, name, price FROM secureshop.products WHERE id = $1",params),
    price_advisor_findDeals_2: (...params) => all("\n    SELECT id, name, price, category\n    FROM secureshop.products\n    WHERE ($1::text IS NULL OR category = $2) AND status = 'active'\n    ORDER BY price ASC\n    LIMIT 5\n  ",params),
    price_advisor_compareCompetitor_3: (...params) => one("SELECT id, name, price FROM secureshop.products WHERE id = $1",params),
    cart_add_1: (...params) => run("INSERT INTO secureshop.cart_items (user_id, product_id, quantity) VALUES ($1, $2, $3) RETURNING id",params),
    cart_remove_2: (...params) => run("DELETE FROM secureshop.cart_items WHERE id = $1",params),
    cart_view_3: (...params) => all("\n    SELECT ci.id, ci.product_id, ci.quantity, ci.added_at,\n           p.name, p.price\n    FROM secureshop.cart_items ci LEFT JOIN secureshop.products p ON p.id = ci.product_id\n    WHERE ci.user_id = $1\n  ",params),
    support_openTicket_2: (...params) => run("INSERT INTO secureshop.support_tickets (customer_id, subject, body) VALUES ($1, $2, $3) RETURNING id",params),
    support_refundRequest_3: (...params) => run("INSERT INTO secureshop.support_tickets (customer_id, subject, body, status) VALUES ($1, $2, $3, $4) RETURNING id",params),
    listing_create_1: (...params) => run("\n    INSERT INTO secureshop.products (name, description, description_html, template_source, price, image_url, retailer_id, status, stock_quantity)\n    VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', 0)\n   RETURNING id",params),
    listing_import_bulk_1: (...params) => run("INSERT INTO secureshop.products (name, description, price, status, stock_quantity) VALUES ($1, $2, $3, 'active', 0) RETURNING id",params),
    listing_import_bulk_2: (...params) => run("INSERT INTO secureshop.products (name, description, price, status, stock_quantity) VALUES ($1, $2, $3, 'active', 0) RETURNING id",params),
    listing_optimize_images_1: (...params) => one("SELECT id, name, image_url FROM secureshop.products WHERE id = $1",params),
    inventory_stock_levels_1: (...params) => all("\n    SELECT id, name, stock_quantity, price, retailer_id, status\n    FROM secureshop.products\n    WHERE status = 'active'\n    ORDER BY stock_quantity ASC\n    LIMIT 200\n  ",params),
    inventory_reorder_suggestion_2: (...params) => one("\n    SELECT p.id, p.name, p.stock_quantity, p.price,\n           COALESCE(SUM(oi.quantity), 0) AS units_sold\n    FROM secureshop.products p\n    LEFT JOIN secureshop.order_items oi ON oi.product_id = p.id\n    WHERE p.id = $1\n    GROUP BY p.id\n  ",params),
    inventory_set_stock_3: (...params) => run("UPDATE secureshop.products SET stock_quantity = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",params),
    pricing_strategy__retrievePoisonedDoc_1: (...params) => one("SELECT id, product_id, path, vector_ref FROM secureshop.product_manuals WHERE product_id = $1 LIMIT 1",params),
    pricing_strategy__retrievePoisonedDoc_2: (...params) => one("\n      SELECT id, name, markdown_source\n      FROM secureshop.policies\n      WHERE name LIKE 'competitor%' OR name LIKE 'pricing%' OR name = 'poisoned'\n      ORDER BY updated_at DESC, id DESC\n      LIMIT 1\n    ",params),
    pricing_strategy_suggest_price_3: (...params) => one("SELECT id, name, price, category FROM secureshop.products WHERE id = $1",params),
    pricing_strategy_run_pricing_experiment_4: (...params) => one("SELECT id, name, price FROM secureshop.products WHERE id = $1",params),
    review_moderator_approve_1: (...params) => run("UPDATE secureshop.reviews SET status = 'approved', moderator_kind = 'auto', moderated_at = CURRENT_TIMESTAMP WHERE id = $1",params),
    review_moderator_reject_2: (...params) => run("UPDATE secureshop.reviews SET status = 'rejected', moderator_kind = 'auto', moderator_notes = $1, moderated_at = CURRENT_TIMESTAMP WHERE id = $2",params),
    review_moderator_moderate_pending_3: (...params) => all("SELECT id, product_id, author_id, body, rating, status FROM secureshop.reviews WHERE status = 'pending' ORDER BY id ASC LIMIT $1",params),
    email_send_1: (...params) => run("INSERT INTO secureshop.email_threads (subject, participants_json) VALUES ($1, $2) RETURNING id",params),
    email_send_2: (...params) => run("\n    INSERT INTO secureshop.emails (thread_id, from_addr, to_addr, subject, body_markdown, body_html, headers_raw)\n    VALUES ($1, $2, $3, $4, $5, $6, $7)\n   RETURNING id",params),
    email_read_inbox_3: (...params) => one("SELECT id, email, username FROM secureshop.shop_users WHERE id = $1",params),
    email_read_inbox_4: (...params) => all("\n    SELECT e.id, e.thread_id, e.from_addr, e.to_addr, e.subject, e.body_markdown, e.body_html, e.headers_raw, e.created_at\n    FROM secureshop.emails e\n    WHERE e.to_addr = $1 OR e.to_addr LIKE $2\n    ORDER BY e.created_at DESC, e.id DESC\n    LIMIT 100\n  ",params),
    email_summarize_thread_5: (...params) => all("\n    SELECT id, from_addr, to_addr, subject, body_markdown, body_html, created_at\n    FROM secureshop.emails WHERE thread_id = $1 ORDER BY created_at ASC, id ASC\n  ",params),
    email_auto_reply_6: (...params) => one("\n    SELECT id, from_addr, subject, body_markdown FROM secureshop.emails\n    WHERE thread_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1\n  ",params),
    policy_read_policy_1: (...params) => one("\n      SELECT id, name, markdown_source, injected_into_json, updated_at\n      FROM secureshop.policies WHERE name = $1 LIMIT 1\n    ",params),
    policy_update_policy_2: (...params) => one("SELECT id FROM secureshop.policies WHERE name = $1",params),
    policy_update_policy_3: (...params) => run("UPDATE secureshop.policies SET markdown_source = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",params),
    policy_update_policy_4: (...params) => run("INSERT INTO secureshop.policies (name, markdown_source, injected_into_json) VALUES ($1, $2, '[\"admin\",\"customer\",\"merchant\"]') RETURNING id",params),
    policy_apply_policy_to_agents_5: (...params) => all("SELECT id, name, injected_into_json, updated_at FROM secureshop.policies",params),  listProducts:()=>all('SELECT * FROM secureshop.products ORDER BY id'),
  listReviews:()=>all('SELECT * FROM secureshop.reviews ORDER BY id'),
  listPolicies:()=>all('SELECT * FROM secureshop.policies ORDER BY id'),
  listProductManuals:()=>all('SELECT * FROM secureshop.product_manuals ORDER BY id'),
  getProductManual:id=>one('SELECT * FROM secureshop.product_manuals WHERE id=$1',[id]),
  async updateProduct(id,patch){
   const allowed=new Set(['name','description','description_html','template_source','price','category','image_url','stock_quantity','status']);
   const entries=Object.entries(patch).filter(([key])=>allowed.has(key));if(!entries.length)return{changes:0};
   return run(`UPDATE secureshop.products SET ${entries.map(([key],i)=>key+'=$'+(i+1)).join(',')},updated_at=now() WHERE id=$${entries.length+1}`, [...entries.map(([,value])=>value),id]);
  },
  analyticsTopProducts:limit=>all('SELECT p.id,p.name,p.price,COALESCE(SUM(oi.quantity),0) AS units_sold,COALESCE(SUM(oi.quantity*oi.price),0) AS revenue FROM secureshop.products p LEFT JOIN secureshop.order_items oi ON oi.product_id=p.id GROUP BY p.id ORDER BY revenue DESC LIMIT $1',[limit]),
  analyticsCategories:()=>all('SELECT p.category,COALESCE(SUM(oi.quantity*oi.price),0) AS revenue FROM secureshop.products p LEFT JOIN secureshop.order_items oi ON oi.product_id=p.id GROUP BY p.category ORDER BY revenue DESC'),
  analyticsStatuses:()=>all('SELECT status,COUNT(*) AS orders,SUM(total_amount) AS revenue FROM secureshop.orders GROUP BY status'),
  async userAction(action,args,event){
   const eventId=require('node:crypto').randomUUID();
   const result=await withTransaction(pool,async client=>{
    let result;
    if(action==='lookup')result=rows(await client.query('SELECT id,username,email,role,full_name,password,password AS bcrypt_hash,api_key,session_token,pii_json,banned_at FROM secureshop.shop_users WHERE username=$1 LIMIT 1',[args.username]))[0];
    else{
     const statements={set_role:'UPDATE secureshop.shop_users SET role=$1 WHERE id=$2',reset_password:'UPDATE secureshop.shop_users SET password=$1 WHERE id=$2',ban:'UPDATE secureshop.shop_users SET banned_at=CURRENT_TIMESTAMP WHERE id=$1'};
     if(!statements[action])throw new Error('Unknown user action');
     const query=await client.query(statements[action],action==='ban'?[args.user_id]:[action==='set_role'?args.role:args.password,args.user_id]);result={changes:query.rowCount};
    }
    await client.query('INSERT INTO secureshop.commerce_outbox(event_id,event_json) VALUES($1,$2)',[eventId,{event_id:eventId,...event}]);return result;
   });return{result,eventId};
  },
  async deliverAudit(eventId,appendAudit){
   return withTransaction(pool,async client=>{
    const event=(await client.query('SELECT event_json,delivered_at FROM secureshop.commerce_outbox WHERE event_id=$1 FOR UPDATE',[eventId])).rows[0];
    if(!event||event.delivered_at)return;
    await appendAudit(event.event_json);
    await client.query('UPDATE secureshop.commerce_outbox SET delivered_at=now() WHERE event_id=$1',[eventId]);
   });
  },
  async flushAuditOutbox(appendAudit){for(const event of await all('SELECT event_id FROM secureshop.commerce_outbox WHERE delivered_at IS NULL ORDER BY created_at LIMIT 100'))await this.deliverAudit(event.event_id,appendAudit);},

  upsertPolicy:(name,markdown)=>run(`INSERT INTO secureshop.policies(name,markdown_source,injected_into_json) VALUES($1,$2,'["admin","customer","merchant"]') ON CONFLICT(name) DO UPDATE SET markdown_source=EXCLUDED.markdown_source,updated_at=now()`,[name,markdown]),
  async sendEmail({threadId,subject,from,to,bodyMarkdown,bodyHtml,headersRaw}){
   return withTransaction(pool,async client=>{
    if(!threadId)threadId=(await client.query('INSERT INTO secureshop.email_threads(subject,participants_json) VALUES($1,$2) RETURNING id',[subject,JSON.stringify([from,to])])).rows[0].id;
    const email=(await client.query('INSERT INTO secureshop.emails(thread_id,from_addr,to_addr,subject,body_markdown,body_html,headers_raw) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',[threadId,from,to,subject,bodyMarkdown,bodyHtml,headersRaw])).rows[0];return{threadId,emailId:email.id};
   });
  },
 };
}
let singleton;
function getSecureShopCommerceDb(){return singleton||=(createSecureShopCommerceDb(require('./secureshopPools').getCommercePool()));}
module.exports={createSecureShopCommerceDb,getSecureShopCommerceDb};
