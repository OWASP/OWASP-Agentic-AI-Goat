'use strict';
const {withTransaction}=require('./index');
function dto(result){return result.rows.map(row=>Object.fromEntries(Object.entries(row).map(([key,value])=>[key,value!=null&&[20,1700].includes(result.fields.find(field=>field.name===key)?.dataTypeID)?Number(value):value])));}
function createSecureShopCustomerRepository(commerce,agents){
  const all=async(sql,args=[])=>dto(await commerce.query(sql,args));
  const one=async(sql,args)=>(await all(sql,args))[0];
  const cart=owner=>all('SELECT ci.id,ci.product_id,ci.quantity,p.name,p.price,p.description FROM secureshop.cart_items ci LEFT JOIN secureshop.products p ON p.id=ci.product_id WHERE ci.user_id=$1',[owner]);
  return {
    createLegacyUser:(username,email,password,role,name,phone,address)=>one('INSERT INTO secureshop.shop_users(username,email,password,role,full_name,phone,address) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',[username,email,password,role,name,phone,address]),
    findUser:username=>one('SELECT * FROM secureshop.shop_users WHERE username=$1',[username]),
    async browse({category,search,sort,limit,offset}){
      const order={price_asc:'p.price ASC',price_desc:'p.price DESC',newest:'p.created_at DESC',deals:'p.price ASC'}[sort]||'p.id ASC';
      const values=[category,search?`%${search}%`:null];
      const products=await all(`SELECT p.id,p.name,p.description,p.price,p.category,p.image_url,p.stock_quantity,p.status,p.created_at,
        COALESCE(ROUND(AVG(CASE WHEN r.status='approved' THEN r.rating END),2),0) AS avg_rating,
        COALESCE(SUM(CASE WHEN r.status='approved' THEN 1 ELSE 0 END),0) AS review_count
        FROM secureshop.products p LEFT JOIN secureshop.reviews r ON r.product_id=p.id
        WHERE p.status='active' AND ($1::text IS NULL OR p.category=$1) AND ($2::text IS NULL OR p.name LIKE $2 OR p.description LIKE $2)
        GROUP BY p.id ORDER BY ${order} LIMIT $3 OFFSET $4`,[...values,limit,offset]);
      const count=await one("SELECT count(*)::int AS total FROM secureshop.products WHERE status='active' AND ($1::text IS NULL OR category=$1) AND ($2::text IS NULL OR name LIKE $2 OR description LIKE $2)",values);
      return{products,count:products.length,total:count.total};
    },
    async product(id){
      const product=await one('SELECT id,name,description,description_html,price,category,image_url,stock_quantity,status FROM secureshop.products WHERE id=$1',[id]);
      if(!product)return null;
      Object.assign(product,await one("SELECT COALESCE(ROUND(AVG(CASE WHEN status='approved' THEN rating END),2),0) AS avg_rating,COALESCE(SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END),0) AS review_count FROM secureshop.reviews WHERE product_id=$1",[id]));
      product.images=(await all('SELECT path FROM secureshop.product_images WHERE product_id=$1 ORDER BY id',[id])).map(row=>row.path).filter(Boolean);
      if(!product.images.length&&product.image_url)product.images.push(product.image_url);
      const reviews=await all('SELECT id,body,rating,status,moderator_kind,created_at FROM secureshop.reviews WHERE product_id=$1 ORDER BY created_at DESC,id DESC LIMIT 20',[id]);
      return{product,reviews};
    },
    async reviews(id,limit,offset){return{reviews:await all('SELECT r.id,r.body,r.rating,r.status,r.moderator_kind,r.created_at,u.username AS author_name FROM secureshop.reviews r LEFT JOIN secureshop.shop_users u ON u.id=r.author_id WHERE r.product_id=$1 ORDER BY r.created_at DESC,r.id DESC LIMIT $2 OFFSET $3',[id,limit,offset]),total:(await one('SELECT count(*)::int AS total FROM secureshop.reviews WHERE product_id=$1',[id])).total};},
    addReview:(id,author,body,rating)=>one("INSERT INTO secureshop.reviews(product_id,author_id,body,rating,status,moderator_kind) VALUES($1,$2,$3,$4,'approved','auto') RETURNING id",[id,author,body,rating]),
    categories:()=>all('SELECT id,name,description FROM secureshop.categories'),
    cart,
    addCart:(owner,product,quantity)=>one('INSERT INTO secureshop.cart_items(user_id,product_id,quantity) VALUES($1,$2,$3) RETURNING id',[owner,product,quantity]),
    updateCart:(id,quantity)=>commerce.query('UPDATE secureshop.cart_items SET quantity=$2 WHERE id=$1',[id,quantity]),
    deleteCart:id=>commerce.query('DELETE FROM secureshop.cart_items WHERE id=$1',[id]),
    // Raw SQL remains at the annotated route. The old prepared read accepted a
    // single SELECT; native extended-protocol read-only execution preserves that.
    coupon:sql=>withTransaction(commerce,async client=>{await client.query('SET TRANSACTION READ ONLY');return dto(await client.query({text:sql,values:[],queryMode:'extended'}))[0];}),
    orders:owner=>all('SELECT id,customer_id,total_amount,status,payment_method,payment_status,shipping_address,order_date,shipped_date,delivered_date FROM secureshop.orders WHERE customer_id=$1 ORDER BY order_date DESC,id DESC LIMIT 50',[owner]),
    async order(id){const order=await one('SELECT * FROM secureshop.orders WHERE id=$1',[id]);if(!order)return null;return{order,items:await all('SELECT oi.id,oi.product_id,oi.quantity,oi.price,p.name,p.image_url FROM secureshop.order_items oi LEFT JOIN secureshop.products p ON p.id=oi.product_id WHERE oi.order_id=$1',[id])};},
    checkout:(owner,address,method)=>withTransaction(commerce,async client=>{
      await client.query('SELECT id FROM secureshop.shop_users WHERE id=$1 FOR UPDATE',[owner]);
      const items=dto(await client.query('SELECT ci.id,ci.product_id,ci.quantity,p.price FROM secureshop.cart_items ci LEFT JOIN secureshop.products p ON p.id=ci.product_id WHERE ci.user_id=$1 FOR UPDATE OF ci',[owner]));
      if(!items.length)return null;
      const total=items.reduce((sum,row)=>sum+Number(row.price||0)*row.quantity,0);
      const order=(await client.query("INSERT INTO secureshop.orders(customer_id,total_amount,status,payment_method,payment_status,shipping_address) VALUES($1,$2,'confirmed',$3,'paid',$4) RETURNING id",[owner,total,method,address])).rows[0];
      for(const item of items)await client.query('INSERT INTO secureshop.order_items(order_id,product_id,quantity,price) VALUES($1,$2,$3,$4)',[order.id,item.product_id,item.quantity,item.price]);
      await client.query('DELETE FROM secureshop.cart_items WHERE user_id=$1 AND id=ANY($2::integer[])',[owner,items.map(row=>row.id)]);
      return{ok:true,order_id:order.id,total};
    }),
    latestTrace:async({userId,role,limit})=>dto(await agents.query(`SELECT t.id,t.session_id,t.step,t.actor,t.kind,t.agent_ns,t.tool_name,t.latency_ms,t.provider,t.ts
      FROM secureshop_agents.agent_trace t
      INNER JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE s.user_id=$1 AND s.role=$2 AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy'
      ORDER BY t.ts DESC,t.id DESC LIMIT $3`,[userId,role,limit])),
    sessionTrace:async id=>dto(await agents.query("SELECT t.id,t.session_id,t.step,t.actor,t.kind,t.agent_ns,t.tool_name,t.params_json,t.result_json,t.latency_ms,t.tokens_in,t.tokens_out,t.provider,t.ts FROM secureshop_agents.agent_trace t INNER JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id WHERE t.session_id=$1 AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy' ORDER BY t.ts,t.id",[id])),
  };
}
module.exports={createSecureShopCustomerRepository};
