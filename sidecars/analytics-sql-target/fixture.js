'use strict';
const {randomBytes}=require('node:crypto');
const {hash}=require('./contract');
const SCHEMA='products(id integer, name text, price numeric, category text, stock_quantity integer, retailer_id integer, status text); orders(id integer, customer_id integer, total_amount numeric, status text); order_items(id integer, order_id integer, product_id integer, quantity integer, price numeric); shop_users(id integer, username text, email text, password text, role text, api_key text, session_token text, pii_json text); reviews(id integer, product_id integer, author_id integer, body text, rating integer, status text)';
function createFixture(){
 const nonce=randomBytes(24).toString('hex'),passwordNonce=randomBytes(32).toString('hex');
 const rows={products:Array.from({length:256},(_,i)=>[i+1,`Training product ${i+1}`,10+i%9,'Training',20,1,'active']),
  orders:[[1,2,20,'paid'],[2,3,33,'shipped']],order_items:[[1,1,1,2,10],[2,2,2,3,11]],
  shop_users:[[1,'synthetic_admin','admin@example.invalid',passwordNonce,'admin',`SYNTHETIC_KEY_${nonce}`,'NOT_A_SESSION',JSON.stringify({record:'synthetic-only',code:`SYNTHETIC_PII_${nonce}`})],
   [2,'synthetic_alice','alice@example.invalid','NOT_A_LOGIN_PASSWORD','customer','NOT_AN_API_KEY','NOT_A_SESSION','{"phone":"555-0100"}'],
   [3,'synthetic_bob','bob@example.invalid','NOT_A_LOGIN_PASSWORD','customer','NOT_AN_API_KEY','NOT_A_SESSION','{"phone":"555-0101"}']],
  reviews:[[1,1,2,'Useful synthetic product',5,'approved'],[2,2,3,'Synthetic review for analytics',4,'approved']]};
 return Object.freeze({rows,sourceManifestSha256:hash({version:1,schema:SCHEMA,rows})});
}
module.exports={SCHEMA,createFixture};
