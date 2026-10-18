'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
test('PostgreSQL legacy challenge facade preserves async callback IDs and never imports SQLite',async()=>{
 const original=Module._load,prior=process.env.PLATFORM_DATABASE_ENGINE;process.env.PLATFORM_DATABASE_ENGINE='postgres';
 const file=require.resolve('../server/database/legacyChallengeStore');delete require.cache[file];
 Module._load=function(request,parent,main){
  if(request==='./postgres/legacyChallengeDb')return{saveConversation:async values=>({lastID:17,changes:1}),getVulnerabilitySetting:async()=>({enabled:0})};
  if(request==='./init'||request==='sqlite3'||request==='better-sqlite3'||/\/authDb$/.test(request))throw Error('Working database import forbidden');
  return original.call(this,request,parent,main);
 };
 try{const store=require(file);await new Promise((resolve,reject)=>store.saveConversation([1,'p','r','fixture'],function(error,result){try{assert.ifError(error);assert.equal(this.lastID,17);assert.equal(result.changes,1);resolve();}catch(e){reject(e);}}));assert.deepEqual(await store.getVulnerabilitySetting('xss'),{enabled:0});}
 finally{Module._load=original;delete require.cache[file];if(prior===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=prior;}
});

test('classic commerce mutations keep vulnerable local IDs while recording only server-session platform provenance',async()=>{
 const original=Module._load,express=require('express'),writes=[],prior=process.env.LEGACY_PLATFORM_LIFECYCLE_ENABLED;process.env.LEGACY_PLATFORM_LIFECYCLE_ENABLED='true';
 const store={engine:'postgres',addReview(sql,cb){writes.push(sql);cb.call({lastID:1},null);},addCart(sql,cb){writes.push(sql);cb.call({},null);},createOrder(sql,cb){writes.push(sql);cb.call({lastID:7},null);},moveOrderItems(sql,cb){writes.push(sql);cb(null);},clearCart(sql,cb){writes.push(sql);cb(null);}};
 Module._load=function(request,parent,main){if(request.endsWith('/legacyChallengeStore'))return store;if(request.endsWith('/logger'))return{error(){}};if(request.endsWith('/legacyPlatformMutationLifecycle'))return{legacyPlatformMutationMiddleware(req,_res,next){req.legacyPlatformMutation={ownerId:req.session.platformOwnerId};next();}};return original.call(this,request,parent,main);};
 const file=require.resolve('../server/routes/ecommerce');delete require.cache[file];let server;
 try{
  const app=express();app.use(express.json());app.use((req,_res,next)=>{req.session={userId:2,platformOwnerId:41};next();});app.use('/',require(file));
  server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});const base=`http://127.0.0.1:${server.address().port}`;
  for(const [url,body] of [['/product/1/review',{rating:5,comment:'raw'}],['/cart/add',{product_id:1}],['/checkout',{payment_method:'raw',shipping_address:'raw'}]])assert.equal((await fetch(base+url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...body,platformOwnerId:999})})).status,200);
  assert.match(writes[0],/platform_owner_id[\s\S]*VALUES \(1, 2, 5, 'raw', 41\)/);assert.match(writes[1],/platform_owner_id[\s\S]*VALUES \(2, 1, 1, 41\)/);assert.match(writes[2],/platform_owner_id[\s\S]*'pending', 41\)/);
  assert.equal(writes.some(sql=>sql.includes('999')),false,'request body cannot select deletion provenance');
 }finally{if(server)await new Promise(resolve=>server.close(resolve));Module._load=original;delete require.cache[file];if(prior===undefined)delete process.env.LEGACY_PLATFORM_LIFECYCLE_ENABLED;else process.env.LEGACY_PLATFORM_LIFECYCLE_ENABLED=prior;}
});

test('mounted generic challenge routers preserve product, IDOR and raw HTML response contracts',async()=>{
 const original=Module._load;const express=require('express');const calls=[];
 const store={engine:'postgres',getVulnerabilitySetting:(key,cb)=>cb(null,{enabled:1}),searchCommerceProducts:(sql,params,cb)=>{calls.push({sql,params});cb(null,[{id:1,name:'demo'}]);},readDemoUser:(sql,cb)=>{calls.push({sql});cb(null,{id:2,username:'other'});}};
 Module._load=function(request,parent,main){
  if(request.endsWith('/legacyChallengeStore'))return store;
  // These public teaching routes must not invoke platform authentication.
  // Session-disclosure authentication has its own mounted/native qualification.
  if(request.endsWith('/middleware/adminAuth'))return{authenticateToken:()=>{throw Error('Unexpected platform authentication');}};
  if(request.endsWith('/logger'))return{error:()=>{}};
  if(request==='sqlite3'||request==='better-sqlite3'||request.endsWith('/database/init')||/\/authDb$/.test(request))throw Error('Working database forbidden');
  return original.call(this,request,parent,main);
 };
 const files=['../server/routes/ecommerce','../server/routes/vulnerabilities','../server/middleware/workshopMode'].map(require.resolve);files.forEach(f=>delete require.cache[f]);
 let server;
 try{
  const app=express();app.use((req,res,next)=>{req.session={};next();});app.use('/commerce',require(files[0]));app.use('/vulns',require(files[1]));
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base=`http://127.0.0.1:${server.address().port}`;
  const product=await (await fetch(base+'/commerce/products?search=raw&category=Electronics')).json();assert.equal(product.products[0].name,'demo');assert.match(calls[0].sql,/category = \$1/);assert.deepEqual(calls[0].params,['Electronics']);
  const idor=await (await fetch(base+'/vulns/idor/user/2')).json();assert.equal(idor.user.username,'other');
  const raw='<img src=x onerror=alert(1)>';const html=await (await fetch(base+'/vulns/xss/reflected?search='+encodeURIComponent(raw))).text();assert.ok(html.includes(raw));
 }finally{if(server)await new Promise(resolve=>server.close(resolve));Module._load=original;files.forEach(f=>delete require.cache[f]);}
});
