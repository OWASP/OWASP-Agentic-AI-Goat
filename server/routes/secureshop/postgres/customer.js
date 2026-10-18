'use strict';
const express=require('express');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const {getCommercePool,getAgentsPool}=require('../../../database/postgres/secureshopPools');
const {createSecureShopCustomerRepository}=require('../../../database/postgres/secureshopCustomerRepository');
const {customerSupervisor}=require('../../../services/secureshop/supervisors/customerSupervisor');
const {runChatTurn}=require('../../../services/secureshop/streaming');
const {requireRole}=require('../_ssAuthMiddleware');
const {agentSessionControl}=require('../_agentSessionControl');
const {productWithMountedAssetUrls}=require('../../../services/secureshop/assetPaths');

module.exports=function buildRouter({pool,manifest,provider,repository=createSecureShopCustomerRepository(getCommercePool(),getAgentsPool())}){
  const router=express.Router();
  const agentSession=agentSessionControl('customer');
  const route=fn=>async(req,res)=>{try{await fn(req,res);}catch(error){res.status(500).json({error:error.message});}};
  const limit=(value,fallback,max)=>Math.max(1,Math.min(Math.trunc(Number(value))||fallback,max));
  const offset=value=>Math.max(0,Math.trunc(Number(value))||0);
  const token=user=>jwt.sign({id:user.id,username:user.username,role:user.role},'shop-secret-key',{expiresIn:'4h'});
  router.use('/agents/customer',requireRole('customer'));
  router.post('/auth/register',route(async(req,res)=>{
    const {username,email,password,role='customer',full_name,phone,address}=req.body||{};
    if(!username||!email||!password)return res.status(400).json({error:'username, email, and password are required'});
    try{
      const row=await repository.createLegacyUser(username,email,await bcrypt.hash(password,10),role,full_name||null,phone||null,address||null);
      res.json({success:true,message:'User registered successfully',token:token({...row,username,role}),user:{id:row.id,username,email,role,full_name}});
    }catch(error){if(error.code==='23505')return res.status(400).json({error:'Username or email already exists'});throw error;}
  }));
  router.post('/auth/login',route(async(req,res)=>{
    const {username,password}=req.body||{};
    if(!username||!password)return res.status(400).json({error:'username and password required'});
    const user=await repository.findUser(username);
    if(!user||!await bcrypt.compare(password,user.password))return res.status(401).json({error:'Invalid credentials'});
    res.json({success:true,token:token(user),user:{id:user.id,username:user.username,email:user.email,role:user.role,full_name:user.full_name}});
  }));
  router.get('/products',route(async(req,res)=>{
    const result=await repository.browse({category:req.query.category||null,search:req.query.search||req.query.q||null,sort:String(req.query.sort||'').toLowerCase(),limit:limit(req.query.limit,24,100),offset:offset(req.query.offset)});
    res.json({...result,products:(result.products||[]).map((product)=>productWithMountedAssetUrls(product))});
  }));
  const similar=async id=>require('../../../../agent-host/agents/product-search/tools/similar').similar({product_id:Number(id)||0});
  router.get('/products/similar',route(async(req,res)=>res.json(await similar(req.query.id))));
  router.get('/recommended',route(async(req,res)=>res.json(await require('../../../../agent-host/agents/product-search/tools/personalized_feed').personalizedFeed({user_id:Number(req.query.user_id)||1}))));
  router.get('/products/:id',route(async(req,res)=>{
    const result=await repository.product(req.params.id);if(!result)return res.status(404).json({error:'not found'});res.json({...result,product:productWithMountedAssetUrls(result.product)});
  }));
  router.post('/products/:id/summary',route(async(req,res)=>res.json(await require('../../../../agent-host/agents/summarizer/tools/summarize_product').summarizeProduct({product_id:Number(req.params.id)}))));
  router.post('/orders/summary',route(async(req,res)=>{
    const items=await repository.cart(req.body?.user_id??1);
    const total=items.reduce((sum,row)=>sum+Number(row.price||0)*row.quantity,0);
    const lines=items.map(item=>`  - ${item.quantity}× ${item.name} @ $${Number(item.price).toFixed(2)}`);
    res.json({ok:true,items,total,summary:`Order review\n${items.length} line item${items.length===1?'':'s'}\n${lines.join('\n')}\n\nTotal: $${Number(total).toFixed(2)}`});
  }));
  router.get('/products/:id/similar',route(async(req,res)=>res.json(await similar(req.params.id))));
  router.get('/products/:id/reviews',route(async(req,res)=>res.json(await repository.reviews(req.params.id,limit(req.query.limit,10,50),offset(req.query.offset)))));
  router.post('/products/:id/reviews',route(async(req,res)=>{
    const {author_id=1,body='',rating=5}=req.body||{};
    if(!String(body).trim())return res.status(400).json({error:'body required'});
    // @intentional-vulnerability xss-stored-review
    // Preserve raw review HTML and caller-selected author for the exercise.
    const row=await repository.addReview(req.params.id,author_id,body,rating);
    res.json({ok:true,review_id:row.id});
  }));
  router.get('/categories',route(async(req,res)=>res.json({categories:await repository.categories()})));
  router.get('/cart',route(async(req,res)=>{
    const items=await repository.cart(Number(req.query.user_id||1));
    const subtotal=items.reduce((sum,row)=>sum+Number(row.price||0)*row.quantity,0);
    res.json({items,subtotal:Number(subtotal.toFixed(2))});
  }));
  router.post('/cart',route(async(req,res)=>{
    const {user_id=1,product_id,quantity=1}=req.body||{};
    if(!product_id)return res.status(400).json({error:'product_id required'});
    res.json({ok:true,cart_item_id:(await repository.addCart(user_id,product_id,quantity)).id});
  }));
  router.patch('/cart/:id',route(async(req,res)=>{
    if(req.body?.quantity==null)return res.status(400).json({error:'quantity required'});
    const result=await repository.updateCart(req.params.id,Number(req.body.quantity));
    res.json({ok:result.rowCount>0,changes:result.rowCount});
  }));
  router.delete('/cart/:id',route(async(req,res)=>{
    const result=await repository.deleteCart(req.params.id);res.json({ok:result.rowCount>0,changes:result.rowCount});
  }));
  router.post('/cart/apply-coupon',route(async(req,res)=>{
    const {user_id=1,code=''}=req.body||{};
    // @intentional-vulnerability sqli-coupon
    // Deliberate native PostgreSQL predicate injection, preserving the raw sink.
    const sql=`SELECT id,code,discount_percent,active FROM secureshop.coupons WHERE code='${String(code).replace(/;/g,'')}' AND active=1 LIMIT 1`;
    let row;
    try{row=await repository.coupon(sql);}catch(error){return res.status(400).json({ok:false,error:error.message,sql});}
    if(!row)return res.status(404).json({ok:false,error:'coupon not found'});
    const subtotal=(await repository.cart(user_id)).reduce((sum,item)=>sum+Number(item.price||0)*item.quantity,0);
    res.json({ok:true,code:row.code,discount_percent:row.discount_percent,subtotal:Number(subtotal.toFixed(2)),applied_amount:Number((subtotal*(row.discount_percent||0)/100).toFixed(2))});
  }));
  router.get('/orders',route(async(req,res)=>res.json({orders:(await repository.orders(Number(req.query.user_id)||1)).map((order)=>productWithMountedAssetUrls(order))})));
  router.get('/orders/:id',route(async(req,res)=>{
    const result=await repository.order(req.params.id);if(!result)return res.status(404).json({error:'not found'});res.json({...result,items:(result.items||[]).map((item)=>productWithMountedAssetUrls(item))});
  }));
  router.post('/orders',route(async(req,res)=>{
    const {user_id=1,shipping_address='',payment_method='card'}=req.body||{};
    const result=await repository.checkout(user_id,shipping_address,payment_method);
    if(!result)return res.status(400).json({error:'cart empty'});res.json(result);
  }));
  // ---- Agent endpoints -----------------------------------------------------

  router.post('/agents/customer/session',agentSession.create);

  router.post('/agents/customer/chat',agentSession.requireOwned, async (req, res) => {
    const { sessionId, message } = req.body || {};
    if (!sessionId || !message) {
      return res.status(400).json({ error: 'sessionId and message required' });
    }
    await runChatTurn(req, res, {
      sessionId, message, agentSession, supervisor: customerSupervisor,
      provider, pool, manifest,
    });
  });

  router.get('/agents/customer/trace/latest',route(async(req,res)=>{
    const rows=await agentSession.getLatestOwned(req,limit(req.query.limit,5,50),(owner)=>repository.latestTrace(owner));
    res.json({rows});
  }));
  router.get('/agents/customer/trace/:sessionId',agentSession.requireOwned,route(async(req,res)=>res.json({session_id:req.params.sessionId,rows:await repository.sessionTrace(req.params.sessionId)})));
  return router;
};
