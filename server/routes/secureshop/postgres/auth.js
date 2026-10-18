'use strict';
const express=require('express');
const crypto=require('node:crypto');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const rateLimit=require('express-rate-limit');
const {getCommercePool}=require('../../../database/postgres/secureshopPools');
const {createSecureShopAccountRepository}=require('../../../database/postgres/secureshopAccountRepository');

function _secret() {
  const s = process.env.JWT_SECRET;
  if (!s) {
    // This should never fire in practice because server/services/secureshop
    // refuses to boot without JWT_SECRET, but the defensive throw here keeps
    // the invariant local.
    throw new Error('Refusing to sign/verify tokens without JWT_SECRET');
  }
  return s;
}

const ALLOWED_ROLES = new Set(['customer', 'merchant', 'admin']);

function _publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    role: row.role,
    full_name: row.full_name || null,
    phone: row.phone || null,
  };
}

function _signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    _secret(),
    { algorithm: 'HS256', expiresIn: '24h' }
  );
}

function _readBearer(req) {
  const raw = req.headers.authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(raw);
  return m ? m[1].trim() : null;
}

/**
 * F1 helper: map a role to the demo account username that owns it. The
 * workshop provisions three parallel accounts sharing the same student
 * password so instructors can rehearse the customer/merchant/admin surfaces
 * without three separate logins. `switch-role` is really "log in as the
 * companion account of role X" — with a password re-check.
 */
function _targetUsernameForRole(role) {
  // student_c / student_m / student_a — see docs/secureshop/QUICK_START.md.
  return `student_${String(role || '').trim().charAt(0).toLowerCase()}`;
}

/**
 * M14 canonical companion username. Introduced in seed
 * `22_secureshop_v2_m14_identities.js`. Post-M14 the RoleSwitcher UI logs the
 * user out and points them to /secureshop/login?prefill=<this username>.
 */
function _m14CanonicalUsernameForRole(role) {
  return `student_${String(role || '').trim().toLowerCase()}`;
}

// F6 — per-IP rate limiters. Kept moderately tight because these are the
// student-facing auth endpoints; a runaway attacker would otherwise brute-force
// bcrypt hashes at the server's max throughput.
//
// Wave 6 note: the skip predicate ALSO honours node's built-in test runner
// (which sets NODE_TEST_CONTEXT on the worker). Without this, the integration
// suite in tests/secureshop/integration/auth-v2.test.js self-DoSes at the
// 6th login and every downstream test that needs a bearer token 401s.
function _skipLimiter() {
  return (
    process.env.NODE_ENV === 'test' ||
    process.env.SS_DISABLE_RATE_LIMIT === 'true' ||
    !!process.env.NODE_TEST_CONTEXT
  );
}

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many login attempts; please retry in a minute' },
  skip: _skipLimiter,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many registrations from this IP; please retry later' },
  skip: _skipLimiter,
});

module.exports=function buildAuthRouter({repository=createSecureShopAccountRepository(getCommercePool())}={}) {
  const router=express.Router();
  const route=handler=>async(req,res)=>{try{await handler(req,res);}catch(error){res.status(error.code==='23505'?409:500).json({error:error.code==='23505'?'username or email already exists':error.message});}};
  function requireUser(req,res) {
    const token=_readBearer(req);
    if(!token){res.status(401).json({error:'missing bearer token'});return null;}
    try{return jwt.verify(token,_secret(),{algorithms:['HS256']});}
    catch{res.status(401).json({error:'invalid token'});return null;}
  }
  router.post('/register',registerLimiter,route(async(req,res)=>{
    const {username,email,password,role='customer',full_name}=req.body||{};
    if(!username||!email||!password)return res.status(400).json({error:'username, email, and password are required'});
    if(!ALLOWED_ROLES.has(role))return res.status(400).json({error:`role must be one of ${[...ALLOWED_ROLES].join(', ')}`});
    if(String(password).length<6)return res.status(400).json({error:'password must be at least 6 characters'});
    if(await repository.findConflict(username,email))return res.status(409).json({error:'username or email already exists'});
    const row=await repository.createUser(username,email,await bcrypt.hash(password,10),role,full_name||null);
    res.json({ok:true,token:_signToken(row),user:{id:row.id,username,email,role,full_name:full_name||null}});
  }));
  router.post('/login',loginLimiter,route(async(req,res)=>{
    const {username,password}=req.body||{};
    if(!username||!password)return res.status(400).json({error:'username and password required'});
    const row=await repository.findByUsername(username);
    if(!row)return res.status(401).json({error:'invalid credentials'});
    if(row.banned_at)return res.status(403).json({error:'account banned'});
    if(!await bcrypt.compare(password,row.password))return res.status(401).json({error:'invalid credentials'});
    const token=_signToken(row);
    const ip=(req.headers['x-forwarded-for']||req.socket?.remoteAddress||'').toString().split(',')[0].trim();
    await repository.recordLogin(row.id,ip||null,String(req.headers['user-agent']||'').slice(0,240)||null);
    res.json({ok:true,token,user:_publicUser(row)});
  }));
  router.post('/logout',route(async(req,res)=>{
    const token=_readBearer(req);let decoded;
    if(token){try{decoded=jwt.verify(token,_secret(),{algorithms:['HS256']});}catch{}}
    if(decoded?.id)await repository.recordLogout(decoded.id);
    res.json({ok:true,next:'login',hint:'M14 role change = logout + login as target identity'});
  }));
  router.get('/whoami',route(async(req,res)=>{
    const decoded=requireUser(req,res);if(!decoded)return;
    const row=await repository.findById(decoded.id);
    if(!row)return res.status(401).json({error:'user not found'});
    res.json({ok:true,user:_publicUser(row)});
  }));
  router.post('/switch-role',route(async(req,res)=>{
    const decoded=requireUser(req,res);if(!decoded)return;
    const {role,password}=req.body||{};
    if(!ALLOWED_ROLES.has(role))return res.status(400).json({error:`role must be one of ${[...ALLOWED_ROLES].join(', ')}`});
    if(decoded.role===role){
      const row=await repository.findById(decoded.id);
      if(!row)return res.status(401).json({error:'user not found'});
      return res.json({ok:true,token:_signToken(row),user:_publicUser(row),deprecated:true});
    }
    if(!password)return res.status(403).json({ok:false,error:'cross-role switch requires password re-authentication in the request body',hint:'M14 preferred flow: POST /logout then POST /login with target account'});
    const row=await repository.findCompanion(_m14CanonicalUsernameForRole(role),_targetUsernameForRole(role),role);
    if(!row)return res.status(403).json({ok:false,error:`no companion account provisioned for role=${role}`});
    if(!await bcrypt.compare(String(password),row.password))return res.status(403).json({ok:false,error:'password does not match target account'});
    if(row.banned_at)return res.status(403).json({ok:false,error:'target account is banned'});
    res.json({ok:true,token:_signToken(row),user:_publicUser(row),deprecated:true,hint:'M14 preferred flow: POST /logout then POST /login with target account'});
  }));
  router.put('/users/me',route(async(req,res)=>{
    const decoded=requireUser(req,res);if(!decoded)return;
    const {full_name,email,phone}=req.body||{};
    if(!email||!String(email).includes('@'))return res.status(400).json({error:'valid email required'});
    const row=await repository.updateProfile(decoded.id,full_name||null,email,phone||null);
    if(!row)return res.status(401).json({error:'user not found'});
    res.json({ok:true,user:{..._publicUser(row),phone:row.phone}});
  }));
  router.post('/users/me/password',route(async(req,res)=>{
    const decoded=requireUser(req,res);if(!decoded)return;
    const {current_password,new_password}=req.body||{};
    if(!current_password||!new_password)return res.status(400).json({error:'current_password and new_password required'});
    if(String(new_password).length<8)return res.status(400).json({error:'new password must be at least 8 characters'});
    const row=await repository.findById(decoded.id);
    if(!row)return res.status(401).json({error:'user not found'});
    if(!await bcrypt.compare(current_password,row.password))return res.status(403).json({error:'current password does not match'});
    const result=await repository.changePassword(decoded.id,row.password,await bcrypt.hash(new_password,10));
    if(!result.rowCount)return res.status(409).json({error:'password changed; retry with current credentials'});
    res.json({ok:true});
  }));
  router.get('/users/me/addresses',route(async(req,res)=>{
    const decoded=requireUser(req,res);if(decoded)res.json({addresses:await repository.listAddresses(decoded.id)});
  }));
  function addressFields(body){const {label,line1,line2,city,state,zip,phone,is_default}=body||{};return[label||null,line1||'',line2||null,city||null,state||null,zip||null,phone||null,is_default?1:0];}
  router.post('/users/me/addresses',route(async(req,res)=>{
    const decoded=requireUser(req,res);if(!decoded)return;
    if(!req.body?.line1||!String(req.body.line1).trim())return res.status(400).json({error:'line1 required'});
    const row=await repository.saveAddress(decoded.id,null,addressFields(req.body));
    if(!row)return res.status(404).json({error:'user not found'});
    res.json({ok:true,id:row.id});
  }));
  router.put('/users/me/addresses/:id',route(async(req,res)=>{
    const decoded=requireUser(req,res);if(!decoded)return;
    const row=await repository.saveAddress(decoded.id,req.params.id,addressFields(req.body));
    if(!row)return res.status(404).json({error:'not found'});
    res.json({ok:true});
  }));
  router.delete('/users/me/addresses/:id',route(async(req,res)=>{
    const decoded=requireUser(req,res);if(decoded)res.json({ok:(await repository.deleteAddress(decoded.id,req.params.id)).rowCount>0});
  }));
  router.get('/users/me/api-keys',route(async(req,res)=>{
    const decoded=requireUser(req,res);if(!decoded)return;
    const row=await repository.findById(decoded.id);
    if(!row)return res.status(404).json({error:'user not found'});
    res.json({api_key:row.api_key||null,created_at:row.created_at||null});
  }));
  router.post('/users/me/api-keys/rotate',route(async(req,res)=>{
    const decoded=requireUser(req,res);if(!decoded)return;
    const key=`sk_ss_live_${crypto.randomBytes(16).toString('hex')}`;
    await repository.rotateKey(decoded.id,key);res.json({ok:true,api_key:key});
  }));
  router.get('/users/me/sessions',route(async(req,res)=>{
    const decoded=requireUser(req,res);if(decoded)res.json({sessions:await repository.listSessions(decoded.id)});
  }));
  router.post('/users/me/sessions/:id/revoke',route(async(req,res)=>{
    const decoded=requireUser(req,res);if(decoded)res.json({ok:(await repository.revokeSession(decoded.id,req.params.id)).rowCount>0});
  }));
  return router;
};
