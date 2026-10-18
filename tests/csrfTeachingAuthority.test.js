'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { createCsrfTeachingAuthority } = require('../server/services/csrfTeachingAuthority');
function fixture() {
 const state = { valid: true, lease: false, calls: [] };
 const authority = { ownerId: 7, sessionId: 12, check: async () => {
  state.calls.push('check'); assert.equal(state.lease, false);
  if (!state.valid) throw Object.assign(new Error('private failure'), { statusCode: 401 });
 } };
 const runtime = { bindBearer: async () => { state.calls.push('bearer'); return authority; },
  resolveAuthority: async (_req, options) => { state.calls.push(options.allowCookie ? 'cookie' : 'denied');
   if (!options.allowCookie) throw Object.assign(new Error('private'), { statusCode: 401 }); return authority; },
  store: { withAuthority: async (sid, binding, work) => {
   assert.equal(sid, 'captured'); assert.deepEqual(binding, { ownerId: 7, sessionId: 12 });
   state.calls.push('lease'); state.lease = true;
   try { return await work(); } finally { state.lease = false; state.calls.push('commit'); }
  } } };
 const service = createCsrfTeachingAuthority({ runtime });
 const req = { headers: {}, sessionID: 'captured' };
 const res = { status(value) { this.code = value; return this; }, json(value) { this.body = value; } };
 const admit = async options => { let admitted = false; await service.middleware(options)(req,res,()=>{admitted=true;}); return admitted; };
 return { state, runtime, service, req, res, admit };
}
test('cookie authority requires explicit sink opt-in and never adds platform principal', async () => {
 const f=fixture(); assert.equal(await f.admit(),false); assert.equal(f.res.code,401);
 assert.equal(await f.admit({allowCookie:true}),true); assert.equal(f.req.user,undefined);
 assert.equal(f.service.get(f.req).ownerId,7);
});
test('presented bearer takes precedence; principal mismatch is denied',async()=>{
 const f=fixture(); f.req.headers.authorization='Bearer token'; f.req.user={id:8,role:'admin'};
 assert.equal(await f.admit({allowCookie:true}),false); assert.equal(f.res.code,401);
 assert.ok(f.state.calls.includes('bearer')); assert.ok(!f.state.calls.includes('cookie'));
 assert.throws(()=>f.service.get(f.req));
});
test('effect checks bracket only the short lease; retirement prevents later effects',async()=>{
 const f=fixture(); await f.admit({allowCookie:true}); const context=f.service.get(f.req);
 assert.equal(await context.withTeachingEffect(async()=>{assert.equal(f.state.lease,true);return 42;}),42);
 assert.deepEqual(f.state.calls.slice(-3),['lease','commit','check']);
 f.state.valid=false; let effect=false;
 await assert.rejects(context.withTeachingEffect(async()=>{effect=true;}),{statusCode:401}); assert.equal(effect,false);
});
test('captured SID cannot silently change and private failures remain sanitized',async()=>{
 const f=fixture(); await f.admit({allowCookie:true}); f.req.sessionID='replacement';
 await assert.rejects(f.service.get(f.req).check(),{statusCode:401});
 const g=fixture(); g.runtime.resolveAuthority=async()=>{throw new Error('postgres private credentials');};
 assert.equal(await g.admit({allowCookie:true}),false); assert.equal(g.res.code,503);
 assert.deepEqual(g.res.body,{error:'Teaching session authority unavailable'});
});
test('revocation after an observed effect denies publication without replaying it',async()=>{
 const f=fixture(); await f.admit({allowCookie:true}); let effects=0;
 await assert.rejects(f.service.get(f.req).withTeachingEffect(async()=>{
  effects++; f.state.valid=false; return 'observed';
 }),{statusCode:401});
 assert.equal(effects,1);
 assert.equal(f.state.calls.filter(value=>value==='lease').length,1);
 assert.equal(f.state.lease,false);
});
