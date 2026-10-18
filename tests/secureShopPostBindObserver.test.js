'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createSecureShopSsrfOwnedTarget } = require('../server/services/secureshopSsrfOwnedTarget');
const { createSecureShopEndpointCapabilities } = require('./fixtures/secureShopEndpointCapabilities');
const { createObservedTargetFactory, createEndpointSocketPolicy } = require('./fixtures/secureShopPostBindObserver');
const scope = { targetId:'10000000-0000-4000-8000-000000000001', launchId:'20000000-0000-4000-8000-000000000001', scenarioId:'30000000-0000-4000-8000-000000000001', generation:0, platformOwnerId:1, platformSessionId:1 };
const request = url => new Promise((resolve, reject) => { const req=http.get(url, response => { let body='';response.on('data',c=>body+=c);response.on('end',()=>{req.destroy();resolve({status:response.statusCode,body});}); });req.on('error',reject); });

test('genuine owned target issue result registers exact listener and tracked socket revokes', async t => {
 const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'ss-post-bind-')));t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const registry=createSecureShopEndpointCapabilities();const grant=registry.grant(scope);
 const factory=createObservedTargetFactory({root,registry,grant,scope,createTarget:createSecureShopSsrfOwnedTarget});
 const target=await factory({root:await fs.realpath(root),targetId:scope.targetId});t.after(async()=>{try { await target.cleanup(); } finally { registry.close(); }});
 const issued=target.issue({requestId:'40000000-0000-4000-8000-000000000001',resourceKind:'public-policy',operationId:'50000000-0000-4000-8000-000000000001'});
 const issuedPrivate=target.issue({requestId:'40000000-0000-4000-8000-000000000002',resourceKind:'private-policy',operationId:'50000000-0000-4000-8000-000000000002'});
 assert.equal(new URL(issued.url).port, new URL(issuedPrivate.url).port);
 const policy=createEndpointSocketPolicy({permits:registry.permits,trackSocket:registry.trackSocket});
 const result=await request(issued.url);assert.equal(result.status,200);assert.match(result.body,/accepted within 30 days/);
 assert.throws(()=>policy.assert('127.0.0.1',1),{code:'QUALIFICATION_ENDPOINT_BLOCKED'});
 const socket={destroyed:0,destroy(){this.destroyed++;}};policy.track('127.0.0.1',new URL(issued.url).port,socket);
 await target.cleanup(); assert.equal(socket.destroyed,1);
 assert.throws(()=>target.issue({}),{code:'POST_BIND_TARGET_RETIRED'});
 await assert.rejects(request(issued.url),{code:'ECONNREFUSED'});
 await assert.rejects(factory({root:await fs.realpath(root),targetId:scope.targetId}),{code:'POST_BIND_FACTORY_REBOUND'});assert.throws(()=>policy.assert('127.0.0.1',new URL(issued.url).port),{code:'QUALIFICATION_ENDPOINT_BLOCKED'});
});

test('factory rejects symlink root, fabricated target args, and unsupported socket forms', async t => {
 const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'ss-post-bind-')));t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const registry=createSecureShopEndpointCapabilities();const grant=registry.grant(scope);
 const factory=createObservedTargetFactory({root,registry,grant,scope,createTarget:async()=>({issue(){return {targetId:scope.targetId,url:'http://127.0.0.1:35001/x'};}})});
 await assert.rejects(factory({root,targetId:'10000000-0000-4000-8000-000000000002'}),{code:'POST_BIND_FACTORY_SCOPE'});
 const alias=path.join(path.dirname(root), 'ss-post-bind-alias-'+process.pid);
 try { await fs.symlink(root, alias); const linked=createObservedTargetFactory({root:alias,registry,grant,scope,createTarget:async()=>({issue(){return {targetId:scope.targetId,url:'http://127.0.0.1:35001/x'};}})}); await assert.rejects(linked({root:alias,targetId:scope.targetId}),{code:'POST_BIND_ROOT_INVALID'}); } finally { await fs.rm(alias,{recursive:true,force:true}); }
 const policy=createEndpointSocketPolicy({permits:registry.permits,trackSocket:registry.trackSocket});
 assert.throws(()=>policy.track('127.0.0.1',35001,{destroy(){}}),{code:'QUALIFICATION_ENDPOINT_BLOCKED'});
 assert.throws(()=>policy.assert('localhost',35001),{code:'QUALIFICATION_ENDPOINT_BLOCKED'});registry.close();
});

test('cleanup failure still invokes genuine target cleanup after revocation', async () => {
 const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'ss-post-bind-'))); await fs.mkdir(root,{recursive:true});
 const registry=createSecureShopEndpointCapabilities(); const grant=registry.grant(scope); let closed=false;
 const factory=createObservedTargetFactory({root,registry,grant,scope,createTarget:async()=>({
   issue(){ return {targetId:scope.targetId,url:'http://127.0.0.1:35003/policy/public-policy/x',operationId:'50000000-0000-4000-8000-000000000001',requestId:'40000000-0000-4000-8000-000000000001',resourceKind:'public-policy',nonce:'60000000-0000-4000-8000-000000000001'}; },
   async cleanup(){ closed=true; throw Error('controlled cleanup failure'); },
 })});
 const target=await factory({root:await fs.realpath(root),targetId:scope.targetId}); target.issue({requestId:'40000000-0000-4000-8000-000000000001',resourceKind:'public-policy',operationId:'50000000-0000-4000-8000-000000000001'});
 registry.trackSocket('127.0.0.1',35003,{destroy(){throw Error('controlled revoke failure');}});
 await assert.rejects(target.cleanup(), error => error instanceof AggregateError && error.errors.length === 2
   && error.errors[0].errors[0].message === 'controlled revoke failure' && error.errors[1].message === 'controlled cleanup failure'); assert.equal(closed,true); assert.equal(registry.permits('127.0.0.1',35003),false); registry.close(); await fs.rm(root,{recursive:true,force:true});
});


test('factory admission is claimed before async creation can race', async t => {
 const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'ss-post-bind-')));
 const registry=createSecureShopEndpointCapabilities();const grant=registry.grant(scope);let calls=0;
 t.after(async()=>{registry.close();await fs.rm(root,{recursive:true,force:true});});
 const factory=createObservedTargetFactory({root,registry,grant,scope,createTarget:async()=>{calls++;return {issue(){},async cleanup(){}};}});
 const args={root,targetId:scope.targetId};const pending=factory(args);
 await assert.rejects(factory(args),{code:'POST_BIND_FACTORY_REBOUND'});
 const target=await pending;assert.equal(calls,1);await target.cleanup();
});
