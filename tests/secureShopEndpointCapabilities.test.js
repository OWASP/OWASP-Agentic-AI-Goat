'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopEndpointCapabilities:create}=require('./fixtures/secureShopEndpointCapabilities');
const scope=n=>({targetId:`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`,launchId:'20000000-0000-4000-8000-000000000001',scenarioId:'30000000-0000-4000-8000-000000000001',generation:0,platformOwnerId:n,platformSessionId:n});
const register=(grant,port=35001)=>({...grant,sequence:1,operation:'register',endpoint:{host:'127.0.0.1',port}});
test('private grant binds exact endpoint and ordered acknowledgement, then revokes tracked sockets',()=>{
 const r=create(),g=r.grant(scope(1));assert.equal(r.permits('127.0.0.1',35001),false);
 assert.equal(r.apply(register(g)).state,'active');let destroyed=0;
 r.trackSocket('127.0.0.1',35001,{destroy(){destroyed++;}});
 assert.equal(r.permits('localhost',35001),false);
 r.apply({...g,sequence:2,operation:'revoke',endpoint:null});assert.equal(destroyed,1);
 assert.equal(r.permits('127.0.0.1',35001),false);assert.throws(()=>r.apply(register(g)));
});
test('forged, stale, aliased, reserved and colliding registration fails closed',()=>{
 const r=create({reservedPorts:[35005]}),g=r.grant(scope(1));
 for(const mutate of [m=>m.capability='a'.repeat(64),m=>m.scope.generation++,m=>m.scope.platformOwnerId++,
  m=>m.sequence=2,m=>m.endpoint.host='localhost',m=>m.endpoint.host='example.invalid',m=>m.endpoint.port=0,
  m=>m.endpoint.port='35001',m=>m.endpoint.port=35005,m=>m.endpoint.path='/tmp/x']) {
  const m=structuredClone(register(g));mutate(m);assert.throws(()=>r.apply(m));assert.equal(r.permits('127.0.0.1',35001),false);
 }
 r.apply(register(g));assert.throws(()=>r.apply(register(g)));
 const sibling=r.grant(scope(2));assert.throws(()=>r.apply(register(sibling)));
 r.apply(register(sibling,35002));r.apply({...g,sequence:2,operation:'revoke',endpoint:null});
 assert.equal(r.permits('127.0.0.1',35002),true);r.close();assert.equal(r.permits('127.0.0.1',35002),false);
});
test('cleanup errors still revoke every endpoint and block later admissions',()=>{
 const r=create(),a=r.grant(scope(1)),b=r.grant(scope(2));r.apply(register(a));r.apply(register(b,35002));let siblingClosed=false;
 r.trackSocket('127.0.0.1',35001,{destroy(){throw Error('controlled');}});
 r.trackSocket('127.0.0.1',35002,{destroy(){siblingClosed=true;}});
 assert.throws(()=>r.close(),AggregateError);assert.equal(siblingClosed,true);
 assert.equal(r.permits('127.0.0.1',35001),false);assert.equal(r.permits('127.0.0.1',35002),false);
 assert.throws(()=>r.grant(scope(3)));assert.throws(()=>r.apply(register(a)));
});
