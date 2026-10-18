'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const net=require('node:net');
const {allowedDatabaseConnect}=require('./fixtures/fullBackendBootControls');
const {installStaticDynamicSocketGuard}=require('./fixtures/secureShopStaticDynamicSocketGuard');
test('composition preserves exact static admission and privately admits dynamic endpoints',()=>{
 const original=net.Socket.prototype.connect,calls=[],tracked=[],dynamic=new Set();
 const fixed={host:'127.0.0.1',port:35001};
 const guard=installStaticDynamicSocketGuard({staticAllows:args=>allowedDatabaseConnect(args,fixed),
  permits:(host,port)=>host==='127.0.0.1'&&dynamic.has(port),
  trackSocket:(host,port)=>tracked.push(port),connect:function(...args){calls.push(args);return this;}});
 try{
  const socket={destroy(){}};
  guard.guarded.call(socket,{...fixed});
  assert.equal(calls.length,1);assert.deepEqual(tracked,[]);
  assert.throws(()=>guard.guarded.call(socket,{host:'127.0.0.1',port:35002}));
  dynamic.add(35002);guard.guarded.call(socket,[{host:'127.0.0.1',port:35002}]);
  assert.deepEqual(tracked,[35002]);dynamic.clear();
  for(const args of [[{host:'127.0.0.1',port:35002}],[{host:'127.0.0.2',port:35001}],
   [{path:'/not-opened.sock'}],[{host:'127.0.0.1',port:35002,lookup(){}}],[NaN,'127.0.0.1'],[1.5,'127.0.0.1']]){
   assert.throws(()=>guard.guarded.apply(socket,args));
  }
  assert.equal(calls.length,2);
 }finally{guard.restore();}
 assert.strictEqual(net.Socket.prototype.connect,original);
});
