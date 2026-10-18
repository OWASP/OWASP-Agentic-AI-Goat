'use strict';
// Characterization only: no sockets, server, database or provider is started.
const test=require('node:test'),assert=require('node:assert/strict');
const {disconnect}=require('../server/services/secureshop/mcpTransport');
const {McpClientPool}=require('../server/services/secureshop/mcpClientPool');
test('current transport wrapper suppresses a real client close rejection',async()=>{
 const error=Error('controlled close failure');let called=0;
 await assert.doesNotReject(disconnect({close:async()=>{called++;throw error;}}));
 assert.equal(called,1);
});
test('current pool drain waits on first client before attempting later clients',async()=>{
 let release;const pending=new Promise(resolve=>{release=resolve;});const calls=[];
 const pool=new McpClientPool({baseUrl:'http://127.0.0.1:1',agents:[]});
 pool.clients.set('first',{close:async()=>{calls.push('first');await pending;}});
 pool.clients.set('second',{close:async()=>{calls.push('second');}});
 let done=false;const closing=pool.close().then(()=>{done=true;});
 await new Promise(resolve=>setImmediate(resolve));
 try{assert.deepEqual(calls,['first']);assert.equal(done,false);assert.equal(pool.clients.size,2);}finally{release();await closing;}
 assert.deepEqual(calls,['first','second']);assert.equal(pool.clients.size,0);
});
