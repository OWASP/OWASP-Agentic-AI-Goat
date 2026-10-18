'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {EventEmitter}=require('node:events');
const {createSecureShopAgentHostIpcSpawn:create}=require('./fixtures/secureShopAgentHostIpcSpawn');
function setup(t){const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'ss-spawn-contract-')));fs.chmodSync(root,0o555);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return root;}
function child(pid){const c=new EventEmitter();c.pid=pid;c.connected=true;c.send=()=>{};c.disconnect=()=>{c.connected=false;c.emit('disconnect');};return c;}
test('exact Supervisor spawn retains env/identity and gives each restart separate IPC ownership',t=>{
 const root=setup(t),calls=[],revoked=[],children=[];
 const adapter=create({sourceRoot:root,spawnProcess(...args){calls.push(args);const c=child(100+calls.length);children.push(c);return c;},revokeChild:c=>revoked.push(c)});
 const options={cwd:root,env:{SS_AGENT_HOST_INSTANCE_ID:'123e4567-e89b-42d3-a456-426614174000',SS_AGENT_HOST_PORT:'35002',MARKER:'retained'},stdio:['ignore','inherit','inherit']};
 const first=adapter.spawn(process.execPath,['agent-host/index.js'],options);
 assert.deepEqual(calls[0][2].env,options.env);assert.deepEqual(calls[0][2].stdio,['ignore','inherit','inherit','ipc']);assert.equal(calls[0][2].detached,false);
 first.emit('exit',0);assert.throws(()=>adapter.senderFor(first));assert.deepEqual(revoked,[first]);
 const second=adapter.spawn(process.execPath,['agent-host/index.js'],options);assert.notEqual(adapter.senderFor(second),undefined);
 adapter.close();assert.deepEqual(revoked,[first,second]);assert.ok(adapter.status().every(r=>r.closed));
});
test('foreign executable/argv/cwd/stdio/detached request is rejected before spawn',t=>{
 const root=setup(t);let calls=0;const adapter=create({sourceRoot:root,spawnProcess(){calls++;},revokeChild(){}});
 const options={cwd:root,env:{SS_AGENT_HOST_INSTANCE_ID:'123e4567-e89b-42d3-a456-426614174000',SS_AGENT_HOST_PORT:'35002'},stdio:['ignore','inherit','inherit']};
 for(const [cmd,args,opts]of [['/foreign/node',['agent-host/index.js'],options],[process.execPath,['other.js'],options],
 [process.execPath,['agent-host/index.js'],{...options,cwd:os.tmpdir()}],[process.execPath,['agent-host/index.js'],{...options,detached:true}],
 [process.execPath,['agent-host/index.js'],{...options,stdio:'inherit'}],
 ...['shell','uid','gid','unknown','detached'].map(key=>[process.execPath,['agent-host/index.js'],{...options,[key]:key==='shell'?true:0}]),
 [process.execPath,['agent-host/index.js'],{...options,env:{...options.env,SS_AGENT_HOST_INSTANCE_ID:'not-uuid'}}]])assert.throws(()=>adapter.spawn(cmd,args,opts));assert.equal(calls,0);
});
test('disconnect revokes immediately and cleanup failure remains inspectable',t=>{
 const root=setup(t),c=child(200);const adapter=create({sourceRoot:root,spawnProcess:()=>c,revokeChild(){throw Error('controlled');}});
 adapter.spawn(process.execPath,['agent-host/index.js'],{cwd:root,env:{SS_AGENT_HOST_INSTANCE_ID:'123e4567-e89b-42d3-a456-426614174000',SS_AGENT_HOST_PORT:'35002'},stdio:['ignore','inherit','inherit']});
 c.emit('disconnect');assert.throws(()=>adapter.senderFor(c));assert.deepEqual(adapter.status()[0].failures,['REVOKE_FAILED']);adapter.close();
});
