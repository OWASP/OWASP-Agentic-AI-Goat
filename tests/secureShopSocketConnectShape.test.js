'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),{fork}=require('node:child_process'),{once}=require('node:events');
const NODE_BIN=process.execPath;
const {waitForChild}=require('./fixtures/fullBackendBootControls');
const childSource=`'use strict';const net=require('node:net'),dns=require('node:dns');const shapes=[];const original=net.Socket.prototype.connect;net.Socket.prototype.connect=function(...args){const first=args[0], value=Array.isArray(first)?first[0]:first;shapes.push({array:Array.isArray(first),argCount:args.length,firstType:Array.isArray(first)?'array':typeof first,keys:value&&typeof value==='object'?Object.keys(value).sort():[],pathPresent:!!(value&&value.path!=null),lookupPresent:!!(value&&value.lookup!==undefined),lookupIsDefault:!!(value&&value.lookup===dns.lookup)});return original.apply(this,args)};const target=process.env.TARGET;const options={hostname:'127.0.0.1',port:Number(new URL(target).port),path:'/'};if(process.env.CUSTOM==='1')options.lookup=(host,opts,cb)=>cb(null,'127.0.0.1',4);const req=require('node:http').request(options,res=>{res.resume();res.on('end',()=>{process.send({version:process.version,executable:process.execPath,shapes});process.disconnect()})});req.on('error',error=>{process.send({version:process.version,executable:process.execPath,error:error.code||'ERR',shapes});process.disconnect()});req.end();`;
async function runChild(target, custom) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'ss-connect-shape-'));
  const file=path.join(root,'child.cjs');
  fs.writeFileSync(file,childSource,{mode:0o600});
  const child=fork(file,[],{execPath:NODE_BIN,silent:true,detached:false,
    env:{TARGET:target,CUSTOM:custom?'1':'0'}});
  const exited=waitForChild(child,{timeoutMs:6000});
  void exited.catch(()=>{});
  let timer;
  try {
    const [message]=await Promise.race([once(child,'message'),new Promise((_,reject)=>{
      timer=setTimeout(()=>reject(Error('shape child timeout')),5000);
    })]);
    clearTimeout(timer);
    assert.equal(await exited,0);
    return message;
  } finally {
    clearTimeout(timer);
    if(child.exitCode===null&&child.signalCode===null) {
      child.kill('SIGTERM');
      try { await waitForChild(child,{timeoutMs:2000}); }
      catch {
        if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');
        await waitForChild(child,{timeoutMs:2000});
      }
    }
    assert.throws(()=>process.kill(child.pid,0),{code:'ESRCH'});
    fs.rmSync(root,{recursive:true,force:true});
  }
}
test('current Node records bounded http.request socket connect shapes',async t=>{assert.equal(fs.existsSync(NODE_BIN),true,'pinned Node runtime is required');const server=http.createServer((req,res)=>res.end('ok'));await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve)});const port=server.address().port;try{const target=`http://127.0.0.1:${port}/`;for(const custom of [false,true]){const result=await runChild(target,custom);assert.equal(result.error,undefined);assert.equal(result.version,process.version);assert.equal(result.executable,NODE_BIN);assert.ok(result.shapes.length>=1);t.diagnostic(JSON.stringify({node:result.executable,version:result.version,custom,shapes:result.shapes}));for(const shape of result.shapes){assert.equal(typeof shape.array,'boolean');assert.equal(typeof shape.argCount,'number');assert.ok(Array.isArray(shape.keys));assert.equal(shape.pathPresent,false);if(custom)assert.equal(shape.lookupPresent,true);}}const normal=(await runChild(target,false)).shapes;assert.ok(normal.some(shape=>shape.lookupPresent===false||shape.lookupIsDefault===true));const customShapes=(await runChild(target,true)).shapes;assert.ok(customShapes.some(shape=>shape.lookupPresent===true&&shape.lookupIsDefault===false));}finally{await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));assert.equal(server.address(),null);}});
