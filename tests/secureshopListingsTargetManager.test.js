'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{randomUUID}=require('node:crypto');
const {createListingsTargetManager}=require('../sidecars/sandbox-runner/owned-listings/target-manager');
const {createListingsManagerHttp}=require('../sidecars/sandbox-runner/owned-listings/manager-http');
const {listingRequestDigest}=require('../server/services/secureshopListingRequestContract');
const binding=()=>({scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},targetId:randomUUID(),mode:'vuln'});
test('one shared listener isolates target tokens, persists recovery and redacts only retired target',async t=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'listing-manager-'));await fs.chmod(directory,0o700);t.after(()=>fs.rm(directory,{recursive:true,force:true}));let executions=0;
 const namespace={checkReadiness:async()=>({ready:true,runtimeDigest:'a'.repeat(64)}),async execute({request,mode}){executions++;return{version:1,operationId:request.operationId,requestSha256:listingRequestDigest(request),mode,products:[],sources:[]};}};
 const origin='http://127.0.0.1:8095',manager=await createListingsTargetManager({directory,origin,namespace}),a=binding(),b=binding();
 const [ca,cb]=await Promise.all([manager.register(a),manager.register(b)]);assert.notEqual(ca.token,cb.token);assert.deepEqual(await manager.register(a),ca);
 const server=createListingsManagerHttp({manager,controlToken:'c'.repeat(43)});const {port}=await server.start(),url=`http://127.0.0.1:${port}`;
 const headers={authorization:'Bearer '+ca.token};
 const request={version:1,action:'import',operationId:randomUUID(),json_url:'http://192.0.2.10/catalog.json',xml_url:null};
 const receipt=await(await fetch(url+'/operations',{method:'POST',headers,body:JSON.stringify(request)})).json();assert.equal(receipt.status,'completed');
 assert.equal((await fetch(url+'/operations/'+request.operationId,{headers:{authorization:'Bearer '+cb.token}})).status,404);
 assert.equal((await fetch(url+'/targets',{method:'POST',headers,body:JSON.stringify(a)})).status,401);
 const retirement={operationId:randomUUID(),canonicalReceiptSha256:'d'.repeat(64)};
 const retired=await manager.retire(a,retirement);assert.equal(retired.operationCount,1);assert.equal(retired.retired,true);
 assert.equal((await fetch(url+'/health',{headers})).status,503);
 assert.equal((await fetch(url+'/health',{headers:{authorization:'Bearer '+cb.token}})).status,200);
 await server.close();
 const restarted=await createListingsTargetManager({directory,origin,namespace});assert.deepEqual(await restarted.inspect(b),cb);assert.deepEqual(await restarted.retire(a,retirement),retired);await assert.rejects(restarted.register(a),{code:'LISTINGS_TARGET_RETIRED'});await assert.rejects(restarted.inspect({...b,mode:'fixed'}),{code:'LISTINGS_TARGET_MISMATCH'});await restarted.close();assert.equal(executions,1);
 const registration=JSON.parse(await fs.readFile(path.join(directory,a.targetId,'registration.json')));assert.equal(Object.hasOwn(registration,'token'),false);
 const files=await fs.readdir(path.join(directory,a.targetId,'journal'));assert.deepEqual(files,[request.operationId+'.retired.json']);
});
test('concurrent retirement drains actual pending target request and returns identical receipt',async t=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'listing-manager-drain-'));await fs.chmod(directory,0o700);t.after(()=>fs.rm(directory,{recursive:true,force:true}));
 let entered,release;const started=new Promise(r=>{entered=r;}),gate=new Promise(r=>{release=r;});
 const namespace={checkReadiness:async()=>({ready:true,runtimeDigest:'a'.repeat(64)}),async execute({request,mode}){entered();await gate;return{version:1,operationId:request.operationId,requestSha256:listingRequestDigest(request),mode,products:[],sources:[]};}};
 const manager=await createListingsTargetManager({directory,origin:'http://127.0.0.1:8095',namespace}),b=binding(),config=await manager.register(b),server=createListingsManagerHttp({manager,controlToken:'c'.repeat(43)}),{port}=await server.start();
 const request={version:1,action:'import',operationId:randomUUID(),json_url:'http://192.0.2.10/catalog.json',xml_url:null};
 t.after(async()=>{release();await server.close();});
 const response=fetch(`http://127.0.0.1:${port}/operations`,{method:'POST',headers:{authorization:'Bearer '+config.token},body:JSON.stringify(request)});
 await started;const options={operationId:randomUUID(),canonicalReceiptSha256:'e'.repeat(64)};
 const one=manager.retire(b,options),two=manager.retire(b,options);release();
 const [a,c]=await Promise.all([one,two]);assert.deepEqual(a,c);assert.equal(a.operationCount,1);await response;await server.close();
});
test('FIFO registration is rejected without waiting for a writer',async t=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'listing-manager-fifo-'));await fs.chmod(directory,0o700);t.after(()=>fs.rm(directory,{recursive:true,force:true}));
 const dir=path.join(directory,randomUUID());await fs.mkdir(dir,{mode:0o700});require('node:child_process').execFileSync('/usr/bin/mkfifo',[path.join(dir,'registration.json')]);
 const namespace={checkReadiness:async()=>({ready:true,runtimeDigest:'a'.repeat(64)}),execute:async()=>{}};
 await assert.rejects(createListingsTargetManager({directory,origin:'http://127.0.0.1:8095',namespace}),{code:'LISTINGS_MANAGER_STATE'});
});
test('shutdown cancels queued namespaces while draining four already running jobs',async t=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'listing-manager-queue-'));await fs.chmod(directory,0o700);t.after(()=>fs.rm(directory,{recursive:true,force:true}));
 let release,entered,executions=0;const gate=new Promise(r=>{release=r;}),four=new Promise(r=>{entered=r;});
 const namespace={checkReadiness:async()=>({ready:true,runtimeDigest:'a'.repeat(64)}),async execute({request,mode}){executions++;if(executions===4)entered();await gate;return{version:1,operationId:request.operationId,requestSha256:listingRequestDigest(request),mode,products:[],sources:[]};}};
 const manager=await createListingsTargetManager({directory,origin:'http://127.0.0.1:8095',namespace}),targets=await Promise.all(Array.from({length:6},()=>manager.register(binding()))),server=createListingsManagerHttp({manager,controlToken:'c'.repeat(43)}),{port}=await server.start();
 t.after(async()=>{release();await server.close();});
 const requests=targets.map(config=>fetch(`http://127.0.0.1:${port}/operations`,{method:'POST',headers:{authorization:'Bearer '+config.token},body:JSON.stringify({version:1,action:'import',operationId:randomUUID(),json_url:'http://192.0.2.10/catalog.json',xml_url:null})}).then(r=>r.json()));
 await four;
 let admissions=0;for(let i=0;i<1000;i++){admissions=0;for(const config of targets){const files=await fs.readdir(path.join(directory,config.targetId,'journal')).catch(()=>[]);admissions+=files.filter(v=>v.endsWith('.admission.json')).length;}if(admissions===6)break;await new Promise(setImmediate);}
 assert.equal(admissions,6);
 const closed=manager.close();release();const results=await Promise.all(requests);await closed;
 assert.equal(executions,4);assert.equal(results.filter(v=>v.status==='completed').length,4);assert.equal(results.filter(v=>v.status==='failed').length,2);
 await server.close();
});
test('canonical acknowledgement releases target capacity only after exact retirement receipt',async t=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'listing-manager-forget-'));await fs.chmod(directory,0o700);t.after(()=>fs.rm(directory,{recursive:true,force:true}));
 const namespace={checkReadiness:async()=>({ready:true,runtimeDigest:'a'.repeat(64)}),execute:async()=>{throw Error('No execution expected');}};
 const manager=await createListingsTargetManager({directory,origin:'http://127.0.0.1:8095',namespace}),a=binding(),b=binding();await manager.register(a);const sibling=await manager.register(b);const options={operationId:randomUUID(),canonicalReceiptSha256:'c'.repeat(64)};
 await assert.rejects(manager.forget(a,options),{code:'LISTINGS_FORGET_DENIED'});await manager.retire(a,options);
 await assert.rejects(manager.forget(a,{...options,canonicalReceiptSha256:'d'.repeat(64)}),{code:'LISTINGS_FORGET_DENIED'});
 assert.equal((await manager.forget(a,options)).replayed,false);assert.equal((await manager.forget(a,options)).replayed,true);
 assert.deepEqual(await manager.inspect(b),sibling);assert.deepEqual(await fs.readdir(directory),[b.targetId]);await manager.close();
});
