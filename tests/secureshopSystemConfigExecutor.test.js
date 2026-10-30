'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {EventEmitter}=require('node:events'),{PassThrough}=require('node:stream');
const {createSystemConfigExecutor,loadAssets,buildReadArgv,decodeRead,ASSET_HASHES,FIXTURES,ATTESTATION,INIT,SUPERVISOR,MAX_CAPTURE_BYTES}=require('../sidecars/sandbox-runner/owned-system/executor');
const {VERSION,ISOLATION,hash,normalizeRequest,requestDigest}=require('../sidecars/sandbox-runner/owned-system/contract');
const {readSyntheticConfig}=require('../sidecars/sandbox-runner/owned-system/config-reader');
const request={operationId:'11111111-1111-4111-8111-111111111111',path:'....//.env'},marker='__SYSTEM_CONFIG_'+'a'.repeat(64)+'__';
function envelope(req,readResult){return Buffer.concat([ATTESTATION,Buffer.from(marker+Buffer.from(JSON.stringify({version:VERSION,isolation:ISOLATION,operationId:req.operationId,requestSha256:requestDigest(req),readResult})).toString('base64'))]);}
function childFixture(run){let killed=[];let child;const spawnImpl=(binary,argv,options)=>{assert.equal(binary,SUPERVISOR);assert.deepEqual(options.env,{PATH:'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'});child=new EventEmitter();child.stdio=options.stdio.map(()=>new PassThrough());child.stdout=child.stdio[1];child.stderr=child.stdio[2];child.kill=signal=>{killed.push(signal);run?.kill?.(child,signal);};setImmediate(()=>run.start?.(child,argv));return child;};return {spawnImpl,killed,get child(){return child;}};}
test('closed request rejects caller roots/helper paths/files and malformed identities',()=>{
 for(const extra of [{root:'/private'},{worker:'/bin/sh'},{files:{}},{path:'\0'},{operationId:'fake'}])assert.throws(()=>normalizeRequest({...request,...extra}));
 assert.equal(normalizeRequest(request).path,'....//.env');
});
test('namespace exposes only fixed read-only synthetic files and checked code, no host app or private bind',()=>{
 assert.equal(Object.keys(loadAssets()).length,3);assert.throws(()=>loadAssets(()=>Buffer.from('tampered')),e=>e.code==='SYSTEM_CONFIG_ASSET_INVALID');
 const argv=buildReadArgv(request,marker,['/usr','/bin']);
 for(const flag of ['--unshare-net','--unshare-user','--unshare-pid','--clearenv','--die-with-parent'])assert.ok(argv.includes(flag));
 assert.equal(argv.filter(x=>x==='--ro-bind-data').length,3);assert.equal(argv.filter(x=>x==='--file').length,3);assert.ok(argv.includes('--remount-ro'));assert.equal(argv.includes('--bind'),false);assert.equal(argv.includes('--proc'),false);
 assert.ok(argv.includes('/app/.env'));assert.ok(argv.includes('/app/config/application.json'));assert.ok(argv.includes('/app/platform_secrets.json'));assert.equal(argv.includes('/home'),false);assert.ok(argv.includes(INIT));
 assert.equal(FIXTURES['/app/.env'],'SECURESHOP_SYSTEM_FIXTURE=true\nSYSTEM_SECRET=TRAINING-OWNED-SYSTEM-CONFIG-ONLY\n');
 assert.equal(FIXTURES['/app/config/application.json'],'{"application":"SecureShop owned System fixture","environment":"synthetic-only"}\n');
 assert.deepEqual(argv.slice(argv.indexOf(INIT,argv.indexOf('--hostname'))+1, -1),['--read',Buffer.from(JSON.stringify(request)).toString('base64')]);
});
test('real synthetic file reads including traversal correspond to outer known bytes; negative read is completed negative',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-system-reader-contract-'));try{
 fs.mkdirSync(path.join(root,'config'));for(const [target,content]of Object.entries(FIXTURES))fs.writeFileSync(path.join(root,target.slice('/app/'.length)),content);
 for(const input of ['application.json','....//.env','....//platform_secrets.json','platform_secrets.json','missing','/etc/passwd','....//....//etc/passwd','','application.json/nope']){
 const req={...request,path:input};const observation=readSyntheticConfig(root,input);const result=decodeRead(envelope(req,observation),marker,req);assert.deepEqual(result.readResult,observation);
 if(input==='....//.env'){assert.equal(observation.ok,true);assert.equal(observation.content,FIXTURES['/app/.env']);}
 if(input==='....//platform_secrets.json'){
  assert.equal(observation.ok,true);assert.equal(observation.targetPath,'/app/platform_secrets.json');
  assert.equal(observation.content,FIXTURES['/app/platform_secrets.json']);
  assert.deepEqual(JSON.parse(observation.content),{synthetic:true,api_key:'TRAINING-OWNED-SYSTEM-API-KEY-ONLY',session_token:'TRAINING-OWNED-SYSTEM-SESSION-TOKEN-ONLY'});
  for(const patch of [{content:'fabricated'},{contentSha256:hash('fabricated')},{targetPath:'/app/.env'},{size:1}])assert.throws(()=>decodeRead(envelope(req,{...observation,...patch}),marker,req));
 }
 }
 const read=readSyntheticConfig(root,request.path);for(const patch of [{content:'fabricated'},{contentSha256:hash('fabricated')},{targetPath:'/private/.env'},{ok:false}])assert.throws(()=>decodeRead(envelope(request,{...read,...patch}),marker,request));
 assert.throws(()=>decodeRead(envelope(request,read),marker,{...request,operationId:'22222222-2222-4222-8222-222222222222'}));
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
test('executor feeds every checked asset and synthetic fixture pipe including the credential file',async()=>{
 const req={...request,path:'....//platform_secrets.json'},content=FIXTURES['/app/platform_secrets.json'];
 const fixture=childFixture({start(child,argv){
  const inputs=[];for(let i=0;i<argv.length;i++)if(['--ro-bind-data','--file'].includes(argv[i]))inputs.push({fd:Number(argv[i+1]),target:argv[i+2]});
  assert.equal(child.stdio.length,10);assert.equal(inputs.length,6);
  const assets=loadAssets();for(const {fd,target}of inputs){const expected=target.startsWith('/opt/system-config/')?assets[path.basename(target)]:Buffer.from(FIXTURES[target]);assert.deepEqual(child.stdio[fd].read(),expected);}
  assert.deepEqual(inputs.at(-1),{fd:9,target:'/app/platform_secrets.json'});
  const observation={ok:true,input:req.path,sanitized:'../platform_secrets.json',targetPath:'/app/platform_secrets.json',size:Buffer.byteLength(content),content,contentSha256:hash(content)};
  child.stdout.write(envelope(req,observation).toString().replace(marker,argv.at(-1)));child.emit('close',0);
 }});
 const result=await createSystemConfigExecutor({...fixture,existsSync:()=>true,spawnSyncImpl:()=>({status:0})}).read(req);
 assert.equal(result.status,'completed');assert.equal(result.readResult.content,content);assert.equal(result.drained,true);
});
test('strict unavailable isolation does not dispatch or fall back',()=>{
 let dispatched=0;const executor=createSystemConfigExecutor({existsSync:()=>true,spawnSyncImpl:()=>({status:1}),spawnImpl:()=>dispatched++});assert.throws(()=>executor.read(request),e=>e.code==='SYSTEM_CONFIG_ISOLATION_UNAVAILABLE');assert.equal(dispatched,0);
});
test('completed worker receipt retains negative observation distinctly from isolation failure',async()=>{
 const req={...request,path:'missing'};const fixture=childFixture({start(child,argv){const actualMarker=argv.at(-1);const bytes=envelope(req,{ok:false,error:'config not found'}).toString().replace(marker,actualMarker);child.stdout.write(bytes);child.emit('close',0);}});
 const result=await createSystemConfigExecutor({...fixture,existsSync:()=>true,spawnSyncImpl:()=>({status:0})}).read(req);assert.equal(result.status,'completed');assert.equal(result.readResult.ok,false);assert.equal(result.drained,true);
});
test('timeout terminates supervisor then waits for close before resolving; forced drain unavailable',async()=>{
 const fixture=childFixture({kill(child,signal){if(signal==='SIGKILL')setImmediate(()=>child.emit('close',null));}});const promise=createSystemConfigExecutor({...fixture,existsSync:()=>true,spawnSyncImpl:()=>({status:0}),timeoutMs:100,drainGraceMs:100}).read(request);const result=await promise;assert.deepEqual(fixture.killed,['SIGTERM','SIGKILL']);assert.equal(result.status,'unavailable');assert.equal(result.timedOut,true);assert.equal(result.drained,false);assert.equal(result.readResult,undefined);
});
test('bounded capture stops supervisor and never accepts partial evidence',async()=>{
 const fixture=childFixture({start(child){child.stdout.write(Buffer.alloc(MAX_CAPTURE_BYTES+1,65));},kill(child){setImmediate(()=>child.emit('close',124));}});const result=await createSystemConfigExecutor({...fixture,existsSync:()=>true,spawnSyncImpl:()=>({status:0})}).read(request);assert.equal(result.status,'unavailable');assert.equal(result.truncated,true);assert.equal(result.readResult,undefined);
});
test('aborted request joins cooperative child before rejection and missing attestation rejects',async()=>{
 const controller=new AbortController();const fixture=childFixture({start(){controller.abort();},kill(child){setImmediate(()=>child.emit('close',124));}});await assert.rejects(createSystemConfigExecutor({...fixture,existsSync:()=>true,spawnSyncImpl:()=>({status:0})}).read(request,{signal:controller.signal}),e=>e.name==='AbortError');assert.deepEqual(fixture.killed,['SIGTERM']);assert.throws(()=>decodeRead(Buffer.from('{}'),marker,request));
});
