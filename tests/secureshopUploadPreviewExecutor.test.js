'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process'),{EventEmitter}=require('node:events'),{PassThrough}=require('node:stream');
const C=require('../sidecars/sandbox-runner/owned-system/upload-preview-contract');
const W=require('../sidecars/sandbox-runner/owned-system/upload-preview-worker');
const E=require('../sidecars/sandbox-runner/owned-system/upload-preview-executor');
const D=require('../sidecars/sandbox-runner/owned-system/upload-preview-dependencies');
const sharp=require('sharp');
const GIF=Buffer.from('47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b','hex');
const POLYGLOT=Buffer.from('4749463839612f2a0100800000000000ffffff21f90401000000002c00000000010001000002024401003b2a2f3d313b766f696420303b0a','hex');
const id=n=>`70000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const runtime={nodeVersion:'v26.10.0',platform:'linux',arch:'x64'};
const request=(bytes=POLYGLOT,mode='vuln')=>({version:1,operationId:id(1),uploadOperationId:id(2),uploadEffectId:id(3),storageKey:id(4),
 bindingSha256:'a'.repeat(64),uploadRequestSha256:'b'.repeat(64),bodySha256:C.hash(bytes),byteCount:bytes.length,bytesBase64:bytes.toString('base64'),mode});

test('closed preview request binds original operation, storage, complete bytes and mode',()=>{
 const raw=request();assert.deepEqual(C.normalizeUploadPreviewRequest(raw),raw);
 for(const patch of [{extra:true},{mode:'other'},{byteCount:0},{byteCount:raw.byteCount+1},{bytesBase64:raw.bytesBase64+'\n'},
  {bodySha256:'f'.repeat(64)},{storageKey:'../file'},{operationId:raw.operationId.toUpperCase()},{bytesBase64:'!!!!'}]){
  if(patch.operationId===raw.operationId)continue;
  assert.throws(()=>C.normalizeUploadPreviewRequest({...raw,...patch}));
 }
 assert.notEqual(C.requestDigest(raw),C.requestDigest({...raw,mode:'fixed'}));
 assert.notEqual(C.requestDigest(raw),C.requestDigest({...raw,operationId:id(5)}));
 assert.throws(()=>C.normalizeUploadPreviewRequest(request(Buffer.alloc(C.MAX_INPUT_BYTES+1))));
});

test('real sharp fully decodes retained GIF/JS with logical and frame bounds, without executing it',async()=>{
 const decoded=await W.decodeGif(POLYGLOT),ordinary=await W.decodeGif(GIF);
 assert.equal(decoded.decoder.logicalWidth,10799);assert.equal(decoded.decoder.logicalHeight,1);
 assert.equal(decoded.decoder.width,1);assert.equal(decoded.decoder.height,1);assert.equal(decoded.decoder.pages,1);
 assert.equal(decoded.decoder.rawByteCount,4);assert.equal(decoded.decoder.rawSha256,ordinary.decoder.rawSha256);
 assert.equal(decoded.decoder.sharpVersion,'0.35.4');
 // Syntax-only feasibility uses the real parser; never run uploaded bytes on
 // this host. Actual code execution is exclusively a native namespace gate.
 const parsed=spawnSync(process.execPath,['--check','--input-type=commonjs'],{input:POLYGLOT,timeout:2000,maxBuffer:8192});
 assert.equal(parsed.status,0);assert.equal(parsed.stdout.length,0);
 assert.throws(()=>W.assertNamespace());
});

test('malformed, truncated, animated and oversized logical GIF inputs cannot reach Node',async()=>{
 const large=Buffer.from(POLYGLOT);large.writeUInt16LE(16385,6);
 const area=Buffer.from(POLYGLOT);area.writeUInt16LE(16384,6);area.writeUInt16LE(16384,8);
 const animated=Buffer.concat([GIF.subarray(0,-1),GIF.subarray(19,-1),GIF.subarray(-1)]);
 assert.equal((await sharp(animated,{animated:true}).metadata()).pages,2);
 for(const bytes of [Buffer.from('GIF89a'),GIF.subarray(0,35),Buffer.from('not an image'),large,area,animated]){
  let calls=0;const result=await W.processPreview(request(bytes),{measuredRuntime:runtime,execute:async()=>{calls++;throw Error('Unexpected interpreter');}});
  assert.equal(result.status,'invalid_image');assert.equal(result.decoder,null);assert.equal(calls,0);
  assert.equal(result.originalInterpreterStarted,false);assert.equal(result.scriptSyntaxValid,null);
  assert.doesNotThrow(()=>C.validateUploadPreviewReceipt(result,request(bytes)));
 }
});

test('vulnerable dispatch preserves exact file bytes and ordinary images remain image-only',async()=>{
 let calls=0;
 // Controlled process responses test dispatch order only, never RCE or credit.
 const result=await W.processPreview(request(),{measuredRuntime:runtime,execute:async(bytes,{syntax})=>{
  assert.deepEqual(bytes,POLYGLOT);assert.equal(syntax,calls++===0);return{started:true,exitCode:0,timedOut:false,truncated:false};}});
 assert.equal(calls,2);assert.equal(result.status,'executed');assert.equal(result.codeEffectObserved,false);
 assert.doesNotThrow(()=>C.validateUploadPreviewReceipt(result,request()));
 const ordinary=await W.processPreview(request(GIF),{measuredRuntime:runtime,execute:async(_bytes,{syntax})=>{
  assert.equal(syntax,true);return{started:true,exitCode:1,timedOut:false,truncated:false};}});
 assert.equal(ordinary.status,'image_only');assert.equal(ordinary.originalInterpreterStarted,false);
 await assert.rejects(W.processPreview(request(),{bytes:GIF,measuredRuntime:runtime}));
 for(const stopped of [{started:false,exitCode:null,timedOut:false,truncated:false},
  {started:true,exitCode:null,timedOut:true,truncated:false},{started:true,exitCode:1,timedOut:false,truncated:true}]){
  const failed=await W.processPreview(request(),{measuredRuntime:runtime,execute:async()=>stopped});
  assert.equal(failed.status,'failed');assert.equal(failed.originalInterpreterStarted,false);
 }
});

test('Fixed fully reconstructs a PNG and never parses or executes original Node bytes',async()=>{
 let calls=0;const raw=request(POLYGLOT,'fixed');
 const result=await W.processPreview(raw,{measuredRuntime:runtime,execute:async()=>{calls++;throw Error('Fixed must not dispatch original');}});
 assert.equal(calls,0);assert.equal(result.status,'fixed_reencoded');assert.equal(result.scriptSyntaxValid,null);
 assert.equal(result.originalInterpreterStarted,false);assert.equal(result.reencoded.format,'png');
 assert.notEqual(result.reencoded.bodySha256,raw.bodySha256);assert.doesNotThrow(()=>C.validateUploadPreviewReceipt(result,raw));
 const bad=structuredClone(result);bad.originalInterpreterStarted=true;assert.throws(()=>C.validateUploadPreviewReceipt(bad,raw));
});

test('closed receipt rejects changed identity, decoder, runtime, interpreter and effect claims',async()=>{
 const raw=request(),receipt=await W.processPreview(raw,{measuredRuntime:runtime,
  execute:async()=>({started:true,exitCode:0,timedOut:false,truncated:false})});
 for(const change of [r=>{r.extra=true;},r=>{r.operationId=id(90);},r=>{r.requestSha256='f'.repeat(64);},
  r=>{r.bodySha256='e'.repeat(64);},r=>{r.mode='fixed';},r=>{r.runtime.platform='darwin';},
  r=>{r.decoder.pages=2;},r=>{r.decoder.logicalWidth=16385;},r=>{r.decoder.rawByteCount++;},
  r=>{r.decoder.rawSha256='bad';},r=>{r.originalInterpreterStarted=false;},r=>{r.scriptSyntaxValid=false;},
  r=>{r.exitCode=1;},r=>{r.workerAttested=false;},r=>{r.drained=false;},r=>{r.timedOut=true;},
  r=>{r.codeEffectObserved=true;},r=>{r.effectSha256='d'.repeat(64);},r=>{r.reencoded={format:'png'};}]){
  const value=structuredClone(receipt);change(value);assert.throws(()=>C.validateUploadPreviewReceipt(value,raw));
 }
 const observed={...receipt,codeEffectObserved:true,effectSha256:'d'.repeat(64)};
 assert.doesNotThrow(()=>C.validateUploadPreviewReceipt(observed,raw),'Schema consistency is not independent physical observation authority');
});

test('RGBA and reencoded output bounds remain enforced after decoder metadata',async()=>{
 const broken=()=>({metadata:async()=>({format:'gif',pages:1,width:1,height:1}),ensureAlpha(){return this;},raw(){return this;},
  toBuffer:async()=>({data:Buffer.alloc(5),info:{channels:4,width:1,height:1}})});
 Object.assign(broken,{versions:sharp.versions,cache(){},concurrency(){}});
 await assert.rejects(W.decodeGif(GIF,broken));
 const huge=(...args)=>args[1]?.raw?{png(){return this;},toBuffer:async()=>Buffer.alloc(C.MAX_REENCODE_BYTES+1)}:sharp(...args);
 Object.assign(huge,{versions:sharp.versions,cache:sharp.cache,concurrency:sharp.concurrency});
 assert.equal((await W.processPreview(request(GIF,'fixed'),{sharp:huge,measuredRuntime:runtime})).status,'failed');
});

test('external effect observer checks actual exact file bytes, ownership, mode and no-follow identity',t=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-preview-observer-'));t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 const effect=path.join(directory,'command-effect'),canary=Buffer.from('owned unpredictable observer sample'),options={expectedUid:process.getuid()};
 assert.deepEqual(E.observeEffect(directory,canary,options),{codeEffectObserved:false,effectSha256:null});
 fs.writeFileSync(effect,canary,{mode:0o600});
 assert.deepEqual(E.observeEffect(directory,canary,options),{codeEffectObserved:true,effectSha256:C.hash(canary)});
 fs.chmodSync(effect,0o644);assert.throws(()=>E.observeEffect(directory,canary,options));fs.chmodSync(effect,0o600);
 assert.throws(()=>E.observeEffect(directory,canary,{expectedUid:process.getuid()+1}));
 fs.writeFileSync(effect,Buffer.alloc(canary.length,65));assert.equal(E.observeEffect(directory,canary,options).codeEffectObserved,false);
 fs.linkSync(effect,path.join(directory,'other'));assert.throws(()=>E.observeEffect(directory,canary,options));fs.unlinkSync(path.join(directory,'other'));
 fs.unlinkSync(effect);fs.symlinkSync('/dev/null',effect);assert.throws(()=>E.observeEffect(directory,canary,options));
 fs.unlinkSync(effect);assert.equal(spawnSync('/usr/bin/mkfifo',[effect],{timeout:1000}).status,0);
 let opened=false;const checkedFs={...fs,openSync(){opened=true;throw Error('FIFO must be rejected before open');}};
 assert.throws(()=>E.observeEffect(directory,canary,{...options,filesystem:checkedFs}));assert.equal(opened,false);
});

test('namespace argv uses bounded FD source, private effect mount and unchanged strict supervisor family',()=>{
 const marker='__UPLOAD_PREVIEW_'+'a'.repeat(64)+'__';
 const argv=E.buildPreviewArgv({marker,canaryPath:'/owned/canary',effectDirectory:'/owned/effect'});
 for(const flag of ['--unshare-user','--unshare-net','--unshare-pid','--unshare-uts','--unshare-ipc','--die-with-parent','--clearenv'])assert(argv.includes(flag));
 assert(argv.includes('--ro-bind-data'));assert(argv.includes('/preview/original.gif'));assert(argv.includes('/preview/request.json'));
 assert(!argv.includes('--proc'));assert(!argv.includes('/bin/sh'));assert(!argv.includes(request().bytesBase64));
 const probe=E.buildPreviewArgv({marker,probe:true});assert(!probe.includes('/effect'));assert(!probe.includes('/preview/canary'));
 // --remount-ro requires an actual mountpoint even for the no-input probe.
 // A plain --dir caused the real bwrap readiness failure before worker startup.
 for(const args of [argv,probe]){
  const mount=args.findIndex((value,index)=>value==='--tmpfs'&&args[index+1]==='/preview');
  const remount=args.findIndex((value,index)=>value==='--remount-ro'&&args[index+1]==='/preview');
  assert.ok(mount>=0&&remount>mount);
  assert.equal(args.some((value,index)=>value==='--dir'&&args[index+1]==='/preview'),false);
 }
 assert.equal(probe.at(-1),'--probe');assert.equal(E.SUPERVISOR,'/usr/local/libexec/dvaia-system-config-supervisor');
 assert.throws(()=>E.buildPreviewArgv({marker:'caller marker',probe:true}));
});

function executorFixture(t,{changed=false,outputLimit=false,abort=false}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-preview-parent-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const manifest={runtime,sharpVersion:'0.35.4',vipsVersion:sharp.versions.vips};let dispatches=0,probes=0;
 const executor=E.createUploadPreviewExecutor({root,verify:()=>manifest,
  spawnSyncImpl(_file,argv){probes++;const marker=argv.at(-2);return{status:0,stdout:Buffer.concat([E.ATTESTATION,Buffer.from(marker+JSON.stringify({ready:true,isolation:C.ISOLATION,...manifest}))])};},
  spawnImpl(_file,argv){dispatches++;const child=new EventEmitter();child.stdio=Array.from({length:5},()=>new PassThrough());child.stdout=child.stdio[1];child.stderr=child.stdio[2];
   child.kill=()=>{setImmediate(()=>child.emit('close',124));return true;};
   setImmediate(async()=>{
    if(abort){abort.abort();return;}
    if(outputLimit){child.stderr.write(Buffer.alloc(C.MAX_OUTPUT_BYTES+1));return;}
    const chunks=[];for await(const chunk of child.stdio[3])chunks.push(chunk);const raw=JSON.parse(Buffer.concat(chunks));
    const receipt=await W.processPreview(raw,{measuredRuntime:runtime,execute:async()=>({started:true,exitCode:1,timedOut:false,truncated:false})});
    if(changed)receipt.bodySha256='f'.repeat(64);
    child.stdout.write(Buffer.concat([E.ATTESTATION,Buffer.from(argv.at(-1)+JSON.stringify(receipt))]));child.emit('close',0);
   });return child;
  }});
 return{executor,root,get dispatches(){return dispatches;},get probes(){return probes;}};
}

test('real decoder producer crosses strict parent framing with exact FD request and terminal cleanup',async t=>{
 const f=executorFixture(t);assert.deepEqual(f.executor.assertReady(),{ready:true,isolation:C.ISOLATION});assert.equal(f.dispatches,0);
 const result=await f.executor.preview(request());assert.equal(result.status,'image_only');assert.equal(result.codeEffectObserved,false);
 assert.equal(f.probes,1);assert.equal(f.dispatches,1);assert.deepEqual(fs.readdirSync(f.root),[]);
});
test('changed worker correspondence and bounded process output fail closed and clean drained operations',async t=>{
 for(const options of [{changed:true},{outputLimit:true}]){
  const f=executorFixture(t,options);await assert.rejects(f.executor.preview(request()));assert.deepEqual(fs.readdirSync(f.root),[]);
 }
 const marker='__UPLOAD_PREVIEW_'+'a'.repeat(64)+'__';
 for(const bytes of [Buffer.from('{}'),Buffer.concat([E.ATTESTATION,Buffer.from(marker+'{}\n')]),
  Buffer.concat([E.ATTESTATION,Buffer.from('foreign{}')])])assert.throws(()=>E.decodeWorkerOutput(bytes,marker));
 const aborted=new AbortController(),f=executorFixture(t,{abort:aborted});
 await assert.rejects(f.executor.preview(request(),{signal:aborted.signal}),{code:'UPLOAD_PREVIEW_ABORTED'});
 assert.deepEqual(fs.readdirSync(f.root),[]);
});

test('minimal Linux runtime package lock is exactly derived from existing integrity-pinned dependencies',async()=>{
 const original=require('../package-lock.json'),derived=D.deriveRuntimeLock(original);
 assert.deepEqual(require('../sidecars/sandbox-runner/owned-system/upload-preview-runtime/package.json'),derived.manifest);
 assert.deepEqual(require('../sidecars/sandbox-runner/owned-system/upload-preview-runtime/package-lock.json'),derived.lock);
 for(const [name,record]of Object.entries(derived.lock.packages))if(name)assert.deepEqual(record,original.packages[name]);
 for(const name of ['sharp','@img/colour','detect-libc','semver','@img/sharp-linux-x64','@img/sharp-libvips-linux-x64'])assert(derived.lock.packages['node_modules/'+name]);
 assert.equal(Object.hasOwn(derived.lock.packages,'node_modules/sqlite3'),false);
 assert.throws(()=>D.deriveRuntimeLock({lockfileVersion:3,packages:{}}));
 await assert.rejects(D.buildRuntimeManifest(),'Linux native package proof cannot be fabricated on this host');
});
