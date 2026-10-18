'use strict';
// Controlled native protocol providers exercise the consumer and real JS
// adapters. They do not execute PowerShell/C# or prove native OS behavior.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {prepareFreshEnvironmentPublication:prepare}=require('../scripts/lib/setup-environment-publication');
const {createWindowsPrivateState}=require('../scripts/lib/windows-private-state');
const {createWindowsPrivatePublication}=require('../scripts/lib/windows-private-publication');
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const denied={code:'SETUP_PUBLICATION_INVALID',message:'Private setup publication unavailable'};
const generated=['JWT_SECRET','SESSION_SECRET','IPI_MAIL_HMAC_SECRET'];
function controlled(){
 const root='C:\\workspace',directory='C:\\Users\\learner\\private',envPath=root+'\\.env';
 const options={root,directory,envPath,id:hash(root).slice(0,12),environment:{IDENTITY_DATABASE_URL:'postgres://synthetic:owned@localhost/test',AI_PROVIDER:'ollama'}};
 const intentPath=directory+'\\fresh-environment.publication.json',resultPath=intentPath+'.result';
 const files=new Map(),calls=[];let next=10,fault=null,privateDenied=false;
 const create=(name,bytes)=>{if(files.has(name))throw Error('controlled collision');const file={bytes:Buffer.from(bytes),identity:{volumeSerial:21,fileId:(++next).toString(16).padStart(16,'0')}};files.set(name,file);return file;};
 const record=file=>({identity:{...file.identity},bytes:file.bytes.toString('base64')});
 const matches=(file,expected)=>file&&expected&&file.identity.fileId===expected.identity.fileId&&file.identity.volumeSerial===expected.identity.volumeSerial&&file.bytes.toString('base64')===expected.bytes;
 const executeState=(exe,args,wire)=>{
  const r=JSON.parse(wire.input);calls.push(r);
  if(privateDenied)throw Error('synthetic private ACL failure');
  if(r.operation==='inspectPrivateDirectory'){
   if(r.path!==directory)throw Error('unadmitted private directory');
   return JSON.stringify({version:1,ok:true,operation:r.operation,path:r.path,size:null,identity:{volumeSerial:21,fileId:'0000000000000001'}});
  }
  if(r.operation!=='readPrivateFile')throw Error('unexpected private write');
  const f=files.get(r.path);if(!f||f.invalid)throw Error('synthetic private file authority failure');
  return JSON.stringify({version:1,ok:true,operation:r.operation,path:r.path,size:f.bytes.length,identity:f.identity,bytesBase64:f.bytes.toString('base64')});
 };
 const executePublication=(exe,args,wire)=>{
  const r=JSON.parse(wire.input);calls.push(r);if(privateDenied)throw Error('private authority denied');
  const stagePath=r.targetPath+'.dvaia-'+r.operationId+'.stage';let retained=files.get(r.intentPath),intent;
  if(!retained){
   if(r.operation!=='preparePrivatePublication'||r.originalBytesBase64!==null||files.has(r.targetPath))throw Error('fresh target conflict');
   const bytes=Buffer.from(r.resultBytesBase64,'base64');let result=files.get(r.intentPath+'.result'),stage=files.get(stagePath);
   if(!result)result=create(r.intentPath+'.result',bytes);else if(!result.bytes.equals(bytes))throw Error('retained result mismatch');
   if(fault==='prepare-flush'){fault=null;throw Error('synthetic retained payload flush failure');}
   if(!stage)stage=create(stagePath,bytes);else if(!stage.bytes.equals(bytes))throw Error('stage mismatch');
   if(fault==='prepare-before-intent'){fault=null;throw Error('synthetic before intent interruption');}
   intent={targetPath:r.targetPath,intentPath:r.intentPath,operationId:r.operationId,result:record(result),stage:record(stage)};
   retained=create(r.intentPath,Buffer.from(JSON.stringify(intent)));
  }else intent=JSON.parse(retained.bytes.toString());
  if(intent.targetPath!==r.targetPath||intent.intentPath!==r.intentPath||intent.operationId!==r.operationId||!matches(files.get(r.intentPath+'.result'),intent.result))throw Error('intent binding mismatch');
  let state;
  if(matches(files.get(r.targetPath),intent.stage)){if(files.has(stagePath))throw Error('unexpected stage');state='committed';}
  else{if(files.has(r.targetPath)||!matches(files.get(stagePath),intent.stage))throw Error('target changed');state='prepared';}
  if(r.operation==='preparePrivatePublication'&&(r.originalBytesBase64!==null||r.resultBytesBase64!==intent.result.bytes))throw Error('requested bytes conflict');
  if(r.operation==='publishPrivatePublication'&&state==='prepared'){
   if(fault==='publish-before-move'){fault=null;throw Error('synthetic before move interruption');}
   files.set(r.targetPath,files.get(stagePath));files.delete(stagePath);state='committed';
   if(fault==='publish-after-move'){fault=null;throw Error('synthetic after move acknowledgement loss');}
  }
  return JSON.stringify({version:1,ok:true,operation:r.operation,targetPath:r.targetPath,intentPath:r.intentPath,operationId:r.operationId,state,intentSha256:hash(retained.bytes),size:Buffer.from(intent.result.bytes,'base64').length,identity:intent.stage.identity});
 };
 const dependencies={platform:'win32',exists:p=>files.has(p),privateState:createWindowsPrivateState({platform:'win32',systemRoot:'C:\\Windows',execute:executeState}),publication:createWindowsPrivatePublication({platform:'win32',systemRoot:'C:\\Windows',execute:executePublication})};
 return {options,dependencies,files,calls,intentPath,resultPath,create,setFault:value=>{fault=value;},denyPrivate:()=>{privateDenied=true;},prepare:()=>prepare(options,dependencies)};
}

test('Windows fresh consumer retains private secrets before environment use and defers native publication',()=>{
 const f=controlled(),a=f.prepare();assert(Object.isFrozen(a));assert(Object.isFrozen(a.environment));
 assert(!f.files.has(f.options.envPath));assert(f.files.has(f.intentPath));assert(f.files.has(f.resultPath));
 for(const key of generated)assert.match(a.environment[key],/^[a-f0-9]{96}$/);
 const request=f.calls.find(r=>r.operation==='preparePrivatePublication');assert.equal(request.originalBytesBase64,null);
 assert.equal(request.targetPath,f.options.envPath);assert.equal(request.intentPath,f.intentPath);
 assert(!f.calls.some(r=>r.operation==='publishPrivatePublication'||r.operation==='createPrivateFile'));
 a.publish();assert.equal(f.calls.at(-1).operation,'publishPrivatePublication');
 assert(f.files.get(f.options.envPath).bytes.equals(f.files.get(f.resultPath).bytes));
 assert(!f.files.has(f.options.directory+'\\fresh-environment.pending.json'));
});

test('Windows repeated preparation preserves exact bytes, secrets and operation identity across configuration ordering',()=>{
 const f=controlled(),a=f.prepare(),retained=f.files.get(f.resultPath),intent=f.files.get(f.intentPath);
 const b=prepare({...f.options,environment:{AI_PROVIDER:'ollama',IDENTITY_DATABASE_URL:f.options.environment.IDENTITY_DATABASE_URL}},f.dependencies);
 assert.deepEqual(b.environment,a.environment);assert.equal(f.files.get(f.resultPath),retained);assert.equal(f.files.get(f.intentPath),intent);
 assert.equal(f.calls.filter(r=>r.operation==='preparePrivatePublication')[0].operationId,f.calls.filter(r=>r.operation==='preparePrivatePublication')[1].operationId);
});

test('Windows interrupted payload flush and pre-intent preparation retry reuse signing secrets without rotation',()=>{
 for(const fault of ['prepare-flush','prepare-before-intent']){
  const f=controlled();f.setFault(fault);assert.throws(()=>f.prepare(),denied);
  const retained=f.files.get(f.resultPath),bytes=Buffer.from(retained.bytes);assert(retained);assert(!f.files.has(f.intentPath));
  const retry=f.prepare();assert.equal(f.files.get(f.resultPath),retained);assert(retained.bytes.equals(bytes));
  for(const key of generated)assert(bytes.includes(Buffer.from(retry.environment[key])));
  retry.publish();assert(f.files.get(f.options.envPath).bytes.equals(bytes));
 }
});

test('Windows publication interruption before and after move recovers exact retained environment',()=>{
 for(const fault of ['publish-before-move','publish-after-move']){
  const f=controlled(),a=f.prepare(),bytes=Buffer.from(f.files.get(f.resultPath).bytes);f.setFault(fault);
  assert.throws(()=>a.publish(),denied);const prior=f.files.get(f.options.envPath);
  const b=f.prepare();assert.deepEqual(b.environment,a.environment);b.publish();assert(f.files.get(f.options.envPath).bytes.equals(bytes));
  if(prior)assert.equal(f.files.get(f.options.envPath),prior);
  a.publish();assert(f.files.get(f.options.envPath).bytes.equals(bytes));
 }
});

test('Windows requested configuration conflicts preserve private recovery artifacts and do not publish',()=>{
 const f=controlled();f.prepare();const retained=f.files.get(f.resultPath),bytes=Buffer.from(retained.bytes);
 for(const environment of [{...f.options.environment,AI_PROVIDER:'other'},{AI_PROVIDER:'ollama'},{...f.options.environment,EXTRA:'value'},{...f.options.environment,JWT_SECRET:'a'.repeat(96)}]){
  assert.throws(()=>prepare({...f.options,environment},f.dependencies),denied);assert.equal(f.files.get(f.resultPath),retained);assert(retained.bytes.equals(bytes));
 }
 assert(!f.files.has(f.options.envPath));
});

test('Windows malformed/partial/noncanonical retained payloads fail without rewriting secrets or target',()=>{
 for(const bytes of [Buffer.from('{partial'),Buffer.from('JWT_SECRET="bad"\n'),Buffer.from([0xff]),Buffer.from('AI_PROVIDER="ollama"\nAI_PROVIDER="ollama"\n'),Buffer.alloc(1024*1024+1)]){
  const f=controlled(),retained=f.create(f.resultPath,bytes);assert.throws(()=>f.prepare(),denied);assert.equal(f.files.get(f.resultPath),retained);
  assert(!f.files.has(f.intentPath));assert(!f.files.has(f.options.envPath));assert(!f.calls.some(r=>r.operation==='preparePrivatePublication'));
 }
 const f=controlled();f.prepare();const retained=f.files.get(f.resultPath);retained.bytes=Buffer.from(retained.bytes.toString().replace('AI_PROVIDER="ollama"','AI_PROVIDER= "ollama"'));
 assert.throws(()=>f.prepare(),denied);assert(!f.files.has(f.options.envPath));
});

test('Windows existing environment is never adopted or overwritten without retained immutable authority',()=>{
 const f=controlled(),operator=f.create(f.options.envPath,Buffer.from('operator bytes'));assert.throws(()=>f.prepare(),denied);assert.equal(f.files.get(f.options.envPath),operator);assert(!f.files.has(f.resultPath));
 const other=controlled(),a=other.prepare();other.create(other.options.envPath,Buffer.from('operator bytes'));
 assert.throws(()=>a.publish(),denied);assert.equal(other.files.get(other.options.envPath).bytes.toString(),'operator bytes');
});

test('Windows directory/file authority failures, changed receipt and payload tamper refuse deferred publication',()=>{
 const acl=controlled(),a=acl.prepare();acl.denyPrivate();assert.throws(()=>a.publish(),denied);assert(!acl.files.has(acl.options.envPath));
 const payload=controlled(),b=payload.prepare();payload.files.get(payload.resultPath).bytes[0]^=1;assert.throws(()=>b.publish(),denied);assert(!payload.files.has(payload.options.envPath));
 const changed=controlled(),c=changed.prepare(),retained=changed.files.get(changed.intentPath);retained.bytes=Buffer.from(retained.bytes.toString()+' ');
 assert.throws(()=>c.publish(),denied);assert(!changed.calls.some(r=>r.operation==='publishPrivatePublication'));assert(!changed.files.has(changed.options.envPath));
 const wrongFile=controlled();wrongFile.prepare();wrongFile.files.get(wrongFile.resultPath).invalid=true;assert.throws(()=>wrongFile.prepare(),denied);
});

test('Windows paths, workspace binding and payload bound reject before any native publication',()=>{
 const f=controlled();for(const override of [{root:'C:\\workspace\\..\\other'},{envPath:'C:\\other\\.env'},{directory:'\\\\host\\share'},{id:'000000000000'},{environment:{VALUE:'x'.repeat(1024*1024)}},{environment:{AI_PROVIDER:'ollama\nsecret'}},{root:'C:\\'+ 'w'.repeat(192),envPath:'C:\\'+ 'w'.repeat(192)+'\\.env'}]){
  assert.throws(()=>prepare({...f.options,...override},f.dependencies),denied);
 }
 assert(!f.calls.some(r=>r.operation==='preparePrivatePublication'));assert.equal(f.files.size,0);
});

test('Windows legacy POSIX journal/staging and missing retained payload refuse new recovery state',()=>{
 for(const name of ['C:\\Users\\learner\\private\\fresh-environment.pending.json','C:\\workspace\\.env.setup-publication']){
  const f=controlled(),retained=f.create(name,Buffer.from('legacy retained data'));assert.throws(()=>f.prepare(),denied);assert.equal(f.files.get(name),retained);assert(!f.files.has(f.resultPath));
 }
 const f=controlled();f.prepare();f.files.delete(f.resultPath);assert.throws(()=>f.prepare(),denied);assert(!f.files.has(f.options.envPath));
});

test('Windows native errors containing payloads are scrubbed at the setup boundary',()=>{
 const f=controlled();f.dependencies.publication={preparePrivatePublication(){throw Object.assign(Error('synthetic secret'),{stderr:'synthetic secret'});}};
 assert.throws(()=>f.prepare(),error=>{assert.equal(error.code,denied.code);assert.equal(error.message,denied.message);assert.deepEqual(Object.keys(error),['code']);assert(!String(error.stack).includes('synthetic secret'));return true;});
});

test('Windows consumer does not invoke POSIX create/chmod/fsync/link authority',()=>{
 const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),file=path.resolve(__dirname,'../scripts/lib/setup-environment-publication.js');
 const module={exports:{}};let posixCalls=0;
 const forbidden=new Proxy({}, {get(){return()=>{posixCalls++;throw Error('POSIX filesystem authority forbidden');};}});
 vm.runInNewContext(fs.readFileSync(file,'utf8'),{module,exports:module.exports,process,Buffer,require:n=>n==='node:fs'?forbidden:n.startsWith('./')?require(path.resolve(path.dirname(file),n)):require(n)});
 const f=controlled(),prepared=module.exports.prepareFreshEnvironmentPublication(f.options,f.dependencies);prepared.publish();
 assert.equal(posixCalls,0);assert(f.files.has(f.options.envPath));
});
