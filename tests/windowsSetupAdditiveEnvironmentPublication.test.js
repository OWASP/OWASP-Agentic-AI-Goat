'use strict';
// Consumer and actual JS adapters run against bounded controlled protocol
// providers. Interrupted-state cases describe that provider; C# is not run.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{createRequire}=require('node:module');
const {prepareAdditiveEnvironmentPublication:prepare,readAdditiveEnvironmentPublication:readRetained}=require('../scripts/lib/setup-additive-environment-publication');
const {createWindowsPrivateState}=require('../scripts/lib/windows-private-state');
const {createWindowsPrivatePublication}=require('../scripts/lib/windows-private-publication');
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const operationId='11111111-2222-4333-8444-555555555555',denial={code:'SETUP_ADDITIVE_PUBLICATION_INVALID',message:'Private additive publication unavailable'};
function fixture(){
 const root='C:\\workspace',directory='C:\\Users\\Learner\\private',envPath=root+'\\.env',originalBytes=Buffer.from('JWT_SECRET="synthetic retained"');
 const args={root,directory,id:hash(root).slice(0,12),operationId,originalBytes,encodedAdditions:'NEW_KEY="synthetic new"\n'},journal=directory+`\\additive-environment-${operationId}.json`;
 const files=new Map(),calls=[];let index=1,fault,unsafe=false;
 const create=(name,bytes)=>{if(files.has(name))throw Error('controlled exclusive collision');const file={bytes:Buffer.from(bytes),identity:{volumeSerial:23,fileId:(++index).toString(16).padStart(16,'0')}};files.set(name,file);return file;};
 create(envPath,originalBytes);
 const record=file=>file?{bytes:file.bytes.toString('base64'),identity:{...file.identity}}:null;
 const matches=(file,bound)=>Boolean(file&&bound&&file.bytes.toString('base64')===bound.bytes&&file.identity.fileId===bound.identity.fileId&&file.identity.volumeSerial===bound.identity.volumeSerial);
 const executePrivate=(exe,argv,wire)=>{
  const r=JSON.parse(wire.input);calls.push(r);if(unsafe)throw Error('synthetic native private authority denial');
  if(r.operation==='inspectPrivateDirectory')return JSON.stringify({version:1,ok:true,operation:r.operation,path:r.path,size:null,identity:{volumeSerial:23,fileId:'0000000000000001'}});
  if(!['readPrivateFile','readPrivateWorkspaceFile'].includes(r.operation)||!files.has(r.path))throw Error('controlled file unavailable');
  const file=files.get(r.path);if(file.invalid)throw Error('controlled unsafe private read');
  return JSON.stringify({version:1,ok:true,operation:r.operation,path:r.path,size:file.bytes.length,identity:file.identity,bytesBase64:file.bytes.toString('base64')});
 };
 const executePublication=(exe,argv,wire)=>{
  const r=JSON.parse(wire.input);calls.push(r);if(unsafe)throw Error('synthetic native authority denial');
  const kind=r.targetPath===journal?'journal':'environment',stagePath=r.targetPath+`.dvaia-${r.operationId}.stage`,oldPath=r.intentPath+'.original',resultPath=r.intentPath+'.result';
  let intentFile=files.get(r.intentPath),intent,current=files.get(r.targetPath),old=files.get(oldPath),result=files.get(resultPath),stage=files.get(stagePath);
  if(!intentFile){
   if(r.operation!=='preparePrivatePublication')throw Error('intent required');
   const original=r.originalBytesBase64===null?null:Buffer.from(r.originalBytesBase64,'base64'),requested=Buffer.from(r.resultBytesBase64,'base64');
   if(current?!original||!current.bytes.equals(original):original!==null)throw Error('exact prior required');
   if(current){if(!old)old=create(oldPath,current.bytes);else if(!old.bytes.equals(current.bytes))throw Error('old backup mismatch');}else if(old)throw Error('unexpected old backup');
   if(!result)result=create(resultPath,requested);else if(!result.bytes.equals(requested))throw Error('result conflict');
   if(!stage)stage=create(stagePath,requested);else if(!stage.bytes.equals(requested))throw Error('stage conflict');
   if(fault===kind+'-before-intent'){fault=null;throw Error('controlled before intent failure');}
   intent={targetPath:r.targetPath,intentPath:r.intentPath,operationId:r.operationId,original:record(current),old:record(old),result:record(result),stage:record(stage)};
   intentFile=create(r.intentPath,Buffer.from(JSON.stringify(intent)));
  }else intent=JSON.parse(intentFile.bytes.toString());
  if(intent.targetPath!==r.targetPath||intent.intentPath!==r.intentPath||intent.operationId!==r.operationId||!matches(result,intent.result)||(intent.old?!matches(old,intent.old):old!==undefined))throw Error('immutable intent mismatch');
  let state;
  if(matches(current,intent.stage)){if(stage)throw Error('unexpected committed stage');state='committed';}
  else{if(intent.original?!matches(current,intent.original):current!==undefined)throw Error('old identity mismatch');if(!matches(stage,intent.stage)||stage.bytes.toString('base64')!==intent.result.bytes)throw Error('stage mismatch');state='prepared';}
  if(r.operation==='preparePrivatePublication'&&(r.resultBytesBase64!==intent.result.bytes||(intent.original?r.originalBytesBase64!==intent.original.bytes:r.originalBytesBase64!==null)))throw Error('requested bytes mismatch');
  if(fault===kind+'-flush'){fault=null;throw Error('controlled retained flush failure');}
  if(r.operation==='publishPrivatePublication'&&state==='prepared'){
   if(fault===kind+'-before-move'){fault=null;throw Error('controlled before move failure');}
   files.set(r.targetPath,stage);files.delete(stagePath);state='committed';
   if(fault===kind+'-after-move'){fault=null;throw Error('controlled lost promotion acknowledgement');}
  }
  return JSON.stringify({version:1,ok:true,operation:r.operation,targetPath:r.targetPath,intentPath:r.intentPath,operationId:r.operationId,state,intentSha256:hash(intentFile.bytes),size:Buffer.from(intent.result.bytes,'base64').length,identity:intent.stage.identity});
 };
 const dependencies={platform:'win32',realpath:p=>p,exists:p=>files.has(p),privateState:createWindowsPrivateState({platform:'win32',systemRoot:'C:\\Windows',execute:executePrivate}),publication:createWindowsPrivatePublication({platform:'win32',systemRoot:'C:\\Windows',execute:executePublication})};
 return {args,dependencies,files,calls,journal,envPath,create,prepare:()=>prepare(args,undefined,dependencies),bound:()=>({root,directory,id:args.id,operationId,journalSha256:hash(files.get(journal).bytes)}),setFault:f=>{fault=f;},deny:()=>{unsafe=true;}};
}

test('Windows additive retains exact existing JSON journal and publishes only after deferred call',()=>{
 const f=fixture(),publication=f.prepare(),result=publication.resultBytes;
 const expected=Buffer.from(JSON.stringify({version:1,kind:'additive',root:f.args.root,directory:f.args.directory,id:f.args.id,operationId,envPath:f.envPath,original:f.args.originalBytes.toString('base64'),result:result.toString('base64')})+'\n');
 assert(f.files.get(f.journal).bytes.equals(expected));assert(f.files.get(f.envPath).bytes.equals(f.args.originalBytes));
 assert(f.files.has(f.journal+'.native-journal'));assert(f.files.has(f.journal+'.native-environment.original'));assert(f.files.has(f.journal+'.native-environment.result'));
 assert.equal(f.calls.filter(r=>r.operation==='publishPrivatePublication').length,1);assert.equal(f.calls.find(r=>r.operation==='publishPrivatePublication').targetPath,f.journal);
 const stage=f.files.get(f.envPath+`.dvaia-${operationId}.stage`);publication.resultBytes.fill(0);f.args.originalBytes.fill(0);
 publication.publish();assert.equal(f.files.get(f.envPath),stage);assert(f.files.get(f.envPath).bytes.equals(result));
 assert(Object.isFrozen(publication));assert(!f.files.has(f.args.root+'\\.env.upgrade'));
});

test('Windows additive native journal interruption before/after promotion or retained flush failure reuses all exact bytes',()=>{
 for(const fault of ['journal-before-intent','journal-before-move','journal-after-move','journal-flush']){
  const f=fixture();f.setFault(fault);assert.throws(()=>f.prepare(),denial);assert(f.files.get(f.envPath).bytes.equals(f.args.originalBytes));
  const retained=[...f.files.entries()].filter(([name])=>name!==f.envPath).map(([name,file])=>[name,file,Buffer.from(file.bytes)]);
  const p=f.prepare();for(const [name,file,bytes]of retained){if(f.files.has(name))assert.equal(f.files.get(name),file);assert(file.bytes.equals(bytes));}
  p.publish();assert(f.files.get(f.envPath).bytes.equals(p.resultBytes));
 }
});

test('Windows additive environment preparation and before/after-promotion interruptions recover via externally bound journal',()=>{
 for(const fault of ['environment-before-intent','environment-flush','environment-before-move','environment-after-move']){
  const f=fixture();if(fault.includes('intent')||fault.includes('flush')){f.setFault(fault);assert.throws(()=>f.prepare(),denial);}
  else{const p=f.prepare();f.setFault(fault);assert.throws(()=>p.publish(),denial);}
  const bound=f.bound(),old=f.files.get(f.envPath),recovered=readRetained(bound,f.dependencies),result=recovered.resultBytes;
  recovered.originalBytes.fill(0);recovered.resultBytes.fill(0);assert(recovered.originalBytes.equals(f.args.originalBytes));assert(recovered.resultBytes.equals(result));
  recovered.publish();assert(f.files.get(f.envPath).bytes.equals(result));if(fault==='environment-after-move')assert.equal(f.files.get(f.envPath),old);
  const committed=f.files.get(f.envPath);readRetained(bound,f.dependencies).publish();assert.equal(f.files.get(f.envPath),committed);
 }
});

test('Windows additive externally provided digest rejects before any native intent rebuild or publication',()=>{
 const f=fixture();f.prepare();const count=f.calls.length,bytes=Buffer.from(f.files.get(f.envPath).bytes);
 assert.throws(()=>readRetained({...f.bound(),journalSha256:'0'.repeat(64)},f.dependencies),denial);
 assert(f.calls.slice(count).every(r=>r.operation==='inspectPrivateDirectory'||r.operation==='readPrivateFile'));assert(f.files.get(f.envPath).bytes.equals(bytes));
 f.files.get(f.journal).bytes=Buffer.from(f.files.get(f.journal).bytes.toString()+' ');const changed=f.bound(),before=f.calls.length;
 assert.throws(()=>readRetained(changed,f.dependencies),denial);assert(!f.calls.slice(before).some(r=>/Publication$/.test(r.operation)));
});

test('Windows additive conflicts preserve original target, private journal and native authority',()=>{
 const f=fixture(),p=f.prepare(),journal=f.files.get(f.journal),bytes=Buffer.from(journal.bytes);
 assert.throws(()=>prepare({...f.args,encodedAdditions:'OTHER="conflict"\n'},undefined,f.dependencies),denial);assert.equal(f.files.get(f.journal),journal);assert(journal.bytes.equals(bytes));
 f.files.delete(f.envPath);const conflicting=f.create(f.envPath,Buffer.from('operator bytes'));assert.throws(()=>p.publish(),denial);assert.equal(f.files.get(f.envPath),conflicting);
 const same=fixture(),q=same.prepare(),old=Buffer.from(same.files.get(same.envPath).bytes);same.files.delete(same.envPath);const changed=same.create(same.envPath,old);
 assert.throws(()=>q.publish(),denial);assert.equal(same.files.get(same.envPath),changed);
});

test('Windows additive packed journal bound denies before mutations without weakening individual payload limits',()=>{
 const f=fixture(),large={...f.args,originalBytes:Buffer.alloc(400000,65),encodedAdditions:'\nNEW="bounded"\n'};
 assert(large.originalBytes.length<1024*1024);assert.throws(()=>prepare(large,undefined,f.dependencies),denial);assert.equal(f.calls.length,0);assert.equal(f.files.size,1);
 for(const change of [{originalBytes:Buffer.alloc(1024*1024+1)},{encodedAdditions:'x'.repeat(1024*1024)},{encodedAdditions:'nul\0secret'},{originalBytes:'not bytes'},{root:'C:\\workspace\\..\\other'},{directory:'\\\\host\\share'},{operationId:'invalid'},{id:'0'.repeat(12)}])assert.throws(()=>prepare({...f.args,...change},undefined,f.dependencies),denial);
 assert.equal(f.calls.length,0);assert.equal(f.files.size,1);
});

test('Windows additive existing legacy journal, missing journal, stale stage and unsafe reads do not create fallback authority',()=>{
 const legacy=fixture(),result=Buffer.concat([legacy.args.originalBytes,Buffer.from('\n'+legacy.args.encodedAdditions)]);
 const exact=Buffer.from(JSON.stringify({version:1,kind:'additive',root:legacy.args.root,directory:legacy.args.directory,id:legacy.args.id,operationId,envPath:legacy.envPath,original:legacy.args.originalBytes.toString('base64'),result:result.toString('base64')})+'\n');
 legacy.create(legacy.journal,exact);assert.throws(()=>legacy.prepare(),denial);assert.throws(()=>readRetained(legacy.bound(),legacy.dependencies),denial);assert(!legacy.files.has(legacy.journal+'.native-journal'));assert(legacy.files.get(legacy.envPath).bytes.equals(legacy.args.originalBytes));
 const absent=fixture();assert.throws(()=>readRetained({...absent.args,journalSha256:'a'.repeat(64)},absent.dependencies),denial);assert.equal(absent.files.size,1);
 const stage=fixture();stage.create(stage.args.root+'\\.env.upgrade',Buffer.from('retained staging'));assert.throws(()=>stage.prepare(),denial);assert(!stage.files.has(stage.journal));
 const unsafe=fixture(),p=unsafe.prepare();unsafe.deny();assert.throws(()=>p.publish(),denial);assert(unsafe.files.get(unsafe.envPath).bytes.equals(unsafe.args.originalBytes));
});

test('Windows retained reader requires canonical bounded journal and exact original prefix with UTF8 additions',()=>{
 for(const change of [doc=>({...doc,extra:true}),doc=>({...doc,id:'0'.repeat(12)}),doc=>({...doc,original:doc.original+'='}),doc=>({...doc,result:Buffer.from('foreign prefix').toString('base64')}),doc=>({...doc,result:Buffer.concat([Buffer.from(doc.original,'base64'),Buffer.from([0xff])]).toString('base64')})]){
  const f=fixture();f.prepare();const doc=JSON.parse(f.files.get(f.journal).bytes);f.files.get(f.journal).bytes=Buffer.from(JSON.stringify(change(doc))+'\n');const count=f.calls.length;
  assert.throws(()=>readRetained(f.bound(),f.dependencies),denial);assert(!f.calls.slice(count).some(r=>r.operation==='preparePrivatePublication'));
 }
});

test('Windows additive does not invoke POSIX mode/create/fsync/rename publication authority',()=>{
 const module={exports:{}},file=path.resolve(__dirname,'../scripts/lib/setup-additive-environment-publication.js'),requireHere=createRequire(file);let calls=0;
 vm.runInNewContext(fs.readFileSync(file,'utf8'),{module,exports:module.exports,Buffer,process,require:n=>n==='node:fs'?new Proxy({}, {get(){return()=>{calls++;throw Error('POSIX authority forbidden');};}}):requireHere(n)});
 const f=fixture(),p=module.exports.prepareAdditiveEnvironmentPublication(f.args,undefined,f.dependencies);p.publish();module.exports.readAdditiveEnvironmentPublication(f.bound(),f.dependencies).publish();assert.equal(calls,0);
});

test('Windows additive native process failures discard all potentially secret-bearing diagnostics',()=>{
 const f=fixture();f.dependencies.publication={preparePrivatePublication(){throw Object.assign(Error('synthetic secret payload'),{stderr:'synthetic secret payload',cause:Error('synthetic secret payload')});}};
 assert.throws(()=>f.prepare(),e=>{assert.equal(e.code,denial.code);assert.equal(e.message,denial.message);assert.equal(e.cause,undefined);assert(!String(e.stack).includes('synthetic secret payload'));return true;});assert(f.files.get(f.envPath).bytes.equals(f.args.originalBytes));
});
