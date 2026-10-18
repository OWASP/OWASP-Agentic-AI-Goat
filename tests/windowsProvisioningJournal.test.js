'use strict';
// Controlled capability providers exercise adapter sequencing and byte/receipt
// bindings. They are not native Windows recovery or DDL execution evidence.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createWindowsProvisioningJournal,MAX_FILE_BYTES}=require('../scripts/lib/windows-provisioning-journal');
const filePath='C:\\Users\\Learner\\private\\provisioning.json',parent='C:\\Users\\Learner\\private';
const denied={code:'WINDOWS_PROVISIONING_JOURNAL_DENIED',message:'Windows provisioning journal unavailable'};
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function controlled(initial){
 const files=new Map(),intents=new Map(),calls=[];let next=1,fault,unsafe=false;
 const file=bytes=>({bytes:Buffer.from(bytes),identity:{volumeSerial:9,fileId:(++next).toString(16).padStart(16,'0')}});
 if(initial!==undefined)files.set(filePath,file(initial));
 const same=(a,b)=>Boolean(a&&b&&a.bytes.equals(b.bytes)&&a.identity.fileId===b.identity.fileId);
 const receipt=(options,intent,state)=>Object.freeze({...options,state,intentSha256:hash(intent.encoded),size:intent.result.bytes.length,identity:Object.freeze({...intent.result.identity})});
 const privateState={
  inspectPrivateDirectory(p){calls.push({operation:'inspect',path:p});if(p!==parent||unsafe)throw Error('synthetic private parent denial');return Object.freeze({path:p,size:null,identity:Object.freeze({volumeSerial:9,fileId:'0000000000000001'})});},
  readPrivateFile(p){calls.push({operation:'read',path:p});if(unsafe||!files.has(p))throw Error('synthetic private read denial');return Buffer.from(files.get(p).bytes);},
 };
 const publication={
  preparePrivatePublication(options){
   calls.push({operation:'prepare',options});if(unsafe)throw Error('synthetic native denial');
   let intent=intents.get(options.intentPath),current=files.get(options.targetPath);
   if(!intent){
    if(current?options.originalBytes===null||!current.bytes.equals(options.originalBytes):options.originalBytes!==null)throw Error('exact original mismatch');
    const original=current?{bytes:Buffer.from(current.bytes),identity:{...current.identity}}:null,result=file(options.resultBytes);
    intent={targetPath:options.targetPath,operationId:options.operationId,original,result,encoded:Buffer.from(JSON.stringify({path:options.targetPath,operationId:options.operationId,old:original?.bytes.toString('base64'),result:result.bytes.toString('base64')}))};intents.set(options.intentPath,intent);
   }
   if(intent.targetPath!==options.targetPath||intent.operationId!==options.operationId||!intent.result.bytes.equals(options.resultBytes)||(intent.original?options.originalBytes===null||!intent.original.bytes.equals(options.originalBytes):options.originalBytes!==null))throw Error('intent request binding mismatch');
   let state;if(same(current,intent.result))state='committed';else{if(intent.original?!same(current,intent.original):current!==undefined)throw Error('prior changed');state='prepared';}
   if(fault==='prepare-flush'){fault=null;throw Error('synthetic retained flush failure');}
   return receipt({targetPath:options.targetPath,intentPath:options.intentPath,operationId:options.operationId},intent,state);
  },
  publishPrivatePublication(options){
   calls.push({operation:'publish',options});const intent=intents.get(options.intentPath);if(!intent||unsafe)throw Error('retained authority required');
   const current=files.get(options.targetPath);if(!same(current,intent.result)){
    if(intent.original?!same(current,intent.original):current!==undefined)throw Error('prior authority mismatch');
    if(fault==='before-move'){fault=null;throw Error('synthetic before move interruption');}
    files.set(options.targetPath,intent.result);
    if(fault==='after-move'){fault=null;throw Error('synthetic lost move acknowledgement');}
   }
   const result=receipt(options,intent,'committed');if(fault==='receipt'){fault=null;return {...result,intentSha256:'0'.repeat(64)};}return result;
  },
 };
 const dependencies={platform:'win32',privateState,publication};
 return {adapter:createWindowsProvisioningJournal(dependencies),dependencies,files,intents,calls,replace(p,bytes){files.set(p,file(bytes));},setFault(value){fault=value;},deny(){unsafe=true;}};
}
const old=Buffer.from('{"status":"incomplete","created":[]}\n'),next=Buffer.from('{"status":"incomplete","created":[{"role":"owned"}]}\n');

test('provisioning destination admission is private, read-only and can precede a database connection',()=>{
 const f=controlled();assert.equal(f.adapter.inspectDestination({filePath}).path,parent);assert.deepEqual(f.calls,[{operation:'inspect',path:parent}]);assert.equal(f.files.size,0);assert.equal(f.intents.size,0);
 f.deny();assert.throws(()=>f.adapter.inspectDestination({filePath}),denied);assert.equal(f.files.size,0);
});
test('create persists exact private bytes through native create-new publication then verifies bounded read',()=>{
 const f=controlled(),receipt=f.adapter.createJournal({filePath,bytes:old});assert.equal(receipt.state,'committed');assert(Object.isFrozen(receipt));assert(Object.isFrozen(receipt.identity));assert(f.files.get(filePath).bytes.equals(old));
 assert.deepEqual(f.calls.map(c=>c.operation),['inspect','prepare','publish','read']);assert.equal(f.calls[1].options.originalBytes,null);assert(f.calls[1].options.resultBytes.equals(old));
 const bytes=f.adapter.readJournal({filePath});bytes.fill(0);assert(f.adapter.readJournal({filePath}).equals(old));
});
test('updates bind exact prior bytes and retain each transition with deterministic UUID/name',()=>{
 const f=controlled(old),receipt=f.adapter.updateJournal({filePath,originalBytes:old,resultBytes:next});assert.equal(receipt.state,'committed');assert(f.files.get(filePath).bytes.equals(next));
 const request=f.calls.find(c=>c.operation==='prepare').options;assert.match(request.operationId,/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);assert.equal(request.intentPath,parent+'\\provisioning-'+request.operationId+'.intent');
 assert(request.originalBytes.equals(old));assert(request.resultBytes.equals(next));const final=f.files.get(filePath);
 f.adapter.updateJournal({filePath,originalBytes:old,resultBytes:next});assert.equal(f.files.get(filePath),final);assert.equal(f.intents.size,1);
 const other=controlled(old);other.adapter.updateJournal({filePath,originalBytes:old,resultBytes:next});assert.equal(other.calls.find(c=>c.operation==='prepare').options.intentPath,request.intentPath);
});
test('target/old/new framing yields distinct transition authority and prior artifacts are never deleted',()=>{
 const f=controlled(old);f.adapter.updateJournal({filePath,originalBytes:old,resultBytes:next});const first=[...f.intents.keys()][0],complete=Buffer.from('{"status":"complete"}\n');
 f.adapter.updateJournal({filePath,originalBytes:next,resultBytes:complete});assert.equal(f.intents.size,2);assert(f.intents.has(first));
 const otherPath=parent+'\\provisioning.other.json';f.adapter.createJournal({filePath:otherPath,bytes:complete});assert.equal(f.intents.size,3);assert.notEqual([...f.intents.keys()][2],[...f.intents.keys()][1]);
 assert(!f.calls.some(c=>/delete|remove|truncate|ddl|query/i.test(c.operation)));
});
test('create cannot adopt existing equal bytes or overwrite operator files without retained intent',()=>{
 for(const bytes of [old,Buffer.from('operator bytes')]){const f=controlled(bytes),existing=f.files.get(filePath);assert.throws(()=>f.adapter.createJournal({filePath,bytes:old}),denied);assert.equal(f.files.get(filePath),existing);assert.equal(f.intents.size,0);}
 const missing=controlled();assert.throws(()=>missing.adapter.updateJournal({filePath,originalBytes:old,resultBytes:next}),denied);assert.equal(missing.files.size,0);
});
test('interrupted creation before/after promotion and retained flush failure reuses exact bounded authority',()=>{
 for(const failure of ['prepare-flush','before-move','after-move']){const f=controlled();f.setFault(failure);assert.throws(()=>f.adapter.createJournal({filePath,bytes:old}),denied);const retained=[...f.intents.values()][0],current=f.files.get(filePath);
  f.adapter.createJournal({filePath,bytes:old});assert.equal(f.intents.size,1);assert.equal([...f.intents.values()][0],retained);assert(f.files.get(filePath).bytes.equals(old));if(current)assert.equal(f.files.get(filePath),current);
 }
});
test('interrupted acknowledged update retains exact transition for an explicit filesystem retry',()=>{
 for(const failure of ['prepare-flush','before-move','after-move']){const f=controlled(old);f.setFault(failure);assert.throws(()=>f.adapter.updateJournal({filePath,originalBytes:old,resultBytes:next}),denied);
  const retained=[...f.intents.values()][0],current=f.files.get(filePath);f.adapter.updateJournal({filePath,originalBytes:old,resultBytes:next});assert.equal(f.intents.size,1);assert.equal([...f.intents.values()][0],retained);if(failure==='after-move')assert.equal(f.files.get(filePath),current);
 }
});
test('original manifest remains authoritative until complete upgrade bytes are promoted; upgrade journal remains retained',()=>{
 const f=controlled(old),upgradePath=filePath+'.upgrade-bound',complete=Buffer.from('{"status":"complete","created":[{"role":"owned"}]}\n');
 f.adapter.createJournal({filePath:upgradePath,bytes:next});assert(f.files.get(filePath).bytes.equals(old));f.adapter.updateJournal({filePath:upgradePath,originalBytes:next,resultBytes:complete});assert(f.files.get(filePath).bytes.equals(old));
 const retained=f.files.get(upgradePath);f.adapter.updateJournal({filePath,originalBytes:old,resultBytes:complete});assert(f.files.get(filePath).bytes.equals(complete));assert.equal(f.files.get(upgradePath),retained);assert.equal(f.intents.size,3);
});
test('changed original bytes, identity or receipt refuse without fallback writes or deletion',()=>{
 const wrong=controlled(old),original=wrong.files.get(filePath);assert.throws(()=>wrong.adapter.updateJournal({filePath,originalBytes:Buffer.from('wrong'),resultBytes:next}),denied);assert.equal(wrong.files.get(filePath),original);
 const raced=controlled(old);raced.setFault('before-move');assert.throws(()=>raced.adapter.updateJournal({filePath,originalBytes:old,resultBytes:next}),denied);raced.replace(filePath,old);const changed=raced.files.get(filePath);assert.throws(()=>raced.adapter.updateJournal({filePath,originalBytes:old,resultBytes:next}),denied);assert.equal(raced.files.get(filePath),changed);
 const receipt=controlled(old);receipt.setFault('receipt');assert.throws(()=>receipt.adapter.updateJournal({filePath,originalBytes:old,resultBytes:next}),denied);assert(receipt.files.get(filePath).bytes.equals(next));assert.equal(receipt.intents.size,1);
});
test('bounded native payloads admit zero and 1MiB and reject oversize/schema/path before authority calls',()=>{
 for(const size of [0,MAX_FILE_BYTES]){const f=controlled(),bytes=Buffer.alloc(size);f.adapter.createJournal({filePath,bytes});assert.equal(f.adapter.readJournal({filePath}).length,size);}
 const f=controlled();for(const options of [{filePath,bytes:Buffer.alloc(MAX_FILE_BYTES+1)},{filePath,bytes:'secret'},{filePath,bytes:old,extra:true},{filePath:'\\\\host\\share\\journal',bytes:old},{filePath:'C:\\private\\..\\journal',bytes:old},{filePath:'C:\\private\\NUL',bytes:old},{filePath:'C:\\private\\journal:stream',bytes:old},{filePath:'C:\\'+ 'x'.repeat(200),bytes:old},{filePath:'C:\\private\\bad\ud800',bytes:old}])assert.throws(()=>f.adapter.createJournal(options),denied);
 assert.throws(()=>f.adapter.updateJournal({filePath,originalBytes:Buffer.alloc(MAX_FILE_BYTES+1),resultBytes:old}),denied);assert.throws(()=>f.adapter.readJournal({filePath,extra:true}),denied);assert.equal(f.calls.length,0);assert.equal(f.files.size,0);
});
test('native private parent/read/process denials and non-Windows operation never fall back or expose diagnostics',()=>{
 const f=controlled(old);f.deny();for(const action of [()=>f.adapter.inspectDestination({filePath}),()=>f.adapter.readJournal({filePath}),()=>f.adapter.updateJournal({filePath,originalBytes:old,resultBytes:next})])assert.throws(action,e=>{assert.equal(e.code,denied.code);assert.equal(e.message,denied.message);assert.equal(e.cause,undefined);assert(!String(e.stack).includes('synthetic private'));return true;});
 const unavailable=createWindowsProvisioningJournal({...f.dependencies,platform:'linux'}),count=f.calls.length;assert.throws(()=>unavailable.createJournal({filePath,bytes:old}),denied);assert.equal(f.calls.length,count);
 const malformed=controlled(old);malformed.dependencies.privateState.readPrivateFile=()=>Buffer.alloc(MAX_FILE_BYTES+1);assert.throws(()=>malformed.adapter.readJournal({filePath}),denied);
 const process=controlled(old);process.dependencies.publication.preparePrivatePublication=()=>{throw Object.assign(Error('synthetic secret stdin'),{stderr:'synthetic secret stdin'});};assert.throws(()=>process.adapter.updateJournal({filePath,originalBytes:old,resultBytes:next}),e=>e.code===denied.code&&!String(e.stack).includes('synthetic secret stdin'));
});
