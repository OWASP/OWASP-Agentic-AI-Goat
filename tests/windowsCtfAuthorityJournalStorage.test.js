'use strict';
// Controlled storage composition only; no native Windows, PowerShell or DB calls.
const test=require('node:test'),assert=require('node:assert/strict');
const {createWindowsCtfAuthorityJournalStorage,MAX_JOURNAL_BYTES,MAX_LOCK_BYTES}=require('../scripts/lib/windows-ctf-authority-journal-storage');
const directory='C:\\private\\installation',journal=directory+'\\ctf-authority.json',lock=journal+'.lock';
const failure={code:'WINDOWS_CTF_AUTHORITY_JOURNAL_DENIED',message:'Windows CTF journal storage unavailable.'};
function fixture(options={}){
 const files=new Map(),intents=new Map(),calls=[],control={directoryExists:true,parentExists:true,directoryId:'1111111111111111',metadataError:null,nativeReadError:false,createLost:false,deleteRetains:false,deleteReplaces:false,deleteReadDenied:false,deleteError:false,publishBefore:false,publishAfter:false,...options};let serial=1;
 const identity=()=>({volumeSerial:1,fileId:(++serial).toString(16).padStart(16,'0')});
 const add=(p,bytes)=>{const record={bytes:Buffer.from(bytes),identity:identity()};files.set(p,record);return record;};
 const metadata=(p,r)=>({path:p,size:r.bytes.length,identity:{...r.identity}});
 const nativeError=()=>Object.assign(Error('synthetic native secret'),{code:'ENOENT',stderr:'synthetic native secret'});
 const privateState={
  ensurePrivateDirectory(p){calls.push(['ensure',p]);if(!control.parentExists)throw nativeError();control.directoryExists=true;return{path:p,size:null,identity:{volumeSerial:1,fileId:control.directoryId}};},
  inspectPrivateDirectory(p){calls.push(['inspect',p]);if(!control.directoryExists)throw nativeError();return{path:p,size:null,identity:{volumeSerial:1,fileId:control.directoryId}};},
  createPrivateFile(p,bytes){calls.push(['create',p]);if(files.has(p))throw nativeError();const r=add(p,bytes);if(control.createLost)throw nativeError();return metadata(p,r);},
  readAndFlushPrivateFileSnapshot(p){calls.push(['snapshot',p]);if(control.nativeReadError||!files.has(p))throw nativeError();const r=files.get(p);return{...metadata(p,r),bytes:Buffer.from(r.bytes)};},
  deleteMatchingPrivateFile(p,bytes,id){calls.push(['delete',p]);const r=files.get(p);if(control.deleteError||!r||!r.bytes.equals(bytes)||JSON.stringify(r.identity)!==JSON.stringify(id))throw nativeError();const out={...metadata(p,r),deleted:true};if(!control.deleteRetains)files.delete(p);if(control.deleteReplaces)add(p,'replacement');if(control.deleteReadDenied)control.metadataError='EACCES';return out;},
 };
 const receipt=(binding,r,state)=>({state,...binding,size:r.bytes.length,identity:{...r.identity},intentSha256:'a'.repeat(64)});
 const publication={
  preparePrivatePublication(request){calls.push(['prepare',request]);const binding={targetPath:request.targetPath,intentPath:request.intentPath,operationId:request.operationId};let saved=intents.get(binding.intentPath);if(saved){assert.equal(saved.original===null,request.originalBytes===null);if(saved.original)assert(saved.original.equals(request.originalBytes));assert(saved.staged.bytes.equals(request.resultBytes));return receipt(binding,saved.staged,saved.committed?'committed':'prepared');}
   const old=files.get(binding.targetPath);if(request.originalBytes===null?!!old:!old||!old.bytes.equals(request.originalBytes))throw nativeError();
   const staged={bytes:Buffer.from(request.resultBytes),identity:identity()};saved={binding,original:request.originalBytes===null?null:Buffer.from(request.originalBytes),oldIdentity:old?.identity,staged,committed:false};intents.set(binding.intentPath,saved);add(binding.intentPath,'immutable modeled intent');add(binding.intentPath+'.result',staged.bytes);if(saved.original)add(binding.intentPath+'.original',saved.original);return receipt(binding,staged,'prepared');},
  publishPrivatePublication(binding){calls.push(['publish',binding]);const saved=intents.get(binding.intentPath);if(control.publishBefore)throw nativeError();if(!saved.committed){const old=files.get(binding.targetPath);if(saved.original===null?!!old:!old||!old.bytes.equals(saved.original)||JSON.stringify(old.identity)!==JSON.stringify(saved.oldIdentity))throw nativeError();files.set(binding.targetPath,saved.staged);saved.committed=true;}if(control.publishAfter)throw nativeError();return receipt(binding,saved.staged,'committed');},
 };
 const fileSystem={lstatSync(p){calls.push(['present',p]);if(control.metadataError)throw Object.assign(Error('synthetic metadata secret'),{code:control.metadataError});if(!files.has(p))throw Object.assign(Error('missing'),{code:'ENOENT'});return{};}};
 const storage=createWindowsCtfAuthorityJournalStorage({directory,filesystemPlatform:'win32',privateState,publication,fileSystem});
 return{storage,files,intents,calls,control,add};
}
test('directory admission captures native identity and never recreates a replaced admitted directory',()=>{
 const f=fixture({directoryExists:false});f.storage.ensureDirectory();f.storage.verifyDirectory();assert.equal(f.calls.filter(x=>x[0]==='ensure').length,1);f.control.directoryExists=false;assert.throws(()=>f.storage.ensureDirectory(),failure);assert.equal(f.calls.filter(x=>x[0]==='ensure').length,1);
 const missing=fixture({directoryExists:false,parentExists:false});assert.throws(()=>missing.storage.ensureDirectory(),failure);assert.equal(missing.control.directoryExists,false);
 const replaced=fixture();replaced.storage.verifyDirectory();replaced.control.directoryId='2222222222222222';assert.throws(()=>replaced.storage.verifyDirectory(),failure);
});
test('lock creation is strictly create-new even for identical bytes and receipt copies grant no authority',()=>{
 const f=fixture(),bytes=Buffer.from('owned lock'),receipt=f.storage.createLock(bytes);bytes.fill(0);assert(Object.isFrozen(receipt));f.storage.assertLock(receipt);assert.throws(()=>f.storage.createLock(Buffer.from('owned lock')),failure);assert.throws(()=>f.storage.assertLock({...receipt}),failure);f.storage.releaseLock(receipt);assert.equal(f.files.has(lock),false);assert.throws(()=>f.storage.releaseLock(receipt),failure);
});
test('lock byte or identity drift prevents matching deletion',()=>{
 for(const change of [r=>r.bytes=Buffer.from('different'),r=>r.identity.fileId='ffffffffffffffff']){const f=fixture(),receipt=f.storage.createLock(Buffer.from('owned'));change(f.files.get(lock));assert.throws(()=>f.storage.releaseLock(receipt),failure);assert.equal(f.calls.filter(x=>x[0]==='delete').length,0);assert(f.files.has(lock));}
});
test('uncertain strict creation retains lock and cannot reacquire or opportunistically delete it',()=>{
 for(const options of [{createLost:true},{nativeReadError:true}]){const f=fixture(options);assert.throws(()=>f.storage.createLock(Buffer.from('owned')),failure);assert(f.files.has(lock));f.control.createLost=false;f.control.nativeReadError=false;assert.throws(()=>f.storage.createLock(Buffer.from('owned')),failure);assert.equal(f.calls.filter(x=>x[0]==='delete').length,0);}
});
test('release requires named absence after native acknowledgment and uncertainty consumes the receipt',()=>{
 for(const options of [{deleteRetains:true},{deleteReplaces:true},{deleteReadDenied:true},{deleteError:true}]){const f=fixture(options),receipt=f.storage.createLock(Buffer.from('owned'));assert.throws(()=>f.storage.releaseLock(receipt),failure);assert.throws(()=>f.storage.releaseLock(receipt),failure);assert.equal(f.calls.filter(x=>x[0]==='delete').length,1);}
});
test('journal absence is fresh exact metadata ENOENT and native denial never falls back to missing',()=>{
 const f=fixture();assert.equal(f.storage.readJournal(),null);assert.equal(f.calls.filter(x=>x[0]==='snapshot').length,0);f.add(journal,'bytes');assert.equal(f.storage.readJournal().toString(),'bytes');for(const code of ['EACCES','UNKNOWN']){f.control.metadataError=code;assert.throws(()=>f.storage.readJournal(),failure);}f.control.metadataError=null;f.control.nativeReadError=true;assert.throws(()=>f.storage.readJournal(),failure);
});
test('fresh and replacement journal publications retain exact originals/results with deterministic intents',async()=>{
 const f=fixture(),guard=()=>{f.calls.push(['guard']);};await f.storage.publishJournal({originalBytes:null,resultBytes:Buffer.from('initial')},guard);await f.storage.publishJournal({originalBytes:Buffer.from('initial'),resultBytes:Buffer.from('complete')},guard);assert.equal(f.storage.readJournal().toString(),'complete');assert.equal(f.intents.size,2);assert([...f.files].some(([p,r])=>p.endsWith('.original')&&r.bytes.toString()==='initial'));assert([...f.files].some(([p,r])=>p.endsWith('.result')&&r.bytes.toString()==='complete'));assert.equal(f.calls.filter(x=>x[0]==='guard').length,6);const prepare=f.calls.findIndex(x=>x[0]==='prepare'),publish=f.calls.findIndex(x=>x[0]==='publish');assert(f.calls.slice(prepare+1,publish).some(x=>x[0]==='guard'));
 await assert.rejects(f.storage.publishJournal({originalBytes:Buffer.from('foreign'),resultBytes:Buffer.from('new')},guard),failure);assert.equal(f.storage.readJournal().toString(),'complete');
});
test('interrupted journal preparation/promotion retains transitions and supports only exact filesystem retry',async()=>{
 for(const flag of ['publishBefore','publishAfter']){const f=fixture({[flag]:true}),request={originalBytes:null,resultBytes:Buffer.from('exact')};await assert.rejects(f.storage.publishJournal(request,()=>{}),failure);assert.equal(f.intents.size,1);const intent=[...f.intents.keys()][0];f.control[flag]=false;await f.storage.publishJournal(request,()=>{});assert.equal(f.intents.size,1);assert.equal([...f.intents.keys()][0],intent);assert.equal(f.storage.readJournal().toString(),'exact');}
});
test('ownership barrier failure between prepare and commit retains intent without journal mutation',async()=>{
 const f=fixture();let guards=0;await assert.rejects(f.storage.publishJournal({originalBytes:null,resultBytes:Buffer.from('result')},()=>{if(++guards===2)throw Error('lost lease');}),failure);assert.equal(f.intents.size,1);assert.equal(f.files.has(journal),false);assert.equal(f.calls.filter(x=>x[0]==='publish').length,0);
});
test('predecessor reclamation requires exact bounded bytes, a current barrier and matching held identity deletion',async()=>{
 const f=fixture();f.add(lock,'prior');let guards=0;assert.equal(await f.storage.reclaimLock([Buffer.from('prior')],()=>{guards++;}),true);assert.equal(guards,1);assert.equal(f.files.has(lock),false);assert.equal(await f.storage.reclaimLock([Buffer.from('prior')],()=>{}),false);
 const foreign=fixture();foreign.add(lock,'prior');await assert.rejects(foreign.storage.reclaimLock([Buffer.from('foreign')],()=>{}),failure);assert(foreign.files.has(lock));
 const replaced=fixture();replaced.add(lock,'prior');await assert.rejects(replaced.storage.reclaimLock([Buffer.from('prior')],()=>{replaced.files.get(lock).identity.fileId='ffffffffffffffff';}),failure);assert(replaced.files.has(lock));
});
test('predecessor guard failure and retained-name deletion acknowledgment never report reclaimed success',async()=>{
 const f=fixture();f.add(lock,'prior');await assert.rejects(f.storage.reclaimLock([Buffer.from('prior')],()=>{throw Error('authority lost');}),failure);assert.equal(f.calls.filter(x=>x[0]==='delete').length,0);
 for(const options of [{deleteRetains:true},{deleteReplaces:true},{deleteReadDenied:true}]){const g=fixture(options);g.add(lock,'prior');await assert.rejects(g.storage.reclaimLock([Buffer.from('prior')],()=>{}),failure);}
});
test('bounds and platforms deny before native writes; diagnostic data never escapes',async()=>{
 const f=fixture();assert.throws(()=>f.storage.createLock(Buffer.alloc(MAX_LOCK_BYTES+1)),failure);await assert.rejects(f.storage.publishJournal({originalBytes:null,resultBytes:Buffer.alloc(MAX_JOURNAL_BYTES+1)},()=>{}),failure);assert.equal(f.calls.length,0);assert.throws(()=>createWindowsCtfAuthorityJournalStorage({directory,filesystemPlatform:'darwin'}),failure);assert.throws(()=>createWindowsCtfAuthorityJournalStorage({directory:'C:\\'+ 'a'.repeat(185),filesystemPlatform:'win32'}),failure);
 f.control.nativeReadError=true;f.add(journal,'secret');assert.throws(()=>f.storage.readJournal(),e=>{assert.equal(e.code,failure.code);assert.deepEqual(Object.keys(e),['code']);assert(!String(e.stack).includes('synthetic native secret'));return true;});
});

test('asynchronous ownership barrier directory replacement denies the next native mutation',async()=>{
 for(const stage of [1,2]){const f=fixture();let calls=0;await assert.rejects(f.storage.publishJournal({originalBytes:null,resultBytes:Buffer.from('result')},async()=>{await Promise.resolve();if(++calls===stage)f.control.directoryId='ffffffffffffffff';}),failure);assert.equal(f.calls.filter(x=>x[0]==='publish').length,0);assert.equal(f.calls.filter(x=>x[0]==='prepare').length,stage===1?0:1);}
});
