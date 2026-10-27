'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const file=path.join(__dirname,'postgres/ownedV03GuestClock.js'),source=fs.readFileSync(file,'utf8');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const root=path.resolve(__dirname,'..'),parent='a'.repeat(32),plan='b'.repeat(64);
const boot='01234567-0123-0123-0123-012345678901';
function harness(fault={}){
 let now=1000,execs=0,opens=0,closes=0;
 const signal=new AbortController().signal,window={deadlineMs:1801000};
 const owner={binding:()=>({runId:parent,planSha256:plan,expiresAtMs:11097000}),nowMs:()=>now,
  phaseWindow:kind=>fault.retirementWindow?fault.retirementWindow:window,
  phaseSignal:()=>fault.retirementSignal||signal,isRevoked:()=>!!fault.revoked};
 const files=new Map(),stats={isFile:()=>true,nlink:1,dev:1,ino:1,mtimeMs:1,ctimeMs:1};
 const python='/controlled/python',driverFile=path.join(path.dirname(file),'ownedSystemConfigPhaseDriver.js');
 files.set(file,Buffer.from(source));files.set(driverFile,Buffer.from('driver'));files.set(python,Buffer.from('python'));
 const mockFs={
  async realpath(name){return name==='/opt/homebrew/bin/python3'?python:name;},
  async mkdir(){if(fault.preparationDelay)now+=fault.preparationDelay;},
  async open(name,flags){
   opens++;
   if(flags&fs.constants.O_CREAT){assert(!files.has(name));files.set(name,Buffer.alloc(0));}
   const bytes=files.get(name)||Buffer.alloc(0);
   const directory=name===path.join(root,'tasks/tmp','v03-clock-'+parent);
   return {fd:opens,async stat(){if(name===file&&fault.sourceStatError)throw fault.sourceStatError;return {...stats,size:bytes.length};},
    async read(buffer,offset,length,position){const count=bytes.copy(buffer,offset,position,position+length);return {bytesRead:count};},
    async sync(){if(directory&&fault.directorySyncError)throw fault.directorySyncError;},
    async close(){closes++;
     if(name===file&&fault.sourceCloseError)throw fault.sourceCloseError;
     if(directory&&fault.directoryCloseError)throw fault.directoryCloseError;
     if(fault.closeFailure&&name.endsWith('/input'))throw Error('close');}};
  }
 };
 const controller={DEPS:{},validateReceipt:()=>{},localRetired:value=>value.retired,
  async executePython(conf){
   execs++;assert.equal(conf.phase,'v03-clock-sample');assert.equal(conf.remoteSeconds,2);
   assert.equal(conf.outputLimit,1024);assert(conf.command.startsWith('/usr/bin/python3 -I -S -B -c '));
   assert(conf.command.endsWith(parent+' '+plan));
   if(fault.controllerError)throw fault.controllerError;
   const start=now;now+=fault.transit??100;
   const packet={version:1,parentRunId:parent,combinedPlanSha256:plan,
    guestMonotonicMs:start+100000,guestBootId:boot,...fault.packet};
   const output=Buffer.from(JSON.stringify(packet));
   files.set(path.join(path.dirname(conf.inputPath),'stdout'),output);
   const result={code:0,failure:null,muxUnchanged:true,retired:true,
    stdout:{bytes:output.length,sha256:sha(output)},stderr:{bytes:0,sha256:sha('')},...fault.receipt};
   return result;
  }};
 const module={exports:{}};
 vm.runInNewContext(source+'\nmodule.exports.testing={mappingFor,GUEST};',{
  module,Buffer,__dirname:path.dirname(file),__filename:file,
  require(name){if(name==='node:fs/promises')return mockFs;
   if(name==='./ownedSystemConfigPhaseDriver')return {_internals:controller};
   if(name==='./ownedV03PrivateExecutors')return {assertCombinedOwner(value){if(value!==owner)throw Error('brand');return value;}};
   return require(name);}
 },{filename:file});
 const options={owner,root,expectedClockSha256:sha(source),expectedDriverSha256:sha('driver'),expectedPythonSha256:sha('python')};
 return {api:module.exports,owner,options,setNow:value=>now=value,counts:()=>({execs,opens,closes})};
}
test('fixed sampler executes actual controller seam and maps one absolute owner expiry conservatively',async()=>{
 const h=harness(),mapping=await h.api.sampleGuestClock(h.options);
 assert.equal(h.api.assertGuestClockMapping(mapping,h.owner),mapping);
 assert.equal(mapping.uncertaintyMs(),101);
 assert.equal(mapping.mapDeadline(10000),109899);
 assert.deepEqual({...mapping.mapInterval({startedAtMs:2000,deadlineMs:10000})},{startedAtMs:101899,deadlineMs:109899});
 h.setNow(9000);assert.equal(mapping.mapDeadline(10000),109899);
 h.setNow(10000);assert.throws(()=>mapping.mapDeadline(10000),/DEADLINE/);
 assert.equal(h.counts().execs,1);assert.equal(h.counts().opens,h.counts().closes);
});
test('source preparation delay is charged before send and cannot reset owner expiry',async()=>{
 const h=harness({preparationDelay:500000}),mapping=await h.api.sampleGuestClock(h.options);
 assert.equal(mapping.binding().sentAtMs,501000);
 assert.equal(mapping.mapDeadline(h.owner.binding().expiresAtMs),11196899);
 assert.throws(()=>mapping.mapDeadline(h.owner.binding().expiresAtMs+1),/DEADLINE/);
 const late=harness({preparationDelay:1800000});
 await assert.rejects(late.api.sampleGuestClock(late.options),/PHASE/);assert.equal(late.counts().execs,0);
});
test('integer millisecond mapping includes fractional-phase rounding guard',async()=>{
 const h=harness({transit:0}),mapping=await h.api.sampleGuestClock(h.options);
 // A sample at real guest101000.01 and host1000.99 has true offset99999.02.
 // Merely subtracting integer floors would incorrectly admit offset100000.
 assert.equal(mapping.mapDeadline(10000),109999);
 assert(mapping.mapDeadline(10000)<=10000+99999.02);
 assert.equal(mapping.uncertaintyMs(),1);
});
test('mapping cannot be minted from JSON, foreign owner, arbitrary command, or runner',async()=>{
 const h=harness(),mapping=await h.api.sampleGuestClock(h.options);
 assert.throws(()=>h.api.assertGuestClockMapping({...mapping},h.owner),/MAPPING_REQUIRED/);
 assert.throws(()=>h.api.assertGuestClockMapping(mapping,{}),/MAPPING_REQUIRED/);
 for(const extra of [{runner(){}},{command:'ignored'},{clock:()=>0}])
  await assert.rejects(h.api.sampleGuestClock({...h.options,...extra}),/OPTIONS/);
 await assert.rejects(h.api.sampleGuestClock({...h.options,owner:{}}),/brand/);
});
test('overwide or backward brackets and malformed identity fail closed',async()=>{
 for(const fault of [{transit:2000},{transit:2001},{transit:-1},{packet:{version:true}},{packet:{parentRunId:'c'.repeat(32)}},
  {packet:{combinedPlanSha256:'c'.repeat(64)}},{packet:{guestBootId:'bad'}},{packet:{guestMonotonicMs:1.5}},
  {packet:{extra:'no'}}]){
  const h=harness(fault);await assert.rejects(h.api.sampleGuestClock(h.options),/SAMPLE_UNPROVEN/);
  assert.equal(h.counts().opens,h.counts().closes);
 }
});
test('unjoined, failed, changed-mux and tampered-output receipts never mint mapping',async()=>{
 for(const receipt of [{retired:false},{code:1},{failure:'PHASE_EXIT'},{muxUnchanged:false},
  {stdout:{bytes:0,sha256:sha('')}}]){
  const h=harness({receipt});await assert.rejects(h.api.sampleGuestClock(h.options),/UNPROVEN|OUTPUT_CHANGED/);
  assert.equal(h.counts().opens,h.counts().closes);
 }
});
test('close failures retain original controller failure identity and debt',async()=>{
 const primary=Object.assign(Error('primary'),{code:'PRIMARY'}),h=harness({controllerError:primary,closeFailure:true});
 await assert.rejects(h.api.sampleGuestClock(h.options),error=>error===primary&&error.cleanupDebt===true);
 assert.equal(h.counts().opens,h.counts().closes);
 const only=harness({closeFailure:true});await assert.rejects(only.api.sampleGuestClock(only.options),/FILE_CLOSE/);
});
test('pre-dispatch source descriptor close uncertainty retains primary and cleanup debt',async()=>{
 for(const withPrimary of [false,true]){
  const close=Error('source close'),primary=withPrimary?Error('source stat primary'):null;
  const h=harness({sourceCloseError:close,sourceStatError:primary});
  await assert.rejects(h.api.sampleGuestClock(h.options),error=>error===(primary||close)
   &&error.cleanupDebt===true&&error.clockCleanupErrors.includes('V03_CLOCK_SOURCE_CLOSE'));
  assert.equal(h.counts().execs,0);assert.equal(h.counts().opens,h.counts().closes);
 }
});
test('directory sync primary survives directory and later owned-file close debt',async()=>{
 for(const withPrimary of [false,true]){
  const close=Error('directory close'),primary=withPrimary?Error('directory sync primary'):null;
  const h=harness({directoryCloseError:close,directorySyncError:primary,closeFailure:true});
  await assert.rejects(h.api.sampleGuestClock(h.options),error=>error===(primary||close)
   &&error.cleanupDebt===true&&error.clockCleanupErrors.includes('V03_CLOCK_DIRECTORY_CLOSE')
   &&error.clockCleanupErrors.includes('V03_CLOCK_FILE_CLOSE'));
  assert.equal(h.counts().execs,0);assert.equal(h.counts().opens,h.counts().closes);
 }
});
test('source mismatch and revoked owner cannot dispatch',async()=>{
 const h=harness();await assert.rejects(h.api.sampleGuestClock({...h.options,expectedDriverSha256:'f'.repeat(64)}),/SOURCE_CHANGED/);
 assert.equal(h.counts().execs,0);
 const revoked=harness({revoked:true});await assert.rejects(revoked.api.sampleGuestClock(revoked.options),/REVOKED/);
 assert.equal(revoked.counts().opens,0);
});
test('post-sample revocation prevents further mapping or brand admission',async()=>{
 const fault={},h=harness(fault),mapping=await h.api.sampleGuestClock(h.options);
 fault.revoked=true;
 assert.throws(()=>mapping.mapDeadline(10000),/REVOKED/);
 assert.throws(()=>mapping.mapInterval({startedAtMs:2000,deadlineMs:10000}),/REVOKED/);
 assert.throws(()=>h.api.assertGuestClockMapping(mapping,h.owner),/REVOKED/);
});
test('revoked mapping accepts only the actual fixed active retirement window',async()=>{
 const fault={},h=harness(fault),mapping=await h.api.sampleGuestClock(h.options);
 assert.throws(()=>mapping.mapRetirementInterval('diagnosticCleanupMs'),/RETIREMENT/);
 fault.revoked=true;fault.retirementWindow={kind:'diagnosticCleanupMs',startedAtMs:2000,deadlineMs:602000};
 assert.deepEqual({...mapping.mapRetirementInterval('diagnosticCleanupMs')},{startedAtMs:101899,deadlineMs:701899});
 for(const kind of ['cohortClaim','diagnosticBuildMs','caller-kind'])assert.throws(()=>mapping.mapRetirementInterval(kind),/RETIREMENT/);
 for(const delta of [{kind:'listingsCleanupMs'},{deadlineMs:11097001},{deadlineMs:1000},{startedAtMs:999},{startedAtMs:true}]){
  fault.retirementWindow={kind:'diagnosticCleanupMs',startedAtMs:2000,deadlineMs:602000,...delta};
  assert.throws(()=>mapping.mapRetirementInterval('diagnosticCleanupMs'),/RETIREMENT/);
 }
 fault.retirementWindow={kind:'diagnosticCleanupMs',startedAtMs:2000,deadlineMs:602000};
 const controller=new AbortController();controller.abort(Error('retirement expired'));fault.retirementSignal=controller.signal;
 assert.throws(()=>mapping.mapRetirementInterval('diagnosticCleanupMs'),/expired/);
 assert.throws(()=>mapping.mapDeadline(10000),/REVOKED/);
});
test('actual emitted guest sampler executes under injected observations without native probes',()=>{
 const guest=harness().api.testing.GUEST;
 const script=`import sys,types,io,builtins,json\nsource=${JSON.stringify(guest)}\n`+
  `sys.modules['os']=types.SimpleNamespace(geteuid=lambda:0)\n`+
  `sys.modules['time']=types.SimpleNamespace(monotonic_ns=lambda:123456789000)\n`+
  `sys.platform='linux';sys.argv=['sample','${parent}','${plan}']\n`+
  `def opened(name,*args,**kwargs):\n assert name=='/proc/sys/kernel/random/boot_id'\n return io.StringIO('${boot}\\n')\n`+
  `builtins.open=opened\nexec(compile(source,'actual-guest-sampler','exec'))\n`;
 const result=spawnSync(process.env.PYTHON||'python3',['-I','-S','-B','-c',script],{encoding:'utf8',timeout:5000,maxBuffer:4096});
 assert.ifError(result.error);assert.equal(result.status,0,result.stderr);
 assert.deepEqual(JSON.parse(result.stdout),{version:1,parentRunId:parent,combinedPlanSha256:plan,guestMonotonicMs:123456,guestBootId:boot});
});
