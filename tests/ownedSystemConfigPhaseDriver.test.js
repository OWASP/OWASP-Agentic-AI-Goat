'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {EventEmitter}=require('node:events'),{PassThrough}=require('node:stream');
const {spawnSync}=require('node:child_process'),crypto=require('node:crypto');
const driver=require('./postgres/ownedSystemConfigPhaseDriver'),I=driver._internals;
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const phase='inventory';
const mux={config:'/repo/.qualification/ssh_config',socket:'/repo/tasks/l/colima-goat-q/ssh.sock',
 configSha256:'a'.repeat(64),limaConfigSha256:'b'.repeat(64),socketDevice:1,socketInode:2,masterPid:23,masterBirth:[1,2]};
const retirement=()=>({pid:100,birth:[11,22],reaped:true,groupAbsent:true,errors:[]});
const packet=()=>({version:1,phase,controller:{pid:99,birth:[4,5]},mux:structuredClone(mux),muxUnchanged:true,
 children:[retirement()],code:0,cleanup:retirement(),failure:null,
 stdout:{bytes:0,sha256:sha('')},stderr:{bytes:0,sha256:sha('')}});
test('closed receipt rejects unknown/missing/type and identity mutations',()=>{
 assert.equal(I.validateReceipt(packet(),phase,mux).code,0);
 for(const change of [
 v=>v.extra=true,v=>delete v.cleanup,v=>v.version=true,v=>v.children=[],v=>v.children[0].reaped=1,
 v=>v.controller.birth=[1],v=>v.mux.masterPid='23',v=>v.mux.configSha256='x',
 v=>v.stdout.bytes=true,v=>v.stdout.sha256='z'.repeat(64),v=>v.failure='raw secret',v=>v.phase='build',
 v=>v.mux.socket='/tmp/other'
 ]){const v=packet();change(v);assert.throws(()=>I.validateReceipt(v,phase,mux));}
 const debt=packet();debt.children[0].groupAbsent=false;
 assert.equal(I.localRetired(I.validateReceipt(debt,phase,mux)),false);
});
test('ordered phase machine blocks repeats, skip, concurrent work and postfailure effects but permits cleanup',()=>{
 const s=new I.Sequence();assert.throws(()=>s.enter('build'));
 s.enter('inventory');assert.throws(()=>s.enter('inventory'));s.leave(true);
 assert.throws(()=>s.enter('inventory'));s.enter('preflight');s.leave(false);
 assert.throws(()=>s.enter('prepare'));s.enter('stop',true);s.leave(true,true);
 assert.throws(()=>s.enter('build',true));s.closed=true;assert.throws(()=>s.enter('stop',true));
});
test('paired exact phase order acquires both targets before outbound retirement and serial offline builds',()=>{
 const a=require('./postgres/ownedSystemConfigBuildAdapter')._internals;
 const plan={target:a.PAIR_TARGET},lists=I.phaseLists(plan),s=new I.Sequence(lists);
 assert.deepEqual(lists.normal,a.PAIR_PHASES);assert.deepEqual(lists.cleanup,a.PAIR_CLEANUP);
 for(const name of a.PAIR_PHASES){s.enter(name);s.leave(true);}
 assert.throws(()=>s.enter('systemReplay'));assert.throws(()=>s.enter('build',true));
 for(const name of ['systemAcquireRetire','policyAcquireRetire','systemReplayRetire','policyReplayRetire']){s.enter(name,true);s.leave(true,true);}
 const failed=new I.Sequence(lists);failed.enter('inventory');failed.leave(false);
 assert.throws(()=>failed.enter('preflight'));failed.enter('policyReplayRetire',true);failed.leave(true,true);
});
test('paired transport selects exact target base/stdin phase without changing acquisition or archive limits',()=>{
 const a=require('./postgres/ownedSystemConfigBuildAdapter')._internals;
 const plan={target:a.PAIR_TARGET,spec:{root:'/repo',guest:'/var/tmp/owned'},runId:'a'.repeat(32),binding:{base:'system-base'},slots:{policy:{binding:{base:'renderer-base'}}},
  commands:Object.fromEntries([...a.PAIR_PHASES,...a.PAIR_CLEANUP].map(n=>[n,'fixed-'+n]))};
 for(const [name,base]of [['systemMetadata','system-base'],['policyMetadata','renderer-base']]){
  const config=I.optionsFor(plan,name,mux,Buffer.from('original target guest'),'/repo/private/input');
  assert.equal(config.base,base);assert.equal(config.remoteSeconds,310);assert.equal(config.inputSha256,sha('original target guest'));
  assert(I.pythonProgram(config).includes("if CONF['phase'] in ('metadataFetch','systemMetadata','policyMetadata'):remote.append(CONF['base'])"));
 }
 for(const name of ['systemExport','policyExport'])assert.equal(I.optionsFor(plan,name,mux,Buffer.alloc(0),'p').outputLimit,145*1024**2);
 assert.throws(()=>I.optionsFor(plan,'system-runtime-start',mux,Buffer.alloc(0),'p'));
 assert.throws(()=>I.optionsFor(plan,'metadataFetch',mux,Buffer.alloc(0),'p'));
});
test('fixed command derivation has no caller argv/env and keeps remote time/output caps',()=>{
 const plan={spec:{root:'/repo',guest:'/var/tmp/owasp-ai-goat-v23-build-'+ 'a'.repeat(32)},runId:'a'.repeat(32),binding:{base:'sha256:'+'b'.repeat(64)},
 commands:Object.fromEntries([...I.NORMAL,...I.CLEANUP].map(n=>[n,'fixed-'+n]))};
 const conf=I.optionsFor(plan,'build',mux,Buffer.from('tar'),'/repo/private/input');
 assert.equal(conf.command,'fixed-build');assert.equal(conf.remoteSeconds,310);assert.equal(conf.inputSha256,sha('tar'));
 assert.equal(conf.outputLimit,2*1024**2);assert.equal(I.optionsFor(plan,'retainedExport',mux,Buffer.alloc(0),'/repo/private/input').outputLimit,145*1024**2);
 assert.throws(()=>I.optionsFor(plan,'arbitrary',null,Buffer.alloc(0),'x'));
 assert(I.SOURCE.includes("mux.mux_command(before,shlex.join(remote))"));
 assert(!I.SOURCE.includes('limactl'));assert(!I.SOURCE.includes('shell=True'));
});
test('public factory rejects arbitrary options and preabort before any source/allocation/launch',async()=>{
 await assert.rejects(driver.createOwnedSystemDriver({launch(){throw Error('effect');}}),/SYSTEM_DRIVER_OPTIONS/);
 const c=new AbortController();c.abort(Error('stopped'));
 await assert.rejects(driver.createOwnedSystemDriver({plan:null,signal:c.signal,deadline:performance.now()+100000,
 expectedPlanSha256:'a',expectedDriverSha256:'b',expectedPythonSha256:'c'}),/stopped/);
 await assert.rejects(driver.createOwnedSystemDriver({plan:{target:'original-v03-diagnostic'},
  signal:new AbortController().signal,deadline:performance.now()+100000,combinedOwner:{},
  expectedPlanSha256:'a',expectedDriverSha256:'b',expectedPythonSha256:'c'}),/V03_COMBINED_OWNER_REQUIRED/);
});
async function fakeCall(value,{code=0,signal=null,oversize=false,pipeFailure=false}={}){
 const calls=[],conf={root:'/repo',phase,expectedMux:mux,remoteSeconds:1};
 const launch=(file,args,options)=>{
  calls.push({file,args,options});const c=new EventEmitter();Object.assign(c,{pid:99,exitCode:null,signalCode:null,
   stdout:new PassThrough(),stderr:new PassThrough()});
  if(pipeFailure){
   const original=c.stdout.destroy.bind(c.stdout);c.stdout.destroy=()=>{original();calls.push({pipe:'stdout'});throw Error('pipe close');};
   const second=c.stderr.destroy.bind(c.stderr);c.stderr.destroy=()=>{calls.push({pipe:'stderr'});return second();};
  }
  c.kill=s=>{calls.push({signal:s});c.signalCode=s;queueMicrotask(()=>c.emit('close',null,s));return true;};
  queueMicrotask(()=>{c.stdout.write(oversize?Buffer.alloc(65537):JSON.stringify(value));c.exitCode=code;c.signalCode=signal;c.emit('close',code,signal);});
  return c;
 };
 const files={journal:{fd:3},stdout:{fd:4},stderr:{fd:5}};
 try{return {result:await I.executePython(conf,files,{python:'/fixed/python'},launch),calls};}
 catch(error){return {error,calls};}
}
test('actual Node transport binds inherited private descriptors, fixed env and controller PID',async()=>{
 const run=await fakeCall(packet());assert.ifError(run.error);assert.equal(run.result.code,0);
 const call=run.calls[0];assert.equal(call.file,'/fixed/python');
 assert.deepEqual(call.args.slice(0,3),['-I','-S','-B']);assert.deepEqual(call.options.stdio,['ignore','pipe','pipe',3,4,5]);
 assert.deepEqual(Object.keys(call.options.env).sort(),['HOME','PATH','PYTHONDONTWRITEBYTECODE','TMPDIR']);
 assert.equal(call.options.detached,true);
 const wrong=packet();wrong.controller.pid=98;const bad=await fakeCall(wrong);
 assert.equal(bad.error.code,'SYSTEM_DRIVER_CONTROLLER_IDENTITY');assert.equal(bad.error.remoteUncertain,true);
});
test('nonzero, lost terminal, output overflow and actual cleanup debt remain failures',async()=>{
 const cases=[
 [packet(),{code:1}],[{},{}],[packet(),{oversize:true}],
 [Object.assign(packet(),{failure:'PHASE_EXIT'}),{}],
 [Object.assign(packet(),{cleanup:{...retirement(),groupAbsent:false}}),{}],
 ];
 for(const [v,opts]of cases){const r=await fakeCall(v,opts);assert(r.error);assert.equal(r.error.remoteUncertain,true);}
 const missing=await fakeCall({});assert.equal(missing.error.cleanupDebt,true);
});
test('local pipe retirement independently attempts both endpoints and retains failure debt',async()=>{
 const r=await fakeCall(packet(),{pipeFailure:true});
 assert.equal(r.error.code,'SYSTEM_DRIVER_PIPE_RETIREMENT');assert.equal(r.error.cleanupDebt,true);
 assert.equal(r.error.remoteUncertain,true);assert.deepEqual(r.error.pipeCleanupErrors,['stdout']);
 assert.deepEqual(r.calls.filter(v=>v.pipe).map(v=>v.pipe),['stdout','stderr']);
});
function pythonControl(code){
 const run=spawnSync('/opt/homebrew/bin/python3',['-I','-S','-B','-c',I.SOURCE+'\n'+code],{
 encoding:'utf8',timeout:10000,maxBuffer:65536,env:{PATH:'/usr/bin:/bin',PYTHONDONTWRITEBYTECODE:'1'}});
 assert.equal(run.status,0,run.stderr);return run.stdout.trim();
}
const PYTHON_CONTROLS=["class Info:\n start_sec=10;start_usec=20;pgid=44;uid=os.getuid();ruid=os.getuid()\nclass Api:\n def identity(self,pid):return Info()\n def group_pids(self,pid):return []\nclass Proc:\n pid=44;returncode=None\n def wait(self,timeout):self.returncode=0\nsent=[];os.killpg=lambda pid,sig:sent.append((pid,sig))\np=Proc();r=retire(Api(),p,(99,20,44,os.getuid(),os.getuid()))\nassert not sent and r['errors']==['SIGNAL_UNPROVEN'] and r['reaped'] and r['groupAbsent']\np=Proc();r=retire(Api(),p,(10,20,44,os.getuid(),os.getuid()))\nassert len(sent)==1 and not r['errors']\np.returncode=0;retire(Api(),p,(10,20,44,os.getuid(),os.getuid()));assert len(sent)==1\nprint('owned-identity-control')\n","class Info:\n start_sec=10;start_usec=20;pgid=44;uid=os.getuid();ruid=os.getuid()\nclass Api:\n def identity(self,pid):return Info()\n def group_pids(self,pid):return [45]\nclass Proc:\n pid=44;returncode=None\n def wait(self,timeout):raise subprocess.TimeoutExpired('fixed',timeout)\nsent=[]\ndef denied(pid,sig):sent.append(sig);raise PermissionError()\nos.killpg=denied\nr=retire(Api(),Proc(),(10,20,44,os.getuid(),os.getuid()))\nassert len(sent)==2 and not r['reaped'] and not r['groupAbsent'] and len(r['errors'])==2\nprint('uncertainty-preserved')\n","CONF={'root':'/repo','phase':'build','commandSha256':'a'*64}\nevents=[];journal=lambda v:events.append(v)\nclass Info:\n start_sec=1;start_usec=2;pgid=44;uid=os.getuid();ruid=os.getuid()\nclass Api:\n def identity(self,pid):return Info()\n def group_pids(self,pid):return []\nclass Stream:\n def close(self):events.append('close')\nclass Proc:\n pid=44;returncode=None;stdin=Stream();stdout=Stream();stderr=Stream()\n def wait(self,timeout):self.returncode=-15\ndef launch(*args,**kw):\n assert events[0]['stage']=='dispatch-intent'\n assert kw['start_new_session'] and kw['close_fds']\n events.append('popen');return Proc()\nsubprocess.Popen=launch\ndef broken():raise RuntimeError('selector allocation failure')\nselectors.DefaultSelector=broken\nos.killpg=lambda pid,sig:events.append(('kill',pid))\nresult,_=run(['/usr/bin/ssh'],b'',1,65536,Api(),True)\nassert result['failure']=='OPERATION_FAILED' and result['cleanup']['reaped'] and result['cleanup']['groupAbsent']\nassert events.count('close')==3\nassert events[-1]['stage']=='child-terminal'\nprint('partial-launch-retired')\n"];
test('exact emitted Python refuses reused birth/group without signaling',()=>{
 assert.equal(pythonControl(PYTHON_CONTROLS[0]),'owned-identity-control');
});
test('emitted cleanup attempts both signals/waits and retains uncertain descendants',()=>{
 assert.equal(pythonControl(PYTHON_CONTROLS[1]),'uncertainty-preserved');
});
test('emitted coordinator journals before Popen and handles selector allocation failure',()=>{
 assert.equal(pythonControl(PYTHON_CONTROLS[2]),'partial-launch-retired');
});
test('actual emitted controller denies Popen after delayed intent expiry or cancellation',()=>{
 assert.equal(pythonControl(String.raw`
CONF={'root':'/repo','phase':'stop','commandSha256':'a'*64}
clock=[100];time.monotonic=lambda:clock[0]
launches=[];subprocess.Popen=lambda *args,**kwargs:launches.append(args)
for kind in ('deadline','abort'):
 CANCELLED=False;clock[0]=100
 def delayed(value):
  global CANCELLED
  if value['stage']=='dispatch-intent':
   if kind=='abort':CANCELLED=True
   else:clock[0]+=11
 journal=delayed
 result,_=run(['/fixed/mux'],b'',10,65536,None,True)
 assert result['failure']==('INTERRUPTED' if kind=='abort' else 'PHASE_TIMEOUT')
 assert result['cleanup']['reaped'] and result['cleanup']['groupAbsent'] and not launches
print('no-late-popen')
`),'no-late-popen');
});


test('already aborted transport performs zero process launches',async()=>{
 const c=new AbortController();c.abort(Error('before spawn'));let calls=0;
 await assert.rejects(I.executePython({},{},{python:'/fixed/python',signal:c.signal},()=>{calls++;}),/before spawn/);
 assert.equal(calls,0);
});
test('already exited controller with unclosed pipes has bounded debt and receives no signal',async()=>{
 const fs=require('node:fs/promises'),vm=require('node:vm'),path=require('node:path');
 const source=await fs.readFile(path.join(__dirname,'postgres/ownedSystemConfigPhaseDriver.js'),'utf8');
 const timers=[],module={exports:{}};let signals=0;
 const timer=(fn,ms)=>{const row={fn,ms,cleared:false};timers.push(row);return row;};
 vm.runInNewContext('(function(require,module,exports){'+source+'\n})',{
  Buffer,performance,AbortSignal,setTimeout:timer,clearTimeout:row=>{if(row)row.cleared=true;},process
 })(id=>id==='./ownedSystemConfigBuildAdapter'?{}:require(id.startsWith('./owned')?'./postgres/'+id.slice(2):id),module,module.exports);
 const child=new EventEmitter();Object.assign(child,{pid:99,exitCode:0,signalCode:null,
  stdout:new PassThrough(),stderr:new PassThrough(),kill(){signals++;}});
 const pending=module.exports._internals.executePython({root:'/repo',phase:'inventory',remoteSeconds:1},
  {journal:{fd:3},stdout:{fd:4},stderr:{fd:5}},{python:'/fixed/python'},()=>child);
 const observed=pending.then(()=>({unexpected:true}),error=>error);
 assert.equal(timers.length,1);assert.equal(timers[0].ms,41000);timers[0].fn();
 const join=timers.find(row=>row.ms===6000);assert(join);assert.equal(signals,0);join.fn();
 const failure=await observed;assert.equal(failure.code,'SYSTEM_DRIVER_CONTROLLER_TIMEOUT');
 assert.equal(failure.cleanupDebt,true);assert.equal(failure.remoteUncertain,true);assert.equal(signals,0);
 assert.equal(child.stdout.destroyed,true);assert.equal(child.stderr.destroyed,true);
 assert.equal(child.stdout.listenerCount('data'),0);assert.equal(child.stderr.listenerCount('data'),0);
 assert.equal(child.listenerCount('close'),0);
 child.emit('error',Error('late'));child.stdout.emit('error',Error('late pipe'));
 assert(timers.every(row=>row.cleared));
});
async function virtualDriver(fault='',pair=false,diagnostic=false){
 const fs=require('node:fs/promises'),path=require('node:path'),vm=require('node:vm');
 const filename=path.resolve(__dirname,'postgres/ownedSystemConfigPhaseDriver.js'),source=await fs.readFile(filename,'utf8');
 const root=path.resolve(__dirname,'..'),runId='7'.repeat(32),directory=path.join(root,'tasks/tmp','system-driver-'+runId);
 const map=new Map(),descriptors=new Map(),calls=[],closeEvents=[],waiters=[],configs=[],openFlags=[];let number=40,clock=1000,dirs=false,abortOnce=false,bridgeCompletion;
 const controller=new AbortController();
 let diagnosticPhase='diagnosticBuildMs',revoked=false;
 const diagnosticWindows={diagnosticBuildMs:{deadlineMs:1801000},diagnosticStartupMs:{deadlineMs:121000},
  cohortClaim:{deadlineMs:11000},diagnosticControllerJoinMs:{deadlineMs:7000},diagnosticCleanupMs:{deadlineMs:601000}};
 diagnosticWindows.diagnosticLostReplyMs={deadlineMs:337000};
 const clockMapping={binding:()=>({parentRunId:'8'.repeat(32),combinedPlanSha256:'9'.repeat(64),guestBootId:'01234567-0123-0123-0123-012345678901',
  guestMonotonicMs:101000,receivedAtMs:1100}),uncertaintyMs:()=>101,
  mapDeadline:value=>value+99899,mapInterval:value=>({startedAtMs:value.startedAtMs+99899,deadlineMs:value.deadlineMs+99899}),
  mapRetirementInterval:kind=>{assert.equal(kind,'diagnosticCleanupMs');assert(revoked);return {startedAtMs:100899,deadlineMs:700899};}};
 const combinedOwner={isRevoked:()=>revoked,remainingMs:()=>11096000-(clock-1000),binding:()=>({expiresAtMs:11097000}),
  cohortDeadlineMs:()=>1211000,
  clockMapping:()=>clockMapping,
  producerBinding:kind=>{assert.equal(kind,'diagnostic');return {parentRunId:'8'.repeat(32),runId,planSha256:'9'.repeat(64),expiresAtMs:11097000};},
  phaseWindow:kind=>{assert.equal(kind,diagnosticPhase);return diagnosticWindows[kind];},
  phaseSignal:kind=>{assert.equal(kind,diagnosticPhase);return controller.signal;}};
 let relayFixture;
 if(fault.startsWith('qualified-')){
  const file=path.resolve(__dirname,'ownedSystemConfigBuildAdapter.test.js'),mod={exports:{}};
  const local=require('node:module').createRequire(file);
  new Function('require','module','exports','__dirname','__filename',await fs.readFile(file,'utf8')+'\nmodule.exports=pairRelayFixture;')(
   id=>id==='node:test'?()=>{}:local(id),mod,mod.exports,__dirname,file);
  relayFixture=await mod.exports();
  const rows=relayFixture.packet.files['relay.adapter.log'].trim().split('\n').map(JSON.parse);
  const start=JSON.parse(relayFixture.observations.find(r=>r.name==='systemReserve').value).before.rows.adapter.pairBudget.connections;
  // Preserve the actual accept-thread ordinal: this fixture exercises a
  // qualification-only denial, not malformed transport ownership evidence.
  rows[0].records[start]={...rows[0].records[start],host:'deb.debian.org',status:'denied'};
  if(fault==='qualified-malformed-ordinal')delete rows[0].records[start].connection;
  relayFixture.packet.files['relay.adapter.log']=rows.map(JSON.stringify).join('\n');
 }
 const pins=require('./postgres/ownedMcpBoundedBuild').PINS;
 const network={version:1,bridge:{},links:[{ifname:'docker0'}],addresses:[],routes4:[],routes6:[],rules4:[],rules6:[],firewall4:[],firewall6:[],nft:[],forwarding:{}};
 const inventory=JSON.stringify(pins.daemon)+'\n'+pins.postgres+' postgres:18\nNETWORK\n'+JSON.stringify(network);
 const fakeFs={
  async realpath(p){if(p===directory||p.startsWith(directory+'/'))return p;return fs.realpath(p);},
  async mkdir(p){assert.equal(p,directory);if(dirs)throw Error('exists');dirs=true;},
  async open(p,flags,mode){
   if(p!==directory&&!p.startsWith(directory+'/'))return fs.open(p,flags);
   openFlags.push({path:p,flags,mode});
   const writing=Boolean(flags&require('node:fs').constants.O_CREAT);
   if(writing){if(map.has(p))throw Error('exists');map.set(p,Buffer.alloc(0));}
   if(p!==directory&&!map.has(p))throw Error('missing');
   let offset=0;const handle={fd:number++,
    async stat(){return {isFile:()=>p!==directory,nlink:1,size:map.get(p)?.length||0,mtimeMs:1,ctimeMs:1};},
    async write(b,start,length){const part=Buffer.from(b).subarray(start,start+length);map.set(p,Buffer.concat([map.get(p),part]));return {bytesWritten:part.length};},
    async writeFile(b){map.set(p,Buffer.from(b));},
    async sync(){if(['setup-sync-journal-close','setup-sync-directory-close'].includes(fault)&&p===directory)throw Object.assign(Error('setup sync primary'),{code:'SETUP_SYNC_PRIMARY'});
     if(fault==='abort-journal'&&p.endsWith('journal.jsonl')&&!abortOnce){abortOnce=true;controller.abort(Error('journal abort'));}
     if(fault==='policy-preparation-expiry'&&p.endsWith('journal.jsonl')&&!abortOnce&&map.get(p).includes(Buffer.from('policy-runtime-start'))){abortOnce=true;clock+=900001;}
     if(fault==='diagnostic-preparation-expiry'&&p.endsWith('journal.jsonl')&&!abortOnce&&map.get(p).includes(Buffer.from('diagnostic-runtime-start'))){abortOnce=true;clock+=120001;}
     if(fault==='bridge-sync'&&p.endsWith('bridge.stdout'))throw Error('bridge sync');
     if(fault==='pair-export'&&p.endsWith('-policyExport.stdout')||fault==='failed-export-sync'&&p.endsWith('-policyFailureExport.stdout'))throw Error('archive sync');
     if(fault==='qualified-export'&&p.endsWith('-policyExport.stdout'))throw Error('archive sync');
     if(fault==='qualified-journal'&&p.endsWith('journal.jsonl')&&map.get(p).includes(Buffer.from('"name":"evidence","code"')))throw Error('journal sync');
     if(fault==='qualified-deadline'&&p.endsWith('-policyExport.stdout'))clock+=600001;
     if(fault==='cleanup-preparation-expiry'&&p.endsWith('journal.jsonl')&&map.get(p).includes(Buffer.from('"name":"stop"')))clock+=600001;},
    async read(b,start,length,position){const bytes=map.get(p)||Buffer.alloc(0);position??=offset;
     const n=Math.max(0,Math.min(length,bytes.length-position));bytes.copy(b,start,position,position+n);offset=position+n;return {bytesRead:n};},
    async close(){closeEvents.push(p);
     if(fault==='setup-sync-journal-close'&&p.endsWith('journal.jsonl')
      ||['setup-directory-close','setup-sync-directory-close'].includes(fault)&&p===directory)throw Error('setup close unproven');
     if(writing&&fault==='stdout-close'&&p.endsWith('001-inventory.stdout')
     ||fault==='qualified-close'&&p.endsWith('-evidence.stdout'))throw Error('close');}
   };descriptors.set(handle.fd,p);return handle;
  }
 };
 const plan={spec:{root,guest:'/var/tmp/owasp-ai-goat-v23-build-'+runId},runId,binding:{base:'sha256:'+'a'.repeat(64)},
  captured:{recipe:{},inputSha256:'c'.repeat(64)},helperHashes:{'tests/postgres/owned_system_private_http_channel.py':'f'.repeat(64)},
  commands:Object.fromEntries([...I.NORMAL,...I.CLEANUP].map(n=>[n,'fixed:'+n])),
  metadataGuestSource:'fixed metadata',guestSource:'fixed artifact guest'};
 let diagnosticMetadata;
 if(diagnostic){
  plan.target='original-v03-diagnostic';
  // Reuse the controlled complete DTO; real metadata validation remains active.
  const file=path.resolve(__dirname,'ownedPolicySystemMetadata.test.js'),mod={exports:{}};
  const local=require('node:module').createRequire(file);
  new Function('require','module','exports',await fs.readFile(file,'utf8')+'\nmodule.exports=systemRetainedEnvelope;')(
   id=>id==='node:test'?()=>{}:local(id),mod,mod.exports);
  diagnosticMetadata=structuredClone(mod.exports());
  plan.binding={runId,target:'v03-diagnostic',base:require('./postgres/ownedPolicySystemBuild').TARGETS['v03-diagnostic'].base};
  diagnosticMetadata.binding={...plan.binding};
  diagnosticMetadata.candidate.sourcePolicy.policy='v03-diagnostic-trixie-freshness-v1';
  diagnosticMetadata.candidate.retainedMetadata.kind='v03-diagnostic-original-apt-retention';
  diagnosticMetadata.candidate.retainedMetadata.binding={...plan.binding};
  diagnosticMetadata.candidate.retainedMetadata.stages[0].name='diagnostic';
 }
 const pairApi=require('./postgres/ownedSystemConfigBuildAdapter')._internals;
 if(pair){
  plan.target=pairApi.PAIR_TARGET;plan.slots={};
  for(const slot of ['system','policy'])plan.slots[slot]={binding:{base:'sha256:'+(slot==='system'?'a':'b').repeat(64)},captured:{},
   metadataSource:'metadata-'+slot,acquisitionSource:'acquisition-'+slot,replaySource:'replay-'+slot};
  plan.commands=Object.fromEntries([...pairApi.PAIR_PHASES,...pairApi.PAIR_CLEANUP].map(n=>[n,'fixed:'+n]));
 }
 const binding={version:1,target:'original-v24-system',runId,imageId:'sha256:'+'d'.repeat(64),inputSha256:'c'.repeat(64),daemonId:'controlled-private-id',
  physical:{privateDockerHost:'unix://'+plan.spec.guest+'/fs/docker.sock',namespaceInode:'net:[12345]',filesystemIdentity:{device:1,inode:2},
   daemonProcess:{pid:101,startTicks:'100',exe:'/usr/bin/dockerd'},namespaceHolder:{pid:102,startTicks:'101',exe:'/usr/bin/sleep'}}};
 const runtimeRow={version:1,runId,containerId:'e'.repeat(64),imageId:binding.imageId,running:true,namespaceInode:12345};
 if(diagnostic)binding.target='original-v03-diagnostic';
 const remote={version:1,runId,containerAbsent:true,profileAbsent:true,remoteChannelsAbsent:true,channelFailures:[],builderReleaseAllowed:false};
 const local={version:1,runId,channelIds:['b'.repeat(32)],localRetired:true,retirementUnproven:false,remoteRetired:false,builderReleaseAllowed:false,failures:[]};
 const stable=JSON.stringify(plan),planSha=sha(stable);
 const fakeAdapter={systemBuildPlan:async()=>Object.freeze(structuredClone(plan)),systemPolicyBuildPlan:async()=>Object.freeze(structuredClone(plan)),planDigest:p=>sha(JSON.stringify(p)),
  verifyPlan:async p=>assert.equal(JSON.stringify(p),stable),_internals:{contextBytes:async()=>Buffer.from('exact-context'),
   rendererContextBytes:async()=>Buffer.from('exact-renderer-context'),PAIR_PHASES:pairApi.PAIR_PHASES,PAIR_CLEANUP:pairApi.PAIR_CLEANUP,
   PAIR_CREDIT_PHASES:pairApi.PAIR_CREDIT_PHASES,
   pairMetadataComplete:(p,rows,slot)=>rows.some(row=>row.name===slot+'Metadata'),
   validatePairPhaseAdmission(p,rows,name){calls.push('admit:'+name);if(name==='policyReserve')this.validatePairAcquisitionBudget(p,rows);
    if(fault==='pair-signed-join'&&name==='policyOverhead')throw Error('prior authenticated join');},
   validatePairCredits(p,rows,name){calls.push('credits:'+name);if(fault==='pair-partial-ack'&&name==='systemReserve')throw Error('both process ACK required');},
   isPairRelayQualificationFailure:pairApi.isPairRelayQualificationFailure,
   validatePairRelayTerminal(){calls.push('terminal-credits');if(fault==='pair-terminal')throw Error('terminal credit debt');
    if(relayFixture)pairApi.validatePairRelayTerminal(relayFixture.plan,relayFixture.observations,JSON.stringify(relayFixture.packet));},
   validatePairAcquisitionBudget(p,rows){assert.equal(rows.at(-1).name,'policyMetadataRetire');calls.push('pair-budget');
    if(fault==='pair-budget')throw Error('combined artifact cap');},
   validatePairDriverObservations:async(p,rows)=>{assert.deepEqual(Array.from(rows,x=>x.name),Array.from(pairApi.PAIR_PHASES));
    if(fault.startsWith('qualified-'))throw Object.assign(Error('original pre-cohort failure'),{code:'CONTROLLED_PRIMARY'});
    return {version:1,target:pairApi.PAIR_TARGET,runId,daemonId:binding.daemonId,physical:binding.physical,
     images:{system:{imageId:binding.imageId,inputSha256:binding.inputSha256},policy:{imageId:'sha256:'+'f'.repeat(64),inputSha256:'9'.repeat(64)}},runtimeAvailable:false};},
   validateDriverObservations:async(p,rows)=>{assert.deepEqual(Array.from(rows,x=>x.name),Array.from(I.NORMAL));return structuredClone(binding);}}};
 const fakeTransport={operation(p,b,kind,token,ids=[]){const policy=b.target==='original-v24-policy',slot=policy?'policy':'system';
  assert.equal(b.imageId,policy?'sha256:'+'f'.repeat(64):binding.imageId);
  if(kind==='start')assert.equal(token,policy?undefined:'t'.repeat(43));if(kind==='stop')assert.deepEqual(Array.from(ids),calls.includes(policy?'policy-bridge-open':'bridge-open')?local.channelIds:[]);
  return {name:slot+'-runtime-'+kind,command:'fixed:'+slot+'-runtime-'+kind,input:Buffer.from('{}')};},
  async openOwnedBridge(o){const policy=o.binding.target==='original-v24-policy';calls.push(policy?'policy-bridge-open':'bridge-open');assert.equal(o.binding.runId,runId);
   if(fault==='bridge-start')throw Object.assign(Error('bridge lost'),{retirementUnproven:true});
   map.set(descriptors.get(o.files.journal.fd),Buffer.from(JSON.stringify({version:1,stage:'channel-intent',runId,channelId:local.channelIds[0]})+'\n'));
   return {port:policy?18091:18090,async close(){calls.push(policy?'policy-bridge-close':'bridge-close');
    if(diagnostic&&fault.startsWith('diagnostic-slow-'))await new Promise((resolve,reject)=>{bridgeCompletion={resolve,reject};});
    if(policy&&fault==='policy-bridge-debt')throw Error('renderer channel unjoined');
    if(diagnostic&&fault==='diagnostic-bridge-debt')throw Error('diagnostic channel unjoined');
    return {...local,channelIds:[...local.channelIds],failures:[],...(policy||diagnostic?{target:o.binding.target}:{}),
     ...(fault==='diagnostic-no-marker'?{localRetired:undefined}:{})};}};
  }};
 const launch=(file,args,opts)=>{
  const conf=JSON.parse(JSON.parse(args[4].split('\n')[0].slice(5)));
  assert.equal(conf.command,'fixed:'+conf.phase);assert.equal(conf.root,root);
  calls.push(conf.phase);
  configs.push({...conf,at:clock});
  const c=new EventEmitter();Object.assign(c,{pid:99,exitCode:null,signalCode:null,stdout:new PassThrough(),stderr:new PassThrough()});
  c.kill=()=>true;
  queueMicrotask(()=>{
   const lastInventory=conf.phase==='inventory'&&calls.filter(n=>n==='inventory').length>1;
   const inventoryOutput=fault==='inventory-first'||lastInventory&&fault==='inventory-malformed'?'malformed':
    lastInventory&&fault==='inventory-changed'?inventory.replace('\nNETWORK\n','\nnew-shared-volume\nNETWORK\n'):inventory;
   const out=diagnostic&&conf.phase==='metadataFetch'?JSON.stringify(diagnosticMetadata):conf.phase==='inventory'?inventoryOutput:conf.phase==='diagnostic-runtime-claim-cohort'?JSON.stringify({version:1,runId,target:binding.target,claimed:true}):
    conf.phase==='diagnostic-runtime-stop'?JSON.stringify({...remote,target:binding.target}):
    conf.phase==='diagnostic-runtime-start'?JSON.stringify({...runtimeRow,target:binding.target}):
    conf.phase==='policy-runtime-stop'?JSON.stringify({...remote,target:'original-v24-policy'}):
    conf.phase.startsWith('policy-runtime-')?JSON.stringify({...runtimeRow,target:'original-v24-policy',imageId:'sha256:'+'f'.repeat(64),namespaceInode:23456,containerId:'f'.repeat(64)}):
    conf.phase==='system-runtime-stop'?JSON.stringify(remote):conf.phase.startsWith('system-runtime-')?JSON.stringify(runtimeRow):
    conf.phase==='cleanup'?(fault==='cleanup-marker'?'present\n':'absent\n'):
    conf.phase==='retireArtifacts'||pair&&/Retire$/.test(conf.phase)?(fault==='pair-retirement'&&conf.phase==='policyReplayRetire'?'present\n':'absent\n'):
    I.archivePhase(conf.phase)?'controlled archive':'controlled '+conf.phase;
   const outBytes=Buffer.from(out);map.set(descriptors.get(opts.stdio[4]),outBytes);
   map.set(descriptors.get(opts.stdio[5]),Buffer.alloc(0));
   const receipt=packet();receipt.phase=conf.phase;receipt.stdout={bytes:outBytes.length,sha256:sha(outBytes)};
   if(fault==='lost-reply'&&conf.phase==='prepare'){c.exitCode=255;c.emit('close',255,null);return;}
   if(['metadata-failure','metadata-abort','failed-export-sync','cleanup-preparation-expiry','cleanup-time-spent'].includes(fault)&&conf.phase==='policyMetadata'){
    if(fault==='metadata-abort')controller.abort(Error('controlled abort'));
    receipt.code=1;receipt.failure='PHASE_EXIT';c.stdout.end(JSON.stringify(receipt));c.exitCode=1;c.emit('close',1,null);return;}
   if(fault==='cleanup-time-spent'&&conf.phase.endsWith('Retire')&&clock>300000)clock+=170000;
   if(fault==='hash'&&conf.phase==='prepare')receipt.stdout.sha256='0'.repeat(64);
   c.stdout.end(JSON.stringify(receipt));c.exitCode=0;c.emit('close',0,null);
  });return c;
 };
 const module={exports:{}};
 const load=id=>id==='node:fs/promises'?fakeFs:id==='node:child_process'?{spawn:launch}:
  id==='./ownedV03PrivateExecutors'?{assertCombinedOwner:value=>{assert.equal(value,combinedOwner);return value;}}:
  id==='./ownedV03GuestClock'?{assertGuestClockMapping:(value,owner)=>{assert.equal(value,clockMapping);assert.equal(owner,combinedOwner);return value;}}:
  id==='./ownedSystemDiagnosticRuntime'?{...require('./postgres/ownedSystemDiagnosticRuntime'),
   operation(p,b,kind,settings,ids){assert.equal(b.target,'original-v03-diagnostic');
    calls.push('diagnostic-settings:'+kind);configs.push({kind,settings,ids});
    return {name:'diagnostic-runtime-'+kind,command:'fixed:diagnostic-runtime-'+kind,input:Buffer.from(JSON.stringify(settings))};}}:
  id==='./ownedSystemDiagnosticBuildAdapter'?{diagnosticBuildPlan:async()=>Object.freeze(structuredClone(plan))}:
  id==='./ownedSystemConfigBuildAdapter'?fakeAdapter:id==='./ownedSystemRuntimeTransport'?fakeTransport:
  require(id.startsWith('./owned')?'./postgres/'+id.slice(2):id);
 const timers=(fn,ms)=>{
  // Controller watchdogs are cancelled by the fake child close. Only the
  // uncertainty join is manually advanced, never actually wait330s in tests.
  if(ms===330000||ms===170000||ms===329999){const row={fn,ms,cancelled:false};waiters.push(row);return row;}
  return setTimeout(fn,ms);
 };
 const clear=timer=>{if(waiters.includes(timer))timer.cancelled=true;else clearTimeout(timer);};
 vm.runInNewContext('(function(require,module,exports,__filename){'+source+'\n})',{Buffer,URL,AbortSignal,AbortController,performance:{now:()=>clock},
  structuredClone,setTimeout:timers,clearTimeout:clear,process})(load,module,module.exports,filename);
 const python=await fs.realpath('/opt/homebrew/bin/python3');
 const owned=await module.exports.createOwnedSystemDriver({plan,signal:controller.signal,deadline:clock+1800000,
  expectedPlanSha256:planSha,expectedDriverSha256:sha(source),expectedPythonSha256:sha(await fs.readFile(python)),...(diagnostic?{combinedOwner}:{})});
 return {owned,calls,map,closeEvents,configs,waiters,openFlags,advance:ms=>{clock+=ms;},
  completeBridge(error){assert(bridgeCompletion);error?bridgeCompletion.reject(error):bridgeCompletion.resolve();},
  wake(){const row=waiters.find(r=>!r.cancelled);assert(row);row.cancelled=true;row.fn();},
  async produce(){
   const filename=path.resolve(__dirname,'postgres/ownedSystemImageProducer.js'),source=await fs.readFile(filename,'utf8'),module={exports:{}};
   vm.runInNewContext('(function(require,module,exports,__filename){'+source+'\n})',
    {Buffer,AbortController,AbortSignal,AggregateError,performance:{now:()=>clock},setTimeout,clearTimeout})(
    id=>id==='./ownedSystemConfigBuildAdapter'?fakeAdapter:id==='./ownedSystemConfigPhaseDriver'?{createOwnedSystemDriver:async()=>owned}:
     require(id.startsWith('./owned')?'./postgres/'+id.slice(2):id),module,module.exports,filename);
   return module.exports.withPrivateSystemAndPolicyImages({root,runId,recipe:plan.captured.recipe,signal:controller.signal,buildDeadline:clock+1800000,
    expectedPlanSha256:planSha,expectedProducerSha256:sha(source),expectedDriverSha256:sha(await fs.readFile(path.resolve(__dirname,'postgres/ownedSystemConfigPhaseDriver.js'))),
    expectedPythonSha256:sha(await fs.readFile(python))},()=>assert.fail('failed metadata cannot invoke cohort'));
  },diagnosticPhase:(kind,retiring=false)=>{diagnosticPhase=kind;revoked=retiring;},
  enterDiagnosticCleanup:()=>{diagnosticPhase='diagnosticCleanupMs';revoked=true;},mutate:()=>{plan.commands.prepare='injected';}};
}
test('actual early driver setup preserves primary and marks directory or journal close uncertainty',async()=>{
 for(const [fault,detail]of [['setup-sync-journal-close','JOURNAL_CLOSE_UNPROVEN'],
  ['setup-directory-close','DIRECTORY_CLOSE_UNPROVEN'],['setup-sync-directory-close','DIRECTORY_CLOSE_UNPROVEN']])
  await assert.rejects(virtualDriver(fault,false,true),error=>error.cleanupDebt===true
   &&error.driverSetupCleanupErrors.includes(detail)
   &&(fault==='setup-directory-close'?error.message==='setup close unproven':error.code==='SETUP_SYNC_PRIMARY'));
});
test('actual diagnostic driver follows parent phases, mapped cohort, owned bridge join and remote retirement',async()=>{
 const v=await virtualDriver('',false,true);
 assert.throws(()=>v.owned.claimDiagnosticRuntime(),/NOT_ADMITTED/);
 for(const name of I.NORMAL)await v.owned.run(name);
 await v.owned.claimDiagnosticImage();const runtime=v.owned.claimDiagnosticRuntime();
 assert.throws(()=>v.owned.claimDiagnosticRuntime(),/NOT_ADMITTED/);
 v.diagnosticPhase('diagnosticStartupMs');
 assert.equal((await runtime.startRuntime('t'.repeat(43))).ready,true);
 await assert.rejects(runtime.startRuntime('t'.repeat(43)),/START_ONCE/);
 v.diagnosticPhase('cohortClaim');assert.equal((await runtime.claimCohort()).port,18090);
 const claim=v.configs.find(row=>row.kind==='claim-cohort').settings.cohort;
 assert.equal(claim.deadlineMs-claim.startedAtMs,1210000);
 assert.equal(claim.combinedPlanSha256,'9'.repeat(64));assert.equal(claim.phase,'cohortClaim');
 await assert.rejects(runtime.claimCohort(),/COHORT_ONCE/);
 assert.throws(()=>runtime.join(),/RETIREMENT_ORDER/);
 await assert.rejects(v.owned.close(),/RETIREMENT_UNPROVEN/);
 v.diagnosticPhase('diagnosticControllerJoinMs',true);assert.equal(runtime.join().joinRequested,true);
 v.diagnosticPhase('diagnosticLostReplyMs',true);assert.equal((await runtime.settle()).localRetired,true);
 v.enterDiagnosticCleanup();assert.equal((await runtime.stopRuntime()).containerAbsent,true);
 assert.equal((await v.owned.close()).remoteCleanupVerified,true);
 assert.equal(v.calls.filter(name=>name==='bridge-close').length,1);
});
test('diagnostic bridge7s and26s joins settle once within existing330s phase, uncertainty blocks cleanup',async()=>{
 for(const duration of [7000,26000,26001]){
  const v=await virtualDriver('diagnostic-slow-'+duration,false,true);
  for(const name of I.NORMAL)await v.owned.run(name);
  await v.owned.claimDiagnosticImage();const runtime=v.owned.claimDiagnosticRuntime();v.diagnosticPhase('diagnosticStartupMs');
  await runtime.startRuntime('t'.repeat(43));v.diagnosticPhase('cohortClaim');await runtime.claimCohort();
  v.diagnosticPhase('diagnosticControllerJoinMs',true);assert.deepEqual({...runtime.join()},{joinRequested:true});
  assert.equal(v.calls.filter(name=>name==='bridge-close').length,1);
  v.diagnosticPhase('diagnosticLostReplyMs',true);let settled=false;
  const pending=runtime.settle();pending.then(()=>{settled=true;},()=>{});
  await Promise.resolve();assert.equal(settled,false);assert(!v.calls.includes('diagnostic-runtime-stop'));
  v.advance(duration);v.completeBridge(duration>26000?Error('transport join unproven'):null);
  if(duration>26000){await assert.rejects(pending,/unproven/);v.enterDiagnosticCleanup();
   await assert.rejects(runtime.stopRuntime(),/UNPROVEN/);await assert.rejects(v.owned.close(),/RETIREMENT_UNPROVEN/);
  }else{assert.equal((await pending).localRetired,true);v.enterDiagnosticCleanup();await runtime.stopRuntime();await v.owned.close();}
  assert.equal(v.calls.filter(name=>name==='bridge-close').length,1);
 }
});
test('actual diagnostic predispatch expiry and bridge retirement debt cannot authorize builder deletion',async()=>{
 for(const fault of ['diagnostic-preparation-expiry','diagnostic-bridge-debt','bridge-start','bridge-sync','diagnostic-no-marker']){
  const v=await virtualDriver(fault,false,true);
  for(const name of I.NORMAL)await v.owned.run(name);
  await v.owned.claimDiagnosticImage();const runtime=v.owned.claimDiagnosticRuntime();v.diagnosticPhase('diagnosticStartupMs');
  if(fault==='diagnostic-preparation-expiry'){
   await assert.rejects(runtime.startRuntime('t'.repeat(43)),/DEADLINE/);
   assert(!v.calls.includes('diagnostic-runtime-start'));
  }else{
   await runtime.startRuntime('t'.repeat(43));v.diagnosticPhase('cohortClaim');
   if(fault==='bridge-start')await assert.rejects(runtime.claimCohort(),/bridge lost/);else await runtime.claimCohort();
   v.diagnosticPhase('diagnosticControllerJoinMs',true);assert.equal(runtime.join().joinRequested,true);
   assert.throws(()=>runtime.join(),/ALREADY_ATTEMPTED/);
   v.diagnosticPhase('diagnosticLostReplyMs',true);await assert.rejects(runtime.settle());
   assert.equal(v.closeEvents.filter(name=>name.endsWith('diagnostic-bridge.stdout')).length,1);
   v.enterDiagnosticCleanup();await assert.rejects(runtime.stopRuntime(),/UNPROVEN/);
  }
  await assert.rejects(v.owned.close(),/RETIREMENT_UNPROVEN/);assert(!v.calls.includes('cleanup'));
 }
});
test('late diagnostic join continuation cannot cross settlement phase into remote deletion',async()=>{
 const v=await virtualDriver('diagnostic-slow-late',false,true);
 for(const name of I.NORMAL)await v.owned.run(name);
 await v.owned.claimDiagnosticImage();const runtime=v.owned.claimDiagnosticRuntime();v.diagnosticPhase('diagnosticStartupMs');
 await runtime.startRuntime('t'.repeat(43));v.diagnosticPhase('cohortClaim');await runtime.claimCohort();
 v.diagnosticPhase('diagnosticControllerJoinMs',true);runtime.join();v.diagnosticPhase('diagnosticLostReplyMs',true);
 const pending=runtime.settle();v.enterDiagnosticCleanup();v.completeBridge();
 await assert.rejects(pending);await assert.rejects(runtime.stopRuntime(),/UNPROVEN/);
 assert(!v.calls.includes('diagnostic-runtime-stop'));assert.equal(v.calls.filter(x=>x==='bridge-close').length,1);
});
test('diagnostic build branch consumes branded parent window and remaining lease but never System runtime',async()=>{
 const v=await virtualDriver('',false,true);
 await assert.rejects(v.owned.claimRuntime(),/DIAGNOSTIC_DISTINCT_RUNTIME_REQUIRED/);
 await assert.rejects(v.owned.claimDiagnosticImage(),/DIAGNOSTIC_IMAGE_NOT_ADMITTED/);
 for(const name of I.NORMAL)await v.owned.run(name);
 const image=await v.owned.claimDiagnosticImage();
 assert.equal(image.binding.target,'original-v03-diagnostic');assert.equal(image.runtimeAvailable,false);
 await assert.rejects(v.owned.claimDiagnosticImage(),/DIAGNOSTIC_IMAGE_NOT_ADMITTED/);
 const input=JSON.parse([...v.map].find(([name])=>name.endsWith('-prepare.input'))[1]);
 assert.deepEqual(input,{version:1,runId:'7'.repeat(32),parentRunId:'8'.repeat(32),combinedPlanSha256:'9'.repeat(64),
  guestBootId:'01234567-0123-0123-0123-012345678901',expiresAtMs:11196899});
 v.enterDiagnosticCleanup();const receipt=await v.owned.close();
 assert.equal(receipt.guestResourcesAbsent,true);assert.equal(receipt.localCleanupVerified,true);
});
test('actual paired driver dispatches target-bound stdin, joins each CID and exports both archives before deletion',async()=>{
 const a=require('./postgres/ownedSystemConfigBuildAdapter')._internals,v=await virtualDriver('',true);
 await assert.rejects(v.owned.claimRuntime(),/SYSTEM_PAIR_RUNTIME_NOT_ADMITTED/);
 await assert.rejects(v.owned.claimImages(),/SYSTEM_PAIR_NOT_ADMITTED/);
 for(const name of a.PAIR_PHASES)await v.owned.run(name);
 const owner=await v.owned.claimImages();assert.equal(owner.binding.images.policy.imageId,'sha256:'+'f'.repeat(64));
 await assert.rejects(v.owned.claimImages(),/SYSTEM_PAIR_NOT_ADMITTED/);
 assert(v.calls.indexOf('pair-budget')<v.calls.indexOf('policyAcquire'));
 for(const slot of ['system','policy'])for(const [suffix,text]of [['Metadata','metadata-'],['Acquire','acquisition-'],['Replay','replay-']]){
  const entry=[...v.map].find(([p])=>p.endsWith('-'+slot+suffix+'.input'));assert(entry);assert.equal(entry[1].toString(),text+slot);
 }
 const receipt=await v.owned.close();assert.equal(receipt.guestResourcesAbsent,true);assert.equal(receipt.sharedStateUnchanged,true);
 for(const slot of ['system','policy'])assert(v.calls.indexOf(slot+'Export')<v.calls.indexOf('cleanup'));
 assert.throws(()=>owner.assertActive(),/SYSTEM_PAIR_INACTIVE/);
 assert.equal(v.calls.filter(x=>x==='systemAcquireRetire').length,1);assert.equal(v.calls.filter(x=>x==='policyReplayRetire').length,1);
});
test('paired runtime owner joins both original images, one cohort and one retirement deadline',async()=>{
 const v=await virtualDriver('',true),phases=require('./postgres/ownedSystemConfigBuildAdapter')._internals.PAIR_PHASES;
 await assert.rejects(v.owned.claimPairedRuntime(),/SYSTEM_PAIR_NOT_ADMITTED/);
 for(const phase of phases)await v.owned.run(phase);
 const owner=await v.owned.claimPairedRuntime(),{system,policy}=owner.slots;
 await assert.rejects(v.owned.claimPairedRuntime(),/SYSTEM_PAIR_RUNTIME_NOT_ADMITTED/);
 await assert.rejects(policy.startRuntime({}),/SYSTEM_PAIR_START_ORDER/);
 await system.startRuntime({token:'t'.repeat(43)});await system.inspectRuntime();await system.openBridge();
 const end=owner.cohortDeadline;v.advance(1000);
 await policy.startRuntime({});await policy.inspectRuntime();await policy.openBridge();assert.equal(owner.cohortDeadline,end);
 await assert.rejects(v.owned.close(),/SYSTEM_RUNTIME_RETIREMENT_UNPROVEN/);
 const retirementEnd=owner.beginRetirement();v.advance(1000);assert.equal(owner.beginRetirement(),retirementEnd);
 assert.equal(system.beginRetirement(),policy.beginRetirement());
 await system.closeBridge();await policy.closeBridge();await system.stopRuntime();await policy.stopRuntime();
 await system.confirmRetired();await policy.confirmRetired();
 const receipt=await v.owned.close();assert.equal(receipt.guestResourcesAbsent,true);
 assert(v.calls.indexOf('policy-bridge-close')<v.calls.indexOf('system-runtime-stop'));
 assert(v.calls.indexOf('policy-runtime-stop')<v.calls.indexOf('stop'));
 for(const slot of ['system','policy'])for(const suffix of ['journal','stdout','stderr'])
  assert([...v.map.keys()].some(p=>p.endsWith('/'+slot+'-bridge.'+suffix)));
});
test('paired openBridge allocates append-only journals for both targets without changing owner or output flags',async()=>{
 const flags=require('node:fs').constants,v=await virtualDriver('',true);
 for(const phase of require('./postgres/ownedSystemConfigBuildAdapter')._internals.PAIR_PHASES)await v.owned.run(phase);
 const owner=await v.owned.claimPairedRuntime();
 for(const slot of ['system','policy']){
  await owner.slots[slot].startRuntime(slot==='system'?{token:'t'.repeat(43)}:{});
  await owner.slots[slot].inspectRuntime();await owner.slots[slot].openBridge();
 }
 const journals=v.openFlags.filter(row=>/bridge\.journal$/.test(row.path));
 assert.deepEqual(journals.map(row=>row.path.split('/').at(-1)).sort(),['policy-bridge.journal','system-bridge.journal']);
 for(const row of journals){
  assert.equal(row.flags&flags.O_APPEND,flags.O_APPEND);
  assert.equal(row.flags&(flags.O_RDWR|flags.O_CREAT|flags.O_EXCL|flags.O_NOFOLLOW),flags.O_RDWR|flags.O_CREAT|flags.O_EXCL|flags.O_NOFOLLOW);
  assert.equal(row.mode,0o600);
 }
 const other=v.openFlags.filter(row=>row.path.endsWith('journal.jsonl')||/bridge\.(stdout|stderr)$/.test(row.path));
 assert.equal(other.filter(row=>/bridge\.(stdout|stderr)$/.test(row.path)).length,4);
 assert(other.some(row=>row.path.endsWith('journal.jsonl')));
 for(const row of other)assert.equal(row.flags&flags.O_APPEND,0,row.path);
 owner.beginRetirement();await owner.slots.system.closeBridge();await owner.slots.policy.closeBridge();
 await owner.slots.system.stopRuntime();await owner.slots.policy.stopRuntime();
 await owner.slots.system.confirmRetired();await owner.slots.policy.confirmRetired();await v.owned.close();
});
test('second target shares elapsed cohort budget and unresolved renderer channels veto builder deletion',async()=>{
 const phases=require('./postgres/ownedSystemConfigBuildAdapter')._internals.PAIR_PHASES;
 const expired=await virtualDriver('',true);for(const phase of phases)await expired.owned.run(phase);
 const first=await expired.owned.claimPairedRuntime();await first.slots.system.startRuntime({token:'t'.repeat(43)});await first.slots.system.inspectRuntime();
 const end=first.cohortDeadline;expired.advance(710000);
 await assert.rejects(first.slots.policy.startRuntime({}),/SYSTEM_DRIVER_DEADLINE/);
 assert.equal(first.cohortDeadline,end);assert(!expired.calls.includes('policy-runtime-start'));
 const v=await virtualDriver('policy-bridge-debt',true);for(const phase of phases)await v.owned.run(phase);
 const owner=await v.owned.claimPairedRuntime();
 for(const slot of ['system','policy']){await owner.slots[slot].startRuntime(slot==='system'?{token:'t'.repeat(43)}:{});await owner.slots[slot].inspectRuntime();await owner.slots[slot].openBridge();}
 owner.beginRetirement();await owner.slots.system.closeBridge();
 await assert.rejects(owner.slots.policy.closeBridge(),/renderer channel unjoined/);
 await assert.rejects(v.owned.close(),/SYSTEM_RUNTIME_RETIREMENT_UNPROVEN/);
 assert(!v.calls.includes('stop'));assert(!v.calls.includes('cleanup'));
});
test('paired runtime rechecks deadline after actual intent publication before remote dispatch',async()=>{
 const v=await virtualDriver('policy-preparation-expiry',true);
 for(const phase of require('./postgres/ownedSystemConfigBuildAdapter')._internals.PAIR_PHASES)await v.owned.run(phase);
 const owner=await v.owned.claimPairedRuntime();await owner.slots.system.startRuntime({token:'t'.repeat(43)});await owner.slots.system.inspectRuntime();
 await assert.rejects(owner.slots.policy.startRuntime({}),/SYSTEM_DRIVER_DEADLINE/);
 assert(!v.calls.includes('policy-runtime-start'));
 await assert.rejects(v.owned.close(),/SYSTEM_RUNTIME_RETIREMENT_UNPROVEN/);assert(!v.calls.includes('cleanup'));
});
test('paired driver refuses combined byte overflow before second acquisition and retains unresolved second retirement/archive debt',async()=>{
 const a=require('./postgres/ownedSystemConfigBuildAdapter')._internals;
 const budget=await virtualDriver('pair-budget',true);
 for(const name of a.PAIR_PHASES){if(name==='policyReserve')break;await budget.owned.run(name);}
 await assert.rejects(budget.owned.run('policyReserve'),/combined artifact cap/);assert(!budget.calls.includes('policyAcquire'));assert(!budget.calls.includes('policyReserve'));
 await budget.owned.close();
 const v=await virtualDriver('pair-retirement',true);
 for(const name of a.PAIR_PHASES){if(name==='policyReplayRetire')break;await v.owned.run(name);}
 await assert.rejects(v.owned.run('policyReplayRetire'),/SYSTEM_DRIVER_REMOTE_ABSENCE/);
 await assert.rejects(v.owned.claimImages(),/SYSTEM_PAIR_NOT_ADMITTED/);
 await assert.rejects(v.owned.close(),/SYSTEM_DRIVER_CLEANUP_DEBT/);assert(!v.calls.includes('stop'));assert(!v.calls.includes('cleanup'));
 assert.equal(v.calls.filter(name=>name==='policyReplayRetire').length,1,'failed retirement must not be retried by close');
 const archive=await virtualDriver('pair-export',true);for(const name of a.PAIR_PHASES)await archive.owned.run(name);
 await assert.rejects(archive.owned.close(),/SYSTEM_DRIVER_CLEANUP_DEBT/);assert(!archive.calls.includes('cleanup'));
 assert.equal(archive.calls.at(-1),'inventory');
});
test('partial credit acknowledgement and failed signed join block the actual next dispatch',async()=>{
 const phases=require('./postgres/ownedSystemConfigBuildAdapter')._internals.PAIR_PHASES;
 for(const [fault,phase,forbidden]of [['pair-partial-ack','systemReserve','systemAcquire'],['pair-signed-join','policyOverhead','policyMetadata']]){
  const v=await virtualDriver(fault,true);
  for(const name of phases){if(name===phase)break;await v.owned.run(name);}
  await assert.rejects(v.owned.run(phase));await assert.rejects(v.owned.run(forbidden));
  assert(!v.calls.includes(forbidden));if(fault==='pair-signed-join')assert(!v.calls.includes(phase));
  await v.owned.close();
 }
 const v=await virtualDriver('pair-terminal',true);
 for(const name of phases)await v.owned.run(name);
 await assert.rejects(v.owned.close(),/CLEANUP_DEBT/);assert(!v.calls.includes('cleanup'));
});
test('real factory uses canonical snapshot, fixed phases and separate verified cleanup without caller callbacks',async()=>{
 const v=await virtualDriver();v.mutate();
 for(const name of I.NORMAL)await v.owned.run(name);
 const receipt=await v.owned.close();assert.equal(receipt.localCleanupVerified,true);assert.equal(receipt.remoteCleanupVerified,true);
 assert.equal(receipt.guestResourcesAbsent,true);assert.equal(receipt.sharedStateUnchanged,true);
 assert.deepEqual(v.calls.slice(0,I.NORMAL.length),I.NORMAL);
 assert(v.calls.indexOf('stop')<v.calls.indexOf('cleanup'));
 const again=await v.owned.close();assert.equal(again,receipt);
 await assert.rejects(v.owned.run('inventory'),/SYSTEM_DRIVER_STATE/);
});
test('factory predispatch abort and file-close debt stop later effect phases',async()=>{
 const aborted=await virtualDriver('abort-journal');
 await assert.rejects(aborted.owned.run('inventory'),/journal abort/);assert.equal(aborted.calls.length,0);
 await aborted.owned.close();
 const debt=await virtualDriver('stdout-close');await debt.owned.run('inventory');
 await assert.rejects(debt.owned.run('preflight'),/SYSTEM_DRIVER_PRIOR_DEBT/);assert.deepEqual(debt.calls,['inventory']);
 await assert.rejects(debt.owned.close(),/SYSTEM_DRIVER_CLEANUP_DEBT/);
});
test('lost controller reply retains debt and cannot advance or remove resources after cooldown alone',async()=>{
 const v=await virtualDriver('lost-reply');await v.owned.run('inventory');await v.owned.run('preflight');
 await assert.rejects(v.owned.run('prepare'));
 // Local unjoined debt is permanent; no timer alone grants deletion.
 await assert.rejects(v.owned.close(),/SYSTEM_DRIVER_CLEANUP_DEBT/);assert(!v.calls.includes('cleanup'));
});
test('successful exit cannot substitute for output hash or exact guest cleanup absence',async()=>{
 const hashFault=await virtualDriver('hash');await hashFault.owned.run('inventory');await hashFault.owned.run('preflight');
 await assert.rejects(hashFault.owned.run('prepare'),/SYSTEM_DRIVER_OUTPUT_CHANGED/);
 // Real local/process proof is retained, but successful phase content is not.
 await hashFault.owned.close();
 const marker=await virtualDriver('cleanup-marker');
 for(const name of ['inventory','preflight','prepare'])await marker.owned.run(name);
 await assert.rejects(marker.owned.close(),/SYSTEM_DRIVER_CLEANUP_DEBT/);
});
test('runtime owner binds its own observations, fixed operations and one shared retirement deadline',async()=>{
 const v=await virtualDriver();await assert.rejects(v.owned.claimRuntime(),/SYSTEM_RUNTIME_NOT_ADMITTED/);
 for(const name of I.NORMAL)await v.owned.run(name);
 const owner=await v.owned.claimRuntime();await assert.rejects(v.owned.claimRuntime(),/SYSTEM_RUNTIME_NOT_ADMITTED/);
 assert(Object.isFrozen(owner.binding.physical.daemonProcess));
 assert.throws(()=>{owner.binding.physical.daemonProcess.pid=999;},TypeError);
 await owner.startRuntime({token:'t'.repeat(43)});
 await assert.rejects(owner.startRuntime({token:'t'.repeat(43)}),/SYSTEM_RUNTIME_ALREADY_STARTED/);
 await owner.inspectRuntime();assert.equal((await owner.openBridge()).port,18090);
 await assert.rejects(v.owned.close(),/SYSTEM_RUNTIME_RETIREMENT_UNPROVEN/);
 const end=owner.beginRetirement();assert.equal(end,601000);v.advance(1000);assert.equal(owner.beginRetirement(),end);
 await assert.rejects(owner.inspectRuntime(),/SYSTEM_RUNTIME_INACTIVE/);
 const local=await owner.closeBridge();assert.equal(local.localRetired,true);assert(Object.isFrozen(local.channelIds));
 await assert.rejects(owner.stopRuntime(['forged']),/SYSTEM_RUNTIME_STOP_ORDER/);
 const remote=await owner.stopRuntime();assert.equal(remote.remoteChannelsAbsent,true);
 assert.equal(await owner.stopRuntime(),remote);
 await assert.rejects(owner.confirmRetired({retired:true}),/SYSTEM_RUNTIME_RETIREMENT_UNPROVEN/);
 assert.equal(await owner.confirmRetired(),true);
 const result=await v.owned.close();assert.equal(result.remoteCleanupVerified,true);
 assert(v.calls.indexOf('bridge-close')<v.calls.indexOf('system-runtime-stop'));
 assert(v.calls.indexOf('system-runtime-stop')<v.calls.indexOf('stop'));
 assert.equal(v.calls.filter(name=>name==='system-runtime-stop').length,1);
});
test('partial bridge launch keeps owned file closure separate from remote retirement authority',async()=>{
 const v=await virtualDriver('bridge-start');for(const name of I.NORMAL)await v.owned.run(name);
 const owner=await v.owned.claimRuntime();await owner.startRuntime({token:'t'.repeat(43)});await owner.inspectRuntime();
 await assert.rejects(owner.openBridge(),/bridge lost/);owner.beginRetirement();
 for(const suffix of ['journal','stdout','stderr'])assert(v.closeEvents.some(p=>p.endsWith('bridge.'+suffix)));
 await assert.rejects(owner.closeBridge(),/SYSTEM_BRIDGE_RETIREMENT_UNPROVEN/);
 await assert.rejects(owner.stopRuntime(),/SYSTEM_RUNTIME_STOP_ORDER/);
 await assert.rejects(v.owned.close(),/SYSTEM_RUNTIME_RETIREMENT_UNPROVEN/);
 assert(!v.calls.includes('stop'));assert(!v.calls.includes('cleanup'));
});
test('expired shared cleanup deadline cannot be renewed by owner or builder',async()=>{
 const v=await virtualDriver();for(const name of I.NORMAL)await v.owned.run(name);
 const owner=await v.owned.claimRuntime();await owner.startRuntime({token:'t'.repeat(43)});
 const end=owner.beginRetirement();await owner.closeBridge();await owner.stopRuntime();await owner.confirmRetired();
 v.advance(600001);assert.equal(owner.beginRetirement(),end);
 await assert.rejects(owner.confirmRetired(),/SYSTEM_RUNTIME_CLEANUP_DEADLINE/);
 const before=v.calls.length;await assert.rejects(v.owned.close(),/SYSTEM_DRIVER_CLEANUP_DEBT/);
 assert.equal(v.calls.length,before);assert(!v.calls.includes('cleanup'));
});
test('bridge capture failure closes every owned file once and cannot permit remote or builder deletion',async()=>{
 const v=await virtualDriver('bridge-sync');for(const name of I.NORMAL)await v.owned.run(name);
 const owner=await v.owned.claimRuntime();await owner.startRuntime({token:'t'.repeat(43)});await owner.inspectRuntime();await owner.openBridge();
 owner.beginRetirement();
 for(let n=0;n<2;n++)await assert.rejects(owner.closeBridge(),e=>e.message==='bridge sync'&&e.retirementUnproven===true);
 for(const suffix of ['journal','stdout','stderr'])assert.equal(v.closeEvents.filter(p=>p.endsWith('bridge.'+suffix)).length,1);
 assert.equal(v.calls.filter(n=>n==='bridge-close').length,1);
 await assert.rejects(owner.stopRuntime(),/SYSTEM_RUNTIME_STOP_ORDER/);
 await assert.rejects(v.owned.close(),/SYSTEM_RUNTIME_RETIREMENT_UNPROVEN/);assert(!v.calls.includes('cleanup'));
});
test('full driver rejects malformed initial or changed/malformed final shared inventory independently of guest absence',async()=>{
 const initial=await virtualDriver('inventory-first');await assert.rejects(initial.owned.run('inventory'),/BUILD_SHARED_IDENTITY_MISMATCH/);
 await assert.rejects(initial.owned.run('preflight'),/SYSTEM_DRIVER_ORDER/);await initial.owned.close();
 for(const fault of ['inventory-changed','inventory-malformed']){
  const v=await virtualDriver(fault);for(const name of I.NORMAL)await v.owned.run(name);
  await assert.rejects(v.owned.close(),e=>e.code==='SYSTEM_DRIVER_CLEANUP_DEBT'
   &&e.receipt.guestResourcesAbsent===true&&e.receipt.remoteCleanupVerified===false
   &&e.receipt.sharedStateUnchanged===false);
  assert(v.calls.includes('cleanup'));assert.equal(v.calls.at(-1),'inventory');
 }
});
test('archive verification hashes bounded chunks without buffering the archive',async()=>{
 const fs=require('node:fs/promises'),vm=require('node:vm'),path=require('node:path');
 const filename=path.resolve(__dirname,'postgres/ownedSystemConfigPhaseDriver.js'),source=await fs.readFile(filename,'utf8');
 const total=145*1024**2,maxima=[];let closed=false;
 const fake={realpath:async p=>p,open:async()=>({
  stat:async()=>({isFile:()=>true,nlink:1,size:total,mtimeMs:1,ctimeMs:1}),
  read:async(b,offset,length,position)=>{maxima.push(b.length);const n=Math.max(0,Math.min(length,total-position));b.fill(42,offset,offset+n);return {bytesRead:n};},
  close:async()=>{closed=true;}
 })};
 const module={exports:{}};
 vm.runInNewContext('(function(require,module,exports){'+source+'\n})',{Buffer})(
  id=>id==='node:fs/promises'?fake:id==='./ownedSystemConfigBuildAdapter'?{}:require(id.startsWith('./owned')?'./postgres/'+id.slice(2):id),module,module.exports);
 const proof=await module.exports._internals.fileDigest('/controlled/archive',total);
 const h=crypto.createHash('sha256'),block=Buffer.alloc(65536,42);
 for(let n=0;n<total;n+=block.length)h.update(block);
 assert.equal(proof.bytes,total);assert.equal(proof.sha256,h.digest('hex'));assert.equal(Math.max(...maxima),65536);assert(closed);
});

async function pendingWait(v){
 for(let n=0;n<200&&!v.waiters.length;n++)await new Promise(resolve=>setTimeout(resolve,1));
 assert.equal(v.waiters.length,1,'actual driver must own one bounded uncertainty join');
}
test('real producer and driver preserve failed metadata while memoized cleanup joins uncertainty once',async()=>{
 const v=await virtualDriver('metadata-failure',true);
 const outcome=v.produce().then(()=>assert.fail('failed build promoted'),error=>error);
 await pendingWait(v);
 const first=v.owned.close(),second=v.owned.close();assert.equal(first,second);
 assert(!v.calls.includes('stop'));assert(!v.calls.includes('cleanup'));
 v.advance(329999);assert(!v.calls.includes('policyMetadataRetire'));
 v.advance(1);v.wake();
 const error=await outcome,receipt=await first;
 assert.equal(error.code,'SYSTEM_PRODUCER_FAILED');assert.equal(error.primary.code,'SYSTEM_DRIVER_PHASE_FAILED');
 assert.equal(error.retirementUnproven,false);assert.equal(error.driverReceipt,receipt);
 assert.equal(receipt.remoteCleanupVerified,true);assert.equal(receipt.guestResourcesAbsent,true);
 assert.deepEqual(Object.keys(receipt).sort(),['debts','guestResourcesAbsent','localCleanupVerified','remoteCleanupVerified','sharedStateUnchanged']);
 assert.equal(v.calls.filter(x=>x==='policyMetadata').length,1);
 for(const name of ['policyMetadataRetire','stop','systemExport','policyFailureExport','cleanup'])assert.equal(v.calls.filter(x=>x===name).length,1);
 assert(!v.calls.includes('policyExport'));assert(!v.calls.includes('systemFailureExport'));
 assert(v.calls.indexOf('policyEvidence')<v.calls.indexOf('stop'));
 assert(v.calls.indexOf('policyFailureExport')<v.calls.indexOf('cleanup'));
 const rows=[...v.map].filter(([p])=>p.endsWith('journal.jsonl'))[0][1].toString().trim().split('\n').map(JSON.parse);
 const end=rows.find(r=>r.stage==='driver-preclose');assert.equal(end.cleanupDeadline,601000);
 assert.equal(end.exports.find(e=>e.slot==='policy').kind,'failed-slot-raw-metadata');
 assert.equal(end.exports.find(e=>e.slot==='system').kind,'complete-metadata');
 assert.equal(new Set([...v.map.keys()]).size,v.map.size);
 assert.equal(v.owned.close(),first,'settled cleanup retains the original promise');
});
test('composed archive fsync failure retains disk and actual error receipt without replacing primary failure',async()=>{
 const v=await virtualDriver('failed-export-sync',true);
 const outcome=v.produce().catch(e=>e);await pendingWait(v);v.advance(330000);v.wake();
 const error=await outcome;
 assert.equal(error.primary.code,'SYSTEM_DRIVER_PHASE_FAILED');assert.equal(error.retirementUnproven,true);
 assert.equal(error.driverReceipt,error.cleanupErrors[0].receipt);
 assert.equal(error.driverReceipt.guestResourcesAbsent,false);assert.equal(error.driverReceipt.remoteCleanupVerified,false);
 assert(!v.calls.includes('cleanup'));assert.equal(v.calls.at(-1),'inventory');
 const before=v.calls.length;await assert.rejects(v.owned.close(),e=>e.receipt===error.driverReceipt);assert.equal(v.calls.length,before);
});
test('actual paired producer retains qualification rejection but closes exports and owned resources',async()=>{
 const v=await virtualDriver('qualified-clean',true),error=await v.produce().catch(e=>e);
 assert.equal(error.code,'SYSTEM_PRODUCER_FAILED');assert.equal(error.primary.code,'CONTROLLED_PRIMARY');
 assert.equal(error.retirementUnproven,false);assert.equal(error.cleanupErrors.length,0);
 assert(error.errors.some(e=>require('./postgres/ownedSystemConfigBuildAdapter')._internals.isPairRelayQualificationFailure(e)));
 const r=error.driverReceipt;
 assert.deepEqual(Object.keys(r).sort(),['debts','guestResourcesAbsent','localCleanupVerified','remoteCleanupVerified','sharedStateUnchanged']);
 assert.equal(r.localCleanupVerified,true);assert.equal(r.remoteCleanupVerified,true);assert.equal(r.guestResourcesAbsent,true);
 assert.equal(r.sharedStateUnchanged,true);assert.equal(r.debts.length,0);
 for(const name of ['systemExport','policyExport','cleanup'])assert.equal(v.calls.filter(n=>n===name).length,1);
 assert(v.calls.indexOf('systemExport')<v.calls.indexOf('cleanup'));assert(v.calls.indexOf('policyExport')<v.calls.indexOf('cleanup'));
 const journal=[...v.map].find(([p])=>p.endsWith('journal.jsonl'))[1].toString().trim().split('\n').map(JSON.parse);
 assert(journal.some(r=>r.stage==='phase-failed'&&r.name==='evidence'&&r.code==='SYSTEM_PAIR_RELAY_TERMINAL'));
 const owner=require('./postgres/ownedSystemOriginalBrowserOwner')._internals;
 const packet=owner.mainTerminal('7'.repeat(32),null,Object.assign(error,{ownerOutcome:{childAttempted:false,childPacket:null,driverReceipt:r}}));
 assert.equal(packet.passed,false);assert.equal(packet.cleanupVerified,true);assert.equal(packet.qualificationAccepted,false);
 assert.equal(packet.failure,'SYSTEM_OWNER_FAILED');
 const before=v.calls.length;await assert.rejects(v.owned.close(),e=>e.receipt===r);assert.equal(v.calls.length,before);
});
test('missing terminal connection ordinal remains cleanup debt, never qualification-only rejection',async()=>{
 const v=await virtualDriver('qualified-malformed-ordinal',true),error=await v.produce().catch(e=>e);
 assert.equal(error.primary.code,'CONTROLLED_PRIMARY');assert.equal(error.retirementUnproven,true);
 assert.equal(error.driverReceipt.remoteCleanupVerified,false);assert.equal(error.driverReceipt.guestResourcesAbsent,false);
 assert(!v.calls.includes('cleanup'));
 assert(error.cleanupErrors.some(e=>Array.isArray(e.qualificationErrors)&&e.qualificationErrors.length===0));
});
test('branded terminal rejection cannot hide export, journal, FD or absolute deadline debt',async()=>{
 for(const fault of ['qualified-export','qualified-journal','qualified-close','qualified-deadline']){
  const v=await virtualDriver(fault,true),error=await v.produce().catch(e=>e);
  assert.equal(error.primary.code,'CONTROLLED_PRIMARY');assert.equal(error.retirementUnproven,true);
  assert.equal(error.driverReceipt.remoteCleanupVerified,false);assert.equal(error.driverReceipt.guestResourcesAbsent,false);
  assert(!v.calls.includes('cleanup'));
  // A readback FD close failure precedes semantic validation, so it cannot
  // acquire the qualification-only brand at all. Later debts retain the brand.
  assert(error.cleanupErrors.some(e=>e.qualificationErrors?.length===(fault==='qualified-close'?0:1)),fault);
 }
});
test('cleanup consumes the original600s endpoint and rechecks envelope after asynchronous intent persistence',async()=>{
 for(const fault of ['cleanup-preparation-expiry','cleanup-time-spent']){
  const v=await virtualDriver(fault,true),outcome=v.produce().catch(e=>e);
  await pendingWait(v);v.advance(330000);v.wake();const error=await outcome;
  assert.equal(error.primary.code,'SYSTEM_DRIVER_PHASE_FAILED');assert.equal(error.retirementUnproven,fault==='cleanup-preparation-expiry');
  if(fault==='cleanup-preparation-expiry'){
   assert(!v.calls.includes('stop'));assert(!v.calls.includes('cleanup'));assert(error.driverReceipt.debts.includes('SYSTEM_DRIVER_DEADLINE'));
  }else{
   const stop=v.configs.find(c=>c.phase==='stop');assert(stop.remoteSeconds<150);
   for(const conf of v.configs.filter(c=>c.at>=331000))assert(conf.at+(conf.remoteSeconds+46)*1000<=601000);
  }
 }
});
test('abort cannot cancel owned retirement; expiry during uncertainty cannot renew or dispatch cleanup',async()=>{
 for(const fault of ['metadata-abort','metadata-failure']){
  const v=await virtualDriver(fault,true),outcome=v.produce().catch(e=>e);
  await pendingWait(v);v.advance(fault==='metadata-abort'?330000:600001);v.wake();
  const error=await outcome;assert(error.primary);assert.equal(error.retirementUnproven,fault!=='metadata-abort');
  if(fault==='metadata-abort')assert.equal(error.driverReceipt.remoteCleanupVerified,true);
  else{assert(!v.calls.includes('stop'));assert(!v.calls.includes('cleanup'));assert.equal(error.driverReceipt.guestResourcesAbsent,false);}
 }
});


test('actual V03 metadata phase guard rejects semantic failure before next phase acceptance',()=>{
 const fs=require('node:fs'),vm=require('node:vm');
 const source=fs.readFileSync(require.resolve('./postgres/ownedSystemConfigPhaseDriver'),'utf8');
 const start=source.indexOf("   if(diagnostic&&name==='metadataFetch'){");
 assert(start>=0,'diagnostic semantic guard required');
 const guard=source.slice(start,source.indexOf("   if(name==='inventory'){",start));
 function run(diagnostic,name,envelope,validator){let reached=false;
  vm.runInNewContext(guard+'\nreached();',{diagnostic,name,text:'controlled',plan:{binding:{target:'v03-diagnostic'}},
   require:()=>({validateResultEnvelope:validator||(()=>envelope)}),error:code=>Error(code),reached:()=>{reached=true;}});
  return reached;
 }
 assert.equal(run(true,'metadataFetch',{ok:true,version:3}),true);
 for(const value of [{ok:false,version:3},{ok:true,version:2},{ok:1,version:3}])assert.throws(()=>run(true,'metadataFetch',value),/SYSTEM_METADATA_NOT_READY/);
 for(const code of ['METADATA_ENVELOPE_INVALID','METADATA_BINDING_INVALID'])assert.throws(()=>run(true,'metadataFetch',null,()=>{throw Error(code);}),new RegExp(code));
 const actual=require('./postgres/ownedPolicySystemMetadata');
 assert.throws(()=>run(true,'metadataFetch',null,()=>actual.validateResultEnvelope('{}',{target:'v03-diagnostic'})),/METADATA_BINDING_INVALID/);
 assert.equal(run(false,'metadataFetch',null),true);assert.equal(run(true,'inventory',null),true);
 assert(source.indexOf('const receipt=await executePython(conf')<start);
 assert(start<source.indexOf('receipts.push({ordinal,name,...receipt})'));
 assert(start<source.indexOf("await journal(fd,{stage:'phase-accepted'"));
 assert(source.includes("await journal(fd,{stage:'phase-failed',ordinal,name"));
 assert(source.includes('sequence.leave(ok,cleanup)'));
});
