'use strict';
// Controlled VM dependencies only; successful fake APT is not signature proof.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {EventEmitter}=require('node:events'),{PassThrough}=require('node:stream');
const crypto=require('node:crypto'),targets=require('./postgres/ownedPolicySystemBuild');
const source=fs.readFileSync(require.resolve('./postgres/ownedAptAuthentication'),'utf8');
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
function fixture(target='v23-registry',fault=''){
 const spec=targets.targetSpecification(target),contract=targets.metadataRetentionSpecification(target);
 const binding={target,base:spec.base},files=new Map(),commands=[],events=[];let closed=0;const cancel=new AbortController();
 const put=(p,v)=>{const b=Buffer.from(v);files.set(p,b);return b;};
 const key=put('/key','controlled key'),status=put('/var/lib/dpkg/status','controlled status'),index=put('/metadata/lists/index','controlled index');
 const selected={name:'gcc',version:'1',architecture:'arm64',filename:'pool/gcc.deb',sha256:'a'.repeat(64),bytes:123};
 const retained={kind:contract.kind,objects:[],stages:contract.stages.map(s=>({...s,selection:"'http://deb.debian.org/pool/gcc.deb' gcc.deb 123 SHA256:a",simulation:'Inst gcc (1)',selected:[selected]}))};
 const object=put('/metadata-retained/object','controlled upstream');retained.objects.push({kind:'upstream',url:'http://deb.debian.org/index',file:'object',bytes:object.length,sha256:hash(object)});
 const original=put('/etc/apt/sources.list','controlled source');
 const releaseNames=['deb.debian.org_debian_dists_trixie_InRelease','deb.debian.org_debian_dists_trixie-updates_InRelease','deb.debian.org_debian-security_dists_trixie-security_InRelease'];
 // Controlled byte fixtures, not signed releases: actual signature/time validation
 // belongs to the separately tested metadata module and real APT execution.
 for(const name of releaseNames)put('/metadata/lists/'+name,'controlled release');
 const candidate={keyringPath:'/key',keyringSha256:hash(key),installedStatusSha256:hash(status),indices:[{name:'index',bytes:index.length,sha256:hash(index)}],releaseFreshness:releaseNames.map(name=>({name}))};
 const envelope={candidate,sourceSnapshot:{files:[{path:'/etc/apt/sources.list',text:original.toString(),bytes:original.length,sha256:hash(original)}]}};
 put('/metadata-retained/result.json',JSON.stringify(envelope));put('/metadata-retained/manifest.json',JSON.stringify(retained));
 if(fault==='integrity')files.set('/metadata-retained/object',Buffer.from('changed'));
 if(fault==='base')files.set('/var/lib/dpkg/status',Buffer.from('changed'));
 if(fault==='keyring')files.set('/key',Buffer.from('changed'));
 const fakeFs={realpath:async p=>p,readFile:async p=>{assert(files.has(p),p);if(fault==='cancel-status'&&p==='/var/lib/dpkg/status'&&commands.length)cancel.abort(Error('status cancelled'));return files.get(p);},
  open:async p=>({stat:async()=>({isFile:()=>true,nlink:1,uid:0,mode:0o444,size:files.get(p).length,mtimeMs:1,ctimeMs:1}),readFile:async()=>files.get(p),close:async()=>{}}),
  mkdir:async()=>{events.push('mkdir');},writeFile:async(p,b,o)=>{assert.equal(o.flag,'wx');put(p,b);}};
 const spawn=(file,args)=>{commands.push({file,args});const c=new EventEmitter();c.stdout=new PassThrough();c.stderr=new PassThrough();
  if(['never-close','kill-failure','descendant'].includes(fault))c.pid=123;
  if(['never-close','kill-failure'].includes(fault)){queueMicrotask(()=>cancel.abort(Error('controlled cancellation')));return c;}
  queueMicrotask(()=>{let out='';if(file.endsWith('apt-helper'))out='expanded';
   if(file.endsWith('apt-get')&&args.includes('install'))out=args.includes('--simulate')?'Inst gcc (1)':retained.stages[0].selection;
   if(file.endsWith('apt-cache'))out=`Package: gcc\nVersion: 1\nArchitecture: arm64\nFilename: pool/gcc.deb\nSHA256: ${selected.sha256}\nSize: 123\n`;
   if(fault==='selection'&&args.includes('--print-uris'))out="'changed'";
   if(fault==='runtime-selection'&&args.includes('--print-uris')&&args.includes('bubblewrap'))out="'changed-runtime'";
   if(fault==='package'&&file.endsWith('apt-cache'))out='Package: wrong';
   c.stdout.end(out);c.stderr.end();c.emit('close',fault.startsWith('apt')&&args.includes('update')?100:0,null);
  });return c;};
 const metadata={validateResultEnvelope:()=>envelope,validateRetainedMetadata:()=>retained,
  canonicalSources:(n,t,p)=>{events.push(['policy',p]);return t;},metadataAptOptions:p=>['--proxy',String(p)],authenticatedReleaseFreshness:()=>{events.push('freshness');}};
 const replay={replayCertificate:()=>({}),createReplayBudget:()=>({}),createReplay:()=>({listen:async()=>{events.push('listen');if(fault==='listen')throw Error('listen failed');return {port:1234};},
  close:async()=>{closed++;if(fault==='cancel-close'){await Promise.resolve();cancel.abort(Error('close cancelled'));}if(fault==='apt-close'||fault==='close')throw Object.assign(Error('close failed'),{code:'CLOSE_FAILED'});return {absenceVerified:true,failure:null};}})};
 const module={exports:{}};
 vm.runInNewContext(source,{module,exports:module.exports,Buffer,AbortSignal,AbortController,structuredClone,setTimeout:(fn,ms)=>setTimeout(fn,ms===5000?10:ms),clearTimeout,
  process:{hrtime:{bigint:()=>0n},kill(pid,signal){assert.equal(pid,-123);if(fault==='kill-failure')throw Object.assign(Error('signal denied'),{code:'EPERM'});if(signal===0&&fault!=='descendant')throw Object.assign(Error('absent'),{code:'ESRCH'});}},
  require:id=>id==='node:fs/promises'?fakeFs:id==='node:child_process'?{spawn}:id==='./ownedPolicySystemMetadata'?metadata:id==='./ownedMcpArtifactReplay'?replay:id==='./ownedPolicySystemBuild'?targets:require(id)});
 return {api:module.exports,binding,commands,events,files,retained,cancel,closed:()=>closed};
}
const lifecycle=()=>({deadline:10000,signal:new AbortController().signal});
test('closed targets preserve exact stages and distinct policy/freshness paths',async()=>{
 for(const target of ['v23-registry','v24-system','v33-pricing','v24-policy']){const f=fixture(target),cap=await f.api.admitRetained(f.binding);
  assert.equal(f.commands.length,0);assert.equal(f.events.length,0); // caller npm gate fits here for V23
  const result=await f.api.authenticate(cap,lifecycle());assert.equal(result.method,'original-base-apt-closed-replay');
  assert.equal(f.closed(),1);assert.equal(f.commands[0].args.at(-1),'--error-on=any');
  assert.equal(f.events.find(x=>Array.isArray(x))[1],targets.metadataSourcePolicy(target,true));
  assert.equal(f.events.filter(x=>x==='freshness').length,3);
  assert.equal(result.stages.length,target==='v24-system'?1:2);
  await assert.rejects(f.api.authenticate(cap,lifecycle()),/ADMISSION/);
 }
});
test('renderer authenticates both original stages and never continues after failed update or admits foreign base/stages',async()=>{
 const f=fixture('v24-policy'),cap=await f.api.admitRetained(f.binding);
 await f.api.authenticate(cap,lifecycle());
 assert.deepEqual(f.commands.filter(c=>c.args.includes('install')).map(c=>Array.from(c.args.slice(c.args.indexOf('install')+1))),
  [['gcc','libc6-dev'],['gcc','libc6-dev'],['bubblewrap'],['bubblewrap']]);
 for(const fault of ['apt','apt-close','selection','runtime-selection','package','base','keyring','integrity']){
  const p=fixture('v24-policy',fault);
  if(['base','keyring','integrity'].includes(fault)){await assert.rejects(p.api.admitRetained(p.binding));assert.equal(p.commands.length,0);continue;}
  const admission=await p.api.admitRetained(p.binding);
  await assert.rejects(p.api.authenticate(admission,lifecycle()));assert.equal(p.closed(),1);
  if(fault.startsWith('apt'))assert.equal(p.commands.length,1,'no offline selection/authentication after failed update');
  if(fault==='runtime-selection')assert.deepEqual(p.commands.filter(c=>c.args.includes('install')).map(c=>Array.from(c.args.slice(c.args.indexOf('install')+1))),
   [['gcc','libc6-dev'],['gcc','libc6-dev'],['bubblewrap']],'second-stage mismatch must not yield authentication or simulate runtime');
 }
 for(const mutate of [p=>p.binding.base=targets.TARGETS['v24-system'].base,
  p=>p.binding.target='v33-pricing',p=>p.retained.stages.reverse(),p=>p.retained.stages[0].packages=['gcc','libc6-dev','bubblewrap']]){
  const p=fixture('v24-policy');mutate(p);p.files.set('/metadata-retained/manifest.json',Buffer.from(JSON.stringify(p.retained)));
  await assert.rejects(p.api.admitRetained(p.binding));assert.equal(p.commands.length,0);
 }
});
test('Pricing authentication rejects foreign retention even when base and packages match',async()=>{
 for(const target of ['v23-registry','v24-system']){
  const f=fixture('v33-pricing');f.retained.kind=targets.metadataRetentionSpecification(target).kind;
  f.files.set('/metadata-retained/manifest.json',Buffer.from(JSON.stringify(f.retained)));
  await assert.rejects(f.api.admitRetained(f.binding),/TARGET_STAGES/);assert.equal(f.commands.length,0);
 }
});
test('forged admission, wrong target/base/stages and changed inputs fail before commands',async()=>{
 for(const fault of ['integrity','base']){const f=fixture('v23-registry',fault);await assert.rejects(f.api.admitRetained(f.binding));assert.equal(f.commands.length,0);}
 const f=fixture();await assert.rejects(f.api.admitRetained({...f.binding,target:'v24-policy'}));await assert.rejects(f.api.admitRetained({...f.binding,base:'wrong'}));
 await assert.rejects(f.api.authenticate({},lifecycle()));
 f.retained.stages[0].packages=['wrong'];await assert.rejects(f.api.admitRetained(f.binding));assert.equal(f.commands.length,0);
});
test('update/selection/package/listen failures always retire replay; first cause retains cleanup debt',async()=>{
 for(const fault of ['apt','selection','package','listen','apt-close','close']){const f=fixture('v23-registry',fault),cap=await f.api.admitRetained(f.binding);
  await assert.rejects(f.api.authenticate(cap,lifecycle()),e=>{if(fault==='apt-close'){assert.equal(e.code,'ORIGINAL_BUILD_APT_FAILED');assert.equal(e.replayCleanupError,'CLOSE_FAILED');}return true;});
  assert.equal(f.closed(),1);
 }
});
test('deadline/cancellation and extra lifecycle authority reject before filesystem effects',async()=>{
 for(const kind of ['aborted','expired','extended','callback']){const f=fixture(),cap=await f.api.admitRetained(f.binding),l=lifecycle();
  if(kind==='aborted'){const c=new AbortController();c.abort();l.signal=c.signal;}
  if(kind==='expired')l.deadline=0;if(kind==='extended')l.deadline=300001;if(kind==='callback')l.command=()=>{};
  await assert.rejects(f.api.authenticate(cap,l));assert.equal(f.events.length,0);assert.equal(f.commands.length,0);
 }
});
test('cancellation during final status read or replay close cannot publish authentication',async()=>{
 for(const fault of ['cancel-status','cancel-close']){const f=fixture('v23-registry',fault),cap=await f.api.admitRetained(f.binding);
  await assert.rejects(f.api.authenticate(cap,{deadline:10000,signal:f.cancel.signal}),/cancelled/);assert.equal(f.closed(),1);
 }
});
test('bounded child join preserves failed-kill and live-descendant retirement debt',async()=>{
 for(const fault of ['never-close','kill-failure','descendant']){const f=fixture('v23-registry',fault),cap=await f.api.admitRetained(f.binding);
  await assert.rejects(f.api.authenticate(cap,{deadline:10000,signal:f.cancel.signal}),e=>{
   assert(e.cleanupDebt.some(x=>x.pid===123));
   assert(e.cleanupDebt.some(x=>x.code===(fault==='descendant'?'ORIGINAL_BUILD_DESCENDANTS_UNRETIRED':'ORIGINAL_BUILD_CHILD_JOIN_UNPROVEN')));
   if(fault==='kill-failure')assert(e.cleanupDebt.some(x=>x.code==='ORIGINAL_BUILD_CHILD_KILL_FAILED'));
   return true;
  });assert.equal(f.closed(),1);
 }
});
