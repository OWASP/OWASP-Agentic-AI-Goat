'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),crypto=require('node:crypto');
const api=require('./postgres/ownedPricingBuildAdapter'),producer=require('./postgres/ownedPricingOriginalBuild');
const root=path.resolve(__dirname,'..'),run='b'.repeat(32),hash=b=>crypto.createHash('sha256').update(b).digest('hex');
test('V25 source-only plan binds original manual inputs and exact840s lease without changing image or acquisition',async()=>{
 const old=await api.pricingBuildPlan(root,run),next=await api.pricingBuildPlan(root,run,'v25-manual');
 assert.equal(next.inputs.consumerProfile,'v25-manual');
 assert.deepEqual(next.binding,old.binding);assert.deepEqual(next.guest,old.guest);
 assert.equal(next.metadataGuestSource,old.metadataGuestSource);
 assert.deepEqual(api.pricingContext(next.inputs),api.pricingContext(old.inputs));
 for(const name of ['tests/postgres/secureshopPricingJournal.integration.test.js','tests/fixtures/secureshopPricingV25OwnerPreload.mjs',
  'tests/postgres/ownedPricingManualConsumer.js','tests/fixtures/pricingOwnedOutput.js','tests/fixtures/inheritedFifoGrant.js',
  'tests/fixtures/secureshopPricingActual.js','tests/postgres/pricing_runtime_pins.py']){
  assert.equal(next.inputs.sources[name],hash(require('node:fs').readFileSync(path.join(root,name))));
  assert.equal(Object.hasOwn(old.inputs.sources,name),false);
 }
 assert.equal(next.buildApproved,false);assert.equal(next.qualificationComplete,false);
 await api._internals.verifyPlan(next);
 const changed=structuredClone(next);delete changed.inputs.sources['tests/fixtures/secureshopPricingV25OwnerPreload.mjs'];
 await assert.rejects(api._internals.verifyPlan(changed),/PLAN_CHANGED/);
 for(const name of ['prepare','namespace','build','handoff'])assert.match(next.commands[name],/original-v25-pricing-total-lease-v1/);
 let time=2256000;const t=api._internals.createFixedTransport(next,async()=>{},{now:()=>time-2256000,execute:async()=>''});
 // No arbitrary profile or caller-provided lease extension is admitted.
 assert.throws(()=>t.beginRetirement(600001),/ADMISSION/);t.close();
});
test('V34 plan binds only its closed lifetime, with identical original package and acquisition',async()=>{
 const old=await api.pricingBuildPlan(root,run),next=await api.pricingBuildPlan(root,run,'v34-browser');
 assert.equal(Object.hasOwn(old.inputs,'consumerProfile'),false);
 assert.equal(next.inputs.consumerProfile,'v34-browser');
 assert.deepEqual(next.inputs,{...old.inputs,consumerProfile:'v34-browser'});
 assert.deepEqual(next.binding,old.binding);assert.deepEqual(next.guest,old.guest);
 assert.deepEqual(api.pricingContext(next.inputs),api.pricingContext(old.inputs));
 assert.equal(next.metadataGuestSource,old.metadataGuestSource);
 assert.equal(next.buildApproved,false);assert.equal(next.qualificationComplete,false);
 await api._internals.verifyPlan(next);
 await assert.rejects(api._internals.verifyPlan({...next,inputs:{...next.inputs,consumerProfile:'v33'}}),/PLAN_CHANGED/);
 await assert.rejects(api._internals.verifyPlan({...next,commands:old.commands}),/PLAN_CHANGED/);
 await assert.rejects(api.pricingBuildPlan(root,run,'unreviewed'),/PROFILE/);
 for(const name of ['prepare','namespace','build','handoff'])assert.match(next.commands[name],/original-v34-pricing-total-lease-v1/);
});
test('V34 transport retirement uses its total endpoint without extending600s or renewing',async()=>{
 const plan=await api.pricingBuildPlan(root,run,'v34-browser');let time=0;
 const t=api._internals.createFixedTransport(plan,async()=>{},{now:()=>time,execute:async(_p,_n,o)=>{assert.equal(o.deadline,3016000);return 'ok';}});
 time=2416000;t.beginRetirement(600000);await t.phase('stop',{cleanup:true});
 assert.throws(()=>t.beginRetirement(600000),/ADMISSION/);
 time=3016000;await assert.rejects(t.phase('evidence',{cleanup:true}),/EXPIRED/);
 const other=api._internals.createFixedTransport(plan,async()=>{},{now:()=>0});
 assert.throws(()=>other.beginRetirement(600001),/ADMISSION/);
});
test('actual generated context extractor preserves public source0444 under private umask077',async()=>{
 const plan=await api.pricingBuildPlan(root,run),{spawnSync}=require('node:child_process');
 const program=String.raw`import sys,json,shlex,tempfile,pathlib,os,io,base64,stat,hashlib
p=json.load(sys.stdin)
start=p['command'].index("/usr/bin/python3 -I -S -B -c 'import os,sys,json,tarfile")
line=p['command'][start:p['command'].index('\nport=$(',start)]
args=shlex.split(line);source=args[5];rows=json.loads(args[7])
if p.get('chmodFailure'):
 def denied(*args):raise PermissionError('controlled-fchmod-denied')
 os.fchmod=denied
with tempfile.TemporaryDirectory(prefix='pricing-context-mode-',dir=p['tmp']) as directory:
 os.mkdir(directory+'/fs',0o700);prior=os.umask(0o077)
 try:
  sys.argv=['unpack',directory,args[7]];sys.stdin=type('Input',(),{'buffer':io.BytesIO(base64.b64decode(p['tar']))})()
  exec(compile(source,'actual-generated-unpack','exec'),{})
 finally:os.umask(prior)
 context=pathlib.Path(directory+'/fs/pricing-context')
 assert stat.S_IMODE(context.stat().st_mode)==0o700
 for name,row in rows.items():
  file=context/name;s=file.stat();assert stat.S_IMODE(s.st_mode)==0o444 and s.st_nlink==1
  assert s.st_size==row['bytes'] and hashlib.sha256(file.read_bytes()).hexdigest()==row['sha256']
 for directory in context.rglob('*'):
  if directory.is_dir():assert stat.S_IMODE(directory.stat().st_mode)==0o700
 print(len(rows))
`;
 const result=spawnSync('/opt/homebrew/bin/python3',['-B','-c',program],{input:JSON.stringify({command:plan.commands.build,tar:api.pricingContext(plan.inputs).toString('base64'),tmp:path.join(root,'tasks/tmp')}),encoding:'utf8',timeout:10000,maxBuffer:65536});
 assert.equal(result.status,0,result.stderr);assert.equal(result.stdout.trim(),'14');
 const denied=spawnSync('/opt/homebrew/bin/python3',['-B','-c',program],{input:JSON.stringify({command:plan.commands.build,tar:api.pricingContext(plan.inputs).toString('base64'),tmp:path.join(root,'tasks/tmp'),chmodFailure:true}),encoding:'utf8',timeout:10000,maxBuffer:65536});
 assert.notEqual(denied.status,0);assert.match(denied.stderr,/controlled-fchmod-denied/);assert.equal(denied.stdout,'');
 assert(plan.commands.build.startsWith('set -eu\n'));
});
function overheadPacket(){const policy=require('./postgres/ownedPricingEgressPolicy'),rows={};for(const mode of ['adapter','connector'])rows[mode]={kind:'transport-audit',variant:'metadata-idle-barrier-v4',runId:run,mode,sequence:2,trigger:'checkpoint',counts:{dnsSubprocesses:0,externalConnectAttempts:0,unixConnectAttempts:0,peerChecks:0,peerDenied:0},activeWorkers:0,deniedAuthorities:{hosts:{},unclassified:0,overflow:0},admission:{workerLimitRejected:0,connectionLimitRejected:0,saturated:false},pricingBudget:{version:1,policy:policy.VERSION,sourceSha256:policy.RELAY_SHA,limit:68,connections:14}};return {version:1,runId:run,variant:'metadata-idle-barrier-v4',rows};}
test('phase diagnostics aggregate before journaling and a normal journal limit still permits retirement',async()=>{
 const plan=await api.pricingBuildPlan(root,run),saved=[],calls=[];
 const t=api._internals.createFixedTransport(plan,async(n,v)=>{saved.push([n,v]);if(n==='inventory-diagnostic')throw Object.assign(Error('limit'),{code:'PRICING_JOURNAL_LIMIT'});},{execute:async(_p,n,{diagnosticSink})=>{calls.push(n);for(let i=0;i<74;i++)await diagnosticSink(Buffer.from(i%5===0?'\n':'fragment\n'));return 'ok';}});
 await assert.rejects(t.phase('inventory'),/limit/);assert.equal(t.status().retirementDebt,false);
 assert.equal(saved.filter(([n])=>n==='inventory-diagnostic').length,1);
 t.beginRetirement(600000);await t.phase('stop',{cleanup:true});await t.phase('evidence',{cleanup:true});
 assert.deepEqual(calls,['inventory','stop','evidence']);assert(saved.some(([n])=>n==='stop-result'));
 const primary=Object.assign(Error('original'),{code:'ORIGINAL'});
 const broken=api._internals.createFixedTransport(plan,async n=>{if(n.endsWith('diagnostic'))throw Error('journal');},{execute:async(_p,_n,{diagnosticSink})=>{await diagnosticSink(Buffer.from('failure detail'));throw primary;}});
 await assert.rejects(broken.phase('inventory'),e=>e===primary&&e.journalError==='Error');
});

test('fixed Pricing transport reserves phases synchronously and retains the first failure',async()=>{
 const plan=await api.pricingBuildPlan(root,run);assert.deepEqual(plan.binding,plan.inputs.binding);
 let release,calls=0;
 const transport=api._internals.createFixedTransport(plan,async()=>{}, {execute:async()=>{calls++;return new Promise(resolve=>{release=resolve;});}});
 const first=transport.phase('inventory');
 await assert.rejects(transport.phase('inventory'),/PHASE_AUTHORITY/);
 while(!release)await new Promise(resolve=>setImmediate(resolve));
 assert.throws(()=>transport.close(),/PHASE_PENDING/);release('ok');await first;
 assert.equal(calls,1);await assert.rejects(transport.phase('build'),/PHASE_AUTHORITY/);transport.close();
 const original=Object.assign(new Error('original'),{code:'ORIGINAL'});
 const broken=api._internals.createFixedTransport(plan,async name=>{if(name.endsWith('-failure'))throw Object.assign(new Error('journal'),{code:'JOURNAL'});},{execute:async()=>{throw original;}});
 await assert.rejects(broken.phase('inventory'),error=>error===original&&error.journalError==='JOURNAL');
 await assert.rejects(broken.phase('preflight'),/PHASE_AUTHORITY/);
});

test('fixed Pricing transport rechecks authority after journaling and never renews cleanup',async()=>{
 const plan=await api.pricingBuildPlan(root,run);let time=0,calls=0;
 const t=api._internals.createFixedTransport(plan,async name=>{if(name==='inventory-intent')time=180000;},{now:()=>time,execute:async()=>{calls++;return 'ok';}});
 await assert.rejects(t.phase('inventory'),/WORK_EXPIRED/);assert.equal(calls,0);
 await t.phase('stop',{cleanup:true});const deadline=t.status().cleanupUntil;
 time=deadline;await assert.rejects(t.phase('evidence',{cleanup:true}),/RETIREMENT_EXPIRED/);
 assert.equal(t.status().cleanupUntil,deadline);assert.equal(calls,1);
 const controller=new AbortController();calls=0;
 const aborted=api._internals.createFixedTransport(plan,async()=>controller.abort(),{execute:async()=>{calls++;}});
 await assert.rejects(aborted.phase('inventory',{signal:controller.signal}));assert.equal(calls,0);
});
test('outside owner may only grant one remaining retirement budget',async()=>{
 const plan=await api.pricingBuildPlan(root,run);let time=0,calls=0,deadline;
 const t=api._internals.createFixedTransport(plan,async()=>{},{now:()=>time,execute:async(_p,_n,opts)=>{calls++;deadline=opts.deadline;return 'ok';}});
 t.beginRetirement(20000);time=1000;await t.phase('stop',{cleanup:true});assert.equal(deadline,20000);
 assert.throws(()=>t.beginRetirement(600000),/ADMISSION/);time=20000;
 await assert.rejects(t.phase('cleanup',{cleanup:true}),/EXPIRED/);assert.equal(calls,1);
});
test('fixed publisher phase streams token privately only after original build sequence',async()=>{
 const p=await api.pricingBuildPlan(root,run),journal=[],seen=[];
 const t=api._internals.createFixedTransport(p,async(n,v)=>journal.push([n,v]),{execute:async(plan,name,{input})=>{
  let bytes='';if(input)for await(const b of input)bytes+=b.toString();seen.push({name,bytes,command:plan.commands[name]});return 'ok';
 }});
 for(const name of ['inventory','preflight','prepare','namespace','relayStart','daemonStart','inspect','metadataFetch','relayCheckpoint','startArtifacts','closureEvidence','inspect','build','image','retireArtifacts','closureEvidence','inspect','handoff'])await t.phase(name);
 const token='s'.repeat(43);
 await t.phase('publishHandoff',{publication:{ownerId:'10000000-0000-4000-8000-000000000001',observed:observed(p.inputs),token}});
 assert.deepEqual(JSON.parse(seen.at(-1).bytes),{token});assert(!seen.at(-1).command.includes(token));assert(!JSON.stringify(journal).includes(token));
 assert.equal(t.status().normalCompleted,true);await assert.rejects(t.phase('publishHandoff'),/PHASE_AUTHORITY/);
});

function metadataFixture(p){
 const m=require('./postgres/ownedPolicySystemMetadata'),spec=require('./postgres/ownedPolicySystemBuild').TARGETS['v33-pricing'];
 const source='Types: deb\nURIs: http://deb.debian.org/debian\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\n\nTypes: deb\nURIs: http://deb.debian.org/debian-security\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\n';
 const suites=['trixie','trixie-updates','trixie-security'],now=Date.parse('2026-10-21T12:00:00Z');
 const releases=suites.map(s=>{const name='deb.debian.org_'+(s==='trixie-security'?'debian-security':'debian')+'_dists_'+s+'_InRelease';
  const text='-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nCodename: '+s+'\nDate: Tue, 20 Oct 2026 12:00:00 UTC\n-----BEGIN PGP SIGNATURE-----\ncontrolled-not-a-signature\n-----END PGP SIGNATURE-----\n';
  return {name,text,fresh:m.authenticatedReleaseFreshness(name,text,now)};});
 const selected=[{name:'bubblewrap',version:'1',architecture:'arm64',filename:'pool/main/b/bubblewrap/bubblewrap_1_arm64.deb',bytes:5,sha256:'f'.repeat(64)}];
 const selection="'http://deb.debian.org/debian/pool/main/b/bubblewrap/bubblewrap_1_arm64.deb' bubblewrap_1_arm64.deb 5 SHA256:"+'f'.repeat(64);
 const c={version:1,candidateOnly:true,qualified:false,requestedPackages:[...spec.packages],release:'ID=debian\nVERSION_CODENAME=trixie\n',
  keyringPath:'/usr/share/keyrings/debian-archive-keyring.pgp',keyringBytes:20,keyringSha256:'a'.repeat(64),installedStatusSha256:'b'.repeat(64),
  sources:[{name:'debian.sources',sha256:hash(source)},{name:'main.list',sha256:hash('')}],
  indices:[...releases.map(r=>({name:r.name,sha256:hash(r.text),bytes:Buffer.byteLength(r.text)})),{name:'debian_Packages.lz4',sha256:'e'.repeat(64),bytes:48}],
  sourcePolicy:m.sourcePolicyWitness([['debian.sources',source],['main.list','']],spec.metadataSourcePolicy,m.canonicalSources),releaseFreshness:releases.map(r=>r.fresh),
  selected,selection,selectionKind:'deduplicated-stage-uri-aggregate',compressedBytes:0,expandedBytes:100,expandedMeterStage:'after-update-before-offline-resolution',diagnosticBytes:100};
 const objects=[{kind:'keyring',url:null,sha256:c.keyringSha256,bytes:20},{kind:'installed-status',url:null,sha256:c.installedStatusSha256,bytes:19}];
 releases.forEach((r,i)=>{const prefix='http://deb.debian.org/'+(i===2?'debian-security':'debian')+'/dists/'+suites[i]+'/';
  objects.push({kind:'upstream',url:prefix+'InRelease',sha256:hash(r.text),bytes:Buffer.byteLength(r.text)},{kind:'upstream',url:prefix+'main/binary-arm64/Packages.xz',sha256:String(i+1).repeat(64),bytes:30});});
 objects.forEach(o=>{o.file='objects/'+o.sha256;});c.compressedBytes=objects.filter(o=>o.kind==='upstream').reduce((n,o)=>n+o.bytes,0);
 c.retainedMetadata={version:1,kind:'v33-pricing-original-apt-retention',binding:{...p.inputs.binding},capBytes:144*1024**2,retainedBytes:objects.reduce((n,o)=>n+o.bytes,0),objects,
  stages:producer.STAGES.map(s=>({...s,selected,selection,simulation:'Inst bubblewrap (1 Debian [arm64])\n',installedStatusSha256:c.installedStatusSha256}))};
 const env={version:3,kind:'owned-policy-system-metadata-result',binding:p.inputs.binding,ok:true,commandFailure:null,candidate:c,errorCode:null,
  sourceSnapshot:{version:1,kind:'owned-image-apt-sources',files:[{path:'/etc/apt/sources.list.d/debian.sources',text:source,bytes:Buffer.byteLength(source),sha256:hash(source)}]}};
 m.validateResultEnvelope(JSON.stringify(env),p.inputs.binding);
 const artifacts=producer.pricingArtifactPlan({stages:c.retainedMetadata.stages}).artifacts;
 const record={version:1,binding:p.inputs.binding,overhead:overheadPacket(),authentication:{binding:p.inputs.binding,version:1,method:'original-base-apt-closed-replay',retainedManifestSha256:hash(JSON.stringify(c.retainedMetadata)),
  keyringSha256:c.keyringSha256,installedStatusSha256:c.installedStatusSha256,stages:c.retainedMetadata.stages.map(s=>({name:s.name,selectionSha256:hash(s.selection)})),expandedBytes:100},
  acquired:{version:1,artifactBytesVerified:true,metadataAuthenticated:false,buildApproved:false,qualificationComplete:false,bytes:{deb:5,npm:0,total:5},
   artifacts:artifacts.map(a=>({...a,actualBytes:a.bytes,file:'objects/'+require('./postgres/ownedMcpDependencyClosure')._internals.objectName(a)}))}};
 return {env,record};
}
async function controlledCase(fault,profile='v33'){
 const p=await api.pricingBuildPlan(root,run,profile),{env,record}=metadataFixture(p),calls=[],saved=[];
 const pins=require('./postgres/ownedMcpBoundedBuild').PINS;
 const inventory=JSON.stringify(pins.daemon)+'\n'+pins.postgres+' postgres:18\nNETWORK\n'+JSON.stringify({version:1,bridge:{},links:[{ifname:'docker0'}],addresses:[],routes4:[],routes6:[],rules4:[],rules6:[],firewall4:'',firewall6:'',nft:{},forwarding:''});
 const image={Id:'sha256:'+'a'.repeat(64),Architecture:'arm64',Os:'linux',Config:{User:p.inputs.user,Entrypoint:p.inputs.entrypoint,Labels:{'owasp-ai-goat.pricing.package':p.inputs.packageDigest,'owasp-ai-goat.build-run':run}}};
 let retired=false;
 const phase=async(name,{input,cleanup,sink})=>{
  calls.push({name,cleanup});if(input){let n=0;for await(const b of input)n+=b.length;assert(n>0);}
  if(fault===name||fault==='build-and-retire'&&['build','retireArtifacts'].includes(name))throw Object.assign(Error('controlled failure'),{code:'TEST_FAILURE'});
  if(name==='inventory')return inventory;
  if(name==='relayCheckpoint'){const value=overheadPacket();if(fault==='overhead')value.rows.adapter.pricingBudget.connections=33;return JSON.stringify(value);}
  if(name==='inspect')return JSON.stringify({ID:'b'.repeat(64),DockerRootDir:p.spec.mount+'/data',Driver:'overlay2',Architecture:'arm64'});
  if(name==='metadataFetch')return JSON.stringify(env);
  if(name==='startArtifacts')return JSON.stringify({binding:p.inputs.binding,metadataAuthenticated:true,artifactBytesVerified:true,closureSha256:hash(JSON.stringify(record))});
  if(name==='closureEvidence')return JSON.stringify({'closure.json':JSON.stringify(record),'terminal.json':retired?JSON.stringify({binding:p.inputs.binding,failure:null,result:{failure:null,absenceVerified:true},cleanupErrors:[]}):null});
  if(name==='image')return JSON.stringify([image]);
  if(name==='retireArtifacts'){retired=true;return 'absent\n';}
  if(name==='handoff')return JSON.stringify(observed(p.inputs));
  if(name==='cleanup')return 'absent\n';
  if(name==='retainedExport'){await sink(Buffer.from('controlled archive'));return '';}
  return '{}';
 };
 let result,error;try{result=await api._internals.runControlledBuild(p,{phase,record:async(n,v)=>saved.push({n,v}),createExport:()=>({sink:async()=>{},finish:()=>{if(fault==='export-fsync')throw Error('fsync');return {controlled:true,durable:true};},close(){}})});}catch(e){error=e;}
 return {result,error,calls,saved};
}
test('full controlled Pricing build joins original context, APT closure, image and handoff then retires',async()=>{
 for(const profile of ['v33','v34-browser']){
 const c=await controlledCase(undefined,profile);assert.ifError(c.error);assert.equal(c.result.buildCompleted,true);assert.equal(c.result.cleanupVerified,true);
 assert.equal(c.result.controlled,true);assert.equal(c.result.runtimeAvailable,false);assert.equal(c.result.qualificationComplete,false);
 assert(c.saved.some(r=>r.n==='image-observation'));assert.deepEqual(c.calls.slice(-6).map(r=>r.name),['closureEvidence','stop','evidence','retainedExport','cleanup','inventory']);
 }
});
test('failure paths retain primary cause and never delete past unproven artifact/evidence retirement',async()=>{
 for(const name of ['prepare','metadataFetch','build','image','retainedExport','export-fsync','build-and-retire']){
  const c=await controlledCase(name);assert(c.error,name);assert.equal(c.error.result.qualificationComplete,false);assert.equal(c.calls.at(-1).name,'inventory');
  if(['retainedExport','export-fsync','build-and-retire'].includes(name)){assert.equal(c.error.result.cleanupVerified,false);assert(!c.calls.some(r=>r.name==='cleanup'));}
 }
});
test('real controlled coordinator rejects overhead before artifact container admission',async()=>{
 const c=await controlledCase('overhead');assert(c.error);assert.equal(c.error.result.failure,'PRICING_EGRESS_OVERHEAD');
 assert(!c.calls.some(r=>r.name==='startArtifacts'));assert(c.calls.some(r=>r.name==='cleanup'));
 const p=await api.pricingBuildPlan(root,run),{env,record}=metadataFixture(p);record.overhead.rows.connector.pricingBudget.connections=33;
 assert.throws(()=>api.validatePricingClosure(p.inputs,JSON.stringify(env),record),/EGRESS_OVERHEAD/);
});
test('target-specific executable phase programs parse without executing native commands',async()=>{
 const p=await api.pricingBuildPlan(root,run),{spawnSync}=require('node:child_process');
 for(const [name,command]of Object.entries(p.commands)){const r=spawnSync('/bin/sh',['-n'],{input:command,encoding:'utf8'});assert.equal(r.status,0,name+':'+r.stderr);}
 assert(p.commands.build.includes(producer.DOCKERFILE));assert(p.commands.build.includes('stop_private_relay'));assert(!p.commands.build.includes('npm '));
});

test('serialized Pricing guest loads its pinned modules but rejects absent lease before IO',async()=>{
 const p=api.pricingBuildInputs(root,run),guest=api.pricingGuestSource(p),vm=require('node:vm');
 assert.equal(hash(guest.text),guest.sha256);let io=0;const proc={env:{},hrtime:process.hrtime,exitCode:0};
 const denied=new Proxy({},{get(){io++;throw Error('unexpected filesystem access');}});
 await vm.runInNewContext(guest.text,{Buffer,AbortController,AbortSignal,URL,setTimeout,clearTimeout,process:proc,
  require:name=>name==='node:fs/promises'?denied:require(name)});
 assert.equal(proc.exitCode,2);assert.equal(io,0);
});
test('serialized Pricing guest rejects invalid deadlines with valid proxy before any IO',async()=>{
 const guest=api.pricingGuestSource(api.pricingBuildInputs(root,run)),vm=require('node:vm');
 for(const value of [undefined,'NaN','not-a-number','Infinity','-Infinity','1e309','0','-1','100','401']){
  let io=0;const proc={env:{OWASP_AI_GOAT_ARTIFACT_PROXY_PORT:'3128'},hrtime:{bigint:()=>100000000000n},exitCode:0};
  if(value!==undefined)proc.env.OWASP_AI_GOAT_ARTIFACT_DEADLINE_SECONDS=value;
  const denied=new Proxy({},{get(){io++;throw Error('unexpected filesystem access');}});
  await vm.runInNewContext(guest.text,{Buffer,AbortController,AbortSignal,URL,setTimeout,clearTimeout,process:proc,
   require:name=>name==='node:fs/promises'?denied:require(name)});
  assert.equal(proc.exitCode,2,String(value));assert.equal(io,0,String(value));
 }
});
test('actual guest terminal retains bounded phase and closed acquisition diagnostics',async()=>{
 const vm=require('node:vm'),closure=require('./postgres/ownedMcpDependencyClosure');
 for(const phase of ['authenticate','acquire']){
  let terminal;
  const error=Object.assign(Error('secret URL must not be retained'),{code:'ECONNRESET',closureTransport:'tls',closureArtifact:{index:0,kind:'deb',algorithm:'sha256',digest:'a'.repeat(64),stage:'request'},secret:'credential'});
  const modules={ownedAptAuthentication:{admitRetained:async()=>({}),authenticate:async()=>{if(phase==='authenticate')throw error;return {};}},
   ownedPolicySystemMetadata:{validateResultEnvelope:()=>({candidate:{}}),validateRetainedMetadata:()=>({stages:[]})},
   ownedMcpDependencyClosure:{BASE:closure.BASE,failureDiagnostic:closure.failureDiagnostic,_internals:{debArtifacts:()=>[],validateArtifacts:()=>{}},acquireArtifacts:async()=>{throw error;}},ownedMcpArtifactReplay:{},ownedPricingEgressPolicy:{validateOverheadCheckpoint(){},validatePricingArtifactCensus(){}}};
  const fake={open:async()=>({stat:async()=>({isFile:()=>true,nlink:1,uid:0,mode:0o600,size:2}),readFile:async()=>'{}',writeFile:async b=>{terminal=JSON.parse(b);},sync:async()=>{},close:async()=>{}}),link:async()=>{},unlink:async()=>{},readFile:async()=>'{}'};
  const proc={env:{OWASP_AI_GOAT_ARTIFACT_PROXY_PORT:'3128',OWASP_AI_GOAT_ARTIFACT_DEADLINE_SECONDS:'200'},hrtime:{bigint:()=>100000000000n},on(){},off(){},exitCode:0};
  await vm.runInNewContext('('+api._internals.pricingGuest.toString()+')(load,binding)',{load:n=>modules[n],binding:{target:'v33-pricing',base:closure.BASE},require:n=>n==='node:fs/promises'?fake:require(n),process:proc,AbortController,setTimeout,clearTimeout,Buffer});
  assert.equal(proc.exitCode,1);assert.equal(terminal.failure,'ECONNRESET');assert.equal(terminal.diagnostic.phase,phase);assert.equal(terminal.diagnostic.transport,'tls');
  assert.deepEqual(Object.keys(terminal.diagnostic).sort(),['artifact','phase','transport']);assert(!JSON.stringify(terminal).includes('secret'));assert(!JSON.stringify(terminal).includes('credential'));
 }
});
test('actual guest validates mounted checkpoint and authenticated census before any artifact request',async()=>{
 const vm=require('node:vm'),closure=require('./postgres/ownedMcpDependencyClosure'),policy=require('./postgres/ownedPricingEgressPolicy');
 for(const fault of ['overhead','census']){
  let terminal,auth=0,acquire=0;const overhead=overheadPacket();if(fault==='overhead')overhead.rows.adapter.pricingBudget.connections=33;
  const artifacts=Array.from({length:37},(_,i)=>({kind:'deb',algorithm:'sha256',digest:i.toString(16).padStart(64,'0'),bytes:1,urls:[`https://deb.debian.org/debian/pool/main/f/fixture/fixture${i}_1_arm64.deb`],stages:['build']}));
  const modules={ownedAptAuthentication:{admitRetained:async()=>({}),authenticate:async()=>{auth++;return {};}},ownedPolicySystemMetadata:{validateResultEnvelope:()=>({candidate:{}}),validateRetainedMetadata:()=>({stages:[]})},ownedPricingEgressPolicy:policy,
   ownedMcpDependencyClosure:{BASE:closure.BASE,failureDiagnostic:closure.failureDiagnostic,_internals:{debArtifacts:()=>artifacts,validateArtifacts:closure._internals.validateArtifacts},acquireArtifacts:async()=>{acquire++;throw Error('must not dispatch');}},ownedMcpArtifactReplay:{}};
  const fake={open:async()=>({stat:async()=>({isFile:()=>true,nlink:1,uid:0,mode:0o600,size:1000}),readFile:async()=>JSON.stringify(overhead),writeFile:async b=>{terminal=JSON.parse(b);},sync:async()=>{},close:async()=>{}}),link:async()=>{},unlink:async()=>{},readFile:async()=>'{}'};
  const proc={env:{OWASP_AI_GOAT_ARTIFACT_PROXY_PORT:'3128',OWASP_AI_GOAT_ARTIFACT_DEADLINE_SECONDS:'200'},hrtime:{bigint:()=>100000000000n},on(){},off(){},exitCode:0};
  await vm.runInNewContext('('+api._internals.pricingGuest.toString()+')(load,binding)',{load:n=>modules[n],binding:{target:'v33-pricing',base:closure.BASE,runId:run},require:n=>n==='node:fs/promises'?fake:require(n),process:proc,AbortController,setTimeout,clearTimeout,Buffer});
  assert.equal(acquire,0);assert.equal(auth,fault==='overhead'?0:1);assert.equal(terminal.failure,fault==='overhead'?'PRICING_EGRESS_OVERHEAD':'PRICING_EGRESS_CENSUS');
 }
});
test('Pricing capture is exact original fourteen-file authority, metadata is not build permission',()=>{
 const p=api.pricingBuildInputs(root,run);assert.equal(p.files.length,14);assert.equal(p.buildApproved,false);assert.equal(p.binding.target,'v33-pricing');
 assert.equal(p.dockerfileSha256,producer.DOCKERFILE_SHA256);assert.equal(p.metadataPolicy,'v33-pricing-trixie-freshness-v1');
 assert.equal(api.verifyPricingBuildInputs(p),true);assert.throws(()=>api.withPrivatePricingImage(p),/NOT_ADMITTED/);
 for(const edit of [p=>p.files.pop(),p=>p.binding.target='v23-registry',p=>p.buildApproved=true,p=>p.sources['tests/postgres/ownedAptAuthentication.js']='0'.repeat(64)]){
  const changed=structuredClone(p);edit(changed);assert.throws(()=>api.verifyPricingBuildInputs(changed));
 }
});
test('Pricing streamed context preserves every original byte and admits no extra members',()=>{
 const p=api.pricingBuildInputs(root,run),tar=api.pricingContext(p);let offset=0,index=0;
 while(tar[offset]){const h=tar.subarray(offset,offset+512),name=h.subarray(0,100).toString().split('\0')[0],size=parseInt(h.subarray(124,136).toString(),8),row=p.files[index++];
  assert.equal(name,row.name);assert.equal(size,row.bytes);assert.equal(hash(tar.subarray(offset+512,offset+512+size)),row.sha256);
  offset+=512+Math.ceil(size/512)*512;
 }
 assert.equal(index,14);assert.equal(tar.length-offset,1024);
 assert.throws(()=>api._internals.tarMember('../escape',Buffer.from('x')));
});
function observed(p){return {version:1,target:'original-v33-pricing',runId:p.runId,packageDigest:p.packageDigest,imageId:'sha256:'+'a'.repeat(64),
 daemonId:'b'.repeat(64),sharedDaemonId:'c'.repeat(64),namespaceInode:'net:[100]',sharedNamespaceInode:'net:[101]',
 filesystemIdentity:{device:1,inode:2},daemonProcess:{pid:20,startTicks:'123',exe:'/usr/bin/dockerd'},namespaceHolder:{pid:21,startTicks:'124',exe:'/usr/bin/sleep'},relayRetired:true};}
test('physical handoff rejects shared namespace/daemon, missing retirement and identity confusion',()=>{
 const p=api.pricingBuildInputs(root,run);assert.deepEqual(api.validatePricingHandoff(p,observed(p)),observed(p));
 for(const edit of [v=>v.daemonId=v.sharedDaemonId,v=>v.namespaceInode=v.sharedNamespaceInode,v=>v.relayRetired=false,v=>v.daemonProcess.pid=v.namespaceHolder.pid,v=>v.namespaceHolder.exe='/bin/sh',v=>v.extra=true]){
  const v=observed(p);edit(v);assert.throws(()=>api.validatePricingHandoff(p,v));
 }
});
test('image inspection joins exact original entrypoint/user/package/run, not merely image ID',()=>{
 const p=api.pricingBuildInputs(root,run),image={Id:'sha256:'+'a'.repeat(64),Architecture:'arm64',Os:'linux',Config:{User:p.user,Entrypoint:p.entrypoint,Labels:{'owasp-ai-goat.pricing.package':p.packageDigest,'owasp-ai-goat.build-run':p.runId}}};
 assert.equal(api.validatePricingImage(p,[image]),image.Id);
 for(const edit of [v=>v.Config.User='0',v=>v.Config.Entrypoint=['sh'],v=>v.Config.Labels['owasp-ai-goat.build-run']='c'.repeat(32),v=>v.Architecture='amd64']){const v=structuredClone(image);edit(v);assert.throws(()=>api.validatePricingImage(p,[v]));}
 assert.throws(()=>api.validatePricingImage(p,[image,image]));
});
