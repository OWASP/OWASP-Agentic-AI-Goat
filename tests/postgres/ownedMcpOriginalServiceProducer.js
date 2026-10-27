'use strict';
// Private producer implementation. No public start, generic command API or
// authority reconstructed from a serialized image/daemon receipt.
const crypto=require('node:crypto'),{Readable}=require('node:stream');
const {performance}=require('node:perf_hooks');
const {isDeepStrictEqual:equal}=require('node:util');
const service=require('./ownedMcpOriginalService');
const derivation=require('./ownedMcpOriginalServiceDerivation');
const legacy=require('./ownedMcpRegistryService')._internals;
const fail=code=>Object.assign(new Error(code),{code});
// Identity provenance, not a serialized cleanup claim. The adapter must also
// verify its own real executor, journal, source and final retirement.
const retiredFailures=new WeakMap();
function isRetiredFailure(error,handoff,plan){
 const row=retiredFailures.get(error);
 return !!row&&row.handoff===handoff&&row.plan===plan;
}
const quote=x=>"'"+x.replace(/'/g,"'\\''")+"'";
const PREFIX='/secureshop/mcp-registry';
const REMAINING_PROGRAM="import json,sys,time,math; r=json.load(sys.stdin); n=r['deadlineMs']/1000-time.monotonic(); assert math.isfinite(n) and n>0; value=format(n,'.9f'); assert float(value)>0; print(value,end='')";
const PHASE_HEADER='set -eu\numask 077\nroot=$1\nnonce=$2\n';
function replace(text,from,to){if(text.split(from).length!==2)throw fail('ORIGINAL_SERVICE_SOURCE_SHAPE');return text.replace(from,to);}
function boundedPhase(guard,script,phase,profile='original-service'){
 const leaseCommand=op=>derivation.leaseCommand(op,profile);
 if(!['build','settlement','startup','cohort','retirement','cleanup','artifact-retirement'].includes(phase))throw fail('ORIGINAL_SERVICE_PHASE');
 const selected=phase==='artifact-retirement'?'settlement':phase;
 const read=leaseCommand('check-'+selected)+(['retirement','artifact-retirement'].includes(phase)?' 2>/dev/null || '+leaseCommand('check-cleanup'):'');
 // The fixed lease program validates root/run/owner before reading. Keep the
 // original full runtime guard inside the timed shell, without duplicating it
 // into an over-limit exec argument. Both shells initialize their own scope.
 return PHASE_HEADER+'remaining=$( ('+read+') | /usr/bin/python3 -I -S -B -c '+quote(REMAINING_PROGRAM)+')\n'+
  '/usr/bin/timeout --signal=TERM --kill-after=10 "$remaining" /bin/sh -c '+quote(PHASE_HEADER+'('+read+') >/dev/null\n'+script)+' owned-original-service "$root" "$nonce" "${3:-}"\n';
}
function commands(registry,guard,profile='original-service'){
 const leaseCommand=op=>derivation.leaseCommand(op,profile);
 const check=phase=>phase==='retirement'
  ? '('+leaseCommand('check-retirement')+' >/dev/null 2>&1 || '+leaseCommand('check-cleanup')+' >/dev/null)\n'
  : leaseCommand('check-'+phase)+' >/dev/null\n';
 const claim=phase=>guard+'\ncheck_mount; check_runtime\n'+leaseCommand('claim-'+phase)+'\n';
 const identity=registry.identity;
 if(typeof identity!=='string')throw fail('ORIGINAL_SERVICE_IDENTITY_SOURCE');
 const envProgram=String.raw`import os,sys,re,json
root,profile=sys.argv[1:]
b=sys.stdin.buffer.read(1025);assert len(b)<=1024
q=json.loads(b);assert type(q) is dict and set(q)=={'token'} and re.fullmatch('[-_A-Za-z0-9]{43}',q['token'])
data=('SECURESHOP_MCP_REGISTRY_ENABLED=true\nSECURESHOP_MCP_REGISTRY_TOKEN='+q['token']+'\nSECURESHOP_MCP_REGISTRY_PROFILE='+profile+'\nSECURESHOP_MCP_REGISTRY_HOST=127.0.0.1\nSECURESHOP_MCP_REGISTRY_PORT=8094\n').encode()
fd=os.open(root+'/fs/service.env',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
try:
 while data:
  n=os.write(fd,data);assert n>0;data=data[n:]
 os.fsync(fd)
finally:os.close(fd)
fd=os.open(root+'/fs',os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
`;
 let create=replace(registry.commands.registryCreate,'\ncheck_mount; check_runtime; check_network\n',
  '\ncheck_mount; check_runtime; check_network\n'+check('startup')+
  '/usr/bin/python3 -I -S -B -c '+quote(envProgram)+' "$root" '+quote(registry.name)+'\n');
 create=replace(create,"--env 'SECURESHOP_MCP_REGISTRY_PROFILE="+registry.name+"' --entrypoint node -i \"$image\" -",
  '--restart no --env-file "$root/fs/service.env" --entrypoint node "$image" sidecars/sandbox-runner/owned-mcp-registry/http-listener.js');
 let start=registry.commands.registryStart;
 const attach='docker --host "unix://$root/fs/docker.sock" attach --sig-proxy=false "$registry_cid"';
 if(start.split(attach).length!==2)throw fail('ORIGINAL_SERVICE_SOURCE_SHAPE');
 start=start.slice(0,start.indexOf(attach))+'registry_identity\ndocker --host "unix://$root/fs/docker.sock" inspect "$registry_cid"\n';
 start=replace(start,'\ncheck_mount; check_runtime; registry_identity\n',
  '\ncheck_mount; check_runtime; registry_identity\n'+check('startup'));
 const inspect=guard+identity+'\ncheck_mount; check_runtime; registry_identity\n'+check('startup')+
  'docker --host "unix://$root/fs/docker.sock" inspect "$registry_cid"\n';
 const proxy=service.fixedProxy(profile);
 const exec=phase=>guard+identity+'\ncheck_mount; check_runtime; registry_identity\n'+check(phase)+
  '[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format \'{{.State.Running}}\' "$registry_cid")" = true ]\n'+
  'docker --host "unix://$root/fs/docker.sock" exec -i "$registry_cid" node -e '+quote(proxy.source)+'\n';
 const readiness="require('/app/sidecars/sandbox-runner/owned-mcp-registry/executor').createOwnedMcpRegistryExecutor({expectedProfile:process.env.SECURESHOP_MCP_REGISTRY_PROFILE}).checkReadiness().then(v=>process.stdout.write(JSON.stringify(v))).catch(e=>{process.stderr.write(String(e.code||'READINESS_FAILED'));process.exitCode=1;})";
 const retirementClaim=guard+'\ncheck_mount; check_runtime\n'+
  'if [ -e "$root/original-service-phase-cohort.json" ] || [ -L "$root/original-service-phase-cohort.json" ]; then\n'+
  leaseCommand('claim-retirement')+'\nelse\n'+leaseCommand('claim-cleanup')+'\nfi\n';
 const result={serviceStartupClaim:claim('startup'),serviceCohortClaim:guard+'\ncheck_mount; check_runtime\n'+check('startup')+leaseCommand('claim-cohort')+'\n',serviceRetirementClaim:retirementClaim,
  serviceCreate:create,serviceStart:start,serviceInspect:inspect,
  serviceReadiness:guard+identity+'\ncheck_mount; check_runtime; registry_identity\n'+check('startup')+
   'docker --host "unix://$root/fs/docker.sock" exec "$registry_cid" node -e '+quote(readiness)+'\n',
  serviceHealth:exec('startup'),serviceExec:exec('cohort'),serviceDrain:exec('retirement'),
  serviceRetire:replace(registry.commands.registryRetire,'\ncheck_mount; check_runtime; registry_identity\n',
   '\ncheck_mount; check_runtime; registry_identity\n'+check('retirement')),
  serviceProfileInstall:replace(registry.commands.registryProfileInstall,'\ncheck_mount; check_runtime\n',
   '\ncheck_mount; check_runtime\n'+check('startup')),
  serviceProfileRetire:registry.commands.registryProfileRetire};
 for(const name of ['serviceCreate','serviceStart','serviceInspect','serviceReadiness','serviceHealth','serviceProfileInstall'])result[name]=boundedPhase(guard,result[name],'startup',profile);
 result.serviceExec=boundedPhase(guard,result.serviceExec,'cohort',profile);
 for(const name of ['serviceDrain','serviceRetire','serviceProfileRetire'])result[name]=boundedPhase(guard,result[name],'retirement',profile);
 return result;
}
function validateContainer(rows,{id,imageId,name,runId,token,running}){
 const row=rows?.[0],h=row?.HostConfig,c=row?.Config;
 if(!Array.isArray(rows)||rows.length!==1||!/^[a-f0-9]{64}$/.test(row?.Id||'')||(id&&row.Id!==id)
  ||row.Image!==imageId||row.Name!=='/'+name||c?.Labels?.['dvaia.original.registry']!==runId
  ||row.State?.Running!==running)throw fail('ORIGINAL_SERVICE_CONTAINER_IDENTITY');
 const expected=['SECURESHOP_MCP_REGISTRY_ENABLED=true','SECURESHOP_MCP_REGISTRY_TOKEN='+token,
  'SECURESHOP_MCP_REGISTRY_PROFILE='+name,'SECURESHOP_MCP_REGISTRY_HOST=127.0.0.1','SECURESHOP_MCP_REGISTRY_PORT=8094'];
 if(c.User!=='10001:10001'||!equal(c.Entrypoint,['node'])
  ||!equal(c.Cmd,['sidecars/sandbox-runner/owned-mcp-registry/http-listener.js'])
  ||!Array.isArray(c.Env)||!expected.every(x=>c.Env.includes(x))||c.Env.filter(x=>x.startsWith('SECURESHOP_MCP_REGISTRY_')).length!==5
  ||h?.NetworkMode!=='none'||h.ReadonlyRootfs!==true||h.Privileged!==false||h.PidMode||h.IpcMode==='host'
  ||(h.CapAdd||[]).length||!equal(h.CapDrop,['ALL'])||h.Memory!==536870912||h.NanoCpus!==1000000000||h.PidsLimit!==128
  ||h.LogConfig?.Type!=='none'||h.RestartPolicy?.Name!=='no'||!equal(h.SecurityOpt,['apparmor='+name,'seccomp=unconfined'])
  ||!equal(h.Tmpfs,{'/tmp':'rw,nosuid,nodev,noexec,size=16m'})||Object.keys(h.PortBindings||{}).length||h.PublishAllPorts
  ||(h.Binds||[]).length||(h.Mounts||[]).length||!Array.isArray(row.Mounts)||row.Mounts.length>1
  ||row.Mounts.some(x=>x.Type!=='tmpfs'||x.Destination!=='/tmp'))throw fail('ORIGINAL_SERVICE_CONTAINER_BOUNDARY');
 return row.Id;
}
// Called only inside the producer's live handoff scope. Controlled entry is
// separately marked by the producer; it can never create live image authority.
async function consume({handoff,lifetime,plan,step,record,cohort,relayFactory=legacy.createRelay}){
 if(typeof cohort!=='function'||!['original-service','v39-atomic-pair','q05-registered-pair'].includes(plan.consumerMode))throw fail('ORIGINAL_SERVICE_CONSUMER');
 const profile=plan.consumerMode,pair=profile!=='original-service',cohortMs=pair?480000:1200000;
 const token=crypto.randomBytes(32).toString('base64url');
 let profileAttempted=false,container=false,retired=false,retirementClaim,relay,state,id,primary,result,cohortTimer,cohortFailure,cleanupFailed=false;
 const startupTimer=setTimeout(()=>lifetime.expireWork(),120000);
 const completed=new Set();
 const phase=(name,input,cleanup=false)=>{
  if(cleanup)lifetime.assertRetirementAdmission();else lifetime.assertActive();
  return lifetime.joinPhase(async()=>{
   const value=await step(name,{...(input===undefined?{}:{input:Readable.from([input])}),assertOpen:lifetime.assertOpen,
    signal:cleanup?lifetime.retirementSignal:lifetime.signal,...(cleanup?{}:{assertActive:lifetime.assertActive})},cleanup);
   lifetime.assertOpen();if(!cleanup)lifetime.assertActive();completed.add(name);return value;
  });
 };
 let cleanupEnd;
 const beginRetirement=()=>{
  lifetime.beginRetirement();lifetime.assertOpen();
  return cleanupEnd??=lifetime.retirementDeadline();
 };
 const claimRetirement=()=>retirementClaim??=phase('serviceRetirementClaim',undefined,true);
 const owner={assertActive:lifetime.assertActive,record,
  beginRetirement,
  async closeEndpoint(){await claimRetirement();},
  async stopListener(){
   await claimRetirement();
   if(container&&!(completed.has('serviceRetire'))){if((await phase('serviceRetire',undefined,true)).trim()!=='absent')throw fail('ORIGINAL_SERVICE_RETIREMENT_UNPROVEN');}
   if(profileAttempted&&!completed.has('serviceProfileRetire')){if((await phase('serviceProfileRetire',undefined,true)).trim()!=='absent')throw fail('ORIGINAL_SERVICE_RETIREMENT_UNPROVEN');}
  },
  confirmRetired(){
   if(container&&!completed.has('serviceRetire')||profileAttempted&&!completed.has('serviceProfileRetire'))throw fail('ORIGINAL_SERVICE_RETIREMENT_UNPROVEN');
   lifetime.confirmRetired();retired=true;return true;
  },
  async execRegistration(packet){
   // Validate the serialized packet again at the final producer boundary.
   if(typeof packet!=='string'||Buffer.byteLength(packet)>service.LIMITS.packetBytes)throw fail('ORIGINAL_SERVICE_PACKET_BYTES');
   const q=JSON.parse(packet);
   if(Object.keys(q).sort().join(',')!=='body,method,path,token'||q.token!==token
    ||service._internals.serializeRequest(q.method,PREFIX+q.path,q.body,token,profile)!==packet)throw fail('ORIGINAL_SERVICE_REQUEST');
   const cleanup=cleanupEnd!==undefined;
   if(cleanup&&!(q.method==='POST'&&(q.path==='/registration/drain'||pair&&q.path==='/invoke/drain')))throw fail('ORIGINAL_SERVICE_REVOKED');
   if(cleanup)await claimRetirement();
   return phase(cleanup?'serviceDrain':'serviceExec',packet,cleanup);
  }};
 try{
  await phase('serviceStartupClaim');profileAttempted=true;await phase('serviceProfileInstall');container=true;
  const binding={imageId:handoff.imageId,name:plan.registryConsumer.name,runId:handoff.runId,token};
  id=validateContainer(JSON.parse(await phase('serviceCreate',JSON.stringify({token}))),{...binding,running:false});
  validateContainer(JSON.parse(await phase('serviceStart')),{...binding,id,running:true});
  validateContainer(JSON.parse(await phase('serviceInspect')),{...binding,id,running:true});
  const ready=JSON.parse(await phase('serviceReadiness'));
  if(Object.keys(ready).sort().join(',')!=='ready,runtimeDigest'||ready.ready!==true||!/^[a-f0-9]{64}$/.test(ready.runtimeDigest||''))throw fail('ORIGINAL_SERVICE_READINESS');
  record({version:1,stage:'actual-executor-readiness',containerId:id,imageId:handoff.imageId,runtimeDigest:ready.runtimeDigest});
  const client=require('../../server/services/secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient({
   baseURL:'http://127.0.0.1:8094',token,expectedRuntimeDigest:ready.runtimeDigest,
   fetchImpl:async(url,options)=>{
    if(options.method!=='GET'||![PREFIX+'/registration/health',...(pair?[PREFIX+'/health',PREFIX+'/invoke/health']:[])].includes(url.pathname))throw fail('ORIGINAL_SERVICE_HEALTH_ROUTE');
    const packet=service._internals.serializeRequest('GET',url.pathname,null,token,profile);
    const reply=service._internals.parseResponse(await phase('serviceHealth',packet));
    return new Response(JSON.stringify(reply.body),{status:reply.status});
   }});
  // Preserve the original bounded readiness-only poll. Registration mutations
  // and recovery requests are never retried by this producer.
  for(let attempt=0;attempt<5;attempt++){
   lifetime.assertActive();
   try{await client.registrationHealth({signal:lifetime.signal});if(pair){await client.health({signal:lifetime.signal});await client.invocationHealth({signal:lifetime.signal});}break;}
   catch(error){
    if(attempt===4)throw error;
    lifetime.assertActive();
    await lifetime.joinPhase(()=>new Promise((resolve,reject)=>{
     const abort=()=>{clearTimeout(timer);lifetime.signal.removeEventListener('abort',abort);reject(fail('ORIGINAL_SERVICE_START_ABORTED'));};
     const timer=setTimeout(()=>{lifetime.signal.removeEventListener('abort',abort);resolve();},100);
     lifetime.signal.addEventListener('abort',abort,{once:true});if(lifetime.signal.aborted)abort();
    }));
   }
  }
  relay=relayFactory({token,profile,dispatch:(...args)=>{if(!state)throw fail('ORIGINAL_SERVICE_NOT_READY');return state.dispatch(...args);}});
  const address=await lifetime.joinPhase(()=>{lifetime.assertActive();return relay.listen();});
  if(address?.address!=='127.0.0.1'||!Number.isInteger(address.port)||address.port<1024||address.port>65535)throw fail('ORIGINAL_SERVICE_ENDPOINT');
  const started=performance.now(),claim=await phase('serviceCohortClaim');
  let budgetMs=cohortMs;
  if(pair){
   const row=JSON.parse(claim);
   if(Object.keys(row).sort().join(',')!=='deadlineMs,phase,runId,startedAtMs,target,version'
    ||row.version!==1||row.target!==require('./ownedMcpOriginalServiceLease').specification(profile).target||row.runId!==handoff.runId||row.phase!=='cohort'
    ||!Number.isSafeInteger(row.startedAtMs)||!Number.isSafeInteger(row.deadlineMs)
    ||row.deadlineMs<=row.startedAtMs||row.deadlineMs-row.startedAtMs>cohortMs)throw fail('V39_SERVICE_COHORT_WINDOW');
   // Sampling before the remote claim makes the cross-clock mapping conservative;
   // delayed delivery consumes this same window, never grants a renewed one.
   budgetMs=row.deadlineMs-row.startedAtMs;
  }
  const deadline=started+budgetMs;
  record({version:1,stage:'cohort-window',clock:'producer-performance-now-ms',startedAtMs:started,
   deadlineMs:deadline,budgetMs,admissionIncluded:true,renewable:false});
  clearTimeout(startupTimer);
  cohortTimer=setTimeout(()=>lifetime.expireWork(),Math.max(0,deadline-performance.now()));
  state=service._internals.createControlledService({...owner,closeEndpoint:async()=>{
   await lifetime.joinPhase(()=>relay.close());await owner.closeEndpoint();
  }},{token,signal:lifetime.signal,deadline,profile});
  result=await lifetime.joinPhase(()=>{lifetime.assertActive();const entered=performance.now();
   if(entered>=deadline)throw fail('ORIGINAL_SERVICE_COHORT_EXPIRED');
   return Promise.resolve().then(()=>{lifetime.assertActive();return cohort(Object.freeze({configuration:Object.freeze({version:1,
   workspace:require('../../server/services/mcp/ownedManagedConfiguration').workspaceId(plan.spec.root),enabled:true,
   baseURL:'http://127.0.0.1:'+address.port,token,runtimeDigest:ready.runtimeDigest,mode:'vuln'}),
   deadline,cohortWindow:Object.freeze({version:1,clock:'producer-performance-now-ms',startedAtMs:started,
    callbackEnteredAtMs:entered,deadlineMs:deadline,budgetMs,remainingMs:deadline-entered,
    admissionIncluded:true,renewable:false}),signal:lifetime.signal,qualificationComplete:false}));})
    .catch(error=>{cohortFailure=error;throw error;});});
 }catch(error){primary=error;}
 finally{clearTimeout(startupTimer);clearTimeout(cohortTimer);}
 // A lost assembly owner or unjoined browser/PG is not permission to tear the
 // executor out from under it. Preserve the private runtime for recovery.
 if(pair&&primary?.retirementUnproven){
  // Retire only this owner's local forwarding handles. Do not remove the
  // remote listener/profile or assert that external work has settled.
  try{beginRetirement();if(relay)await lifetime.joinPhase(()=>relay.close());}
  catch(error){primary.localCleanupError=error;}
  throw primary;
 }
 try{
  beginRetirement();
  if(state)await state.close();
  else{if(relay)await lifetime.joinPhase(()=>relay.close());await owner.closeEndpoint();await owner.stopListener();owner.confirmRetired();}
 }catch(error){cleanupFailed=true;if(primary)primary.cleanupError=error;else primary=error;if(!retired)primary.retirementUnproven=true;}
 if(profile==='original-service'&&primary instanceof Error&&primary===cohortFailure&&retired&&!cleanupFailed
  &&!lifetime.signal.aborted&&!lifetime.retirementSignal.aborted){
  lifetime.assertOpen();retiredFailures.set(primary,Object.freeze({handoff,plan}));
 }
 if(primary)throw primary;
 return {value:result,controlled:handoff.controlled,cleanupVerified:retired,qualificationComplete:false};
}
// The assembly owns the socketpair and the PG/browser process tree. This
// channel carries only a fixed protocol, never commands or image authority.
function pairChannel(socket, binding) {
 const max=16384;let buffer=Buffer.alloc(0),waiting=null,queued=null,problem=null,closed=false;
 const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&Object.keys(value).sort().join(',')===keys.slice().sort().join(',');
 const reject=error=>{problem=problem||error;if(waiting){clearTimeout(waiting.timer);waiting.reject(problem);waiting=null;}};
 socket.on('error',()=>reject(fail('V39_IPC_IO')));
 socket.on('end',()=>reject(fail('V39_IPC_EOF')));
 socket.on('close',()=>{closed=true;reject(fail('V39_IPC_CLOSED'));});
 socket.on('data',chunk=>{try{
  if(problem) return;
  if(buffer.length+chunk.length>max)throw fail('V39_IPC_LIMIT');
  buffer=Buffer.concat([buffer,chunk]);const end=buffer.indexOf(10);
  if(end<0)return;
  if(end!==buffer.length-1||queued)throw fail('V39_IPC_MULTIPLE');
  const raw=buffer.subarray(0,end).toString('utf8'),value=JSON.parse(raw);buffer=Buffer.alloc(0);
  if(JSON.stringify(value)!==raw||value.version!==1||value.runId!==binding.runId||value.planSha256!==binding.planSha256)
   throw fail('V39_IPC_BINDING');
  if(waiting){const current=waiting;waiting=null;clearTimeout(current.timer);current.resolve(value);}else queued=value;
 }catch(error){reject(fail(error.code||'V39_IPC_FRAME'));}});
 const read=async(op,keys,deadline)=>{
  if(problem)throw problem;if(waiting||!Number.isFinite(deadline)||deadline<=performance.now())throw fail('V39_IPC_DEADLINE');
  const value=queued?(v=>{queued=null;return Promise.resolve(v);})(queued):new Promise((resolve,rejectRead)=>{
   waiting={resolve,reject:rejectRead,timer:setTimeout(()=>reject(fail('V39_IPC_DEADLINE')),deadline-performance.now())};
  });
  const result=await value;
  if(performance.now()>=deadline||result.op!==op||!exact(result,['version','op','runId','planSha256',...keys]))throw fail('V39_IPC_SCHEMA');
  return result;
 };
 const send=(op,fields,deadline)=>new Promise((resolve,rejectWrite)=>{
  if(problem||closed||deadline<=performance.now())return rejectWrite(problem||fail('V39_IPC_DEADLINE'));
  const bytes=Buffer.from(JSON.stringify({version:1,op,...binding,...fields})+'\n');
  if(bytes.length>max)return rejectWrite(fail('V39_IPC_LIMIT'));
  const timer=setTimeout(()=>{reject(fail('V39_IPC_DEADLINE'));rejectWrite(problem);},deadline-performance.now());
  socket.write(bytes,error=>{clearTimeout(timer);if(error||problem)rejectWrite(problem||fail('V39_IPC_IO'));else resolve();});
 });
 return Object.freeze({read,send,close(){socket.destroy();}});
}
async function pairCohort(channel,value) {
 const debt=error=>{error.retirementUnproven=true;return error;};
 try {
  // The parent samples its clock before requesting this window. The reply's
  // remaining duration therefore cannot renew the producer's child deadline.
  await channel.send('endpoint',{configuration:value.configuration},value.deadline);
  await channel.read('window',[],value.deadline);
  const remainingMs=Math.floor(value.deadline-performance.now());
  if(remainingMs<1||remainingMs>480000)throw fail('V39_IPC_CHILD_DEADLINE');
  await channel.send('window',{remainingMs},value.deadline);
  const result=await channel.read('retired',['childAbsent','browserAbsent','postgresAbsent','passed'],value.deadline+1080000);
  if(result.childAbsent!==true||result.browserAbsent!==true||result.postgresAbsent!==true||typeof result.passed!=='boolean')
   throw fail('V39_ASSEMBLY_RETIREMENT_UNPROVEN');
  if(!result.passed)throw fail('V39_ASSEMBLY_FAILED');
  return {version:1,assemblyRetired:true,passed:true};
 }catch(error){if(error.code!=='V39_ASSEMBLY_FAILED')throw debt(error);throw error;}
}
module.exports={commands,consume,validateContainer,boundedPhase,pairChannel,pairCohort,isRetiredFailure,_internals:{REMAINING_PROGRAM,PHASE_HEADER}};
