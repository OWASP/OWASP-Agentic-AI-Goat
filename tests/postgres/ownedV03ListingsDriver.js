'use strict';
// Fixed V03 Listings command owner. No caller command, runner, image or expiry.
// The combined parent is the only capability source; serialized plans are pins.
const fs=require('node:fs/promises'),native=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const adapter=require('./ownedMcpOriginalBuildAdapter');
const bounded=require('./ownedMcpBoundedBuild')._internals;
const transport=require('./ownedSystemConfigPhaseDriver')._internals;
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=code=>Object.assign(new Error(code),{code});
const exact=(v,names)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===names.split(',').sort().join(',');
const drivers=new WeakMap();
const BUILD=Object.freeze(['inventory','preflight','prepare','serviceLeasebuild','namespace','relayStart','daemonStart',
 'inspect','metadataFetch','startArtifacts','closureEvidence','inspect','build','image','inspect']);
const SETTLE=Object.freeze(['serviceLeasesettlement','retireArtifacts','closureEvidence','handoff']);
const makeFile=(d,n)=>fs.open(path.join(d,n),native.constants.O_RDWR|native.constants.O_CREAT|native.constants.O_EXCL|native.constants.O_NOFOLLOW,0o600);
function transportPlannedCommand(plan,name,seconds){
 const source=plan?.commands?.[name];
 if(typeof source!=='string'||!source||Buffer.byteLength(source)>1024**2||!Number.isSafeInteger(seconds)||seconds<1||seconds>310)
  throw fail('V03_LISTINGS_COMMAND');
 const selected=adapter._internals.phaseTransport(source,'owned-system-build');
 const sourceSha256=sha(source);
 if(selected.scriptSha256!==sourceSha256)throw fail('V03_LISTINGS_TRANSPORT_BINDING');
 const argv=['sudo','-n','timeout','--signal=TERM','--kill-after=10',String(seconds),
  '/bin/sh','-c',selected.command,'owned-system-build',plan.spec.guest,plan.spec.runId];
 if(name==='metadataFetch')argv.push(plan.binding.base);
 const envelope=adapter._internals.limaArgvEnvelope(argv);
 return Object.freeze({command:selected.command,sourceSha256,commandSha256:sha(selected.command),
  decodedBytes:selected.decodedBytes,encodedBytes:selected.encodedBytes,envelopeBytes:envelope.scriptBytes});
}
async function trackedExecute(outcomes,conf,files,options,now){
 const dispatchedAtMs=now();
 const outcome={phase:conf.phase,receipt:null,settled:false,localClosureProven:false,
  dispatchedAtMs,remoteNotBeforeMs:dispatchedAtMs+(conf.remoteSeconds+20)*1000,remoteUncertain:true};
 outcomes.push(outcome);
 try{outcome.receipt=await transport.executePython(conf,files,options);return outcome.receipt;}
 catch(error){outcome.receipt=error.phaseReceipt||null;outcome.failure=error.code||'V03_LISTINGS_EXECUTE_FAILED';throw error;}
 finally{
  outcome.settled=true;
  try{transport.validateReceipt(outcome.receipt,conf.phase,conf.expectedMux);
   outcome.localClosureProven=transport.localRetired(outcome.receipt)===true;
   if(!outcome.failure&&outcome.receipt.code===0&&outcome.receipt.failure===null&&outcome.localClosureProven)
    outcome.remoteUncertain=false;
  }catch{outcome.localClosureProven=false;}
  // Match the existing failed-command safety delay from terminal observation,
  // not dispatch: remote command startup may lag local dispatch.
  if(outcome.remoteUncertain)outcome.remoteNotBeforeMs=now()+(conf.remoteSeconds+20)*1000;
 }
}
function requireRemoteSettlement(outcomes,now){
 if(outcomes.some(row=>row.remoteUncertain&&(!Number.isFinite(row.remoteNotBeforeMs)||now<row.remoteNotBeforeMs)))
  throw Object.assign(fail('V03_LISTINGS_REMOTE_SETTLEMENT_PENDING'),{cleanupDebt:true});
}
function requireLocalClosure(outcomes){
 if(outcomes.some(row=>row.settled!==true||row.localClosureProven!==true))
  throw Object.assign(fail('V03_LISTINGS_LOCAL_CLOSURE_UNPROVEN'),{cleanupDebt:true});
}
async function durable(fd,value){
 const bytes=Buffer.from(JSON.stringify(value)+'\n');if(bytes.length>65536)throw fail('V03_LISTINGS_RECORD_BOUND');
 let offset=0;while(offset<bytes.length){const r=await fd.write(bytes,offset,bytes.length-offset);if(!r.bytesWritten)throw fail('V03_LISTINGS_WRITE');offset+=r.bytesWritten;}
 await fd.sync();
}
function assertListingsDriver(value){if(!drivers.has(value))throw fail('V03_LISTINGS_DRIVER_REQUIRED');return value;}
async function createListingsDriver(options){
 if(!exact(options,'root,runId,parentRunId,combinedOwner,expectedPlanSha256,expectedDriverSha256,expectedTransportSha256,expectedPythonSha256,expectedHostPythonSha256'))throw fail('V03_LISTINGS_DRIVER_OPTIONS');
 const owner=require('./ownedV03PrivateExecutors').assertCombinedOwner(options.combinedOwner),binding=owner.producerBinding('listings');
 if(options.runId!==binding.runId||options.parentRunId!==binding.parentRunId||owner.isRevoked())throw fail('V03_LISTINGS_DRIVER_BINDING');
 const mapping=require('./ownedV03GuestClock').assertGuestClockMapping(owner.clockMapping(),owner);
 for(const key of ['expectedPlanSha256','expectedDriverSha256','expectedTransportSha256','expectedPythonSha256','expectedHostPythonSha256'])
  if(!/^[a-f0-9]{64}$/.test(options[key]||''))throw fail('V03_LISTINGS_DRIVER_PIN');
 const root=path.resolve(__dirname,'../..');if(options.root!==root||await fs.realpath(root)!==root)throw fail('V03_LISTINGS_ROOT');
 const plan=await adapter.originalBuildPlan(root,binding.runId,{target:'listings-package',listingsMode:'v03-manager'});
 if(adapter.planDigest(plan)!==options.expectedPlanSha256)throw fail('V03_LISTINGS_PLAN');
 const python=await fs.realpath('/opt/homebrew/bin/python3');
 const pins=[[__filename,options.expectedDriverSha256,1024**2],
  [path.join(__dirname,'ownedSystemConfigPhaseDriver.js'),options.expectedTransportSha256,1024**2],
  [python,options.expectedPythonSha256,64*1024**2],
  ...Object.entries(transport.DEPS).map(([n,h])=>[path.join(__dirname,n+'.py'),h,1024**2])];
 async function verify(){
  for(const [file,digest,limit]of pins)if(sha(await transport.regular(file,limit))!==digest)throw fail('V03_LISTINGS_SOURCE');
  await adapter._internals.verifyPlanSources(plan);
 }
 await verify();owner.phaseSignal('listingsBuildMs').throwIfAborted();
 const directory=path.join(root,'tasks/tmp','v03-listings-driver-'+binding.runId);
 if(await fs.realpath(path.dirname(directory))!==path.dirname(directory))throw fail('V03_LISTINGS_DIRECTORY');
 await fs.mkdir(directory,{mode:0o700});
 const receipts=[],outcomes=[],debts=[];let ordinal=0,mux=null,busy=false,stage='new',baseline=null,daemon=null,envelope=null,ready=null,image=null,handoff=null,started=false,artifacts=false,artifactRetired=false,retirement=null,joined=false;
 let bridge=null,managerInput=null,channelInput=null,managerHandoff=null,profileAttempted=false,managerAttempted=false,runtimeRetired=false,token=null;
 let journal;
 try{
  journal=await makeFile(directory,'journal.jsonl');
  const parent=await fs.open(directory,native.constants.O_RDONLY|native.constants.O_DIRECTORY|native.constants.O_NOFOLLOW);
  try{await parent.sync();}finally{await parent.close();}
 }catch(error){
  if(journal)try{await journal.close();}catch{error.journalCloseFailed=true;}
  throw Object.assign(error,{cleanupDebt:true,driverDirectory:directory});
 }
 async function inputFor(name,kind){
  const proof=mapping.binding();
  if(proof.parentRunId!==binding.parentRunId||proof.combinedPlanSha256!==binding.planSha256)throw fail('V03_LISTINGS_CLOCK_BINDING');
  if(name==='prepare')return Buffer.from(JSON.stringify({version:1,runId:binding.runId,parentRunId:binding.parentRunId,
   combinedPlanSha256:binding.planSha256,guestBootId:proof.guestBootId,expiresAtMs:mapping.mapDeadline(binding.expiresAtMs)}));
  if(name.startsWith('serviceLease')){
   const phase=name.slice('serviceLease'.length),window=owner.phaseWindow(kind);
   const interval=owner.isRevoked()?mapping.mapRetirementInterval(kind):mapping.mapInterval({startedAtMs:window.startedAtMs,deadlineMs:window.deadlineMs});
   return Buffer.from(JSON.stringify({parentRunId:binding.parentRunId,runId:binding.runId,combinedPlanSha256:binding.planSha256,
    guestBootId:proof.guestBootId,phase:phase==='cohort'?'cohortClaim':phase,...interval}));
  }
  if(name==='metadataFetch')return Buffer.from(plan.metadataGuestSource);
  if(name==='listingsManagerCreate'){
   if(!managerInput)throw fail('V03_LISTINGS_MANAGER_INPUT');return Buffer.from(JSON.stringify(managerInput));
  }
  if(name==='listingsManagerChannels'){
   if(!channelInput)throw fail('V03_LISTINGS_CHANNEL_INPUT');return Buffer.from(JSON.stringify(channelInput));
  }
  if(name==='startArtifacts')return Buffer.from(plan.guestSource);
  if(name==='build'){
   const captured=await adapter._internals.captureListings(root),chunks=[];let bytes=0;
   for await(const chunk of require('../../scripts/install/secureshop-owned-mcp-registry-setup')._internals.contextStream(captured.files)){
    bytes+=chunk.length;if(bytes>17*1024**2)throw fail('V03_LISTINGS_INPUT_BOUND');chunks.push(chunk);
   }
   return Buffer.concat(chunks);
  }
  return Buffer.alloc(0);
 }
 async function phase(name,kind){
  requireLocalClosure(outcomes);
  const window=owner.phaseWindow(kind),signal=owner.phaseSignal(kind);
  const check=()=>{signal.throwIfAborted();if(owner.phaseWindow(kind)!==window)throw fail('V03_LISTINGS_PHASE_CHANGED');};
  check();await verify();check();
  const input=await inputFor(name,kind);if(input.length>17*1024**2)throw fail('V03_LISTINGS_INPUT_BOUND');
  const prefix=String(++ordinal).padStart(3,'0')+'-'+name,handles={},inputPath=path.join(directory,prefix+'.input');
  let primary,result;
  try{
   for(const suffix of ['input','stdout','stderr'])handles[suffix]=await makeFile(directory,prefix+'.'+suffix);
   await handles.input.writeFile(input);await handles.input.sync();
   const parent=await fs.open(directory,native.constants.O_RDONLY|native.constants.O_DIRECTORY|native.constants.O_NOFOLLOW);
   try{await parent.sync();}finally{await parent.close();}
   const cohortClaim=name==='serviceLeasecohort'&&kind==='cohortClaim';
   const maximum=cohortClaim?3:['metadataFetch','startArtifacts','build'].includes(name)?310:150;
   const reserve=cohortClaim?1:46;
   const seconds=Math.min(maximum,Math.floor((window.deadlineMs-owner.nowMs())/1000)-reserve);
   if(seconds<1)throw fail('V03_LISTINGS_PHASE_RESERVE');
   const selected=transportPlannedCommand(plan,name,seconds);
   const conf={root,runId:binding.runId,guest:plan.spec.guest,base:plan.binding.base,phase:name,command:selected.command,
    commandSha256:selected.commandSha256,deps:transport.DEPS,expectedMux:mux,inputPath,inputSha256:sha(input),remoteSeconds:seconds,
    outputLimit:name==='retainedExport'?145*1024**2:2*1024**2};
   await durable(journal,{stage:'intent',ordinal,name,planSha256:options.expectedPlanSha256,inputSha256:sha(input),
    commandSha256:selected.sourceSha256,transportCommandSha256:selected.commandSha256});
   check();if(window.deadlineMs-owner.nowMs()<(seconds+reserve)*1000)throw fail('V03_LISTINGS_PHASE_RESERVE');
   if(name==='prepare')started=true;if(name==='startArtifacts')artifacts=true;
   const receipt=await trackedExecute(outcomes,conf,{journal,stdout:handles.stdout,stderr:handles.stderr},{python,signal},()=>owner.nowMs());
   receipts.push(receipt);
   transport.validateReceipt(receipt,name,mux);
   if(receipt.code!==0||receipt.failure!==null||!receipt.muxUnchanged||!transport.localRetired(receipt))throw fail('V03_LISTINGS_PHASE_UNPROVEN');
   mux=receipt.mux;
   for(const suffix of ['stdout','stderr']){
    await handles[suffix].sync();const actual=await transport.fileDigest(path.join(directory,prefix+'.'+suffix),suffix==='stdout'?conf.outputLimit:2*1024**2);
    if(actual.bytes!==receipt[suffix].bytes||actual.sha256!==receipt[suffix].sha256)throw fail('V03_LISTINGS_OUTPUT_CHANGED');
   }
   result=name==='retainedExport'?null:(await transport.regular(path.join(directory,prefix+'.stdout'),2*1024**2)).toString();
   check();await durable(journal,{stage:'accepted',ordinal,name,receipt});
  }catch(error){primary=error;debts.push({name,code:error.code||'V03_LISTINGS_PHASE_FAILED',remoteUncertain:true});}
  finally{for(const fd of Object.values(handles))try{await fd.close();}catch(error){primary ||= error;debts.push({name,code:'V03_LISTINGS_FILE_CLOSE'});}}
  if(primary)throw primary;return result;
 }
 async function closure(text,terminal,allowFailedReplay=false){
  const packet=JSON.parse(text),lock=await fs.readFile(path.join(root,'sidecars/sandbox-runner/owned-mcp-registry/package-lock.json'));
  if(ready&&envelope)adapter._internals.validateClosureEvidence(packet,ready,envelope,lock,{terminal,allowFailedReplay});
  else if(packet['replay-intent.json']!==null)adapter._internals.validateReplayTerminal(packet,plan.binding,{allowFailedReplay});
  else if(packet['replay-terminal.json']!==null||packet['replay-failure.json']!==null)throw fail('V03_LISTINGS_REPLAY_EVIDENCE');
 }
 async function runList(names,kind){
  if(busy)throw fail('V03_LISTINGS_OVERLAP');busy=true;
  try{for(const name of names){
   const text=await phase(name,kind);
   if(name==='inventory'){const value=bounded.checkInventory(text);if(baseline===null)baseline=value;else if(value!==baseline)throw fail('V03_LISTINGS_SHARED_CHANGED');}
   if(name==='inspect'){const value=bounded.checkDaemon(JSON.parse(text),plan.spec);if(daemon===null)daemon=value;else if(value!==daemon)throw fail('V03_LISTINGS_DAEMON_CHANGED');}
   if(name==='metadataFetch'){envelope=require('./ownedPolicySystemMetadata').validateResultEnvelope(text,plan.binding);if(envelope.version!==3||envelope.ok!==true)throw fail('V03_LISTINGS_METADATA');}
   if(name==='startArtifacts'){ready=JSON.parse(text);if(ready?.version!==1||JSON.stringify(ready.binding)!==JSON.stringify(plan.binding)||ready.artifactBytesVerified!==true||ready.metadataAuthenticated!==true||!/^[a-f0-9]{64}$/.test(ready.closureSha256||''))throw fail('V03_LISTINGS_ARTIFACT_READY');}
   if(name==='closureEvidence')await closure(text,artifactRetired);
   if(name==='image'){
    const rows=JSON.parse(text);image=rows?.[0];const c=plan.imageContract;
    if(rows.length!==1||!/^sha256:[a-f0-9]{64}$/.test(image?.Id||'')||image.Architecture!=='arm64'||image.Os!=='linux'
     ||image.Config?.Labels?.[c.label]!==plan.packageDigest||image.Config?.Labels?.['owasp-ai-goat.build-run']!==binding.runId
     ||image.Config?.Labels?.['owasp-ai-goat.listings.runtime']!==c.runtimeDigest||image.Config?.User!==c.user
     ||JSON.stringify(image.Config?.Entrypoint)!==JSON.stringify(c.entrypoint))throw fail('V03_LISTINGS_IMAGE');
   }
   if(name==='retireArtifacts'){if(text.trim()!=='absent')throw fail('V03_LISTINGS_ARTIFACT_RETIREMENT');artifactRetired=true;}
   if(name==='handoff')handoff=adapter._internals.validatePhysicalHandoff(JSON.parse(text),plan);
  }}finally{busy=false;}
 }
 const value=Object.freeze({
  async prepare(){if(stage!=='new')throw fail('V03_LISTINGS_PREPARE_ONCE');stage='preparing';try{await runList(BUILD,'listingsBuildMs');stage='built';return {built:true};}catch(e){stage='failed';throw e;}},
  async settle(){if(stage!=='built')throw fail('V03_LISTINGS_SETTLE_ORDER');stage='settling';try{await runList(SETTLE,'listingsSettlementMs');stage='prepared';return {prepared:true};}catch(e){stage='failed';throw e;}},
  async startRuntime(sourcePins){
   if(stage!=='prepared'||busy||bridge)throw fail('V03_LISTINGS_RUNTIME_ORDER');busy=true;
   try{
    for(const [name,digest]of Object.entries({...plan.buildSources,...plan.helperHashes}))
     if(sourcePins?.[name]!==digest)throw fail('V03_LISTINGS_RUNTIME_SOURCE');
    bridge=await require('./ownedV03ListingsBridgeHost').createListingsBridgeHost({owner,root,sourcePins,expectedPythonSha256:options.expectedHostPythonSha256});
    require('./ownedV03ListingsBridgeHost').assertListingsBridgeHost(bridge);
    const endpoint=await bridge.start();token=crypto.randomBytes(32).toString('base64url');
    managerInput={origin:endpoint.origin,token};
    await phase('serviceLeasestartup','listingsStartupMs');profileAttempted=true;
    await phase('listingsProfileInstall','listingsStartupMs');managerAttempted=true;
    if((await phase('listingsManagerCreate','listingsStartupMs')).trim()!=='created')throw fail('V03_LISTINGS_MANAGER_CREATE');
    const row=JSON.parse(await phase('listingsManagerStart','listingsStartupMs'));
    if(row.runId!==binding.runId||row.root!==plan.spec.mount||row.imageId!==image.Id||row.sourceSha256!==plan.packageDigest
     ||row.runtimeSha256!==plan.imageContract.runtimeDigest||row.publicOrigin!==endpoint.origin||row.privateDockerHost!==handoff.privateDockerHost
     ||row.holderPid!==handoff.namespaceHolder.pid||String(row.holderStart)!==handoff.namespaceHolder.startTicks
     ||row.filesystemDevice!==handoff.filesystemIdentity.device||row.filesystemInode!==handoff.filesystemIdentity.inode
     ||'net:['+row.namespaceInode+']'!==handoff.namespaceInode||!/^[a-f0-9]{64}$/.test(row.containerId||''))throw fail('V03_LISTINGS_MANAGER_HANDOFF');
    managerHandoff=row;stage='ready';return {ready:true};
   }catch(error){stage='failed';if(error.cleanupDebt)debts.push({name:'runtime',code:error.code||'V03_LISTINGS_RUNTIME_DEBT'});throw error;}
   finally{busy=false;}
  },
  async claimCohort(){
   if(stage!=='ready'||busy||!managerHandoff)throw fail('V03_LISTINGS_COHORT_ORDER');busy=true;stage='claiming';
   try{
    const record=JSON.parse(await phase('serviceLeasecohort','cohortClaim'));
    await bridge.claim(managerHandoff,record);
    const authority=require('../../scripts/local-docker-authority').authorityDigest({version:1,
     workspaceId:require('../../scripts/application-data-root').workspaceId(root),host:managerHandoff.privateDockerHost,daemonId:managerHandoff.daemonId});
    stage='claimed';return {additionalClockUncertaintyMs:bridge.uncertaintyMs(),environment:{
     SECURESHOP_LISTINGS_TEST_MANAGER_ORIGIN:managerHandoff.publicOrigin,SECURESHOP_LISTINGS_TEST_MANAGER_TOKEN:token,
     SECURESHOP_LISTINGS_TEST_MANAGER_RUNTIME_DIGEST:managerHandoff.runtimeSha256,SECURESHOP_LISTINGS_TEST_MANAGER_IMAGE_ID:managerHandoff.imageId,
     SECURESHOP_LISTINGS_TEST_MANAGER_SOURCE_SHA256:managerHandoff.sourceSha256,SECURESHOP_LISTINGS_TEST_MANAGER_CONTAINER_ID:managerHandoff.containerId,
     SECURESHOP_LISTINGS_TEST_MANAGER_DOCKER_AUTHORITY_SHA256:authority,SECURESHOP_LISTINGS_TEST_DOCKER_HOST:managerHandoff.privateDockerHost,
     SECURESHOP_LISTINGS_TEST_DOCKER_DAEMON_ID:managerHandoff.daemonId}};
   }catch(error){stage='failed';throw error;}finally{busy=false;}
  },
  async join(){
   const window=owner.phaseWindow('listingsRetirementMs'),signal=owner.phaseSignal('listingsRetirementMs');
   if(!owner.isRevoked()||joined||busy)throw fail('V03_LISTINGS_JOIN_UNPROVEN');
   requireLocalClosure(outcomes);
   const until=Math.max(owner.nowMs(),...outcomes.filter(row=>row.remoteUncertain).map(row=>row.remoteNotBeforeMs));
   if(!Number.isFinite(until)||until>=window.deadlineMs)throw fail('V03_LISTINGS_REMOTE_SETTLEMENT_RESERVE');
   while(owner.nowMs()<until){
    signal.throwIfAborted();if(owner.phaseWindow('listingsRetirementMs')!==window)throw fail('V03_LISTINGS_PHASE_CHANGED');
    await new Promise(resolve=>setTimeout(resolve,Math.min(100,until-owner.nowMs())));
   }
   signal.throwIfAborted();if(owner.phaseWindow('listingsRetirementMs')!==window)throw fail('V03_LISTINGS_PHASE_CHANGED');
   requireRemoteSettlement(outcomes,owner.nowMs());
   if(bridge){
    const local=await bridge.close();
    if(local.listenerClosed!==true||local.localChannelsRetired!==true||!Array.isArray(local.channelIds)
     ||new Set(local.channelIds).size!==local.channelIds.length||local.channelIds.some(id=>!/^[a-f0-9]{32}$/.test(id)))throw fail('V03_LISTINGS_BRIDGE_CLOSURE');
    channelInput={channelIds:local.channelIds,listenerClosed:true,localChannelsRetired:true};
   }
   if(profileAttempted||managerAttempted){
    await phase('serviceLeaseretirement','listingsRetirementMs');
    if(managerAttempted){
     if(!managerHandoff||!channelInput)throw fail('V03_LISTINGS_PARTIAL_MANAGER_DEBT');
     const proof=JSON.parse(await phase('listingsManagerChannels','listingsRetirementMs'));
     if(proof.version!==1||proof.runId!==binding.runId||proof.remoteChannelsAbsent!==true
      ||!Array.isArray(proof.channels)||JSON.stringify(proof.channels.map(row=>row.channelId))!==JSON.stringify(channelInput.channelIds))throw fail('V03_LISTINGS_CHANNELS_UNPROVEN');
     if((await phase('listingsManagerRetire','listingsRetirementMs')).trim()!=='absent')throw fail('V03_LISTINGS_MANAGER_REMAINS');
    }
    if((await phase('listingsProfileRetire','listingsRetirementMs')).trim()!=='absent')throw fail('V03_LISTINGS_PROFILE_REMAINS');
   }
   runtimeRetired=true;
   joined=true;return Object.freeze({localRetired:true,cleanupVerified:false});
  },
  retire(){
   if(retirement)return retirement;
   owner.phaseWindow('listingsCleanupMs');if(!owner.isRevoked()||!joined||busy)throw fail('V03_LISTINGS_RETIREMENT_ORDER');
   requireLocalClosure(outcomes);
   requireRemoteSettlement(outcomes,owner.nowMs());
   if(!runtimeRetired)throw fail('V03_LISTINGS_RUNTIME_RETIREMENT_UNPROVEN');
   retirement=(async()=>{
    stage='retiring';const errors=[];
    try{
     if(started){
      await phase('serviceLeasecleanup','listingsCleanupMs');
      if(artifacts&&!artifactRetired){
       if((await phase('retireArtifacts','listingsCleanupMs')).trim()!=='absent')throw fail('V03_LISTINGS_ARTIFACT_RETIREMENT');
       artifactRetired=true;
      }
      if(artifacts)await closure(await phase('closureEvidence','listingsCleanupMs'),true,true);
      await phase('stop','listingsCleanupMs');
      await phase('evidence','listingsCleanupMs');
      await phase('retainedExport','listingsCleanupMs');
      if((await phase('cleanup','listingsCleanupMs')).trim()!=='absent')throw fail('V03_LISTINGS_CLEANUP');
     }
     const after=bounded.checkInventory(await phase('inventory','listingsCleanupMs'));
     if(baseline===null||after!==baseline)throw fail('V03_LISTINGS_SHARED_CHANGED');
     await verify();
    }catch(error){errors.push(error.code||'V03_LISTINGS_RETIREMENT_FAILED');}
    const receipt={version:1,runId:binding.runId,closed:false,cleanupVerified:false,
     resourceAbsenceProven:false,errors,debts:debts.slice(),ownedCommands:outcomes.length,commandOutcomes:outcomes.slice()};
    try{await durable(journal,{stage:'cleanup-candidate',journalClosePending:true,
     resourcesVerified:errors.length===0&&debts.length===0,receipt});}catch{errors.push('V03_LISTINGS_TERMINAL_WRITE');}
    try{await journal.close();}catch{errors.push('V03_LISTINGS_JOURNAL_CLOSE');}
    stage='closed';
    if(errors.length||debts.length){receipt.cleanupVerified=false;receipt.resourceAbsenceProven=false;
     throw Object.assign(fail('V03_LISTINGS_RETIREMENT_UNPROVEN'),{receipt,retirementUnproven:true});}
    receipt.closed=true;receipt.cleanupVerified=true;receipt.resourceAbsenceProven=true;
    return Object.freeze(receipt);
   })();return retirement;
  },
  publicStatus:()=>Object.freeze({stage,started,artifacts,artifactRetired,ownedCommands:outcomes.length,debtCount:debts.length,resourceAbsenceProven:false}),
 });
 drivers.set(value,{owner,plan,phase,runList,receipts,debts,journal,directory,get handoff(){return handoff;},get image(){return image;},get daemon(){return daemon;}});
 return value;
}
module.exports={createListingsDriver,assertListingsDriver,
 _internals:{transportPlannedCommand}};
