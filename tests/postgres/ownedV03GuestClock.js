'use strict';
// Fixed read-only clock sampling through the existing birth-checked controller.
// No caller-supplied command, runner, transport, or serialized mapping authority.
const fs=require('node:fs/promises'),native=require('node:fs'),path=require('node:path');
const {createHash}=require('node:crypto');
const driver=require('./ownedSystemConfigPhaseDriver')._internals;
const mappings=new WeakMap();
const MAX_UNCERTAINTY_MS=2000;
const PHASE='v03-clock-sample';
const fail=code=>Object.assign(new Error(code),{code});
const sha=value=>createHash('sha256').update(value).digest('hex');
const keys=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)
 &&Object.keys(value).sort().join(',')===names.split(',').sort().join(',');
const quote=value=>"'"+value.replace(/'/g,"'\\''")+"'";
const GUEST=String.raw`import os,sys,time,json,re
parent,plan=sys.argv[1:]
assert sys.platform=='linux' and os.geteuid()==0
assert re.fullmatch('[a-f0-9]{32}',parent) and re.fullmatch('[a-f0-9]{64}',plan)
with open('/proc/sys/kernel/random/boot_id','r',encoding='ascii') as stream:
 boot=stream.read(38).strip()
assert re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}',boot)
sample=time.monotonic_ns()//1000000
print(json.dumps(dict(version=1,parentRunId=parent,combinedPlanSha256=plan,guestMonotonicMs=sample,guestBootId=boot),separators=(',',':')))
`;

async function readBounded(file,maximum){
 if(await fs.realpath(file)!==file)throw fail('V03_CLOCK_SOURCE_PATH');
 const fd=await fs.open(file,native.constants.O_RDONLY|native.constants.O_NOFOLLOW|native.constants.O_NONBLOCK);
 let primary,result;
 try{
  const before=await fd.stat();
  if(!before.isFile()||before.nlink!==1||before.size>maximum)throw fail('V03_CLOCK_SOURCE_FILE');
  const bytes=Buffer.alloc(before.size);let offset=0;
  while(offset<bytes.length){const row=await fd.read(bytes,offset,bytes.length-offset,offset);
   if(!row.bytesRead)throw fail('V03_CLOCK_SOURCE_CHANGED');offset+=row.bytesRead;}
  const after=await fd.stat();
  for(const key of ['dev','ino','size','mtimeMs','ctimeMs'])if(before[key]!==after[key])throw fail('V03_CLOCK_SOURCE_CHANGED');
  result=bytes;
 }catch(error){primary=error;}
 finally{try{await fd.close();}catch(error){primary=retainCloseDebt(primary,error,'V03_CLOCK_SOURCE_CLOSE');}}
 if(primary)throw primary;
 return result;
}
function retainCloseDebt(primary,secondary,code){
 const error=primary||secondary;error.cleanupDebt=true;
 error.clockCleanupErrors=[...(error.clockCleanupErrors||[]),code];return error;
}
function mappingFor(owner,packet,sent,received,receipt){
 const binding=owner.binding();
 if(!keys(packet,'version,parentRunId,combinedPlanSha256,guestMonotonicMs,guestBootId')||packet.version!==1
  ||packet.parentRunId!==binding.runId||packet.combinedPlanSha256!==binding.planSha256
  ||!Number.isSafeInteger(packet.guestMonotonicMs)||packet.guestMonotonicMs<0
  ||! /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(packet.guestBootId||'')
  ||!Number.isSafeInteger(sent)||!Number.isSafeInteger(received)||received<sent
  ||received-sent+1>MAX_UNCERTAINTY_MS)throw fail('V03_CLOCK_SAMPLE_UNPROVEN');
 // Both clocks are integer-millisecond floors; charge one additional ms so
 // differing fractional phases cannot make the lower offset optimistic.
 const lower=packet.guestMonotonicMs-received-1;
 // The guest sample is taken between send and receive. The lower offset is
 // conservative: source preparation and every later delay consume the same
 // absolute expiry, never guest-now + freshly copied remaining time.
 const proof=Object.freeze({parentRunId:binding.runId,combinedPlanSha256:binding.planSha256,
  guestBootId:packet.guestBootId,sentAtMs:sent,receivedAtMs:received,
  guestMonotonicMs:packet.guestMonotonicMs,uncertaintyMs:received-sent+1});
 function mapDeadline(value){
  if(owner.isRevoked())throw fail('V03_CLOCK_REVOKED');
  if(!Number.isSafeInteger(value)||value<=owner.nowMs()||value>binding.expiresAtMs)
   throw fail('V03_CLOCK_DEADLINE');
  const mapped=value+lower;
  if(!Number.isSafeInteger(mapped)||mapped<=packet.guestMonotonicMs)throw fail('V03_CLOCK_DEADLINE');
  return mapped;
 }
 const mapping=Object.freeze({
  binding:()=>proof,
  uncertaintyMs:()=>proof.uncertaintyMs,
  mapDeadline,
  mapInterval(interval){
   if(!keys(interval,'startedAtMs,deadlineMs')||!Number.isSafeInteger(interval.startedAtMs)
    ||interval.startedAtMs<sent||interval.startedAtMs>=interval.deadlineMs)throw fail('V03_CLOCK_INTERVAL');
   return Object.freeze({startedAtMs:interval.startedAtMs+lower,deadlineMs:mapDeadline(interval.deadlineMs)});
  },
  mapRetirementInterval(kind){
   if(!['diagnosticControllerJoinMs','diagnosticLostReplyMs','diagnosticCleanupMs',
     'listingsRetirementMs','listingsCleanupMs'].includes(kind)||!owner.isRevoked())throw fail('V03_CLOCK_RETIREMENT');
   // This is not general mapping authority after revocation: only the actual
   // parent's currently active fixed retirement phase can supply endpoints.
   const window=owner.phaseWindow(kind),signal=owner.phaseSignal(kind);
   signal.throwIfAborted();
   if(window.kind!==kind||!Number.isSafeInteger(window.startedAtMs)||window.startedAtMs<sent
     ||!Number.isSafeInteger(window.deadlineMs)||window.deadlineMs<=owner.nowMs()
     ||window.startedAtMs>=window.deadlineMs||window.deadlineMs>binding.expiresAtMs)
    throw fail('V03_CLOCK_RETIREMENT');
   return Object.freeze({startedAtMs:window.startedAtMs+lower,deadlineMs:window.deadlineMs+lower});
  }
 });
 mappings.set(mapping,{owner,receipt});return mapping;
}
function assertGuestClockMapping(mapping,owner){
 const state=mappings.get(mapping);
 if(!state||state.owner!==owner)throw fail('V03_CLOCK_MAPPING_REQUIRED');
 if(owner.isRevoked())throw fail('V03_CLOCK_REVOKED');
 return mapping;
}
async function sampleGuestClock(options){
 if(!keys(options,'owner,root,expectedClockSha256,expectedDriverSha256,expectedPythonSha256'))throw fail('V03_CLOCK_OPTIONS');
 const owner=require('./ownedV03PrivateExecutors').assertCombinedOwner(options.owner);
 const window=owner.phaseWindow('diagnosticBuildMs'),signal=owner.phaseSignal('diagnosticBuildMs');
 if(owner.isRevoked())throw fail('V03_CLOCK_REVOKED');
 const root=path.resolve(__dirname,'../..');
 if(options.root!==root||await fs.realpath(root)!==root)throw fail('V03_CLOCK_ROOT');
 for(const name of ['expectedClockSha256','expectedDriverSha256','expectedPythonSha256'])
  if(! /^[a-f0-9]{64}$/.test(options[name]||''))throw fail('V03_CLOCK_SOURCE_PIN');
 const python=await fs.realpath('/opt/homebrew/bin/python3');
 for(const [file,expected,maximum] of [[__filename,options.expectedClockSha256,1024**2],
  [path.join(__dirname,'ownedSystemConfigPhaseDriver.js'),options.expectedDriverSha256,1024**2],
  [python,options.expectedPythonSha256,64*1024**2],
  ...Object.entries(driver.DEPS).map(([name,digest])=>[path.join(__dirname,name+'.py'),digest,1024**2])])
  if(sha(await readBounded(file,maximum))!==expected)throw fail('V03_CLOCK_SOURCE_CHANGED');
 const binding=owner.binding(),directory=path.join(root,'tasks/tmp','v03-clock-'+binding.runId);
 if(await fs.realpath(path.dirname(directory))!==path.dirname(directory))throw fail('V03_CLOCK_DIRECTORY');
 signal.throwIfAborted();await fs.mkdir(directory,{mode:0o700});
 const files={},handles=[];let primary,result;
 try{
  for(const name of ['journal','stdout','stderr','input']){
   const fd=await fs.open(path.join(directory,name),native.constants.O_RDWR|native.constants.O_CREAT
    |native.constants.O_EXCL|native.constants.O_NOFOLLOW,0o600);
   handles.push(fd);files[name]=fd;
  }
  await files.input.sync();
  const parent=await fs.open(directory,native.constants.O_RDONLY|native.constants.O_DIRECTORY|native.constants.O_NOFOLLOW);
  let parentFailure;
  try{await parent.sync();}catch(error){parentFailure=error;}
  finally{try{await parent.close();}catch(error){parentFailure=retainCloseDebt(parentFailure,error,'V03_CLOCK_DIRECTORY_CLOSE');}}
  if(parentFailure)throw parentFailure;
  const command='/usr/bin/python3 -I -S -B -c '+quote(GUEST)+' '+binding.runId+' '+binding.planSha256;
  const conf={root,runId:binding.runId,guest:'/var/tmp/dvaia-v23-build-'+binding.runId,base:'',
   phase:PHASE,command,commandSha256:sha(command),deps:driver.DEPS,expectedMux:null,
   inputPath:path.join(directory,'input'),inputSha256:sha(''),remoteSeconds:2,outputLimit:1024};
  signal.throwIfAborted();
  if(owner.isRevoked()||owner.phaseWindow('diagnosticBuildMs')!==window||window.deadlineMs-owner.nowMs()<48000)
   throw fail('V03_CLOCK_PHASE');
  // All source verification and durable-file setup precede this bracket.
  const sent=owner.nowMs();
  const receipt=await driver.executePython(conf,files,{python,signal});
  const received=owner.nowMs();
  driver.validateReceipt(receipt,PHASE);
  if(receipt.code!==0||receipt.failure!==null||!receipt.muxUnchanged||!driver.localRetired(receipt))
   throw fail('V03_CLOCK_CONTROLLER_UNPROVEN');
  const output=await readBounded(path.join(directory,'stdout'),1024);
  const stderr=await readBounded(path.join(directory,'stderr'),65536);
  if(output.length!==receipt.stdout.bytes||sha(output)!==receipt.stdout.sha256
   ||stderr.length!==receipt.stderr.bytes||sha(stderr)!==receipt.stderr.sha256)throw fail('V03_CLOCK_OUTPUT_CHANGED');
  signal.throwIfAborted();if(owner.isRevoked())throw fail('V03_CLOCK_REVOKED');
  result=mappingFor(owner,JSON.parse(output.toString('utf8')),sent,received,receipt);
 }catch(error){primary=error;}
 finally{
  const failures=[];
  for(const fd of handles)try{await fd.close();}catch{failures.push('V03_CLOCK_FILE_CLOSE');}
  if(failures.length){primary ||= fail('V03_CLOCK_FILE_CLOSE');primary.cleanupDebt=true;
   primary.clockCleanupErrors=[...(primary.clockCleanupErrors||[]),...failures];}
 }
 if(primary)throw primary;
 return result;
}
module.exports={sampleGuestClock,assertGuestClockMapping};
