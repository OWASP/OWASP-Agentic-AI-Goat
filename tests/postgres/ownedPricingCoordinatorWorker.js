'use strict';
// Fixed child protocol; exact owner/source admission precedes any transport.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const api=require('./ownedPricingBuildAdapter');
const lease=require('./ownedPricingRuntimeLease');
const LIVE_ENABLED=true;
const V34_LIVE_ENABLED=true;
const V25_LIVE_ENABLED=true;
const fail=code=>Object.assign(new Error(code),{code});
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
// Work cannot spend the retirement journal's independently reserved capacity.
// Failed writes retain their partial file but never consume committed capacity.
function journal(directory,{io=fs}={}){
 let ordinal=0,retiring=false,firstFailure=null;const used={work:{count:0,bytes:0},retirement:{count:0,bytes:0}},reserved={work:{count:0,bytes:0},retirement:{count:0,bytes:0}};
 const record=async(name,value)=>{
  const bucket=retiring?'retirement':'work',limit=retiring?{count:37,bytes:8*1024**2}:{count:94,bytes:24*1024**2};
  const state=used[bucket],held=reserved[bucket];
  try{
   const raw=Buffer.from(JSON.stringify({name,value})+'\n');
   if(held.count>=limit.count||raw.length>2*1024**2||held.bytes+raw.length>limit.bytes||ordinal>=131)throw fail('PRICING_JOURNAL_LIMIT');
   // Partial failed files remain evidence and still charge the physical bound.
   held.count++;held.bytes+=raw.length;
   const file=path.join(directory,'builder-'+String(++ordinal).padStart(3,'0')+'.json');
   const fd=io.openSync(file,'wx',0o600);let error;
   try{let n=0;while(n<raw.length){const k=io.writeSync(fd,raw,n,raw.length-n);if(k<=0)throw fail('PRICING_JOURNAL_WRITE');n+=k;}io.fsyncSync(fd);}catch(e){error=e;}
   try{io.closeSync(fd);}catch(e){error ||= e;}
   if(error)throw error;state.count++;state.bytes+=raw.length;
  }catch(e){firstFailure ||= e;throw e;}
 };
 record.beginRetirement=()=>{retiring=true;};
 record.status=()=>({used:JSON.parse(JSON.stringify(used)),reserved:JSON.parse(JSON.stringify(reserved)),failure:firstFailure});
 return record;
}
function channel(input,output,deadline,now=()=>Number(process.hrtime.bigint())/1e6){
 let buffered=Buffer.alloc(0),total=0,ended=false,pending=null,writing=null;const queue=[];
 const deliver=()=>{if(pending&&(queue.length||ended)){const p=pending;pending=null;clearTimeout(p.timer);queue.length?p.resolve(queue.shift()):p.reject(fail('PRICING_OWNER_EOF'));}};
 const onData=b=>{total+=b.length;if(total>262144){ended=true;queue.length=0;input.pause();deliver();return;}
  buffered=Buffer.concat([buffered,b]);let i;while((i=buffered.indexOf(10))>=0){const raw=buffered.subarray(0,i);buffered=buffered.subarray(i+1);
   try{if(raw.length>65536||queue.length>=4)throw Error();queue.push(JSON.parse(raw));}catch{ended=true;queue.length=0;input.pause();break;}}
  if(buffered.length>65536){ended=true;queue.length=0;input.pause();}deliver();};
 const end=()=>{ended=true;queue.length=0;deliver();};input.on('data',onData);input.on('end',end);input.on('error',end);
 let outputFailed=false;const outputEnd=()=>{outputFailed=true;if(writing)writing(fail('PRICING_IPC_OUTPUT_CLOSED'));};
 output.on('error',outputEnd);output.on('close',outputEnd);
 return {
  read(){if(pending)throw fail('PRICING_IPC_CONCURRENT');return new Promise((resolve,reject)=>{const ms=deadline-now();if(ms<=0)return reject(fail('PRICING_IPC_DEADLINE'));pending={resolve,reject,timer:setTimeout(()=>{pending=null;reject(fail('PRICING_IPC_DEADLINE'));},ms)};deliver();});},
  send(value){const raw=JSON.stringify(value)+'\n';if(Buffer.byteLength(raw)>65536||writing)throw fail('PRICING_IPC_OUTPUT');return new Promise((resolve,reject)=>{
   const ms=deadline-now();if(outputFailed||ms<=0)return reject(fail('PRICING_IPC_OUTPUT_DEADLINE'));
   let done=false;const timer=setTimeout(()=>finish(fail('PRICING_IPC_OUTPUT_DEADLINE')),ms);
   const finish=e=>{if(done)return;done=true;clearTimeout(timer);writing=null;const failure=e||(now()>=deadline?fail('PRICING_IPC_OUTPUT_DEADLINE'):null);failure?reject(failure):resolve();};writing=finish;
   try{output.write(raw,e=>finish(e));}catch(e){finish(e);}
  });},
  close(){input.off('data',onData);input.off('end',end);input.off('error',end);input.pause();if(writing)writing(fail('PRICING_IPC_CLOSED'));output.off('error',outputEnd);output.off('close',outputEnd);if(pending){clearTimeout(pending.timer);pending.reject(fail('PRICING_IPC_CLOSED'));pending=null;}},
 };
}
async function execute(io,{profile='v33',makePlan=api.pricingBuildPlan,makeTransport=api._internals.createFixedTransport,build=api._internals.runControlledBuild,now=()=>Number(process.hrtime.bigint())/1e6}={}){
 lease.profile(profile);
 const root=path.resolve(__dirname,'../..'),admission=await io.read();
 const paired=profile!=='v33',version=paired?2:1;
 if(!exact(admission,['verb','version','runId','ownerId','ownerPlanSha256','sources','packageSha256',...(paired?['consumerProfile']:[])])||admission.verb!=='admit'||admission.version!==version||paired&&admission.consumerProfile!==profile||!/^[a-f0-9]{32}$/.test(admission.runId)||!/^[a-f0-9]{64}$/.test(admission.ownerPlanSha256))throw fail('PRICING_WORKER_ADMISSION');
 const plan=await makePlan(root,admission.runId,profile),nodePlanSha256=hash(JSON.stringify(plan));
 if((plan.inputs.consumerProfile??'v33')!==profile)throw fail('PRICING_WORKER_PROFILE');
 if(admission.packageSha256!==plan.inputs.packageDigest||Object.entries(plan.inputs.sources).some(([k,v])=>admission.sources?.[k]!==v))throw fail('PRICING_WORKER_SOURCE');
 const binding={version,runId:admission.runId,ownerPlanSha256:admission.ownerPlanSha256,nodePlanSha256,...(paired?{consumerProfile:profile}:{})};
 const next=async verb=>{const m=await io.read();const extra=verb==='publish'?['token']:verb==='retire'?['retired','remainingMs']:[];if(!exact(m,[...Object.keys(binding),'verb',...extra])||m.verb!==verb||Object.entries(binding).some(([k,v])=>m[k]!==v))throw fail('PRICING_IPC_ORDER');return m;};
 await io.send({...binding,verb:'ready',packageSha256:plan.inputs.packageDigest,sources:plan.inputs.sources});await next('build');
 const directory=path.join(root,'tasks/qualification','pricing-private-'+admission.runId);
 const stat=fs.lstatSync(directory);if(fs.realpathSync(directory)!==directory||!stat.isDirectory()||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o700)throw fail('PRICING_WORKER_DIRECTORY');
 const record=journal(directory);
 const transport=makeTransport(plan,record);let retirement=null,result,primary;
 try{result=await build(plan,{phase:transport.phase,record,
  consume:async observed=>{
   await io.send({...binding,verb:'image',observed});const publication=await next('publish');
   const published=JSON.parse(await transport.phase('publishHandoff',{publication:{ownerId:admission.ownerId,observed,token:publication.token}}));
   if(published.version!==1||published.runId!==admission.runId||published.published!==true||published.runtimeStarted!==false)throw fail('PRICING_PUBLICATION_REPLY');
   await io.send({...binding,verb:'published'});await next('consumer-retired');
   retirement=true;
  },beforeRetirement:async()=>{
   record.beginRetirement();
   if(!retirement){await io.send({...binding,verb:'retirement-request'});await next('consumer-retired');}
   const requestedAt=now();await io.send({...binding,verb:'retirement-ready'});
   retirement=await next('retire');
   if(retirement.retired!==true||!Number.isSafeInteger(retirement.remainingMs)||retirement.remainingMs<=0||retirement.remainingMs>600000)throw fail('PRICING_CONSUMER_RETIREMENT_UNPROVEN');
   const remaining=requestedAt+retirement.remainingMs-now();
   if(!Number.isFinite(remaining)||remaining<=0)throw fail('PRICING_RETIREMENT_EXPIRED');
   transport.beginRetirement(retirement.remainingMs,requestedAt);
  }});
 }catch(e){primary=e;result=e.result||{cleanupVerified:false,failure:e.code||e.name};}
 finally{try{transport.close();}catch(e){primary ||= e;result={...result,cleanupVerified:false};}
  const journalFailure=record.status().failure;if(journalFailure){primary ||= journalFailure;result={...result,cleanupVerified:false,failure:result.failure||journalFailure.code||journalFailure.name,cleanupErrors:[...(result.cleanupErrors||[]),'PRICING_JOURNAL_INCOMPLETE']};}}
 await io.send({...binding,verb:'terminal',result});if(primary)throw primary;return result;
}
function ownerChannel(input,output,profile='v33',now=()=>Number(process.hrtime.bigint())/1e6){return channel(input,output,now()+lease.profile(profile).totalMs,now);}
// Reviewed retained compositions; exact private owner admission is mandatory.
async function main(enabled=LIVE_ENABLED,profile='v33'){
 lease.profile(profile);
 if(profile==='v25-manual'&&!V25_LIVE_ENABLED)throw fail('PRICING_WORKER_NOT_ADMITTED');
 if(!enabled||profile==='v34-browser'&&!V34_LIVE_ENABLED)throw fail('PRICING_WORKER_NOT_ADMITTED');
 const io=ownerChannel(process.stdin,process.stdout,profile);try{await execute(io,{profile});}finally{io.close();}
}
function entryProfile(args){
 if(args.length===0)return 'v33';
 if(args.length===1&&args[0]==='--v34-retained-session')return 'v34-browser';
 if(args.length===1&&args[0]==='--v25-manual-session')return 'v25-manual';
 throw fail('PRICING_WORKER_ARGUMENTS');
}
if(require.main===module)Promise.resolve().then(()=>main(LIVE_ENABLED,entryProfile(process.argv.slice(2)))).catch(()=>{process.exitCode=1;});
module.exports={LIVE_ENABLED,V34_LIVE_ENABLED,V25_LIVE_ENABLED,execute,channel,ownerChannel,main,entryProfile,journal};
