'use strict';
// No launch or standalone entry. The existing retained private-image owner
// supplies its real Listings lifetime; this module only exposes closed phases.
const {performance}=require('node:perf_hooks');
const {pairChannel}=require('./ownedMcpOriginalServiceProducer');
const fail=code=>Object.assign(new Error(code),{code,retirementUnproven:true});
const work=Object.freeze(['listingsProfileInstall','listingsManagerCreate','listingsManagerStart']);
const retirement=Object.freeze(['listingsManagerChannels','listingsManagerRetire','listingsProfileRetire']);

async function serveListingsPhases(socket,binding,lifetime,{now=()=>performance.now()}={}) {
  if(!binding||! /^[a-f0-9]{32}$/.test(binding.runId)||! /^[a-f0-9]{64}$/.test(binding.planSha256)
    ||!lifetime||typeof lifetime.runListingsPhase!=='function'||typeof lifetime.confirmRetired!=='function')throw fail('LISTINGS_ENDPOINT_ADMISSION');
  const channel=pairChannel(socket,binding),epoch=now();let sequence=0,workEnd,cleanupEnd,closed=false,pending=false;
  const check=end=>{if(closed||!Number.isFinite(end)||now()>=end)throw fail('LISTINGS_ENDPOINT_DEADLINE');};
  const duration=value=>{if(!Number.isSafeInteger(value)||value<1||value>600000)throw fail('LISTINGS_ENDPOINT_WINDOW');return value;};
  const read=async(op,keys,end)=>{
    check(end);const row=await channel.read(op,['sequence',...keys],end);check(end);
    if(row.sequence!==sequence)throw fail('LISTINGS_ENDPOINT_SEQUENCE');return row;
  };
  const send=async(op,fields,end)=>{check(end);await channel.send(op,{sequence,...fields},end);check(end);};
  const phase=async(name,end)=>{
    const row=await read('phase',['name','input','remainingMs'],end);
    if(row.name!==name)throw fail('LISTINGS_ENDPOINT_PHASE_ORDER');
    const cap=Math.min(end,now()+duration(row.remainingMs));check(cap);
    // The original lifetime owns cancellation and phase joining. Never detach
    // a timeout and then grant release while the phase is still running.
    pending=true;
    const operation=Promise.resolve().then(()=>{check(cap);return lifetime.runListingsPhase(name,row.input===null?undefined:row.input);});
    operation.finally(()=>{pending=false;}).catch(()=>{});
    let timer,output;
    try{
      output=await Promise.race([operation,new Promise((_,reject)=>{timer=setTimeout(()=>{
        lifetime.expireWork();reject(fail('LISTINGS_ENDPOINT_PHASE_UNJOINED'));
      },Math.max(0,cap-now()));})]);
    }finally{clearTimeout(timer);}
    check(cap);
    if(typeof output!=='string'||Buffer.byteLength(output)>8192)throw fail('LISTINGS_ENDPOINT_OUTPUT');
    await send('result',{name,output},cap);sequence++;
  };
  try{
    await send('hello',{},epoch+15000);
    const admitted=await read('admit',['remainingMs'],epoch+15000);
    workEnd=epoch+duration(admitted.remainingMs);check(workEnd);
    await send('admitted',{},workEnd);sequence++;
    for(const name of work)await phase(name,workEnd);
    const grant=await read('retirement',['remainingMs','deadlineOffsetMs'],workEnd+600000);
    if(!Number.isSafeInteger(grant.deadlineOffsetMs)||grant.deadlineOffsetMs<1||grant.deadlineOffsetMs>1200000)throw fail('LISTINGS_ENDPOINT_WINDOW');
    // Client epoch is observed AFTER this server's hello. Anchoring its offset
    // to our earlier epoch conservatively charges transit/queue delay, never
    // renews a window from the time a delayed message happens to arrive.
    cleanupEnd=Math.min(epoch+grant.deadlineOffsetMs,workEnd+600000,now()+duration(grant.remainingMs));check(cleanupEnd);
    await send('retirement-admitted',{},cleanupEnd);sequence++;
    for(const name of retirement)await phase(name,cleanupEnd);
    const confirm=await read('confirm',['remainingMs'],cleanupEnd);
    const end=Math.min(cleanupEnd,now()+duration(confirm.remainingMs));check(end);
    lifetime.assertOpen();lifetime.assertRetirementAdmission();check(end);
    if(pending)throw fail('LISTINGS_ENDPOINT_PENDING');
    lifetime.confirmRetired();
    check(end);await send('retired',{},end);sequence++;
    return {version:1,runId:binding.runId,retired:true,qualificationComplete:false};
  }catch(error){lifetime.expireWork();error.retirementUnproven=true;throw error;}
  finally{closed=true;channel.close();}
}
module.exports={serveListingsPhases};
