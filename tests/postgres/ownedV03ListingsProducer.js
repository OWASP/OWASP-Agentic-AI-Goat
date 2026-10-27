'use strict';
// Fixed concrete build/runtime owner. Caller JSON cannot create this capability.
const crypto=require('node:crypto');
const drivers=require('./ownedV03ListingsDriver');
const producers=new WeakMap();
const fail=code=>Object.assign(new Error(code),{code});
function assertListingsProducer(value){if(!producers.has(value))throw fail('V03_LISTINGS_PRODUCER_REQUIRED');return value;}
function createListingsProducer(options){
 if(!options||Object.keys(options).sort().join(',')!=='combinedOwner,expectedDriverSha256,expectedHostPythonSha256,expectedPlanSha256,expectedProducerSha256,expectedPythonSha256,expectedTransportSha256,parentRunId,root,runId,sourcePins')throw fail('V03_LISTINGS_PRODUCER_OPTIONS');
 const owner=require('./ownedV03PrivateExecutors').assertCombinedOwner(options.combinedOwner),binding=owner.producerBinding('listings');
 if(options.runId!==binding.runId||options.parentRunId!==binding.parentRunId||owner.isRevoked())throw fail('V03_LISTINGS_PRODUCER_BINDING');
 for(const key of ['expectedDriverSha256','expectedHostPythonSha256','expectedPlanSha256','expectedProducerSha256','expectedPythonSha256','expectedTransportSha256'])
  if(!/^[a-f0-9]{64}$/.test(options[key]||''))throw fail('V03_LISTINGS_PRODUCER_PIN');
 let stage='new',driver=null,primary=null,retirement=null,joined=false;
 const active=()=>{if(owner.isRevoked()||primary)throw fail('V03_LISTINGS_PRODUCER_INACTIVE');};
 const attempt=async operation=>{try{return await operation();}catch(error){primary ||= error;stage='failed';throw error;}};
 const value=Object.freeze({
  async prepare(){
   active();if(stage!=='new')throw fail('V03_LISTINGS_PREPARE_ONCE');stage='preparing';
   return attempt(async()=>{
    try{
     const bytes=await require('./ownedSystemConfigPhaseDriver')._internals.regular(__filename,131072);
     if(crypto.createHash('sha256').update(bytes).digest('hex')!==options.expectedProducerSha256)throw fail('V03_LISTINGS_PRODUCER_SOURCE');
     driver=await drivers.createListingsDriver({root:options.root,runId:options.runId,parentRunId:options.parentRunId,combinedOwner:owner,
      expectedPlanSha256:options.expectedPlanSha256,expectedDriverSha256:options.expectedDriverSha256,
      expectedTransportSha256:options.expectedTransportSha256,expectedPythonSha256:options.expectedPythonSha256,
      expectedHostPythonSha256:options.expectedHostPythonSha256});
     drivers.assertListingsDriver(driver);
    }catch(error){error.cleanupDebt=true;throw error;}
    const result=await driver.prepare();active();stage='built';return result;
   });
  },
  async settle(){active();if(stage!=='built')throw fail('V03_LISTINGS_SETTLE_ORDER');return attempt(async()=>{
   const result=await driver.settle();active();stage='prepared';return result;
  });},
  async start(){active();if(stage!=='prepared')throw fail('V03_LISTINGS_START_ORDER');return attempt(async()=>{
   const result=await driver.startRuntime(options.sourcePins);active();stage='ready';return result;
  });},
  async claimCohort(){active();if(stage!=='ready')throw fail('V03_LISTINGS_CLAIM_ORDER');return attempt(async()=>{
   const result=await driver.claimCohort();active();stage='claimed';return result;
  });},
  async join(){
   if(!owner.isRevoked()||joined)throw fail('V03_LISTINGS_JOIN_ORDER');owner.phaseWindow('listingsRetirementMs');
   const result=driver?await driver.join():{localRetired:!primary?.cleanupDebt};
   if(result.localRetired!==true)throw fail('V03_LISTINGS_JOIN_UNPROVEN');joined=true;return result;
  },
  retire(){
   if(retirement)return retirement;
   if(!owner.isRevoked()||!joined)throw fail('V03_LISTINGS_RETIREMENT_ORDER');owner.phaseWindow('listingsCleanupMs');
   retirement=(async()=>{
    const receipt=driver?await driver.retire():null;
    if(driver?receipt?.cleanupVerified!==true||receipt.resourceAbsenceProven!==true:primary?.cleanupDebt)
     throw Object.assign(fail('V03_LISTINGS_RETIREMENT_UNPROVEN'),{retirementUnproven:true,receipt});
    stage='closed';return {cleanupVerified:true,resourceAbsenceProven:true};
   })();return retirement;
  },
  publicStatus:()=>Object.freeze({stage,cleanupDebt:!!primary?.cleanupDebt})
 });producers.set(value,{owner});return value;
}
module.exports={createListingsProducer,assertListingsProducer};
