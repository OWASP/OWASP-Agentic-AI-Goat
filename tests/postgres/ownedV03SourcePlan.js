'use strict';
// Read-only source planning. No driver, lease, owner, image or process factory.
const path=require('node:path'),crypto=require('node:crypto');
const ROOT=path.resolve(__dirname,'../..');
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const fail=code=>Object.assign(new Error(code),{code});
function mergeSources(destination,source){
 if(!source||Object.getPrototypeOf(source)!==Object.prototype)throw fail('V03_PLAN_SOURCE_MAP');
 for(const [name,digest]of Object.entries(source)){
  if(name.startsWith('/')||name.split('/').some(part=>!part||part==='.'||part==='..')||! /^[a-f0-9]{64}$/.test(digest||''))
   throw fail('V03_PLAN_SOURCE_PIN');
  if(Object.hasOwn(destination,name)&&destination[name]!==digest)throw fail('V03_PLAN_SOURCE_CONFLICT');
  destination[name]=digest;
 }
}
async function captureProducerSources(root,parentRunId){
 if(arguments.length!==2||root!==ROOT||! /^[a-f0-9]{32}$/.test(parentRunId||''))throw fail('V03_SOURCE_PLAN_BINDING');
 const child=kind=>sha(parentRunId+':v03-'+kind).slice(0,32);
 const diagnostic=require('./ownedSystemDiagnosticBuildAdapter'),listings=require('./ownedMcpOriginalBuildAdapter');
 const diagnosticPlan=await diagnostic.diagnosticBuildPlan(root,child('diagnostic'));
 const listingsPlan=await listings.originalBuildPlan(root,child('listings'),{target:'listings-package',listingsMode:'v03-manager'});
 const sourcePins={};
 for(const map of [diagnosticPlan.helperHashes,diagnosticPlan.metadata.buildSources,listingsPlan.helperHashes,listingsPlan.buildSources])
  mergeSources(sourcePins,map);
 const read=require('./ownedV03MainAdmission')._internals.sourceBytes;
 const required=new Set([...require('./ownedV03SourceInventory').capture(),
  'tests/postgres/ownedV03SourcePlan.js','tests/ownedV03SourcePlan.test.js']);
 for(const name of required)mergeSources(sourcePins,{[name]:sha(await read(path.join(root,name),128*1024**2))});
 // Re-read every declared file after both actual plan factories and the full
 // union have been captured. One changed producer map never silently wins.
 await require('./ownedV03MainAdmission').verifySources(root,sourcePins);
 return Object.freeze({version:1,target:'original-v03-producer-source-union-v1',parentRunId,
  diagnosticRunId:child('diagnostic'),listingsRunId:child('listings'),
  diagnosticPlanSha256:diagnostic.planDigest(diagnosticPlan),listingsPlanSha256:listings.planDigest(listingsPlan),
  sourcePins:Object.freeze(Object.fromEntries(Object.entries(sourcePins).sort(([a],[b])=>a.localeCompare(b)))),
  executionApproved:false,qualificationComplete:false});
}
module.exports={captureProducerSources};
