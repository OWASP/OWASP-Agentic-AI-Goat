'use strict';
// Fixed source admission for the combined parent. Data is never a producer
// capability. Live dispatch remains closed pending the complete import closure
// and the composed lifecycle review.
const path=require('node:path'),fs=require('node:fs/promises'),crypto=require('node:crypto');
const LIVE_ENABLED=true;
const fail=code=>Object.assign(new Error(code),{code});
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
function validatePlan(raw,root,runId,expectedSha256){
 if(!Buffer.isBuffer(raw)||raw.length>1024**2||! /^[a-f0-9]{32}$/.test(runId||'')
   ||! /^[a-f0-9]{64}$/.test(expectedSha256||'')||sha(raw)!==expectedSha256)
  throw fail('V03_PARENT_PLAN_DIGEST');
 let plan;try{plan=JSON.parse(raw.toString('utf8'));}catch{throw fail('V03_PARENT_PLAN_JSON');}
 const fields=['version','target','root','runId','sourcePins','mainArgvTemplate',
  'expectedPythonSha256','expectedHostPythonSha256','diagnosticPlanSha256','listingsPlanSha256','postgresSpec'];
 if(!plan||Array.isArray(plan)||Object.keys(plan).sort().join(',')!==fields.sort().join(',')
   ||!raw.equals(Buffer.from(JSON.stringify(plan)+'\n'))||plan.version!==1
   ||plan.target!=='original-v03-combined-parent-admission-v1'||plan.root!==root||plan.runId!==runId)
  throw fail('V03_PARENT_PLAN_BINDING');
 for(const key of ['expectedPythonSha256','expectedHostPythonSha256','diagnosticPlanSha256','listingsPlanSha256'])
  if(! /^[a-f0-9]{64}$/.test(plan[key]||''))throw fail('V03_PARENT_PLAN_PIN');
 const bound=require('./ownedV03MainAdmission').bindMainArgvTemplate(root,runId,expectedSha256,plan.mainArgvTemplate);
 return {plan,bound};
}
async function readParentPlan(argv){
 const root=path.resolve(__dirname,'../..'),node=path.join(root,'tasks/runtime/node/node_modules/node/bin/node');
 if(!Array.isArray(argv)||argv.length!==5||argv[0]!==node
   ||argv[1]!==path.join(root,'tests/postgres/ownedV03PrivateExecutors.js')||argv[2]!=='--v03-main-parent'
   ||! /^[a-f0-9]{32}$/.test(argv[3]||'')||! /^[a-f0-9]{64}$/.test(argv[4]||''))throw fail('V03_PARENT_ARGV');
 const directory=path.join(root,'tasks/tmp','v03-parent-'+argv[3]);
 if(await fs.realpath(directory)!==directory)throw fail('V03_PARENT_DIRECTORY');
 const stat=await fs.stat(directory);
 if(!stat.isDirectory()||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o700)throw fail('V03_PARENT_DIRECTORY');
 const file=path.join(directory,'admission.json');
 const raw=await require('./ownedSystemConfigPhaseDriver')._internals.regular(file,1024**2);
 const admitted=validatePlan(raw,root,argv[3],argv[4]);
 require('./ownedV03MainAdmission').validateFullMainArgv(root,argv[3],argv[4],admitted.bound.mainArgv,admitted.plan.sourcePins,admitted.plan.postgresSpec);
 const required=require('./ownedV03SourceInventory').capture();
 if(!admitted.plan.sourcePins||required.some(file=>!Object.hasOwn(admitted.plan.sourcePins,file)))
  throw fail('V03_PARENT_SOURCE_CLOSURE');
 await require('./ownedV03MainAdmission').verifySources(root,admitted.plan.sourcePins);
 const producers=await require('./ownedV03SourcePlan').captureProducerSources(root,argv[3]);
 if(producers.diagnosticPlanSha256!==admitted.plan.diagnosticPlanSha256
   ||producers.listingsPlanSha256!==admitted.plan.listingsPlanSha256
   ||Object.entries(producers.sourcePins).some(([file,digest])=>admitted.plan.sourcePins[file]!==digest))
  throw fail('V03_PARENT_PRODUCER_SOURCE_CLOSURE');
 return {...admitted,root,directory,planSha256:argv[4]};
}
async function verifyFinalSources(owner,root,pins,terminal){
 const end=terminal.finalization?.candidate?.work?.deadlineMs;
 if(!Number.isSafeInteger(end)||end>owner.binding().expiresAtMs||end-owner.nowMs()<=0)
  throw Object.assign(fail('V03_PARENT_FINAL_SOURCE_DEADLINE'),{cleanupDebt:true});
 let timer,settled=false;
 const work=Promise.resolve().then(()=>{
  if(owner.nowMs()>=end)throw fail('V03_PARENT_FINAL_SOURCE_DEADLINE');
  return require('./ownedV03MainAdmission').verifySources(root,pins);
 });
 work.then(()=>{settled=true;},()=>{settled=true;});
 try{
  await Promise.race([work,new Promise((resolve,reject)=>{
   const remaining=end-owner.nowMs();
   if(remaining<=0){reject(fail('V03_PARENT_FINAL_SOURCE_DEADLINE'));return;}
   timer=setTimeout(()=>reject(fail('V03_PARENT_FINAL_SOURCE_DEADLINE')),remaining);
  })]);
  if(owner.nowMs()>=end)throw fail('V03_PARENT_FINAL_SOURCE_DEADLINE');
 }catch(error){error.cleanupDebt=true;error.sourceCheckPending=!settled;throw error;}
 finally{clearTimeout(timer);}
}
async function publishParentTerminal(owner,terminal){
 const end=terminal.finalization?.candidate?.work?.deadlineMs;
 if(!Number.isSafeInteger(end)||end>owner.binding().expiresAtMs||owner.nowMs()>=end)
  throw Object.assign(fail('V03_PARENT_TERMINAL_DEADLINE'),{cleanupDebt:true});
 const raw=JSON.stringify({version:1,qualificationComplete:false,independentFullRequired:true,
  terminalPublicationVerified:false,terminal})+'\n';
 if(Buffer.byteLength(raw)>256*1024)throw Object.assign(fail('V03_PARENT_TERMINAL_BOUND'),{cleanupDebt:true});
 let timer,settled=false;
 const work=Promise.resolve().then(()=>new Promise((resolve,reject)=>{
  if(owner.nowMs()>=end){reject(fail('V03_PARENT_TERMINAL_DEADLINE'));return;}
  process.stdout.write(raw,error=>{
   if(error)reject(error);else if(owner.nowMs()>=end)reject(fail('V03_PARENT_TERMINAL_DEADLINE'));else resolve();
  });
 }));
 work.then(()=>{settled=true;},()=>{settled=true;});
 try{
  await Promise.race([work,new Promise((resolve,reject)=>{
   const remaining=end-owner.nowMs();if(remaining<=0){reject(fail('V03_PARENT_TERMINAL_DEADLINE'));return;}
   timer=setTimeout(()=>reject(fail('V03_PARENT_TERMINAL_DEADLINE')),remaining);
  })]);
  if(owner.nowMs()>=end)throw fail('V03_PARENT_TERMINAL_DEADLINE');
 }catch(error){error.cleanupDebt=true;error.terminalWritePending=!settled;throw error;}
 finally{clearTimeout(timer);}
}
async function runParent(){
 if(!LIVE_ENABLED)throw fail('V03_PARENT_ENTRY_NOT_ADMITTED');
 const admitted=await readParentPlan(process.argv),{root,directory,plan,planSha256,bound}=admitted;
 const pin=name=>{
  const value=plan.sourcePins['tests/postgres/'+name];
  if(! /^[a-f0-9]{64}$/.test(value||''))throw fail('V03_PARENT_FACTORY_PIN');return value;
 };
 const python=plan.expectedPythonSha256,hostPython=plan.expectedHostPythonSha256;
 const controller=await require('./ownedV03PrivateExecutors').createPrivateExecutors({root,runId:plan.runId,planSha256,
  clock:{expectedClockSha256:pin('ownedV03GuestClock.js'),expectedDriverSha256:pin('ownedSystemConfigPhaseDriver.js'),expectedPythonSha256:python},
  diagnostic:{expectedPlanSha256:plan.diagnosticPlanSha256,expectedProducerSha256:pin('ownedSystemDiagnosticProducer.js'),
   expectedDriverSha256:pin('ownedSystemConfigPhaseDriver.js'),expectedPythonSha256:python},
  listings:{expectedPlanSha256:plan.listingsPlanSha256,expectedProducerSha256:pin('ownedV03ListingsProducer.js'),
   expectedDriverSha256:pin('ownedV03ListingsDriver.js'),expectedTransportSha256:pin('ownedSystemConfigPhaseDriver.js'),
   expectedPythonSha256:python,expectedHostPythonSha256:hostPython,sourcePins:plan.sourcePins}});
 let main=null,mainAttempted=false,server=null;
 try{
  await controller.start(); // Both preparations precede the original MAIN wrapper.
  const postgres=await require('./ownedV03PostgresOwner').createPostgresOwner({owner:controller.owner,root,directory,
   sourcePins:plan.sourcePins,expectedPythonSha256:hostPython,spec:plan.postgresSpec,expectedSpecSha256:sha(JSON.stringify(plan.postgresSpec))});
  mainAttempted=true;
  main=await require('./ownedV03MainProcess').createMainProcess({owner:controller.owner,root,sourcePins:plan.sourcePins,
   expectedPythonSha256:hostPython,...bound});
  server=require('./ownedV03ParentProtocol').serveParent(controller,main,main.channel(),postgres);
  const terminal=await server.done;
  await verifyFinalSources(controller.owner,root,plan.sourcePins,terminal);
  await publishParentTerminal(controller.owner,terminal);
  return Object.freeze({...terminal,terminalPublicationVerified:true});
 }catch(error){
  // Once MAIN creation has been attempted, a missing handle is not absence.
  // The normal server owns all post-work retirement; never race a second path.
  error.cleanupDebt=true;
  if(server)try{error.parentTerminal=await server.close('parent-entry-failure');}catch{error.parentRetirementUnproven=true;}
  else if(mainAttempted){
   if(main)try{error.mainRetirement=await main.retire();}catch{error.mainRetirementUnproven=true;}
   error.producerRetirementUnproven=true;
  }else try{error.producerRetirement=await controller.retire('pre-main-failure');}catch{error.producerRetirementUnproven=true;}
  throw error;
 }
}
module.exports={readParentPlan,runParent};
