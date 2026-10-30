'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto'),{Pool}=require('pg');
const {migrate}=require('../../db/postgres/migrate');
const {qualifyListings}=require('../fixtures/secureshopListingsIntegratedNative');
const {createResponseLossProxy}=require('../fixtures/secureshopListingsResponseLossProxy');
(async()=>{
 assert.equal(process.env.LISTINGS_INTEGRATED_NATIVE,'1');const pools=[];let proxy;
 const pool=(label,role)=>{const u=new URL(process.env[`LISTINGS_${label}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_listings_[a-f0-9]+_/);const p=new Pool({connectionString:u.href,max:6,statement_timeout:10000});pools.push(p);return p;};
 try{
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('AGENTS','RUNTIME'),am=pool('AGENTS','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION'),review=pool('REVIEW','RUNTIME'),rm=pool('REVIEW','MIGRATION'),leases=pool('IDENTITY','RUNTIME');
 await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
 const canonicalMigrations=process.env.LISTINGS_CATALOG_CANDIDATE==='1'?await require('../fixtures/secureshopListingsCanonicalMigrations').qualifyCanonicalMigrations({agents,am,review,rm}):null;
 if(!canonicalMigrations){await migrate(am,'db/postgres/workshop-migrations/secureshop_agents');await migrate(rm,process.env.OWNED_LISTING_CANDIDATE_MIGRATIONS);}
 if(process.env.LISTINGS_PRODUCTION_ASSEMBLY==='1'){await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);if(process.env.LISTINGS_ACTUAL_GRADING==='1'){const all=require('../../server/services/secureshopListingsEvidence').LISTINGS_OBJECTIVES,ids=process.env.LISTINGS_ACTUAL_GRADING_BROWSER==='1'?all.slice(-1):all;const w=await im.query("UPDATE workshop_platform.exercises SET catalog_active=true,is_visible=true WHERE workshop_key='secureshop_agent_security'");assert.equal(w.rowCount,1);const o=await im.query("UPDATE workshop_platform.objectives SET catalog_active=true,is_enabled=true WHERE workshop_key='secureshop_agent_security' AND objective_id=ANY($1::text[])",[ids]);assert.equal(o.rowCount,ids.length);const active=await identity.query("SELECT objective_id FROM workshop_platform.objectives o JOIN workshop_platform.exercises w USING(workshop_key) WHERE o.workshop_key='secureshop_agent_security' AND o.objective_id=ANY($1::text[]) AND o.is_enabled AND o.catalog_active AND w.is_visible AND w.catalog_active",[ids]);assert.equal(active.rows.length,ids.length,'Exact disposable grading catalog must be active before any model call');}const result=await require('../fixtures/secureshopListingsProductionNative').qualifyProduction({identity,migration:im,leases,agents,commerce,review,actualGrading:process.env.LISTINGS_ACTUAL_GRADING==='1'});fs.writeFileSync(process.env.OWNED_LISTING_RESULT,JSON.stringify({...result,canonicalMigrations},null,2));if(process.env.LISTINGS_ACTUAL_GRADING==='1')assert.equal(result.status,'passed','Genuine grading observed a nonpassing result');return;}
 const configs={};for(const label of['A','B']){const origin=process.env['LISTINGS_EXECUTOR_'+label+'_ORIGIN'],token=process.env['LISTINGS_EXECUTOR_'+label+'_TOKEN'];const response=await fetch(origin+'/health',{headers:{authorization:'Bearer '+token}});assert.equal(response.status,200);const health=await response.json();configs[label]={origin,token,runtimeIdentity:health.identity,runtimeDigest:health.runtimeDigest,executorId:randomUUID()};}
 assert.notEqual(configs.A.runtimeIdentity,configs.B.runtimeIdentity);assert.equal(configs.A.runtimeDigest,configs.B.runtimeDigest);
 const deps={identity,leases,agents,commerce,review};
 if(process.env.LISTINGS_SAVED_EVIDENCE==='1'){
  const savedEvidence=await qualifyListings({...deps,executorConfiguration:configs.A,savedEvidence:true});
  fs.writeFileSync(process.env.OWNED_LISTING_RESULT,JSON.stringify({status:'passed',savedEvidence},null,2));return;
 }
 if(process.env.LISTINGS_ACTUAL8B==='1'){
  const evidencePath=path.join(process.env.LISTINGS_EVIDENCE_ROOT,'actual-model.json');
  const actual=await require('../fixtures/secureshopListingsActualProvider').createActualListingsProvider({maxCalls:10,writeEvidence:value=>fs.writeFileSync(evidencePath,JSON.stringify(value,null,2))});
  const result={status:'running',actual:true,cases:[],limitations:['No rendered browser proof','No canonicalJudge or objectivecredit qualification']};
  try{for(const action of['import','rewrite']){
   try{const value=await qualifyListings({...deps,executorConfiguration:configs[action==='import'?'A':'B'],actualProvider:actual.provider,actualAction:action});result.cases.push(value);}catch(error){result.cases.push({action,error:{code:error.code,name:error.name,message:error.message}});}
   fs.writeFileSync(process.env.OWNED_LISTING_RESULT,JSON.stringify(result,null,2));
  }}finally{actual.close();}
  result.actualHttpCalls=actual.evidence.httpCalls.length;result.status=result.cases.every(c=>c.operation?.state==='completed'&&(c.action!=='rewrite'||c.save))?'passed':'observed_negative';
  fs.writeFileSync(process.env.OWNED_LISTING_RESULT,JSON.stringify(result,null,2));assert.equal(result.status,'passed','actual model workflow not qualified');return;
 }
const baseline=await qualifyListings({...deps,executorConfiguration:configs.A});
 const other=await fetch(configs.B.origin+'/operations/'+baseline.request.request.operationId,{headers:{authorization:'Bearer '+configs.B.token}});assert.equal(other.status,404);
 proxy=await createResponseLossProxy(configs.A.origin);const recovered=await qualifyListings({...deps,executorConfiguration:{...configs.A,origin:proxy.origin},dropProxy:proxy});await proxy.close();proxy=null;
 const reset=await qualifyListings({...deps,executorConfiguration:configs.B,holdBeforePublish:async({admission,launches})=>{await launches.beginReset({...admission.scope,expectedGeneration:admission.scope.generation,idempotencyKey:randomUUID()});}});
 const transactionReset=await qualifyListings({...deps,executorConfiguration:configs.B,transactionResetRace:true});
 const report={status:'passed',actualModelCalls:0,baseline:{state:baseline.result.operation.state,controlledDecisions:baseline.controlledDecisions},recovery:{state:recovered.result.operation.state,executor:recovered.result.executor.state,resume:recovered.result.resume},reset:{noPublication:true},transactionReset,checks:['real persona authority four stores','real graph separate observe publish decisions','actual namespace HTTP and attestation','separate listener target receipt isolation','lost POST GET-only recovery','canonical beginReset during held decision prevents publication','sibling product preservation'],limitations:['controlled provider not actual model evidence','application not mounted']};fs.writeFileSync(process.env.OWNED_LISTING_RESULT,JSON.stringify(report,null,2));
 }catch(error){console.error('INTEGRATED_FAILURE',error.code||error.name,error.message);throw error;}finally{await proxy?.close();await Promise.all(pools.map(p=>p.end()));}
})().catch(error=>{console.error(error);process.exitCode=1;});
