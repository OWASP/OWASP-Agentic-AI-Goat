'use strict';
const path=require('node:path'),os=require('node:os');
const {Pool}=require('pg');
const {provision}=require('./analytics-target');
const {activate}=require('./analytics-activate');
const {readManagedAnalyticsConfiguration}=require('../../server/services/secureshopAnalyticsManagedConfiguration');
const {getOwnedAnalyticsProduction}=require('../../server/services/secureshopOwnedAnalyticsProduction');
const {assertAnalyticsRequestReadiness}=require('../../server/database/postgres/secureshopAnalyticsRequestReadiness');
const fail=code=>Object.assign(Error('Owned Analytics setup unavailable; existing data preserved'),{code});
function assertPrerequisites(environment,{fresh=false}={}){
 if(environment.SS_ENABLE!=='true'||environment.SS_BOUND_REVIEWS_ENABLED!=='true'||(!fresh&&(environment.PLATFORM_DATABASE_ENGINE!=='postgres'||environment.WORKSHOP_DATABASE_ENGINE!=='postgres'||!environment.SECURESHOP_AGENTS_DATABASE_URL)))throw fail('ANALYTICS_SETUP_PREREQUISITES');
}
async function setupOwnedAnalytics({requested=false,explicitActivation=false,root=path.resolve(__dirname,'../..'),homeDirectory=os.homedir(),environment=process.env,applicationEnvironment=environment,
 provisionService=provision,loadRuntime=getOwnedAnalyticsProduction,checkRequests=assertAnalyticsRequestReadiness,makePool=options=>new Pool(options)}={}){
 if(!requested)return {requested:false,activationEnabled:false};
 assertPrerequisites(applicationEnvironment);
 const options={root,homeDirectory,environment},prepared=await provisionService(options),record=await readManagedAnalyticsConfiguration(options);
 if(!record||prepared.containerId!==record.config.containerId)throw fail('ANALYTICS_SETUP_IDENTITY');
 const result=await activate({...options,expectedSha256:record.sha256,explicit:explicitActivation,fresh:prepared.created===true,assertReady:async()=>{
  const runtime=await loadRuntime(options);if(!runtime)throw fail('ANALYTICS_SETUP_IDENTITY');
  let pool;try{
   await runtime.assertReady();pool=makePool({connectionString:applicationEnvironment.SECURESHOP_AGENTS_DATABASE_URL,max:1,connectionTimeoutMillis:5000,idleTimeoutMillis:1000});
   await checkRequests(pool,{requiredVersion:2});
  }finally{try{if(pool)await pool.end();}finally{await runtime.close();}}
 }});
 return {requested:true,...result};
}
module.exports={setupOwnedAnalytics,assertPrerequisites};
