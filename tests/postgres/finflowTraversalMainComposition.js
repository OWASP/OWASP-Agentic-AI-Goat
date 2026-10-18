'use strict';
// Source-only composition seam, NOT a standalone launcher. The future reviewed
// parent/entry must admit exact two-store ownership and install the socket fence
// before supplying pools, transport and v6-capable bindWire. No resources on import.
const assert=require('node:assert/strict'),path=require('node:path');
async function runOwned({pools,transport,bindWire,ports,evidenceRoot,targetRoot,persist}){
 assert.equal(pools.length,4);assert.equal(typeof bindWire,'function');assert.equal(typeof persist,'function');
 const [i,im,f,fm]=pools,identityApi=require('../../server/database/postgres/identityRepository');await identityApi.initializeIdentityRepository(i,im);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);await require('../../server/database/postgres/sensitiveInfoWorkshopDb').createFinflowWorkshopDb(f).initialize(fm);
 const identity=identityApi.createIdentityRepository(i),progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(i),adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
 const users={},sessions={};for(const who of ['owner','sibling']){users[who]=await identity.createUser({username:'traversal-'+who,email:'traversal-'+who+'@fixture.invalid',passwordHash:await require('bcryptjs').hash(require('node:crypto').randomUUID(),4)});sessions[who]=await adapter.createSession(await identity.findCredentialById(users[who].id),{get:()=>null,ip:'127.0.0.1'});}
 const config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(i);await config.setExerciseVisibility('sensitive_info_disclosure',true,users.owner.id);for(const item of require('../fixtures/finflowTraversalQualification').CASES)await config.setObjectiveVisibility('sensitive_info_disclosure',item.id,true,users.owner.id);
 const express=require('express'),app=express();app.use(express.json({limit:'128kb'}));const auth=require('../../server/routes/auth');app.use('/api/auth',auth);app.use('/api/workshop/sensitive-info',require('../../server/routes/sensitiveInfoWorkshop'));let server;const retained=[];
 try{server=await new Promise((resolve,reject)=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));s.once('error',reject);});ports.add(server.address().port);const base='http://127.0.0.1:'+server.address().port+'/api/workshop/sensitive-info';
  async function request(who,route,body,method='POST'){const r=await fetch(base+route,{method,headers:{authorization:'Bearer '+sessions[who].token,'content-type':'application/json'},...(method==='POST'?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(route==='/chat'?125000:15000)});assert.equal(r.status,200);return r.json();}
  const checks=require('../fixtures/finflowTraversalNativeChecks').createChecks({identityPool:i,finflowPool:f,owner:users.owner,sibling:users.sibling,progress,request,transport,targetRoot,bindWire,save:async capture=>{const index=retained.findIndex(x=>x.runId===capture.runId);if(index<0)retained.push(capture);else retained[index]=capture;require('../fixtures/boundedJsonArtifact').saveBounded(path.join(evidenceRoot,'canonical-traversal-evidence.json'),retained);}});
  const result=await require('../fixtures/finflowTraversalQualification').qualify({...checks,persist});transport.assertComplete();return result;
 }finally{const outcome=await require('../fixtures/secureshopAnalyticsBrowserOwner').settleOwnership([['http',()=>server&&new Promise((resolve,reject)=>{server.close(e=>e?reject(e):resolve());server.closeAllConnections();})],['auth',()=>auth.close()]],10000);assert(outcome.every(x=>x.status==='fulfilled'),'Traversal route cleanup unsettled');}
}
module.exports={runOwned};
if(require.main===module){process.stderr.write('TRAVERSAL_DIRECT_ENTRY_NOT_ADMITTED\n');process.exitCode=1;}
