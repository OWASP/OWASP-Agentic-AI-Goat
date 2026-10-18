'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createMailProduction,assertMailSchema,PRODUCTION_QUALIFIED}=require('../server/services/secureshopMailProduction');
function pool(mutate=x=>x){return {async query(sql,args){const rows=args?[...args[0]].map(name=>({name,ready:true})):[{messages_private:true,purpose_ready:true,cleanup_ready:true,browse_ready:true}];return {rows:mutate(rows,sql)};}};}
function fixture(){let revoked=false,reserved=0,provisioned=0;const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},context={scope,persona:{id:2,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
 const authority={capture(x){return {binding:{...x.scope,personaId:x.personaId,role:x.role,...x},async assertRemoteAdmission(){if(revoked)throw Error('revoked');}};}};
 const resetComposition={launches:{async assertCurrent(){if(revoked)throw Error('revoked');},async reservePersonaInboxTarget(){reserved++;return {targetId:randomUUID()};}},personaInbox:{repository:{async provision(){provisioned++;}}},cleanupAuthority:{async checkTarget(){}},conversations:{async getBoundSession(){},async acquireBoundSession(){},async getMessages(){return [];},async getTraceEvents(){return [];}},journal:{async claim(){},async complete(){},async markUncertain(){},async readBoundRequest(){}},runCoordinator:{async run(){throw Error('should not start');}}};
 const deps={enabled:true,identityPool:{async query(sql){return {rows:sql.includes('identity.secureshop_authority_owners')?[{realm:'shop',shop_tenant_id:randomUUID()}]:[]};}},agentsPool:pool(),resetComposition,personaAuthority:authority,personaRepository:{async listMailActors(scope){return this.listPersonas(scope);},async listPersonas(){return [{id:1,role:'customer',email:'customer@lab'},{id:2,role:'merchant',email:'merchant@lab'},{id:3,role:'admin',email:'admin@lab'}];}},provider:{async chat(){throw Error('no model');}},promptPolicyRepository:{async admitRunSnapshot(){}},toolPolicyRepository:{async admitTool(){}},assessmentDependencies:{personaBindings:{async capture(){}},receipts:{async beginEvaluation(){},async recordVerdict(){}},progress:{async getGeneration(){}},publicationModes:{async getEvaluationScope(){return {binding:{mode:'vuln'},async assertCurrent(){}};}},judge:async()=>{throw Error('no Judge');}},authenticatePersona(){}};
 return {deps,context,revoke(){revoked=true;},get reserved(){return reserved;},get provisioned(){return provisioned;}};
}

const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path'),{createRequire}=require('node:module');
function promotedProduction(){const file=path.resolve('server/services/secureshopMailProduction.js'),actual=createRequire(file),module={exports:{}};let browser;
 vm.runInNewContext(fs.readFileSync(file,'utf8'),{module,exports:module.exports,require(name){
 if(name==='./secureshopMailObjectiveReadiness')return {readMailObjectiveReadiness:async()=>Object.freeze({ss_mail_stored_browser_execution:true})};
 if(name==='./secureshopMailBrowserAssessment')return {createMailBrowserAssessment:deps=>{browser=deps.browserQualification;return {runAttempt:async()=>({completed:false})};}};
 return actual(name);},Object,Error,TypeError});return {create:module.exports.createMailProduction,browser:()=>browser};}
test('trusted factory stays cold until promoted readiness; close awaited and future use denied',async()=>{
 const f=fixture(),p=promotedProduction();let factories=0,calls=0,closed=0;
 const instance=await p.create({...f.deps,createBrowserQualification(){factories++;return {readComponent:()=>({}),qualifyMail:async()=>{calls++;return {};},qualifyInjection:async()=>({}),close:async()=>{await Promise.resolve();closed++;}};}});
 assert.equal(factories,0);assert.equal((await instance.application.readiness(f.context)).objectiveReadiness.ss_mail_stored_browser_execution,true);assert.equal(factories,1);assert.equal(calls,0);
 await p.browser().qualifyMail({});assert.equal(calls,1);await instance.close();assert.equal(closed,1);assert.throws(()=>p.browser().qualifyMail({}));
});
test('missing renderer remains unavailable without failing ordinary mail readiness',async()=>{
 const f=fixture(),p=promotedProduction();const instance=await p.create({...f.deps,createBrowserQualification(){throw Error('missing controlled artifact');}});
 const readiness=await instance.application.readiness(f.context);assert.equal(readiness.ready,true);assert.equal(readiness.objectiveReadiness.ss_mail_stored_browser_execution,false);await instance.close();
});
test('actual catalog-disabled release never constructs trusted browser dependency',async()=>{const f=fixture();let count=0;const instance=await createMailProduction({...f.deps,createBrowserQualification(){count++;throw Error('must remain cold');}});await instance.application.readiness(f.context);assert.equal(count,0);await instance.close();});

test('actual released objective with enabled catalog still denies missing renderer',async()=>{const f=fixture();f.deps.identityPool={async query(sql){return {rows:sql.includes('identity.secureshop_authority_owners')?[{realm:'shop',shop_tenant_id:randomUUID()}]:[{objective_id:'ss_mail_stored_browser_execution'}]};}};let count=0;const instance=await createMailProduction({...f.deps,createBrowserQualification(){count++;throw Error('missing artifact');}});const result=await instance.application.readiness(f.context);assert.equal(result.ready,true);assert.equal(result.objectiveReadiness.ss_mail_stored_browser_execution,false);assert.equal(count,1);await instance.close();});
