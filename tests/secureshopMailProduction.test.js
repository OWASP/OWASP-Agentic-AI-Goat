'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createMailProduction,createRetainedMailBindingResolver,assertMailSchema,PRODUCTION_QUALIFIED}=require('../server/services/secureshopMailProduction');
function pool(mutate=x=>x){return {async query(sql,args){const rows=args?[...args[0]].map(name=>({name,ready:true})):[{messages_private:true,purpose_ready:true,cleanup_ready:true,browse_ready:true}];return {rows:mutate(rows,sql)};}};}
function fixture(){let revoked=false,reserved=0,provisioned=0;const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},context={scope,persona:{id:2,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
 const authority={capture(x){return {binding:{...x.scope,personaId:x.personaId,role:x.role,...x},async assertRemoteAdmission(){if(revoked)throw Error('revoked');}};}};
 const resetComposition={launches:{async assertCurrent(){if(revoked)throw Error('revoked');},async reservePersonaInboxTarget(){reserved++;return {targetId:randomUUID()};}},personaInbox:{repository:{async provision(){provisioned++;}}},cleanupAuthority:{async checkTarget(){}},conversations:{async getBoundSession(){},async acquireBoundSession(){},async getMessages(){return[];},async getTraceEvents(){return[];}},journal:{async claim(){},async complete(){},async markUncertain(){},async readBoundRequest(){}},runCoordinator:{async run(){throw Error('should not start');}}};
 const deps={enabled:true,identityPool:{async query(sql){return {rows:sql.includes('identity.secureshop_authority_owners')?[{realm:'shop',shop_tenant_id:1}]:[]};}},agentsPool:pool(),resetComposition,personaAuthority:authority,personaRepository:{async listMailActors(scope){return this.listPersonas(scope);},async listPersonas(){return [{id:1,role:'customer',email:'customer@lab'},{id:2,role:'merchant',email:'merchant@lab'},{id:3,role:'admin',email:'admin@lab'}];}},provider:{async chat(){throw Error('no model');}},promptPolicyRepository:{async admitRunSnapshot(){}},toolPolicyRepository:{async admitTool(){}},assessmentDependencies:{personaBindings:{async capture(){}},receipts:{async beginEvaluation(){},async recordVerdict(){}},progress:{async getGeneration(){}},publicationModes:{async getEvaluationScope(){throw Error('no assessment');}},judge:async()=>{throw Error('no Judge');}},authenticatePersona(){}};
 return {deps,context,revoke(){revoked=true;},get reserved(){return reserved;},get provisioned(){return provisioned;}};
}
test('qualified transport still keeps explicitly disabled factory dependencies lazy',async()=>{assert.equal(PRODUCTION_QUALIFIED,true);assert.deepEqual(await createMailProduction(),{ready:false});});
test('schema gate rejects privilege, function, missing cleanup/purpose/browse and duplicate rows',async()=>{
 assert.equal(await assertMailSchema(pool()),true);
 for(const mutate of [r=>r.slice(1),r=>r.map(x=>({...x,ready:false})),r=>r.map(x=>({...x,cleanup_ready:false})),r=>r.map(x=>({...x,purpose_ready:false})),r=>r.map(x=>({...x,browse_ready:false})),r=>r.length>1?r.map(()=>r[0]):r])await assert.rejects(assertMailSchema(pool(mutate)));
});
test('composed readiness binds persona session; pending assessment starts no graph/Judge and close/revoke fence reads',async()=>{
 const f=fixture(),production=await createMailProduction(f.deps),first=await production.application.readiness(f.context);
 assert.equal(first.ready,true);assert.match(first.scopeKey,/^[a-f0-9]{64}$/);
 const next=await production.application.readiness({...f.context,personaSession:{...f.context.personaSession,sessionId:randomUUID()}});assert.notEqual(next.scopeKey,first.scopeKey);
 const assessed=await production.application.assess(f.context,{requestId:randomUUID(),replyOperationId:randomUUID(),threadId:5});assert.deepEqual(assessed,{ok:true,completed:false,status:'disabled',modelEvaluated:false});assert.equal(f.reserved,1);assert.equal(f.provisioned,1);
 const header=await production.application.assessHeader(f.context,{requestId:randomUUID(),sendOperationId:randomUUID()});assert.deepEqual(header,{ok:true,completed:false,status:'disabled',modelEvaluated:false});assert(Object.values(first.objectiveReadiness).every(x=>x===false));
 f.revoke();await assert.rejects(production.application.readiness(f.context),/revoked/);production.close();assert.deepEqual(await production.application.readiness(f.context),{ready:false});
});
test('production refuses incomplete policy and Judge dependencies before schema work',async()=>{const f=fixture();await assert.rejects(createMailProduction({...f.deps,toolPolicyRepository:undefined}));await assert.rejects(createMailProduction({...f.deps,assessmentDependencies:{}}));});

test('supported activation defaults only after source qualification and honors explicit opt-out',()=>{const {mailServingEnabled}=require('../server/services/secureshopMailProduction');assert.equal(mailServingEnabled(undefined),true);assert.equal(mailServingEnabled('true'),true);assert.equal(mailServingEnabled(undefined,false),false);assert.equal(mailServingEnabled(undefined,true),true);assert.equal(mailServingEnabled('true',true),true);assert.equal(mailServingEnabled('false',true),false);assert.throws(()=>mailServingEnabled('yes',true));});

test('cold supported mail composition uses actual production factory and keeps disabled dependencies lazy',async()=>{
 const {createOptionalMailComposition}=require('../server/services/secureshopMailComposition'),production=require('../server/services/secureshopMailProduction');let loads=0;
 const f=fixture(),options={flag:undefined,async loadDependencies(){loads++;return f.deps;}};
 assert.equal(await createOptionalMailComposition(options,{...production,PRODUCTION_QUALIFIED:false}),undefined);assert.equal(loads,0);
 const qualified={...production,PRODUCTION_QUALIFIED:true};
 const mounted=await createOptionalMailComposition(options,qualified);assert.equal(loads,1);assert.equal(mounted.ready,true);assert.equal(typeof mounted.router,'function');
 const result=await mounted.application.readiness(f.context);assert.equal(result.ready,true);assert.equal(result.readinessMeaning,'transport_and_catalog_admission');assert.equal(result.modelCapabilities.actor.status,'unknown_unprobed');assert.equal(result.modelCapabilities.judge.status,'unknown_unprobed');assert(Object.values(result.objectiveReadiness).every(value=>value===false));
 mounted.close();assert.deepEqual(await mounted.application.readiness(f.context),{ready:false});
 assert.equal(await createOptionalMailComposition({...options,flag:'false'},qualified),undefined);assert.equal(loads,1);
 await assert.rejects(createOptionalMailComposition({...options,flag:'invalid'},qualified));assert.equal(loads,1);
 await assert.rejects(createOptionalMailComposition({...options,loadDependencies:async()=>({...f.deps,promptPolicyRepository:null})},qualified));
 assert.equal(production.PRODUCTION_QUALIFIED,true);
});


test('retained mail resolver discards serialized scene fields and restores only the canonical WeakMap grant',async()=>{
 const mailScene=require('../server/services/secureshopMailSceneBinding');
 const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
 const {normalize}=require('../server/database/postgres/secureshopBoundMailRepository');
 const birth={launchId:randomUUID(),scenarioId:randomUUID(),generation:3,platformOwnerId:11,platformSessionId:12,targetId:randomUUID()};
 const execution={launchId:randomUUID(),scenarioId:randomUUID(),generation:8,platformOwnerId:11,platformSessionId:13};
 const scene=createSceneBinding(birth,{sceneId:randomUUID(),sceneGeneration:2,grantId:randomUUID(),execution,withLease:async work=>work()});
 const target=mailScene.attach(birth,scene),persona={id:7,role:'merchant'},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 const detached=JSON.parse(JSON.stringify({scope:execution,targetId:birth.targetId,target,persona,personaSession,mode:'vuln',operationId:randomUUID()}));
 assert.equal(mailScene.productScene(normalize(detached)),null);
 let reads=0;const resolve=createRetainedMailBindingResolver(async scope=>{reads++;assert.deepEqual(scope,execution);return target;});
 const resolved=await resolve(detached),copied=normalize(resolved),held=mailScene.productScene(copied);
 assert.equal(reads,1);assert.equal(held,scene);assert.equal(held.scene.grantId,scene.scene.grantId);
 const forged=structuredClone(detached);forged.targetId=randomUUID();forged.target.targetId=forged.targetId;
 await assert.rejects(resolve(forged),/Bound mail production dependencies unavailable/);
});
