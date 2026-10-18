'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createSecureShopGradingBootstrap}=require('../server/services/secureshopGradingBootstrap');
function fixture(){
 const calls=[],identityPool={query(){throw Error('Unexpected SQL');},connect(){throw Error('Unexpected SQL');}},agentsPool={...identityPool};
 const progress={getGeneration:async()=>0},launches={async assertCurrent(scope){calls.push(['current',scope]);return scope;}};
 const authority={capture(){}},bindings=Object.fromEntries(['capture','initial','inherit','commit','check','projectRecoverable'].map(k=>[k,async()=>{}]));
 bindings.assertReady=async()=>{calls.push(['bindingsReady']);};
 const options={identityPool,agentsPool,progress,resetComposition:{launches},assertAuthorityReady:async input=>{calls.push(['authorityReady',input]);}};
 const factories={createAuthority(input){calls.push(['authority',input]);return authority;},createBindings(input){calls.push(['bindings',input]);return bindings;},createCore(input){calls.push(['core',input]);return require('../server/services/objectiveGradingCore').createObjectiveGradingCore(input);}};
 return{calls,options,factories,authority,bindings};
}
test('readiness precedes one shared branded core with exact adapter and stores',async()=>{
 const f=fixture(),prepared=await createSecureShopGradingBootstrap(f.options,f.factories);
 assert.deepEqual(f.calls.map(c=>c[0]),['authorityReady','authority','bindings','bindingsReady','core']);
 assert.equal(f.calls[1][1].pool,f.options.agentsPool);assert.equal(f.calls[2][1].pool,f.options.identityPool);
 assert.equal(f.calls[2][1].personaAuthority,f.authority);assert.equal(prepared.personaBindings.capture,f.bindings.capture);assert.equal(typeof prepared.personaBindings.resolveStores,'function');
 assert.equal(prepared.assessmentDependencies,prepared.gradingCore.assessmentDependencies);
 assert.equal(prepared.assessmentDependencies.personaBindings,prepared.personaBindings);assert.equal(prepared.assessmentDependencies.progress,f.options.progress);
 const scope={owned:true};assert.equal(await f.calls[1][1].checkCurrent(scope),scope);
 assert.equal(Object.isFrozen(prepared),true);
});
test('missing authority readiness and shared cross-store pool fail before construction',async()=>{
 for(const patch of [{assertAuthorityReady:undefined},{agentsPool:null},{resetComposition:{} }]){
  const f=fixture();await assert.rejects(createSecureShopGradingBootstrap({...f.options,...patch},f.factories),TypeError);assert.equal(f.calls.length,0);
 }
 const f=fixture();await assert.rejects(createSecureShopGradingBootstrap({...f.options,agentsPool:f.options.identityPool},f.factories),TypeError);assert.equal(f.calls.length,0);
});
test('authority and binding readiness failures never construct a grading core',async()=>{
 const a=fixture();a.options.assertAuthorityReady=async()=>{throw Error('Authority schema unavailable');};
 await assert.rejects(createSecureShopGradingBootstrap(a.options,a.factories),/Authority schema/);assert.equal(a.calls.length,0);
 const b=fixture();b.bindings.assertReady=async()=>{throw Error('Identity privileges unavailable');};
 await assert.rejects(createSecureShopGradingBootstrap(b.options,b.factories),/Identity privileges/);assert.equal(b.calls.some(c=>c[0]==='core'),false);
 const c=fixture();delete c.bindings.commit;await assert.rejects(createSecureShopGradingBootstrap(c.options,c.factories),/Complete persona grading adapter/);assert.equal(c.calls.some(row=>row[0]==='core'),false);
});
test('bootstrap rejects a core constructed for a different pool or adapter',async()=>{
 for(const mismatch of ['pool','adapter']){
  const f=fixture();f.factories.createCore=input=>require('../server/services/objectiveGradingCore').createObjectiveGradingCore({...input,...(mismatch==='pool'?{identityPool:{...input.identityPool}}:{personaBindings:{capture(){}}})});
  await assert.rejects(createSecureShopGradingBootstrap(f.options,f.factories),TypeError);
 }
});

test('explicit negative readiness cannot be mistaken for successful completion',async()=>{
 for(const stage of ['authority','bindings']){
  const f=fixture();if(stage==='authority')f.options.assertAuthorityReady=async()=>false;else f.bindings.assertReady=async()=>false;
  await assert.rejects(createSecureShopGradingBootstrap(f.options,f.factories),/readiness rejected/);
  assert.equal(f.calls.some(row=>row[0]==='core'),false);
 }
});

test('default readiness rejects mismatched configured identity before authority or construction',async()=>{
 const f=fixture();f.options.identityPool.query=async sql=>{assert.equal(sql,'SELECT current_database() AS database');return{rows:[{database:'unexpected'}]};};
 await assert.rejects(createSecureShopGradingBootstrap({...f.options,assertAuthorityReady:undefined,expectedIdentityDatabase:'identity_owned',expectedAgentsDatabase:'agents_owned'},f.factories),/Identity grading store mismatch/);
 assert.equal(f.calls.length,0);
});

test('prepared bootstrap brand binds exact pools and cleanup composition',async()=>{
 const f=fixture(),prepared=await createSecureShopGradingBootstrap(f.options,f.factories);
 const {resolveSecureShopGradingBootstrap:resolve}=require('../server/services/secureshopGradingBootstrap');
 const scope={identityPool:f.options.identityPool,agentsPool:f.options.agentsPool,resetComposition:f.options.resetComposition};
 assert.equal(resolve(prepared,scope),prepared);assert.equal(prepared.resetComposition,scope.resetComposition);
 assert.throws(()=>resolve({...prepared},scope),TypeError);
 for(const key of ['identityPool','agentsPool','resetComposition'])assert.throws(()=>resolve(prepared,{...scope,[key]:{...scope[key]}}),TypeError);
});
