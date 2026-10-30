'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),Module=require('node:module');
const {beginAclDiagnostic,validateAclDiagnostic}=require('./fixtures/secureshopCustomerConsumptionAclDiagnostic');
const DB={role:'dvaia_secureshop_agents_runtime',database:'owasp_ai_goat_test_agent_host_0123456789ab_secureshop_agents'};
function evidence(spans,{name='vuln',error=null,admitted=spans.flatMap(s=>s.response.tool_uses).length}={}){
  return {name,spans,error,dispatches:Array.from({length:admitted},()=>({agent:'cart',tool:'view',args:{}})),
    traces:Array.from({length:admitted},(_,i)=>({kind:'mcp_call',step:i+1,agent_ns:'cart',tool_name:'view'}))};
}
function actualChecker(repository){
  const filename=require.resolve('../server/services/secureshop/toolAcl'),compiled=new Module(filename,module);
  compiled.filename=filename;compiled.paths=module.paths;
  const originalRequire=Module.createRequire(filename);
  compiled.require=id=>id==='../../database/postgres/secureshopAgentsDb'
    ?{getSecureShopAgentsDb:()=>repository}:originalRequire(id);
  compiled._compile(fs.readFileSync(filename,'utf8'),filename);
  return compiled.exports.checkToolAcl;
}
function fixture({actualDb=DB,ownedDb=DB,repoAllowed=1,ownedAllowed=1}={}){
  const queries=[];
  const repository={
    async getPermission(toolKey,role){queries.push({source:'checker',toolKey,role});return{allowed:repoAllowed};},
    async getEnforcement(){queries.push({source:'checker-enforcement'});return false;},
  };
  const actualPool={async query(sql){assert.match(sql,/^SELECT current_user AS role/);return{rows:[actualDb]};}};
  const ownedPool={async query(sql,args){
    if(sql.includes('current_user'))return{rows:[ownedDb]};
    assert.match(sql,/^SELECT allowed FROM secureshop_agents\.tool_permissions/);
    assert.deepEqual(args,['cart.view','customer']);queries.push({source:'owned'});
    return{rows:[{allowed:ownedAllowed}]};
  }};
  return {repository,actualPool,ownedPool,queries,checker:actualChecker(repository)};
}
test('real checker path is observed without replacing its decisions, including concurrent calls',async()=>{
  const f=fixture(),permission=f.repository.getPermission,enforcement=f.repository.getEnforcement;
  const observer=await beginAclDiagnostic({...f,resolveRepository:()=>f.repository});
  const [a,b]=await Promise.all([1,2].map(step=>observer.check('customer','cart','view',
    {callId:`call-${step}`,step,args:{}})));
  assert.equal(a.allowed,true);assert.strictEqual(a.action,'dispatch');assert.deepEqual(a,b);
  const diagnostic=observer.close();
  assert.strictEqual(f.repository.getPermission,permission);assert.strictEqual(f.repository.getEnforcement,enforcement);
  assert.equal(f.queries.filter(q=>q.source==='checker').length,2);
  assert.equal(f.queries.filter(q=>q.source==='checker-enforcement').length,2);
  assert.equal(f.queries.filter(q=>q.source==='owned').length,2);
  assert.equal(validateAclDiagnostic(diagnostic,evidence([{response:{tool_uses:[{id:'call-1',name:'cart.view',args:{}}]}},
    {response:{tool_uses:[{id:'call-2',name:'cart.view',args:{}}]}}])),true);
  assert.doesNotMatch(JSON.stringify(diagnostic),/password|token|postgresql:|request|sourceText/);
  assert.throws(()=>observer.close());
});
test('wrong role/tool or actual repository change fails before a substituted ACL result',async()=>{
  const f=fixture(),observer=await beginAclDiagnostic({...f,resolveRepository:()=>f.repository});
  for(const [role,agent,tool]of [['admin','cart','view'],['customer','cart','remove'],['customer','orders','view']])
    await assert.rejects(observer.check(role,agent,tool,{callId:'call-1',step:1,args:{}}));
  assert.equal(f.queries.length,0);
  const bad=fixture();let current=bad.repository;
  const changed=await beginAclDiagnostic({...bad,resolveRepository:()=>current});
  current={};
  await assert.rejects(changed.check('customer','cart','view',{callId:'call-1',step:1,args:{}}));
  assert.equal(bad.queries.length,0);
  observer.close();changed.close();
});
test('actual checker pool role/database mismatch is rejected before lookup',async()=>{
  for(const actualDb of [{...DB,role:'wrong_runtime'},{...DB,database:'foreign_store'}]){
    const f=fixture({actualDb});
    await assert.rejects(beginAclDiagnostic({...f,resolveRepository:()=>f.repository}));
    assert.equal(f.queries.length,0);
  }
});
test('denied real checker decision remains denied and diagnostic validation fails closed',async()=>{
  const f=fixture({repoAllowed:0}),observer=await beginAclDiagnostic({...f,resolveRepository:()=>f.repository});
  const decision=await observer.check('customer','cart','view',{callId:'call-1',step:1,args:{}});
  assert.deepEqual(decision,{allowed:false,action:'log',policyViolation:'denied-by-acl',enforcement:false});
  const diagnostic=observer.close();assert.equal(diagnostic.observations[0].matchesOwned,false);
  assert.equal(diagnostic.observations[0].matchesExpected,false);
  assert.throws(()=>validateAclDiagnostic(diagnostic,evidence([{response:{tool_uses:[{id:'call-1',name:'cart.view',args:{}}]}}])));
});
test('duplicate, swapped, or altered lookup provenance cannot validate',async()=>{
  const f=fixture(),observer=await beginAclDiagnostic({...f,resolveRepository:()=>f.repository});
  await observer.check('customer','cart','view',{callId:'call-1',step:1,args:{}});
  const diagnostic=observer.close(),spans=[{response:{tool_uses:[{id:'call-1',name:'cart.view',args:{}}]}}];
  for(const change of [d=>{d.observations[0].callId='foreign';},d=>{d.observations.push(d.observations[0]);},
    d=>{d.observations[0].lookup.role='merchant';},d=>{d.observations[0].ownedAllowed=0;},
    d=>{d.observations[0].decision.policyViolation='denied-by-acl';},d=>{d.actualDatabase.database='other';}]){
    const altered=structuredClone(diagnostic);change(altered);
    assert.throws(()=>validateAclDiagnostic(altered,evidence(spans)));
  }
});
test('Fixed byte budget joins its single admitted selected call by observed identity',async()=>{
  const f=fixture(),observer=await beginAclDiagnostic({...f,resolveRepository:()=>f.repository});
  await observer.check('customer','cart','view',{callId:'first',step:1,args:{}});
  const diagnostic=observer.close(),spans=[{response:{tool_uses:[
    {id:'first',name:'cart.view',args:{}},{id:'second',name:'cart.view',args:{}}]}}];
  const packet=evidence(spans,{name:'fixed',error:{code:'CUSTOMER_CONSUMPTION_LIMIT'},admitted:1});
  assert.equal(validateAclDiagnostic(diagnostic,packet),true);
  const reversed=structuredClone(packet);reversed.spans[0].response.tool_uses.reverse();
  assert.equal(validateAclDiagnostic(diagnostic,reversed),true);
  for(const change of [p=>{p.error={code:'OTHER'};},p=>{p.name='vuln';},
    p=>{p.dispatches.push({agent:'cart',tool:'view',args:{}});},
    p=>{p.traces.push({kind:'mcp_call',step:1,agent_ns:'cart',tool_name:'view'});},
    p=>{p.traces.push({kind:'mcp_result',step:1});},
    p=>{p.spans[0].response.tool_uses[1].name='cart.remove';},
    p=>{p.spans[0].response.tool_uses[1].id='first';}]){
    const altered=structuredClone(packet);change(altered);
    assert.throws(()=>validateAclDiagnostic(diagnostic,altered));
  }
  const second=fixture(),otherObserver=await beginAclDiagnostic({...second,resolveRepository:()=>second.repository});
  await otherObserver.check('customer','cart','view',{callId:'second',step:1,args:{}});
  const observedSecond=otherObserver.close();
  assert.equal(validateAclDiagnostic(observedSecond,packet),true);
  for(const change of [d=>{d.observations[0].callId='foreign';},
    d=>{d.observations[0].step=2;},d=>{d.observations.push(d.observations[0]);}]){
    const altered=structuredClone(observedSecond);change(altered);
    assert.throws(()=>validateAclDiagnostic(altered,packet));
  }
});
