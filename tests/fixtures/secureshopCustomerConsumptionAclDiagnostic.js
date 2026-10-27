'use strict';
// V37-only observation of the original ACL checker. It never supplies a decision.
const assert=require('node:assert/strict');
const {AsyncLocalStorage}=require('node:async_hooks');

const IDENTITY_SQL='SELECT current_user AS role,current_database() AS database';
const PERMISSION_SQL='SELECT allowed FROM secureshop_agents.tool_permissions WHERE tool_name=$1 AND role=$2';
const closed=value=>typeof value==='string'&&/^[a-z][a-z0-9_]{0,127}$/.test(value);
async function identity(pool){
  const rows=(await pool.query(IDENTITY_SQL)).rows;
  assert.equal(rows.length,1);
  assert.ok(closed(rows[0].role)&&closed(rows[0].database));
  return {role:rows[0].role,database:rows[0].database};
}
function allowed(row){
  assert.ok(row===null||(row&&Object.keys(row).length===1&&[0,1].includes(row.allowed)));
  return row?.allowed??null;
}
async function beginAclDiagnostic({ownedPool,actualPool,repository,resolveRepository,checker}){
  assert.equal(typeof checker,'function');assert.equal(typeof resolveRepository,'function');
  assert.equal(resolveRepository(),repository,'Original checker repository must be observed');
  const [ownedDatabase,actualDatabase]=await Promise.all([identity(ownedPool),identity(actualPool)]);
  // The singleton checker must query the same owned runtime role/database; a
  // mismatch fails before any actor or tool dispatch, never by changing ACL.
  assert.deepEqual(actualDatabase,ownedDatabase,'Original checker database differs from owned ACL seed');
  const context=new AsyncLocalStorage(),originalPermission=repository.getPermission;
  const originalEnforcement=repository.getEnforcement;
  assert.equal(typeof originalPermission,'function');assert.equal(typeof originalEnforcement,'function');
  const observations=[];let closedObserver=false;
  const wrappedPermission=async function(toolKey,role){
    const active=context.getStore();
    const result=await originalPermission.call(repository,toolKey,role);
    if(active)active.lookups.push({toolKey,role,allowed:allowed(result??null)});
    return result;
  };
  const wrappedEnforcement=async function(){
    const active=context.getStore(),result=await originalEnforcement.call(repository);
    if(active){assert.equal(typeof result,'boolean');active.enforcementReads.push(result);}
    return result;
  };
  repository.getPermission=wrappedPermission;
  repository.getEnforcement=wrappedEnforcement;
  return Object.freeze({
    async check(role,agent,tool,call){
      assert.equal(closedObserver,false);assert.equal(resolveRepository(),repository);
      assert.equal(role,'customer');assert.equal(agent,'cart');assert.equal(tool,'view');
      assert.ok(call&&typeof call.callId==='string'&&Number.isSafeInteger(call.step)&&call.step>0);
      const active={lookups:[],enforcementReads:[]};
      return context.run(active,async()=>{
        const decision=await checker(role,agent,tool,call);
        assert.equal(resolveRepository(),repository);
        assert.deepEqual(active.lookups.map(({toolKey,role})=>({toolKey,role})),
          [{toolKey:'cart.view',role:'customer'}], 'Actual checker did not query the observed ACL repository');
        assert.ok(active.enforcementReads.length<=1);
        const independent=(await ownedPool.query(PERMISSION_SQL,['cart.view','customer'])).rows;
        assert.equal(independent.length,1);
        const ownedAllowed=allowed(independent[0]);
        const observed={callId:call.callId,step:call.step,role,agent,tool,
          lookup:active.lookups[0],ownedAllowed,enforcementRead:active.enforcementReads[0]??null,
          decision:{allowed:decision.allowed,action:decision.action,
            policyViolation:decision.policyViolation,enforcement:decision.enforcement},
          matchesOwned:active.lookups[0].allowed===ownedAllowed,
          matchesExpected:ownedAllowed===1&&decision.allowed===true&&decision.action==='dispatch'
            &&decision.policyViolation===null&&decision.enforcement===false};
        observations.push(observed);
        return decision;
      });
    },
    close(){
      if(closedObserver)throw Error('V37 ACL observer already closed');
      closedObserver=true;
      const intact=repository.getPermission===wrappedPermission&&repository.getEnforcement===wrappedEnforcement;
      repository.getPermission=originalPermission;repository.getEnforcement=originalEnforcement;
      assert.equal(intact,true,'V37 ACL observer was replaced before restoration');
      return {version:1,ownedDatabase,actualDatabase,observations};
    },
  });
}
function validateAclDiagnostic(diagnostic,{name,spans,dispatches,error,traces}){
  assert.equal(diagnostic?.version,1);
  assert.deepEqual(diagnostic.actualDatabase,diagnostic.ownedDatabase);
  assert.ok(closed(diagnostic.actualDatabase.role)&&closed(diagnostic.actualDatabase.database));
  assert.ok(name==='vuln'||name==='fixed');
  assert.ok(Array.isArray(spans)&&Array.isArray(dispatches)&&Array.isArray(traces));
  const selected=spans.flatMap((span,index)=>(span.response?.tool_uses||[]).map(use=>{
    assert.equal(use.name,'cart.view');assert.deepEqual(use.args,{});
    assert.equal(typeof use.id,'string');assert.ok(use.id.length>0);
    return {callId:use.id,step:index+1};
  }));
  assert.ok(selected.length>0&&selected.length<=4);
  assert.equal(new Set(selected.map(row=>row.callId)).size,selected.length);
  const observed=diagnostic.observations;
  assert.ok(Array.isArray(observed));
  // Concurrent selections can reach the real ACL checker in either order.
  // The Fixed boundary admits exactly the observed selected call, not an
  // assumed prefix of the model's selection order.
  const admitted=name==='fixed'?observed.map(({callId,step})=>{
    const matches=selected.filter(row=>row.callId===callId);
    assert.equal(matches.length,1,'Fixed ACL observation must identify a selected call');
    assert.equal(step,matches[0].step);
    return matches[0];
  }):selected;
  if(name==='fixed'){
    assert.equal(error?.code,'CUSTOMER_CONSUMPTION_LIMIT');
    assert.equal(spans.length,1);
    assert.equal(observed.length,1,'Fixed may stop only after its first admitted ACL check');
    assert.equal(dispatches.length,1);
    assert.equal(traces.filter(trace=>trace.kind==='mcp_result').length,0);
  }
  else {assert.equal(error,null);assert.equal(observed.length,selected.length);}
  assert.equal(dispatches.length,observed.length,'Every admitted ACL check must reach one dispatch');
  const calls=traces.filter(trace=>trace.kind==='mcp_call');
  assert.equal(calls.length,observed.length,'Every admitted ACL check must have one original call trace');
  for(const call of calls){assert.equal(call.agent_ns,'cart');assert.equal(call.tool_name,'view');}
  assert.deepEqual(calls.map(call=>call.step).sort((a,b)=>a-b),admitted.map(call=>call.step).sort((a,b)=>a-b));
  for(const call of dispatches){assert.equal(call.agent,'cart');assert.equal(call.tool,'view');assert.deepEqual(call.args,{});}
  const sorted=rows=>[...rows].sort((a,b)=>a.callId.localeCompare(b.callId));
  assert.deepEqual(sorted(observed.map(({callId,step})=>({callId,step}))),sorted(admitted));
  assert.equal(new Set(observed.map(row=>row.callId)).size,observed.length);
  for(const row of observed){
    assert.equal(row.role,'customer');assert.equal(row.agent,'cart');assert.equal(row.tool,'view');
    assert.deepEqual(row.lookup,{toolKey:'cart.view',role:'customer',allowed:1});
    assert.equal(row.ownedAllowed,1);assert.ok(row.enforcementRead===false||row.enforcementRead===null);
    assert.deepEqual(row.decision,{allowed:true,action:'dispatch',policyViolation:null,enforcement:false});
    assert.equal(row.matchesOwned,true);assert.equal(row.matchesExpected,true);
  }
  return true;
}
module.exports={beginAclDiagnostic,validateAclDiagnostic};
