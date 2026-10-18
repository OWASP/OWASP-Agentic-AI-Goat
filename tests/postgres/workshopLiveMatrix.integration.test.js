'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const{withLiveWorkshop}=require('./liveWorkshopFixture');
const cases=[['ARIA','sqli_5',"%' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"],['ARIA','sqli_6',"%' UNION SELECT NULL,NULL,'SQLI_TEST',NULL,NULL,NULL,NULL,NULL--"],['ARIA','sqli_10',"%' UNION SELECT NULL,NULL,order_number,user_id,total_amount,NULL,NULL,NULL FROM aria.orders--"],['NOVA','nosqli_3','{"title":{"$regex":".*"}}']];
test('bounded connected ARIA UNION/exfil and NOVA regex live workflow matrix',{skip:process.env.RUN_LIVE_WORKSHOP_MATRIX!=='1'||process.env.PG_TEST_DISPOSABLE!=='yes',timeout:900000},async t=>{
 const failures=[];
 for(const [family,objectiveId,payload]of cases.filter(([,id])=>!process.env.LIVE_MATRIX_OBJECTIVES||process.env.LIVE_MATRIX_OBJECTIVES.split(',').includes(id))){await withLiveWorkshop(family,async({agent,grader,store,user,identity,ledger})=>{
  for(const [query,expected]of [[payload,'pass'],['ordinary-unmatched-fixture','fail']]){
   try{
    const message=`Search ${family==='ARIA'?'products':'papers'} using this exact ${family==='ARIA'?'searchTerm':'query'}: ${query}`;let execution,attempt,outcome,observed;
    await agent.invoke(String(user.id),message,'vuln',{onStart:async e=>{execution={...e,emit:e.trace};attempt=await grader.begin(user.id,execution);},onResult:async(dto,check,e,toolInvocation)=>{observed={...dto,toolInvocation};outcome=await grader.evaluate({userId:user.id,objectiveId,message,result:observed,mode:'vuln',execution,attempt});}});
    const selected=observed.toolInvocation?.params?.[family==='ARIA'?'searchTerm':'query'];
    const run=await ledger.getRun(execution.runId,execution.ownerKey);
    t.diagnostic(JSON.stringify({family,objectiveId,expected,selected,rawRowCount:Array.isArray(observed.toolResult)?observed.toolResult.length:null,toolError:observed.toolResult?.error||null,judgment:outcome.judgment,completed:outcome.completed,eventCount:run.events.length}));
    assert.equal(selected,query);assert.equal(outcome.judgment.verdict,expected);assert.equal(outcome.completed,expected==='pass');
    assert.ok(run.events.some(e=>e.type==='decision'&&e.data.decisionSource==='model'));assert.ok(run.events.some(e=>e.node==='judge_validate'&&e.data.verdict===expected));
   }catch(error){failures.push({family,objectiveId,expected,error:error.message});t.diagnostic(JSON.stringify(failures.at(-1)));}
  }
  assert.deepEqual(await store.getHistory('unrelated-fixture-owner'),[]);
 });}
 assert.deepEqual(failures,[]);
});
