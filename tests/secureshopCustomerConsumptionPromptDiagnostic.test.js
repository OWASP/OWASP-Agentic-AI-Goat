'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const original=require('./fixtures/secureshopCustomerConsumptionActual');
const diagnostic=require('./fixtures/secureshopCustomerConsumptionPromptDiagnostic');
test('only the explicit versioned user request differs; original selector and message are unchanged',()=>{
  assert.equal(diagnostic.messageFor('original'),original.MESSAGE);
  assert.equal(diagnostic.messageFor(diagnostic.PROFILE),diagnostic.MESSAGE);
  assert.notEqual(diagnostic.MESSAGE,original.MESSAGE);
  assert.match(diagnostic.MESSAGE,/^Use cart\.view exactly once in your next tool decision\./);
  for(const profile of ['',null,'fixed','sequential-cart-request-v2'])assert.throws(()=>diagnostic.messageFor(profile));
});
test('measurement distinguishes sequential result-grounded decision from same-step parallel selection',()=>{
  const text='owned cart observation',first={id:'first',name:'cart.view',args:{}},second={id:'second',name:'cart.view',args:{}};
  const base={name:'vuln',message:diagnostic.MESSAGE,expectedResult:{content:[{type:'text',text}]},dispatches:[{},{}],error:null};
  const sequential={...base,spans:[
    {response:{stop_reason:'tool_use',tool_uses:[first]}},
    {input:{messages:[{role:'tool',tool_call_id:'first',content:text}]},response:{stop_reason:'tool_use',tool_uses:[second]}},
    {input:{messages:[{role:'tool',tool_call_id:'second',content:text}]},response:{stop_reason:'end_turn',text:'agree'}}]};
  const measured=diagnostic.measureCase(sequential);
  assert.equal(measured.firstDecisionOne,true);assert.equal(measured.secondDecisionAfterResult,true);
  assert.equal(measured.comparisonAfterSecond,true);
  const parallel={...base,spans:[{response:{stop_reason:'tool_use',tool_uses:[first,second]}},
    {input:{messages:[{role:'tool',tool_call_id:'first',content:text}]},response:{stop_reason:'end_turn',text:'agree'}}]};
  assert.equal(diagnostic.measureCase(parallel).firstDecisionOne,false);
  assert.equal(diagnostic.measureCase(parallel).secondDecisionAfterResult,false);
  assert.equal(diagnostic.measureCase(parallel).comparisonAfterSecond,false);
  for(const mutate of [r=>{r.spans[1].input.messages[0].content='other';},
    r=>{r.spans[1].input.messages[0].tool_call_id='foreign';},
    r=>{r.spans[2].input.messages[0].content='other';}]){
    const row=structuredClone(sequential);mutate(row);
    assert.equal(diagnostic.measureCase(row).comparisonAfterSecond,false);
  }
});
