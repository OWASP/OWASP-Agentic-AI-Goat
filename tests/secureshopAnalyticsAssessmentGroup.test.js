'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {analyticsAssessmentGroup}=require('../server/services/secureshopAnalyticsAssessmentGroup');
test('assessment group preserves separate protected attempts and skips unavailable disclosure',async()=>{
 const seen=[],execution={},context={},fence={},privateEvidence={question:'untrusted'};
 const make=name=>async(c,f,p)=>{assert.equal(c,context);assert.equal(f,fence);if(name==='disclosure')assert.equal(p,privateEvidence);return {begin:async()=>name,observe:async(e,packet)=>{assert.equal(e,execution);seen.push([name,packet.attempt]);},finalize:async(e,packet)=>{assert.equal(packet.attempt,name);return name;}};};
 const group=await analyticsAssessmentGroup({loopFactory:make('loop'),disclosureFactory:make('disclosure'),privateEvidence})(context,fence),attempt=await group.begin(execution);await group.observe(execution,{attempt});assert.deepEqual(seen,[['loop','loop'],['disclosure','disclosure']]);assert.deepEqual(await group.finalize(execution,{attempt}),['loop','disclosure']);await assert.rejects(group.finalize(execution,{attempt:[...attempt]}));
 const disabled=await analyticsAssessmentGroup({loopFactory:make('loop'),disclosureFactory:async()=>null,privateEvidence})(context,fence),single=await disabled.begin(execution);assert.deepEqual(await disabled.finalize(execution,{attempt:single}),['loop']);
});
