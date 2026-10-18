'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');
const outer=require('../server/agent-runtime/dpiGraph');const decoder=require('../server/agent-runtime/dpiObfuscationGraph');
const project=g=>{const j=g.getGraph().toJSON();return {nodes:j.nodes.map(({id})=>({id})),edges:j.edges.map(({source,target,conditional})=>({source,target,conditional:conditional===true}))};};
test('metadata uses exact compiled assemblies without invoking callbacks and returns isolated projections',()=>{
 let calls=0;const deny=()=>{calls++;throw Error('must not execute');};
 for(const [getter,graph] of [[outer.getDpiGraphDefinition,outer.compileDpiGraph({prepare:deny,model:deny,detect:deny,judge:deny,publication:deny})],[decoder.getDpiObfuscationGraphDefinition,decoder.compileDpiObfuscationGraph({decoder_decision:deny,decode_payload:deny,decoder_response:deny})]]){
  assert.deepEqual(getter(),project(graph));const first=getter();first.nodes[0].id='poison';assert.notEqual(getter().nodes[0].id,'poison');
  assert(first.edges.every(e=>Object.keys(e).sort().join(',')==='conditional,source,target'));
 }assert.equal(calls,0);
});
test('compiled outer routing retains optional publication and decoder retains early final',async()=>{
 for(const needsJudge of [false,true]){const seen=[];const fn=n=>()=>{seen.push(n);return n==='detect'?{needsJudge}:{};};await outer.compileDpiGraph(Object.fromEntries(['prepare','model','detect','judge','publication'].map(n=>[n,fn(n)]))).invoke({},{recursionLimit:8});assert.deepEqual(seen,needsJudge?['prepare','model','detect','publication','judge']:['prepare','model','detect']);}
 for(const action of ['final','decode_payload']){const seen=[];await decoder.compileDpiObfuscationGraph({decoder_decision:()=>{seen.push('decision');return {action};},decode_payload:()=>{seen.push('decode');return {};},decoder_response:()=>{seen.push('response');return {};}}).invoke({},{recursionLimit:8});assert.deepEqual(seen,action==='final'?['decision']:['decision','decode','response']);}
});
