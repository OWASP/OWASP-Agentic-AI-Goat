'use strict';
const { controlledObjectiveGraph } = require('./helpers/controlledObjectiveBoundary');
const Module=require('node:module');const load=Module._load;
Module._load=function(request,parent,main){if(/(?:^|\/)authDb(?:\.js)?$/.test(request))throw Error('Test isolation: authDb forbidden');return load.call(this,request,parent,main);};
const {test}=require('node:test');const assert=require('node:assert/strict');
const {runMcpWorkshopGraph}=require('../server/agent-runtime/mcpWorkshopGraph');
const {runCtfDefenseGraph}=require('../server/agent-runtime/ctfDefenseGraph');
const {runCtfGuardianGraph}=require('../server/agent-runtime/ctfGuardianGraph');
const {runExcessiveAgencyGraph: runExcessiveAgencyGraphRuntime} = require('../server/agent-runtime/excessiveAgencyGraph');
const runExcessiveAgencyGraph = controlledObjectiveGraph(runExcessiveAgencyGraphRuntime);
test('MCP recon avoids effects; injection decision skips duplicate tool execution',async()=>{
 let executions=0;const deps={model:{provider:'mock'},detectIntent:()=>({intent:'recon'}),phraseRecon:async()=> 'catalog',formatCatalog:()=> 'raw',phraseReply:async()=> 'result',resolveInjectionIntent:async()=>({achieved:true,objective:'fixture'}),executeTool:async()=>{executions++;},detectObjectives:(i,r)=>[r.objective]};
 const recon=await runMcpWorkshopGraph({message:'tools',sandbox:{toolListTools:()=>[]}},deps);assert.deepEqual(recon.objectivesHit,[]);assert.equal(recon.toolUsed,'list_tools');assert.equal(recon.response,'catalog');assert.equal(recon.decisionSource,'scripted');assert.equal(executions,0);
 deps.detectIntent=()=>({tool:'read',intent:'read_ticket',params:{}});
 const result=await runMcpWorkshopGraph({message:'read',sandbox:{}},deps);assert.equal(executions,0);assert.deepEqual(result.objectivesHit,['fixture']);
 deps.resolveInjectionIntent=async()=>null;deps.executeTool=async()=>{executions++;return {objective:'offline'};};
 assert.deepEqual((await runMcpWorkshopGraph({message:'read',sandbox:{}},deps)).objectivesHit,['offline']);assert.equal(executions,1);
});
test('CTF input ordering exits first blocked layer and output grading uses filtered text',async()=>{
 const calls=[];const result=await runCtfDefenseGraph({defense_style:'["a","b","a"]'},'payload',{inputHandlers:{a:()=>{calls.push('a');return {blocked:false};},b:()=>{calls.push('b');return {blocked:true,reason:'blocked'};}}});
 assert.deepEqual(calls,['a','b']);assert.equal(result.layer,'b');
 const guardian=await runCtfGuardianGraph({success_criteria:'SECRET'},'payload',{generate:async()=> 'SECRET',runOutputDefenses:async()=> '[redacted]',normalizedContains:(s,k)=>s.includes(k)});
 assert.equal(guardian.wasSuccessful,false);assert.equal(guardian.aiResponse,'SECRET');
});
test('CTF output layers retain configured order and repeated filters',async()=>{
 const out=await runCtfDefenseGraph({defense_style:'["a","b","a"]'},'x',{output:true,outputHandlers:{a:s=>s+'a',b:async s=>s+'b'}});assert.equal(out,'xaba');
});
test('Excessive Agency grades one catalog-valid effect and stops duplicate selection with fallback',async()=>{
 const events=[];let calls=0;const result=await runExcessiveAgencyGraph({messages:[],message:'read',userId:'a',context:{labMode:'vuln'},mode:'vuln',platformUserId:7},{aiService:{chatWithMessages:async()=>({response:++calls===1?'tool request':'{}',provider:'fixture',model:'fixture'})},eaLogger:{error:()=>{}},parseToolCallFromResponse:()=>({tool:'read',args:{id:2}}),toolRouter:{toolDefinitions:{read:{name:'read',params:[{name:'id',type:'number',required:true}]}},executeTool:async(t,args,ctx)=>{assert.equal(ctx.labMode,'vuln');events.push('execute');return {output:'fixture',_warning:'internal'};}},database:{},trackProgressFromToolResult:()=>{events.push('grade');return {judgments:[],completedObjectiveIds:[]};},progressOwnerKey:id=>id,generateToolResponse:()=> 'fallback fixture'});
 assert.deepEqual(events,['execute','grade']);assert.equal(result.finalResponse,'fallback fixture');assert.equal(result.toolResult.output,'fixture');
});
