'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {runMcpWorkshopGraph}=require('../server/agent-runtime/mcpWorkshopGraph');

function fixture(select){
 const calls=[],prompts=[],events=[],token=Object.freeze({});
 const deps={model:{provider:'ollama',chatWithTools:async messages=>{prompts.push(messages);return {content:JSON.stringify(select(prompts.length))};}},
  execution:{check:async()=>{},trace:async event=>events.push(event)},resolveInjectionIntent:async()=>null,
  executeTool:async(tool,params)=>{calls.push({tool,params});return {tool,args:params,output:`observed ${calls.length}`,objective:`objective_${calls.length}`,achieved:true,configObservation:token};},
  detectObjectives:(_intent,value)=>[value.objective],phraseReply:async()=> 'done',formatCatalog:()=> 'catalog',phraseRecon:async()=> 'catalog'};
 return {calls,prompts,events,token,deps,run:()=>runMcpWorkshopGraph({message:'perform two steps',sandbox:{toolListTools:()=>[{name:'get_config'},{name:'read_file'}]}},deps)};
}
test('MCP observes a result before selecting another tool and retains both grading observations',async()=>{
 const f=fixture(n=>n===1?{tool:'get_config',params:{}}:n===2?{tool:'read_file',params:{path:'../training'}}:{tool:'none',params:{}});
 let phrased;
 f.deps.phraseReply=async(_message,_last,observations)=>{phrased=observations;return 'done';};
 const out=await f.run();
 assert.equal(f.calls.length,2);assert.equal(out.stopReason,'model_finished');
 assert.ok(f.prompts[1].some(m=>m.content.includes('observed 1')));
 assert.deepEqual(out.objectivesHit,['objective_1','objective_2']);
 assert.equal(out.toolObservations[0].toolResult.configObservation,f.token,'Opaque provenance survives the actual graph by reference');
 assert.equal(out.toolObservations[0].toolUsed,'get_config');assert.equal(out.toolUsed,'read_file');
 assert.equal(phrased,out.toolObservations,'Final phrasing receives every original observation');
});
test('MCP refuses duplicate calls and bounds distinct model-selected calls',async()=>{
 const duplicate=fixture(()=>({tool:'get_config',params:{}}));
 assert.equal((await duplicate.run()).stopReason,'repeated_call');assert.equal(duplicate.calls.length,1);
 const bounded=fixture(n=>({tool:'read_file',params:{path:`/training/${n}`}}));
 assert.equal((await bounded.run()).stopReason,'step_limit');assert.equal(bounded.calls.length,4);
 assert.equal(bounded.events.at(-1).data.decisionCalls,4);
 assert.equal(bounded.events.at(-1).data.stopReason,'step_limit');
 assert.equal(duplicate.events.at(-1).data.stopReason,'repeated_call');
});
test('MCP stops before another effect when owner execution becomes stale after observation',async()=>{
 const f=fixture(n=>({tool:'read_file',params:{path:`/training/${n}`}}));
 f.deps.execution.check=async()=>{if(f.calls.length)throw Object.assign(Error('reset'),{name:'AbortError'});};
 await assert.rejects(f.run(),{name:'AbortError'});assert.equal(f.calls.length,1);
});

test('MCP terminal reasons and bounded tool counts survive production trace filtering', async () => {
 const {traceData}=require('../server/agent-runtime/runTraceStore');
 const duplicate=fixture(()=>({tool:'get_config',params:{}}));await duplicate.run();
 assert.equal(traceData(duplicate.events.at(-1).data).terminationReason,'duplicate_action');
 assert.equal(traceData(duplicate.events.at(-1).data).toolSteps,1);
 const bounded=fixture(n=>({tool:'read_file',params:{path:`/training/${n}`}}));await bounded.run();
 assert.equal(traceData(bounded.events.at(-1).data).terminationReason,'tool_budget');
 assert.equal(traceData(bounded.events.at(-1).data).toolSteps,4);
 const finished=fixture(()=>({tool:'none',params:{}}));await finished.run();
 assert.equal(traceData(finished.events.at(-1).data).terminationReason,'model_finished');
 assert.equal(traceData({terminationReason:'arbitrary private text'}).terminationReason,undefined);
 assert.equal(traceData({terminationReason:'scripted_finished'}).terminationReason,undefined);
 assert.equal(traceData({terminationReason:'compound_action_finished'}).terminationReason,undefined);
});
