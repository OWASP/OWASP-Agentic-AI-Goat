'use strict';
// Explicit synthetic dependencies for the full-index diagnostic only. No actual
// provider transport, no genuine model/effect qualification claim.
const Module=require('node:module'),path=require('node:path'),fs=require('node:fs');
const root=fs.realpathSync(process.env.CSRF_FULL_INDEX_ROOT),source=process.cwd(),load=Module._load;let actorCalls=0,judgeCalls=0;
const record=()=>fs.writeFileSync(path.join(root,'csrf-controlled-provider.json'),JSON.stringify({controlled:true,actualModelCalls:0,actorCalls,judgeCalls}),{mode:0o600});
const model={generate:async()=>{judgeCalls++;record();return{response:JSON.stringify({verdict:'pass',explanation:'Synthetic diagnostic Judge, not actual credit evidence.',criteria:[{id:'observed_outcome',satisfied:true,evidenceRefs:['action']}]}),provider:'controlled-diagnostic',model:'synthetic-judge'};}};
Module._load=function(name,...args){const result=load.call(this,name,...args),resolved=Module._resolveFilename(name,args[0]);
 if(resolved===path.join(source,'server/services/multiProviderAIService.js'))return new Proxy(result,{get(target,key){if(key==='provider')return'controlled-diagnostic';if(key==='chatWithTools')return async()=>{actorCalls++;record();return{content:JSON.stringify({intent:'attack',action:'change_email',vector:'direct_get',defenseOn:false,params:{email:'managed-owned@fixture.invalid'}}),provider:'controlled-diagnostic',model:'synthetic-actor'};};if(key==='generateResponse')return async()=>({response:'Controlled diagnostic account-change narration.',provider:'controlled-diagnostic',model:'synthetic-actor'});const value=Reflect.get(target,key);return typeof value==='function'?value.bind(target):value;}});
 if(resolved===path.join(source,'server/agent-runtime/objectiveJudge.js'))return {...result,createObjectiveJudge:options=>result.createObjectiveJudge({...options,model})};return result;
};record();
