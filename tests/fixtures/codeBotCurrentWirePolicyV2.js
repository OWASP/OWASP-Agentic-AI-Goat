'use strict';
// Closed current CodeBot wire grammar with the qualified Ollama context default.
const assert=require('node:assert/strict');
const MODEL='llama3.1:8b';
const REPAIR={type:'object',properties:{action:{type:'string',enum:['check_dependencies','none']}},required:['action'],additionalProperties:false};
function requestRole(v){return v.options?.num_predict===900?'judge':'actor';}
function validateRequest(method,url,body){
 if(method==='GET'){assert.equal(url,'/api/tags');assert.equal(body.length,0);return 'tags';}
 assert.equal(method,'POST');assert.equal(url,'/api/chat');assert(body.length>0&&body.length<=262144);
 const v=JSON.parse(body);assert.equal(v.model,MODEL);assert([true,false].includes(v.stream));
 assert(Object.keys(v).every(k=>['model','stream','options','format','messages','tools'].includes(k)));
 assert(Array.isArray(v.messages)&&v.messages.length);const o=v.options;assert(o&&typeof o==='object'&&!Array.isArray(o));
 assert(Object.keys(o).every(k=>['temperature','num_predict','num_ctx','top_p','top_k','stop'].includes(k)));
 if(requestRole(v)==='judge'){assert.equal(o.temperature,0);assert.equal(o.num_predict,900);assert.equal(o.num_ctx,32768);assert(v.format&&typeof v.format==='object');assert(!v.tools||v.tools.length===0);}
 else{assert.equal(o.num_predict,1024);assert.equal(o.num_ctx,8192);
  if(o.temperature===0){assert.deepEqual(v.format,REPAIR);assert(!v.tools||v.tools.length===0);}
  else{assert.equal(o.temperature,0.3);assert.equal(v.format,undefined);if(v.tools?.length)assert.deepEqual(v.tools,require('../../server/services/supplyChainWorkshopAgent').CODEBOT_TOOL_SCHEMAS);}
 }
 if(o.top_p!==undefined)assert(Number.isFinite(o.top_p)&&o.top_p>=0&&o.top_p<=1);
 if(o.top_k!==undefined)assert(Number.isInteger(o.top_k)&&o.top_k>=0&&o.top_k<=100);
 if(o.stop!==undefined)assert(Array.isArray(o.stop)&&o.stop.length<=8&&o.stop.every(x=>typeof x==='string'&&Buffer.byteLength(x)<=128));
 return 'chat';
}
function validateToolFrames(frames,row){
 const actor=requestRole(JSON.parse(row.request))==='actor';
 for(const frame of frames){assert(!frame.tool_calls);if(frame.message?.tool_calls!==undefined){assert(actor);assert(Array.isArray(frame.message.tool_calls));for(const call of frame.message.tool_calls){assert.equal(typeof call.function?.name,'string');assert(call.function.arguments&&typeof call.function.arguments==='object'&&!Array.isArray(call.function.arguments));}}}
}
module.exports={validateRequest,requestRole,validateToolFrames,REPAIR};
