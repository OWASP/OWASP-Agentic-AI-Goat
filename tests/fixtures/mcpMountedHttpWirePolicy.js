'use strict';
const assert=require('node:assert/strict');
const MODEL='llama3.1:8b';
function requestRole(url,v){
 if(url==='/api/generate')return 'phrase';
 return v.options.num_predict===1024?(v.format?.oneOf?.[0]?.properties?.action?'observed':'actor'):'judge';
}
function validateRequest(method,url,body,{poisoning=false,positive=false,recon=false,recon70b=false}={}){
 assert.equal(typeof recon70b,'boolean');if(recon70b)assert.equal(recon,true);
 if(method==='GET'){assert.equal(url,'/api/tags');assert.equal(body.length,0);return 'tags';}
 assert.equal(method,'POST');assert(['/api/chat','/api/generate'].includes(url));assert(body.length>0&&body.length<=262144);
 const v=JSON.parse(body);assert.equal(v.model,recon70b?'llama3.3:70b':MODEL);assert([true,false].includes(v.stream));
 const keys=['model','stream','options','format',...(url==='/api/chat'?['messages','tools']:['prompt','system','template','raw','keep_alive'])];assert(Object.keys(v).every(k=>keys.includes(k)));
 const o=v.options;assert(o&&typeof o==='object'&&!Array.isArray(o));assert(Object.keys(o).every(k=>['temperature','num_predict','num_ctx','top_p','top_k','stop'].includes(k)));
 const role=requestRole(url,v);if(poisoning&&!positive)assert.notEqual(role,'judge');if(!poisoning) assert.notEqual(role,'observed');
 if(role==='phrase'){assert.equal(o.temperature,0.4);assert([260,500].includes(o.num_predict));assert(o.num_ctx===undefined||o.num_ctx===8192);assert.equal(typeof v.prompt,'string');assert.equal(v.format,undefined);}
 else{
  assert.equal(o.temperature,0);assert(Array.isArray(v.messages)&&v.messages.length>0);assert(!v.tools||v.tools.length===0);assert(v.format&&typeof v.format==='object'&&!Array.isArray(v.format));
  if(role==='observed'){assert(poisoning);assert.equal(o.num_predict,1024);assert(o.num_ctx===undefined||o.num_ctx===8192);assert.deepEqual(v.format,require('../../server/agent-runtime/mcpDecision').observedActionSchema('tool_poisoning'));}
  else if(role==='actor'){
   assert(o.num_ctx===undefined||o.num_ctx===8192);const schema=require('../../server/agent-runtime/mcpDecision').schema;
   assert.deepEqual(Object.keys(v.format),['oneOf']);assert(Array.isArray(v.format.oneOf)&&v.format.oneOf.length>0);
   const seen=new Set();for(const branch of v.format.oneOf){const name=branch?.properties?.tool?.const;assert(!seen.has(name));seen.add(name);assert.deepEqual(branch,schema.oneOf.find(b=>b.properties.tool.const===name));}
  }else{assert.equal(o.num_predict,900);assert.equal(o.num_ctx,32768);}
 }
 if(o.top_p!==undefined)assert(Number.isFinite(o.top_p)&&o.top_p>=0&&o.top_p<=1);
 if(o.top_k!==undefined)assert(Number.isInteger(o.top_k)&&o.top_k>=0&&o.top_k<=100);
 if(o.stop!==undefined)assert(Array.isArray(o.stop)&&o.stop.length<=8&&o.stop.every(x=>typeof x==='string'&&Buffer.byteLength(x)<=128));
 return url==='/api/chat'?'chat':'generate';
}
module.exports={validateRequest,requestRole};
