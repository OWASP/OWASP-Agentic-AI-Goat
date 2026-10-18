'use strict';
// V2 binds the current explicit8192 actor context; V1 remains historical.
// Fixture binding only: the caller must capture the actual canonical invocation.
// This does not authenticate actor evidence, prove semantics, or authorize credit.
const {isDeepStrictEqual}=require('node:util');
const MODEL='llama3.1:8b',LIMIT=262144;
function deny(){throw Object.assign(new Error('DPI request contract rejected'),{code:'DPI_REQUEST_CONTRACT_INVALID'});}
function object(v){if(!v||Object.getPrototypeOf(v)!==Object.prototype)deny();return v;}
function keys(v,allowed){object(v);if(Reflect.ownKeys(v).some(k=>typeof k!=='string'||!allowed.includes(k)))deny();}
function snapshot(value){
  const visit=(v,depth=0)=>{if(depth>40)deny();if(v===null||typeof v==='string'||typeof v==='boolean')return;
    if(typeof v==='number'&&Number.isFinite(v))return;
    if(Array.isArray(v)){for(const x of v)visit(x,depth+1);return;}
    object(v);for(const k of Reflect.ownKeys(v)){const d=Object.getOwnPropertyDescriptor(v,k);if(typeof k!=='string'||!d.enumerable||!('value'in d))deny();visit(d.value,depth+1);}};
  visit(value);const raw=JSON.stringify(value);if(Buffer.byteLength(raw)>LIMIT)deny();return JSON.parse(raw);
}
function createRequestContract({model=MODEL}={}){
  if(model!==MODEL)deny();let active=null,pending=null;const retired=new Set(),tokens=new WeakMap();
  return Object.freeze({
    beginCase(id){if(active!==null||typeof id!=='string'||!id.length||id.length>128||retired.has(id))deny();active=id;},
    expect({caseId,kind,messages,tools,options}){
      if(active!==caseId||active===null||pending||!['judge','actor'].includes(kind))deny();
      if(!Array.isArray(tools)||tools.length||!Array.isArray(messages)||messages.length<2||(kind==='judge'&&messages.length!==2))deny();
      for(let i=0;i<messages.length;i++){
        keys(messages[i],['role','content']);
        const allowed=i===0?['system']:i===messages.length-1?['user']:['user','assistant'];
        if(!allowed.includes(messages[i].role)||typeof messages[i].content!=='string')deny();
      }
      keys(options,['temperature','max_tokens','num_predict','num_ctx','format','signal','timeout','ownerId']);
      if(options.signal?.aborted)deny();
      if(options.timeout!==undefined&&(!Number.isFinite(options.timeout)||options.timeout<=0))deny();
      const output=kind==='judge'?900:1024,temp=kind==='judge'?0:0.6;
      if(options.temperature!==temp||(options.num_predict??options.max_tokens)!==output)deny();
      for(const k of ['max_tokens','num_predict'])if(options[k]!==undefined&&options[k]!==output)deny();
      if(kind==='judge'){if(options.num_ctx!==32768||!options.format)deny();object(options.format);}
      else if(Object.hasOwn(options,'num_ctx')||Object.hasOwn(options,'format'))deny();
      const expected={model,messages:snapshot(messages),stream:true,options:{temperature:temp,num_predict:output}};
      expected.options.num_ctx=kind==='judge'?32768:8192;
      if(kind==='judge'){expected.format=snapshot(options.format);}
      const token=Object.freeze({});tokens.set(token,{caseId,expected:snapshot(expected),signal:options.signal});pending=token;return token;
    },
    validate(token,{caseId,method,path,body}){
      const entry=tokens.get(token);if(!entry||pending!==token)deny();tokens.delete(token);pending=null;
      if(active!==caseId||entry.caseId!==caseId||entry.signal?.aborted||method!=='POST'||path!=='/api/chat')deny();
      if(typeof body!=='string'||Buffer.byteLength(body)>LIMIT)deny();
      let wire;try{wire=JSON.parse(body);}catch{deny();}
      if(!isDeepStrictEqual(wire,entry.expected))deny();return true;
    },
    endCase(){if(active===null)deny();if(pending)tokens.delete(pending);pending=null;retired.add(active);active=null;}
  });
}
module.exports={createRequestContract};
