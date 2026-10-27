'use strict';
const {createHash}=require('node:crypto');
// A deterministic copy boundary, NOT a semantic disclosure Judge. NFKC, case
// and whitespace normalization do not detect paraphrase, translation or encoding.
const POLICY_VERSION='original-customer-literal-normalized-copy-v1';
const LIMITS=Object.freeze({sourceBytes:262144,decisionBytes:131072,nodes:8192,depth:24});
const fail=code=>Object.assign(new Error(code),{code,executionBoundary:true});
const digest=value=>createHash('sha256').update(value,'utf8').digest('hex');
const normalize=value=>value.normalize('NFKC').toLowerCase().replace(/\s+/gu,' ').trim();
function snapshot(value){
  let nodes=0;
  const seen=new Set();
  function visit(item,depth){
    if(++nodes>LIMITS.nodes||depth>LIMITS.depth)throw fail('CUSTOMER_DISCLOSURE_DECISION_INVALID');
    if(item===null||typeof item==='string'||typeof item==='boolean')return item;
    if(typeof item==='number'&&Number.isFinite(item))return item;
    if(!item||typeof item!=='object'||seen.has(item)||(!Array.isArray(item)&&Object.getPrototypeOf(item)!==Object.prototype))throw fail('CUSTOMER_DISCLOSURE_DECISION_INVALID');
    if(Array.isArray(item)&&item.length>LIMITS.nodes)throw fail('CUSTOMER_DISCLOSURE_DECISION_INVALID');
    seen.add(item);
    const result=Array.isArray(item)?[]:{};
    for(const key of Reflect.ownKeys(item)){
      if(Array.isArray(item)&&key==='length')continue;
      const descriptor=Object.getOwnPropertyDescriptor(item,key);
      if(typeof key!=='string'||!descriptor.enumerable||!Object.hasOwn(descriptor,'value'))throw fail('CUSTOMER_DISCLOSURE_DECISION_INVALID');
      Object.defineProperty(result,key,{value:visit(descriptor.value,depth+1),enumerable:true});
    }
    seen.delete(item);return Object.freeze(result);
  }
  const result=visit(value,0);
  if(Buffer.byteLength(JSON.stringify(result))>LIMITS.decisionBytes)throw fail('CUSTOMER_DISCLOSURE_DECISION_INVALID');
  return result;
}
function createProtectedSourceDecision(system,{publicToolNames=[]}={}){
  if(!Array.isArray(publicToolNames)||publicToolNames.some(name=>typeof name!=='string'||! /^[a-z][a-z0-9-]*\.[a-z][a-z0-9_]*$/.test(name)))throw fail('CUSTOMER_DISCLOSURE_SOURCE_INVALID');
  const catalogNames=new Set(publicToolNames);
  if(typeof system!=='string'||!system.trim()||Buffer.byteLength(system)>LIMITS.sourceBytes)throw fail('CUSTOMER_DISCLOSURE_SOURCE_INVALID');
  const normalized=normalize(system),windows=new Set(),fragments=new Set();
  // Any 48-character normalized source run, complete >=24-character line, or
  // complete >=16-character source token (sans sentence-edge punctuation) is
  // protected. No witness is hardcoded.
  for(let i=0;i+48<=normalized.length;i++)windows.add(normalized.slice(i,i+48));
  for(const line of system.split(/\r?\n/u)){const s=normalize(line);if(s.length>=24)fragments.add(s);}
  for(const token of normalized.split(' ')){
    const bare=token.replace(/^[.,;:!?"'`]+|[.,;:!?"'`]+$/gu,'');
    if(bare.length>=16)fragments.add(bare);
  }
  const strings=(value,publicRows)=>{
    if(typeof value==='string')return[value];
    if(!value||typeof value!=='object')return[];
    return Object.entries(value).flatMap(([key,item])=>[key,...(key==='name'&&publicRows.has(value)?[]:strings(item,publicRows))]);
  };
  function inspect(value,providerDecision=false){
      const result=snapshot(value),publicRows=new Set();
      // Only the normalized provider routing field may be public. Tool results
      // always use inspect(), never this decision-only exception.
      if(providerDecision&&result&&result.stop_reason==='tool_use'&&Array.isArray(result.tool_uses)){
        for(const row of result.tool_uses){
          if(row&&Object.getPrototypeOf(row)===Object.prototype&&Object.keys(row).sort().join(',')==='args,id,name'&&typeof row.id==='string'&&row.args&&Object.getPrototypeOf(row.args)===Object.prototype&&catalogNames.has(row.name))publicRows.add(row);
        }
      }
      for(const raw of strings(result,publicRows)){
        const text=normalize(raw);
        if([...fragments].some(fragment=>text.includes(fragment)))throw fail('CUSTOMER_DISCLOSURE_BLOCKED');
        for(let i=0;i+48<=text.length;i++)if(windows.has(text.slice(i,i+48)))throw fail('CUSTOMER_DISCLOSURE_BLOCKED');
      }
      return result;
  }
  return Object.freeze({sourceSha256:digest(system),policyVersion:POLICY_VERSION,
    inspect:value=>inspect(value),inspectDecision:value=>inspect(value,true),
  });
}
module.exports={createProtectedSourceDecision,POLICY_VERSION,LIMITS,digest};
