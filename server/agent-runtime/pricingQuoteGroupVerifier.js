'use strict';
// Versioned transport schema around the unchanged historical semantic verifier.
const {createPricingDirectiveGroupComparison}=require('./pricingDirectiveGroupVerifier');
const {resolveExactQuote,sha,MAX_FIELD_BYTES,MAX_QUOTE_BYTES}=require('./exactQuoteResolver');
const VERSION='pricing-directive-quotes-v2',MAX_QUOTES=2048;
function quoteSchema(value){
 if(!value||typeof value!=='object')return value;
 if(value.type==='object'&&value.properties?.start&&value.properties?.end&&value.properties?.text)return{type:'string',minLength:1,maxLength:MAX_QUOTE_BYTES};
 if(Array.isArray(value))return value.map(quoteSchema);
 return Object.fromEntries(Object.entries(value).map(([key,child])=>[key,quoteSchema(child)]));
}
const QUOTES=' Return citations as exact nonempty quote strings from the complete indicated source or response. Do not calculate offsets. Each quote must occur exactly once in that complete field; include enough surrounding context to distinguish repeated text. Never normalize, paraphrase, trim or invent a quote. A valid quote does not establish the semantic claim it cites.';
function createPricingQuoteGroupComparison(spec,evidence){
 if(spec.supportContract!==VERSION)throw Error('Pricing quote protocol mismatch');
 const read=id=>evidence.find(e=>e.id===id)?.content;
 const source=read(spec.sourceEvidenceId),response=read(spec.responseEvidenceId),task=read(spec.taskEvidenceId);
 if([source,response,task].some(x=>typeof x!=='string'||!x.isWellFormed()||Buffer.byteLength(x)>MAX_FIELD_BYTES))throw Error('Pricing quote field unavailable');
 const base=createPricingDirectiveGroupComparison({...spec,supportContract:'pricing-directive-groups-v1'},evidence);
 const instructions=value=>value.replace('Offsets are UTF-16 code units into original_source; never split a Unicode code point.','').replace('exact UTF-16 response spans','exact response quotes')+QUOTES;
 const policy=Object.freeze({...base.policy,version:VERSION,offsets:'server_resolved_unique_exact_quote_v1',sourceInstructions:instructions(base.policy.sourceInstructions),effectInstructions:instructions(base.policy.effectInstructions),supportInstructions:instructions(base.policy.supportInstructions),sourceFormat:quoteSchema(base.policy.sourceFormat),effectFormat:quoteSchema(base.policy.effectFormat),supportFormat:quoteSchema(base.policy.supportFormat),quoteBounds:{maximumQuotes:MAX_QUOTES,maximumFieldBytes:MAX_FIELD_BYTES,maximumQuoteBytes:MAX_QUOTE_BYTES}});
 let sourceBindings=[],responseBindings=[];
 const prepared=(value,stage)=>({...value,messages:value.messages.map((m,i)=>i===0?{...m,content:instructions(m.content)}:m),format:policy[stage+'Format']});
 function convert(text,field,kind){
  const value=JSON.parse(text),bindings=[];
  const resolve=quote=>{if(bindings.length>=MAX_QUOTES)throw Error('Quote count exceeded');const span=resolveExactQuote(field,quote);bindings.push({field:kind,start:span.start,end:span.end,quoteSha256:sha(quote)});return span;};
  // Only declared citation positions are transformed; unknown keys remain for strict rejection.
  if(Array.isArray(value.groups))for(const group of value.groups){
   for(const key of kind==='source'?['sourceSpans']:['adoptionSpans'])if(Array.isArray(group[key]))group[key]=group[key].map(resolve);
   if(Array.isArray(group.conditions))for(const condition of group.conditions){
    const key=kind==='source'?'sourceSpans':'responseSpans';if(Array.isArray(condition[key]))condition[key]=condition[key].map(resolve);
    if(kind==='source'&&condition.constraintSpan!==null&&condition.constraintSpan!==undefined)condition.constraintSpan=resolve(condition.constraintSpan);
   }
  }
  return{value,bindings};
 }
 function audited(value){return{...value,observation:{...value.observation,citationResolution:{version:'unique-exact-quotes-v1',sourceSha256:sha(source),responseSha256:sha(response),taskSha256:sha(task),spans:[...sourceBindings,...responseBindings].map(s=>({...s}))}}};}
 const pending=new WeakMap();
 return{policy,
  sourceMessages:error=>prepared(base.sourceMessages(error),'source'),
  validateSource(text){const resolved=convert(text,source,'source');const value=base.validateSource(JSON.stringify(resolved.value));sourceBindings=resolved.bindings;return value;},
  effectMessages:(value,error)=>prepared(base.effectMessages(value,error),'effect'),
  validateEffect(text,value){const result=base.validateEffect(text,value),out=audited(result);if(result.pending){pending.set(out,result);Object.freeze(out);}return out;},
  needsSupport:value=>pending.has(value),
  supportMessages(value,error){if(!pending.has(value))throw Error('Unbound quote stage');return prepared(base.supportMessages(pending.get(value),error),'support');},
  validateSupport(text,value){if(!pending.has(value))throw Error('Unbound quote stage');const resolved=convert(text,response,'response');if(sourceBindings.length+resolved.bindings.length>MAX_QUOTES)throw Error('Aggregate quote count exceeded');const result=base.validateSupport(JSON.stringify(resolved.value),pending.get(value));responseBindings=resolved.bindings;return audited(result);},
  sourceOnlyResult:value=>audited(base.sourceOnlyResult(value)),
  projectCriteria:(criteria,value)=>base.projectCriteria(criteria,value)
 };
}
module.exports={createPricingQuoteGroupComparison,VERSION};
