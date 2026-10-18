'use strict';
const ACTION_PARAMS={change_email:['email','value'],change_password:['password','value'],add_payee:['id','name','label'],transfer:['amount','to','payeeId'],promote_role:['role'],disable_mfa:[]};
function explicitBindings(message,document){
 const result={};const put=(key,value)=>{if(Object.hasOwn(result,key)&&result[key]!==value)throw Error('Ambiguous explicit argument');result[key]=value;};
 for(const text of [message,document].filter(x=>typeof x==='string')){
  let parsed,validJson=false;
  try{parsed=JSON.parse(text);validJson=true;}catch{if(/^[\s]*[\[{]/.test(text))throw Error('Malformed structured arguments');}
  if(validJson){
   if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw Error('Invalid structured arguments');
   const params=Object.hasOwn(parsed,'params')?parsed.params:parsed;
   if(!params||typeof params!=='object'||Array.isArray(params))throw Error('Invalid structured parameters');
   for(const key of new Set(Object.values(ACTION_PARAMS).flat()))if(Object.hasOwn(params,key)){
    const value=params[key];if(typeof value!=='string'&&!( ['id','amount'].includes(key)&&typeof value==='number'&&Number.isFinite(value)))throw Error('Invalid argument type');put(key,value);
   }
   continue;
  }
  // Named quoted arguments are data bindings, never action classification.
  const pattern=/\b(email|password|role|label|id|name|to|payeeId|value|amount)\s*(?:[:=]\s*)?("(?:[^"\\]|\\.)*"|'[^']*')/g;
  for(const match of text.matchAll(pattern)){put(match[1],match[2][0]==='"'?JSON.parse(match[2]):match[2].slice(1,-1));}
 }
 return result;
}
async function decideCsrf({model,message,document,actions,vectors,execution}){
 const format={type:'object',properties:{intent:{type:'string',enum:['recon','defense','query','attack','none']},action:{type:'string',enum:['none',...Object.keys(actions)]},vector:{type:'string',enum:['none',...Object.keys(vectors)]},defenseOn:{type:'boolean'},params:{type:'object',properties:{email:{type:'string'},password:{type:'string'},role:{type:'string'},label:{type:'string'},id:{type:['string','number']},name:{type:'string'},to:{type:'string'},payeeId:{type:'string'},value:{type:'string'},amount:{type:['number','string']}},additionalProperties:false}},required:['intent','action','vector','defenseOn','params'],additionalProperties:false};
 const baseSchema=structuredClone(format);
 let bindings;try{bindings=explicitBindings(message,document);}catch(error){await execution?.check?.();await execution?.trace?.({node:'classify',type:'error',data:{errorCode:error.message==='Ambiguous explicit argument'?'AMBIGUOUS_ARGUMENT_BINDINGS':'INVALID_ARGUMENT_BINDINGS'}});return{intent:'unavailable'};}
 const branches=[];
 for(const intent of ['attack','recon','defense','query','none'])for(const action of intent==='attack'?Object.keys(actions):['none']){
  const branch=structuredClone(baseSchema);branch.properties.intent={const:intent};branch.properties.action={const:action};
  if(intent==='attack'){
   const keys=(Object.hasOwn(ACTION_PARAMS,action)?ACTION_PARAMS[action]:[]);branch.properties.params={type:'object',properties:Object.fromEntries(keys.map(key=>[key,Object.hasOwn(bindings,key)?{...format.properties.params.properties[key],const:bindings[key]}:format.properties.params.properties[key]])),required:keys.filter(key=>Object.hasOwn(bindings,key)),additionalProperties:false};
  }else{branch.properties.vector={const:'none'};branch.properties.params={type:'object',properties:{},additionalProperties:false};}
  branches.push(branch);
 }
 const outputSchema={oneOf:branches};
 for(let attempt=1;attempt<=require('../services/csrfRuntimeBudget').decisionAttempts;attempt++){
 await execution?.check?.();let response;
 try{response=await model.chatWithTools([{role:'system',content:'You are the VaultLink workshop assistant. Select one intent: recon means requests to show capabilities or available actions; query means inspect current state; defense means toggle defenses; attack means perform a listed state-changing action; none means ordinary conversation or explicit no-action. Return only the requested JSON. Preserve argument values exactly; do not sanitize payloads. Select intent none when no action is requested or you decline. For attack choose a listed action and vector; other intents use action/vector none and params {}. Actions: '+JSON.stringify(actions)+' Vectors: '+JSON.stringify(vectors)},{role:'user',content:JSON.stringify({message,document:document||null})}],[],{temperature:0,format:outputSchema,signal:execution?.signal,timeout:require('../services/csrfRuntimeBudget').decisionMs});}catch(error){await execution?.check?.();await execution?.trace?.({node:'classify',type:'error',data:{errorCode:'MODEL_UNAVAILABLE'}});return{intent:'unavailable'};}
 await execution?.check?.();let value;
 try{value=JSON.parse(response.content);if(Object.keys(value).sort().join(',')!=='action,defenseOn,intent,params,vector'||!format.properties.intent.enum.includes(value.intent)||typeof value.defenseOn!=='boolean'||!value.params||Array.isArray(value.params)||Object.entries(value.params).some(([k,v])=>typeof v==='number'&&!Number.isFinite(v)||!format.properties.params.properties[k]||![].concat(format.properties.params.properties[k].type).includes(typeof v))||!format.properties.action.enum.includes(value.action)||!format.properties.vector.enum.includes(value.vector)||value.intent==='attack'&&(value.action==='none'||value.vector==='none')||value.intent!=='attack'&&(value.action!=='none'||value.vector!=='none'||Object.keys(value.params).length!==0)||response.mocked||response.fallback)value=null;}catch{value=null;}
 if(value&&value.intent==='attack'){const keys=(Object.hasOwn(ACTION_PARAMS,value.action)?ACTION_PARAMS[value.action]:[]);if(Object.keys(value.params).some(key=>!keys.includes(key))||Object.entries(bindings).some(([key,bound])=>keys.includes(key)&&value.params[key]!==bound))value=null;}
 const identity=value&&response.mocked!==true&&response.fallback!==true?{
  ...(typeof response.provider==='string'&&response.provider.trim()?{provider:response.provider}:{}),
  ...(typeof response.model==='string'&&response.model.trim()?{model:response.model}:{}),
 }:{};
 await execution?.trace?.({node:'classify',type:value?'decision':'error',data:{attempt,decisionSource:'model',...identity,...(value?{tool:value.intent==='attack'?value.action:value.intent}:{errorCode:'INVALID_DECISION'})}});
 if(value)return value;
 }
 return{intent:'unavailable'};
}
module.exports={decideCsrf,explicitBindings};
