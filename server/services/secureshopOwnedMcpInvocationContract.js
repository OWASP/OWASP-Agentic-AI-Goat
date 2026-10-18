'use strict';
// Unwired candidate protocol. No URL resolution, process spawn or credit.
const {createHash}=require('node:crypto');
const {createConversationBinding}=require('./secureshopConversationBinding');
const {mcpSchemaDigest}=require('./secureshopMcpSchemaDigest');
const VERSION='owned-mcp-invocation-v1',UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail=()=>{throw Object.assign(new Error('Invalid owned MCP invocation contract'),{code:'MCP_INVOCATION_INVALID'});};
function data(value,depth=0,budget={nodes:0,chars:0}){
 if(depth>16||++budget.nodes>16384)fail();
 if(value===null||typeof value==='boolean')return value;
 if(typeof value==='string'){if((budget.chars+=value.length)>131072||!value.isWellFormed()||value.includes('\0'))fail();return value;}
 if(typeof value==='number'){if(!Number.isFinite(value))fail();return value;}
 if(!value||typeof value!=='object'||(!Array.isArray(value)&&![Object.prototype,null].includes(Object.getPrototypeOf(value))))fail();
 const descriptors=Object.getOwnPropertyDescriptors(value);
 if(Reflect.ownKeys(descriptors).some(key=>typeof key!=='string'||(!Array.isArray(value)||key!=='length')&&(!Object.hasOwn(descriptors[key],'value')||!descriptors[key].enumerable)))fail();
 if(Array.isArray(value)){if(Reflect.ownKeys(value).length!==value.length+1||Object.keys(value).some((key,index)=>key!==String(index)))fail();return value.map(item=>data(item,depth+1,budget));}
 return Object.fromEntries(Object.keys(value).sort().map(key=>[key,data(descriptors[key].value,depth+1,budget)]));
}
function bounded(value,max=65536){const copy=data(value);if(Buffer.byteLength(JSON.stringify(copy))>max)fail();return copy;}
function digest(value){return createHash('sha256').update(JSON.stringify(data(value))).digest('hex');}
function freeze(value){if(value&&typeof value==='object'){for(const item of Object.values(value))freeze(item);Object.freeze(value);}return value;}
function exact(value,keys){if(!value||Array.isArray(value)||Object.keys(value).sort().join()!==keys.slice().sort().join())fail();}
function snapshot(raw){
 const v=bounded(raw,98304);exact(v,['binding','entryId','registryVersion','schemaSha256','tools']);
 const binding=createConversationBinding(v.binding,{id:v.binding.shopUserId,role:v.binding.role});
 if(digest(binding)!==digest(v.binding)||binding.role!=='admin'||typeof v.entryId!=='string'||!UUID.test(v.entryId)||typeof v.registryVersion!=='string'||! /^[1-9][0-9]{0,18}$/.test(v.registryVersion)||BigInt(v.registryVersion)>9223372036854775807n)fail();
 if(!Array.isArray(v.tools)||!v.tools.length||v.tools.length>64||Buffer.byteLength(JSON.stringify(v.tools))>65536||mcpSchemaDigest(v.tools)!==v.schemaSha256)fail();
 const names=new Set();for(const tool of v.tools){if(!tool||typeof tool.name!=='string'||!tool.name.trim()||Buffer.byteLength(tool.name)>256||names.has(tool.name)||typeof tool.description!=='string'||tool.inputSchema?.type!=='object')fail();names.add(tool.name);}
 return freeze({...v,binding});
}
function request({snapshot:raw,runId,requestId,callId,toolIndex,args,mode}){
 const s=snapshot(raw),argumentsValue=bounded(args,16384);
 if(typeof runId!=='string'||!UUID.test(runId)||typeof requestId!=='string'||!UUID.test(requestId)||typeof callId!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(callId)||!Number.isInteger(toolIndex)||!s.tools[toolIndex]||!['vuln','fixed'].includes(mode)||!argumentsValue||Array.isArray(argumentsValue)||typeof argumentsValue!=='object')fail();
 return freeze({version:VERSION,snapshotSha256:digest(s),binding:s.binding,entryId:s.entryId,registryVersion:s.registryVersion,schemaSha256:s.schemaSha256,runId,requestId,callId,toolName:s.tools[toolIndex].name,args:argumentsValue,argumentsSha256:digest(argumentsValue),mode});
}
function receipt(raw,req,policy){
 const v=bounded(raw,131072);exact(v,['version','requestSha256','result','resultSha256','policySha256','approved','receiptSha256']);
 if(v.version!==VERSION||v.requestSha256!==digest(req)||v.resultSha256!==digest(v.result)||v.policySha256!==policy.policySha256||v.approved!==policy.approved||typeof v.receiptSha256!=='string'||!/^[0-9a-f]{64}$/.test(v.receiptSha256))fail();
 const {receiptSha256,...body}=v;if(digest(body)!==receiptSha256)fail();return freeze(v);
}
module.exports={VERSION,snapshot,request,receipt,digest,bounded,freeze};
