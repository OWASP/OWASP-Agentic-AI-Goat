'use strict';
const {createHash}=require('node:crypto');
function canonical(value){if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}';return JSON.stringify(value);}
function canonicalDigest(value){return createHash('sha256').update(canonical(require('../../../server/services/secureshopOwnedMcpInvocationContract').bounded(value,196608))).digest('hex');}
const {mcpSchemaDigest}=require('../../../server/services/secureshopMcpSchemaDigest');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail=()=>{throw Object.assign(Error('Owned registry invocation invalid'),{code:'MCP_REGISTRY_INVOCATION_INVALID'});};
function exact(v,keys){if(!v||Array.isArray(v)||Object.keys(v).sort().join()!==keys.sort().join())fail();}
function request(raw){
 const q=require('../../../server/services/secureshopOwnedMcpInvocationContract').bounded(raw,131072);
 exact(q,['version','instanceId','operationId','entry','toolName','args']);exact(q.entry,['entryId','registryVersion','transport','endpoint','schemaSha256','tools']);
 const e=q.entry;if(q.version!==1||!UUID.test(q.instanceId)||!UUID.test(q.operationId)||!UUID.test(e.entryId)||!/^[1-9][0-9]{0,15}$/.test(e.registryVersion)||!Number.isSafeInteger(Number(e.registryVersion))||!['sse','streamable-http','stdio'].includes(e.transport)||typeof e.endpoint!=='string'||!e.endpoint||Buffer.byteLength(e.endpoint)>8192||!Array.isArray(e.tools)||e.tools.length<1||e.tools.length>64||mcpSchemaDigest(e.tools)!==e.schemaSha256||typeof q.toolName!=='string'||e.tools.filter(t=>t.name===q.toolName).length!==1||!q.args||Array.isArray(q.args)||typeof q.args!=='object'||Buffer.byteLength(JSON.stringify(q.args))>16384)fail();
 const names=new Set();for(const tool of e.tools){if(!tool||typeof tool.name!=='string'||!tool.name.trim()||Buffer.byteLength(tool.name)>256||names.has(tool.name)||tool.description!==undefined&&typeof tool.description!=='string'||tool.inputSchema?.type!=='object')fail();names.add(tool.name);}
 try{const {AjvJsonSchemaValidator}=require('@modelcontextprotocol/sdk/validation/ajv');const validate=new AjvJsonSchemaValidator().getValidator(e.tools.find(t=>t.name===q.toolName).inputSchema);if(validate(q.args).valid!==true)fail();}catch{fail();}
 if(e.transport!=='stdio'){let url;try{url=new URL(e.endpoint);}catch{fail();}if(!['http:','https:'].includes(url.protocol)||url.username||url.password)fail();}
 return q;
}
async function callCapturedTool(raw,client,{signal}={}){
 const q=request(raw);signal?.throwIfAborted();
 const found=await require('../../../server/services/secureshopMcpRegistryDiscovery').discoverRegistryTools(client,{signal});
 if(found.schemaSha256!==q.entry.schemaSha256||canonicalDigest(found.tools)!==canonicalDigest(q.entry.tools))fail();
 signal?.throwIfAborted();const result=await client.callTool({name:q.toolName,arguments:q.args},undefined,{signal,timeout:10000,maxTotalTimeout:10000,resetTimeoutOnProgress:false});
 signal?.throwIfAborted();if(Buffer.byteLength(JSON.stringify(result))>65536)fail();
 return receipt({version:1,instanceId:q.instanceId,operationId:q.operationId,entryId:q.entry.entryId,registryVersion:q.entry.registryVersion,requestSha256:canonicalDigest(q),schemaSha256:q.entry.schemaSha256,endpointSha256:canonicalDigest(q.entry.endpoint),argumentsSha256:canonicalDigest(q.args),resultSha256:canonicalDigest(result),result,isolation:'owned-mcp-registry-v1'},q);
}
function receipt(raw,rawRequest){
 const q=request(rawRequest),v=require('../../../server/services/secureshopOwnedMcpInvocationContract').bounded(raw,98304);
 exact(v,['version','instanceId','operationId','entryId','registryVersion','requestSha256','schemaSha256','endpointSha256','argumentsSha256','resultSha256','result','isolation']);
 if(!v.result||Array.isArray(v.result)||typeof v.result!=='object'||!Array.isArray(v.result.content)||!require('@modelcontextprotocol/sdk/types.js').CallToolResultSchema.safeParse(v.result).success)fail();
 const expected={version:1,instanceId:q.instanceId,operationId:q.operationId,entryId:q.entry.entryId,registryVersion:q.entry.registryVersion,requestSha256:canonicalDigest(q),schemaSha256:q.entry.schemaSha256,endpointSha256:canonicalDigest(q.entry.endpoint),argumentsSha256:canonicalDigest(q.args),resultSha256:canonicalDigest(v.result),isolation:'owned-mcp-registry-v1'};
 if(Object.entries(expected).some(([k,value])=>v[k]!==value)||Buffer.byteLength(JSON.stringify(v.result))>65536)fail();return v;
}
module.exports={request,receipt,callCapturedTool,digest:canonicalDigest};
