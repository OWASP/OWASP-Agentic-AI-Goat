'use strict';
// Shared data contract only. No network, database, process or grading authority.
const {createHash}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {registryRequestDigest}=require('./secureshopMcpRegistryContract');
const {mcpSchemaDigest,mcpCanonicalJsonDigest}=require('./secureshopMcpSchemaDigest');
const manifest=require('../../sidecars/sandbox-runner/owned-mcp-registry/network-manifest.json');
const hash=value=>createHash('sha256').update(value).digest('hex');
const DISCOVERY_POLICY=Object.freeze({version:1,registrationOnly:true,fixed:Object.freeze({protocol:'http:',
 hostnames:Object.freeze(['benign.training','192.0.2.10']),port:80,pathname:'/mcp',allowQuery:false,
 allowFragment:false,allowCredentials:false}),vulnerable:'owned-namespace-only'});
const DISCOVERY_POLICY_SHA256=hash(JSON.stringify(DISCOVERY_POLICY));
const SHA=/^[a-f0-9]{64}$/;
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
 &&equal(Object.keys(value).sort(),[...keys].sort())
 &&Object.values(Object.getOwnPropertyDescriptors(value)).every(d=>Object.hasOwn(d,'value'));
const fail=()=>{throw Object.assign(Error('Invalid MCP discovery receipt'),{code:'MCP_REGISTRY_DISCOVERY_RECEIPT_INVALID'});};
function validateDiscoveryReceipt(value,{request,tools,endpoint}={}){
 if(!exact(value,['version','operationId','registryRequestSha256','endpointSha256','policySha256','destination',
  'toolsListRequestBody','toolsListRequestSha256','toolsListResponse','toolsListResponseSha256','schemaSha256'])
  ||value.version!==1||request?.action!=='register'||!['sse','streamable-http'].includes(request.transport)
  ||endpoint!==request.url||value.operationId!==request.operationId
  ||value.registryRequestSha256!==registryRequestDigest(request)||value.endpointSha256!==hash(endpoint)
  ||value.policySha256!==DISCOVERY_POLICY_SHA256||!exact(value.destination,['listenerId','address','port','sensitive'])
  ||!manifest.listeners.some(peer=>equal(value.destination,{listenerId:peer.id,address:peer.address,port:peer.port,sensitive:peer.sensitive}))
  ||!['registryRequestSha256','endpointSha256','policySha256','toolsListRequestSha256','toolsListResponseSha256','schemaSha256'].every(k=>SHA.test(value[k]||''))
  ||typeof value.toolsListRequestBody!=='string'||!value.toolsListRequestBody.isWellFormed()
  ||Buffer.byteLength(value.toolsListRequestBody)>65536||value.toolsListRequestBody.includes('\0')
  ||hash(value.toolsListRequestBody)!==value.toolsListRequestSha256)fail();
 let body;try{body=JSON.parse(value.toolsListRequestBody);}catch{fail();}
 if(!body||body.jsonrpc!=='2.0'||body.method!=='tools/list'
  ||!(typeof body.id==='string'&&body.id.length>0&&body.id.length<=128||Number.isSafeInteger(body.id))
  ||!Array.isArray(value.toolsListResponse?.tools)||value.toolsListResponse.tools.length<1
  ||value.toolsListResponse.tools.length>64||Buffer.byteLength(JSON.stringify(value.toolsListResponse))>262144
  ||mcpCanonicalJsonDigest(value.toolsListResponse)!==value.toolsListResponseSha256
  ||value.schemaSha256!==mcpSchemaDigest(value.toolsListResponse.tools)
  ||!Array.isArray(tools)||!equal(tools,value.toolsListResponse.tools)||mcpSchemaDigest(tools)!==value.schemaSha256)fail();
 return structuredClone(value);
}
function validateDiscoveryDenial(value,{request,mode}={}){
 if(!exact(value,['version','error','effectNotStarted','operationId','registryRequestSha256','policySha256'])
  ||mode!=='fixed'||request?.action!=='register'||!['sse','streamable-http'].includes(request.transport)
  ||value.version!==1||value.error!=='MCP_REGISTRY_FIXED_DESTINATION_DENIED'||value.effectNotStarted!==true
  ||value.operationId!==request.operationId||value.registryRequestSha256!==registryRequestDigest(request)
  ||value.policySha256!==DISCOVERY_POLICY_SHA256)fail();
 return structuredClone(value);
}
module.exports={DISCOVERY_POLICY,DISCOVERY_POLICY_SHA256,validateDiscoveryReceipt,validateDiscoveryDenial};
