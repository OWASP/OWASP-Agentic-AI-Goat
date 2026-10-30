'use strict';
const {randomUUID,createHash}=require('node:crypto');
const {Client}=require('@modelcontextprotocol/sdk/client');
const {AjvJsonSchemaValidator}=require('@modelcontextprotocol/sdk/validation/ajv');
const fail=code=>Object.assign(new Error('Shadow MCP protocol operation unavailable'),{code});
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function bounded(value,bytes,depth=0){
 if(depth>8)throw fail('SHADOW_LIMIT');
 if(value&&typeof value==='object')for(const [key,item]of Object.entries(value)){if(['__proto__','prototype','constructor','$ref','$dynamicRef'].includes(key))throw fail('SHADOW_SCHEMA_UNSUPPORTED');bounded(item,bytes,depth+1);}
 if(Buffer.byteLength(JSON.stringify(value))>bytes)throw fail('SHADOW_LIMIT');
 return value;
}
function binding(scope){
 if(!Number.isSafeInteger(scope?.ownerId)||scope.ownerId<1||!Number.isSafeInteger(scope?.platformSessionId)||scope.platformSessionId<1
  ||!/^\d+$/.test(scope?.generation)||!Number.isSafeInteger(Number(scope.generation))
  ||!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(scope?.targetId||''))throw fail('SHADOW_SCOPE_REQUIRED');
 return Object.freeze({ownerId:scope.ownerId,platformSessionId:scope.platformSessionId,targetId:scope.targetId,generation:scope.generation});
}
// Deliberately NOT a production authority constructor. The owned namespace
// connector, durable receipt protocol and graph/Judge wiring are not qualified.
// DI fixtures exercise real SDK traffic without granting an objective capability.
function createShadowSdkProtocolFixture({connector,checkCurrent,timeoutMs=3000}={}){
 if(typeof connector?.open!=='function'||typeof checkCurrent!=='function'||!Number.isInteger(timeoutMs)||timeoutMs<50||timeoutMs>10000)throw new TypeError('Controlled connector and authority required');
 const handles=new WeakMap(),live=new Set();
 return Object.freeze({qualification:'controlled-sdk-protocol-only',productionQualified:false,
  async register({scope,endpoint,mode='vuln'}){
   const owned=binding(scope),scopeDigest=digest(owned);if(!['vuln','fixed'].includes(mode)||typeof endpoint!=='string'||endpoint.length>2048)throw fail('SHADOW_ENDPOINT_DENIED');
   await checkCurrent(owned);let client,connection;
   try{
    connection=await connector.open({endpoint,scope:owned,scopeDigest});
    const attestation=connection?.attestation;
    if(attestation?.endpoint!==endpoint||attestation.scopeDigest!==scopeDigest||attestation.authentication!=='owned-control-manifest'
      ||!/^[a-f0-9]{64}$/.test(attestation.manifestDigest||'')||typeof attestation.peerKey!=='string')throw fail('SHADOW_ENDPOINT_DENIED');
    if(mode==='fixed'&&attestation.approved!==true)throw fail('SHADOW_UNAPPROVED_PEER');
    client=new Client({name:'owasp-ai-goat-shadow-protocol-fixture',version:'1.0.0'});
    await client.connect(connection.transport,{timeout:timeoutMs});await checkCurrent(owned);
    const identity=client.getServerVersion();bounded(identity,2048);
    if(!identity||identity.name!==attestation.expectedServerName||identity.version!==attestation.expectedServerVersion)throw fail('SHADOW_PEER_IDENTITY_MISMATCH');
    const listed=await client.listTools(undefined,{timeout:timeoutMs});await checkCurrent(owned);
    if(listed.nextCursor||!Array.isArray(listed.tools)||!listed.tools.length||listed.tools.length>16)throw fail('SHADOW_CATALOG_LIMIT');
    bounded(listed,32768);const registrationId=randomUUID(),prefix='shadow_'+registrationId.replaceAll('-','')+'_';
    const validators=new AjvJsonSchemaValidator(),tools=new Map();
    for(const tool of listed.tools){
     if(!/^[a-zA-Z0-9_-]{1,24}$/.test(tool.name)||tools.has(prefix+tool.name)||tool.inputSchema?.type!=='object')throw fail('SHADOW_CATALOG_INVALID');
     bounded(tool.inputSchema,4096);const validator=validators.getValidator(tool.inputSchema);
     tools.set(prefix+tool.name,{remoteName:tool.name,validate:validator,inputSchema:structuredClone(tool.inputSchema),description:String(tool.description||'').slice(0,1024)});
    }
    const catalog=Object.freeze([...tools].map(([name,value])=>Object.freeze({name,description:value.description,inputSchema:JSON.parse(JSON.stringify(value.inputSchema))})));
    const catalogDigest=digest(catalog);const handle=Object.freeze({registrationId});
    const observation=Object.freeze({registrationId,endpoint,scopeDigest,peerKey:attestation.peerKey,manifestDigest:attestation.manifestDigest,serverIdentity:Object.freeze({...identity}),catalogDigest});
    const state={owned,scopeDigest,client,connection,tools,catalogDigest,observation,retired:false};handles.set(handle,state);live.add(state);
    return Object.freeze({handle,catalog,observation,productionQualified:false});
   }catch(error){await client?.close().catch(()=>{});await Promise.resolve(connection?.close?.()).catch(()=>{});throw error.code?.startsWith('SHADOW_')?error:fail('SHADOW_PROTOCOL_FAILED');}
  },
  async invoke({handle,scope,name,args={}}){
   const state=handles.get(handle),owned=binding(scope);if(!state||state.retired||state.scopeDigest!==digest(owned))throw fail('SHADOW_HANDLE_DENIED');
   await checkCurrent(owned);if(state.retired)throw fail('SHADOW_HANDLE_DENIED');const tool=state.tools.get(name);if(!tool)throw fail('SHADOW_TOOL_DENIED');bounded(args,8192);
   if(!tool.validate(args).valid)throw fail('SHADOW_ARGUMENTS_INVALID');
   let result;
   try{result=await state.client.callTool({name:tool.remoteName,arguments:structuredClone(args)},undefined,{timeout:timeoutMs});}
   catch{throw fail('SHADOW_INVOCATION_UNCERTAIN');} // Never automatically retry an uncertain peer invocation.
   await checkCurrent(owned);if(state.retired)throw fail('SHADOW_HANDLE_DENIED');bounded(result,32768);
   if(result.isError||!Array.isArray(result.content)||result.content.some(item=>item.type!=='text'||typeof item.text!=='string'))throw fail('SHADOW_RESULT_INVALID');
   return Object.freeze({result:structuredClone(result),observation:Object.freeze({...state.observation,toolName:name,argumentsDigest:digest(args),resultDigest:digest(result)}),productionQualified:false});
  },
  async retire({handle,scope}){const state=handles.get(handle);if(!state||state.scopeDigest!==digest(binding(scope)))throw fail('SHADOW_HANDLE_DENIED');await checkCurrent(state.owned);state.retired=true;live.delete(state);await state.client.close();await state.connection.close?.();},
  async close(){for(const state of live){state.retired=true;await state.client.close().catch(()=>{});await Promise.resolve(state.connection.close?.()).catch(()=>{});}live.clear();},
 });
}
module.exports={createShadowSdkProtocolFixture};
