'use strict';
const crypto=require('node:crypto');
const {digestMcpValue}=require('./secureshopMcpTrustTools');
const {discoverRegistryTools}=require('./secureshopMcpRegistryDiscovery');
function unavailable(message='Controlled MCP transport unavailable'){return Object.assign(new Error(message),{code:'BOUND_MCP_TRANSPORT_UNAVAILABLE'});}
function createSecureShopMcpSdkTransport({controlledServer}={}){
  if(!controlledServer?.server||typeof controlledServer.qualifyDiscovery!=='function'||typeof controlledServer.takeEffect!=='function')throw unavailable();
  let session;let connecting;let protocolClosed=false;let disconnecting;async function client(){if(protocolClosed)throw unavailable();if(session)return session;if(connecting)return connecting;
    connecting=(async()=>{
    const [{Client},{InMemoryTransport}]=await Promise.all([import('@modelcontextprotocol/sdk/client/index.js'),import('@modelcontextprotocol/sdk/inMemory.js')]);
    const [clientTransport,serverTransport]=InMemoryTransport.createLinkedPair();const value=new Client({name:'secureshop-bound-mcp-client',version:'1.0.0'});
    try{await controlledServer.server.connect(serverTransport);await value.connect(clientTransport);if(protocolClosed)throw unavailable();session={value,clientTransport,serverTransport};return session;}
    catch(error){await Promise.allSettled([value.close(),clientTransport.close(),serverTransport.close()]);throw error;}
    finally{connecting=null;}})();return connecting;}
  async function disconnect(){if(disconnecting)return disconnecting;
    // Close admission before yielding: retirement must not open a replacement
    // SDK session while the previous server is still shutting down.
    protocolClosed=true;disconnecting=(async()=>{const active=await connecting?.catch(()=>null)||session;session=null;connecting=null;
    const closed=await Promise.allSettled([active?.value.close(),active?.clientTransport.close(),active?.serverTransport.close(),controlledServer.server.close()]);
    const failed=closed.find(result=>result.status==='rejected');if(failed)throw failed.reason;})();return disconnecting;}
  return Object.freeze({
    async discover({serverIdentity,targetId,signal}={}){signal?.throwIfAborted();if(serverIdentity!==controlledServer.serverIdentity)throw unavailable();
      const {tools}=await discoverRegistryTools((await client()).value,{signal});const proof=controlledServer.qualifyDiscovery(tools,targetId);
      return Object.freeze({serverIdentity,trustScenario:proof.trustScenario,tools:Object.freeze(tools),receiptSha256:proof.receiptSha256,schemaSha256:digestMcpValue(tools)});},
    async callTool({serverIdentity,toolName,args,schemaSha256,targetId,signal}={}){if(serverIdentity!==controlledServer.serverIdentity)throw unavailable();
      signal?.throwIfAborted();const nonce=crypto.randomUUID();let response;
      try{response=await (await client()).value.callTool({name:toolName,
        arguments:{...args,__invocation_nonce:nonce,__target_id:targetId,__schema_sha256:schemaSha256}},undefined,{signal});
        signal?.throwIfAborted();}
      catch(error){await controlledServer.settleEffect?.(nonce);throw error;}
      const effect=controlledServer.takeEffect(nonce);if(!effect||effect.serverIdentity!==serverIdentity||effect.targetId!==targetId
        ||effect.toolName!==toolName||digestMcpValue(controlledServer.currentSchema())!==schemaSha256)throw unavailable('Controlled MCP effect receipt mismatch');
      const content=response.content;if(!Array.isArray(content)||content.length!==1||content[0]?.type!=='text')throw unavailable();
      let result;try{result=JSON.parse(content[0].text);}catch{throw unavailable();}
      if(digestMcpValue(result)!==digestMcpValue(effect.result))throw unavailable('Controlled MCP result mismatch');
      return Object.freeze({serverIdentity,schemaSha256,receiptSha256:effect.receiptSha256,
        trustScenario:effect.trustScenario,approved:effect.approved,serverApproved:effect.serverApproved,
        schemaApproved:effect.schemaApproved,trustPolicySha256:effect.trustPolicySha256,behaviorClass:effect.behaviorClass,
        result:Object.freeze(result)});},
    disconnect,
    async close(){let disconnectError;try{await disconnect();}catch(error){disconnectError=error;}
      let cleanupError;try{await controlledServer.cleanup?.();}catch(error){cleanupError=error;}
      if(disconnectError&&cleanupError)throw new AggregateError([disconnectError,cleanupError],'Controlled MCP disconnect and cleanup failed');
      if(cleanupError)throw cleanupError;if(disconnectError)throw disconnectError;},
  });
}
module.exports={createSecureShopMcpSdkTransport};
