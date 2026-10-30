'use strict';
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {workspaceId}=require('./mcp/ownedManagedConfiguration');
const fail=()=>Object.assign(new Error('Owned MCP registry production unavailable'),{code:'MCP_REGISTRY_NOT_READY'});
// This adapter owns requests only. The separately provisioned executor owns its
// process and isolation resources; application shutdown never removes them.
// Registry administration is qualified through the owned ARM64 executor and
// connected browser flow. Generic supervisor tool invocation is separate.
const PRODUCTION_QUALIFIED=true;
function validateConfiguration(value,{root=path.resolve(__dirname,'../..')}={}){
 const keys=['version','workspace','enabled','baseURL','token','runtimeDigest','mode'];
 if(!value||Object.keys(value).sort().join()!==keys.sort().join()||value.version!==1||value.workspace!==workspaceId(root)||typeof value.enabled!=='boolean'||!['vuln','fixed'].includes(value.mode)||!/^[0-9a-f]{64}$/.test(value.runtimeDigest||''))throw fail();
 let url;try{url=new URL(value.baseURL);}catch{throw fail();}
 if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||!url.port||url.pathname!=='/'||url.username||url.password||url.search||url.hash||!/^[A-Za-z0-9_-]{43,128}$/.test(value.token||''))throw fail();
 return Object.freeze({...value});
}
async function readConfiguration({root=path.resolve(__dirname,'../..'),home=os.homedir()}={}){
 const file=path.join(home,'.owasp-ai-goat',workspaceId(root),'secureshop-owned-mcp-registry.json');
 let stat;try{stat=await fs.lstat(file);}catch(error){if(error.code==='ENOENT')return null;throw fail();}
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size>8192||(stat.mode&0o077)||stat.uid!==process.getuid())throw fail();
 try{return validateConfiguration(JSON.parse(await fs.readFile(file,'utf8')),{root});}catch{throw fail();}
}
async function createOwnedMcpRegistryProduction({configuration,agentsPool,personaAuthority,authenticatePersona,expectedDatabase,
 createClient=require('./secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient,
 createComposition=require('./secureshopOwnedMcpRegistryComposition').createOwnedMcpRegistryComposition}={}){
 if(!configuration||configuration.enabled!==true)return Object.freeze({ready:false,async close(){}});
 const value=validateConfiguration(configuration),client=createClient({baseURL:value.baseURL,token:value.token,expectedRuntimeDigest:value.runtimeDigest});
 let closing=false,closePromise;const pending=new Set(),controllers=new Set();
 function wrapService(service){
  function run(method,args,options={}){
   if(closing)return Promise.reject(fail());
   const controller=new AbortController(),abort=()=>controller.abort();controllers.add(controller);
   options.signal?.addEventListener('abort',abort,{once:true});if(options.signal?.aborted)abort();
   let promise;
   try{controller.signal.throwIfAborted();promise=Promise.resolve(service[method](args,{...options,signal:controller.signal}));}
   catch(error){promise=Promise.reject(error);}
   pending.add(promise);
   promise.finally(()=>{pending.delete(promise);controllers.delete(controller);options.signal?.removeEventListener('abort',abort);}).catch(()=>{});
   return promise;
  }
  return Object.freeze({mutate:(args,options)=>run('mutate',args,options),read:args=>run('read',args)});
 }
 const composition=await createComposition({enabled:true,agentsPool,personaAuthority,authenticatePersona,expectedDatabase,executorClient:client,readMode:async()=>value.mode,wrapService});
 // Configuration is immutable for this process. Browser input cannot change mode.
 return Object.freeze({ready:true,capability:composition.capability,router:composition.router,service:composition.service,
  async assertReady(){if(closing)throw fail();await client.health();if(closing)throw fail();},
  close(){if(!closePromise){closing=true;for(const controller of controllers)controller.abort();closePromise=Promise.allSettled([...pending]).then(()=>{});}return closePromise;}
 });
}
module.exports={PRODUCTION_QUALIFIED,validateConfiguration,readConfiguration,createOwnedMcpRegistryProduction};
