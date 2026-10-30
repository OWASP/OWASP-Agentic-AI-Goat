'use strict';
const path=require('node:path'),os=require('node:os');
const {provision}=require('./mcp-owned-shadow');
const {activateOwnedShadow}=require('./mcp-owned-shadow-activate');
const {readRetryEnvironment}=require('./mcp-owned-service-retry-environment');
const {loadOwnedManagedConfiguration}=require('../../server/services/mcp/ownedManagedConfiguration');
const {createMcpOwnedTargetClient}=require('../../server/services/mcp/ownedTargetClient');
async function provisionOwnedShadowForSetup({root=path.resolve(__dirname,'../..'),homeDirectory=os.homedir(),platform=process.platform,
 environment=process.env,applicationEnvironment,ownedLabSession,provisionService=provision,activate=activateOwnedShadow,
 createCli=createMcpOwnedTargetClient,createPool=require('../../server/database/postgres').createPool,loadCli=loadOwnedManagedConfiguration}={}){
 if(!applicationEnvironment)throw TypeError('Private application environment required');
 environment={...applicationEnvironment,...environment};
 const managed=loadCli({root,home:homeDirectory});
 if(managed.MCP_OWNED_RESOURCES_ENABLED!=='true')throw Object.assign(Error('Owned CLI must be activated before shadow setup'),{code:'MCP_SHADOW_CLI_REQUIRED'});
 const cli=createCli({baseURL:managed.MCP_OWNED_TARGET_URL,token:managed.MCP_OWNED_TARGET_TOKEN});
 // The CLI readiness check precedes profile/build/container mutation.
 const ready=await cli.readiness();if(ready?.ready!==true)throw Error('MCP_SHADOW_CLI_NOT_READY');
 const pools=[];const pool=key=>{const value=createPool(applicationEnvironment,key);pools.push(value);return value;};
 try{
  const identityPool=pool('IDENTITY_DATABASE_URL'),resourcePool=pool('MCP_WORKSHOP_DATABASE_URL');
  const identityMigrationPool=pool('IDENTITY_MIGRATION_DATABASE_URL'),resourceMigrationPool=pool('MCP_WORKSHOP_MIGRATION_DATABASE_URL');
  // Missing grants/schema fail before installing infrastructure.
  await require('../../server/database/postgres/mcpShadowReceiptRepository').createMcpShadowReceiptRepository(identityPool).checkReadiness();
  await require('../../server/database/postgres/mcpShadowLeaseRepository').createMcpShadowLeaseRepository(resourcePool).checkReadiness();
  const staged=await provisionService({root,home:homeDirectory,platform,ownedLabSession,
   colimaProfile:platform==='darwin'?(environment.OWASP_AI_GOAT_MCP_OWNED_COLIMA_PROFILE||'colima-default'):undefined,commandEnv:environment});
  if(staged?.ok!==true)throw Error('MCP_SHADOW_PROVISION_FAILED');
  const result=await activate({file:staged.managedPath,identityPool,resourcePool,identityMigrationPool,resourceMigrationPool,cli});
  if(result?.activationEnabled!==true)throw Error('MCP_SHADOW_ACTIVATION_FAILED');
  return Object.freeze({...result,available:true});
 }finally{await Promise.all(pools.map(p=>p.end()));}
}
async function runOwnedShadowRetryCli({root=path.resolve(__dirname,'../..'),homeDirectory=os.homedir(),platform=process.platform,
 readEnvironment=readRetryEnvironment,prepareWindowsLabInstallation,provisionForSetup=provisionOwnedShadowForSetup}={}){
 const applicationEnvironment=await readEnvironment({root,platform,service:'SHADOW'});
 let facade,forwardFailure;
 try{
  if(platform==='win32'){
   const prepare=prepareWindowsLabInstallation||require('../lib/windows-lab-installation').prepareWindowsLabInstallation;
   facade=await prepare({root,homeDirectory,environment:applicationEnvironment,mode:'existing'});
   const forward=await facade.session.openLoopbackForwards([{local:8092,guest:8092},{local:8094,guest:8094}],{ownChild:facade.ownLabChild});
   forward.failurePromise?.catch(error=>{forwardFailure=error;});
  }
  const result=await provisionForSetup({root,homeDirectory,platform,applicationEnvironment,ownedLabSession:facade?.session});
  if(forwardFailure)throw forwardFailure;
  return result;
 }finally{if(facade)await facade.close();}
}
module.exports={provisionOwnedShadowForSetup,runOwnedShadowRetryCli};
if(require.main===module){
 runOwnedShadowRetryCli().then(result=>console.log(JSON.stringify(result)))
  .catch(error=>{console.error(JSON.stringify({ok:false,code:error.code||'MCP_SHADOW_SETUP_FAILED',message:'Shadow setup did not complete; preserve private state and retry after fixing CLI/schema/service readiness.'}));process.exitCode=1;});
}
