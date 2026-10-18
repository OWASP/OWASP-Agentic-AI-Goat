'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs/promises'), path = require('node:path'), os = require('node:os');
const { activateExisting, parseArgs } = require('../scripts/install/mcp-owned-activate');
const { prepareOwnedManagedConfiguration } = require('../scripts/install/mcp-owned-local');
const { parseManagedConfiguration } = require('../server/services/mcp/ownedManagedConfiguration');
const caps = require('../server/services/mcp/ownedQualification');
function ready() { return { resources: { ready: true, repositoryReady: true, runnerReady: true, runnerIsolation: 'bwrap-seccomp-v1', supervisorProfile: 'dvaia-mcp-sandbox (enforce)', protectedStateCapability: caps.PROTECTED_STATE_CAPABILITY, observedActionCapability: caps.OBSERVED_ACTION_CAPABILITY, ticketReadCapability: caps.TICKET_READ_CAPABILITY, packageInstallCapability: caps.PACKAGE_INSTALL_CAPABILITY }, codeBot: { ready: true, isolation: 'bwrap-codebot-v1' }, conversationsReady: true, mailReady: true }; }
async function fixture(t) { const root = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-activate-control-'));t.after(() => fs.rm(root,{recursive:true,force:true}));const envPath=path.join(root,'.env'),managedPath=path.join(root,'private','mcp.env');await fs.writeFile(envPath,`JWT_SECRET=${'j'.repeat(48)}\nCUSTOM=untouched\n`,{mode:0o600});await prepareOwnedManagedConfiguration({envPath,managedPath,activateQualified:true,randomToken:()=> 'T'.repeat(64)});return {envPath,managedPath}; }
test('CLI requires explicit closed flags and absolute paths',()=>{assert.throws(()=>parseArgs([]));assert.throws(()=>parseArgs(['--all']));assert.throws(()=>parseArgs(['--observed-action','--observed-action']));assert.throws(()=>parseArgs(['--env','relative','--observed-action']));assert.equal(parseArgs(['--observed-action']).activateObservedAction,true);});
test('activation preserves token/base config and is idempotent without provisioning',async t=>{const f=await fixture(t),before=await fs.readFile(f.envPath),old=parseManagedConfiguration(await fs.readFile(f.managedPath));let calls=0;const probe=async env=>{calls++;assert.equal(env.MCP_OWNED_TARGET_TOKEN,old.MCP_OWNED_TARGET_TOKEN);return ready();};const opts={...f,activateObservedAction:true,activateIndirectInjection:true,probe};const result=await activateExisting(opts);assert.equal(result.changed,true);assert.equal(result.runtimeActivated,false);assert.equal(result.runtimeReloadRequired,true);assert(!JSON.stringify(result).includes(old.MCP_OWNED_TARGET_TOKEN));const now=parseManagedConfiguration(await fs.readFile(f.managedPath));assert.deepEqual(now,{...old,MCP_OBSERVED_ACTION_ENABLED:'true',MCP_INDIRECT_INJECTION_ENABLED:'true'});assert.deepEqual(await fs.readFile(f.envPath),before);assert.equal((await activateExisting(opts)).changed,false);assert.equal(calls,2);});
test('each readiness or exact capability failure leaves both files byte-identical',async t=>{const f=await fixture(t),old=await fs.readFile(f.managedPath),env=await fs.readFile(f.envPath);for(const change of [r=>r.resources.ready=false,r=>r.resources.repositoryReady=false,r=>r.resources.runnerIsolation='wrong',r=>r.resources.supervisorProfile='complain',r=>r.codeBot.ready=false,r=>r.conversationsReady=false,r=>r.mailReady=false,...['protectedStateCapability','observedActionCapability','ticketReadCapability','packageInstallCapability'].map(k=>r=>r.resources[k]='wrong')]){const r=ready();change(r);await assert.rejects(activateExisting({...f,activateObservedAction:true,activateIndirectInjection:true,activateSupplyChain:true,probe:async()=>r}));assert.deepEqual(await fs.readFile(f.managedPath),old);assert.deepEqual(await fs.readFile(f.envPath),env);}});
test('missing/private unsafe configuration and absent explicit prerequisites never probe',async t=>{const f=await fixture(t),probe=async()=>{throw Error('must not probe');};await assert.rejects(activateExisting({...f,activateIndirectInjection:true,probe}),{code:'MCP_ACTIVATE_OBSERVED_REQUIRED'});await fs.chmod(f.managedPath,0o644);await assert.rejects(activateExisting({...f,activateObservedAction:true,probe}),{code:'MCP_ACTIVATE_PRIVATE_FILE'});await fs.unlink(f.managedPath);await assert.rejects(activateExisting({...f,activateObservedAction:true,probe}));});
test('concurrent config change during readiness is rejected before activation',async t=>{const f=await fixture(t);const before=await fs.readFile(f.managedPath);await assert.rejects(activateExisting({...f,activateObservedAction:true,probe:async()=>{await fs.appendFile(f.envPath,'OTHER=changed\n');return ready();}}),{code:'MCP_ACTIVATE_CONFIGURATION_CHANGED'});assert.deepEqual(await fs.readFile(f.managedPath),before);});
test('unrequested existing gates including protected recovery are preserved',async t=>{const f=await fixture(t);await prepareOwnedManagedConfiguration({...f,activateQualified:true,activateObservedAction:true,activateIndirectInjection:true,activateProtectedRecovery:true,protectedRecoveryQualified:true});const old=parseManagedConfiguration(await fs.readFile(f.managedPath));await activateExisting({...f,activateSupplyChain:true,probe:async()=>ready()});assert.deepEqual(parseManagedConfiguration(await fs.readFile(f.managedPath)),{...old,MCP_SUPPLY_CHAIN_ENABLED:'true'});});
test('default readiness probe closes every owned pool and SMTP transport before returning, including failures',async()=>{
 const Module=require('node:module'),original=Module._load,{probeExisting}=require('../scripts/install/mcp-owned-activate');
 for(const failMail of [false,true]){
  const closed=[],r=ready();
  Module._load=function(request,parent,isMain){
   if(parent?.filename.endsWith('/scripts/install/mcp-owned-activate.js')){
    if(request==='../../server/database/postgres')return {createPool:(_env,key)=>({end:async()=>closed.push(key)})};
    if(request==='../../server/services/mcp/ownedTargetClient')return {createMcpOwnedTargetClient:()=>({})};
    if(request==='../../server/services/mcp/ownedResourceComposition')return {createMcpOwnedResourceReadiness:()=>async()=>r.resources};
    if(request==='../../server/services/mcp/ownedResourceProduction')return {conversationReadiness:async()=>true};
    if(request==='../../server/services/supplyChain/codeBotProduction')return {readRunnerReadiness:async()=>r.codeBot};
    if(request==='nodemailer')return {createTransport:()=>({verify:async()=>{if(failMail)throw Error('private diagnostic');return true;},close:()=>closed.push('smtp')})};
    if(request==='../../server/services/mcp/mailClient')return {_internals:{fetchWithTimeout:async()=>({ok:true})}};
   }
   return original.apply(this,arguments);
  };
  try{const work=probeExisting({PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'});if(failMail)await assert.rejects(work);else assert.equal((await work).mailReady,true);assert.deepEqual(closed.sort(),['IDENTITY_DATABASE_URL','MCP_WORKSHOP_DATABASE_URL','smtp'].sort());}finally{Module._load=original;}
 }
});

test('CLI failure formatting exposes only actionable closed codes, never provider diagnostics',()=>{
 const {activationFailure}=require('../scripts/install/mcp-owned-activate');
 const privateMessage='postgresql://secret@private/path';
 const result=activationFailure({code:'MCP_INSTALL_CAPABILITY_UNAVAILABLE',message:privateMessage});
 assert.equal(result.code,'MCP_INSTALL_CAPABILITY_UNAVAILABLE');assert.match(result.message,/Upgrade the owned runner/);
 assert(!JSON.stringify(result).includes(privateMessage));
 for(const code of ['UNKNOWN_PRIVATE_CODE',privateMessage,undefined,'toString']){const denied=activationFailure({code,message:privateMessage});assert.equal(denied.code,'MCP_ACTIVATE_FAILED');assert(!JSON.stringify(denied).includes(privateMessage));}
 assert.equal(activationFailure({code:'MCP_ACTIVATE_OBSERVED_REQUIRED'}).code,'MCP_ACTIVATE_OBSERVED_REQUIRED');
});
