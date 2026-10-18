'use strict';
// Owned native fixture process only. Credentials arrive over IPC, never argv.
// Test-only lifetime bound also covers parent death before detached registration.
setTimeout(()=>process.exit(124),process.argv[2]==='--private-phase'?600000:45000).unref();
const {executeDatabasePhase}=require('../../scripts/install/setup-database-phase');
const {acquireApplicationMaintenanceLease}=require('../../server/services/applicationMaintenanceLease');
if(process.env.SETUP_PHASE_ENTRY_OBSERVATION){
 const leaseModule=require('../../server/services/applicationMaintenanceLease');
 const original=leaseModule.acquireApplicationMaintenanceLease;
 leaseModule.acquireApplicationMaintenanceLease=async function(...args){
  try{return await original.apply(this,args);}catch(error){
   require('node:fs').writeFileSync(process.env.SETUP_PHASE_ENTRY_OBSERVATION,JSON.stringify({code:error.code,serverConstructed:Boolean(require.cache[require.resolve('../../server/applicationServer')])}),{mode:0o600});throw error;
  }
 };
}
// Qualification boundary only: execute the real index and real clean check,
// then stop before constructing the full backend. This is not full readiness.
if(process.env.SETUP_PHASE_CLEAN_ENTRY_OBSERVATION){
 const Module=require('node:module'),load=Module._load,leaseModule=require('../../server/services/applicationMaintenanceLease'),original=leaseModule.acquireApplicationMaintenanceLease;
 let validated=false;
 leaseModule.acquireApplicationMaintenanceLease=async(...args)=>{const lease=await original(...args);return{...lease,async assertClean(){const result=await lease.assertClean();validated=true;return result;}};};
 Module._load=function(request,parent,isMain){
  if(parent?.filename===require.resolve('../../server/index')&&request==='./applicationServer'){
   if(!validated)throw Error('Clean control was not validated');
   return{async startApplicationServer(){require('node:fs').writeFileSync(process.env.SETUP_PHASE_CLEAN_ENTRY_OBSERVATION,JSON.stringify({controlValidated:true,constructionBoundaryReached:true,realServerImported:Boolean(require.cache[require.resolve('../../server/applicationServer')])}),{mode:0o600});setImmediate(()=>process.kill(process.pid,'SIGTERM'));}};
  }
  return load.apply(this,arguments);
 };
}
const controller=new AbortController();
process.on('SIGTERM',()=>controller.abort());process.on('disconnect',()=>controller.abort());
let admitted=false;
const send=value=>{if(process.connected)process.send(value);};
process.on('message',async message=>{
 if(message?.type==='cancel'){controller.abort();return;}
 if(admitted)return;admitted=true;
 try{
  if(process.argv[2]==='--private-phase'){
   const result=await executeDatabasePhase(message,{signal:controller.signal,notify:send,execute:async(request,scope,dependencies)=>{
    const {privatePhaseCommand}=require('./setupPrivatePhaseDispatch');
    return require('../../scripts/setup-application').executeSetupDatabasePhase(request,scope,{...dependencies,runCommand:async(command,args,cwd,env,options)=>{
     const translated=privatePhaseCommand(command,args,cwd,request.context.root);
     return require('../../scripts/lib/setup-command').runSetupCommand(command,translated,cwd,env,options);
    }});
   }});
   process.send({type:'result',result},()=>process.exit(0));return;
  }
  if(message.mode==='lease'){
   const lease=await acquireApplicationMaintenanceLease({mode:'application',env:message.environment,signal:controller.signal});
   send({type:'ready'});
   await new Promise(resolve=>{if(controller.signal.aborted)resolve();else controller.signal.addEventListener('abort',resolve,{once:true});});
   await lease.close();process.exit(0);
  }
  await executeDatabasePhase(message.request,{signal:controller.signal,notify:send,execute:async(_request,scope,{deferPublication})=>{
   deferPublication(()=>require('node:fs/promises').writeFile(message.publication,'unexpected',{flag:'wx',mode:0o600}));
   const code=`setTimeout(()=>process.exit(124),45000);const {Client}=require(${JSON.stringify(require.resolve('pg'))});const c=new Client({connectionString:process.env.IDENTITY_DATABASE_URL});(async()=>{await c.connect();await c.query('SELECT 1');process.on('SIGTERM',()=>{});process.stdout.write('ready');setInterval(()=>{},1000);})().catch(()=>process.exit(1));`;
   if(message.mode==='runner-failure'){
    const run=require('../../scripts/install/secureshop-owned-system-provision')._internals.createRunner({cwd:message.request.context.root,env:process.env});
    await run(process.execPath,['-e',code],{timeoutMs:200,maxOutputBytes:1024});
    throw Error('Expected runner failure');
   }
   const child=require('node:child_process').spawn(process.execPath,['-e',code],{cwd:message.request.context.root,env:process.env,detached:true,stdio:['ignore','pipe','pipe']});
   await new Promise((resolve,reject)=>{child.stdout.once('data',resolve);child.once('error',reject);child.once('exit',()=>reject(Error('Helper exited before ready')));});
   send({type:'barrier',pid:child.pid});
   await new Promise((resolve,reject)=>{scope.signal.addEventListener('abort',()=>reject(Object.assign(Error('Controlled cancellation'),{code:'CONTROLLED_CANCELLED'})),{once:true});if(scope.signal.aborted)reject(scope.signal.reason);});
  }});
  process.exit(0);
 }catch(error){
  send(require('./setupPrivatePhaseDispatch').privatePhaseFailure(error));
  try{await error.drainOwnedChildren?.();process.exit(1);}catch{setInterval(()=>{},1000);}
 }
});
