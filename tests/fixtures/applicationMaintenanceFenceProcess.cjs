'use strict';
// Disposable fixture process. No credentials in argv; lifetime bounded even if IPC is lost.
const fs=require('node:fs'),path=require('node:path');
setTimeout(()=>process.exit(124),30000).unref();
const send=value=>{if(process.connected)process.send(value);};
const controller=new AbortController();process.on('SIGTERM',()=>controller.abort());process.on('disconnect',()=>controller.abort());let admitted=false;
process.on('message',async message=>{
 if(admitted)return;admitted=true;
 try{
  if(process.env.APPLICATION_MAINTENANCE_FENCE_ISOLATED!=='1')throw Error('Isolation required');
  Object.assign(process.env,message.environment);
  if(message.mode==='entry'){
   const leaseModule=require('../../server/services/applicationMaintenanceLease'),original=leaseModule.acquireApplicationMaintenanceLease;
   leaseModule.acquireApplicationMaintenanceLease=async options=>{const lease=await original(options);return{...lease,async assertClean(){try{return await lease.assertClean();}catch(error){fs.writeFileSync(message.observation,JSON.stringify({code:error.code,constructed:Boolean(require.cache[require.resolve('../../server/applicationServer')])}),{mode:0o600});throw error;}}};};
   require('../../server/index');return;
  }
  if(message.mode==='writer'){
   const {Client}=require('pg'),client=new Client({connectionString:process.env.IDENTITY_MIGRATION_DATABASE_URL,connectionTimeoutMillis:2000,statement_timeout:2000});await client.connect();send({type:'ready',pid:process.pid,backend:client.processID});process.once('message',async value=>{try{if(value.type!=='write')throw Error('Unexpected command');await client.query('INSERT INTO public.fence_probe(value) VALUES(42)');send({type:'written'});}finally{await client.end();process.exit(0);}});return;
  }
  await require('../../scripts/lib/application-maintenance-scope').withApplicationMaintenanceScope({environment:process.env,signal:controller.signal,drain:async()=>{}},async()=>{
   send({type:'dirty',pid:process.pid});await new Promise((resolve,reject)=>{const stop=()=>reject(Object.assign(Error('Owned cancellation'),{code:'CONTROLLED_CANCELLED'}));controller.signal.addEventListener('abort',stop,{once:true});if(controller.signal.aborted)stop();});
  });throw Error('Unexpected success');
 }catch(error){send({type:'failure',code:error.code||'FIXTURE_FAILURE'});process.exit(1);}
});
