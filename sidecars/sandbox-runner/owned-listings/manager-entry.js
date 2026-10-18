'use strict';
const {createOwnedListingsExecutor}=require('./namespace-executor');
const {createListingsTargetManager}=require('./target-manager');
const {createListingsManagerHttp}=require('./manager-http');
(async()=>{
 if(process.env.LISTINGS_MANAGER_ENABLED!=='true')throw Error('disabled');
 const namespace=createOwnedListingsExecutor({expectedProfile:process.env.LISTINGS_PROFILE});await namespace.assertReady();
 const manager=await createListingsTargetManager({directory:'/journal',origin:process.env.LISTINGS_PUBLIC_ORIGIN,namespace});
 const server=createListingsManagerHttp({manager,controlToken:process.env.LISTINGS_CONTROL_TOKEN,host:'0.0.0.0',port:8095});await server.start();
 let closing;const stop=()=>closing ||= server.close().catch(()=>{process.exitCode=1;});process.once('SIGTERM',stop);process.once('SIGINT',stop);process.stdout.write('LISTINGS_MANAGER_READY\n');
})().catch(()=>{process.stderr.write('LISTINGS_MANAGER_UNAVAILABLE\n');process.exitCode=1;});
