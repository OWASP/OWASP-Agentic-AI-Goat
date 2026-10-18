'use strict';
const {createListingListener}=require('../../sidecars/sandbox-runner/owned-listings/http-listener');
const {createOwnedListingsExecutor}=require('../../sidecars/sandbox-runner/owned-listings/namespace-executor');
const fs=require('node:fs/promises');
(async()=>{
 const base=createOwnedListingsExecutor({expectedProfile:process.env.LISTINGS_PROFILE});await base.assertReady();
 let tail=Promise.resolve();const namespace={checkReadiness:()=>base.checkReadiness(),execute(...args){const work=tail.then(()=>base.execute(...args));tail=work.catch(()=>{});return work;}};
 const listeners=[];
 for(const [index,label]of ['A','B'].entries()){
  const directory='/journal/'+label;await fs.mkdir(directory,{mode:0o700});
  const listener=await createListingListener({namespace,directory,token:process.env['LISTINGS_TOKEN_'+label],identity:process.env['LISTINGS_IDENTITY_'+label],mode:'vuln',host:'0.0.0.0',port:8095+index});await listener.start();listeners.push(listener);
 }
 console.log('LISTINGS_DUAL_READY');
 const stop=()=>Promise.all(listeners.map(l=>l.close())).catch(()=>{process.exitCode=1;});process.once('SIGTERM',stop);process.once('SIGINT',stop);
})().catch(error=>{console.error(error);process.exitCode=1;});
