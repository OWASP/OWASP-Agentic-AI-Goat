'use strict';
// Cooperative direct-child admission. The native owner pins this process and
// assigns its Job before activation; this protocol grants no database authority.
const {randomBytes}=require('node:crypto');
const exact=(value,fields)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===fields.slice().sort().join(',');
const token=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const denied=()=>Object.assign(Error('Windows maintenance lifecycle unavailable'),{code:'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE'});
function validateRecoveryResult(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||!['completed,epoch,recovery','completed,epoch,observed,recovery'].includes(Object.keys(value).sort().join(','))||value.completed!==true||value.recovery!==true||typeof value.epoch!=='string'||!/^[1-9][0-9]{0,18}$/.test(value.epoch)||BigInt(value.epoch)>9223372036854775807n||Object.hasOwn(value,'observed')&&value.observed!==true)throw denied();
 return Object.freeze({...value});
}
function awaitWindowsMaintenanceActivation({runtime=process,timeoutMs=10000}={}){
 return new Promise((resolve,reject)=>{
  if(!runtime.connected||typeof runtime.send!=='function')return reject(denied());
  const challenge=randomBytes(32).toString('hex');let phase='waiting',nonce,done=false;
  const fail=()=>{if(done)return;done=true;clearTimeout(timer);runtime.removeListener('message',message);runtime.removeListener('disconnect',fail);reject(denied());};
  const message=value=>{try{
   if(exact(value,['type'])&&value.type==='dvaia-owned-guardian-stop')return fail();
   if(phase==='waiting'&&exact(value,['type'])&&value.type==='dvaia-owned-guardian-hello'){
    phase='ready';runtime.send({type:'dvaia-owned-guardian-ready',pid:runtime.pid,challenge},error=>{if(error)fail();});return;
   }
   if(phase==='ready'&&exact(value,['type','challenge','nonce'])&&value.type==='dvaia-owned-guardian-probe'&&value.challenge===challenge&&token(value.nonce)){
    phase='proved';nonce=value.nonce;runtime.send({type:'dvaia-owned-guardian-proof',pid:runtime.pid,challenge,nonce},error=>{if(error)fail();});return;
   }
   if(phase==='proved'&&exact(value,['type','challenge','nonce'])&&value.type==='dvaia-owned-guardian-activate'&&value.challenge===challenge&&value.nonce===nonce){
    phase='activating';runtime.send({type:'dvaia-owned-guardian-active',pid:runtime.pid,challenge,nonce},error=>{if(error)return fail();if(done)return;done=true;clearTimeout(timer);runtime.removeListener('message',message);runtime.removeListener('disconnect',fail);resolve();});return;
   }
   fail();
  }catch{fail();}};
  const timer=setTimeout(fail,timeoutMs);runtime.on('message',message);runtime.once('disconnect',fail);
 });
}
function completeWindowsMaintenance({runtime=process,timeoutMs=10000,result}={}){
 return new Promise((resolve,reject)=>{
  let recoveryResult;try{if(result!==undefined)recoveryResult=validateRecoveryResult(result);}catch(error){reject(error);return;}
  const nonce=randomBytes(32).toString('hex');let done=false;
  const finish=error=>{if(done)return;done=true;clearTimeout(timer);runtime.removeListener('message',message);runtime.removeListener('disconnect',disconnect);error?reject(denied()):resolve();};
  const disconnect=()=>finish(true),message=value=>{
   if(value?.type==='journal-bound-completion-approved')finish(!exact(value,['type','nonce'])||value.nonce!==nonce);
   else if(value?.type==='dvaia-owned-guardian-stop')finish(true);
  };
  const timer=setTimeout(disconnect,timeoutMs);runtime.on('message',message);runtime.once('disconnect',disconnect);
  if(!runtime.connected)return disconnect();
  try{runtime.send({type:'journal-bound-complete',completed:true,nonce,...(recoveryResult?{result:recoveryResult}:{})},error=>{if(error)disconnect();});}catch{disconnect();}
 });
}
module.exports={awaitWindowsMaintenanceActivation,completeWindowsMaintenance,validateRecoveryResult};
