'use strict';
const {createCtfDeliveryActivation}=require('../database/postgres/ctfDeliveryActivation');
const {createCtfDeliveryPool}=require('../database/postgres/ctfDeliveryPool');
const {createCtfAuthorityApplication}=require('./ctfAuthorityApplication');
let state='idle',initializing,closing,config,published,candidate,ownedPool,cleanupPromise;
const shutdown=new AbortController();
const unavailable=()=>Object.assign(Error('CTF authority unavailable'),{code:'CTF_RUNTIME_UNAVAILABLE',statusCode:503});
const envKeys=['CTF_DELIVERY_DATABASE_URL','PG_TLS','PG_POOL_BUDGET','PG_POOL_MAX_WORKSHOP'];
function capture(options){
 const keys=['identityPool','ctfPool','validateSession','coordinator','env','signal'];
 if(!options||Object.keys(options).some(k=>!keys.includes(k))||typeof options.identityPool?.connect!=='function'||typeof options.ctfPool?.connect!=='function'||options.identityPool===options.ctfPool||typeof options.validateSession!=='function'||typeof options.coordinator?.run!=='function')throw TypeError('Explicit CTF production dependencies required');
 if(options.signal!==undefined&&!(options.signal instanceof AbortSignal))throw TypeError('Invalid CTF initialization signal');
 const env=options.env??process.env,snapshot={};for(const key of envKeys)if(env[key]!==undefined){if(typeof env[key]!=='string')throw TypeError('CTF environment values must be strings');snapshot[key]=env[key];}
 return{identityPool:options.identityPool,ctfPool:options.ctfPool,validateSession:options.validateSession,coordinator:options.coordinator,signal:options.signal,env:Object.freeze(snapshot)};
}
function same(a,b){return ['identityPool','ctfPool','validateSession','coordinator','signal'].every(k=>a[k]===b[k])&&JSON.stringify(a.env)===JSON.stringify(b.env);}
function cleanup(){
 if(cleanupPromise)return cleanupPromise;
 cleanupPromise=(async()=>{const errors=[];if(candidate){try{await candidate.stop();}catch(e){errors.push(e);}}if(ownedPool){try{await ownedPool.end();}catch(e){errors.push(e);}}if(errors.length)throw new AggregateError(errors,'CTF authority cleanup failed');})();return cleanupPromise;
}
function initializeProductionCtfAuthority(options){
 if(state==='closing'||state==='closed')return Promise.reject(unavailable());
 let next;try{next=capture(options);}catch(e){return Promise.reject(e);}
 if(initializing){if(!same(config,next))return Promise.reject(TypeError('CTF production initialization configuration changed'));return initializing;}
 config=next;state='initializing';const signal=AbortSignal.any([shutdown.signal,...(config.signal?[config.signal]:[])]);
 initializing=(async()=>{
  try{
   signal.throwIfAborted();const activation=await createCtfDeliveryActivation(config).loadCurrent({signal});signal.throwIfAborted();
   ownedPool=await createCtfDeliveryPool({env:config.env,activation});signal.throwIfAborted();
   candidate=createCtfAuthorityApplication({identityPool:config.identityPool,ctfPool:config.ctfPool,deliveryPool:ownedPool,deliveryDatabaseUrl:config.env.CTF_DELIVERY_DATABASE_URL,activation,validateSession:config.validateSession,coordinator:config.coordinator});
   await candidate.start();signal.throwIfAborted();if(state!=='initializing')throw unavailable();published=candidate;state='running';return published;
  }catch(error){published=undefined;if(state==='initializing')state='failed';try{await cleanup();}catch(cleanupError){throw new AggregateError([error,cleanupError],'CTF authority initialization and cleanup failed');}throw error;}
 })();return initializing;
}
function getProductionCtfAuthority(){if(state!=='running'||!published)throw unavailable();return published;}
function closeProductionCtfAuthority(){
 if(closing)return closing;state='closing';published=undefined;shutdown.abort();
 closing=(async()=>{try{if(initializing)await initializing.catch(()=>{});await cleanup();}finally{state='closed';}})();return closing;
}
module.exports={initializeProductionCtfAuthority,getProductionCtfAuthority,closeProductionCtfAuthority};
