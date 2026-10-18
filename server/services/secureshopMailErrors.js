'use strict';
const beforeEffect=new WeakSet();
function validateMailInput(work){try{return work();}catch(error){if(error&&typeof error==='object')beforeEffect.add(error);throw error;}}
function invalidMailInput(){return validateMailInput(()=>{throw Object.assign(Error('Invalid mail input'),{code:'INVALID_ARGUMENT'});});}
module.exports={validateMailInput,invalidMailInput,isPreEffectMailError:error=>beforeEffect.has(error)};
