'use strict';
// Qualification-only cleanup accounting. A timed-out operation remains unknown;
// the outer owned-process/container launcher supplies final containment.
async function boundedCleanup(actions,{timeoutMs=10000}={}){
 if(!Array.isArray(actions)||actions.some(fn=>typeof fn!=='function')||!Number.isSafeInteger(timeoutMs)||timeoutMs<1)throw TypeError('Invalid cleanup plan');
 return Promise.all(actions.map(async action=>{
  let timer;
  try{await Promise.race([Promise.resolve().then(action),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('CTF_FIXTURE_CLEANUP_TIMEOUT')),timeoutMs);})]);return{status:'fulfilled'};}
  catch{return{status:'rejected'};}
  finally{clearTimeout(timer);}
 }));
}
module.exports={boundedCleanup};
