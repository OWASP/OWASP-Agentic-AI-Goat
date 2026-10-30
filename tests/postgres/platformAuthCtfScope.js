'use strict';
function pair(env,prefix){
 if(env.OWASP_AI_GOAT_AUTH_CTF_PROFILE!=='1')return; // Retained explicitly isolated historical launchers keep their own gate.
 if(!/^[1-9][0-9]{0,4}$/.test(env.OWASP_AI_GOAT_AUTH_CTF_PORT||'')||Number(env.OWASP_AI_GOAT_AUTH_CTF_PORT)>65535)throw Error('Owned port required');
 const urls=['RUNTIME','MIGRATION'].map(role=>new URL(env[prefix+'_'+role+'_URL']));
 urls.forEach((u,i)=>{if(u.protocol!=='postgresql:'||u.hostname!=='127.0.0.1'||u.port!==env.OWASP_AI_GOAT_AUTH_CTF_PORT||u.username!=='owasp_ai_goat_identity_'+['runtime','migration'][i]||u.password||u.search||u.hash||!/^\/owasp_ai_goat_test_[a-z0-9_]+$/.test(u.pathname))throw Error('Owned pair mismatch');});
 if(urls[0].pathname!==urls[1].pathname)throw Error('Owned pair database mismatch');
}
async function bounded(work,ms=5000){let timer;try{return await Promise.race([Promise.resolve().then(work),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Fixture cleanup deadline')),ms);})]);}finally{clearTimeout(timer);}}
async function cleanup(steps){const failures=[];const deadline=Date.now()+10000;for(const step of steps){try{const left=deadline-Date.now();if(left<=0)throw Error('Fixture cleanup deadline');await bounded(step,left);}catch(error){failures.push(error);}}if(failures.length)throw new AggregateError(failures,'Fixture cleanup incomplete');}
module.exports={pair,bounded,cleanup};
