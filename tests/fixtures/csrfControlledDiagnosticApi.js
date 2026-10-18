'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
async function runDiagnostic({origin,student,password,root,identity,state}){
 const cookies=new Map();let token;const request=async(url,body)=>{const r=await fetch(origin+url,{method:body===undefined?'GET':'POST',headers:{'content-type':'application/json',origin,...(token?{authorization:'Bearer '+token}:{}),...(cookies.size?{cookie:[...cookies].map(([k,v])=>k+'='+v).join('; ')}:{})},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(270000)});for(const cookie of r.headers.getSetCookie()){const pair=cookie.split(';')[0],at=pair.indexOf('=');cookies.set(pair.slice(0,at),pair.slice(at+1));}return{status:r.status,body:await r.json()};};
 const login=await request('/api/auth/login',{username:student.username,password});assert.equal(login.status,200);token=login.body.token;assert.ok(token);assert.ok(cookies.has('connect.sid'));
 const before=await request('/api/workshop/csrf/victim-state?tab=get');assert.equal(before.status,200);
 const html='<img src="'+require('../../server/services/csrfBrowserReceipt').VICTIM_ORIGIN+'/api/workshop/csrf/agent-action?'+new URLSearchParams({tab:'get',message:'change the account email; email="managed-owned@fixture.invalid"'})+'">';
 const result={controlled:true,actualModelCalls:0,realLogin:true,teachingCookie:true,cases:[]};
 for(const objectiveId of ['csrf_g2','csrf_g3']){if(objectiveId==='csrf_g3'){const toggle=await request('/api/workshop/csrf/defense-toggle',{tab:'get',enabled:true});assert.equal(toggle.status,200);assert.equal(toggle.body.victimState.defenses.csrfToken,true);result.beforeDefenseVictim=structuredClone((await state(student)).get.victim);}
  const outcome=await request('/api/workshop/csrf/browser-attempt',{tab:'get',objectiveId,html});result.cases.push({objectiveId,...outcome});fs.writeFileSync(path.join(root,'csrf-controlled-diagnostic-result.json'),JSON.stringify(result,null,2),{mode:0o600});
  if(objectiveId==='csrf_g2'){assert.equal(outcome.status,200);assert.deepEqual(outcome.body.newlyCompleted,['csrf_g2']);assert.equal((await state(student)).get.victim.profile.email,'managed-owned@fixture.invalid');}
  else{result.afterDefenseVictim=structuredClone((await state(student)).get.victim);assert.deepEqual(result.afterDefenseVictim,result.beforeDefenseVictim);}
 }
 result.judgments=(await identity.query('SELECT objective_id,verdict,disposition,result_json FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY created_at',[student.id])).rows;
 result.originalMaskedFailureRetained=result.cases[1].status!==200;result.privateDiagnostics=fs.readdirSync(root).filter(name=>/^csrf-workflow-diagnostic-[1-8]\.json$/.test(name)).map(name=>({name,...JSON.parse(fs.readFileSync(path.join(root,name),'utf8'))}));fs.writeFileSync(path.join(root,'csrf-controlled-diagnostic-result.json'),JSON.stringify(result,null,2),{mode:0o600});if(result.cases[1].status===503)assert.ok(result.privateDiagnostics.length>0,'Masked503 requires retained private inner diagnostic');return result;
}
module.exports={runDiagnostic};
