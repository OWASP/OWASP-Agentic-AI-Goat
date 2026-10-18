'use strict';
const assert=require('node:assert/strict');
async function qualifyPasswordReset({page,frame,origin,directory,loginHeaders}){
 const target=directory.users.find(user=>user.username==='student_customer');assert.ok(target?.password_reset_available);
 const postResponse=suffix=>page.waitForResponse(r=>r.url()===origin+`/api/secureshop/admin/users/${target.id}`+suffix&&r.request().method()==='POST',{timeout:15000});
 const login=async password=>fetch(origin+'/api/secureshop/v2/auth/login',{method:'POST',headers:{'content-type':'application/json','x-dvaia-secureshop-launch':loginHeaders['x-dvaia-secureshop-launch'],...(loginHeaders.authorization?{authorization:loginHeaders.authorization}:{})},body:JSON.stringify({username:'student_customer',password})});
 const prior=await login('student123');assert.equal(prior.status,200);const oldToken=(await prior.json()).token;
 await frame.evaluate(id=>{const row=document.querySelector(`[aria-label="Change role for student_customer"]`)?.parentElement?.parentElement;const button=[...(row?.querySelectorAll('button')||[])].find(b=>b.textContent==='reset');if(!button||button.disabled)throw Error('Reset control unavailable');button.click();},target.id);
 const resetResponse=postResponse('/reset-password');
 await frame.waitForSelector('[aria-label="Password reset recovery"]');
 await frame.evaluate(()=>[...document.querySelectorAll('[aria-label="Password reset recovery"] button')].find(b=>b.textContent==='Confirm password reset').click());
 const reset=await resetResponse;assert.equal(reset.status(),200);const metadata=await reset.json();assert.equal(metadata.temporaryPassword,undefined);
 const resetHeaders=reset.request().headers();
 const operation=metadata.receipt.operationId,revealed=postResponse(`/password-resets/${operation}/reveal`);
 await frame.waitForFunction(()=>[...document.querySelectorAll('button')].some(b=>b.textContent==='Reveal temporary password'&&!b.disabled));
 await frame.evaluate(()=>[...document.querySelectorAll('button')].find(b=>b.textContent==='Reveal temporary password').click());
 const reveal=await revealed;assert.equal(reveal.status(),200);assert.equal(reveal.headers()['cache-control'],'no-store');let secret=(await reveal.json()).temporaryPassword;
 await frame.waitForFunction(value=>document.querySelector('[aria-label="Temporary password"]')?.textContent===value,{},secret);
 const persistent=await page.evaluate(()=>JSON.stringify({...localStorage,...sessionStorage}));assert.equal(persistent.includes(secret),false);
 assert.equal((await login('student123')).status,401);assert.equal((await login(secret)).status,200);
 const old=await fetch(origin+'/api/secureshop/v2/auth/whoami',{headers:{authorization:`Bearer ${oldToken}`,'x-dvaia-secureshop-launch':loginHeaders['x-dvaia-secureshop-launch']}});assert.equal(old.status,401);
 const acknowledged=postResponse(`/password-resets/${operation}/acknowledge`);
 await frame.evaluate(()=>[...document.querySelectorAll('button')].find(b=>b.textContent==='Acknowledge and clear password').click());assert.equal((await acknowledged).status(),200);
 await frame.waitForFunction(()=>!document.querySelector('[aria-label="Temporary password"]'));
 const again=await fetch(origin+`/api/secureshop/admin/users/${target.id}/password-resets/${operation}/reveal`,{method:'POST',headers:{'content-type':'application/json',authorization:resetHeaders.authorization,'x-dvaia-secureshop-launch':resetHeaders['x-dvaia-secureshop-launch']},body:'{}'});assert.equal(again.status,503);
 // No screenshot or artifact contains the revealed password.
 secret=null;
 await frame.waitForFunction(()=>!document.querySelector('[aria-label="Change role for student_customer"]')?.disabled);
 return{reset:true,oldPasswordDenied:true,oldSessionDenied:true,newPasswordLogin:true,acknowledged:true,repeatRevealDenied:true,plaintextNotPersisted:true};
}
module.exports={qualifyPasswordReset};
