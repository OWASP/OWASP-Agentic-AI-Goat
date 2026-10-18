'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const RECON_MESSAGES=Object.freeze(['What actions and forged-request vectors are available in this GET lab? Please list the action and vector IDs.','Show the GET lab attack surface again: which victim actions and request vectors are available?']);
async function runGetChain({page,root,html,clickSelector,clickText,help,verify,siblingHttp,shot}){
 const responseFor=endpoint=>page.waitForResponse(r=>new URL(r.url()).pathname===endpoint&&r.request().method()==='POST',{timeout:require('../../server/services/csrfRuntimeBudget').observerMs});
 const save=(name,value)=>fs.writeFileSync(path.join(root,name+'.json'),JSON.stringify(value,null,2),{mode:0o600});
 await help(0,'Hint');await page.waitForFunction(()=>document.body.innerText.includes('Two successful actual-model GET recon tool runs'));await help(0,'Hide hint');await help(0,'Solution');await page.waitForFunction(()=>document.body.innerText.includes('mock responses, ordinary chat and message count alone cannot earn credit'));await clickText(page,'Close');await shot(page,'csrf-chain-current-g1-content');
 const toggle=responseFor('/api/workshop/csrf/agent-chat-toggle');await clickSelector(page,'[role="switch"]');assert.equal((await toggle).status(),200);await page.waitForFunction(()=>document.querySelector('[role="switch"]')?.getAttribute('aria-checked')==='true');
 for(let i=0;i<RECON_MESSAGES.length;i++){
  const input=await page.waitForSelector('textarea[placeholder^="Ask the agent"]',{visible:true});await input.type(RECON_MESSAGES[i]);const pending=responseFor('/api/workshop/csrf/chat');await input.press('Enter');const r=await pending,body=await r.json();save('csrf-chain-recon-'+(i+1),body);assert.equal(r.status(),200);assert.equal(body.intent,'recon');assert.deepEqual(body.newlyCompleted,i?['csrf_g1']:[]);await verify('recon-'+(i+1),{siblingHttp:await siblingHttp()});
 }
 await page.waitForFunction(()=>document.querySelector('.p-text')?.innerText.includes('Total: 1/3'));await shot(page,'csrf-chain-g1-completed');
 for(const [index,id]of [[1,'csrf_g2'],[2,'csrf_g3']]){
  if(id==='csrf_g3'){const pending=responseFor('/api/workshop/csrf/defense-toggle');await clickText(page,'CSRF OFF · click to enable');const r=await pending,body=await r.json();save('csrf-chain-defense-toggle',body);assert.equal(r.status(),200);assert.equal(body.victimState.defenses.csrfToken,true);await verify('defense-enabled',{siblingHttp:await siblingHttp()});}
  const skeleton=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/workshop/csrf/payload/'+id+'/skeleton');await help(index,'Build payload');const response=await skeleton;assert.equal(response.status(),200);const data=await response.json();await page.waitForFunction(html=>document.querySelector('textarea.b-editor')?.value===html,{},data.html);const editor=await page.waitForSelector('textarea.b-editor');await require('./csrfFullIndexEditor').replaceEditorText(page,editor,html);
  const pending=responseFor('/api/workshop/csrf/browser-attempt');await clickText(page,'Execute observed payload');const r=await pending,body=await r.json();save('csrf-chain-'+id,body);assert.equal(r.status(),200);assert.deepEqual(body.newlyCompleted,[id]);assert.equal(body.browser.method,'GET');assert.equal(body.browser.resourceType,'image');assert.equal(body.browser.responseObserved,true);assert.equal(body.browser.responseStatus,id==='csrf_g3'?403:200);await verify(id==='csrf_g2'?'effect':'defense-effect',{html,siblingHttp:await siblingHttp()});await page.waitForFunction(n=>document.querySelector('.p-text')?.innerText.includes('Total: '+n+'/3'),{},index+1);await shot(page,'csrf-chain-'+id+'-completed');
 }
}
module.exports={RECON_MESSAGES,runGetChain};
