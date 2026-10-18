'use strict';
const assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const key='secureshop_agent_security',id='ss_mail_cross_persona_read';
async function prepareDisclosureCatalog({identity,migration,users,config,user,passwordHash,launches,jwtSecret,transport,observations}){
 const seedUpgrade=await require('./secureshopMailDisclosureSeedUpgrade').qualifyDisclosureSeedUpgrade({identity,migration,config});
 const initial=(await identity.query('SELECT label,hint_content,solution_content FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2',[key,id])).rows[0];assert(initial?.hint_content&&initial.solution_content);
 const admin=await users.createUser({username:'disclosure-admin-'+randomUUID().slice(0,8),email:randomUUID()+'@example.invalid',passwordHash});await migration.query("UPDATE identity.users SET role='super_admin',admin_level=2,email_verified=1 WHERE id=$1",[admin.id]);for(const permission of ['user_management','challenge_management','system_config','manage_progress','system_logs','view_analytics'])await users.grantPermission({userId:admin.id,permission,grantedBy:admin.id});
 await config.setMasterHintVisibility(key,true);await config.setMasterSolutionVisibility(key,true);await config.setObjectiveHintVisibility(key,id,true);await config.setObjectiveSolutionVisibility(key,id,true);
 const snapshot=async()=>(await identity.query('SELECT objective_id,label,hint_content,solution_content,is_enabled FROM workshop_platform.objectives WHERE workshop_key=$1 ORDER BY objective_id',[key])).rows;
 // Preserve instructor content while restoring authentic disclosure teaching bytes for rendering.
 const customized={...initial.hint_content,title:'Owned instructor disclosure hint'};await config.updateHintContent(key,id,customized);const before=await snapshot();await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);assert.deepEqual(await snapshot(),before);await config.updateHintContent(key,id,initial.hint_content);
 const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
 const counts=async()=>(await identity.query('SELECT count(*)::int n FROM workshop_platform.objective_judgments WHERE user_id=$1 AND objective_id=$2',[user.id,id])).rows[0].n;
 return{seedUpgrade,admin,label:initial.label,expectedContent:{hint:initial.hint_content,solution:initial.solution_content},async beforeProjection({page,launch}){
  const binding=await require('./secureshopMailHeaderCatalogApp').resolveBrowserBinding({token:await page.evaluate(()=>localStorage.getItem('token')),launch,userId:user.id,jwtSecret,users,launches});
  const scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(binding),beforeCalls=transport.counts().generation,beforeJudgments=await counts();
  await earnDisclosure({page,foreign:(await observations.personas()).student_customer});
  assert.equal(transport.counts().generation,beforeCalls+1);assert.equal(await counts(),beforeJudgments+1);
  await progress.recordHeartbeat({userId:user.id,workshopKey:key,instanceScope:scope});await new Promise(resolve=>setTimeout(resolve,1200));await progress.recordHeartbeat({userId:user.id,workshopKey:key,instanceScope:scope});
  const current=await progress.getWorkshopProgress(user.id,key);assert.equal(current.completedObjectiveCount,1);assert.equal(current.objectiveCount,1);assert(current.timeSpentSeconds>0);
  return{...current,displayScope:scope,actorCalls:0,judgeCalls:0,timingEvidence:'Two canonical owned heartbeat calls separated by 1200ms; controlled transport completion through actual Inbox',readCurrentProjection:()=>progress.getWorkshopProgress(user.id,key),async afterReset(){assert.equal((await progress.getWorkshopProgress(user.id,key)).completedObjectiveCount,0);assert.equal(await counts(),beforeJudgments+1);assert.equal(transport.counts().generation,beforeCalls+1);}};
 }};
}
async function earnDisclosure({page,foreign}){
 const el=await page.waitForSelector('iframe[title="SecureShop workshop"]'),frame=await el.contentFrame();await frame.waitForFunction(()=>document.querySelector('#ss-login-user')||document.querySelector('a[href="/secureshop/login"]'));if(!await frame.$('#ss-login-user'))await frame.click('a[href="/secureshop/login"]');await frame.waitForSelector('#ss-login-user');await frame.type('#ss-login-user','student_merchant');await frame.type('#ss-login-pw','student123');await frame.click('button[type="submit"]');await frame.waitForSelector('a[href="/secureshop/merchant/inbox"]');await frame.click('a[href="/secureshop/merchant/inbox"]');await frame.waitForSelector('[data-testid="inbox-userid"]');
 const click=async label=>{const b=await require('./secureshopMailHeaderFullAppBrowser').waitForMailButton(frame,label);await b.evaluate(e=>e.scrollIntoView({block:'center',behavior:'instant'}));await b.click();};
 // Exact synthetic target template supplied by owned fixture observation; no receipt or completion injection.
 assert(Number.isSafeInteger(foreign?.id)&&typeof foreign.email==='string');
 await click('Compose');await frame.waitForSelector('[role="dialog"] input[placeholder="someone@example.com"]');const fields=await frame.$$('[role="dialog"] input');await fields[0].type(foreign.email);await fields[2].type('Owned catalog disclosure');await frame.type('[role="dialog"] textarea','Synthetic catalog proof.');const sent=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/secureshop/email/send'&&r.request().method()==='POST');await click('Send');assert.equal((await sent).status(),200);await frame.waitForFunction(require('./secureshopMailHeaderFullAppBrowser').composeClosed);
 await require('./secureshopMailDisclosureBrowser').selectInboxUser({page,frame,id:foreign.id});await click('Read for assessment');await frame.waitForFunction(()=>document.body.innerText.includes('Disclosure read saved'));await click('Check saved disclosure');await frame.waitForFunction(()=>document.body.innerText.includes('Objective completed.'));
}
module.exports={prepareDisclosureCatalog,earnDisclosure};
