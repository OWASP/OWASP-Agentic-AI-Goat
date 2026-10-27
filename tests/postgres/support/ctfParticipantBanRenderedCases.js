'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {createHash} = require('node:crypto');

const TARGET = 3011;
const POST_PATHS = Object.freeze({ban: `/api/ctf/admin/participants/${TARGET}/ban`, unban: `/api/ctf/admin/participants/${TARGET}/unban`});
const FACT_KEYS = Object.freeze(['cancelNoPost','cancelStateUnchanged','abaNoPost','abaStateUnchanged','banDurableBothStores','unbanDurableBothStores','reloadBan','reloadUnban','targetEvidencePreserved','platformPreserved','siblingPreserved','operationsApplied','noSecondPost']);
const sha = value => createHash('sha256').update(value).digest('hex');
const rows = async (pool, sql, args = []) => (await pool.query(sql, args)).rows;
const encoded = value => JSON.stringify(value);
function installBanStorageObserver(target) {
 const scope=target||window;
 if(scope.__ctfBanStorageObserver)scope.removeEventListener('storage',scope.__ctfBanStorageObserver);
 scope.__ctfBanStorageEvents=0;
 scope.__ctfBanStorageObserver=event=>{if(event.key==='token'&&event.storageArea===scope.localStorage)scope.__ctfBanStorageEvents++;};
 scope.addEventListener('storage',scope.__ctfBanStorageObserver);
}
function installBanRosterXhrObserver(target) {
 const scope=target||window;
 if(scope.__ctfBanRosterXhrInstalled)return;
 const XHR=scope.XMLHttpRequest;
 if(typeof XHR?.prototype?.open!=='function')throw Error('CTF roster XHR observer unavailable');
 scope.__ctfBanRosterXhrInstalled=true;
 scope.__ctfBanRosterXhr={version:1,events:[],overflow:0};
 const original=XHR.prototype.open;
 XHR.prototype.open=function(method,url,...rest){
  let pathname=null;
  try{const parsed=new URL(url,scope.location.href);if(parsed.origin===scope.location.origin&&String(method).toUpperCase()==='GET'&&['/api/ctf/leaderboard','/api/ctf/admin/participants'].includes(parsed.pathname))pathname=parsed.pathname;}catch{}
  if(pathname){
   let settled=false;
   const terminal=event=>{
    if(settled)return;settled=true;
    const record={path:pathname,terminal:event.type,status:Number.isInteger(this.status)&&this.status>=0&&this.status<=599?this.status:null,rowCount:null,targetPresent:null,bodyParsed:false};
    if(event.type==='load'&&record.status>=200&&record.status<300){
     try{
      const textResponse=(this.responseType===''||this.responseType==='text')&&typeof this.responseText==='string'&&this.responseText.length<=1048576;
      const value=this.responseType==='json'?this.response:textResponse?JSON.parse(this.responseText):null;
      const list=pathname==='/api/ctf/leaderboard'?value?.leaderboard:value?.participants;
      if(Array.isArray(list)&&list.length<=10000){record.bodyParsed=true;record.rowCount=list.length;record.targetPresent=list.some(row=>pathname==='/api/ctf/leaderboard'?String(row?.participant_id)==='3011':String(row?.id)==='3011'&&String(row?.user_id)==='3011');}
     }catch{}
    }
    const events=scope.__ctfBanRosterXhr.events;
    if(events.length<16)events.push(record);else scope.__ctfBanRosterXhr.overflow++;
   };
   for(const name of ['load','error','abort','timeout'])this.addEventListener(name,terminal,{once:true});
  }
  return original.call(this,method,url,...rest);
 };
}
function collectBanFailureObservation(target) {
 const scope=target||window,doc=scope.document;
 const nav=doc.querySelector('nav[aria-label="CTF admin sections"]');
 const selected=[...(nav?.querySelectorAll('button')||[])].filter(button=>button.getAttribute('aria-selected')==='true');
 const selectedTab=selected.length===1?selected[0].textContent.trim()==='Leaderboard'?'leaderboard':'other':'unknown';
 const rows=[...doc.querySelectorAll('tbody tr')];
 const targets=rows.filter(row=>{
  const usernameCell=row.querySelectorAll('td')[1];
  return usernameCell&&[...usernameCell.childNodes].filter(node=>node.nodeType===3).map(node=>node.textContent).join('').trim()==='content-11';
 });
 return {version:1,pathname:scope.location.pathname,selectedTab,tableRows:Math.min(rows.length,10000),targetRows:Math.min(targets.length,10000),
  targetBanButtons:Math.min(targets.flatMap(row=>[...row.querySelectorAll('button')]).filter(button=>button.textContent.trim()==='Ban').length,10000),
  targetUnbanButtons:Math.min(targets.flatMap(row=>[...row.querySelectorAll('button')]).filter(button=>button.textContent.trim()==='Unban').length,10000),
  rosterXhr:scope.__ctfBanRosterXhr||null};
}
function banTargetAction(label,target) {
 const doc=target||document;
 const rows=[...doc.querySelectorAll('tbody tr')].filter(row=>{
  const usernameCell=row.querySelectorAll('td')[1];
  return usernameCell&&[...usernameCell.childNodes].filter(node=>node.nodeType===3).map(node=>node.textContent).join('').trim()==='content-11';
 });
 if(rows.length!==1)return null;
 const labels=label==='either'?['Ban','Unban']:[label];
 const actions=[...rows[0].querySelectorAll('button')].filter(button=>!button.disabled&&labels.includes(button.textContent.trim()));
 return actions.length===1?actions[0]:null;
}

function assertContentParticipantBanReceipt(r) {
 assert.deepEqual(Object.keys(r).sort(), ['version','profile','modelCalls','judgeCalls','targetId','browserPostCounts','serverOperationCounts','observedPaths','cancelPostCounts','abaPostCounts','abaEvents','flags','facts','unexpectedApiPaths','stage'].sort());
 assert.equal(r.version, 1);
 assert.equal(r.profile, 'ctf-participant-ban-unban-q05');
 assert.equal(r.modelCalls, 0); assert.equal(r.judgeCalls, 0); assert.equal(r.targetId, TARGET);
 assert.deepEqual(r.browserPostCounts, {ban:1,unban:1});
 assert.deepEqual(r.serverOperationCounts, {ban:1,unban:1});
 assert.deepEqual(r.observedPaths, POST_PATHS);
 assert.deepEqual(r.cancelPostCounts, {ban:0,unban:0});
 assert.deepEqual(r.abaPostCounts, {ban:0,unban:0});
 assert.deepEqual(r.abaEvents, {ban:2,unban:2});
 assert.deepEqual(r.flags, {before:false,afterBan:true,afterUnban:false});
 assert.deepEqual(Object.keys(r.facts).sort(), [...FACT_KEYS].sort());
 for (const key of FACT_KEYS) assert.equal(r.facts[key], true, key);
 assert.deepEqual(r.unexpectedApiPaths, []); assert.equal(r.stage, 'complete');
 return r;
}

async function contentParticipantBanCases({i,c,origin,instructor,action,click,pointer,admin,mounted,adapter,ledger,receiptPath,unexpectedApiPaths,userRequest,mutate}) {
 const r={version:1,profile:'ctf-participant-ban-unban-q05',modelCalls:0,judgeCalls:0,targetId:TARGET,
  browserPostCounts:{ban:0,unban:0},serverOperationCounts:{ban:0,unban:0},observedPaths:{ban:null,unban:null},cancelPostCounts:{ban:0,unban:0},abaPostCounts:{ban:0,unban:0},abaEvents:{ban:0,unban:0},
  flags:{before:null,afterBan:null,afterUnban:null},facts:Object.fromEntries(FACT_KEYS.map(key=>[key,false])),unexpectedApiPaths:[],stage:'start'};
 const save=()=>fs.writeFileSync(receiptPath,JSON.stringify(r,null,2),{mode:0o600});save();
 const step=value=>{assert.equal(ledger.length,0);r.stage=value;save();};
 const targetEvidence=async()=>({
  participant:await rows(c.runtime,'SELECT * FROM ctf.ctf_participants WHERE user_id=$1',[TARGET]),
  progress:await rows(c.runtime,'SELECT * FROM ctf.ctf_progress WHERE participant_id=$1 ORDER BY id',[TARGET]),
  attempts:await rows(c.runtime,'SELECT * FROM ctf.ctf_attempts WHERE participant_id=$1 ORDER BY id',[TARGET]),
  sessions:await rows(c.runtime,'SELECT * FROM ctf.ctf_sessions WHERE participant_id=$1 ORDER BY id',[TARGET]),
  leaderboard:await rows(c.runtime,'SELECT * FROM ctf.ctf_leaderboard WHERE participant_id=$1',[TARGET]),
  identityProgress:await rows(i.migration,'SELECT * FROM identity.ctf_progress_bindings WHERE owner_id=$1 ORDER BY progress_id',[TARGET]),
 });
 const sibling=async()=>({
  participant:await rows(c.runtime,'SELECT * FROM ctf.ctf_participants WHERE user_id=1001'),
  progress:await rows(c.runtime,'SELECT * FROM ctf.ctf_progress WHERE participant_id=1001 ORDER BY id'),
  attempts:await rows(c.runtime,'SELECT * FROM ctf.ctf_attempts WHERE participant_id=1001 ORDER BY id'),
  sessions:await rows(c.runtime,'SELECT * FROM ctf.ctf_sessions WHERE participant_id=1001 ORDER BY id'),
  leaderboard:await rows(c.runtime,'SELECT * FROM ctf.ctf_leaderboard WHERE participant_id=1001'),
  ban:await rows(c.runtime,'SELECT * FROM ctf.ctf_bans WHERE user_id=1001'),
  authority:await rows(i.migration,"SELECT * FROM identity.ctf_authority WHERE scope_key='owner:1001'"),
  binding:await rows(i.migration,'SELECT * FROM identity.ctf_participant_bindings WHERE owner_id=1001 ORDER BY participant_id'),
  identityProgress:await rows(i.migration,'SELECT * FROM identity.ctf_progress_bindings WHERE owner_id=1001 ORDER BY progress_id'),
  identityTechnique:await rows(i.migration,"SELECT * FROM identity.ctf_adaptive_memory WHERE owner_id=1001 AND kind='technique' ORDER BY memory_id"),
  account:await rows(i.migration,'SELECT id,role,admin_level,is_active,account_locked_until,login_attempts,password_reset_required FROM identity.users WHERE id=1001'),
  platformSessions:await rows(i.migration,'SELECT id,user_id,session_token_hash,is_active,expires_at,created_at,revoked_at,revoked_by,revoke_reason FROM identity.user_sessions WHERE user_id=1001 ORDER BY id'),
 });
 const platform=async()=>({
  account:await rows(i.migration,'SELECT id,role,admin_level,is_active,account_locked_until,login_attempts,password_reset_required FROM identity.users WHERE id=$1',[TARGET]),
  sessions:await rows(i.migration,'SELECT id,user_id,session_token_hash,is_active,expires_at,created_at,revoked_at,revoked_by,revoke_reason FROM identity.user_sessions WHERE user_id=$1 ORDER BY id',[TARGET]),
 });
 const flags=async()=>({
  ctf:await rows(c.runtime,'SELECT user_id,reason,banned_by FROM ctf.ctf_bans WHERE user_id=$1',[TARGET]),
  authority:await rows(i.migration,"SELECT owner_generation::text,revision::text,banned,lifecycle_state FROM identity.ctf_authority WHERE scope_key=$1",['owner:'+TARGET]),
  binding:await rows(i.migration,'SELECT owner_id,participant_id,owner_generation::text,active,banned,applied_sequence::text,applied_operation_id::text FROM identity.ctf_participant_bindings WHERE owner_id=$1',[TARGET]),
 });
 const state=async()=>({evidence:await targetEvidence(),sibling:await sibling(),platform:await platform(),flags:await flags()});
 // Existing populated 3011 has ten completed progress rows but no CTF session.
 // Recover its registration through the ordinary owned learner route so the
 // session-preservation assertion below is non-vacuous without fabricating SQL.
 const beforeRegistration=await targetEvidence();
 assert.equal(beforeRegistration.progress.filter(row=>row.status==='completed').length,10);
 assert.equal(beforeRegistration.sessions.length,0);
 const learner=await userRequest(TARGET);
 const recovered=await mutate(learner,'register',{});
 assert.equal(recovered.status,200,'Canonical active-recovery registration must be acknowledged');
 const afterRegistration=await targetEvidence();
 assert.equal(encoded(afterRegistration.progress),encoded(beforeRegistration.progress));
 assert.equal(encoded(afterRegistration.attempts),encoded(beforeRegistration.attempts));
 assert.equal(afterRegistration.sessions.length,1);
 assert.equal(afterRegistration.sessions[0].is_active,1);
 const registerRows=await rows(i.migration,"SELECT actor_id::text,session_id::text,registration_disposition,registration_participant_before::text,canonical_command FROM identity.ctf_outbox WHERE kind='register' AND canonical_command::jsonb->'scope'->>'ownerId'=$1 ORDER BY sequence",[String(TARGET)]);
 const recoveredRow=registerRows.at(-1);
 assert.equal(recoveredRow?.actor_id,String(TARGET));
 assert.equal(recoveredRow?.session_id,String(learner.identitySession.id));
 assert.equal(recoveredRow?.registration_disposition,'active_recovery');
 assert.equal(recoveredRow?.registration_participant_before,String(TARGET));
 assert.equal(JSON.parse(recoveredRow.canonical_command).scope.ownerId,String(TARGET));
 const mountedAuthority=await adapter.validateSession(mounted.adminToken);
 assert(mountedAuthority?.user?.id&&mountedAuthority?.session?.id);
 assert.notEqual(String(mountedAuthority.user.id),String(admin.user.id));
 const tokenA=mounted.adminToken,tokenB=admin.headers.authorization.slice(7);
 assert.notEqual(tokenA,tokenB);
 const before=await state();
 assert.equal(before.evidence.progress.filter(row=>row.status==='completed').length,10);
 assert(before.evidence.progress.every(row=>row.attempts_count===3));
 assert.equal(before.evidence.sessions.length,1);
 assert.equal(before.evidence.sessions[0].is_active,1);
 assert(before.platform.sessions.length>0);
 assert.equal(before.evidence.participant.length,1);
 assert.equal(Number(before.evidence.participant[0].id),TARGET);
 assert.equal(Number(before.evidence.participant[0].user_id),TARGET);
 for(const key of ['participant','progress','attempts','sessions','leaderboard','authority','binding','identityProgress','identityTechnique','account'])assert(before.sibling[key].length>0,'Seeded sibling '+key+' must be nonempty');
 assert.equal(before.flags.ctf.length,0);
 assert.equal(before.flags.authority.length,1);assert.equal(before.flags.authority[0].banned,false);assert.equal(before.flags.authority[0].lifecycle_state,'ready');
 assert.equal(before.flags.binding.length,1);assert.equal(before.flags.binding[0].banned,false);assert.equal(before.flags.binding[0].active,true);
 r.flags.before=false;
 const beforeSequence=String((await i.migration.query('SELECT COALESCE(max(sequence),0)::text AS n FROM identity.ctf_outbox')).rows[0].n);
 const applied=async()=>{
  const all=await rows(i.migration,"SELECT sequence::text,operation_id::text,actor_id::text,session_id::text,kind,state,canonical_command,command_hash,canonical_result,result_hash FROM identity.ctf_outbox WHERE sequence>$1 AND kind IN ('ban','unban') ORDER BY sequence",[beforeSequence]);
  const selected=all.filter(row=>{
   const command=JSON.parse(row.canonical_command);
   return command.scope?.ownerId===String(TARGET);
  });
  const counts={ban:0,unban:0};
  for(const row of selected){
   counts[row.kind]++;
   assert.equal(row.state,'applied');
   assert.equal(row.actor_id,String(mountedAuthority.user.id));
   assert.equal(row.session_id,String(mountedAuthority.session.id));
   assert.equal(sha(row.canonical_command),row.command_hash);
   assert.equal(sha(row.canonical_result),row.result_hash);
   const command=JSON.parse(row.canonical_command),result=JSON.parse(row.canonical_result);
   assert.equal(command.kind,row.kind);
   assert.equal(command.actorId,String(mountedAuthority.user.id));
   assert.equal(command.scope.ownerId,String(TARGET));
   if(row.kind==='ban')assert.equal(command.body.reason,'Controlled CTF ban 3011');
   assert.equal(result.kind,row.kind);
   assert.equal(result.data.ownerId,String(TARGET));
   assert.equal(result.data.banned,row.kind==='ban');
   const receipt=await rows(c.runtime,'SELECT sequence::text,operation_id::text,kind,command_hash,canonical_result,result_hash FROM ctf.projection_receipts WHERE operation_id=$1',[row.operation_id]);
   assert.deepEqual(receipt,[{sequence:row.sequence,operation_id:row.operation_id,kind:row.kind,command_hash:row.command_hash,canonical_result:row.canonical_result,result_hash:row.result_hash}]);
  }
  return {counts,selected};
 };
 const unchanged=async baseline=>encoded(await state())===encoded(baseline);
 const preserved=async current=>encoded(current.evidence)===encoded(before.evidence) && encoded(current.sibling)===encoded(before.sibling) && encoded(current.platform)===encoded(before.platform);
 const button=async label=>action(()=>instructor.waitForFunction(banTargetAction,{},label));
 const showLeaderboard=async()=>{
  await click(instructor,'nav[aria-label="CTF admin sections"] button','Leaderboard');
  const h=await button('either');await h.dispose();
 };
 const dialog=async kind=>{
  const h=await button(kind==='ban'?'Ban':'Unban');
  try{await pointer(instructor,h,action);}finally{await h.dispose();}
  const title=kind==='ban'?'Ban participant from CTF':'Unban participant from CTF';
  const ready=await action(()=>instructor.waitForFunction(title=>{
   const ds=[...document.querySelectorAll('[role="dialog"]')].filter(d=>d.querySelector('h3')?.textContent.trim()===title);
   return ds.length===1&&ds[0].textContent.includes('content-11')&&ds[0].textContent.includes('platform account remain');
  },{},title));await ready.dispose();
 };
 const switcher=await action(()=>instructor.browserContext().newPage());
 let promptCount=0,promptFailure=null;
 const onPrompt=prompt=>{if(prompt.type()!=='prompt'){promptFailure=Error('Unexpected CTF browser dialog');void prompt.dismiss().catch(error=>{promptFailure=error;});return;}promptCount++;void prompt.accept('Controlled CTF ban 3011').catch(error=>{promptFailure=error;});};
 const onRequest=req=>{if(req.method()!=='POST')return;const u=new URL(req.url());for(const kind of ['ban','unban'])if(u.origin===origin&&u.pathname===POST_PATHS[kind]){r.browserPostCounts[kind]++;r.observedPaths[kind]=u.pathname;}};
 instructor.on('dialog',onPrompt);instructor.on('request',onRequest);
 let complete=false,primaryFailure;
 try{
  await action(()=>instructor.evaluateOnNewDocument(installBanRosterXhrObserver));
  await action(()=>instructor.evaluate(installBanRosterXhrObserver));
  await action(()=>switcher.setRequestInterception(true));
  switcher.on('request',req=>{const u=new URL(req.url());return u.origin===origin||['about:','data:','blob:'].includes(u.protocol)?req.continue():req.abort();});
  await action(()=>switcher.goto(origin+'/api/ctf/config',{waitUntil:'domcontentloaded'}));
  const aba=async kind=>{
   await dialog(kind);
   // A reload replaces the document. Each ABA phase installs its own observer
   // in the currently rendered page before the other tab writes.
   await action(()=>instructor.evaluate(installBanStorageObserver));
   const confirm=kind==='ban'?'Confirm Ban':'Confirm Unban';
   const retained=await action(()=>instructor.evaluateHandle(label=>[...document.querySelectorAll('[role="dialog"] button')].find(node=>node.textContent.trim()===label),confirm));
   try{
    const initial=await action(()=>instructor.evaluate(()=>window.__ctfBanStorageEvents));
    await action(()=>switcher.evaluate(([b,a])=>{localStorage.setItem('token',b);localStorage.setItem('token',a);},[tokenB,tokenA]));
    // Attempt the retained physical control immediately after the cross-tab write.
    // The storage events can retire it before the pointer reaches the DOM.
    try{await pointer(instructor,retained,action);}catch(error){
     const retired=await action(()=>instructor.evaluate(()=>!document.querySelector('[role="dialog"]')));
     if(!retired)throw error;
    }
    const observed=await action(()=>instructor.waitForFunction(n=>(window.__ctfBanStorageEvents||0)>=n+2,{polling:100,timeout:15000},initial));await observed.dispose();
    r.abaEvents[kind]=(await action(()=>instructor.evaluate(()=>window.__ctfBanStorageEvents)))-initial;
    assert.equal(r.abaEvents[kind],2);
    const retired=await action(()=>instructor.waitForFunction(()=>!document.querySelector('[role="dialog"]')));await retired.dispose();
   }finally{await retained.dispose();}
  };
  step('cancel-ban');await showLeaderboard();await dialog('ban');await click(instructor,'[role="dialog"] button','Cancel');
  assert.deepEqual(r.browserPostCounts,{ban:0,unban:0});assert.deepEqual((await applied()).counts,{ban:0,unban:0});
  r.cancelPostCounts={...r.browserPostCounts};r.facts.cancelNoPost=true;r.facts.cancelStateUnchanged=await unchanged(before);assert(r.facts.cancelStateUnchanged);save();
  step('aba-ban');await aba('ban');assert.deepEqual(r.browserPostCounts,{ban:0,unban:0});assert.deepEqual((await applied()).counts,{ban:0,unban:0});
  r.abaPostCounts={...r.browserPostCounts};r.facts.abaNoPost=true;r.facts.abaStateUnchanged=await unchanged(before);assert(r.facts.abaStateUnchanged);save();
  step('confirm-ban');await action(()=>instructor.reload({waitUntil:'domcontentloaded'}));await showLeaderboard();
  const banResponse=action(()=>instructor.waitForResponse(response=>response.request().method()==='POST'&&new URL(response.url()).pathname===POST_PATHS.ban,{timeout:15000}));
  await dialog('ban');await click(instructor,'[role="dialog"] button','Confirm Ban');assert([200,202].includes((await banResponse).status()));
  const banned=await button('Unban');assert.equal(await action(()=>banned.evaluate(button=>[...button.closest('tr').querySelectorAll('td')[1].querySelectorAll('span')].some(badge=>badge.textContent.trim()==='banned'))),true);await banned.dispose();
  const afterBan=await state();assert.equal(afterBan.flags.ctf.length,1);assert.equal(Number(afterBan.flags.ctf[0].user_id),TARGET);assert.equal(afterBan.flags.ctf[0].reason,'Controlled CTF ban 3011');assert.equal(Number(afterBan.flags.ctf[0].banned_by),Number(mountedAuthority.user.id));assert.equal(afterBan.flags.authority[0].banned,true);assert.equal(afterBan.flags.authority[0].lifecycle_state,'ready');assert.equal(afterBan.flags.binding[0].banned,true);assert.equal(afterBan.flags.binding[0].active,true);r.flags.afterBan=true;
  r.facts.banDurableBothStores=true;assert(await preserved(afterBan));r.facts.targetEvidencePreserved=true;r.facts.platformPreserved=true;r.facts.siblingPreserved=true;
  const banApplied=await applied();assert.deepEqual(banApplied.counts,{ban:1,unban:0});
  assert.equal(afterBan.flags.binding[0].applied_operation_id,banApplied.selected[0].operation_id);save();
  step('reload-ban');await action(()=>instructor.reload({waitUntil:'domcontentloaded'}));await showLeaderboard();const unban=await button('Unban');await unban.dispose();r.facts.reloadBan=true;
  step('cancel-unban');await dialog('unban');await click(instructor,'[role="dialog"] button','Cancel');assert.deepEqual(r.browserPostCounts,{ban:1,unban:0});assert.deepEqual((await applied()).counts,{ban:1,unban:0});assert(await unchanged(afterBan));save();
  step('aba-unban');await aba('unban');assert.deepEqual(r.browserPostCounts,{ban:1,unban:0});assert.deepEqual((await applied()).counts,{ban:1,unban:0});assert(await unchanged(afterBan));save();
  step('confirm-unban');await action(()=>instructor.reload({waitUntil:'domcontentloaded'}));await showLeaderboard();
  const unbanResponse=action(()=>instructor.waitForResponse(response=>response.request().method()==='POST'&&new URL(response.url()).pathname===POST_PATHS.unban,{timeout:15000}));
  await dialog('unban');await click(instructor,'[role="dialog"] button','Confirm Unban');assert([200,202].includes((await unbanResponse).status()));
  const unbanned=await button('Ban');assert.equal(await action(()=>unbanned.evaluate(button=>[...button.closest('tr').querySelectorAll('td')[1].querySelectorAll('span')].some(badge=>badge.textContent.trim()==='banned'))),false);await unbanned.dispose();
  const afterUnban=await state();assert.equal(afterUnban.flags.ctf.length,0);assert.equal(afterUnban.flags.authority[0].banned,false);assert.equal(afterUnban.flags.authority[0].lifecycle_state,'ready');assert.equal(afterUnban.flags.binding[0].banned,false);assert.equal(afterUnban.flags.binding[0].active,true);r.flags.afterUnban=false;
  r.facts.unbanDurableBothStores=true;assert(await preserved(afterUnban));const bothApplied=await applied();assert.deepEqual(bothApplied.counts,{ban:1,unban:1});
  assert.deepEqual(bothApplied.selected.map(row=>row.kind),['ban','unban']);
  assert.equal(afterUnban.flags.binding[0].applied_operation_id,bothApplied.selected[1].operation_id);
  const rev=[before,afterBan,afterUnban].map(x=>BigInt(x.flags.authority[0].revision));assert.equal(rev[1],rev[0]+1n);assert.equal(rev[2],rev[1]+1n);
  assert.equal(afterBan.flags.authority[0].owner_generation,before.flags.authority[0].owner_generation);assert.equal(afterUnban.flags.authority[0].owner_generation,before.flags.authority[0].owner_generation);
  for(const current of [afterBan,afterUnban])for(const field of ['owner_id','participant_id','owner_generation','active'])assert.equal(current.flags.binding[0][field],before.flags.binding[0][field]);
  r.serverOperationCounts=bothApplied.counts;r.facts.operationsApplied=true;r.facts.noSecondPost=r.browserPostCounts.ban===1&&r.browserPostCounts.unban===1;assert(r.facts.noSecondPost);save();
  step('reload-unban');await action(()=>instructor.reload({waitUntil:'domcontentloaded'}));await showLeaderboard();const ban=await button('Ban');await ban.dispose();r.facts.reloadUnban=true;
  assert(await preserved(await state()));assert.equal(promptCount,3);assert.equal(promptFailure,null);
  r.unexpectedApiPaths=unexpectedApiPaths.slice();r.stage='complete';assertContentParticipantBanReceipt(r);save();complete=true;
  return async()=>{
   try{
    assert.deepEqual(r.browserPostCounts,{ban:1,unban:1});
    assert.deepEqual((await applied()).counts,{ban:1,unban:1});
    r.unexpectedApiPaths=unexpectedApiPaths.slice();assertContentParticipantBanReceipt(r);save();
   }finally{instructor.off('request',onRequest);}
  };
 }catch(error){primaryFailure=error;throw error;
 }finally{
  instructor.off('dialog',onPrompt);if(!complete)instructor.off('request',onRequest);
  let cleanupFailure;
  try{await switcher.close();}catch(error){cleanupFailure=error;}
  try{r.unexpectedApiPaths=unexpectedApiPaths.slice();if(!complete)save();}catch(error){cleanupFailure=cleanupFailure?new AggregateError([cleanupFailure,error],'Ban facet cleanup failures'):error;}
  if(cleanupFailure){if(primaryFailure)throw new AggregateError([primaryFailure,cleanupFailure],'Ban facet failed and cleanup failed');throw cleanupFailure;}
 }
}

module.exports={contentParticipantBanCases,assertContentParticipantBanReceipt,installBanStorageObserver,installBanRosterXhrObserver,collectBanFailureObservation,banTargetAction,POST_PATHS};
