'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {assertContentParticipantBanReceipt,installBanStorageObserver,installBanRosterXhrObserver,collectBanFailureObservation,banTargetAction,POST_PATHS}=require('./postgres/support/ctfParticipantBanRenderedCases');
const {contentApiAllowed}=require('./postgres/support/ctfRecoveryRenderedCases');

function validReceipt(){
 return {version:1,profile:'ctf-participant-ban-unban-q05',modelCalls:0,judgeCalls:0,targetId:3011,
  browserPostCounts:{ban:1,unban:1},serverOperationCounts:{ban:1,unban:1},observedPaths:{...POST_PATHS},
  cancelPostCounts:{ban:0,unban:0},abaPostCounts:{ban:0,unban:0},abaEvents:{ban:2,unban:2},
  flags:{before:false,afterBan:true,afterUnban:false},
  facts:{cancelNoPost:true,cancelStateUnchanged:true,abaNoPost:true,abaStateUnchanged:true,banDurableBothStores:true,unbanDurableBothStores:true,reloadBan:true,reloadUnban:true,targetEvidencePreserved:true,platformPreserved:true,siblingPreserved:true,operationsApplied:true,noSecondPost:true},
  unexpectedApiPaths:[],stage:'complete'};
}

test('separate Ban/Unban receipt admits only exact physical/durable transition facts',()=>{
 const good=validReceipt();assert.equal(assertContentParticipantBanReceipt(good),good);
 const invalid=[
  {version:2},{profile:'ctf-ten-content'},{modelCalls:1},{judgeCalls:1},{targetId:1001},
  {browserPostCounts:{ban:2,unban:1}},{serverOperationCounts:{ban:1,unban:0}},
  {observedPaths:{ban:'/api/ctf/admin/participants/1001/ban',unban:POST_PATHS.unban}},
  {cancelPostCounts:{ban:1,unban:0}},{abaPostCounts:{ban:0,unban:1}},{abaEvents:{ban:1,unban:2}},
  {flags:{before:false,afterBan:false,afterUnban:false}},
  {facts:{...good.facts,platformPreserved:false}},
  {facts:{...good.facts,reloadUnban:false}},
  {unexpectedApiPaths:[{method:'POST',path:'/api/other'}]},{stage:'confirm-unban'},
  {operationId:'12345678-1234-4234-8234-123456789abc'},
  {sameIdRecovery:true},
 ];
 for(const patch of invalid)assert.throws(()=>assertContentParticipantBanReceipt({...good,...patch}),JSON.stringify(patch));
});

test('browser admission opens only the two target-3011 Ban/Unban mutations',()=>{
 for(const path of Object.values(POST_PATHS))assert.equal(contentApiAllowed('POST',path),true,path);
 for(const path of ['/api/ctf/admin/participants/1001/ban','/api/ctf/admin/participants/3010/ban','/api/ctf/admin/participants/3011/reset','/api/ctf/admin/participants/3011/remove','/api/ctf/admin/participants/3011/ban/extra'])assert.equal(contentApiAllowed('POST',path),false,path);
 assert.equal(contentApiAllowed('GET',POST_PATHS.ban),false);
});

test('each ABA phase re-arms the observer after a document reload and counts exactly two current-document events',()=>{
 const document=()=>{
  const listeners=new Set(),storage={};
  return {localStorage:storage,addEventListener:(name,fn)=>{assert.equal(name,'storage');listeners.add(fn);},removeEventListener:(name,fn)=>{assert.equal(name,'storage');listeners.delete(fn);},dispatch(event){for(const fn of listeners)fn(event);}};
 };
 const banDocument=document();installBanStorageObserver(banDocument);
 banDocument.dispatch({key:'token',storageArea:banDocument.localStorage});banDocument.dispatch({key:'token',storageArea:banDocument.localStorage});
 assert.equal(banDocument.__ctfBanStorageEvents,2);
 const unbanDocument=document();installBanStorageObserver(unbanDocument);
 assert.equal(unbanDocument.__ctfBanStorageEvents,0,'new document cannot inherit a prior counter/listener');
 unbanDocument.dispatch({key:'other',storageArea:unbanDocument.localStorage});
 unbanDocument.dispatch({key:'token',storageArea:banDocument.localStorage});
 assert.equal(unbanDocument.__ctfBanStorageEvents,0,'only own token storage events count');
 unbanDocument.dispatch({key:'token',storageArea:unbanDocument.localStorage});unbanDocument.dispatch({key:'token',storageArea:unbanDocument.localStorage});
 assert.equal(unbanDocument.__ctfBanStorageEvents,2);
 installBanStorageObserver(unbanDocument);unbanDocument.dispatch({key:'token',storageArea:unbanDocument.localStorage});
 assert.equal(unbanDocument.__ctfBanStorageEvents,1,'re-arm replaces rather than stacks observers');
 const facet=fs.readFileSync('tests/postgres/support/ctfParticipantBanRenderedCases.js','utf8');
 assert(facet.indexOf('const aba=async kind=>')<facet.indexOf('await action(()=>instructor.evaluate(installBanStorageObserver))'));
 assert(facet.indexOf('await action(()=>instructor.evaluate(installBanStorageObserver))')<facet.indexOf('const initial=await action(()=>instructor.evaluate(()=>window.__ctfBanStorageEvents))'));
});

test('current-document roster XHR diagnostics distinguish usable 200, 304, and abort without retaining bodies',()=>{
 class FakeXHR {
  constructor(){this.listeners=new Map();this.status=0;this.responseType='';this.responseText='';}
  addEventListener(name,fn){this.listeners.set(name,fn);}
  open(method,url){this.method=method;this.url=url;}
  finish(name,status,body=''){this.status=status;this.responseText=body;this.listeners.get(name)?.call(this,{type:name});}
 }
 const scope={XMLHttpRequest:FakeXHR,location:{href:'http://127.0.0.1:8000/admin/ctf-management',origin:'http://127.0.0.1:8000'}};
 installBanRosterXhrObserver(scope);installBanRosterXhrObserver(scope);
 const response=new scope.XMLHttpRequest();response.open('GET','/api/ctf/admin/participants');
 response.finish('load',200,JSON.stringify({participants:[{id:3011,user_id:3011,secret:'never-retain'}]}));
 const revalidated=new scope.XMLHttpRequest();revalidated.open('GET','/api/ctf/leaderboard?limit=50');revalidated.finish('load',304,'');
 const aborted=new scope.XMLHttpRequest();aborted.open('GET','/api/ctf/leaderboard?limit=50');aborted.finish('abort',0);
 const unrelated=new scope.XMLHttpRequest();unrelated.open('GET','/api/ctf/status');unrelated.finish('load',200,'{}');
 assert.deepEqual(scope.__ctfBanRosterXhr,{version:1,events:[
  {path:'/api/ctf/admin/participants',terminal:'load',status:200,rowCount:1,targetPresent:true,bodyParsed:true},
  {path:'/api/ctf/leaderboard',terminal:'load',status:304,rowCount:null,targetPresent:null,bodyParsed:false},
  {path:'/api/ctf/leaderboard',terminal:'abort',status:0,rowCount:null,targetPresent:null,bodyParsed:false},
 ],overflow:0});
 assert.equal(JSON.stringify(scope.__ctfBanRosterXhr).includes('never-retain'),false);
 const next={XMLHttpRequest:class extends FakeXHR{},location:scope.location};installBanRosterXhrObserver(next);
 assert.equal(next.__ctfBanRosterXhr.events.length,0,'reload creates a fresh document-local diagnostic record');
});

test('failure observation returns only bounded tab/row/button counts and XHR metadata',()=>{
 const target={querySelectorAll:name=>name==='td'?[{}, {childNodes:[{nodeType:3,textContent:'content-11'},{nodeType:1,textContent:'banned'}]}]:[{textContent:'Unban'}]};
 const doc={querySelector:name=>name.startsWith('nav[')?{querySelectorAll:()=>[{getAttribute:()=> 'true',textContent:'Leaderboard'}]}:null,
  querySelectorAll:name=>name==='tbody tr'?[target]:[]};
 const scope={document:doc,location:{pathname:'/admin/ctf-management'},__ctfBanRosterXhr:{version:1,events:[],overflow:0}};
 assert.deepEqual(collectBanFailureObservation(scope),{version:1,pathname:'/admin/ctf-management',selectedTab:'leaderboard',tableRows:1,targetRows:1,targetBanButtons:0,targetUnbanButtons:1,rosterXhr:scope.__ctfBanRosterXhr});
});

test('target action binds the exact username-column direct text despite an inline banned badge',()=>{
 const row=(username,buttons,firstCell='')=>({
  querySelectorAll:name=>name==='td'?[{childNodes:[{nodeType:3,textContent:firstCell}]},{childNodes:username}]:buttons,
 });
 const text=value=>({nodeType:3,textContent:value});
 const badge=value=>({nodeType:1,textContent:value});
 const unban={textContent:'Unban',disabled:false};
 const target=row([text('content-11'),badge('banned')],[unban]);
 const decoy=row([text('content-110')],[{textContent:'Unban',disabled:false}],'content-11');
 const wrongColumn=row([text('another-user')],[{textContent:'Unban',disabled:false}],'content-11');
 const doc=rows=>({querySelectorAll:name=>name==='tbody tr'?rows:[]});
 assert.equal(banTargetAction('Unban',doc([decoy,wrongColumn,target])),unban);
 assert.equal(banTargetAction('Ban',doc([target])),null,'only the expected enabled action is admitted');
 assert.equal(banTargetAction('Unban',doc([target,row([text('content-11')],[{textContent:'Unban',disabled:false}])])),null,'duplicate exact target rows are rejected');
 assert.equal(banTargetAction('Unban',doc([row([text('content-11'),badge('banned')],[{textContent:'Unban',disabled:true}])])),null,'disabled action is rejected');
 assert.equal(banTargetAction('Unban',doc([decoy,wrongColumn])),null,'username text elsewhere cannot select a decoy');
});

test('rendered facet is physically inserted after progress parity before reset without changing original receipt credit',()=>{
 const fixture=fs.readFileSync('tests/postgres/support/ctfRecoveryRenderedCases.js','utf8');
 const facet=fs.readFileSync('tests/postgres/support/ctfParticipantBanRenderedCases.js','utf8');
 assert(fixture.indexOf("step('progress-parity')")<fixture.indexOf("step('q05-participant-ban-rendered')"));
 assert(fixture.indexOf("step('q05-participant-ban-rendered')")<fixture.indexOf("step('session-reset')"));
 assert(fixture.includes('CTF_PARTICIPANT_BAN_Q05_RECEIPT'));
 assert(fixture.includes("'ctf-participant-ban-q05-result.json'"));
 assert(fixture.includes('assertContentParticipantBanReceipt(JSON.parse(fs.readFileSync(participantBanReceiptPath)))'));
 assert(fixture.includes('diagnosticPage=instructor;step(\'q05-participant-ban-rendered\')'));
 assert(fixture.includes('diagnostics.banRoster=await bounded(()=>diagnosticPage.evaluate(collectBanFailureObservation))'));
 assert(facet.includes('instructor.evaluateOnNewDocument(installBanRosterXhrObserver)'));
 assert(facet.includes("await dialog('ban')"));assert(facet.includes("await dialog('unban')"));
 assert(facet.includes("'Cancel'"));assert(facet.includes("'Confirm Ban'"));assert(facet.includes("'Confirm Unban'"));
 assert(facet.includes("localStorage.setItem('token',b);localStorage.setItem('token',a)"));
 assert(facet.includes("SELECT * FROM ctf.ctf_progress WHERE participant_id=$1"));
 assert(facet.includes('identity.user_sessions'));assert(facet.includes('account_locked_until'));
 for(const source of ['ctf.ctf_participants WHERE user_id=1001','ctf.ctf_leaderboard WHERE participant_id=1001','identity.ctf_progress_bindings WHERE owner_id=1001','identity.users WHERE id=1001','identity.user_sessions WHERE user_id=1001'])assert(facet.includes(source),source);
 assert(facet.includes("'Seeded sibling '+key+' must be nonempty'"));
 assert(!facet.includes('sameIdGets')&&!facet.includes('sameIdRecovery'));
 assert(!facet.includes("mutate(admin,'ban'"));assert(!facet.includes("mutate(admin,'unban'"));
});
