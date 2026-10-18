'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {createMailHeaderEvidenceRepository}=require('../server/database/postgres/secureshopMailHeaderEvidenceRepository');
const {prepareSend}=require('../server/database/postgres/secureshopBoundMailRepository');
const {buildMailHeaderCandidate,MAIL_HEADER_RUBRIC}=require('../server/services/secureshopMailHeaderEvidence');
const {mailObjectiveReadiness,MAIL_OBJECTIVE_QUALIFICATION}=require('../server/services/secureshopMailObjectiveReadiness');
function fixture(){
 const b={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8},targetId:randomUUID(),persona:{id:2,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},mode:'vuln',operationId:randomUUID()};
 const p=prepareSend({from:'merchant@lab',to:'customer@lab',subject:'Hello\r\nX-Lab: injected',body_markdown:'body'});
 const row={id:10,thread_id:10,from_addr:p.from,to_addr:p.to,subject:p.subject,body_markdown:p.body_markdown,body_html:p.body_html,headers_raw:p.headers_raw};
 const recovered={found:true,operationId:b.operationId,action:'send',requestSha256:'a'.repeat(64),receipt:{senderId:2,recipientId:3,email_id:10,thread_id:10,contentSha256:'b'.repeat(64)}};
 const state={rows:[row],matches:1,append:false,checks:0,queries:[],calls:[],wrongBinding:false,stale:false};
 const personaAuthority={capture(x){return {binding:{...x.scope,personaId:state.wrongBinding?99:x.personaId,role:x.role,sessionId:x.sessionId,authorityVersion:x.authorityVersion},async assertRemoteAdmission(){state.checks++;if(state.stale&&state.checks>1)throw Error('reset');},async withPersonaEffect(work){return work({async query(sql,args){state.queries.push({sql,args});if(!args)return {rows:[]};const candidates=JSON.parse(args[0]);return {rows:Array.from({length:state.matches},()=>({payload:candidates[state.append?1:0]}))};}});}};}};
 const mailRepository={async recover(binding){assert.deepEqual(binding,b);state.calls.push('recover');return recovered;},async browse(binding,userId){assert.deepEqual(binding,b);assert.equal(userId,3);state.calls.push('browse');return {emails:state.rows};}};
 return {b,p,row,recovered,state,repository:createMailHeaderEvidenceRepository({personaAuthority,mailRepository})};
}
test('exact receipt readback uses bounded SQL-native dual hashes and no send/read effect',async()=>{
 const f=fixture(),e=await f.repository.readHeader(f.b);assert.deepEqual(e.payload,f.p);assert.deepEqual(f.state.calls,['recover','browse']);assert.equal(f.state.checks,2);
 const q=f.state.queries;assert.match(q[0].sql,/statement_timeout/);assert.match(q[1].sql,/lock_timeout/);assert.match(q[2].sql,/jsonb_build_array\('send',value\)/);assert.deepEqual(q[2].args.slice(1),['b'.repeat(64),'a'.repeat(64)]);
 assert.equal(JSON.parse(q[2].args[0]).length,2);assert.equal(buildMailHeaderCandidate(e).facts.header_newline_preserved,true);
 f.state.append=true;const appended=await f.repository.readHeader(f.b);assert.equal(appended.payload.threadId,10);
});
test('hash mismatch or ambiguous reconstruction never produces evidence',async()=>{for(const matches of [0,2]){const f=fixture();f.state.matches=matches;await assert.rejects(f.repository.readHeader(f.b),{code:'MAIL_EVIDENCE_UNAVAILABLE'});}});
test('foreign sender/operation, missing effect, wrong thread and duplicate row denied',async()=>{
 for(const mutate of [f=>f.recovered.receipt.senderId=9,f=>f.recovered.operationId=randomUUID(),f=>f.recovered.found=false,f=>f.row.thread_id=11,f=>f.state.rows=[],f=>f.state.rows.push({...f.row}),f=>f.row.headers_raw+='x']){const f=fixture();mutate(f);await assert.rejects(f.repository.readHeader(f.b));}
});
test('wrong authority, fixed mode and reset after read denied',async()=>{
 const wrong=fixture();wrong.state.wrongBinding=true;await assert.rejects(wrong.repository.readHeader(wrong.b));assert.equal(wrong.state.calls.length,0);
 const fixed=fixture();fixed.b.mode='fixed';await assert.rejects(fixed.repository.readHeader(fixed.b));assert.equal(fixed.state.calls.length,0);
 const stale=fixture();stale.state.stale=true;await assert.rejects(stale.repository.readHeader(stale.b),/reset/);
});
test('normal separators/body newlines never become header injection; original fields do',async()=>{
 const f=fixture(),e=await f.repository.readHeader(f.b);
 for(const key of ['from','to','subject']){const p={...e.payload,from:'merchant@lab',to:'customer@lab',subject:'hello'};p[key]+='\nX-Lab: yes';p.headers_raw=`From: ${p.from}\r\nTo: ${p.to}\r\nSubject: ${p.subject}`;assert.deepEqual(buildMailHeaderCandidate({...e,payload:p}).evidence[0].content.newlineFields,[key]);}
 const p=prepareSend({from:'merchant@lab',to:'customer@lab',subject:'Hello',body_markdown:'\r\nBcc: body only'});assert.equal(buildMailHeaderCandidate({...e,payload:p}),null);
 assert.equal(buildMailHeaderCandidate({...e,binding:{...e.binding,mode:'fixed'}}),null);
 assert.match(MAIL_HEADER_RUBRIC.criteria[0].description,/No SMTP/);
});
test('qualified mail source eligibility still requires catalog, transport and Judge',()=>{
 assert.deepEqual(MAIL_OBJECTIVE_QUALIFICATION,{ss_mail_reply_redirect:true,ss_mail_header_construction:true,ss_mail_cross_persona_read:true,ss_mail_stored_browser_execution:true,ss_mail_agent_html_injection:true,ss_mail_agent_cross_persona_read:true});const catalog=Object.fromEntries(Object.keys(MAIL_OBJECTIVE_QUALIFICATION).map(id=>[id,true]));assert.deepEqual(mailObjectiveReadiness({transportReady:true,judgeReady:true,catalog}),MAIL_OBJECTIVE_QUALIFICATION);assert(Object.values(mailObjectiveReadiness({transportReady:true,judgeReady:true,catalog:{}})).every(x=>x===false));
});
test('individual eligibility uses effective catalog and cannot enable reply by association',async()=>{
 const {projectMailObjectiveReadiness,readMailObjectiveCatalog}=require('../server/services/secureshopMailObjectiveReadiness');
 let queried=false;const catalog=await readMailObjectiveCatalog({async query(sql,args){queried=true;assert.match(sql,/o.is_enabled AND o.catalog_active AND w.is_visible AND w.catalog_active/);assert.equal(args[0],'secureshop_agent_security');return {rows:[{objective_id:'ss_mail_header_construction'},{objective_id:'ss_mail_reply_redirect'}]};}});assert(queried);
 const gates={...MAIL_OBJECTIVE_QUALIFICATION,ss_mail_reply_redirect:false};
 assert.equal(projectMailObjectiveReadiness(gates,{transportReady:true,judgeReady:true,catalog}).ss_mail_header_construction,true);
 assert.equal(projectMailObjectiveReadiness(gates,{transportReady:true,judgeReady:true,catalog}).ss_mail_reply_redirect,false);
 for(const options of [{transportReady:false,judgeReady:true,catalog},{transportReady:true,judgeReady:false,catalog},{transportReady:true,judgeReady:true,catalog:{}}])assert(Object.values(projectMailObjectiveReadiness(MAIL_OBJECTIVE_QUALIFICATION,options)).every(value=>value===false));
});
test('mail readiness selects the exact launch owner assessment realm',async()=>{
 const {readMailObjectiveReadiness}=require('../server/services/secureshopMailObjectiveReadiness');
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:81,platformSessionId:811};
 const tenantId=randomUUID(),calls=[];
 const shop={async query(sql,args){calls.push({sql,args});
  if(sql.includes('identity.secureshop_authority_owners'))return{rows:[{realm:'shop',shop_tenant_id:tenantId}]};
  assert.match(sql,/secureshop_auth\.assessment_objectives/);assert.equal(args[0],tenantId);
  return{rows:[{objective_id:'ss_mail_header_construction'}]};}};
 const enabled=await readMailObjectiveReadiness({identityPool:shop,scope,transportReady:true,judgeReady:true});
 assert.equal(calls[0].args[0],scope.platformOwnerId);assert.equal(calls.length,2);
 assert.equal(enabled.ss_mail_header_construction,true);assert.equal(enabled.ss_mail_reply_redirect,false);
 const platform={async query(sql){if(sql.includes('identity.secureshop_authority_owners'))return{rows:[{realm:'platform',shop_tenant_id:null}]};
  assert.match(sql,/workshop_platform\.objectives/);return{rows:[{objective_id:'ss_mail_cross_persona_read'}]};}};
 const legacy=await readMailObjectiveReadiness({identityPool:platform,scope,transportReady:true,judgeReady:true});
 assert.equal(legacy.ss_mail_cross_persona_read,true);assert.equal(legacy.ss_mail_header_construction,false);
 await assert.rejects(readMailObjectiveReadiness({identityPool:{async query(){return{rows:[]};}},scope,transportReady:true,judgeReady:true}),{code:'SHOP_ASSESSMENT_STALE'});
});
