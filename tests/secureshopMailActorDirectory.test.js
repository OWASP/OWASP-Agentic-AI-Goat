'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {readFileSync}=require('node:fs'),{join}=require('node:path');
const {createHash}=require('node:crypto');
const {createSecureShopBoundPersonaRepository}=require('../server/database/postgres/secureshopBoundPersonaRepository');
const scope={launchId:'10000000-0000-4000-8000-000000000074',scenarioId:'20000000-0000-4000-8000-000000000074',generation:7,platformOwnerId:74,platformSessionId:704};
const source=require('../db/postgres/seeds/secureshop.json').shop_users.filter(row=>['student_customer','student_merchant','student_admin'].includes(row.username)).sort((a,b)=>a.username.localeCompare(b.username));
const templates=source.map(row=>{const sha=createHash('sha256').update(JSON.stringify([row.id,row.username,row.email,row.password,row.role,row.full_name??null,row.phone??null])).digest();return {id:row.id,username:row.username,email:row.email,password:row.password,role:row.role,full_name:row.full_name??null,phone:row.phone??null,source_sha256:sha};});
const aggregate=createHash('sha256');templates.forEach(row=>aggregate.update(row.source_sha256));
const catalog={template_count:3,template_sha256:aggregate.digest()};
const base=[{id:1,username:'student_customer',email:'customer@example.test',role:'customer'},{id:2,username:'student_merchant',email:'merchant@example.test',role:'merchant'},{id:3,username:'student_admin',email:'admin@example.test',role:'admin'}];
function fixture(actors){const calls=[];const agentsPool={async query(sql,args){calls.push([sql,args]);if(sql.includes('bound_persona_template_catalog'))return {rows:[catalog]};if(sql.includes('bound_persona_templates ORDER BY'))return {rows:templates};if(sql.includes('FROM secureshop_agents.bound_actor_identities a'))return {rows:actors};throw Error('Unexpected query');},async connect(){throw Error('Mail directory is read only');}};return {repository:createSecureShopBoundPersonaRepository({commercePool:{async query(){throw Error('No commerce query');}},agentsPool}),calls};}
test('mail actor directory reads effective role and ban under exact launch and tenant membership',async()=>{
 const actors=[...base,{id:41,username:'registered',email:'registered@example.test',role:'customer'}],f=fixture(actors);
 assert.deepEqual(await f.repository.listMailActors(scope),actors);
 assert.deepEqual(f.calls.at(-1)[1],[scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId]);
 const sql=f.calls.at(-1)[0];for(const clause of ['COALESCE(st.effective_role,m.role,a.base_role)','st.banned_at IS NULL','bound_actor_in_owner(a.shop_user_id,$4)','st.platform_launch_id=$1','st.platform_scenario_id=$2','st.platform_launch_generation=$3','st.original_platform_owner_id=$4','st.original_platform_session_id=$5'])assert.ok(sql.includes(clause),clause);
});
test('mail actor directory rejects ambiguous email, invalid effective role, and missing baseline actors',async()=>{
 for(const rows of [[...base,{id:41,username:'other',email:base[0].email,role:'customer'}],[...base.slice(0,2)],[...base.slice(0,2),{...base[2],role:'owner'}]])await assert.rejects(fixture(rows).repository.listMailActors(scope),{code:'SHOP_MAIL_ACTORS_UNAVAILABLE'});
});
test('admin actor directory projects stored principal identity without ID or email heuristics',async()=>{
 const rows=[...base.map(row=>({...row,identity_kind:'teaching_persona'})),
  {id:41,username:'registered',email:'registered@example.test',role:'customer',identity_kind:'registered_account'}];
 const f=fixture(rows),result=await f.repository.listActors(scope);
 assert.deepEqual(result.map(row=>row.identity_kind),['teaching_persona','teaching_persona','teaching_persona','registered_account']);
 assert.match(f.calls.at(-1)[0],/CASE WHEN a\.principal_id IS NULL THEN 'teaching_persona' ELSE 'registered_account' END AS identity_kind/);
 await assert.rejects(fixture(rows.map(row=>({...row,identity_kind:undefined}))).repository.listActors(scope),{code:'SHOP_PERSONA_UNAVAILABLE'});
});
test('forward mail function keeps local recipient identifier distinct from message column',()=>{
 const sql=readFileSync(join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents/0047_bound_mail_tenant_actors.sql'),'utf8');
 assert.match(sql,/DECLARE recipient_count integer; chosen_recipient_id integer;/);
 assert.match(sql,/INTO recipient_count,chosen_recipient_id/);
 assert.match(sql,/WHERE shop_user_id=chosen_recipient_id;/);
 assert.doesNotMatch(sql,/DECLARE[^\n]*\brecipient_id\b/);
 assert.match(sql,/OR recipient_id=caller/);
 assert.match(sql,/AND recipient_id=\(payload->>'userId'\)::integer/);
});
