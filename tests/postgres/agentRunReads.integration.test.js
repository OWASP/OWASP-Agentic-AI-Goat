'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const express=require('express');
const bcrypt=require('bcryptjs');
const {createPool}=require('../../server/database/postgres');
const {initializeIdentityRepository,createIdentityRepository}=require('../../server/database/postgres/identityRepository');
const {initializeSecureShopAgentsDb}=require('../../server/database/postgres/secureshopInitialization');
const {createSecureShopLaunchRepository}=require('../../server/database/postgres/secureshopLaunchRepository');
const {createPostgresAgentRunReadRepository,ownerKey,decodeCursor}=require('../../server/database/postgres/agentRunReadRepository');
const {createSecureShopConversationOwnershipResolver}=require('../../server/services/secureshopConversationOwnershipResolver');
const {createAgentRunsRouter}=require('../../server/routes/agentRuns');
test('PG observability reads enforce platform and bound-conversation ownership, keyset, and paging',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.PG_READS_TEST_RUNTIME_URL||!process.env.PG_SECURESHOP_AGENTS_TEST_RUNTIME_URL},async()=>{
 const pool=createPool(process.env,'PG_READS_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_READS_TEST_MIGRATION_URL');
 const agents=createPool(process.env,'PG_SECURESHOP_AGENTS_TEST_RUNTIME_URL'),agentsMigration=createPool(process.env,'PG_SECURESHOP_AGENTS_TEST_MIGRATION_URL');
 let server;
 try{
  await Promise.all([initializeIdentityRepository(pool,migration),initializeSecureShopAgentsDb({runtimePool:agents,migrationPool:agentsMigration})]);
  const identities=createIdentityRepository(pool),launches=createSecureShopLaunchRepository(pool);
  async function platformOwner(label){
   const password=await bcrypt.hash(`Run-reader-${label}`,4);
   const user=await identities.createUser({username:`run-reader-${label}-${randomUUID().slice(0,6)}`,email:`${randomUUID()}@runs.invalid`,passwordHash:password});
   const session=await identities.createSession({userId:user.id,token:randomUUID(),expiresAt:new Date(Date.now()+3600000),expectedPasswordHash:password});
   const issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt:new Date(Date.now()+3600000)});
   return {user,session,binding:{...issued.binding,platformOwnerId:user.id,platformSessionId:session.id}};
  }
  const firstOwner=await platformOwner('first'),secondOwner=await platformOwner('second');
  const purposes=['general','review_moderation','persona_inbox','controlled_ssrf','mcp_rug_pull'];let conversationIndex=0;
  async function conversation(owner,state='active',override={}){
   const id=randomUUID(),binding={...owner.binding,...override};
   await agents.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,user_id,role,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
      platform_launch_generation,original_platform_owner_id,original_platform_session_id,conversation_purpose)
    VALUES($1,1,'customer','launch_bound','pending',$2,$3,$4,$5,$6,$7)`,
   [id,binding.launchId,binding.scenarioId,binding.generation,binding.platformOwnerId,binding.platformSessionId,purposes[conversationIndex++]]);
   if(state!=='pending')await agents.query('UPDATE secureshop_agents.agent_sessions SET binding_state=$2 WHERE id=$1',[id,state]);
   return id;
  }
  const activeConversation=await conversation(firstOwner),abandonedConversation=await conversation(firstOwner,'abandoned');
  const foreignConversation=await conversation(secondOwner),pendingConversation=await conversation(firstOwner,'pending');
  const mismatchedConversation=await conversation(firstOwner,'active',{platformOwnerId:secondOwner.user.id});
  const legacyConversation=randomUUID();
  await agents.query("INSERT INTO secureshop_agents.agent_sessions(id,user_id,role) VALUES($1,1,'customer')",[legacyConversation]);
  const ownership=createSecureShopConversationOwnershipResolver({agentsPool:agents,identityPool:pool});
  const repo=createPostgresAgentRunReadRepository(pool,{secureShopOwnership:ownership});
  const rows=[{id:randomUUID(),owner:'1',family:'ARIA',time:'2026-09-10T10:00:00.000900Z'},{id:randomUUID(),owner:'1',family:'ARIA',time:'2026-09-10T10:00:00.000800Z'},{id:randomUUID(),owner:'1',family:'NOVA',time:'2026-09-10T10:00:00.000700Z'},{id:randomUUID(),owner:'11',family:'ARIA',time:'2026-09-10T10:00:00.000600Z'}];
  for(const row of rows){const owner=ownerKey(row.family,row.owner);await pool.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1) ON CONFLICT DO NOTHING',[owner]);await pool.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status,started_at) VALUES($1,$2,0,'completed',$3)",[row.id,owner,row.time]);}
  for(let seq=1;seq<=3;seq++)await pool.query("INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,$3,'model','node_end','{}')",[rows[0].id,ownerKey('ARIA','1'),seq]);
  const first=await repo.list({userId:'1',limit:1});assert.equal(first.runs[0].runId,rows[0].id);assert.equal(first.runs[0].ownerId,undefined);
  const second=await repo.list({userId:'1',limit:1,before:decodeCursor(first.nextCursor)});assert.equal(second.runs[0]?.runId,rows[1].id,'Sub-millisecond timestamps must not skip a page');
  assert.equal((await repo.list({userId:'1',limit:10})).runs.length,3);assert.equal(await repo.find(rows[3].id,{userId:'1'}),null);assert.equal(await repo.events(rows[3].id,{userId:'1'}),null);
  const admins=await repo.list({admin:true,userId:'99',family:'ARIA',limit:10});assert.equal(admins.runs.length,3);assert.deepEqual(new Set(admins.runs.map(r=>r.ownerId)),new Set(['1','11']));
  assert.equal((await repo.list({admin:true,userId:'99',ownerId:'11',family:'ARIA',limit:10})).runs.length,1);assert.equal((await repo.list({admin:true,userId:'99',ownerId:'11',family:'NOVA',limit:10})).runs.length,0);
  assert.equal(await repo.find(rows[0].id,{admin:true,userId:'99',family:'NOVA'}),null);
  const events=await repo.events(rows[0].id,{userId:'1'},0,2);assert.deepEqual(events.events.map(e=>e.seq),[1,2]);assert.equal(events.nextCursor,2);assert.deepEqual((await repo.events(rows[0].id,{userId:'1'},events.nextCursor,2)).events.map(e=>e.seq),[3]);
  const secureRuns=[];
  for(const conversationId of [activeConversation,abandonedConversation,foreignConversation,pendingConversation,mismatchedConversation,legacyConversation]){
   const runId=randomUUID(),key=ownerKey('SecureShopBoundConversation',conversationId);secureRuns.push({runId,conversationId});
   await pool.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1) ON CONFLICT DO NOTHING',[key]);
   await pool.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,1,'completed')",[runId,key]);
   await pool.query("INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,1,'model','decision','{}')",[runId,key]);
  }
  const firstSecure=await repo.list({userId:firstOwner.user.id,family:'SecureShopBoundConversation',limit:20});
  assert.deepEqual(new Set(firstSecure.runs.map(run=>run.runId)),new Set(secureRuns.slice(0,2).map(run=>run.runId)),
   'active and abandoned history belongs to the original platform owner only');
  assert.equal(await repo.find(secureRuns[2].runId,{userId:firstOwner.user.id}),null);
  assert.equal(await repo.find(secureRuns[3].runId,{userId:firstOwner.user.id}),null,'pending binding is not inspectable');
  assert.equal(await repo.find(secureRuns[4].runId,{userId:firstOwner.user.id}),null,'cross-store mismatch is not inspectable');
  assert.equal(await repo.find(secureRuns[5].runId,{userId:firstOwner.user.id}),null,'legacy shop persona binding is not platform ownership');
  const auth=(req,res,next)=>{const value=Number(req.headers.authorization?.replace('Bearer ',''));
   if(!value)return res.status(401).json({error:'Authentication required'});req.user={id:value};next();};
  const permission=()=>((_req,_res,next)=>next()),app=express();
  app.use('/api/agent-runs',createAgentRunsRouter({repository:repo,authenticateToken:auth,receiptAdapters:{}}));
  app.use('/api/admin/agent-runs',createAgentRunsRouter({repository:repo,authenticateToken:auth,requirePermission:permission,admin:true,receiptAdapters:{}}));
  server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
  const base=`http://127.0.0.1:${server.address().port}`;
  async function request(path,user){const response=await fetch(base+path,{headers:{authorization:`Bearer ${user}`}});return{status:response.status,body:await response.json()};}
  assert.equal((await request(`/api/agent-runs/${secureRuns[0].runId}`,firstOwner.user.id)).status,200);
  assert.equal((await request(`/api/agent-runs/${secureRuns[0].runId}`,secondOwner.user.id)).status,404);
  const admin=await request(`/api/admin/agent-runs?ownerId=${firstOwner.user.id}&family=SecureShopBoundConversation`,999);
  assert.deepEqual(new Set(admin.body.runs.map(run=>run.runId)),new Set(secureRuns.slice(0,2).map(run=>run.runId)));
  assert.ok(admin.body.runs.every(run=>run.ownerId===String(firstOwner.user.id)));
 }finally{if(server)await new Promise(resolve=>server.close(resolve));await Promise.all([pool.end(),migration.end(),agents.end(),agentsMigration.end()]);}
});
