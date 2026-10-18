'use strict';
const path=require('node:path');
const {withTransaction,verifyServer}=require('./index');
const {migrate}=require('../../../db/postgres/migrate');
const {getAgentsPool}=require('./secureshopPools');
const {TOOLS}=require('../../data/secureshopAgentSeeds');
async function seed(client){
 await client.query('SELECT pg_advisory_xact_lock(1886610804, 2)');
 if((await client.query('SELECT EXISTS(SELECT 1 FROM secureshop_agents.import_batches) AS imported')).rows[0].imported)return;
 await client.query("INSERT INTO secureshop_agents.system_config(key,value,updated_by) VALUES('enforce_tool_acl','false','seed') ON CONFLICT DO NOTHING");
 for(const [tool,matrix] of TOOLS)for(const role of ['customer','merchant','admin'])await client.query('INSERT INTO secureshop_agents.tool_permissions(tool_name,role,allowed) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[tool,role,matrix[role]?1:0]);
 await client.query("INSERT INTO secureshop_agents.mcp_registry(name,transport,stdio_cmd,status) VALUES('filesystem-mcp','stdio','npx -y @modelcontextprotocol/server-filesystem ./server/uploads/secureshop/product_manuals','unknown') ON CONFLICT DO NOTHING");
 for(const role of ['customer','merchant','admin'])await client.query("INSERT INTO secureshop_agents.agent_provider_state(role,active_provider) VALUES($1,'ollama') ON CONFLICT DO NOTHING",[role]);
}
async function initializeSecureShopAgentsDb({runtimePool=getAgentsPool(),migrationPool}){
 await verifyServer(runtimePool);
 const runtime=(await runtimePool.query('SELECT current_user role,current_database() database')).rows[0],migration=(await migrationPool.query('SELECT current_user role,current_database() database')).rows[0];
 if(runtime.role!=='dvaia_secureshop_agents_runtime'||migration.role===runtime.role||migration.database!==runtime.database)throw Error('SecureShop agents requires dedicated runtime and migration roles on the same database');
 await migrate(migrationPool,path.join(__dirname,'../../../db/postgres/workshop-migrations/secureshop_agents'));
 await withTransaction(migrationPool,seed);
}
function createSecureShopAgentsDb(pool){
 const all=async(sql,args=[]) => (await pool.query(sql,args)).rows;
 const first=async(sql,args=[]) => (await all(sql,args))[0];
 return {
  createSession:async(id,userId,role)=>{await pool.query('INSERT INTO secureshop_agents.agent_sessions(id,user_id,role) VALUES($1,$2,$3)',[id,userId,role]);return{id};},
  getSession:async id=>{const row=await first("SELECT s.id,s.user_id,s.role FROM secureshop_agents.agent_sessions s WHERE s.id=$1 AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy'",[id]);return row?{id:row.id,userId:row.user_id,role:row.role}:null;},
  appendMessage:async(id,message)=>{const r=await pool.query("UPDATE secureshop_agents.agent_sessions AS s SET messages_json=((s.messages_json::jsonb)||$1::jsonb)::text,updated_at=now() WHERE s.id=$2 AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy'",[JSON.stringify([message]),id]);if(!r.rowCount)throw Error(`unknown session ${id}`);},
  getMessages:async id=>{const row=await first("SELECT s.messages_json FROM secureshop_agents.agent_sessions s WHERE s.id=$1 AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy'",[id]);if(!row)throw Error(`unknown session ${id}`);return JSON.parse(row.messages_json||'[]');},
  getTokens:async id=>(await first("SELECT s.token_budget_used FROM secureshop_agents.agent_sessions s WHERE s.id=$1 AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy'",[id]))?.token_budget_used||0,
  addTokens:async(id,n)=>{await pool.query("UPDATE secureshop_agents.agent_sessions AS s SET token_budget_used=s.token_budget_used+$1 WHERE s.id=$2 AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy'",[n,id]);},
  appendTraces:rows=>withTransaction(pool,async c=>{for(const r of rows)await c.query("INSERT INTO secureshop_agents.agent_trace(event_id,session_id,step,actor,kind,agent_ns,tool_name,params_json,result_json,latency_ms,tokens_in,tokens_out,provider,policy_violation) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14 WHERE EXISTS (SELECT 1 FROM secureshop_agents.agent_sessions s WHERE s.id=$2 AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy') ON CONFLICT(event_id) DO NOTHING",[r.event_id,r.session_id,r.step,r.actor,r.kind,r.agent_ns??null,r.tool_name??null,r.params_json??null,r.result_json??null,r.latency_ms??null,r.tokens_in??null,r.tokens_out??null,r.provider??null,r.policy_violation??null]);}),
  getTrace:sessionId=>all("SELECT t.* FROM secureshop_agents.agent_trace t INNER JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id WHERE t.session_id=$1 AND COALESCE(to_jsonb(s)->>'authority_mode','legacy')='legacy' ORDER BY t.id",[sessionId]),
  appendAudit:async r=>{await pool.query('INSERT INTO secureshop_agents.audit_events(event_id,actor,action,target,params_json,ip,user_agent) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(event_id) DO NOTHING',[r.event_id??null,r.actor,r.action,r.target??null,r.params_json??null,r.ip??null,r.user_agent??null]);},
  getEnforcement:async()=>(await first("SELECT value FROM secureshop_agents.system_config WHERE key='enforce_tool_acl'"))?.value==='true',
  getPermission:(tool,role)=>first('SELECT allowed FROM secureshop_agents.tool_permissions WHERE tool_name=$1 AND role=$2',[tool,role]),
  listPermissions:()=>all('SELECT tool_name,role,allowed,reason,updated_at FROM secureshop_agents.tool_permissions ORDER BY tool_name,role'),
  setPermission:async(tool,role,allowed)=>{await pool.query('INSERT INTO secureshop_agents.tool_permissions(tool_name,role,allowed) VALUES($1,$2,$3) ON CONFLICT(tool_name,role) DO UPDATE SET allowed=EXCLUDED.allowed,updated_at=now()',[tool,role,allowed?1:0]);return{ok:true,tool_name:tool,role,allowed:!!allowed};},
  setEnforcement:async(enabled,by)=>{await pool.query("INSERT INTO secureshop_agents.system_config(key,value,updated_by) VALUES('enforce_tool_acl',$1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=now()",[enabled?'true':'false',by||null]);return{ok:true,enforce_tool_acl:!!enabled};},
  replaceNativeManifest:(names,entries)=>withTransaction(pool,async c=>{await c.query('SELECT pg_advisory_xact_lock(1886610804,61)');await c.query('DELETE FROM secureshop_agents.mcp_tool_cache WHERE server_name=ANY($1::text[])',[names]);for(const [name,tools] of entries)for(const tool of tools)await c.query('INSERT INTO secureshop_agents.mcp_tool_cache(server_name,tool_name,description,input_schema_json) VALUES($1,$2,$3,$4) ON CONFLICT(server_name,tool_name) DO UPDATE SET description=EXCLUDED.description,input_schema_json=EXCLUDED.input_schema_json,cached_at=now()',[name,tool.name,tool.description||'',JSON.stringify(tool.inputSchema||{})]);}),
  externalTools:names=>all('SELECT server_name,tool_name,description,input_schema_json FROM secureshop_agents.mcp_tool_cache WHERE NOT(server_name=ANY($1::text[]))',[names]),
  listServers:()=>all('SELECT id,name,url,transport,stdio_cmd,status,last_schema_hash,added_by,added_at FROM secureshop_agents.mcp_registry ORDER BY added_at DESC,id DESC'),
  registerServer:({name,url,transport,stdio_cmd,schemaHash,tools})=>withTransaction(pool,async c=>{await c.query('SELECT pg_advisory_xact_lock(1886610804,61)');const old=(await c.query('SELECT id,last_schema_hash FROM secureshop_agents.mcp_registry WHERE name=$1',[name])).rows[0];await c.query("INSERT INTO secureshop_agents.mcp_registry(name,url,transport,stdio_cmd,status,last_schema_hash) VALUES($1,$2,$3,$4,'registered',$5) ON CONFLICT(name) DO UPDATE SET url=EXCLUDED.url,transport=EXCLUDED.transport,stdio_cmd=EXCLUDED.stdio_cmd,status=EXCLUDED.status,last_schema_hash=EXCLUDED.last_schema_hash",[name,url,transport,stdio_cmd,schemaHash]);await c.query('DELETE FROM secureshop_agents.mcp_tool_cache WHERE server_name=$1',[name]);for(const t of tools)await c.query('INSERT INTO secureshop_agents.mcp_tool_cache(server_name,tool_name,description,input_schema_json) VALUES($1,$2,$3,$4)',[name,String(t.name||''),String(t.description||''),JSON.stringify(t.inputSchema||{})]);await c.query('INSERT INTO secureshop_agents.mcp_schema_history(name,schema_hash,tools_json) VALUES($1,$2,$3)',[name,schemaHash,JSON.stringify(tools)]);return{existing:!!old,changed:!old||old.last_schema_hash!==schemaHash};}),
  removeServer:name=>withTransaction(pool,async c=>{await c.query('SELECT pg_advisory_xact_lock(1886610804,61)');const r=await c.query('DELETE FROM secureshop_agents.mcp_registry WHERE name=$1',[name]);await c.query('DELETE FROM secureshop_agents.mcp_tool_cache WHERE server_name=$1',[name]);return{ok:r.rowCount>0,name,removed:r.rowCount};}),
  describeTools:name=>all('SELECT id,server_name,tool_name,description,input_schema_json,cached_at FROM secureshop_agents.mcp_tool_cache WHERE server_name=$1',[name]),
  schemaHistory:name=>all('SELECT id,name,schema_hash,tools_json,ts FROM secureshop_agents.mcp_schema_history'+(name?' WHERE name=$1':'')+' ORDER BY ts,id',name?[name]:[]),
  recentAudit:n=>all('SELECT id,actor,action,target,params_json,ip,user_agent,ts FROM secureshop_agents.audit_events ORDER BY ts DESC,id DESC LIMIT $1',[n]),
  summaryAudit:n=>all('SELECT id,actor,action,target,params_json,ts FROM secureshop_agents.audit_events ORDER BY ts DESC,id DESC LIMIT $1',[n]),
  // Intentional raw SELECT sink. Extended protocol rejects multiple statements;
  // read-only transaction preserves the prior statement API's read capability.
  queryAuditTeaching:sql=>withTransaction(pool,async c=>{await c.query('SET TRANSACTION READ ONLY');return(await c.query({text:sql,values:[],queryMode:'extended'})).rows;}),
 };
}
let singleton,selectedPool;
function getSecureShopAgentsDb(){const pool=getAgentsPool();if(pool!==selectedPool){selectedPool=pool;singleton=createSecureShopAgentsDb(pool);}return singleton;}
module.exports={createSecureShopAgentsDb,getSecureShopAgentsDb,initializeSecureShopAgentsDb,seed};
