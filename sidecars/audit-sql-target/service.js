'use strict';
const {randomBytes,createHash}=require('node:crypto');
const {Pool}=require('pg');
const targetName=value=>{if(typeof value!=='string'||!/^audit_[a-f0-9]{32}$/.test(value))throw new TypeError('Invalid owned target');return value;};
const digest=rows=>createHash('sha256').update(JSON.stringify(rows)).digest('hex');
// This module receives only the dedicated synthetic cluster authority. It must
// never be constructed with any application cluster connection configuration.
function createService({controlPool,clusterConfig}) {
 if(typeof controlPool?.query!=='function'||!clusterConfig)throw new TypeError('Synthetic service configuration required');
 const pools=new Map(),queryEffects=new WeakMap(),timingEffects=new WeakMap();
 async function disconnect(target){const active=pools.get(target);if(active){pools.delete(target);await active.end();}}
 return Object.freeze({
  async provision({target,rows,payloadSha256}){
   targetName(target);
   if(!Array.isArray(rows)||rows.length>200||Buffer.byteLength(JSON.stringify(rows))>16*1024*1024||digest(rows)!==payloadSha256)throw new TypeError('Invalid snapshot');
   const admission=(await controlPool.query("SELECT state,receipt FROM owned_audit_targets WHERE target=$1",[target])).rows[0];
   if(admission?.state!=='pending'||admission.receipt.payloadSha256!==payloadSha256)throw Error('Durable admission required');
   const password=randomBytes(32).toString('hex');
   // All identifiers and password consist solely of server-generated hex.
   await controlPool.query(`CREATE ROLE ${target} LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS CONNECTION LIMIT 2`);
   await controlPool.query('INSERT INTO owned_audit_credentials(target,password) VALUES($1,$2)',[target,password]);
   await controlPool.query(`CREATE DATABASE ${target} TEMPLATE template0`);
   await controlPool.query(`REVOKE ALL ON DATABASE ${target} FROM PUBLIC`);
   await controlPool.query(`GRANT CONNECT ON DATABASE ${target} TO ${target}`);
   const admin=new Pool({...clusterConfig,database:target,max:1});
   try{
    await admin.query('REVOKE ALL ON SCHEMA public FROM PUBLIC; CREATE SCHEMA secureshop_agents; CREATE TABLE secureshop_agents.audit_events(id text,actor text,action text,target text,params_json text,ts text); CREATE TABLE secureshop_agents.teaching_secrets(secret text NOT NULL)');
    for(const row of rows){
     if(Object.keys(row).sort().join(',')!=='action,actor,id,params_json,target,ts'||['id','actor','action','params_json','ts'].some(k=>typeof row[k]!=='string')||(row.target!==null&&typeof row.target!=='string'))throw new TypeError('Invalid teaching row');
     await admin.query('INSERT INTO secureshop_agents.audit_events VALUES($1,$2,$3,$4,$5,$6)',[row.id,row.actor,row.action,row.target,row.params_json,row.ts]);
    }
    await admin.query('INSERT INTO secureshop_agents.teaching_secrets VALUES($1)',['SYNTHETIC_AUDIT_CANARY_'+randomBytes(24).toString('hex')]);
    await admin.query(`GRANT USAGE ON SCHEMA secureshop_agents TO ${target}; GRANT SELECT ON ALL TABLES IN SCHEMA secureshop_agents TO ${target}`);
   }finally{await admin.end();}
  },
  async search(target,username){
   targetName(target);if(typeof username!=='string'||Buffer.byteLength(username)>8192)throw new TypeError('Invalid teaching username');
   const row=(await controlPool.query("SELECT c.password FROM owned_audit_credentials c JOIN owned_audit_targets t USING(target) WHERE target=$1 AND t.state='ready'",[target])).rows[0];
   if(!row)throw Error('Owned target unavailable');
   let pool=pools.get(target);if(!pool){pool=new Pool({...clusterConfig,database:target,user:target,password:row.password,max:1,statement_timeout:1000,connectionTimeoutMillis:3000});pools.set(target,pool);}
   const client=await pool.connect();const start=process.hrtime.bigint();
   // Deliberate raw interpolation belongs exclusively inside this isolated target.
   const sql=`SELECT id,actor,action,target,params_json,ts FROM secureshop_agents.audit_events WHERE actor LIKE '%${username}%' OR target LIKE '%${username}%' ORDER BY ts DESC LIMIT 200`;
   try{await client.query('BEGIN READ ONLY');
    const baselineStart=process.hrtime.bigint();await client.query('SELECT 1');
    const baselineDurationMs=Number(process.hrtime.bigint()-baselineStart)/1e6;
    const queryStart=process.hrtime.bigint();
    const events=(await client.query({text:sql,values:[],queryMode:'extended'})).rows;
    const queryDurationMs=Number(process.hrtime.bigint()-queryStart)/1e6;
    const plan=(await client.query({text:'EXPLAIN (VERBOSE, FORMAT JSON) '+sql,values:[],queryMode:'extended'})).rows[0]?.['QUERY PLAN'];
    const referencesSecret=value=>Boolean(value&&typeof value==='object'&&((value['Relation Name']==='teaching_secrets'&&value.Schema==='secureshop_agents')||Object.values(value).some(referencesSecret)));
    const sourceRelationPlanned=referencesSecret(plan);
    const canary=(await client.query('SELECT secret FROM secureshop_agents.teaching_secrets')).rows[0]?.secret;
    if(typeof canary!=='string'||!/^SYNTHETIC_AUDIT_CANARY_[a-f0-9]{48}$/.test(canary))throw Error('Owned teaching canary unavailable');
    const result={ok:true,username,sql,count:events.length,events,error:null,durationMs:Number(process.hrtime.bigint()-start)/1e6};
    const planSha256=digest(plan);
    const sleepFunctionPlanned=value=>Boolean(value&&typeof value==='object'&&((value['Node Type']==='Function Scan'&&value['Function Name']==='pg_sleep')||Object.values(value).some(sleepFunctionPlanned)));
    timingEffects.set(result,Object.freeze({version:1,clock:'process.hrtime.bigint',baselineSql:'SELECT 1',baselineDurationMs,queryDurationMs,statementTimeoutMs:1000,sleepFunctionPlanned:sleepFunctionPlanned(plan),planSha256}));
    queryEffects.set(result,Object.freeze({version:2,kind:'synthetic_audit_canary',sourceRelationPlanned,planSha256,extracted:sourceRelationPlanned&&events.some(row=>Object.values(row).some(value=>value===canary)),canarySha256:createHash('sha256').update(canary).digest('hex')}));return result;
   }catch(error){return{ok:false,username,sql,count:0,events:[],error:error.message,durationMs:Number(process.hrtime.bigint()-start)/1e6};}
   finally{try{await client.query('ROLLBACK');client.release();}catch{client.release(true);}}
  },
  extractionEffect(result){return queryEffects.get(result)||null;},
  timingEffect(result){return timingEffects.get(result)||null;},
  async retire(target){
   targetName(target);await disconnect(target);
   const role=(await controlPool.query('SELECT 1 FROM pg_roles WHERE rolname=$1',[target])).rowCount;
   if(role)await controlPool.query(`ALTER ROLE ${target} NOLOGIN`);
   await controlPool.query(`DROP DATABASE IF EXISTS ${target} WITH (FORCE)`);
   await controlPool.query(`DROP ROLE IF EXISTS ${target}`);
   await controlPool.query('DELETE FROM owned_audit_credentials WHERE target=$1',[target]);
  },
  async close(){await Promise.all([...pools.keys()].map(disconnect));}
 });
}
module.exports={createService};
