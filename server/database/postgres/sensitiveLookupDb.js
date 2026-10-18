'use strict';
const {createPool,withTransaction}=require('./index');
const {initialize}=require('./workshopSupport');
const seeds=require('../../../db/postgres/seeds/sensitiveLookup.json');
function owner(value){if((typeof value!=='string'&&typeof value!=='number')||!String(value).trim()||String(value).length>200)throw new TypeError('Authenticated owner required');return String(value);}
async function seed(client){
 for(const r of seeds.fileReferences)await client.query('INSERT INTO sensitive_lookup.file_references(reference_key,file_path,description,access_level) VALUES($1,$2,$3,$4) ON CONFLICT(reference_key) DO NOTHING',[r.key,r.path,r.desc,r.level]);
 for(const r of seeds.templates)await client.query('INSERT INTO sensitive_lookup.chatbot_templates(template_name,template_content,template_path,category) VALUES($1,$2,$3,$4) ON CONFLICT(template_name) DO NOTHING',[r.name,r.content,r.path,r.category]);
 for(const r of seeds.configs)await client.query('INSERT INTO sensitive_lookup.chatbot_config(config_key,config_value,config_type,is_sensitive) VALUES($1,$2,$3,$4) ON CONFLICT(config_key) DO NOTHING',[r.key,r.value,r.type,r.sensitive]);
}
function createSensitiveLookupDb(pool){
 const read=async(sql,params=[])=>withTransaction(pool,async client=>{
  await client.query('SET TRANSACTION READ ONLY');await client.query('SET LOCAL search_path TO sensitive_lookup,pg_catalog');
  return(await client.query({text:sql,values:params,queryMode:'extended'})).rows;
 });
 return{
  engine:'postgres',dialect:'PostgreSQL',
  initialize:migrationPool=>initialize(pool,migrationPool,'sensitive_lookup',seed),
  async health(){await pool.query('SELECT 1');return true;},
  async getFilePathByReference(referenceKey,userInput=null){
   // Intentional raw SQL branch retains query manipulation and arbitrary path fallback.
   const rows=userInput&&userInput.includes("'")?await read(`SELECT file_path FROM file_references WHERE reference_key = '${referenceKey}' OR '1'='1' LIMIT 1`):await read('SELECT file_path FROM file_references WHERE reference_key=$1',[referenceKey]);
   return rows[0]?.file_path||userInput||referenceKey;
  },
  async getTemplateByName(templateName,userInput=null){
   const raw=userInput&&(userInput.includes("'")||userInput.includes('UNION'));
   const rows=raw?await read(`SELECT template_content,ssi_enabled FROM chatbot_templates WHERE template_name = '${templateName}' OR 1=1`):await read('SELECT template_content,ssi_enabled FROM chatbot_templates WHERE template_name=$1',[templateName]);
   return rows[0]?{content:rows[0].template_content,ssiEnabled:rows[0].ssi_enabled}:null;
  },
  async getConfigValue(key){return(await read('SELECT config_value FROM chatbot_config WHERE config_key=$1',[key]))[0]?.config_value??null;},
  async logExploitation(data){await pool.query('INSERT INTO sensitive_lookup.exploitation_log(user_id,user_input,query_executed,vulnerability_type,file_accessed,flag_captured,success,ip_address,user_agent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[owner(data.userId),data.userInput,data.queryExecuted,data.vulnerabilityType,data.fileAccessed,data.flagCaptured,!!data.success,data.ipAddress,data.userAgent]);},
  async getExploitationStats(userId){return(await pool.query('SELECT count(*)::integer AS total_attempts,count(*) FILTER(WHERE success)::integer AS successful_exploits,count(DISTINCT user_id)::integer AS unique_users,count(DISTINCT file_accessed)::integer AS files_accessed,vulnerability_type,count(*)::integer AS count FROM sensitive_lookup.exploitation_log WHERE user_id=$1 GROUP BY vulnerability_type',[owner(userId)])).rows;},
  async destroyOwner(userId){const result=await pool.query('SELECT sensitive_lookup.destroy_student_owner($1)::integer AS removed',[owner(userId)]);return{removed:result.rows[0].removed};},
 };
}
let instance;
function getSensitiveLookupDb(){return instance||=createSensitiveLookupDb(createPool(process.env,'SENSITIVE_LOOKUP_DATABASE_URL'));}
async function initializeSensitiveLookupDb({runtimePool,migrationPool}={}){
 const db=runtimePool?createSensitiveLookupDb(runtimePool):getSensitiveLookupDb();const migrations=migrationPool||createPool(process.env,'SENSITIVE_LOOKUP_MIGRATION_DATABASE_URL');
 try{await db.initialize(migrations);return db;}finally{if(!migrationPool)await migrations.end();}
}
module.exports={createSensitiveLookupDb,getSensitiveLookupDb,initializeSensitiveLookupDb};
