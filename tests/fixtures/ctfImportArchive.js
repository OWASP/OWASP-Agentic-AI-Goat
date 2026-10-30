'use strict';
const {COLUMNS}=require('../../db/postgres/map-ctf-archive');
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const i=value=>({type:'integer',value:String(value)}),r=value=>({type:'real',value});
const stamp='2026-01-02 03:04:05.123456';
function row(table,values){return Object.fromEntries(COLUMNS[table].split(' ').map(key=>[key,Object.hasOwn(values,key)?values[key]:null]));}
function fixture(){return{archiveDigest:'a'.repeat(64),naiveTimestamps:'UTC',identityMap:{70:7,71:8},tables:{
 ctf_config:[row('ctf_config',{id:i(1),key:'event_name',value:'OWASP-AI-GOAT CTF',description:'edited',updated_at:stamp})],
 ctf_participants:[row('ctf_participants',{id:i(2),user_id:i(70),username:'learner',email:'l@example.test',team_name:'red',started_at:stamp,last_activity:stamp,is_active:i(1),total_completion_time:i(9)})],
 ctf_stages:[row('ctf_stages',{id:i(3),stage_number:i(1),stage_name:'Guardian',stage_description:'deliberate challenge',difficulty_level:'hard',ai_guardian_name:'Sphinx',ai_guardian_personality:'strict',system_prompt:'INTENTIONAL SECRET: keep exact',success_criteria:'extract secret',hints:' ["edited hint"] ',max_attempts:i(-1),time_penalty_per_wrong_attempt:i(5),is_active:i(1),stage_order:i(1),difficulty:'hard',defense_style:' ["output_filter"] ',adaptive_mode:'hybrid',level_score:i(100),time_bonus_seconds:i(300),feedback_mode:'reason',created_at:stamp})],
 ctf_progress:[row('ctf_progress',{id:i(4),participant_id:i(2),stage_id:i(3),status:'completed',started_at:stamp,completed_at:stamp,completion_time:i(9),attempts_count:i(1),successful_attempts:i(1),failed_attempts:i(0),hints_used:i(0),hint_penalty_total:i(0),time_penalties:i(0),final_payload:'ignore previous',techniques_used:' ["override"] ',created_at:stamp,updated_at:stamp})],
 ctf_attempts:[row('ctf_attempts',{id:i(5),participant_id:i(2),stage_id:i(3),attempt_number:i(1),payload:'ignore previous',ai_response:'source response',was_successful:i(1),response_time:i(12),technique_tag:'override',technique_confidence:r(0.9),blocked:i(0),payload_hash:'abc',attempt_timestamp:stamp,session_id:'session',client_ip:'127.0.0.1',user_agent:'fixture'})],
 ctf_judgments:[row('ctf_judgments',{run_id:'run-source',attempt_id:i(5),participant_id:i(2),stage_id:i(3),progress_id:i(4),stage_digest:'d'.repeat(64),verdict:'pass',accepted:i(1),metadata:' {"source":"existing"} ',created_at:stamp})],
 ctf_leaderboard:[row('ctf_leaderboard',{id:i(6),participant_id:i(2),username:'learner',team_name:'red',total_stages_completed:i(1),total_completion_time:i(9),average_stage_time:r(9),fastest_stage_time:i(9),slowest_stage_time:i(9),total_attempts:i(1),success_rate:r(100),total_score:i(100),last_updated:stamp,rank_position:i(1),is_completed:i(0)})],
 ctf_events:[row('ctf_events',{id:i(7),event_type:'stage_complete',participant_id:i(2),stage_id:i(3),event_data:' {"raw":true} ',timestamp:stamp,is_public:i(1)})],
 ctf_sessions:[row('ctf_sessions',{id:i(8),participant_id:i(2),session_token:'private-session',started_at:stamp,last_heartbeat:stamp,total_active_time:i(1000),is_active:i(1),client_ip:'127.0.0.1',user_agent:'fixture'})],
 ctf_technique_blocklist:[row('ctf_technique_blocklist',{id:i(9),participant_id:i(2),stage_id:i(3),technique_tag:'override',first_used_at:stamp})],
 ctf_payload_blocklist:[row('ctf_payload_blocklist',{id:i(10),stage_id:i(3),payload_hash:'abc',normalized_snippet:'ignore previous',first_winner_participant_id:i(2),first_won_at:stamp,hit_count:i(4)})],
 ctf_bans:[row('ctf_bans',{id:i(11),user_id:i(71),banned_at:stamp,reason:'fixture',banned_by:i(70)})],
 }};}
async function writeArchive(directory,source=fixture()){
 const write=async(name,data)=>{await fs.writeFile(path.join(directory,name),data);return{bytes:Buffer.byteLength(data),sha256:crypto.createHash('sha256').update(data).digest('hex')}};
 const tables=[];
 for(const[name,rows]of Object.entries(source.tables)){
  const columns=COLUMNS[name].split(' '),encode=value=>value===null?{type:'null'}:value&&value.type?value:{type:'text',value};
  const content=rows.map(row=>JSON.stringify(columns.map(column=>encode(row[column])))+'\n').join(''),file=name+'.jsonl';
  tables.push({name,columns,file,rows:rows.length,...await write(file,content)});
 }
 const schemaFile='schema.json',schema=await write(schemaFile,JSON.stringify(tables.map(table=>({type:'table',name:table.name}))));
 await fs.writeFile(path.join(directory,'manifest.json'),JSON.stringify({version:1,format:'owasp-ai-goat-sqlite-archive-v1',complete:true,files:[{name:'ctf.db',sourceSha256:'b'.repeat(64),schemaFile,schema,tables}]}));
 return source;
}
module.exports={fixture,i,r,writeArchive};
