'use strict';
const {stageDigest}=require('../../agent-runtime/ctfStageJudge');
const {createHash,randomUUID}=require('node:crypto');
const invalid=()=>{throw new Error('CTF_BOOTSTRAP_LEGACY_DATA_UNAVAILABLE');};
const cfg={ctf_enabled:'enabled',ctf_visible_to_students:'visible_to_students',ctf_registration_open:'registration_open',student_leaderboard_visible:'student_leaderboard_visible',public_leaderboard_visible:'public_leaderboard_visible',ctf_nav_visible:'nav_visible',ctf_show_technique_feedback:'show_technique_feedback',ctf_show_attempt_counter:'show_attempt_counter',ctf_max_participants:'max_participants',ctf_time_limit:'time_limit_ms',leaderboard_update_interval:'leaderboard_update_interval_ms',ctf_hint_gating_attempts:'hint_gating_attempts',ctf_hint_cost_1:'hint_cost_1',ctf_hint_cost_2:'hint_cost_2',ctf_hint_cost_3:'hint_cost_3'};
const booleanFields=new Set(Object.values(cfg).slice(0,8));
async function importBootstrapRow(c,table,row,operationId){
 const marker={applied_sequence:0,applied_operation_id:operationId};
 async function insert(name,value){const keys=Object.keys(value);await c.query(`INSERT INTO identity.${name}(${keys.join(',')}) VALUES(${keys.map((_,i)=>'$'+(i+1)).join(',')})`,Object.values(value));}
 async function owner(id){
  const key=JSON.stringify(['CTF',String(id)]);
  // Registration alone need not have created a graph owner. Serialize against
  // deletion first; never replace an existing generation or resurrect a block.
  const user=(await c.query('SELECT id FROM identity.users WHERE id=$1 FOR UPDATE',[id])).rows[0];if(!user)invalid();
  const blocked=(await c.query('SELECT EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=$1 UNION ALL SELECT 1 FROM identity.student_deletion_run_blocks WHERE owner_key=$2) AS blocked',[id,key])).rows[0];if(!blocked||blocked.blocked)invalid();
  await c.query('INSERT INTO graph_runtime.owners(owner_key,generation) VALUES($1,0) ON CONFLICT(owner_key) DO NOTHING',[key]);
  const r=(await c.query('SELECT generation::text FROM graph_runtime.owners WHERE owner_key=$1 FOR SHARE',[key])).rows[0];if(!r)invalid();return r.generation;
 }
 if(table==='ctf_config')return; // Assembled once from staged pages below.
 if(table==='ctf_stages'){
  const stage={...row};if(stage.created_at!==null&&stage.created_at!==undefined)stage.created_at=new Date(stage.created_at); // Same pg timestamp projection used by stageDigest.
  let hints;try{hints=JSON.parse(row.hints||'[]');}catch{invalid();}if(!Array.isArray(hints)||hints.length>3)invalid();
  await insert('ctf_authority',{scope_key:'stage:'+row.id,lifecycle_state:'uninitialized'});
  await insert('ctf_stage_bindings',{stage_id:row.id,stage_number:row.stage_number,stage_revision:0,global_revision:0,stage_digest:stageDigest(stage),stage_order:row.stage_order,active:row.is_active===1,adaptive_mode:row.adaptive_mode,feedback_mode:row.feedback_mode,hint_count:hints.length,level_score:row.level_score,max_attempts:row.max_attempts,...marker});return;
 }
 if(table==='ctf_participants'){
  const generation=await owner(row.user_id);if(!row.started_at||![0,1].includes(row.is_active))invalid();
  await insert('ctf_authority',{scope_key:'owner:'+row.user_id,owner_generation:generation,lifecycle_state:'uninitialized'});
  await insert('ctf_participant_bindings',{owner_id:row.user_id,owner_generation:generation,participant_id:row.id,owner_revision:0,global_revision:0,active:row.is_active===1,banned:false,registered_at:row.started_at,...marker});return;
 }
 if(table==='ctf_progress'){
  const p=(await c.query('SELECT * FROM identity.ctf_participant_bindings WHERE participant_id=$1',[row.participant_id])).rows[0],s=(await c.query('SELECT * FROM identity.ctf_stage_bindings WHERE stage_id=$1',[row.stage_id])).rows[0];if(!p||!s)invalid();
  await insert('ctf_progress_bindings',{owner_id:p.owner_id,owner_generation:p.owner_generation,stage_id:row.stage_id,participant_id:row.participant_id,progress_id:row.id,owner_revision:0,global_revision:0,stage_revision:0,stage_digest:s.stage_digest,status:row.status,started_at:row.started_at,completed_at:row.completed_at,attempts_count:row.attempts_count,failed_attempts:row.failed_attempts,successful_attempts:row.successful_attempts,hints_used:row.hints_used,hint_penalty_total:row.hint_penalty_total,completion_time:row.completion_time,...marker});return;
 }
 if(table==='ctf_bans'){
  const generation=await owner(row.user_id);await c.query("INSERT INTO identity.ctf_authority(scope_key,owner_generation,lifecycle_state,banned) VALUES($1,$2,'uninitialized',true) ON CONFLICT(scope_key) DO UPDATE SET banned=true",['owner:'+row.user_id,generation]);await c.query('UPDATE identity.ctf_participant_bindings SET banned=true WHERE owner_id=$1',[row.user_id]);return;
 }
 if(table==='ctf_technique_blocklist'||table==='ctf_payload_blocklist'){
  let value={memory_id:randomUUID(),kind:table==='ctf_technique_blocklist'?'technique':'payload',stage_id:row.stage_id,stage_revision:0,clear_revision:0,legacy_source:'bootstrap:'+operationId};
  if(value.kind==='technique'){const p=(await c.query('SELECT * FROM identity.ctf_participant_bindings WHERE participant_id=$1',[row.participant_id])).rows[0];if(!p)invalid();value={...value,owner_id:p.owner_id,owner_generation:p.owner_generation,technique_tag:row.technique_tag};}
  else{if(typeof row.normalized_snippet!=='string'||!/^[a-z0-9_ ]*$/.test(row.normalized_snippet)||createHash('sha256').update(row.normalized_snippet).digest('hex')!==row.payload_hash)invalid();value={...value,payload_hash:row.payload_hash,normalized_payload:row.normalized_snippet};}
  await insert('ctf_adaptive_memory',value);
 }
}
async function importBootstrapConfig(c,operationId){
 const rows=(await c.query("SELECT canonical_rows FROM identity.ctf_bootstrap_pages WHERE operation_id=$1 AND table_name='ctf_config' ORDER BY page_number",[operationId])).rows.flatMap(r=>JSON.parse(r.canonical_rows));
 const value={singleton:true,global_revision:0,applied_sequence:0,applied_operation_id:operationId};
 for(const [key,column] of Object.entries(cfg)){const found=rows.filter(r=>r.key===key);if(found.length!==1)invalid();const raw=found[0].value;if(booleanFields.has(column)){if(!['true','false'].includes(raw))invalid();value[column]=raw==='true';}else{if(!/^-?(0|[1-9][0-9]*)$/.test(raw)||BigInt(raw)<-1n||BigInt(raw)>9223372036854775807n)invalid();value[column]=raw;}}
 const keys=Object.keys(value);await c.query(`INSERT INTO identity.ctf_config_binding(${keys.join(',')}) VALUES(${keys.map((_,i)=>'$'+(i+1)).join(',')})`,Object.values(value));
}
module.exports={importBootstrapRow,importBootstrapConfig};
