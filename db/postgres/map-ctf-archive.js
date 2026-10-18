'use strict';

const { timestamp } = require('../../server/database/postgres/identityValidation');

const COLUMNS = Object.freeze({
  ctf_config: 'id key value description updated_at',
  ctf_participants: 'id user_id username email team_name started_at last_activity is_active total_completion_time final_position completed_at',
  ctf_stages: 'id stage_number stage_name stage_description difficulty_level ai_guardian_name ai_guardian_personality system_prompt success_criteria hints max_attempts time_penalty_per_wrong_attempt is_active stage_order difficulty defense_style adaptive_mode level_score time_bonus_seconds feedback_mode created_at',
  ctf_progress: 'id participant_id stage_id status started_at completed_at completion_time attempts_count successful_attempts failed_attempts hints_used hint_penalty_total time_penalties final_payload techniques_used created_at updated_at',
  ctf_attempts: 'id participant_id stage_id attempt_number payload ai_response was_successful response_time technique_tag technique_confidence blocked block_reason payload_hash attempt_timestamp session_id client_ip user_agent',
  ctf_judgments: 'run_id attempt_id participant_id stage_id progress_id stage_digest verdict accepted metadata created_at',
  ctf_leaderboard: 'id participant_id username team_name total_stages_completed total_completion_time average_stage_time fastest_stage_time slowest_stage_time total_attempts success_rate total_score last_updated rank_position is_completed completion_timestamp',
  ctf_events: 'id event_type participant_id stage_id event_data timestamp is_public',
  ctf_sessions: 'id participant_id session_token started_at last_heartbeat ended_at total_active_time is_active client_ip user_agent',
  ctf_technique_blocklist: 'id participant_id stage_id technique_tag first_used_at',
  ctf_payload_blocklist: 'id stage_id payload_hash normalized_snippet first_winner_participant_id first_won_at hit_count',
  ctf_bans: 'id user_id banned_at reason banned_by',
});
const IDS = new Set('id participant_id stage_id attempt_id progress_id first_winner_participant_id'.split(' '));
const INTEGERS = new Set(('user_id banned_by stage_number max_attempts time_penalty_per_wrong_attempt is_active stage_order level_score time_bonus_seconds completion_time attempts_count successful_attempts failed_attempts hints_used hint_penalty_total time_penalties attempt_number was_successful response_time blocked total_stages_completed total_completion_time fastest_stage_time slowest_stage_time total_attempts total_score rank_position is_completed total_active_time hit_count is_public accepted').split(' '));
const REALS = new Set(['technique_confidence', 'average_stage_time', 'success_rate']);
const TIMES = new Set('updated_at started_at last_activity completed_at created_at attempt_timestamp last_updated completion_timestamp timestamp last_heartbeat ended_at first_used_at first_won_at banned_at'.split(' '));
const FLAGS = new Set('is_active was_successful blocked is_completed is_public accepted'.split(' '));
const REQUIRED = Object.freeze({
  ctf_config: ['id','key','value'], ctf_participants: ['id','user_id','username'],
  ctf_stages: ['id','stage_number','stage_name','stage_order'], ctf_progress: ['id','participant_id','stage_id'],
  ctf_attempts: ['id','participant_id','stage_id','attempt_number','payload'],
  ctf_judgments: ['run_id','participant_id','stage_id','progress_id','stage_digest','verdict','accepted','metadata'],
  ctf_leaderboard: ['id','participant_id','username'], ctf_events: ['id','event_type'],
  ctf_sessions: ['id','participant_id','session_token'],
  ctf_technique_blocklist: ['id','participant_id','stage_id','technique_tag'],
  ctf_payload_blocklist: ['id','stage_id','payload_hash'], ctf_bans: ['id','user_id'],
});
const SEQUENCED_TABLES = Object.freeze(Object.keys(COLUMNS).filter(table => table !== 'ctf_judgments'));

function reject(code, location) { const error = new Error(code); error.code = code; error.location = location; throw error; }
function integer(value, location, positive = false) {
  if (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === 'type,value'
      && value.type === 'integer' && typeof value.value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(value.value)) value = Number(value.value);
  if (!Number.isSafeInteger(value) || value < -2147483648 || value > 2147483647 || (positive && value < 1)) reject('UNSAFE_CTF_INTEGER', location);
  return value;
}
function real(value, location) {
  if (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === 'type,value') {
    if (value.type === 'integer') return integer(value, location);
    if (value.type === 'real') value = value.value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (['-0','Infinity','-Infinity'].includes(value)) return value;
  reject('UNSAFE_CTF_REAL', location);
}
function instant(value, location, policy) {
  if (typeof value !== 'string' || (!/(Z|[+-]\d{2}:\d{2})$/.test(value) && policy !== 'UTC')) reject('AMBIGUOUS_CTF_TIMESTAMP', location);
  try { return timestamp(value, false); } catch { reject('INVALID_CTF_TIMESTAMP', location); }
}
function exact(row, fields, location) {
  if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).sort().join(',') !== fields.slice().sort().join(',')) reject('UNMAPPED_CTF_COLUMNS', location);
}
function canonicalIdentityMap(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject('CTF_IDENTITY_MAP_REQUIRED', 'identityMap');
  const result = new Map();
  for (const [source, target] of Object.entries(value)) {
    if (!/^[1-9][0-9]*$/.test(source)) reject('INVALID_CTF_IDENTITY_SOURCE', `identityMap.${source}`);
    const sourceId = integer(Number(source), `identityMap.${source}`, true);
    result.set(sourceId, integer(target, `identityMap.${source}`, true));
  }
  return result;
}
function mappedOwner(value, location, identityMap, report) {
  const sourceId = integer(value, location, true);
  if (!identityMap.has(sourceId)) reject('UNMAPPED_CTF_IDENTITY', location);
  const targetId = identityMap.get(sourceId);
  report.identityMappings.push({ sourceId, targetId, location });
  return targetId;
}

function mapCtfArchive(raw = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
      || Object.keys(raw).some(key => !['tables','archiveDigest','identityMap','naiveTimestamps','resolutions'].includes(key))) reject('INVALID_CTF_ARCHIVE_INPUT','input');
  const { tables, archiveDigest, naiveTimestamps = 'reject', resolutions = {} } = raw;
  if (!tables || typeof tables !== 'object' || Array.isArray(tables)) reject('INVALID_CTF_ARCHIVE_INPUT','tables');
  if (Object.keys(tables).some(table => !Object.hasOwn(COLUMNS,table))) reject('UNKNOWN_CTF_ARCHIVE_TABLE','tables');
  if (typeof archiveDigest !== 'string' || !/^[a-f0-9]{64}$/.test(archiveDigest)) reject('ARCHIVE_DIGEST_REQUIRED','archiveDigest');
  if (!['reject','UTC'].includes(naiveTimestamps)) reject('INVALID_TIMESTAMP_POLICY','naiveTimestamps');
  const identityMap = canonicalIdentityMap(raw.identityMap);
  if (!resolutions || typeof resolutions !== 'object' || Array.isArray(resolutions)
      || Object.keys(resolutions).some(key=>key!=='missingJudgments')) reject('INVALID_CTF_RESOLUTIONS','resolutions');
  const judgmentsMissing = !Object.hasOwn(tables,'ctf_judgments');
  const decision = resolutions.missingJudgments;
  if (decision !== undefined && (!judgmentsMissing || !decision || typeof decision !== 'object' || Array.isArray(decision)
      || Object.keys(decision).sort().join(',') !== 'archiveDigest,policy'
      || decision.archiveDigest !== archiveDigest || decision.policy !== 'source_table_absent_import_empty')) reject('STALE_CTF_MISSING_JUDGMENTS_RESOLUTION','resolutions.missingJudgments');
  const report = { archiveDigest, counts: {}, identityMappings: [], missingSourceTables: judgmentsMissing?['ctf_judgments']:[],
    resolutions: decision?[{table:'ctf_judgments',policy:decision.policy}]:[], requiresReview: judgmentsMissing&&!decision, readyToApply: !judgmentsMissing||!!decision };
  const mapped = {};
  for (const [table, columnsText] of Object.entries(COLUMNS)) {
    if (!Array.isArray(tables[table]) && !(table==='ctf_judgments'&&judgmentsMissing)) reject('MISSING_CTF_ARCHIVE_TABLE',table);
    const columns = columnsText.split(' '), required = new Set(REQUIRED[table]), ids = new Set();
    mapped[table] = (tables[table]||[]).map((source, index) => {
      const at = `${table}[${index}]`; exact(source,columns,at); const row = {};
      for (const column of columns) {
        const location = `${at}.${column}`, value = source[column];
        if (value === null) { if (required.has(column)) reject('NULL_CTF_REQUIRED_VALUE',location); row[column] = null; continue; }
        if (table === 'ctf_participants' && column === 'user_id' || table === 'ctf_bans' && ['user_id','banned_by'].includes(column)) row[column] = mappedOwner(value,location,identityMap,report);
        else if (IDS.has(column) || INTEGERS.has(column)) { row[column] = integer(value,location,IDS.has(column)); if (FLAGS.has(column) && ![0,1].includes(row[column])) reject('INVALID_CTF_FLAG',location); }
        else if (REALS.has(column)) row[column] = real(value,location);
        else if (TIMES.has(column)) row[column] = instant(value,location,naiveTimestamps);
        else { if (typeof value !== 'string' || value.includes('\0')) reject('INVALID_CTF_TEXT',location); row[column] = value; }
      }
      if (columnHasId(table)) { if (ids.has(row.id)) reject('DUPLICATE_CTF_ID',`${at}.id`); ids.add(row.id); }
      return row;
    });
    report.counts[table] = mapped[table].length;
    if (SEQUENCED_TABLES.includes(table) && mapped[table].some(row => row.id === 2147483647)) reject('CTF_SEQUENCE_EXHAUSTED',table);
  }
  validateRelationships(mapped);
  const participantTargets = mapped.ctf_participants.map(row => row.user_id);
  if (new Set(participantTargets).size !== participantTargets.length) reject('AMBIGUOUS_CTF_IDENTITY_MERGE','ctf_participants.user_id');
  return { tables: mapped, report };
}
function columnHasId(table) { return table !== 'ctf_judgments'; }
function validateRelationships(tables) {
  const participants = new Map(tables.ctf_participants.map(row => [row.id,row]));
  const stages = new Map(tables.ctf_stages.map(row => [row.id,row]));
  const progress = new Map(tables.ctf_progress.map(row => [row.id,row]));
  const attempts = new Map(tables.ctf_attempts.map(row => [row.id,row]));
  const unique = (rows,key,code) => { const seen=new Set(); for(const row of rows){const value=key(row);if(seen.has(value))reject(code,value);seen.add(value);} };
  const refs = (row,table,index) => {
    if (row.participant_id != null && !participants.has(row.participant_id)) reject('MISSING_CTF_PARTICIPANT',`${table}[${index}].participant_id`);
    if (row.stage_id != null && !stages.has(row.stage_id)) reject('MISSING_CTF_STAGE',`${table}[${index}].stage_id`);
  };
  for (const table of ['ctf_progress','ctf_attempts','ctf_leaderboard','ctf_events','ctf_sessions','ctf_technique_blocklist','ctf_payload_blocklist']) tables[table].forEach((row,index)=>refs(row,table,index));
  tables.ctf_payload_blocklist.forEach((row,index)=>{if(row.first_winner_participant_id!=null&&!participants.has(row.first_winner_participant_id))reject('MISSING_CTF_PARTICIPANT',`ctf_payload_blocklist[${index}].first_winner_participant_id`);});
  unique(tables.ctf_config,row=>row.key,'DUPLICATE_CTF_CONFIG_KEY'); unique(tables.ctf_participants,row=>row.user_id,'DUPLICATE_CTF_PARTICIPANT_USER');
  unique(tables.ctf_stages,row=>row.stage_number,'DUPLICATE_CTF_STAGE_NUMBER');
  unique(tables.ctf_progress,row=>JSON.stringify([row.participant_id,row.stage_id]),'DUPLICATE_CTF_PROGRESS');
  unique(tables.ctf_leaderboard,row=>row.participant_id,'DUPLICATE_CTF_LEADERBOARD'); unique(tables.ctf_sessions,row=>row.session_token,'DUPLICATE_CTF_SESSION_TOKEN');
  unique(tables.ctf_technique_blocklist,row=>JSON.stringify([row.participant_id,row.stage_id,row.technique_tag]),'DUPLICATE_CTF_TECHNIQUE');
  unique(tables.ctf_payload_blocklist,row=>JSON.stringify([row.stage_id,row.payload_hash]),'DUPLICATE_CTF_PAYLOAD'); unique(tables.ctf_bans,row=>row.user_id,'DUPLICATE_CTF_BAN');
  unique(tables.ctf_judgments,row=>row.run_id,'DUPLICATE_CTF_JUDGMENT_RUN');
  unique(tables.ctf_judgments.filter(row=>row.attempt_id!=null),row=>row.attempt_id,'DUPLICATE_CTF_JUDGMENT_ATTEMPT');
  tables.ctf_judgments.forEach((row,index)=>{const at=`ctf_judgments[${index}]`,p=progress.get(row.progress_id),a=row.attempt_id==null?null:attempts.get(row.attempt_id);refs(row,'ctf_judgments',index);if(!p||p.participant_id!==row.participant_id||p.stage_id!==row.stage_id)reject('MISMATCHED_CTF_JUDGMENT_PROGRESS',at);if(row.attempt_id!=null&&(!a||a.participant_id!==row.participant_id||a.stage_id!==row.stage_id))reject('MISMATCHED_CTF_JUDGMENT_ATTEMPT',at);});
}

module.exports = { COLUMNS, SEQUENCED_TABLES, mapCtfArchive };
