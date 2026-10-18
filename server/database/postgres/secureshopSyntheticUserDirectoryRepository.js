'use strict';
const { randomBytes, randomUUID, createHash } = require('node:crypto');
const bcrypt = require('bcryptjs');
const { isDeepStrictEqual: equal } = require('node:util');
const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const fields = ['id','username','role','email','full_name','phone','password','api_key','session_token'];
const preparedDirectories = new WeakSet();
const digest = rows => createHash('sha256').update(JSON.stringify(rows.map(row => fields.map(key => row[key])))).digest();
const safeFields=['id','username','role'];
const rowDigest=(row,mode)=>createHash('sha256').update(JSON.stringify(row===null?null:(mode==='fixed'?safeFields:fields).map(key=>row[key]))).digest('hex');
const unavailable=()=>Object.assign(Error('Synthetic lookup source unavailable'),{code:'LOOKUP_SOURCE_UNAVAILABLE'});
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype&&equal(Object.keys(value).sort(),[...keys].sort());
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
function agentContext(raw){
 const scope=createLaunchScope(raw.scope),persona=raw.persona,session=raw.personaSession,mode=raw.modeExecution,scene=raw.sceneExecution;
 if(!Number.isSafeInteger(persona?.id)||persona.id<1||persona.role!=='admin'||!UUID.test(session?.sessionId||'')
  ||typeof session.authorityVersion!=='string'||!/^[1-9]\d*$/.test(session.authorityVersion)
  ||typeof raw.username!=='string'||!raw.username||!raw.username.isWellFormed()||raw.username.includes('\0')||Buffer.byteLength(raw.username)>100
  ||mode?.version!==1||mode.featureId!=='admin_assistant'||mode.policyVersion!=='owned-admin-read-and-confirmation-v1'
  ||!['vuln','fixed'].includes(mode.mode)||!equal(mode.scope,scope)
  ||!Number.isSafeInteger(mode.generation)||mode.generation<0||typeof mode.modeStamp!=='string'||!mode.modeStamp
  ||!exact(scene,['targetId','sceneId','sceneGeneration','grantId'])||![scene.targetId,scene.sceneId,scene.grantId].every(v=>UUID.test(v||''))
  ||!Number.isSafeInteger(scene.sceneGeneration)||scene.sceneGeneration<1)throw unavailable();
 return{scope,persona:{id:persona.id,role:'admin'},personaSession:{sessionId:session.sessionId,authorityVersion:session.authorityVersion},
  username:raw.username,modeExecution:structuredClone(mode),sceneExecution:structuredClone(scene)};
}
const scopeValues=scope=>[scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId];
function directoryIntegrity(row){
 if(!row||!Buffer.isBuffer(row.content_sha256)||row.content_sha256.length!==32)throw unavailable();
 return row.content_sha256.toString('hex');
}
function reference(raw,context){
 if(!exact(raw,['version','eventId','scope','persona','personaSession','username','directorySha256','rowSha256','modeExecution','sceneExecution'])
  ||raw.version!==1||!UUID.test(raw.eventId||'')||!['directorySha256','rowSha256'].every(k=>/^[a-f0-9]{64}$/.test(raw[k]||''))
  ||Object.keys(context).some(k=>!equal(raw[k],context[k])))throw unavailable();
 return structuredClone(raw);
}
// These independent teaching records are never credentials accepted by shop auth.
async function createSyntheticDirectory() {
  const rows = [];
  for (const [index, role] of ['customer', 'merchant', 'admin'].entries()) {
    rows.push({ id: index + 1, username: `student_${role}`, role,
      email: `${role}@training.example.invalid`, full_name: `Synthetic ${role}`, phone: '+1-202-555-0100',
      password: await bcrypt.hash('SYNTHETIC_ONLY_' + randomBytes(24).toString('hex'), 10),
      api_key: 'TRAINING_API_' + randomBytes(24).toString('hex'),
      session_token: 'TRAINING_SESSION_' + randomBytes(24).toString('hex') });
  }
  const prepared = Object.freeze(rows.map(Object.freeze));
  preparedDirectories.add(prepared);
  return prepared;
}
function createSyntheticUserDirectoryRepository({ pool, audit }) {
  if (typeof pool?.query !== 'function' || typeof audit?.append !== 'function') throw TypeError('Agents pool required');
  async function readAgentRow(client,context){
    const values=scopeValues(context.scope);
    if(context.modeExecution.mode==='fixed'){
      // PostgreSQL projects only the identity allowlist. No protected row or
      // credential/PII value crosses this query boundary in fixed mode.
      const row=(await client.query(`SELECT d.content_sha256,
        (SELECT jsonb_build_object('id',u->'id','username',u->'username','role',u->'role')
          FROM jsonb_array_elements(d.rows_json) u WHERE u->>'username'=$6) AS safe_user
        FROM secureshop_agents.bound_synthetic_user_directories d
        WHERE platform_launch_id=$1 AND platform_scenario_id=$2 AND platform_launch_generation=$3
          AND original_platform_owner_id=$4 AND original_platform_session_id=$5`,[...values,context.username])).rows[0];
      const directorySha256=directoryIntegrity(row),user=row.safe_user??null;
      if(user!==null&&(!exact(user,safeFields)||!Number.isSafeInteger(user.id)||user.id<1||user.username!==context.username||!['customer','merchant','admin'].includes(user.role)))throw unavailable();
      return{directorySha256,user};
    }
    const row=(await client.query(`SELECT rows_json,content_sha256 FROM secureshop_agents.bound_synthetic_user_directories
      WHERE platform_launch_id=$1 AND platform_scenario_id=$2 AND platform_launch_generation=$3
        AND original_platform_owner_id=$4 AND original_platform_session_id=$5`,values)).rows[0];
    const directorySha256=directoryIntegrity(row);
    if(!Array.isArray(row.rows_json)||row.rows_json.length!==3||!row.content_sha256.equals(digest(row.rows_json)))throw unavailable();
    const users=row.rows_json.filter(user=>user.username===context.username);if(users.length>1)throw unavailable();
    const user=users[0]??null;if(user!==null&&!exact(user,fields))throw unavailable();
    return{directorySha256,user:structuredClone(user)};
  }
  return Object.freeze({
    async checkReadiness() {
      const result = await pool.query(`SELECT has_table_privilege(current_user,'secureshop_agents.bound_synthetic_user_directories','SELECT') AND has_table_privilege(current_user,'secureshop_agents.bound_synthetic_user_directories','INSERT') AS permitted,
        has_table_privilege(current_user,'secureshop_agents.bound_synthetic_user_directories','UPDATE,DELETE,TRUNCATE') AS mutable,
        has_any_column_privilege(current_user,'secureshop_agents.bound_synthetic_user_directories','UPDATE') AS columns,
        (SELECT count(*)=4 FROM pg_trigger WHERE tgenabled='O' AND tgqual IS NULL AND (
          (tgname='synthetic_user_directory_admission' AND tgrelid='secureshop_agents.bound_synthetic_user_directories'::regclass AND tgtype=7 AND tgfoid='secureshop_agents.guard_bound_persona_admin_insert()'::regprocedure) OR
          (tgname='synthetic_user_directory_immutable' AND tgrelid='secureshop_agents.bound_synthetic_user_directories'::regclass AND tgtype=19 AND tgfoid='secureshop_agents.guard_bound_audit_owner_deletion_receipt()'::regprocedure) OR
          (tgname='synthetic_user_directory_retirement' AND tgrelid='secureshop_agents.conversation_generation_retirements'::regclass AND tgtype=5 AND tgfoid='secureshop_agents.cleanup_synthetic_user_directory()'::regprocedure) OR
          (tgname='synthetic_user_directory_owner' AND tgrelid='secureshop_agents.bound_audit_owner_deletion_receipts'::regclass AND tgtype=5 AND tgfoid='secureshop_agents.cleanup_synthetic_user_directory()'::regprocedure))) AS lifecycle`);
      const row = result.rows[0];
      if (!row?.permitted || row.mutable || row.columns || !row.lifecycle) throw Error('Synthetic directory readiness unavailable');
      const functions = (await pool.query(`SELECT
        has_function_privilege(current_user,'secureshop_agents.cleanup_synthetic_user_directory()','EXECUTE') AS runtime_execute,
        EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
          WHERE p.oid='secureshop_agents.cleanup_synthetic_user_directory()'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute,
        (SELECT prosecdef AND proconfig=ARRAY['search_path=pg_catalog'] FROM pg_proc
          WHERE oid='secureshop_agents.cleanup_synthetic_user_directory()'::regprocedure) AS private_cleanup`)).rows[0];
      if (!functions?.private_cleanup || functions.runtime_execute || functions.public_execute) throw Error('Synthetic directory cleanup privileges unavailable');
      const bounds = (await pool.query(`SELECT conname,pg_get_expr(conbin,conrelid) AS expression,convalidated
        FROM pg_constraint WHERE conrelid='secureshop_agents.bound_synthetic_user_directories'::regclass
        AND conname IN ('synthetic_directory_rows_type','synthetic_directory_rows_count','synthetic_directory_rows_bytes')`)).rows;
      const expected = { synthetic_directory_rows_type: "jsonb_typeofrows_json='array'",
        synthetic_directory_rows_count: 'jsonb_array_lengthrows_json=3',
        synthetic_directory_rows_bytes: 'octet_lengthrows_json<32768' };
      if (bounds.length !== 3 || bounds.some(bound => !bound.convalidated
        || bound.expression.replace(/::text/g, '').replace(/[\s()]/g, '') !== expected[bound.conname])) throw Error('Synthetic directory bounds unavailable');
    },
    prepare: createSyntheticDirectory,
    async lookupForAgent(client,raw){
      const context=agentContext(raw);if(!preparedDirectories.has(raw.prepared))throw unavailable();
      await client.query("SET LOCAL statement_timeout='3000ms'");
      await client.query(`INSERT INTO secureshop_agents.bound_synthetic_user_directories
        (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,rows_json,content_sha256)
        VALUES($1,$2,$3,$4,$5,$6::jsonb,$7) ON CONFLICT DO NOTHING`,[...scopeValues(context.scope),JSON.stringify(raw.prepared),digest(raw.prepared)]);
      const {directorySha256,user}=await readAgentRow(client,context),status=user===null?'not_found':context.modeExecution.mode==='fixed'?'redacted':'complete';
      const receipt={version:1,eventId:randomUUID(),...context,directorySha256,rowSha256:rowDigest(user,context.modeExecution.mode)};
      await audit.append(client,{eventId:receipt.eventId,scope:context.scope,persona:context.persona,actor:'admin',action:'synthetic_user_agent_lookup',
        target:'synthetic-directory',paramsJson:JSON.stringify({version:1,status,receipt}),outcome:'completed',sourceKind:'synthetic_user_agent_lookup',sourceId:receipt.eventId});
      return{version:1,status,user,receipt};
    },
    async readAgentLookup(client,raw){
      const context=agentContext({...raw,username:raw.reference?.username}),saved=reference(raw.reference,context);
      const rows=(await client.query(`SELECT params_json FROM secureshop_agents.bound_audit_events
        WHERE event_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4
          AND original_platform_owner_id=$5 AND original_platform_session_id=$6 AND shop_user_id=$7 AND shop_role='admin'
          AND actor='admin' AND action='synthetic_user_agent_lookup' AND target='synthetic-directory'
          AND outcome='completed' AND source_kind='synthetic_user_agent_lookup' AND source_id=$1::text`,
        [saved.eventId,...scopeValues(context.scope),context.persona.id])).rows;
      let event;try{event=rows.length===1&&JSON.parse(rows[0].params_json);}catch{throw unavailable();}
      if(!exact(event,['version','status','receipt'])||event.version!==1||!equal(event.receipt,saved))throw unavailable();
      const {directorySha256,user}=await readAgentRow(client,context),status=user===null?'not_found':context.modeExecution.mode==='fixed'?'redacted':'complete';
      if(event.status!==status||directorySha256!==saved.directorySha256||rowDigest(user,context.modeExecution.mode)!==saved.rowSha256)throw unavailable();
      return{version:1,status,user,receipt:saved};
    },
    async lookup(client, { scope: rawScope, username, prepared, persona, mode='vuln' }) {
      if (!preparedDirectories.has(prepared) || typeof username !== 'string' || username.length > 100||!['vuln','fixed'].includes(mode)) throw TypeError('Trusted synthetic directory required');
      const scope = createLaunchScope(rawScope);
      const values = [scope.launchId, scope.scenarioId, scope.generation, scope.platformOwnerId, scope.platformSessionId];
      // Called only inside the captured original-admin same-client effect lease.
      await client.query("SET LOCAL statement_timeout='3000ms'");
      await client.query(`INSERT INTO secureshop_agents.bound_synthetic_user_directories
        (platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,rows_json,content_sha256)
        VALUES($1,$2,$3,$4,$5,$6::jsonb,$7) ON CONFLICT DO NOTHING`, [...values, JSON.stringify(prepared), digest(prepared)]);
      let user;
      if(mode==='fixed')user=(await readAgentRow(client,{scope,username,modeExecution:{mode}})).user;
      else{
       const row = (await client.query(`SELECT rows_json,content_sha256 FROM secureshop_agents.bound_synthetic_user_directories
         WHERE platform_launch_id=$1 AND platform_scenario_id=$2 AND platform_launch_generation=$3
         AND original_platform_owner_id=$4 AND original_platform_session_id=$5`, values)).rows[0];
       if (!row || !Buffer.isBuffer(row.content_sha256) || !row.content_sha256.equals(digest(row.rows_json))) throw Error('Synthetic directory integrity unavailable');
       user = row.rows_json.find(user => user.username === username) || null;
      }
      const eventId = randomUUID();
      await audit.append(client, { eventId, scope, persona, actor: 'admin', action: 'synthetic_user_lookup',
        target: 'synthetic-directory', paramsJson: JSON.stringify({ found: !!user }), outcome: 'completed',
        sourceKind: 'synthetic_user_lookup', sourceId: eventId });
      return user;
    },
  });
}
module.exports = { createSyntheticUserDirectoryRepository };
