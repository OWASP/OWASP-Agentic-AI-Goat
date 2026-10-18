'use strict';
// Unregistered candidate durable admission/receipt storage; external execution never occurs here.
const { createLaunchScope, createConversationBinding } = require('../../services/secureshopConversationBinding');
const { canonicalDigest } = require('../../services/mcp/protocolContext');
const {randomUUID}=require('node:crypto');
const {normalizeDiagnosticRequest:normalizeRequest,diagnosticRequestDigest:requestDigest}=require('../../../sidecars/sandbox-runner/owned-system/diagnostic-contract');
const {validateBoundDiagnosticResult}=require('../../../sidecars/sandbox-runner/owned-system/diagnostic-wire');
const C = 'platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id';
const W = C.split(',').map((column,index)=>`${column}=$${index+1}`).join(' AND ');
const T = 'secureshop_agents.bound_system_diagnostic_';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail = code => Object.assign(new Error('Bound System diagnostic unavailable'), { code });
const values = x => [x.scope.launchId,x.scope.scenarioId,x.scope.generation,x.scope.platformOwnerId,x.scope.platformSessionId];
function snapshot(raw, withRequest=true, withOperation=true) {
  const x = structuredClone(raw);
  if(Object.hasOwn(x,'targetId')||Object.hasOwn(x,'request')||Object.hasOwn(x,'digest'))throw fail('INVALID_ARGUMENT');
  x.scope = createLaunchScope(x.scope); createConversationBinding(x.scope,x.persona);
  if(x.persona.role!=='admin') throw fail('ADMIN_REQUIRED');
  if(!UUID.test(x.personaSession?.sessionId)||typeof x.personaSession?.authorityVersion!=='string'
      || !/^[1-9]\d{0,15}$/.test(x.personaSession.authorityVersion)||BigInt(x.personaSession.authorityVersion)>9007199254740991n) throw fail('SHOP_AUTH_INVALID');
  if(withOperation&&!UUID.test(x.operationId)) throw fail('INVALID_ARGUMENT');
  if(withRequest) { x.request=normalizeRequest({operationId:x.operationId,cmd_template:x.cmd_template,args:x.args});x.digest=requestDigest(x.request); }
  return x;
}
function bindingDigest(x,request,targetId) { return canonicalDigest({scope:x.scope,persona:{id:x.persona.id,role:x.persona.role},personaSession:{sessionId:x.personaSession.sessionId,authorityVersion:x.personaSession.authorityVersion},targetId,request}); }
function createSystemDiagnosticRepository({ pool, personaAuthority, audit }={}) {
  if(typeof pool?.query!=='function'||typeof personaAuthority?.capture!=='function'||typeof audit?.append!=='function') throw TypeError('Trusted System repository dependencies required');
  async function transaction(x,work,write=false) {
    const expected={...x.scope,personaId:x.persona.id,role:x.persona.role,sessionId:x.personaSession.sessionId,authorityVersion:x.personaSession.authorityVersion};
    const fence=await personaAuthority.capture({scope:x.scope,personaId:x.persona.id,role:x.persona.role,sessionId:x.personaSession.sessionId,authorityVersion:x.personaSession.authorityVersion});
    if(!fence?.binding||Object.keys(expected).some(k=>fence.binding[k]!==expected[k])||typeof fence.withPersonaEffect!=='function'||typeof fence.assertRemoteAdmission!=='function') throw fail('SHOP_AUTH_INVALID');
    let completed=false;
    try {
      const result=await fence.withPersonaEffect(async client=>{
        await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
        // Authority holds canonical owner→launch/persona locks first. The same
        // scope lock is also enforced by INSERT triggers for direct SQL writes.
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(':','secureshop-system-diagnostic',$1::text,$2::text,$3::text,$4::text,$5::text),0))",values(x));
        const value=await work(client);completed=true;return value;
      });
      await fence.assertRemoteAdmission();return result;
    }catch(cause){if(write&&completed)throw fail('SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN');throw cause;}
  }
  async function admission(client,x,required=false) {
    const row=(await client.query(`SELECT * FROM ${T}admissions WHERE ${W} AND operation_id=$6`,[...values(x),x.operationId])).rows[0];
    if(!row){if(required)throw fail('SYSTEM_DIAGNOSTIC_NOT_FOUND');return null;}
    if(Number(row.persona_id)!==x.persona.id||row.persona_role!==x.persona.role||row.persona_session_id!==x.personaSession.sessionId||String(row.authority_version)!==x.personaSession.authorityVersion)throw fail('OPERATION_CONFLICT');
    if(!row.request_json||!UUID.test(row.target_id))throw fail('SYSTEM_DIAGNOSTIC_RETIRED');
    const request=normalizeRequest(row.request_json),digest=requestDigest(request);
    if(request.operationId!==x.operationId||row.request_sha256.toString('hex')!==digest||row.binding_sha256.toString('hex')!==bindingDigest(x,request,row.target_id))throw fail('SYSTEM_DIAGNOSTIC_INTEGRITY_UNAVAILABLE');
    if(x.digest&&x.digest!==digest)throw fail('OPERATION_CONFLICT');
    return row;
  }
  async function outcome(client,x,row) {
    const result=(await client.query(`SELECT * FROM ${T}outcomes WHERE ${W} AND operation_id=$6`,[...values(x),x.operationId])).rows[0];
    const base={operationId:x.operationId,requestSha256:row.request_sha256.toString('hex'),targetId:row.target_id};
    if(!result)return {state:'pending',...base};
    if(Number(result.persona_id)!==x.persona.id||result.persona_role!==x.persona.role||result.persona_session_id!==x.personaSession.sessionId||String(result.authority_version)!==x.personaSession.authorityVersion||!result.request_sha256.equals(row.request_sha256)||!result.binding_sha256.equals(row.binding_sha256))throw fail('SYSTEM_DIAGNOSTIC_INTEGRITY_UNAVAILABLE');
    if(['unknown','not_executed'].includes(result.state)&&result.receipt_json===null&&result.receipt_sha256===null)return {state:result.state,...base};
    if(result.state!=='completed'||!result.receipt_json||canonicalDigest(result.receipt_json)!==result.receipt_sha256?.toString('hex'))throw fail('SYSTEM_DIAGNOSTIC_INTEGRITY_UNAVAILABLE');
    return {state:'completed',...base,receipt:validateBoundDiagnosticResult({targetId:row.target_id,request:row.request_json},result.receipt_json)};
  }
  async function auditOutcome(client,x,state,receipt) {
    // Audit enum describes the observation; terminal protocol state remains metadata.
    const auditState=state==='completed'&&receipt.result.exitCode===0?'completed':'failed';
    await audit.append(client,{eventId:x.operationId,scope:x.scope,persona:x.persona,actor:'admin',action:'system_diagnostic',target:x.operationId,
      paramsJson:JSON.stringify({operationId:x.operationId,requestSha256:x.digest,state,receiptSha256:receipt?canonicalDigest(receipt):null}),outcome:auditState,sourceKind:'system_diagnostic',sourceId:x.operationId});
  }
  async function finish(raw,state) {
    const x=snapshot(raw);let receipt=null;
    return transaction(x,async client=>{
      const row=await admission(client,x,true),existing=await outcome(client,x,row);
      receipt=state==='completed'?validateBoundDiagnosticResult({targetId:row.target_id,request:x.request},x.receipt):null;
      if(existing.state==='completed'){
        if(state==='completed'&&canonicalDigest(existing.receipt)!==canonicalDigest(receipt))throw fail('OPERATION_CONFLICT');
        return existing;
      }
      if(['unknown','not_executed'].includes(existing.state)){if(state==='completed')throw fail('SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN');return existing;}
      await client.query(`INSERT INTO ${T}outcomes (${C},operation_id,persona_id,persona_session_id,persona_role,authority_version,request_sha256,binding_sha256,state,receipt_json,receipt_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,decode($11,'hex'),decode($12,'hex'),$13,$14::jsonb,decode($15,'hex'))`,[...values(x),x.operationId,x.persona.id,x.personaSession.sessionId,x.persona.role,x.personaSession.authorityVersion,x.digest,bindingDigest(x,x.request,row.target_id),state,receipt?JSON.stringify(receipt):null,receipt?canonicalDigest(receipt):null]);
      await auditOutcome(client,x,state,receipt);
      return {state,operationId:x.operationId,requestSha256:x.digest,targetId:row.target_id,...(receipt?{receipt}: {})};
    },true);
  }
  return Object.freeze({
    async administration(raw){
      const x=snapshot(raw,false,false);
      return transaction(x,async()=>Object.freeze({scopeKey:canonicalDigest({version:'secureshop-system-diagnostic-administration.v1',scope:x.scope,persona:{id:x.persona.id,role:x.persona.role},personaSession:{sessionId:x.personaSession.sessionId,authorityVersion:x.personaSession.authorityVersion}})}));
    },
    async begin(raw){const x=snapshot(raw);return transaction(x,async client=>{
      const row=await admission(client,x);if(row)return outcome(client,x,row);
      const count=Number((await client.query(`SELECT count(*) AS n FROM ${T}admissions WHERE ${W}`,values(x))).rows[0]?.n);
      if(!Number.isInteger(count)||count>=128)throw fail('SYSTEM_DIAGNOSTIC_QUOTA_EXCEEDED');
      const pending=Number((await client.query(`SELECT count(*) AS n FROM ${T}admissions a WHERE ${W.split(' AND ').map(v=>'a.'+v).join(' AND ')} AND persona_session_id=$6 AND NOT EXISTS(SELECT 1 FROM ${T}outcomes o WHERE (o.platform_launch_id,o.platform_scenario_id,o.platform_launch_generation,o.original_platform_owner_id,o.original_platform_session_id,o.operation_id)=(a.platform_launch_id,a.platform_scenario_id,a.platform_launch_generation,a.original_platform_owner_id,a.original_platform_session_id,a.operation_id))`,[...values(x),x.personaSession.sessionId])).rows[0]?.n);
      if(!Number.isInteger(pending)||pending>=8)throw fail('SYSTEM_DIAGNOSTIC_QUOTA_EXCEEDED');
      const targetId=randomUUID();
      await client.query(`INSERT INTO ${T}admissions (${C},operation_id,persona_id,persona_session_id,persona_role,authority_version,request_sha256,binding_sha256,request_json,target_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,decode($11,'hex'),decode($12,'hex'),$13::jsonb,$14::uuid)`,[...values(x),x.operationId,x.persona.id,x.personaSession.sessionId,x.persona.role,x.personaSession.authorityVersion,x.digest,bindingDigest(x,x.request,targetId),JSON.stringify(x.request),targetId]);
      return {state:'admitted',operationId:x.operationId,requestSha256:x.digest,targetId};
    },true);},
    complete:raw=>finish(raw,'completed'),markUnknown:raw=>finish(raw,'unknown'),markNotExecuted:raw=>finish(raw,'not_executed'),
    async assertCurrent(raw,expectedTargetId){const x=snapshot(raw);await transaction(x,async client=>{const row=await admission(client,x,true);
      if(!UUID.test(expectedTargetId)||row.target_id!==expectedTargetId)throw fail('OPERATION_CONFLICT');
      if((await outcome(client,x,row)).state!=='pending')throw fail('SYSTEM_DIAGNOSTIC_OPERATION_TERMINAL');
    });},
    async operation(raw){const x=snapshot(raw,false);return transaction(x,async client=>{const row=await admission(client,x);return row?outcome(client,x,row):{state:'not_found',operationId:x.operationId};});},
    async checkReadiness(){
      if((await pool.query('SELECT current_user AS role')).rows[0]?.role!=='dvaia_secureshop_agents_runtime')throw fail('SYSTEM_DIAGNOSTIC_NOT_READY');
      for(const table of ['admissions','outcomes','cleanup_receipts']){
        for(const privilege of ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']){
          const allowed=privilege==='SELECT'||(privilege==='INSERT'&&table!=='cleanup_receipts');
          if((await pool.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',[T+table,privilege])).rows[0]?.allowed!==allowed)throw fail('SYSTEM_DIAGNOSTIC_NOT_READY');
        }
        if((await pool.query("SELECT NOT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid=$1::regclass AND a.grantee=0) AS private",[T+table])).rows[0]?.private!==true)throw fail('SYSTEM_DIAGNOSTIC_NOT_READY');
        const columns=(await pool.query("SELECT attname,has_column_privilege(current_user,attrelid,attnum,'UPDATE') AS writable FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped",[T+table])).rows;
        if(!columns.length||columns.some(r=>r.writable))throw fail('SYSTEM_DIAGNOSTIC_NOT_READY');
      }
      const triggers=[];
      for(const table of ['admissions','outcomes']) {
        triggers.push({rel:T+table,name:`a_system_diagnostic_${table}_insert`,fn:'secureshop_agents.guard_bound_persona_admin_insert()',kind:7},
          {rel:T+table,name:`b_system_diagnostic_${table}_actor`,fn:'secureshop_agents.guard_system_diagnostic_actor()',kind:7},
          {rel:T+table,name:`system_diagnostic_${table}_immutable`,fn:'secureshop_agents.guard_system_diagnostic_record()',kind:27});
      }
      triggers.push({rel:T+'cleanup_receipts',name:'system_diagnostic_cleanup_immutable',fn:'secureshop_agents.guard_bound_audit_owner_deletion_receipt()',kind:27},
        {rel:'secureshop_agents.conversation_generation_retirements',name:'system_diagnostic_retirement',fn:'secureshop_agents.cleanup_system_diagnostic_records()',kind:5},
        {rel:'secureshop_agents.bound_audit_owner_deletion_receipts',name:'system_diagnostic_owner_delete',fn:'secureshop_agents.cleanup_system_diagnostic_records()',kind:5});
      const integrity=(await pool.query(`SELECT count(*)=9 AS ready FROM jsonb_to_recordset($1::jsonb) AS e(rel text,name text,fn text,kind integer) JOIN pg_trigger t ON t.tgrelid=to_regclass(e.rel) AND t.tgname=e.name AND t.tgfoid=to_regprocedure(e.fn) AND t.tgtype=e.kind AND t.tgenabled='O' AND t.tgqual IS NULL AND NOT t.tgisinternal`,[JSON.stringify(triggers)])).rows[0];
      if(integrity?.ready!==true)throw fail('SYSTEM_DIAGNOSTIC_NOT_READY');
      const functions=(await pool.query(`SELECT count(*)=3 AND bool_and(p.prosecdef AND (p.proname<>'guard_system_diagnostic_record' OR encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='89ee79304a55f5d70519b102a46adf560c1fb280392275b054b647d4c1a72468') AND (p.proname<>'guard_system_diagnostic_actor' OR encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='b41bc7aebd47ded4e66e5f09cc0128e2c855e1cbd241fcd3582bb7d5c94ac491') AND p.proconfig=CASE WHEN p.proname='cleanup_system_diagnostic_records' THEN ARRAY['search_path=pg_catalog']::text[] ELSE ARRAY['search_path=pg_catalog, secureshop_agents']::text[] END AND NOT has_function_privilege(current_user,p.oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) AS ready FROM pg_proc p WHERE p.oid IN(to_regprocedure('secureshop_agents.guard_system_diagnostic_record()'),to_regprocedure('secureshop_agents.guard_system_diagnostic_actor()'),to_regprocedure('secureshop_agents.cleanup_system_diagnostic_records()'))`)).rows[0];
      if(functions?.ready!==true)throw fail('SYSTEM_DIAGNOSTIC_NOT_READY');
      const scoped=['platform_launch_generation > 0','original_platform_owner_id > 0','original_platform_session_id > 0','persona_id > 0',"persona_role = 'admin'::text",'authority_version > 0','octet_length(request_sha256) = 32','octet_length(binding_sha256) = 32'];
      const checks={
        admissions:[...scoped,"request_json IS NULL OR jsonb_typeof(request_json) = 'object'::text AND octet_length(request_json::text) <= 131072"],
        outcomes:[...scoped,"state = ANY (ARRAY['completed'::text, 'unknown'::text, 'not_executed'::text])","receipt_json IS NULL OR jsonb_typeof(receipt_json) = 'object'::text AND octet_length(receipt_json::text) <= 524288",'receipt_sha256 IS NULL OR octet_length(receipt_sha256) = 32',"state = ANY (ARRAY['unknown'::text, 'not_executed'::text]) AND receipt_json IS NULL AND receipt_sha256 IS NULL OR state = 'completed'::text AND receipt_sha256 IS NOT NULL"],
        cleanup_receipts:["cleanup_kind = ANY (ARRAY['retirement'::text, 'owner_deletion'::text])",'octet_length(receipt_sha256) = 32']
      };
      const normalize=expression=>expression.replace(/'([0-9]+)'::(?:bigint|integer)/g,'$1').replace(/::(?:text|bigint|integer)/g,'').replace(/[()\s]/g,'');
      for(const [table,expected] of Object.entries(checks)) {
        const rows=(await pool.query("SELECT pg_get_expr(conbin,conrelid) AS expression,convalidated AND conenforced AS ready FROM pg_constraint WHERE conrelid=$1::regclass AND contype='c'",[T+table])).rows;
        const actual=rows.map(row=>normalize(row.expression)).sort();
        if(rows.some(row=>row.ready!==true)||JSON.stringify(actual)!==JSON.stringify(expected.map(normalize).sort())) {
          const error=fail('SYSTEM_DIAGNOSTIC_NOT_READY');Object.defineProperty(error,'schemaDiagnostic',{value:{table,actual,expected:expected.map(normalize).sort()}});throw error;
        }
      }
      const scopeKey=C.split(',').concat('operation_id');
      for(const table of ['admissions','outcomes','cleanup_receipts']) {
        const required=table==='cleanup_receipts'?['cleanup_id','cleanup_kind','original_platform_owner_id','admission_count','outcome_count','receipt_sha256']:
          [...scopeKey,'persona_id','persona_session_id','persona_role','authority_version','request_sha256','binding_sha256',...(table==='outcomes'?['state']:[])];
        const nonnull=(await pool.query("SELECT attname FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped AND attnotnull",[T+table])).rows.map(row=>row.attname).sort();
        if(JSON.stringify(nonnull)!==JSON.stringify(required.sort()))throw fail('SYSTEM_DIAGNOSTIC_NOT_READY');
        const keys=(await pool.query("SELECT contype,convalidated AND conenforced AS ready,confrelid::regclass::text AS target,ARRAY(SELECT attname::text FROM unnest(conkey) WITH ORDINALITY k(n,ord) JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n ORDER BY ord) AS columns,ARRAY(SELECT attname::text FROM unnest(confkey) WITH ORDINALITY k(n,ord) JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.n ORDER BY ord) AS target_columns,confdeltype,confupdtype FROM pg_constraint c WHERE conrelid=$1::regclass AND contype IN ('p','f','u')",[T+table])).rows;
        const primary=keys.filter(row=>row.contype==='p');
        if(primary.length!==1||primary[0].ready!==true||JSON.stringify(primary[0].columns)!==JSON.stringify(table==='cleanup_receipts'?['cleanup_id']:scopeKey)){const error=fail('SYSTEM_DIAGNOSTIC_NOT_READY');Object.defineProperty(error,'schemaDiagnostic',{value:{table,keys,expectedPrimary:table==='cleanup_receipts'?['cleanup_id']:scopeKey}});throw error;}
        const unique=keys.filter(row=>row.contype==='u');
        if(table==='admissions' ? unique.length!==1||unique[0].ready!==true||JSON.stringify(unique[0].columns)!==JSON.stringify(['target_id']) : unique.length!==0)throw fail('SYSTEM_DIAGNOSTIC_NOT_READY');
        const foreign=keys.filter(row=>row.contype==='f');
        if(table==='outcomes') {
          if(foreign.length!==1||foreign[0].ready!==true||foreign[0].target!==T+'admissions'||JSON.stringify(foreign[0].columns)!==JSON.stringify(scopeKey)||JSON.stringify(foreign[0].target_columns)!==JSON.stringify(scopeKey)||foreign[0].confdeltype!=='a'||foreign[0].confupdtype!=='a')throw fail('SYSTEM_DIAGNOSTIC_NOT_READY');
        }else if(foreign.length)throw fail('SYSTEM_DIAGNOSTIC_NOT_READY');
      }
      return {ready:true,candidate:true};
    },
  });
}
module.exports={createSystemDiagnosticRepository};
