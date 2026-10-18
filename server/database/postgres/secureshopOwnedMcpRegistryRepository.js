'use strict';

// Candidate general registry. It never shares rows with the two bound MCP
// trust scenarios and is not mounted until migration/readiness qualification.
const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { mcpSchemaDigest } = require('../../services/secureshopMcpSchemaDigest');
const { canonicalDigest } = require('../../services/mcp/protocolContext');
const { normalizeRegistryRequest, registryRequestDigest } = require('../../services/secureshopMcpRegistryContract');
const { createLaunchScope, createConversationBinding } = require('../../services/secureshopConversationBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const C = ['platform_launch_id','platform_scenario_id','platform_launch_generation','original_platform_owner_id','original_platform_session_id'];
const W = C.map((name,index)=>`${name}=$${index+1}`).join(' AND ');
function failure(code, message='Owned MCP registry unavailable') { return Object.assign(new Error(message), { code }); }
function positive(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value) || BigInt(value)>9223372036854775807n) throw failure('SHOP_AUTH_INVALID');
  return value;
}
function scopeValues(scope) { return [scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId]; }
function snapshot(raw, requireRequest=true) {
  const copied=structuredClone(raw), scope=createLaunchScope(copied.scope), binding=createConversationBinding(scope,copied.persona);
  if(binding.role!=='admin' || !UUID.test(copied.personaSession?.sessionId)) throw failure('ADMIN_REQUIRED');
  const personaSession=Object.freeze({sessionId:copied.personaSession.sessionId.toLowerCase(),authorityVersion:positive(copied.personaSession.authorityVersion)});
  const request=requireRequest?normalizeRegistryRequest(copied.request):undefined;
  const operationId=(requireRequest?request.operationId:copied.operationId)?.toLowerCase();
  if(!UUID.test(operationId||''))throw failure('INVALID_ARGUMENT');
  const requestSha256=requireRequest?registryRequestDigest(request):undefined;
  return Object.freeze({scope,persona:Object.freeze({id:binding.shopUserId,role:binding.role}),personaSession,operationId,request,requestSha256});
}
function withMode(x,mode){if(!['vuln','fixed'].includes(mode))throw failure('MCP_REGISTRY_MODE_UNAVAILABLE');return Object.freeze({...x,mode,bindingSha256:canonicalDigest(['owned-mcp-registry-binding-v1',x.scope,x.persona,x.personaSession,mode,x.requestSha256])});}
function sameFence(fence,x){const expected={...x.scope,personaId:x.persona.id,role:x.persona.role,sessionId:x.personaSession.sessionId,authorityVersion:x.personaSession.authorityVersion};return fence?.binding&&Object.keys(expected).every(k=>fence.binding[k]===expected[k]);}
function publicOperation(row,replayed=false){
  if(!row)throw failure('MCP_REGISTRY_OPERATION_NOT_FOUND');
  if(row.state==='completed')return Object.freeze({...row.receipt_json,replayed});
  return Object.freeze({version:'secureshop-owned-mcp-registry.v1',operationId:row.operation_id,state:row.state,action:row.action,requestSha256:row.request_sha256.toString('hex'),replayed});
}
function verifyStored(row,x,fullRequest=false){
  if(!row||Number(row.persona_id)!==x.persona.id||row.persona_session_id!==x.personaSession.sessionId
    ||String(row.authority_version)!==x.personaSession.authorityVersion)throw failure('MCP_REGISTRY_OPERATION_NOT_FOUND');
  if(fullRequest&&(row.request_sha256.toString('hex')!==x.requestSha256||row.binding_sha256.toString('hex')!==x.bindingSha256
    ||row.mode!==x.mode||row.action!==x.request.action||String(row.expected_version)!==x.request.expectedVersion))throw failure('MCP_REGISTRY_OPERATION_CONFLICT');
  if(row.state==='completed'&&(!row.receipt_json||canonicalDigest(row.receipt_json)!==row.receipt_sha256?.toString('hex')))throw failure('MCP_REGISTRY_INTEGRITY_UNAVAILABLE');
  return row;
}
async function assertOwnedMcpRegistryReady({pool,expectedDatabase}={}){
 if(typeof pool?.query!=='function'||typeof expectedDatabase!=='string'||!expectedDatabase)throw new TypeError('Owned MCP registry readiness dependencies required');
 const tables=['heads','entries','revisions','operations','cleanup_receipts'].map(suffix=>`secureshop_agents.bound_mcp_registry_${suffix}`);
 const signatures=[
  'secureshop_agents.admit_owned_mcp_registry_operation(uuid,uuid,bigint,integer,integer,uuid,integer,uuid,bigint,text,text,bigint,bytea,bytea,uuid,jsonb)',
  'secureshop_agents.publish_owned_mcp_registry_operation(uuid,uuid,bigint,integer,integer,uuid,uuid,bytea,bytea,jsonb,bytea,jsonb,uuid)',
  'secureshop_agents.finish_owned_mcp_registry_operation(uuid,uuid,bigint,integer,integer,uuid,uuid,bytea,bytea,text,uuid)'];
 const result=await pool.query(`SELECT current_database() AS database,
   (SELECT bool_and(to_regclass(name) IS NOT NULL) FROM unnest($1::text[]) name) AS tables_present,
   (SELECT bool_and(COALESCE(has_table_privilege(current_user,to_regclass(name),'SELECT'),false) AND NOT COALESCE(has_table_privilege(current_user,to_regclass(name),'INSERT,UPDATE,DELETE,TRUNCATE'),true)) FROM unnest($1::text[]) name) AS table_grants,
   (SELECT bool_and(to_regprocedure(name) IS NOT NULL AND has_function_privilege(current_user,to_regprocedure(name),'EXECUTE')) FROM unnest($2::text[]) name) AS function_grants,
   NOT has_function_privilege(current_user,to_regprocedure('secureshop_agents.cleanup_owned_mcp_registry()'),'EXECUTE') AS cleanup_denied,
   NOT has_function_privilege(current_user,to_regprocedure('secureshop_agents.guard_owned_mcp_registry_immutable()'),'EXECUTE') AS guard_denied,
   NOT has_function_privilege(current_user,to_regprocedure('secureshop_agents.assert_owned_mcp_registry_actor_current(uuid,uuid,bigint,integer,integer,integer,uuid,bigint)'),'EXECUTE') AS actor_guard_denied,
   (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='44cf5ddef28eb09243ba53f8472eb89b15100c2c37b6754cee1d7d7b87fd0083' AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, secureshop_agents']::text[] FROM pg_proc p WHERE p.oid=to_regprocedure('secureshop_agents.assert_owned_mcp_registry_actor_current(uuid,uuid,bigint,integer,integer,integer,uuid,bigint)')) AS actor_guard_current,
   (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='4d18968964b74e9574e3476f37f91722938cef0cc1f485778c3aa088f2607345' AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, secureshop_agents']::text[] FROM pg_proc p WHERE p.oid=to_regprocedure('secureshop_agents.admit_owned_mcp_registry_operation(uuid,uuid,bigint,integer,integer,uuid,integer,uuid,bigint,text,text,bigint,bytea,bytea,uuid,jsonb)')) AS admission_guard_current,
   NOT has_function_privilege(current_user,to_regprocedure('secureshop_agents.owned_mcp_registry_request_digest(jsonb)'),'EXECUTE') AS request_digest_denied,
   (SELECT count(*)=4 AND bool_and(t.tgenabled IN ('O','A')) AND bool_and(CASE t.tgname
      WHEN 'bound_mcp_registry_revisions_immutable' THEN t.tgrelid='secureshop_agents.bound_mcp_registry_revisions'::regclass AND t.tgfoid=to_regprocedure('secureshop_agents.guard_owned_mcp_registry_immutable()')
      WHEN 'bound_mcp_registry_cleanup_immutable' THEN t.tgrelid='secureshop_agents.bound_mcp_registry_cleanup_receipts'::regclass AND t.tgfoid=to_regprocedure('secureshop_agents.guard_owned_mcp_registry_immutable()')
      WHEN 'owned_mcp_registry_retirement' THEN t.tgrelid='secureshop_agents.conversation_generation_retirements'::regclass AND t.tgfoid=to_regprocedure('secureshop_agents.cleanup_owned_mcp_registry()')
      WHEN 'owned_mcp_registry_owner_delete' THEN t.tgrelid='secureshop_agents.bound_audit_owner_deletion_receipts'::regclass AND t.tgfoid=to_regprocedure('secureshop_agents.cleanup_owned_mcp_registry()')
      ELSE false END)
    FROM pg_catalog.pg_trigger t
    WHERE NOT t.tgisinternal AND t.tgname IN ('bound_mcp_registry_revisions_immutable','bound_mcp_registry_cleanup_immutable','owned_mcp_registry_retirement','owned_mcp_registry_owner_delete')) AS triggers_ready`,[tables,signatures]);
 const row=result.rows[0];if(row?.database!==expectedDatabase||!row.tables_present||!row.table_grants||!row.function_grants||!row.cleanup_denied||!row.guard_denied||!row.actor_guard_denied||!row.actor_guard_current||!row.admission_guard_current||!row.request_digest_denied||!row.triggers_ready)throw failure('MCP_REGISTRY_NOT_READY');
 return Object.freeze({ready:true,database:row.database});
}
function createOwnedMcpRegistryRepository({pool,personaAuthority,makeId=crypto.randomUUID}={}){
  if(typeof pool?.query!=='function'||typeof personaAuthority?.capture!=='function'||typeof makeId!=='function')throw new TypeError('Owned MCP registry repository dependencies required');
  function capture(x){const fence=personaAuthority.capture({scope:x.scope,personaId:x.persona.id,role:x.persona.role,sessionId:x.personaSession.sessionId,authorityVersion:x.personaSession.authorityVersion});if(!sameFence(fence,x)||typeof fence.withPersonaEffect!=='function'||typeof fence.assertRemoteAdmission!=='function')throw failure('SHOP_AUTH_INVALID');return fence;}
  async function beginPrepared(prepared,{mode}={}){
    const x=withMode(prepared,mode),fence=capture(x),workerToken=makeId().toLowerCase();if(!UUID.test(workerToken))throw failure('MCP_REGISTRY_INTEGRITY_UNAVAILABLE');
    const rows=await fence.withPersonaEffect(async client=>{
      await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");
      try {
        return (await client.query(`SELECT * FROM secureshop_agents.admit_owned_mcp_registry_operation($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,decode($13,'hex'),decode($14,'hex'),$15,$16::jsonb)`,
          [...scopeValues(x.scope),x.operationId,x.persona.id,x.personaSession.sessionId,x.personaSession.authorityVersion,x.mode,x.request.action,x.request.expectedVersion,x.requestSha256,x.bindingSha256,workerToken,JSON.stringify(x.request)])).rows;
      } catch (error) {
        // Only the admission function's exact conflict diagnoses mean HTTP 409.
        // Authority, quota, integrity and database failures remain unavailable.
        if (error?.code === '55000' && ['Owned MCP operation conflict', 'Owned MCP registry version conflict'].includes(error.message)) {
          throw failure('MCP_REGISTRY_OPERATION_CONFLICT', 'Owned MCP registry conflict');
        }
        throw error;
      }
    });
    if(rows.length!==1)throw failure('MCP_REGISTRY_INTEGRITY_UNAVAILABLE');const row=verifyStored(rows[0],x,true);
    return Object.freeze({prepared:x,fence,workerToken:row.worker_token,newlyAdmitted:row.worker_token===workerToken&&row.state==='admitted',operation:publicOperation(row,row.worker_token!==workerToken)});
  }
  function changes(value){
    if(!Array.isArray(value)||value.length<1||value.length>32)throw failure('MCP_REGISTRY_EXECUTOR_INVALID');
    const names=new Set();return Object.freeze(value.map(raw=>{
      if(!raw||typeof raw!=='object'||Array.isArray(raw)||!['register','import','retire'].includes(raw.action)||typeof raw.name!=='string'||names.has(raw.name)||!UUID.test(raw.entryId||'')||!raw.effect||typeof raw.effect!=='object'||Array.isArray(raw.effect))throw failure('MCP_REGISTRY_EXECUTOR_INVALID');
      names.add(raw.name);if(raw.action==='retire')return Object.freeze({name:raw.name,entryId:raw.entryId.toLowerCase(),action:'retire',transport:null,endpoint:null,schemaSha256:null,tools:null,effect:structuredClone(raw.effect)});
      if(!['sse','streamable-http','stdio'].includes(raw.transport)||typeof raw.endpoint!=='string'||!raw.endpoint||!Array.isArray(raw.tools)||!/^[0-9a-f]{64}$/.test(raw.schemaSha256||''))throw failure('MCP_REGISTRY_EXECUTOR_INVALID');
      return Object.freeze({name:raw.name,entryId:raw.entryId.toLowerCase(),action:raw.action,transport:raw.transport,endpoint:raw.endpoint,schemaSha256:raw.schemaSha256,tools:structuredClone(raw.tools),effect:structuredClone(raw.effect)});
    }));
  }
  async function publish(admission,executorChanges){
    const {prepared:x,fence,workerToken}=admission||{};if(!x||!sameFence(fence,x)||!UUID.test(workerToken||''))throw failure('SHOP_AUTH_INVALID');
    let normalized=changes(executorChanges);const request=x.request;
    if(normalized.some(change=>change.action!==request.action)
      ||(request.action!=='import'&&(normalized.length!==1||normalized[0].name!==request.name))
      ||(request.action==='register'&&(normalized[0].transport!==request.transport||normalized[0].endpoint!==(request.transport==='stdio'?request.stdio_cmd:request.url))))throw failure('MCP_REGISTRY_EXECUTOR_INVALID');
    // Retired entries retain their stable identity and fixed-mode pins. They
    // are deliberately absent from the executor's active tool snapshot.
    if(request.action!=='retire'){
      const retired=await fence.withPersonaEffect(async client=>(await client.query(`SELECT name,entry_id::text AS entry_id,transport,endpoint_text,encode(schema_sha256,'hex') AS schema_sha256 FROM secureshop_agents.bound_mcp_registry_entries WHERE ${W} AND lifecycle='retired' AND name=ANY($6::text[])`,[...scopeValues(x.scope),normalized.map(change=>change.name)])).rows);
      const priorByName=new Map(retired.map(row=>[row.name,row]));
      normalized=Object.freeze(normalized.map(change=>{
        const prior=priorByName.get(change.name);if(!prior)return change;
        if(x.mode==='fixed'&&(prior.transport!==change.transport||prior.endpoint_text!==change.endpoint||prior.schema_sha256!==change.schemaSha256))throw failure('MCP_REGISTRY_FIXED_IDENTITY_DENIED');
        return Object.freeze({...change,entryId:prior.entry_id});
      }));
    }
    const registryVersion=(BigInt(request.expectedVersion)+1n).toString();
    const receipt=Object.freeze({version:'secureshop-owned-mcp-registry.v1',operationId:x.operationId,state:'completed',action:x.request.action,requestSha256:x.requestSha256,registryVersion,
      changes:Object.freeze(normalized.map(v=>Object.freeze({name:v.name,entryId:v.entryId,action:v.action,schemaSha256:v.schemaSha256,effect:v.effect})))});
    const receiptSha256=canonicalDigest(receipt),auditId=makeId().toLowerCase();if(!UUID.test(auditId))throw failure('MCP_REGISTRY_INTEGRITY_UNAVAILABLE');
    let committed=false;
    try{
      const rows=await fence.withPersonaEffect(async client=>{await client.query("SET LOCAL statement_timeout='3000ms'");await client.query("SET LOCAL lock_timeout='3000ms'");const result=await client.query(`SELECT * FROM secureshop_agents.publish_owned_mcp_registry_operation($1,$2,$3,$4,$5,$6,$7,decode($8,'hex'),decode($9,'hex'),$10::jsonb,decode($11,'hex'),$12::jsonb,$13)`,[...scopeValues(x.scope),x.operationId,workerToken,x.requestSha256,x.bindingSha256,JSON.stringify(receipt),receiptSha256,JSON.stringify(normalized),auditId]);committed=true;return result.rows;});
      if(rows.length!==1)throw failure('MCP_REGISTRY_INTEGRITY_UNAVAILABLE');await fence.assertRemoteAdmission();return publicOperation(verifyStored(rows[0],x,true));
    }catch(cause){if(committed){const error=failure('MCP_REGISTRY_OUTCOME_UNCERTAIN');Object.defineProperty(error,'cause',{value:cause});error.executionBoundary=true;throw error;}throw cause;}
  }
  async function activeEntries(admission){
    const {prepared:x,fence}=admission||{};if(!x||!sameFence(fence,x))throw failure('SHOP_AUTH_INVALID');
    return fence.withPersonaEffect(async client=>Object.freeze((await client.query(`SELECT name,entry_id::text AS entry_id,transport,endpoint_text,encode(schema_sha256,'hex') AS schema_sha256 FROM secureshop_agents.bound_mcp_registry_entries WHERE ${W} AND lifecycle='active' ORDER BY name`,scopeValues(x.scope))).rows.map(row=>Object.freeze({name:row.name,entryId:row.entry_id,transport:row.transport,endpoint:row.endpoint_text,schemaSha256:row.schema_sha256}))));
  }
  async function finish(admission,state){
    const {prepared:x,fence,workerToken}=admission||{};if(!x||!sameFence(fence,x)||!['failed','unknown'].includes(state))throw failure('INVALID_ARGUMENT');
    const auditId=makeId().toLowerCase();const rows=await fence.withPersonaEffect(async client=>(await client.query(`SELECT * FROM secureshop_agents.finish_owned_mcp_registry_operation($1,$2,$3,$4,$5,$6,$7,decode($8,'hex'),decode($9,'hex'),$10,$11)`,[...scopeValues(x.scope),x.operationId,workerToken,x.requestSha256,x.bindingSha256,state,auditId])).rows);
    if(rows.length!==1)throw failure('MCP_REGISTRY_INTEGRITY_UNAVAILABLE');return publicOperation(verifyStored(rows[0],x,true));
  }
  async function read(raw){
    const x=snapshot(raw,false),fence=capture(x);return fence.withPersonaEffect(async client=>{const row=(await client.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_operations WHERE ${W} AND operation_id=$6`,[...scopeValues(x.scope),x.operationId])).rows[0];return publicOperation(verifyStored(row,x),true);});
  }
  async function readAssessmentManifest(raw){
    const copied=structuredClone(raw),refs=copied.entries;
    const missing=()=>{throw failure('MCP_REGISTRY_OPERATION_NOT_FOUND');};
    if(!Array.isArray(refs)||refs.length<1||refs.length>32||new Set(refs.map(x=>x?.entryId)).size!==refs.length)missing();
    for(const ref of refs)if(!ref||Object.keys(ref).sort().join(',')!=='entryId,registryVersion,schemaSha256'
      ||!UUID.test(ref.entryId||'')||typeof ref.registryVersion!=='string'||!(/^[1-9][0-9]*$/).test(ref.registryVersion)
      ||BigInt(ref.registryVersion)>9223372036854775807n||!(/^[a-f0-9]{64}$/).test(ref.schemaSha256||''))missing();
    const x=snapshot({...copied,operationId:refs[0].entryId},false),fence=capture(x);
    const result=await fence.withPersonaEffect(async client=>{
      const values=[];
      for(const ref of refs){
        const revisions=(await client.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_revisions
          WHERE ${W} AND entry_id=$6 AND registry_version=$7::bigint AND schema_sha256=decode($8,'hex')
          AND redacted_at IS NULL AND action IN ('register','import')`,[...scopeValues(x.scope),ref.entryId,ref.registryVersion,ref.schemaSha256])).rows;
        if(revisions.length!==1)missing();const revision=revisions[0];
        const operations=(await client.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_operations
          WHERE ${W} AND operation_id=$6 AND redacted_at IS NULL`,[...scopeValues(x.scope),revision.operation_id])).rows;
        if(operations.length!==1)missing();const operation=verifyStored(operations[0],x);
        if(operation.state!=='completed'||operation.action!==revision.action)missing();
        values.push({revision,operation});
      }
      return values;
    });await fence.assertRemoteAdmission();return structuredClone(result);
  }
  async function readAssessmentRevisions(raw){
    const copied=structuredClone(raw),entryId=copied?.entryId,version=copied?.registryVersion;
    if(typeof entryId!=='string'||!UUID.test(entryId)||typeof version!=='string'
      ||!(/^[1-9][0-9]*$/).test(version)||BigInt(version)<2n||BigInt(version)>9007199254740991n)
      throw failure('MCP_REGISTRY_OPERATION_NOT_FOUND');
    const x=snapshot({...copied,operationId:entryId},false),fence=capture(x);
    const prior=(BigInt(version)-1n).toString();
    const result=await fence.withPersonaEffect(async client=>{
      const revisions=(await client.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_revisions
        WHERE ${W} AND entry_id=$6 AND registry_version IN ($7::bigint,$8::bigint)
          AND redacted_at IS NULL ORDER BY registry_version`,
      [...scopeValues(x.scope),entryId.toLowerCase(),prior,version])).rows;
      if(revisions.length!==2||String(revisions[0].registry_version)!==prior
        ||String(revisions[1].registry_version)!==version
        ||revisions[0].entry_id!==revisions[1].entry_id||revisions[0].name!==revisions[1].name
        ||revisions[0].action!=='register'||revisions[1].action!=='register')
        throw failure('MCP_REGISTRY_OPERATION_NOT_FOUND');
      const operations=(await client.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_operations
        WHERE ${W} AND operation_id=ANY($6::uuid[]) AND redacted_at IS NULL`,
      [...scopeValues(x.scope),revisions.map(row=>row.operation_id)])).rows;
      if(operations.length!==2||new Set(operations.map(row=>row.operation_id)).size!==2)
        throw failure('MCP_REGISTRY_OPERATION_NOT_FOUND');
      const byId=new Map(operations.map(row=>[row.operation_id,row]));
      for(const row of revisions){
        const operation=byId.get(row.operation_id);
        if(!operation||operation.state!=='completed'||operation.action!=='register'
          ||operation.persona_id!==x.persona.id||operation.persona_session_id!==x.personaSession.sessionId
          ||String(operation.authority_version)!==x.personaSession.authorityVersion)
          throw failure('MCP_REGISTRY_OPERATION_NOT_FOUND');
      }
      return {trusted:{revision:revisions[0],operation:byId.get(revisions[0].operation_id)},
        replacement:{revision:revisions[1],operation:byId.get(revisions[1].operation_id)}};
    });
    await fence.assertRemoteAdmission();
    return structuredClone(result);
  }
  async function readAssessmentPublication(raw,action){
    // Closed public wrappers choose the action. Original immutable publication
    // reads never depend on the current registry head or replacement pair.
    const x=snapshot(raw,false),fence=capture(x);
    const missing=()=>{throw failure('MCP_REGISTRY_OPERATION_NOT_FOUND');};
    const hex=value=>Buffer.isBuffer(value)&&value.length===32?value.toString('hex'):null;
    const scoped=row=>row&&C.every((key,index)=>String(row[key])===String(scopeValues(x.scope)[index]));
    const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
      &&isDeepStrictEqual(Object.keys(value).sort(),[...keys].sort());
    const result=await fence.withPersonaEffect(async client=>{
      const operations=(await client.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_operations
        WHERE ${W} AND operation_id=$6 AND redacted_at IS NULL LIMIT 2`,
      [...scopeValues(x.scope),x.operationId])).rows;
      if(operations.length!==1)missing();
      const operation=verifyStored(operations[0],x);
      if(!scoped(operation)||operation.operation_id!==x.operationId||operation.redacted_at!==null
        ||operation.persona_role!=='admin'||operation.state!=='completed'||operation.action!==action
        ||!['fixed','vuln'].includes(operation.mode))missing();
      let request;
      try{request=normalizeRegistryRequest(operation.request_json);}catch{missing();}
      if(request.action!==action||request.operationId!==x.operationId
        ||request.expectedVersion!==String(operation.expected_version)
        ||BigInt(request.expectedVersion)>9007199254740990n)missing();
      const requestSha256=registryRequestDigest(request);
      const bindingSha256=withMode({...x,request,requestSha256},operation.mode).bindingSha256;
      if(hex(operation.request_sha256)!==requestSha256||hex(operation.binding_sha256)!==bindingSha256)missing();
      const receipt=operation.receipt_json,version=String(BigInt(request.expectedVersion)+1n);
      if(!exact(receipt,['version','operationId','state','action','requestSha256','registryVersion','changes'])
        ||receipt.version!=='secureshop-owned-mcp-registry.v1'||receipt.operationId!==x.operationId
        ||receipt.state!=='completed'||receipt.action!==action||receipt.requestSha256!==requestSha256
        ||receipt.registryVersion!==version||!Array.isArray(receipt.changes)
        ||receipt.changes.length<1||receipt.changes.length>32)missing();
      if(action==='register'&&receipt.changes.length!==1)missing();
      const byName=new Map(),entries=new Set();
      for(const change of receipt.changes){
        if(!exact(change,['name','entryId','action','schemaSha256','effect'])
          ||typeof change.name!=='string'||!change.name.trim()||Buffer.byteLength(change.name)>256
          ||byName.has(change.name)||!UUID.test(change.entryId||'')||entries.has(change.entryId)
          ||change.action!==action||!/^[0-9a-f]{64}$/.test(change.schemaSha256||'')
          ||!change.effect||typeof change.effect!=='object'||Array.isArray(change.effect))missing();
        byName.set(change.name,change);entries.add(change.entryId);
      }
      const revisions=(await client.query(`SELECT * FROM secureshop_agents.bound_mcp_registry_revisions
        WHERE ${W} AND operation_id=$6 AND redacted_at IS NULL ORDER BY name LIMIT 33`,
      [...scopeValues(x.scope),x.operationId])).rows;
      if(revisions.length!==byName.size)missing();
      const seen=new Set();
      for(const revision of revisions){
        const change=byName.get(revision.name);
        if(!change||seen.has(revision.name)||!scoped(revision)||revision.redacted_at!==null
          ||revision.operation_id!==x.operationId||revision.action!==action
          ||String(revision.registry_version)!==version||revision.entry_id!==change.entryId
          ||hex(revision.schema_sha256)!==change.schemaSha256||!Array.isArray(revision.tools_json)
          ||mcpSchemaDigest(revision.tools_json)!==change.schemaSha256
          ||!['sse','streamable-http','stdio'].includes(revision.transport)
          ||typeof revision.endpoint_text!=='string'||!revision.endpoint_text
          ||!isDeepStrictEqual(revision.effect_json,{...change.effect,requestSha256,bindingSha256}))missing();
        if(action==='register'&&(revision.name!==request.name||revision.transport!==request.transport
          ||revision.endpoint_text!==(request.transport==='stdio'?request.stdio_cmd:request.url)))missing();
        seen.add(revision.name);
      }
      return {operation,revisions};
    });
    await fence.assertRemoteAdmission();
    return structuredClone(result);
  }
  const readAssessmentImport=raw=>readAssessmentPublication(raw,'import');
  const readAssessmentRegistration=raw=>readAssessmentPublication(raw,'register');
  return Object.freeze({beginPrepared,activeEntries,publish,finish,read,readAssessmentRevisions,readAssessmentImport,readAssessmentRegistration,readAssessmentManifest,prepare:raw=>snapshot(raw)});
}
module.exports={createOwnedMcpRegistryRepository,assertOwnedMcpRegistryReady};
