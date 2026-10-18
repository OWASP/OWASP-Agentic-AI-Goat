'use strict';

const { randomUUID } = require('node:crypto');
const { canonicalDurableGeneration } = require('../../agent-runtime/durableGeneration');
const { normalizeXssProfileRetirementOutcome } = require('./xssProfileResetJournalRepository');

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CODE=/^[A-Z][A-Z0-9_]{0,63}$/;
const TOP=new Set(['operationId','ownerId']);
const CLEAR=new Set(['operationId','ownerId','profileRevisions','progressRemoved','originsRemoved','appliedAt','replayed']);
function failure(code,message=code){return Object.assign(new Error(message),{code});}
function exact(value,keys,message){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!keys.has(k))||[...keys].some(k=>!(k in value)))throw new TypeError(message);return value;}
function id(value,label='Operation ID'){if(typeof value!=='string'||!UUID.test(value))throw new TypeError(`${label} is invalid`);return value.toLowerCase();}
function owner(value){if(!Number.isSafeInteger(value)||value<1||value>2147483647)throw new TypeError('Authenticated XSS owner is required');return value;}
function gen(value,label){try{return canonicalDurableGeneration(value);}catch{throw new TypeError(`${label} must be a nonnegative int64 generation`);}}
function count(value,label){if(!Number.isSafeInteger(value)||value<0||value>2147483647)throw new TypeError(`${label} is invalid`);return value;}
function revision(value,label){const result=gen(value,label);if(result==='0')throw new TypeError(`${label} must be positive`);return result;}
function beginInput(value){exact(value,TOP,'Exact XSS parent reset coordinates are required');return {operationId:id(value.operationId),ownerId:owner(value.ownerId)};}
function normalizeChild(value){
  return normalizeXssProfileRetirementOutcome(value);
}
function normalizeClear(value){
  exact(value,CLEAR,'Exact XSS clear receipt required');
  exact(value.profileRevisions,new Set(['name','bio','website']),'Exact XSS profile revisions required');
  const appliedAt=value.appliedAt instanceof Date?value.appliedAt.toISOString():value.appliedAt;
  if(typeof appliedAt!=='string'||Buffer.byteLength(appliedAt)<10||Buffer.byteLength(appliedAt)>64||!Number.isFinite(Date.parse(appliedAt)))throw new TypeError('XSS clear applied time is invalid');
  if(typeof value.replayed!=='boolean')throw new TypeError('XSS clear replay flag is invalid');
  return Object.freeze({operationId:id(value.operationId),ownerId:owner(value.ownerId),profileRevisions:Object.freeze({
    name:revision(value.profileRevisions.name,'Name revision'),bio:revision(value.profileRevisions.bio,'Bio revision'),website:revision(value.profileRevisions.website,'Website revision')}),
    progressRemoved:count(value.progressRemoved,'Progress count'),originsRemoved:count(value.originsRemoved,'Origin count'),appliedAt,replayed:value.replayed});
}
const PROJECTION=`operation_id AS "operationId",owner_id AS "ownerId",owner_key AS "ownerKey",
 workshop_generation_from::text AS "workshopGenerationFrom",workshop_generation_to::text AS "workshopGenerationTo",
 child_operation_id AS "childOperationId",child_outcome_sha256 AS "childOutcomeDigest",clear_receipt_sha256 AS "clearReceiptDigest",
 graph_generation::text AS "graphGeneration",status,lease_token AS "leaseToken",lease_expires_at AS "leaseExpiresAt",
 failure_code AS "failureCode",created_at AS "createdAt",updated_at AS "updatedAt",completed_at AS "completedAt"`;
function dto(row){if(!row)return null;return Object.freeze({version:1,kind:'xss_admin_whole_parent_reset',operationId:id(row.operationId),ownerId:owner(Number(row.ownerId)),ownerKey:row.ownerKey,
  workshopGenerationFrom:gen(row.workshopGenerationFrom,'Stored workshop generation'),workshopGenerationTo:row.workshopGenerationTo==null?null:gen(row.workshopGenerationTo,'Stored workshop generation'),
  graphGeneration:row.graphGeneration==null?null:gen(row.graphGeneration,'Stored graph generation'),childOperationId:row.childOperationId? id(row.childOperationId,'Child operation ID'):null,
  childOutcomeDigest:row.childOutcomeDigest||null,clearReceiptDigest:row.clearReceiptDigest||null,status:row.status,
  lease:row.leaseToken?Object.freeze({token:id(row.leaseToken,'Lease token'),expiresAt:row.leaseExpiresAt}):null,
  failureCode:row.failureCode||null,createdAt:row.createdAt,updatedAt:row.updatedAt,completedAt:row.completedAt||null});}
function translate(error,stale=false){if(error?.code==='22023')throw failure('XSS_PARENT_RESET_CONFLICT','XSS parent reset coordinates do not match');if(['55000','23505','23514'].includes(error?.code))throw failure(stale?'XSS_PARENT_RESET_STALE':'XSS_PARENT_RESET_UNAVAILABLE');throw error;}

function createXssParentResetJournalRepository(pool){
 if(!pool||typeof pool.query!=='function')throw new TypeError('PostgreSQL pool required');
 async function one(sql,args,{nullable=false,stale=false}={}){try{const result=await pool.query(sql,args);if(result.rowCount!==1){if(nullable)return null;throw failure(stale?'XSS_PARENT_RESET_STALE':'XSS_PARENT_RESET_UNAVAILABLE');}return dto(result.rows[0]);}catch(error){translate(error,stale);}}
 return Object.freeze({
  async assertReady(){const row=(await pool.query(`SELECT to_regclass('identity.xss_parent_reset_operations') IS NOT NULL AS operations,
   to_regclass('identity.xss_parent_reset_steps') IS NOT NULL AS steps,
   to_regprocedure('identity.begin_xss_parent_reset(uuid,integer)') IS NOT NULL AS begin,
   to_regprocedure('identity.complete_xss_parent_reset(uuid,uuid,bigint)') IS NOT NULL AS complete,
   to_regprocedure('identity.claim_xss_parent_reset(uuid,integer,uuid,integer)') IS NOT NULL AS claim,
   to_regprocedure('identity.guard_xss_parent_reset_scope_binding()') IS NOT NULL AS scope_guard,
   to_regprocedure('identity.assert_xss_mutation_admitted(integer)') IS NOT NULL AS mutation_admission,
   to_regclass('identity.xss_deletion_redaction_authority') IS NOT NULL AS deletion_redaction_authority,
   EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='xss_parent_reset_scope_binding_guard' AND NOT tgisinternal) AS scope_trigger,
   EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='xss_parent_reset_judgment_guard' AND NOT tgisinternal) AS judgment_trigger,
   EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='xss_parent_reset_completion_guard' AND NOT tgisinternal) AS completion_trigger,
   EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='xss_parent_reset_run_guard' AND NOT tgisinternal) AS run_trigger,
   has_function_privilege(current_user,'identity.begin_xss_parent_reset(uuid,integer)','EXECUTE') AS runtime_begin,
   has_function_privilege(current_user,'identity.assert_xss_mutation_admitted(integer)','EXECUTE') AS runtime_mutation_admission,
   NOT has_table_privilege(current_user,'identity.xss_parent_reset_operations','SELECT') AS no_direct_read,
   NOT has_table_privilege(current_user,'identity.xss_deletion_redaction_authority','SELECT') AS no_redaction_authority_read,
   NOT has_table_privilege(current_user,'identity.xss_deletion_redaction_authority','INSERT') AS no_redaction_authority_write`)).rows[0];
   if(!row||Object.values(row).some(v=>v!==true))throw failure('XSS_PARENT_RESET_STORAGE_NOT_READY');return true;},
  begin(value){const input=beginInput(value);return one(`SELECT ${PROJECTION} FROM identity.begin_xss_parent_reset($1,$2)`,[input.operationId,input.ownerId]);},
  read(operationId){return one(`SELECT ${PROJECTION} FROM identity.read_xss_parent_reset($1)`,[id(operationId)],{nullable:true});},
  async listRecoverable({limit=20}={}){if(!Number.isInteger(limit)||limit<1||limit>100)throw new TypeError('Invalid recovery limit');return (await pool.query('SELECT operation_id AS "operationId" FROM identity.list_recoverable_xss_parent_resets($1)',[limit])).rows.map(r=>id(r.operationId));},
  claim(value){if(!value||typeof value!=='object'||Array.isArray(value)
    ||Object.keys(value).some(key=>!['operationId','ownerId','leaseMs'].includes(key))
    ||!('operationId' in value)||!('ownerId' in value))throw new TypeError('Exact XSS parent reset claim required');
   const leaseMs=value.leaseMs===undefined?30000:value.leaseMs;
   if(!Number.isInteger(leaseMs)||leaseMs<1000||leaseMs>300000)throw new TypeError('Invalid lease duration');
   const operationId=id(value.operationId);owner(value.ownerId);
   return one(`SELECT ${PROJECTION} FROM identity.claim_xss_parent_reset($1,$2,$3,$4)`,[operationId,value.ownerId,randomUUID(),leaseMs],{nullable:true});},
  assertCurrent({operationId,leaseToken}={}){return one(`SELECT ${PROJECTION} FROM identity.assert_xss_parent_reset_current($1,$2)`,[id(operationId),id(leaseToken,'Lease token')],{stale:true});},
  async assertMutationAdmitted(ownerId){const result=await pool.query('SELECT identity.assert_xss_mutation_admitted($1) AS admitted',[owner(ownerId)]).catch(error=>translate(error));
   if(result.rowCount!==1||result.rows[0]?.admitted!==true)throw failure('XSS_PARENT_RESET_UNAVAILABLE');return true;},
  async acknowledgeChild({operationId,leaseToken,outcome}={}){const result=await pool.query('SELECT receipt_sha256 AS "receiptSha256",replayed FROM identity.acknowledge_xss_parent_child($1,$2,$3::jsonb)',[id(operationId),id(leaseToken,'Lease token'),JSON.stringify(normalizeChild(outcome))]).catch(e=>translate(e,true));if(result.rowCount!==1)throw failure('XSS_PARENT_RESET_STALE');return Object.freeze({receiptSha256:result.rows[0].receiptSha256,replayed:result.rows[0].replayed===true});},
  async acknowledgeClear({operationId,leaseToken,receipt}={}){const result=await pool.query('SELECT receipt_sha256 AS "receiptSha256",replayed FROM identity.acknowledge_xss_parent_clear($1,$2,$3::jsonb)',[id(operationId),id(leaseToken,'Lease token'),JSON.stringify(normalizeClear(receipt))]).catch(e=>translate(e,true));if(result.rowCount!==1)throw failure('XSS_PARENT_RESET_STALE');return Object.freeze({receiptSha256:result.rows[0].receiptSha256,replayed:result.rows[0].replayed===true});},
  finalize({operationId,leaseToken,graphGeneration}={}){return one(`SELECT ${PROJECTION} FROM identity.complete_xss_parent_reset($1,$2,$3)`,[id(operationId),id(leaseToken,'Lease token'),gen(graphGeneration,'Graph generation')],{stale:true});},
  async fail({operationId,leaseToken,code='XSS_PARENT_RESET_FAILED'}={}){if(typeof code!=='string'||!CODE.test(code))code='XSS_PARENT_RESET_FAILED';const result=await pool.query('SELECT identity.fail_xss_parent_reset($1,$2,$3) AS failed',[id(operationId),id(leaseToken,'Lease token'),code]);if(result.rows[0]?.failed!==true)throw failure('XSS_PARENT_RESET_STALE');return Object.freeze({status:'failed'});}
 });
}
module.exports={createXssParentResetJournalRepository};
