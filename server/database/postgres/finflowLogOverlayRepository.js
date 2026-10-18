'use strict';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256=/^[a-f0-9]{64}$/;
const LOG_TYPES=new Set(['access','error','audit','llm_requests']);
const ACTIONS=new Set(['delete','modify']);
const READINESS_FIELDS=Object.freeze(['schema','overlays','mutations','read_overlay','write_overlay',
  'overlay_guard_function','immutable_function','overlay_guard','mutation_guard','runtime_role','runtime_execute',
  'no_runtime_tables','no_public_execute','expected_definers','security_definers','fixed_search_paths']);
const fail=(code,message,statusCode)=>{const error=new Error(message);error.code=code;if(statusCode)error.statusCode=statusCode;throw error;};
function positive(value,label){value=Number(value);if(!Number.isSafeInteger(value)||value<1)throw new TypeError(`Valid ${label} required`);return value;}
function generation(value){value=Number(value);if(!Number.isSafeInteger(value)||value<0)throw new TypeError('Valid generation required');return value;}
function uuid(value,label){if(!UUID.test(value||''))throw new TypeError(`Valid ${label} required`);return value.toLowerCase();}
function logType(value){if(typeof value!=='string'||!LOG_TYPES.has(value))throw new TypeError('Valid FinFlow log type required');return value;}
function action(value){if(typeof value!=='string'||!ACTIONS.has(value))throw new TypeError('Valid FinFlow log action required');return value;}
function content(value){if(typeof value!=='string'||Buffer.byteLength(value)>1024*1024)throw new TypeError('Valid FinFlow log content required');return value;}
function digest(value){if(!SHA256.test(value||''))throw new TypeError('Valid FinFlow log content digest required');return value;}
function mapOverlay(row){
  if(!row)return null;
  return Object.freeze({ownerId:Number(row.owner_id),generation:Number(row.generation),logType:row.log_type,
    action:row.action,content:row.content,contentSha256:row.content_sha256,byteLength:Number(row.byte_length),
    revision:Number(row.revision)});
}
function mapMutation(row){
  if(!row)return null;
  return Object.freeze({operationId:row.operation_id?.toLowerCase(),ownerId:Number(row.owner_id),
    generation:Number(row.generation),runId:row.run_id?.toLowerCase(),logType:row.log_type,action:row.action,
    contentSha256:row.content_sha256,byteLength:Number(row.byte_length),revision:Number(row.revision),
    completedAt:row.completed_at});
}

function createFinflowLogOverlayRepository(pool){
  if(typeof pool?.query!=='function')throw new TypeError('FinFlow PostgreSQL pool required');
  return Object.freeze({
    async assertReady(){
      const row=(await pool.query(`WITH objects AS (SELECT
        to_regnamespace('finflow') AS schema_oid,
        to_regclass('finflow.log_overlays') AS overlays_oid,
        to_regclass('finflow.log_overlay_mutations') AS mutations_oid,
        to_regprocedure('finflow.read_log_overlay(bigint,bigint,text)') AS read_overlay_oid,
        to_regprocedure('finflow.write_log_overlay(uuid,bigint,bigint,uuid,text,text,text,text)') AS write_overlay_oid,
        to_regprocedure('finflow.guard_finflow_log_overlay()') AS overlay_guard_function_oid,
        to_regprocedure('finflow.guard_finflow_resource_immutable()') AS immutable_function_oid
      ), expanded AS (SELECT objects.*,
        ARRAY[read_overlay_oid,write_overlay_oid]::oid[] AS runtime_function_oids,
        ARRAY[read_overlay_oid,write_overlay_oid,overlay_guard_function_oid,immutable_function_oid]::oid[] AS all_function_oids
        FROM objects)
      SELECT schema_oid IS NOT NULL AS schema,overlays_oid IS NOT NULL AS overlays,
        mutations_oid IS NOT NULL AS mutations,read_overlay_oid IS NOT NULL AS read_overlay,
        write_overlay_oid IS NOT NULL AS write_overlay,
        overlay_guard_function_oid IS NOT NULL AS overlay_guard_function,
        immutable_function_oid IS NOT NULL AS immutable_function,
        EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=overlays_oid
          AND t.tgname='finflow_log_overlay_guard' AND NOT t.tgisinternal AND t.tgenabled='O'
          AND t.tgfoid=overlay_guard_function_oid AND t.tgtype=27) AS overlay_guard,
        EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=mutations_oid
          AND t.tgname='finflow_log_overlay_mutation_guard' AND NOT t.tgisinternal AND t.tgenabled='O'
          AND t.tgfoid=immutable_function_oid AND t.tgtype=27) AS mutation_guard,
        current_user='dvaia_finflow_runtime' AS runtime_role,
        COALESCE((SELECT bool_and(function_oid IS NOT NULL AND has_function_privilege(current_user,function_oid,'EXECUTE'))
          FROM unnest(runtime_function_oids) AS item(function_oid)),false) AS runtime_execute,
        NOT COALESCE(has_table_privilege(current_user,overlays_oid,'SELECT,INSERT,UPDATE,DELETE'),false)
        AND NOT COALESCE(has_table_privilege(current_user,mutations_oid,'SELECT,INSERT,UPDATE,DELETE'),false) AS no_runtime_tables,
        NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
          WHERE p.oid=ANY(all_function_oids) AND a.grantee=0 AND a.privilege_type='EXECUTE') AS no_public_execute,
        COALESCE((SELECT bool_and(function_oid IS NOT NULL AND pg_get_userbyid(p.proowner)='dvaia_finflow_migration')
          FROM unnest(all_function_oids) AS item(function_oid) LEFT JOIN pg_proc p ON p.oid=function_oid),false) AS expected_definers,
        COALESCE((SELECT bool_and(NOT (function_oid=ANY(runtime_function_oids)) OR p.prosecdef)
          FROM unnest(all_function_oids) AS item(function_oid) LEFT JOIN pg_proc p ON p.oid=function_oid),false) AS security_definers,
        COALESCE((SELECT bool_and(p.proconfig=ARRAY['search_path=pg_catalog']::text[])
          FROM unnest(all_function_oids) AS item(function_oid) LEFT JOIN pg_proc p ON p.oid=function_oid),false) AS fixed_search_paths
      FROM expanded`)).rows[0];
      if(!row||READINESS_FIELDS.some(field=>row[field]!==true)){
        fail('FINFLOW_LOG_OVERLAY_STORAGE_NOT_READY','FinFlow durable log overlay storage is not ready',503);
      }
      return true;
    },
    async read(value){
      const params=[positive(value.ownerId,'owner'),generation(value.generation),logType(value.logType)];
      return mapOverlay((await pool.query('SELECT * FROM finflow.read_log_overlay($1,$2,$3)',params)).rows[0]);
    },
    async write(value){
      const body=content(value.content),kind=action(value.action);
      if(kind==='delete'&&body!=='')throw new TypeError('Deleted FinFlow log overlay must be empty');
      const params=[uuid(value.operationId,'operation'),positive(value.ownerId,'owner'),generation(value.generation),
        uuid(value.runId,'run'),logType(value.logType),kind,body,digest(value.contentSha256)];
      return mapMutation((await pool.query(
        'SELECT * FROM finflow.write_log_overlay($1,$2,$3,$4,$5,$6,$7,$8)',params)).rows[0]);
    },
  });
}

module.exports={createFinflowLogOverlayRepository,READINESS_FIELDS};
