'use strict';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const READINESS_FIELDS = Object.freeze(['schema','datasets','deletions','artifacts','reads','retirements','owner_deletions',
  'ensure_dataset','assert_generation', 'read_dataset',
  'delete_dataset','reserve_backup','commit_backup','read_backup','list_backups','record_read','begin_retirement',
  'complete_retirement','read_retirement','begin_owner_deletion','complete_owner_deletion','read_owner_deletion',
  'destroy_owner',
  'immutable_function','lineage_function','retirement_function','owner_deletion_function',
  'dataset_deletion_guard','backup_read_guard','lineage_guard','retirement_guard','owner_deletion_guard',
  'runtime_role','runtime_execute','no_runtime_tables','no_public_execute','expected_definers',
  'security_definers','fixed_search_paths']);
const fail = (code, message) => { const error = new Error(message); error.code = code; throw error; };
function positive(value, label) { value = Number(value); if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`Valid ${label} required`); return value; }
function nonnegative(value, label) { value = Number(value); if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`Valid ${label} required`); return value; }
function id(value, label) { if (!UUID.test(value || '')) throw new TypeError(`Valid ${label} required`); return value.toLowerCase(); }
function rows(value) { if (!Array.isArray(value)) throw new TypeError('FinFlow customer dataset array required'); return JSON.stringify(value); }
function mapDataset(row) {
  if (!row) return null;
  return Object.freeze({ ownerId:Number(row.owner_id), generation:Number(row.generation), revision:Number(row.revision),
    records:row.records, deleted:row.deleted === true });
}
function mapBackup(row) {
  if (!row) return null;
  return Object.freeze({ ownerId:Number(row.owner_id), generation:Number(row.generation), operationId:row.operation_id,
    runId:row.run_id, backupId:row.backup_id, fileToken:row.file_token, virtualPath:row.virtual_path,
    datasetRevision:Number(row.dataset_revision), records:row.records, status:row.status,
    contentSha256:row.content_sha256, byteLength:row.byte_length === null ? null : Number(row.byte_length),
    recordCount:row.record_count === null ? null : Number(row.record_count) });
}
function mapOwnerDeletion(row) {
  if (!row) return null;
  return Object.freeze({ jobId:row.job_id?.toLowerCase(), ownerId:Number(row.owner_id), status:row.status,
    fileTokens:Object.freeze((row.file_tokens || []).map(value=>value.toLowerCase())), artifactCount:Number(row.artifact_count),
    datasetCount:Number(row.dataset_count), completedAt:row.completed_at });
}
function createFinflowDurableResourceRepository(pool) {
  if (typeof pool?.query !== 'function') throw new TypeError('FinFlow PostgreSQL pool required');
  return Object.freeze({
    async assertReady() {
      const row=(await pool.query(`WITH objects AS (SELECT
        to_regnamespace('finflow') AS schema_oid,
        to_regclass('finflow.customer_datasets') AS datasets_oid,
        to_regclass('finflow.dataset_deletions') AS deletions_oid,
        to_regclass('finflow.backup_artifacts') AS artifacts_oid,
        to_regclass('finflow.backup_reads') AS reads_oid,
        to_regclass('finflow.resource_retirements') AS retirements_oid,
        to_regclass('finflow.owner_resource_deletions') AS owner_deletions_oid,
        to_regprocedure('finflow.ensure_customer_dataset(bigint,bigint,jsonb)') AS ensure_dataset_oid,
        to_regprocedure('finflow.assert_finflow_generation_active(bigint,bigint)') AS assert_generation_oid,
        to_regprocedure('finflow.read_customer_dataset(bigint,bigint,jsonb)') AS read_dataset_oid,
        to_regprocedure('finflow.delete_customer_dataset(uuid,bigint,bigint,uuid,jsonb)') AS delete_dataset_oid,
        to_regprocedure('finflow.reserve_customer_backup(uuid,bigint,bigint,uuid,uuid,uuid,text,jsonb)') AS reserve_backup_oid,
        to_regprocedure('finflow.commit_customer_backup(uuid,bigint,bigint,uuid,uuid,uuid,text,bigint,text,bigint,integer)') AS commit_backup_oid,
        to_regprocedure('finflow.read_customer_backup(bigint,bigint,text)') AS read_backup_oid,
        to_regprocedure('finflow.list_customer_backups(bigint,bigint)') AS list_backups_oid,
        to_regprocedure('finflow.record_customer_backup_read(uuid,bigint,bigint,uuid,uuid,text,text,bigint)') AS record_read_oid,
        to_regprocedure('finflow.begin_resource_retirement(uuid,bigint,bigint,bigint)') AS begin_retirement_oid,
        to_regprocedure('finflow.complete_resource_retirement(uuid,bigint,bigint,bigint,uuid[])') AS complete_retirement_oid,
        to_regprocedure('finflow.read_resource_retirement(uuid,bigint,bigint,bigint)') AS read_retirement_oid,
        to_regprocedure('finflow.begin_owner_resource_deletion(uuid,bigint)') AS begin_owner_deletion_oid,
        to_regprocedure('finflow.complete_owner_resource_deletion(uuid,bigint,uuid[])') AS complete_owner_deletion_oid,
        to_regprocedure('finflow.read_owner_resource_deletion(uuid,bigint)') AS read_owner_deletion_oid,
        to_regprocedure('finflow.destroy_student_owner(bigint,uuid)') AS destroy_owner_oid,
        to_regprocedure('finflow.guard_finflow_resource_immutable()') AS immutable_function_oid,
        to_regprocedure('finflow.guard_finflow_backup_lineage()') AS lineage_function_oid,
        to_regprocedure('finflow.guard_finflow_retirement()') AS retirement_function_oid,
        to_regprocedure('finflow.guard_finflow_owner_deletion()') AS owner_deletion_function_oid
      ), expanded AS (SELECT objects.*, ARRAY[read_dataset_oid,delete_dataset_oid,reserve_backup_oid,
        commit_backup_oid,read_backup_oid,list_backups_oid,record_read_oid,begin_retirement_oid,complete_retirement_oid,
        read_retirement_oid,begin_owner_deletion_oid,complete_owner_deletion_oid,read_owner_deletion_oid,destroy_owner_oid]::oid[] AS runtime_function_oids,
        ARRAY[ensure_dataset_oid,assert_generation_oid,read_dataset_oid,delete_dataset_oid,reserve_backup_oid,
        commit_backup_oid,read_backup_oid,list_backups_oid,record_read_oid,begin_retirement_oid,complete_retirement_oid,
        read_retirement_oid,begin_owner_deletion_oid,complete_owner_deletion_oid,read_owner_deletion_oid,
        destroy_owner_oid,immutable_function_oid,lineage_function_oid,retirement_function_oid,owner_deletion_function_oid]::oid[] AS all_function_oids
        FROM objects)
      SELECT schema_oid IS NOT NULL AS schema,
        datasets_oid IS NOT NULL AS datasets,deletions_oid IS NOT NULL AS deletions,
        artifacts_oid IS NOT NULL AS artifacts,reads_oid IS NOT NULL AS reads,
        retirements_oid IS NOT NULL AS retirements,owner_deletions_oid IS NOT NULL AS owner_deletions,
        ensure_dataset_oid IS NOT NULL AS ensure_dataset,assert_generation_oid IS NOT NULL AS assert_generation,
        read_dataset_oid IS NOT NULL AS read_dataset,delete_dataset_oid IS NOT NULL AS delete_dataset,
        reserve_backup_oid IS NOT NULL AS reserve_backup,commit_backup_oid IS NOT NULL AS commit_backup,
        read_backup_oid IS NOT NULL AS read_backup,list_backups_oid IS NOT NULL AS list_backups,
        record_read_oid IS NOT NULL AS record_read,
        begin_retirement_oid IS NOT NULL AS begin_retirement,
        complete_retirement_oid IS NOT NULL AS complete_retirement,
        read_retirement_oid IS NOT NULL AS read_retirement,
        begin_owner_deletion_oid IS NOT NULL AS begin_owner_deletion,
        complete_owner_deletion_oid IS NOT NULL AS complete_owner_deletion,
        read_owner_deletion_oid IS NOT NULL AS read_owner_deletion,
        destroy_owner_oid IS NOT NULL AS destroy_owner,
        immutable_function_oid IS NOT NULL AS immutable_function,
        lineage_function_oid IS NOT NULL AS lineage_function,
        retirement_function_oid IS NOT NULL AS retirement_function,
        owner_deletion_function_oid IS NOT NULL AS owner_deletion_function,
        EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=deletions_oid
          AND t.tgname='finflow_dataset_deletion_guard' AND NOT t.tgisinternal AND t.tgenabled='O'
          AND t.tgfoid=immutable_function_oid AND t.tgtype=27) AS dataset_deletion_guard,
        EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=reads_oid
          AND t.tgname='finflow_backup_read_guard' AND NOT t.tgisinternal AND t.tgenabled='O'
          AND t.tgfoid=immutable_function_oid AND t.tgtype=27) AS backup_read_guard,
        EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=artifacts_oid
          AND t.tgname='finflow_backup_lineage_guard' AND NOT t.tgisinternal AND t.tgenabled='O'
          AND t.tgfoid=lineage_function_oid AND t.tgtype=27) AS lineage_guard,
        EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=retirements_oid
          AND t.tgname='finflow_resource_retirement_guard' AND NOT t.tgisinternal AND t.tgenabled='O'
          AND t.tgfoid=retirement_function_oid AND t.tgtype=27) AS retirement_guard,
        EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=owner_deletions_oid
          AND t.tgname='finflow_owner_deletion_guard' AND NOT t.tgisinternal AND t.tgenabled='O'
          AND t.tgfoid=owner_deletion_function_oid AND t.tgtype=27) AS owner_deletion_guard,
        current_user='dvaia_finflow_runtime' AS runtime_role,
        COALESCE((SELECT bool_and(function_oid IS NOT NULL AND has_function_privilege(current_user,function_oid,'EXECUTE'))
          FROM unnest(runtime_function_oids) AS item(function_oid)),false) AS runtime_execute,
        NOT COALESCE(has_table_privilege(current_user,datasets_oid,'SELECT,INSERT,UPDATE,DELETE'),false)
        AND NOT COALESCE(has_table_privilege(current_user,artifacts_oid,'SELECT,INSERT,UPDATE,DELETE'),false)
        AND NOT COALESCE(has_table_privilege(current_user,reads_oid,'SELECT,INSERT,UPDATE,DELETE'),false)
        AND NOT COALESCE(has_table_privilege(current_user,retirements_oid,'SELECT,INSERT,UPDATE,DELETE'),false)
        AND NOT COALESCE(has_table_privilege(current_user,owner_deletions_oid,'SELECT,INSERT,UPDATE,DELETE'),false)
        AND NOT COALESCE(has_table_privilege(current_user,deletions_oid,'SELECT,INSERT,UPDATE,DELETE'),false) AS no_runtime_tables,
        NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
          WHERE p.oid=ANY(all_function_oids) AND a.grantee=0 AND a.privilege_type='EXECUTE') AS no_public_execute,
        COALESCE((SELECT bool_and(function_oid IS NOT NULL AND pg_get_userbyid(p.proowner)='dvaia_finflow_migration')
          FROM unnest(all_function_oids) AS item(function_oid)
          LEFT JOIN pg_proc p ON p.oid=function_oid),false) AS expected_definers
        ,COALESCE((SELECT bool_and(NOT (function_oid=ANY(runtime_function_oids)) OR p.prosecdef)
          FROM unnest(all_function_oids) AS item(function_oid) LEFT JOIN pg_proc p ON p.oid=function_oid),false) AS security_definers
        ,COALESCE((SELECT bool_and(p.proconfig=ARRAY['search_path=pg_catalog']::text[])
          FROM unnest(all_function_oids) AS item(function_oid) LEFT JOIN pg_proc p ON p.oid=function_oid),false) AS fixed_search_paths
      FROM expanded`)).rows[0];
      if (!row || READINESS_FIELDS.some(field => row[field] !== true)) {
        fail('FINFLOW_RESOURCE_STORAGE_NOT_READY', 'FinFlow durable resource storage is not ready');
      }
      return true;
    },
    async readDataset(value) {
      const ownerId=positive(value.ownerId,'owner'),generation=nonnegative(value.generation,'generation');
      return mapDataset((await pool.query('SELECT * FROM finflow.read_customer_dataset($1,$2,$3::jsonb)',
        [ownerId,generation,rows(value.initialRecords)])).rows[0]);
    },
    async deleteDataset(value) {
      const ownerId=positive(value.ownerId,'owner'),generation=nonnegative(value.generation,'generation');
      const operationId=id(value.operationId,'operation'),runId=id(value.runId,'run');
      const row=(await pool.query('SELECT * FROM finflow.delete_customer_dataset($1,$2,$3,$4,$5::jsonb)',
        [operationId,ownerId,generation,runId,rows(value.initialRecords)])).rows[0];
      return row && Object.freeze({ ownerId:Number(row.owner_id),generation:Number(row.generation),
        operationId:row.operation_id,runId:row.run_id,revision:Number(row.revision),
        deleted:row.deleted===true,records:row.records });
    },
    async reserveBackup(value) {
      const row=(await pool.query('SELECT * FROM finflow.reserve_customer_backup($1,$2,$3,$4,$5,$6,$7,$8::jsonb)',
        [id(value.operationId,'operation'),positive(value.ownerId,'owner'),nonnegative(value.generation,'generation'),
          id(value.runId,'run'),id(value.backupId,'backup'),id(value.fileToken,'file token'),value.virtualPath,rows(value.initialRecords)])).rows[0];
      return mapBackup(row);
    },
    async commitBackup(value) {
      const row=(await pool.query('SELECT * FROM finflow.commit_customer_backup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
        [id(value.operationId,'operation'),positive(value.ownerId,'owner'),nonnegative(value.generation,'generation'),
          id(value.runId,'run'),id(value.backupId,'backup'),id(value.fileToken,'file token'),value.virtualPath,
          nonnegative(value.datasetRevision,'dataset revision'),value.contentSha256,
          nonnegative(value.byteLength,'byte length'),nonnegative(value.recordCount,'record count')])).rows[0];
      return mapBackup(row);
    },
    async readBackup(value) {
      return mapBackup((await pool.query('SELECT * FROM finflow.read_customer_backup($1,$2,$3)',
        [positive(value.ownerId,'owner'),nonnegative(value.generation,'generation'),value.virtualPath])).rows[0]);
    },
    async listBackups(value) {
      const result=await pool.query('SELECT * FROM finflow.list_customer_backups($1,$2)',
        [positive(value.ownerId,'owner'),nonnegative(value.generation,'generation')]);
      return Object.freeze(result.rows.map(mapBackup));
    },
    async recordBackupRead(value) {
      const row=(await pool.query('SELECT * FROM finflow.record_customer_backup_read($1,$2,$3,$4,$5,$6,$7,$8)',
        [id(value.operationId,'operation'),positive(value.ownerId,'owner'),nonnegative(value.generation,'generation'),
          id(value.runId,'run'),id(value.backupId,'backup'),value.requestedPath,value.contentSha256,
          nonnegative(value.byteLength,'byte length')])).rows[0];
      return row && Object.freeze({ ownerId:Number(row.owner_id),generation:Number(row.generation),
        operationId:row.operation_id,runId:row.run_id,backupId:row.backup_id,
        requestedPath:row.requested_path,contentSha256:row.content_sha256,byteLength:Number(row.byte_length) });
    },
    async beginRetirement(value) {
      const row=(await pool.query('SELECT * FROM finflow.begin_resource_retirement($1,$2,$3,$4)',
        [id(value.operationId,'operation'),positive(value.ownerId,'owner'),nonnegative(value.fromGeneration,'from generation'),
          positive(value.toGeneration,'to generation')])).rows[0];
      return row && Object.freeze({ operationId:row.operation_id,ownerId:Number(row.owner_id),
        fromGeneration:Number(row.from_generation),toGeneration:Number(row.to_generation),
        status:row.status,fileTokens:Object.freeze(row.file_tokens || []) });
    },
    async completeRetirement(value) {
      const row=(await pool.query('SELECT * FROM finflow.complete_resource_retirement($1,$2,$3,$4,$5::uuid[])',
        [id(value.operationId,'operation'),positive(value.ownerId,'owner'),nonnegative(value.fromGeneration,'from generation'),
          positive(value.toGeneration,'to generation'),value.fileTokens.map(item=>id(item,'file token'))])).rows[0];
      return row && Object.freeze({ operationId:row.operation_id,ownerId:Number(row.owner_id),
        fromGeneration:Number(row.from_generation),toGeneration:Number(row.to_generation),status:row.status,
        artifactCount:Number(row.artifact_count),completedAt:row.completed_at });
    },
    async readRetirement(value) {
      const row=(await pool.query('SELECT * FROM finflow.read_resource_retirement($1,$2,$3,$4)',
        [id(value.operationId,'operation'),positive(value.ownerId,'owner'),nonnegative(value.fromGeneration,'from generation'),
          positive(value.toGeneration,'to generation')])).rows[0];
      return row && Object.freeze({ operationId:row.operation_id,ownerId:Number(row.owner_id),
        fromGeneration:Number(row.from_generation),toGeneration:Number(row.to_generation),status:row.status,
        artifactCount:Number(row.artifact_count),completedAt:row.completed_at });
    },
    async beginOwnerDeletion(value) {
      return mapOwnerDeletion((await pool.query('SELECT * FROM finflow.begin_owner_resource_deletion($1,$2)',
        [id(value.jobId,'deletion job'),positive(value.ownerId,'owner')])).rows[0]);
    },
    async completeOwnerDeletion(value) {
      if (!Array.isArray(value.fileTokens)) throw new TypeError('FinFlow deletion file tokens required');
      return mapOwnerDeletion((await pool.query('SELECT * FROM finflow.complete_owner_resource_deletion($1,$2,$3::uuid[])',
        [id(value.jobId,'deletion job'),positive(value.ownerId,'owner'),value.fileTokens.map(item=>id(item,'file token'))])).rows[0]);
    },
    async readOwnerDeletion(value) {
      return mapOwnerDeletion((await pool.query('SELECT * FROM finflow.read_owner_resource_deletion($1,$2)',
        [id(value.jobId,'deletion job'),positive(value.ownerId,'owner')])).rows[0]);
    },
  });
}
module.exports = { createFinflowDurableResourceRepository, READINESS_FIELDS };
