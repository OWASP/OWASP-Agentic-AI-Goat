'use strict';
const { createHash } = require('node:crypto');
const TRIGGER_BODY_SHA = 'ce08da57f487eed653d2315e2c1f697e96ee6da56cedef4a417b4234689f8a90';
function failure(stage) { return Object.assign(new Error('Teaching session store is not ready'), { code: 'TEACHING_SESSION_NOT_READY', stage }); }
async function assertTeachingSessionReadiness(pool) {
  let stage = 'runtime-role';
  try {
    const actor = (await pool.query('SELECT current_user AS name')).rows[0];
    if (actor?.name !== 'dvaia_identity_runtime') throw failure();
    // The migration-role initializer verifies the immutable ledger. Runtime
    // readiness checks live capabilities without granting ledger access.
    stage = 'columns';
    const columns = (await pool.query(`SELECT attname FROM pg_attribute
      WHERE attrelid='identity.teaching_sessions'::regclass AND attnum>0 AND NOT attisdropped ORDER BY attname`)).rows.map(row => row.attname);
    if (JSON.stringify(columns) !== JSON.stringify(['expires_at','owner_id','payload','platform_session_id','revoked','session_hash','updated_at'])) throw failure();
    stage = 'privileges';
    const privileges = (await pool.query(`SELECT
      (has_table_privilege(current_user,'identity.teaching_sessions','SELECT') AND
       has_table_privilege(current_user,'identity.teaching_sessions','INSERT') AND
       has_table_privilege(current_user,'identity.teaching_sessions','UPDATE') AND
       has_table_privilege(current_user,'identity.teaching_sessions','DELETE')) AS required,
      has_table_privilege(current_user,'identity.teaching_sessions','TRUNCATE,TRIGGER,REFERENCES') AS extra,
      EXISTS(SELECT 1 FROM pg_class c,LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
        WHERE c.oid='identity.teaching_sessions'::regclass AND a.grantee=0) AS public_table,
      EXISTS(SELECT 1 FROM pg_attribute p,LATERAL aclexplode(p.attacl) a
        WHERE p.attrelid='identity.teaching_sessions'::regclass AND a.grantee=0) AS public_column,
      EXISTS(SELECT 1 FROM pg_attribute p WHERE p.attrelid='identity.teaching_sessions'::regclass
        AND p.attnum>0 AND NOT p.attisdropped AND has_column_privilege(current_user,p.attrelid,p.attnum,'REFERENCES')) AS extra_column`)).rows[0];
    if (!privileges?.required || privileges.extra || privileges.public_table || privileges.public_column || privileges.extra_column) throw failure();
    stage = 'deletion-trigger';
    const trigger = (await pool.query(`SELECT t.tgenabled,t.tgtype,t.tgnargs,t.tgqual IS NULL AS unconditional,p.prosrc,p.prosecdef,p.proconfig,
      pg_get_userbyid(p.proowner) AS owner,
      has_function_privilege(current_user,p.oid,'EXECUTE') AS runtime_execute,
      EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0) AS public_execute
      FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
      WHERE t.tgrelid='identity.users'::regclass AND t.tgname='retire_deleted_owner_teaching_sessions'
        AND p.oid='identity.retire_deleted_owner_teaching_sessions()'::regprocedure`)).rows[0];
    if (!trigger || trigger.tgenabled !== 'O' || trigger.tgtype !== 11 || trigger.tgnargs !== 0 || !trigger.unconditional || !trigger.prosecdef || trigger.owner !== 'dvaia_identity_migration'
        || JSON.stringify(trigger.proconfig) !== JSON.stringify(['search_path=pg_catalog'])
        || trigger.runtime_execute || trigger.public_execute
        || createHash('sha256').update(trigger.prosrc).digest('hex') !== TRIGGER_BODY_SHA) throw failure();
    const inactivation = (await pool.query(`SELECT tgenabled,tgtype,tgattr::text AS columns,
      pg_get_triggerdef(oid) AS definition FROM pg_trigger
      WHERE tgrelid='identity.users'::regclass AND tgname='retire_inactive_owner_teaching_sessions'
        AND tgfoid='identity.retire_deleted_owner_teaching_sessions()'::regprocedure`)).rows[0];
    const activeColumn = (await pool.query("SELECT attnum::text AS number FROM pg_attribute WHERE attrelid='identity.users'::regclass AND attname='is_active' AND NOT attisdropped")).rows[0];
    if (!inactivation || inactivation.tgenabled !== 'O' || inactivation.tgtype !== 19
        || inactivation.columns !== activeColumn?.number || !inactivation.definition.includes(' WHEN ((new.is_active = 0)) EXECUTE FUNCTION ')) throw failure();
    return Object.freeze({ ready: true });
  } catch { throw failure(stage); }
}
module.exports = { assertTeachingSessionReadiness };
