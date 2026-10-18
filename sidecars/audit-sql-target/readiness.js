'use strict';
async function assertReadiness({pool,controlDatabase,administrator}){
 if(!/^(dvaia_audit_control_|dvaia_test_audit_search_)[a-f0-9]+$/.test(controlDatabase)||!/^[_a-z0-9]+$/.test(administrator))throw Error('Synthetic control identity required');
 const identity=(await pool.query('SELECT current_database() AS database,current_user AS role')).rows[0];
 if(identity.database!==controlDatabase||identity.role!==administrator)throw Error('Synthetic control identity mismatch');
 const databases=(await pool.query('SELECT datname,datacl FROM pg_database WHERE NOT datistemplate')).rows;
 if(databases.some(r=>r.datname!==controlDatabase&&r.datname!=='postgres'&&!/^audit_[a-f0-9]{32}$/.test(r.datname)))throw Error('Nonteaching database present');
 const roles=(await pool.query("SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname NOT LIKE 'pg_%' AND rolname<>$1",[administrator])).rows;
 if(roles.some(r=>!/^audit_[a-f0-9]{32}$/.test(r.rolname)||r.rolsuper||r.rolcreatedb||r.rolcreaterole||r.rolreplication||r.rolbypassrls))throw Error('Unexpected role in synthetic cluster');
 const publicConnect=(await pool.query("SELECT 1 FROM pg_database d,LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname=$1 AND a.grantee=0 AND a.privilege_type='CONNECT'",[controlDatabase])).rowCount;
 if(publicConnect)throw Error('Control database is public');
 const tables=(await pool.query("SELECT to_regclass('owned_audit_targets') AS targets,to_regclass('owned_audit_credentials') AS credentials,to_regclass('owned_audit_queries') AS queries")).rows[0];
 if(!tables.targets||!tables.credentials||!tables.queries)throw Error('Control schema missing');
 const tombstones=(await pool.query("SELECT 1 FROM pg_attribute WHERE attrelid='owned_audit_queries'::regclass AND attname='retired_result_sha256' AND NOT attisdropped")).rowCount;
 if(!tombstones)throw Error('Control query destruction migration missing');
 const grants=(await pool.query("SELECT 1 FROM pg_class c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid IN ('owned_audit_targets'::regclass,'owned_audit_credentials'::regclass,'owned_audit_queries'::regclass) AND a.grantee=0")).rowCount;
 if(grants)throw Error('Control tables are public');
 return Object.freeze({version:1,ready:true,capability:'owned-audit-postgres.v1'});
}
module.exports={assertReadiness};
