'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {cases}=require('./fixtures/maintenanceWindowsOwnerSchemaCases');
const {isSupportedLocalAncestorBinding}=require('../scripts/lib/setup-local-process-identity');
const directory=path.resolve(__dirname,'../db/postgres/maintenance-migrations'),sql=fs.readFileSync(path.join(directory,'0005_windows_owner_records.sql'),'utf8');
test('Windows SQL schema vectors match frozen pure JS v3 admission contract',()=>{
 const vectors=cases();for(const [name,value]of vectors.valid)assert.equal(isSupportedLocalAncestorBinding(value),true,name);for(const [name,value]of vectors.invalid)assert.equal(isSupportedLocalAncestorBinding(value),false,name);
});
test('0005 changes only deferred owner acceptance and preserves every other 0004 execution invariant',()=>{
 const previous=fs.readFileSync(path.join(directory,'0004_executable_recovery_admission.sql'),'utf8');const begin=previous.indexOf('CREATE FUNCTION dvaia_maintenance.check_execution_epoch()'),end=previous.indexOf('CREATE CONSTRAINT TRIGGER complete_execution_admission',begin);
 const expected=previous.slice(begin,end).replace('CREATE FUNCTION','CREATE OR REPLACE FUNCTION').replace("a.recovery_owner_record->>'version' IS DISTINCT FROM '2' OR a.recovery_owner_record->>'ancestry' IS DISTINCT FROM 'complete-supported-chain'",'NOT dvaia_maintenance.supported_owner_record(a.recovery_owner_record)');assert(sql.includes(expected));
 assert(!/CREATE (?:CONSTRAINT )?TRIGGER|DROP TRIGGER|DROP TABLE|UPDATE dvaia_maintenance|DELETE FROM dvaia_maintenance|INSERT INTO dvaia_maintenance/i.test(sql));
});
test('0005 bounds distinct Windows schema, total false, clean/exclusive gate and denies new runtime grants',()=>{
 assert(sql.includes("state='clean'"));assert(sql.includes('classid=1886610804 AND objid=90'));assert(sql.includes('count_owned NOT BETWEEN 1 AND 32'));assert(sql.includes('18446744073709551615'));assert(sql.includes('2147483647'));assert(sql.includes('observed-supported-chain'));assert(sql.includes("value->>'version' IS NOT DISTINCT FROM '2'"));
 assert.equal((sql.match(/EXCEPTION WHEN OTHERS THEN RETURN false;/g)||[]).length,5);assert(!/\bGRANT\b|SECURITY DEFINER/i.test(sql));assert(sql.includes('FROM PUBLIC,dvaia_identity_runtime'));assert(sql.includes('cardinality(names) IS DISTINCT FROM 1'));
});
