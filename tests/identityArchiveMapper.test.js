'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { COLUMNS, mapIdentityArchive } = require('../db/postgres/map-identity-archive');
const bcrypt = require('bcryptjs');
const integer = value => ({type:'integer',value:String(value)});
function fixture() {
  const stamp='2026-01-02 03:04:05.123456';
  function row(table, values) {
    return Object.fromEntries(COLUMNS[table].split(' ').map(key=>[key,Object.hasOwn(values,key)?values[key]:null]));
  }
  return { archiveDigest:'a'.repeat(64),naiveTimestamps:'UTC',tables:{
    users:[row('users',{id:integer(7),username:'instructor',email:'instructor@example.test',password:bcrypt.hashSync('synthetic-only',4),role:'admin',admin_level:integer(1),email_verified:integer(1),is_active:integer(1),login_attempts:integer(0),last_password_change:stamp,password_reset_required:integer(0),two_factor_enabled:integer(0),created_at:stamp,updated_at:stamp})],
    admin_permissions:[row('admin_permissions',{id:integer(3),admin_id:integer(7),permission_name:'user_management',granted_at:stamp,is_active:integer(1)})],
    user_sessions:[row('user_sessions',{id:integer(9),user_id:integer(7),session_token:'synthetic-private-token',device_info:'{"userAgent":"fixture"}',is_active:integer(1),last_activity:stamp,expires_at:'2027-01-02 03:04:05',created_at:stamp})],
    activity_logs:[row('activity_logs',{id:integer(12),user_id:integer(7),action_type:'login',action_details:'{"method":"POST","url":"/login?secret=fixture","extra":"retained archive"}',risk_level:'low',success:integer(1),error_message:'source-only error',timestamp:stamp})],
  }};
}
test('preserves raw session DTO and IDs while reporting audit/device normalization without values',()=>{
  const raw=fixture();const result=mapIdentityArchive(raw);
  assert.equal(result.identity.sessions[0].session_token,'synthetic-private-token');
  assert.equal(Object.hasOwn(result.identity.sessions[0],'session_token_hash'),false);
  assert.equal(result.identity.users[0].id,7);
  assert.equal(result.identity.users[0].password,raw.tables.users[0].password);
  assert.equal(result.identity.users[0].created_at,'2026-01-02T03:04:05.123456Z');
  assert.equal(result.identity.audit[0].action_details,raw.tables.activity_logs[0].action_details);
  assert.equal(result.report.requiresReview,true);
  assert.equal(result.report.normalizations.length,3);
  const report=JSON.stringify(result.report);
  for(const secret of ['synthetic-private-token','source-only error','secret=fixture',raw.tables.users[0].password]) assert.equal(report.includes(secret),false);
});
test('rejects unsafe integers, columns, missing collections, duplicate IDs and unresolved owners',()=>{
  let raw=fixture();raw.tables.users[0].id=integer('9007199254740993');assert.throws(()=>mapIdentityArchive(raw),{code:'UNSAFE_IDENTITY_INTEGER'});
  raw=fixture();raw.tables.users[0].unknown='x';assert.throws(()=>mapIdentityArchive(raw),{code:'UNMAPPED_IDENTITY_COLUMNS'});
  raw=fixture();delete raw.tables.activity_logs;assert.throws(()=>mapIdentityArchive(raw),{code:'MISSING_IDENTITY_ARCHIVE_TABLE'});
  raw=fixture();raw.tables.users.push(structuredClone(raw.tables.users[0]));assert.throws(()=>mapIdentityArchive(raw),/Duplicate identity import ID/);
  raw=fixture();raw.tables.user_sessions[0].user_id=integer(99);assert.throws(()=>mapIdentityArchive(raw),/missing user/);
});
test('requires explicit timezone policy and rejects invalid calendar and silent defaults',()=>{
  let raw=fixture();delete raw.naiveTimestamps;assert.throws(()=>mapIdentityArchive(raw),{code:'AMBIGUOUS_TIMESTAMP'});
  raw=fixture();raw.tables.users[0].created_at='2026-02-30 00:00:00';assert.throws(()=>mapIdentityArchive(raw),/Invalid identity timestamp/);
  raw=fixture();raw.tables.users[0].is_active=null;assert.throws(()=>mapIdentityArchive(raw),{code:'NULL_IDENTITY_VALUE_REQUIRES_REVIEW'});
  raw=fixture();raw.tables.users[0].role='';assert.throws(()=>mapIdentityArchive(raw),{code:'EMPTY_IDENTITY_VALUE_REQUIRES_REVIEW'});
  raw=fixture();raw.tables.users[0].updated_at=null;assert.throws(()=>mapIdentityArchive(raw),{code:'NULL_IDENTITY_VALUE_REQUIRES_REVIEW'});
});
test('unknown populated archive tables remain outside exact four-table coverage',()=>{
  const raw=fixture();raw.tables.other=[{id:integer('9223372036854775807'),secret:'not in report'}];raw.tables.empty=[];
  const result=mapIdentityArchive(raw);
  assert.deepEqual(result.report.unknownPopulatedTables,[{table:'other',rows:1,disposition:'outside_identity_scope'}]);
  assert.equal(JSON.stringify(result.report).includes('not in report'),false);
  assert.equal(raw.tables.other[0].id.value,'9223372036854775807');
});
