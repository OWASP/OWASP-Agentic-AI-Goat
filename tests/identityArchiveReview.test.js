'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { COLUMNS, mapIdentityArchive } = require('../db/postgres/map-identity-archive');
const { reviewIdentityArchive, NORMALIZATION_POLICY } = require('../db/postgres/review-identity-archive');
function fixture() {
  const tables=Object.fromEntries(Object.keys(COLUMNS).map(key=>[key,[]]));
  tables.activity_logs=[Object.fromEntries(COLUMNS.activity_logs.split(' ').map(key=>[key,({id:{type:'integer',value:'1'},action_type:'login',action_details:'{"url":"/login?private=secret","unmapped":"private-data"}',risk_level:'low',success:{type:'integer',value:'1'},error_message:'private-error',timestamp:'2026-01-01T00:00:00Z'})[key]??null]))];
  const raw={tables,archiveDigest:'a'.repeat(64)};
  raw.review={archiveDigest:raw.archiveDigest,normalizations:mapIdentityArchive(raw).report.normalizations.map(({requiresReview,...row})=>({...row,policy:NORMALIZATION_POLICY}))};
  return raw;
}
test('exact archive-bound decisions approve native policy while retaining raw source DTO',()=>{
  const raw=fixture();const copy=structuredClone(raw);const result=reviewIdentityArchive(raw);
  assert.equal(result.report.normalizationReviewComplete,true);
  assert.equal(result.report.readyToApply,false);
  assert.equal(result.identity.audit[0].error_message,'private-error');
  assert.equal(result.identity.audit[0].action_details,raw.tables.activity_logs[0].action_details);
  assert.deepEqual(raw,copy);
  for(const secret of ['private-error','private-data','private=secret']) assert.equal(JSON.stringify(result.report).includes(secret),false);
  assert.equal(result.report.approvedNormalizations.length,2);
});
test('rejects stale, missing, extra, duplicate and unsupported decisions',()=>{
  let raw=fixture();raw.review.archiveDigest='b'.repeat(64);assert.throws(()=>reviewIdentityArchive(raw),{code:'STALE_IDENTITY_NORMALIZATION_REVIEW'});
  raw=fixture();raw.review.normalizations.pop();assert.throws(()=>reviewIdentityArchive(raw),{code:'MISSING_IDENTITY_NORMALIZATION_DECISION'});
  raw=fixture();raw.review.normalizations[0].sourceId=2;assert.throws(()=>reviewIdentityArchive(raw),{code:'STALE_OR_EXTRA_IDENTITY_NORMALIZATION_DECISION'});
  raw=fixture();raw.review.normalizations.push({...raw.review.normalizations[0]});assert.throws(()=>reviewIdentityArchive(raw),{code:'DUPLICATE_IDENTITY_NORMALIZATION_DECISION'});
  raw=fixture();raw.review.normalizations[0].policy='discard';assert.throws(()=>reviewIdentityArchive(raw),{code:'UNSUPPORTED_IDENTITY_NORMALIZATION_POLICY'});
  raw=fixture();raw.review.normalizations[0].secret='unexpected';assert.throws(()=>reviewIdentityArchive(raw),{code:'INVALID_IDENTITY_NORMALIZATION_DECISION'});
});
test('recomputes normalization set and leaves unknown source coverage unresolved',()=>{
  const raw=fixture();raw.tables.activity_logs[0].error_message=null;
  assert.throws(()=>reviewIdentityArchive(raw),{code:'STALE_OR_EXTRA_IDENTITY_NORMALIZATION_DECISION'});
  const empty={tables:Object.fromEntries(Object.keys(COLUMNS).map(key=>[key,[]])),archiveDigest:'c'.repeat(64)};
  empty.tables.other=[{secret:'untouched'}];empty.review={archiveDigest:empty.archiveDigest,normalizations:[]};
  const result=reviewIdentityArchive(empty);
  assert.equal(result.report.coverageReviewRequired,true);assert.equal(result.report.readyToApply,false);
  assert.deepEqual(result.report.unknownPopulatedTables,[{table:'other',rows:1,disposition:'outside_identity_scope'}]);
});
