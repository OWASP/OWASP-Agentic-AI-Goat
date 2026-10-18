'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {COLUMNS}=require('../db/postgres/map-platform-snapshot');
const {preparePlatformImport}=require('../db/postgres/import-platform-snapshot');
function input(){const archiveDigest='a'.repeat(64);return{tables:Object.fromEntries(Object.keys(COLUMNS).map(key=>[key,[]])),identityMap:{},archiveDigest,review:{archiveDigest,missingDefaults:{exercises:'catalog_visibility_defaults_without_content',objectiveVisibility:'catalog_visibility_defaults_without_content',hintVisibility:'catalog_visibility_defaults_without_content'},retainedTables:[]}};}
test('platform import requires archive-bound explicit defaults and retained-table decisions',()=>{
 const source=input();assert.equal(preparePlatformImport(source).snapshot.version,1);
 source.review.archiveDigest='b'.repeat(64);assert.throws(()=>preparePlatformImport(source),{code:'ARCHIVE_BOUND_REVIEW_REQUIRED'});source.review.archiveDigest=source.archiveDigest;
 delete source.review.missingDefaults.hintVisibility;assert.throws(()=>preparePlatformImport(source),{code:'DEFAULT_POLICY_SCOPE_MISMATCH'});
});
test('populated solutions cannot be silently mapped or discarded by an unrelated review',()=>{
 const source=input();source.tables.ipi_solutions=[{objective_id:'fixture'}];assert.throws(()=>preparePlatformImport(source),{code:'UNMAPPED_TABLE_RESOLUTION_REQUIRED'});
 source.review.retainedTables=['ipi_solutions'];const plan=preparePlatformImport(source);assert.equal(plan.report.unmappedTables[0].reason,'solution_precedence_requires_review');assert.equal('solutions'in plan.snapshot,false);
 source.snapshot={historicalCompletions:[{verdict:'pass'}]};assert.throws(()=>preparePlatformImport(source),{code:'UNKNOWN_PLATFORM_IMPORT_INPUT'});
});
