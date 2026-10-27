'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {fixture}=require('./secureshopManualRagSourceContract.test');
const {replaceControlledObservation,runProtectedManualSourceStorage}=require('./postgres/secureshopProtectedManualSourceNative');
const ROOT=path.resolve(__dirname,'..');

test('native helper is import safe and controlled observation updates retained trace consistently',()=>{
  assert.equal(typeof runProtectedManualSourceStorage,'function');
  for(const kind of ['consumer','uploader']) {
    const original=fixture().proof[kind].original;
    const hash=original.requestHash,answer=original.result.text,params=structuredClone(original.result.hops[0].params);
    const value={controlled:true,kind};replaceControlledObservation(original,value);
    assert.deepEqual(JSON.parse(original.result.hops[0].result.content[0].text),value);
    assert.deepEqual(JSON.parse(original.traces.find(row=>row.kind==='local_tool_result').result_json),original.result.hops[0].result);
    assert.equal(original.requestHash,hash);assert.equal(original.result.text,answer);
    assert.deepEqual(original.result.hops[0].params,params);
  }
});
test('native private storage partition is inside the existing exact single test and uses no scorer or provider',()=>{
  const entry=fs.readFileSync(path.join(ROOT,'tests/postgres/secureshopManualRagSourceAdapter.integration.test.js'),'utf8');
  assert.match(entry,/if\(require\.main===module\)test\(TITLE/);
  assert.match(entry,/await require\('\.\/secureshopProtectedManualSourceNative'\)\.runProtectedManualSourceStorage\(pools\)/);
  assert.match(entry,/console\.log\('V31_PRIVATE_STORAGE_FACTS '\+JSON\.stringify\(privateFacts\)\)/);
  const source=fs.readFileSync(path.join(ROOT,'tests/postgres/secureshopProtectedManualSourceNative.js'),'utf8');
  for(const method of ['appendManualWithLineage','searchWithProtectedLineage','readRevisionPreimage',
    'readManualPreimage','createProtectedManualSourceAdapter','createProtectedManualSourceReader','products.cleanup'])assert.ok(source.includes(method),method);
  assert.match(source,/actualModel:false,judge:false,objectiveCredit:false/);
  assert.match(source,/physicalFileUpload:false,authenticatedApplicationReset:false/);
  assert.doesNotMatch(source,/createObjectiveCompletionService|createConfigured.*Judge|ollama\/|puppeteer/);
});
test('private migration preserves every public capture authority and integrity statement in a separate named function',()=>{
  const dir=path.join(ROOT,'db/postgres/workshop-migrations/secureshop_review');
  const original=fs.readFileSync(path.join(dir,'0050_product_embedding_revision_preimages.sql'),'utf8');
  const added=fs.readFileSync(path.join(dir,'0055_private_manual_original_preimages.sql'),'utf8');
  const block=source=>source.match(/CREATE FUNCTION secureshop_review\.capture_(?:private_)?product_manual_preimage\([\s\S]*?END \$\$;/)?.[0];
  assert.ok(block(original));assert.ok(block(added));
  assert.equal(block(added).replace('capture_private_product_manual_preimage','capture_product_manual_preimage')
    .replace('original.is_public IS DISTINCT FROM false','NOT original.is_public'),block(original));
  assert.match(added,/REVOKE ALL ON FUNCTION[^;]+FROM PUBLIC,dvaia_secureshop_review_runtime;/);
  assert.match(added,/GRANT EXECUTE ON FUNCTION[^;]+TO dvaia_secureshop_review_runtime;/);
  assert.doesNotMatch(added,/CREATE TABLE|ALTER TABLE|INSERT INTO[^;]+SELECT|GRANT (?:INSERT|UPDATE|DELETE)/);
});
test('native upgrade proof uses distinct fresh and populated databases with no-op and historical retrofit denial',()=>{
  const entry=fs.readFileSync(path.join(ROOT,'tests/postgres/secureshopManualRagSourceAdapter.integration.test.js'),'utf8');
  const helper=fs.readFileSync(path.join(ROOT,'tests/postgres/secureshopProtectedManualSourceNative.js'),'utf8');
  assert.match(entry,/FRESH_REVIEW:'secureshop_review'/);
  assert.match(entry,/!databases\.has\(pair\.runtime\.pathname\)/);
  assert.match(entry,/key==='REVIEW'\?beforePrivateMigration\(\):\{migrate\}/);
  assert.match(entry,/filter\(name=>name<PRIVATE_MIGRATION\)/);
  assert.match(entry,/key==='FRESH_REVIEW'\)assert\.ok\(applied\.includes\(PRIVATE_MIGRATION\),/);
  assert.match(helper,/assert\.deepEqual\(await migrate\(pools\.REVIEW\.migration,directory\),\[migration\]\)/);
  for(const key of ['REVIEW','FRESH_REVIEW'])assert.ok(helper.includes(`assert.deepEqual(await migrate(pools.${key}.migration,directory),[])`));
  assert.match(helper,/Historical manual preimage capture forbidden/);
  assert.match(helper,/assert\.deepEqual\(await saved\(\),before/);
  assert.match(helper,/assert\.equal\(await definition\(review,publicFunction\),originalPublic\)/);
  assert.match(helper,/public_execute:false/);
  assert.match(helper,/freshMigration:true,populatedMigration:true,migrationNoOp:true,runtimePrivileges:true/);
});
