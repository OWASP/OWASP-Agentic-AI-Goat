'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const {retainedEvidenceSuites,isDefaultUnitSuite}=require('../scripts/lib/retained-evidence-suites');
test('default unit classifier excludes exactly three named retained diagnostics and includes portable consistency',()=>{
 assert.deepEqual(retainedEvidenceSuites,['secureshopMailReplyAuthorityCalibration.test.js','secureshopMailHeaderJudgeCases.test.js','dpiPracticeRetainedReplay.test.js']);
 const server=new Set(['api.test.js']);for(const name of retainedEvidenceSuites)assert.equal(isDefaultUnitSuite(name,server),false);
 assert.equal(isDefaultUnitSuite('secureshopMailReplyAuthorityConsistency.test.js',server),true);assert.equal(isDefaultUnitSuite('secureshopMailEvidence.test.js',server),true);assert.equal(isDefaultUnitSuite('api.test.js',server),false);
});
test('direct retained qualification without opt-in fails before reading retained inputs',()=>{
 for(const name of retainedEvidenceSuites){const env={...process.env};delete env.DVAIA_RETAINED_EVIDENCE_TESTS;const r=spawnSync(process.execPath,[`tests/${name}`],{env,encoding:'utf8'});assert.notEqual(r.status,0);assert.match(r.stderr,/requires DVAIA_RETAINED_EVIDENCE_TESTS=1/);assert(!r.stderr.includes('ENOENT'));}
});
