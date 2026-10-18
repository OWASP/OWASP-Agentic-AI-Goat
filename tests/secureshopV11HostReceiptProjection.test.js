'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const host = path.join(__dirname, 'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js');
const source = fs.readFileSync(host, 'utf8');
const contract = require('./fixtures/secureshopMailAgentReadRenderedQualification');
const start = source.indexOf("      const v11Contract = require('../fixtures/secureshopMailAgentReadRenderedQualification');");
const projection = source.slice(start, source.indexOf('      assert.deepEqual(pageErrors, []);', start));
const deletionStart = source.indexOf('    if (MAIL_HTML_BROWSER || V11_MAIL_READ_BROWSER) { delete status.actorCalls;');
const writerStart = source.indexOf('    if (!V03_BROWSER) {\n      const receipt =', deletionStart);
const cleanupStart = source.indexOf("  if (cleanupErrors.length) throw new AggregateError(cleanupErrors, 'Role-choice qualification cleanup or receipt failed');", writerStart);
const writer = source.slice(writerStart, source.lastIndexOf('\n  }', cleanupStart));
const validation = source.slice(cleanupStart, source.indexOf('\n  else assertPrivateReceipt(', cleanupStart));
assert(start > 0 && deletionStart > start && writerStart > deletionStart && cleanupStart > writerStart);
assert.match(validation, /assertReceipt\(v11FinalReceipt\)/);
const deletion = source.slice(deletionStart, source.indexOf('\n', deletionStart));
// Compile the installed host projection, generic cleanup deletion, private
// writer and final consumer together, without registering the native suite.
const execute = new (Object.getPrototypeOf(async function () {}).constructor)(
  'status', 'cleanupErrors', 'pageErrors', 'failure', 'fs', 'require', 'structuredClone',
  `let v11FinalReceipt=null; const V11_MAIL_READ_BROWSER=true, MAIL_HTML_BROWSER=false,
   V03_BROWSER=false, evidencePath='/private/controlled-receipt.json';
   ${projection}\n${deletion}\n${writer}\n${validation}\nreturn v11FinalReceipt;`);

function receipt(hops=1, judges=1) {
  return { ...Object.fromEntries(contract.V11_FLAGS.map(key=>[key,true])),
    scope:contract.V11_SCOPE, actorCalls:11+hops, deniedHopCount:hops, judgeCalls:judges,
    roleTurns:6, assessmentPosts:2, savedAssessmentGets:1, genuineCredit:1, errors:[] };
}
async function run(value, {cleanupErrors=[], pageErrors=[], failure, writeError}={}) {
  const writes=[];
  const result=await execute(value,cleanupErrors,pageErrors,failure,{async writeFile(target,bytes,options){
    assert.equal(target,'/private/controlled-receipt.json');
    assert.deepEqual(options,{flag:'wx',mode:0o600});
    if(writeError)throw writeError;
    writes.push(JSON.parse(bytes));
  }},createRequire(host),structuredClone);
  return {result,writes};
}

test('actual V11 host retains exact observed receipt through generic cleanup and final validation',async()=>{
  for(const [hops,judges] of [[1,1],[1,2],[2,1]]) {
    const expected={...receipt(hops,judges),fixtureLocalCandidateAdmission:false};
    const status={...expected,merchantRenderedSearch:false,ownedMailSeeded:true};
    const {result,writes}=await run(status);
    assert.deepEqual(result,expected);
    assert.deepEqual(writes,[expected]);
    assert.equal(status.actorCalls,undefined); // Existing generic deletion really executed.
    assert.equal(status.roleTurns,undefined);
    assert.equal(result.deniedHopCount,hops);
  }
});
test('actual V11 host cannot invent missing proof or relax observed call accounting',async()=>{
  const absent=receipt();delete absent.deniedHopCount;
  for(const value of [absent,{...receipt(),actorCalls:13},{...receipt(2,2)},
    {...receipt(),fixedIneligible:false},{...receipt(),roleTurns:5}]) await assert.rejects(()=>run(value));
});
test('actual V11 host preserves cleanup, page and original failures',async()=>{
  const original=new Error('original qualification failure');
  await assert.rejects(()=>run(receipt(),{failure:original}),error=>error===original);
  await assert.rejects(()=>run(receipt(),{cleanupErrors:[new Error('cleanup failed')]}),AggregateError);
  await assert.rejects(()=>run(receipt(),{writeError:new Error('receipt write failed')}),AggregateError);
  await assert.rejects(()=>run(receipt(),{pageErrors:[{name:'page failure'}]}));
});
