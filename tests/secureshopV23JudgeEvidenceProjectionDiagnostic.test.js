'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const d=require('./postgres/secureshopV23JudgeEvidenceProjectionDiagnostic');
const retained=require('./postgres/secureshopV23JudgePresentationDiagnostic');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
function seal(e){return {evidence:e,evidenceSha256:canonicalDigest(e)};}
// Generic synthetic datum controls are not original actor evidence.
function synthetic(measured=null){
 const args={stdio_cmd:'synthetic command'},effect={stdioEffect:measured};
 const proof={state:'completed',operationId:'op',requestSha256:'a'.repeat(64),instanceId:'instance',changes:[{endpoint:args.stdio_cmd,effect}]};
 return seal({refs:[...d.REFS],runId:'run',suppliedCommand:args.stdio_cmd,selectedArgs:args,finalText:'untrusted final',effect:measured,
 observation:{tool:'mcp-registry.register',callId:'call',step:1,args,result:{receipt:structuredClone(proof)}},
 registrationLinks:[{record:{envelope:{runId:'run',callId:'call',args,argsSha256:canonicalDigest(args),requestSha256:proof.requestSha256},receipt:{state:'completed',drained:true,proof}}}]});
}
test('generic reference projection preserves null and measured data without inferred awards',()=>{
 for(const measured of [null,{text:'arbitrary bytes',bytes:15,sha256:createHash('sha256').update('arbitrary bytes').digest('hex')}]){
  const p=synthetic(measured),view=d.project(p);assert.deepEqual(view.dataByReference['durable-effect'].observation,measured);
  assert.deepEqual(Object.keys(view.dataByReference),d.REFS);
  for(const forbidden of ['kind','expected','selectedExactCommand','additionalShellEffect','passed'])assert(!JSON.stringify(view).includes('"'+forbidden+'":'));
 }
});
test('missing, contradictory, wrong command/reference/hash/receipt all reject',()=>{
 const mutations=[e=>delete e.effect,e=>delete e.registrationLinks[0].record.receipt.proof.changes[0].effect.stdioEffect,
 e=>e.effect={},e=>e.observation.result.receipt.changes[0].effect.stdioEffect={},e=>e.refs.push('invented'),
 e=>e.suppliedCommand='other',e=>e.registrationLinks[0].record.envelope.argsSha256='0'.repeat(64),
 e=>e.registrationLinks[0].record.receipt.drained=false,e=>e.observation.result.receipt.requestSha256='wrong'];
 for(const mutate of mutations){const e=structuredClone(synthetic().evidence);mutate(e);assert.throws(()=>d.project(seal(e)));}
 const p=synthetic();p.evidenceSha256='0'.repeat(64);assert.throws(()=>d.project(p));
});
test('both pinned genuine packets reconstruct from original terminals; original instruction/schema/model retained',t=>{
 const {inputs,missing}=retained.loadInputs(retained.COMBINED_VERSION);
 if(missing.length){t.skip('Private retained capture absent; synthetic controls are not evidence');return;}
 const packets=[inputs['positive-case-evidence.json'],inputs['benign-case-evidence.json']],wire=inputs['v23-original-wire.json'];
 const out=d.prepare(packets,wire);assert.equal(out.length,2);
 for(let i=0;i<2;i++){
  const original=JSON.parse(wire.judges[i].request),item=out[i];
  assert.deepEqual({...item.request,messages:original.messages},original);
  assert.deepEqual(item.request.messages[0],original.messages[0]);
  assert.deepEqual(item.provenance.rawPacket,packets[i].packet);assert.equal(item.provenance.terminalSha256,canonicalDigest(packets[i].terminal));
  assert.equal(item.canonicalCredit,false);assert.equal(item.qualificationComplete,false);
  assert.deepEqual(item.judgeView.dataByReference['durable-effect'].observation,packets[i].packet.evidence.effect);
 }
 for(const mutate of [w=>w.judges[0].requestSha256='0'.repeat(64),w=>w.modelDigest='0'.repeat(64)]){const w=structuredClone(wire);mutate(w);assert.throws(()=>d.prepare(packets,w));}
 const wrong=structuredClone(packets);wrong[0].terminal.text='substituted';assert.throws(()=>d.prepare(wrong,wire));
});
test('pinned input reader skips only ENOENT and rejects corrupt/inaccessible present captures',()=>{
 assert.equal(retained.loadInputs(retained.COMBINED_VERSION,()=>{throw Object.assign(Error('missing'),{code:'ENOENT'});}).missing.length,3);
 assert.throws(()=>retained.loadInputs(retained.COMBINED_VERSION,()=>Buffer.from('{}')));
 assert.throws(()=>retained.loadInputs(retained.COMBINED_VERSION,()=>{throw Object.assign(Error('denied'),{code:'EACCES'});}));
});
