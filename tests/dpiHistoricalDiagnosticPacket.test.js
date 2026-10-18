'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {historicalPacket,currentV14Packet}=require('./fixtures/dpiHistoricalDiagnosticPacket');
test('historical diagnostic wrappers bind preserved protocols separately from current admission',async()=>{
 const row=require('./fixtures/dpiIndependentHeldoutV2.json')[0];
 const {packet:historical}=await require('./fixtures/dpiContentWitnessDiagnostic').packetFor(row);
 assert.equal(historical.rubric.dpiAnswerComparison.protocolVersion,'dpi-answer-comparison-v8');
 assert.throws(()=>historicalPacket(historical,12));
 assert.throws(()=>historicalPacket(historical,14),/Closed historical/);
 for(const [module,version,protocol] of [['dpiContentWitnessDiagnostic',11,8],['dpiContentWitnessV12Diagnostic',12,9],['dpiExistentialDiagnostic',13,10]]){
  const {packet,provenance}=await require('./fixtures/'+module).packetFor(row);
  assert.equal(packet.rubric.version,`dpi-${row.objective}-v${version}`);
  assert.equal(packet.rubric.dpiAnswerComparison.protocolVersion,`dpi-answer-comparison-v${protocol}`);
  assert.equal(provenance.canonicalCredit,false);
 }
});
test('v15 projection preserves owned evidence and rejects stale or unbound inputs',async()=>{
 const row=require('./fixtures/dpiIndependentHeldoutV2.json').find(item=>item.objective==='obfuscation');
 const {packet:historical}=await require('./fixtures/dpiTaskContributionDiagnostic').packetFor(row);
 assert.equal(historical.rubric.version,'dpi-obfuscation-v14');
 assert.equal(historical.rubric.dpiAnswerComparison.protocolVersion,'dpi-answer-comparison-v11');
 assert.equal(historical.evidence.find(item=>item.id==='decoded_request').content.decodedRequest,row.task);
 assert.equal(historical.evidence.find(item=>item.id==='response').content,row.response);
 assert.equal(historical.facts.owned_decoder_observed,true);
 assert.throws(()=>currentV14Packet(historical));
 const forged={...historical,rubric:{...historical.rubric,version:'dpi-obfuscation-v15',dpiAnswerComparison:{...historical.rubric.dpiAnswerComparison,protocolVersion:'dpi-answer-comparison-v14'},dpiPolicyBinding:'dpi-policy-binding-v2'},evidence:[...historical.evidence,{id:'owned_policy',source:'server_observation',content:{version:'dpi-policy-binding-v2'}}]};
 assert.throws(()=>currentV14Packet(forged));
 for(const id of ['request','response','owned_decoder','decoded_request']){
  const missing={...historical,rubric:structuredClone(historical.rubric),evidence:structuredClone(historical.evidence),facts:structuredClone(historical.facts)};
  missing.rubric.version='dpi-obfuscation-v15';
  missing.rubric.dpiAnswerComparison.protocolVersion='dpi-answer-comparison-v14';
  missing.evidence=missing.evidence.filter(item=>item.id!==id);
  assert.throws(()=>currentV14Packet(missing),id);
 }
});
