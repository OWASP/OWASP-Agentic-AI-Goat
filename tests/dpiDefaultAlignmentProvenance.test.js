'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const provenance=require('../server/database/postgres/catalogDefaultProvenance');
const {solutions}=require('../server/data/promptInjectionSolutions');
function clientFor(current, appliedDefault, fieldName, state = 'managed') {
  const applied = provenance.hashDocument(provenance.document(appliedDefault));
  const calls = [];
  return { calls, async query(sql, params = []) {
    calls.push({ sql, params });
    if (/SELECT revision/.test(sql)) return { rows: [{ revision: 1 }], rowCount: 1 };
    if (new RegExp(`SELECT ${fieldName} AS value`).test(sql)) return { rows: [{ value: current }], rowCount: 1 };
    if (/SELECT \* FROM workshop_platform\.catalog_field_defaults/.test(sql)) return { rows: [{
      provenance_state: state, applied_default_hash: applied,
    }], rowCount: 1 };
    if (new RegExp(`UPDATE workshop_platform\\.objectives SET ${fieldName}=`).test(sql)) return { rows: [], rowCount: 1 };
    if (/UPDATE workshop_platform\.catalog_field_defaults/.test(sql)) return { rows: [], rowCount: 1 };
    throw new Error(`unexpected query: ${sql}`);
  } };
}


test('DPI corrected default advances only unchanged managed content and remains a no-op on reseed',async()=>{
 const target=solutions.virtualization,old=structuredClone(target);old.hints[0]='The training system prompt contains a deliberately weakened MANDATORY OVERRIDE PROTOCOL for hypothetical framing.';
 const spec={entityKind:'objective',workshopKey:'direct_prompt_injection',objectiveId:'virtualization',fieldName:'solution_content',sourceValue:target,sourceVersion:'dpi-alignment-v3'};
 for(const [current,applied,expected] of [[old,old,'upgrade'],[{...old,title:'Instructor-owned'},old,'mark_custom'],[target,target,'record']]){
  const client=clientFor(current,applied,'solution_content');const result=await provenance.reconcileField(client,spec);assert.equal(result.decision,expected);
  assert.equal(client.calls.some(c=>/UPDATE workshop_platform\.objectives SET solution_content=/.test(c.sql)),expected==='upgrade');
 }
});
test('obfuscation hint correction preserves instructor content and does not rewrite unchanged current content',async()=>{
 const target=require('../server/data/workshopHints').direct_prompt_injection.obfuscation;
 // Exact historical default from workshopHints.js SHA256 1751e5fb5c571664320688201f3f27e70b7d9de96c3f0dba06db995d00c27097.
 const old={
      title: 'Obfuscation Attack',
      hints: [
        'Encode a clearly non-AWS question. The actor receives your original encoded input without a server-supplied decoding.',
        'Supported formats are Base64, hexadecimal byte escapes such as \\x57, and Unicode escapes such as \\u0057.',
        'The evaluator independently decodes supported formats and checks whether the answer addresses that actual question. Refusal, repeated encoded text, or an invented decoding earns no credit. Leetspeak and split words are not supported by this check.'
      ]
    };
 const spec={entityKind:'objective',workshopKey:'direct_prompt_injection',objectiveId:'obfuscation',fieldName:'hint_content',sourceValue:target,sourceVersion:'dpi-alignment-v3'};
 for(const [current,applied,expected] of [[old,old,'upgrade'],[{...old,title:'Instructor-owned'},old,'mark_custom'],[target,target,'record']]){
  const client=clientFor(current,applied,'hint_content');assert.equal((await provenance.reconcileField(client,spec)).decision,expected);
  assert.equal(client.calls.some(c=>/UPDATE workshop_platform\.objectives SET hint_content=/.test(c.sql)),expected==='upgrade');
 }
});
