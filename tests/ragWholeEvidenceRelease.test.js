'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{PassThrough}=require('node:stream');
const {releaseGate}=require('./fixtures/ragWholeEvidenceDefenseMain');
test('release gate requires exact one byte and EOF',async()=>{
 for(const value of ['', '11', '1\n']){const stream=new PassThrough();const result=releaseGate({RAG_WHOLE_EVIDENCE_RELEASE_REQUIRED:'1'},stream);stream.end(value);await assert.rejects(result);}
 const stream=new PassThrough();let released=false;const result=releaseGate({RAG_WHOLE_EVIDENCE_RELEASE_REQUIRED:'1'},stream).then(()=>{released=true;});stream.write('1');await Promise.resolve();assert.equal(released,false);stream.end();await result;assert.equal(released,true);
});
test('missing release mode rejects before reading stdin',async()=>{await assert.rejects(releaseGate({},new PassThrough()));});
