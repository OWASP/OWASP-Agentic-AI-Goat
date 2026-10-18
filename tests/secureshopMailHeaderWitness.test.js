'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {buildV2MailHeaderCandidate:build,buildLegacyMailHeaderCandidate:legacy,candidateForVersion,V2_MAIL_HEADER_RUBRIC:MAIL_HEADER_RUBRIC}=require('../server/services/secureshopMailHeaderEvidence');
function input(field='subject',value='😀hello\r\nBcc: owned@lab'){const payload={from:'merchant@lab',to:'customer@lab',subject:'hello'};payload[field]=value;payload.headers_raw=`From: ${payload.from}\r\nTo: ${payload.to}\r\nSubject: ${payload.subject}`;return {binding:{mode:'vuln',persona:{id:2}},payload,receipt:{senderId:2,email_id:3,thread_id:4,contentSha256:'a'.repeat(64)},requestSha256:'b'.repeat(64)};}
test('witness offsets are exact UTF16 code units in each field and stored construction, including lone CR/LF',()=>{
 for(const field of ['from','to','subject'])for(const value of ['😀hello\r\nBcc: owned@lab','x\ry','x\ny']){
  const e=input(field,value),p=build(e).evidence[1].content;assert.equal(p.offsetUnit,'UTF-16 code units');assert.equal(p.originalHeaders[field],value);
  for(const w of p.boundaries){assert.equal(w.field,field);assert.equal(value.charCodeAt(w.sourceOffset),w.codePoint);assert.equal(e.payload.headers_raw.charCodeAt(w.storedOffset),w.codePoint);assert.match(w.description,/Original .* field at UTF-16/);}
 }
});
test('caller witness ignored; literal escapes, normal separators, altered bytes and excessive witnesses denied',()=>{
 const e=input();assert.deepEqual(build({...e,witness:{satisfied:true}}),build(e));
 assert.equal(build(input('subject','hello\\r\\nBcc: literal')),null);assert.equal(build(input('subject','hello')),null);
 assert.equal(build({...e,payload:{...e.payload,headers_raw:e.payload.headers_raw+'changed'}}),null);
 assert.equal(build(input('subject','\n'.repeat(65))),null);assert.equal(build(input('subject','x'.repeat(2048)+'\n')),null);
});
test('immutable v1 reconstruction remains exact and unknown or crossed versions fail closed',()=>{
 const e=input(),old=legacy(e),before=JSON.stringify(old);assert.deepEqual(candidateForVersion(e,{rubricVersion:'secureshop-mail-header-v1',contentVersion:1}),old);assert.equal(JSON.stringify(old),before);
 assert.equal(candidateForVersion(e,{rubricVersion:'secureshop-mail-header-v2',contentVersion:2}).evidence.length,2);
 for(const pair of [{rubricVersion:'secureshop-mail-header-v1',contentVersion:2},{rubricVersion:'unknown',contentVersion:1}])assert.throws(()=>candidateForVersion(e,pair),/Unsupported/);
 assert.equal(MAIL_HEADER_RUBRIC.criterionScoped,true);assert.deepEqual(MAIL_HEADER_RUBRIC.criteria[0].evidenceIds,['header_boundary']);
});
test('shared scoped Judge excludes binding metadata and rejects authority-only citations',async()=>{
 const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');const e=input();e.binding.privateMarker='UNRELATED_BINDING_TEXT';const candidate=build(e);let calls=0;
 const judge=createObjectiveJudge({model:{generate:async args=>{calls++;assert.equal(JSON.stringify(args).includes('UNRELATED_BINDING_TEXT'),false);return {response:JSON.stringify({satisfied:true,citations:[{evidenceId:'mail_header',quote:'UNRELATED_BINDING_TEXT'}]})};}}});
 const result=await judge({rubric:{...MAIL_HEADER_RUBRIC,mode:'vuln'},...candidate,execution:{check:async()=>{}}});assert.equal(result.verdict,'unavailable');assert.equal(calls,2);
});
test('complete candidate respects shared admission budget, including duplicated originals and authority',()=>{
 const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
 const ordinary=build(input());assert.ok(ordinary);assert.equal(prepareJudgeInput({rubric:{...MAIL_HEADER_RUBRIC,mode:'vuln'},...ordinary}).evidenceError,undefined);
 let lastAccepted=0,firstDenied=0;
 for(let n=100;n<=2040;n+=20){const e=input('subject','x'.repeat(n)+'\n');e.payload.from='f'.repeat(n);e.payload.to='t'.repeat(n);e.payload.headers_raw=`From: ${e.payload.from}\r\nTo: ${e.payload.to}\r\nSubject: ${e.payload.subject}`;const candidate=build(e);if(candidate){lastAccepted=n;assert.equal(prepareJudgeInput({rubric:{...MAIL_HEADER_RUBRIC,mode:'vuln'},...candidate}).evidenceError,undefined);}else if(!firstDenied)firstDenied=n;}
 assert.ok(lastAccepted>0);assert.ok(firstDenied>lastAccepted);
 const e=input();e.binding.extra='x'.repeat(24000);assert.equal(build(e),null);
});
