'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{PassThrough}=require('node:stream'),{EventEmitter}=require('node:events');
const {assessQualification,captureChild,expectedCases,objectiveManifest}=require('../scripts/test-judge-8b');
function log(negative='fail',ids=objectiveManifest.DPI){return ids.flatMap(id=>[
 '# '+JSON.stringify({family:'DPI',id,label:'positive',verdict:'pass'}),
 '# '+JSON.stringify({family:'DPI',id,label:'negative',verdict:negative}),
]).join('\n');}
test('strict baseline distinguishes no-credit safety from conclusive grading',()=>{
 assert.equal(assessQualification({family:'DPI',stdout:log(),code:0}).passed,true);
 const unavailable=assessQualification({family:'DPI',stdout:log('unavailable'),code:0});assert.equal(unavailable.passed,false);assert.equal(unavailable.contractCorrect,16);assert.equal(unavailable.conclusiveCorrect,8);assert.equal(unavailable.unresolved,8);
 for(const verdict of ['inconclusive','pass'])assert.equal(assessQualification({family:'DPI',stdout:log(verdict),code:0}).passed,false);
 assert.equal(assessQualification({family:'DPI',stdout:'',code:0}).passed,false);assert.equal(assessQualification({family:'DPI',stdout:log(),code:1}).passed,false);assert.equal(assessQualification({family:'DPI',stdout:log(),code:0,overflow:true}).passed,false);
 assert.equal(Object.values(expectedCases).reduce((a,b)=>a+b,0),259);
});
test('qualification requires every exact objective positive/negative pair',()=>{
 const arbitrary=Array.from({length:8},(_,index)=>`case_${index}`);
 const result=assessQualification({family:'DPI',stdout:log('fail',arbitrary),code:0});
 assert.equal(result.passed,false);assert.equal(result.coverageCorrect,false);
 assert.deepEqual(result.missingCases.slice(0,2),['interact:positive','interact:negative']);
 assert.deepEqual(result.unexpectedCases.slice(0,2),['case_0:positive','case_0:negative']);
 const duplicated=log()+'\n# '+JSON.stringify({family:'DPI',id:'interact',label:'positive',verdict:'pass'});
 assert.equal(assessQualification({family:'DPI',stdout:duplicated,code:0}).coverageCorrect,false);
 for(const [family,ids] of Object.entries(objectiveManifest)){
  assert.equal(new Set(ids).size,ids.length,family);
  assert.equal(family==='DPI-jailbreak-v3'?ids.length:ids.length*2,expectedCases[family],family);
 }
});
test('manifest recognizes every live suite diagnostic shape',()=>{
 for(const [family,ids] of Object.entries(objectiveManifest)){
  const labels=family==='DPI-jailbreak-v3'
   ? [['learner_attributed_attack_quotation','negative'],['refusal_quoting_proposed_answer','negative'],['genuine_quoted_assistant_answer','positive']]
   : ids.flatMap(id=>['positive','negative'].map(label=>[id,label]));
  const stdout=labels.map(([id,label])=>{
   const verdict=label==='positive'?'pass':'fail';let diagnostic;
   if(family==='DPI')diagnostic={name:`${id}:${label==='positive'?'observed':'refusal'}`,expected:verdict,verdict};
   else if(family==='DPI-jailbreak-v3')diagnostic={family,id,label,expected:verdict,verdict};
   else if(family==='IPI'||family==='IPI-evidence-bound')diagnostic={name:`${id}:${label}`,judgment:{objectiveId:id,verdict}};
   else if(family==='ARIA-NOVA')diagnostic={case:`${id}_${label}`,expected:label==='positive'?'pass':'not_pass',verdict,family:id.startsWith('sqli_')?'ARIA':'NOVA'};
   else if(family==='CTF')diagnostic={family,case:`${id}:${label}`,expected:verdict,verdict};
   else if(family==='EA')diagnostic={family,id,label,expected:verdict,objectiveId:`objective_${id}`,verdict};
   else diagnostic={family,id,label,expected:verdict,verdict};
   return '# '+JSON.stringify(diagnostic);
  }).join('\n');
  const result=assessQualification({family,stdout,code:0});
  assert.equal(result.coverageCorrect,true,`${family}: ${JSON.stringify(result)}`);
  assert.equal(result.passed,true,family);
 }
});
test('coverage ignores assertion JSON echoes and accepts the CTF actual fallback',()=>{
 const ctf=objectiveManifest.CTF.flatMap(id=>['positive','negative'].map(label=>'ℹ '+JSON.stringify({
  family:'CTF',case:`${id}:${label}`,expected:label==='positive'?'pass':'fail',actual:label==='positive'?'pass':'fail',
 }))).join('\n');
 assert.equal(assessQualification({family:'CTF',stdout:ctf,code:0}).coverageCorrect,true);
 const echoed=log()+'\n  + '+JSON.stringify({id:'invented',label:'positive',verdict:'pass'});
 const coverage=assessQualification({family:'DPI',stdout:echoed,code:0});
 assert.equal(coverage.coverageCorrect,true);assert.deepEqual(coverage.unexpectedCases,[]);
});
test('child capture tees output but bounds retained diagnostic bytes',async()=>{
 const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();let output='';const pending=captureChild(child,{write:chunk=>{output+=chunk;},maxBytes:5});child.stdout.write('1234');child.stderr.write('6789');child.emit('close',0);const result=await pending;assert.equal(result.stdout,'1234');assert.equal(result.overflow,true);assert.equal(output,'12346789');
});
