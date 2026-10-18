const{test}=require('node:test'),assert=require('node:assert/strict');
const{runEmailTemplateGraph}=require('../server/agent-runtime/emailTemplateGraph');
test('graph preserves native whole-template replacements while distinguishing inserted handler code',async()=>{
 for(const name of ['Alice','alert(4)',"$`|$&|$'|$$"]){
  const raw='<p>{{name}}</p><img src=x onclick="void 0" onerror="{{name}}">';let proof;
  const result=await runEmailTemplateGraph({userId:1,prompt:'fixture'}, {decisionMode:'scripted',loadProfile:async()=>({id:1,full_name:name}),saveTemplate:async()=>7,aiService:{generateResponse:async()=>({response:raw,model:'fixture'})},onProvenance:p=>{proof=p;}});
  assert.equal(result.template.html,raw.replace(/\{\{name\}\}/g,name));assert.equal(proof.html,result.template.html);
  assert.ok(proof.modelRanges.some(r=>proof.html.slice(r.start,r.end).includes('void 0')));
  if(name==='alert(4)'){const injected=proof.html.lastIndexOf(name);assert.ok(!proof.modelRanges.some(r=>r.start<=injected&&r.end>=injected+name.length));}
  assert.equal(Object.hasOwn(result,'modelRanges'),false);
 }
});

test('large profile substitution and appended signature preserve native output without argument spread limits',()=>{
 const {createTemplateProvenance}=require('../server/agent-runtime/emailTemplateProvenance');
 const value='x'.repeat(200*1024),raw='<p>{{name}}</p><img onerror=alert(1)>';
 const tracked=createTemplateProvenance(raw).replace(/\{\{name\}\}/g,value).append(value);
 assert.equal(tracked.html,raw.replace(/\{\{name\}\}/g,value)+value);
 assert.deepEqual(tracked.snapshot().modelRanges,[{start:0,end:3},{start:3+value.length,end:raw.length-8+value.length}]);
});

test('template generation uses placeholders while unsafe profile substitution remains a real server effect', async () => {
 const payload='<script>alert(41)</script>',company='<img src=x onerror="alert(43)">'; let seen; let stored;
 const result=await runEmailTemplateGraph({userId:1,prompt:'Business greeting'}, {
  decisionMode:'scripted',
  loadProfile:async()=>({id:1,full_name:payload,company_name:company}),
  aiService:{generateResponse:async prompt=>{seen=prompt;return {response:'<p>{{name}} at {{company}}</p>',model:'fixture'};}},
  saveTemplate:async params=>{stored=params;return 7;},
 });
 assert.ok(seen.includes('{{name}}'));assert.ok(seen.includes('{{company}}'));
 assert.ok(!seen.includes(payload));assert.ok(!seen.includes(company));
 assert.equal(result.template.html,`<p>${payload} at ${company}</p>`);assert.equal(stored[4],result.template.html);
});


test('synthetic HTML training policy is scoped to vulnerable builder level four', async () => {
 for (const [mode,challengeLevel,allowed] of [['vuln',4,true],['fixed',4,false],['vuln',1,false],['vuln',2,false],['vuln',3,false],[undefined,4,false]]) {
  const prompts=[];
  await runEmailTemplateGraph({userId:1,prompt:'Create a training email',mode,challengeLevel}, {
   decisionMode:'scripted',loadProfile:async()=>({id:1,full_name:'Synthetic Learner'}),saveTemplate:async()=>1,
   aiService:{generateResponse:async prompt=>{prompts.push(prompt);return {response:'<p>Example</p>',model:'fixture'};}}
  });
  assert.equal(prompts.length,1);
  assert.equal(prompts[0].includes('isolated, synthetic HTML security-training preview'),allowed,`${mode}/${challengeLevel}`);
 }
});
