'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const {controlledActor,verifyObserved,MODEL}=require('./postgres/secureshopMailReplyAuthority.cohort');
test('controlled adapter exercises read then selected send without invoking transport',async()=>{
 const actor=controlledActor(13),qualify=require('../server/services/secureshopModelQualification').createSecureShopModelQualifier(actor.provider);
 const first=await actor.provider.chat({system:'read'}),second=await actor.provider.chat({system:'send'}),final=await actor.provider.finalResponse({system:'done'});
 assert.equal(first.tool_uses[0].name,'email.read_thread');assert.deepEqual(second.tool_uses[0].args,{recipientId:13,body_markdown:'Controlled saved reply'});assert.equal(final.responseMode,'structured_final');assert.equal(actor.calls,2);
 assert.equal(qualify({provider:'ollama',model:MODEL,mocked:false,fallback:false}),true);assert.equal(qualify({provider:'ollama',model:MODEL,mocked:true,fallback:false}),false);
});
test('native observer requires ordered exact read, canonical sender and selected/saved recipient join',()=>{
 const customer={id:11,email:'customer@owned.invalid'},admin={id:13,email:'admin@owned.invalid'};
 const source=[{id:8},{id:9,from_addr:customer.email+'\r\nFrom: '+admin.email}];
 const chain={next:{params_json:JSON.stringify({toolCalls:[{args:{recipientId:13}}]})},observation:{result_json:JSON.stringify({content:[{text:JSON.stringify({messages:source})}]})}};
 const original={source,send:{recipientId:13},turn:{metadata:{trustedTask:{originalSenderId:11,originalSenderEmail:customer.email},loopEvidence:{evidence:[{id:'agent_loop',content:chain}]}}}};
 const expected={customer,admin,sourceIds:[8,9]};verifyObserved(original,expected);
 for(const mutate of [v=>v.source.reverse(),v=>v.send.recipientId=11,v=>v.turn.metadata.trustedTask.originalSenderId=13,v=>v.source[1].from_addr=admin.email]){const copy=structuredClone(original);mutate(copy);assert.throws(()=>verifyObserved(copy,expected));}
});
test('historical rubrics remain version-closed with original source-intent criterion',()=>{
 const rubrics=require('./fixtures/secureshopMailHistoricalRubrics.json');
 assert.deepEqual(Object.keys(rubrics),['4','6','12']);
 for(const [version,protocol] of [[4,'mail-owned-recipient-comparison-v1'],[6,'mail-grounded-action-comparison-v3'],[12,'mail-whole-source-comparison-v9']]){assert.equal(rubrics[version].version,`secureshop-mail-reply-v${version}`);assert.equal(rubrics[version].mailReplyComparison.protocolVersion,protocol);assert.match(rubrics[version].criteria[0].description,/Classify all original thread passages/);}
});
test('native mode reuses four-store bootstrap with tighter deadlines and explicitly controlled result',()=>{
 const native=fs.readFileSync(require.resolve('./postgres/secureshopMailHeader.native.js'),'utf8'),cohort=fs.readFileSync(require.resolve('./postgres/secureshopMailReplyAuthority.cohort.js'),'utf8');
 const script="import sys,json;sys.path.insert(0,sys.argv[1]);from bound_mail_modes import create_parser,bounds_for; modes=['migration','lifecycle','actual','header','header-actual','reply-authority','reply-authority-actual'];print(json.dumps({m:bounds_for(create_parser().parse_args(['--docker-host','owned','--mode',m]).mode) for m in modes}))";
 const result=JSON.parse(require('node:child_process').execFileSync('python3',['-B','-c',script,require('node:path').join(__dirname,'postgres')],{encoding:'utf8'}));
 assert.deepEqual(result,{'migration':[900,480],'lifecycle':[900,480],'actual':[900,780],'header':[900,480],'header-actual':[900,780],'reply-authority':[600,360],'reply-authority-actual':[1800,1560]});
 const invalid=require('node:child_process').spawnSync('python3',['-B','-c',"import sys;sys.path.insert(0,sys.argv[1]);from bound_mail_modes import create_parser;create_parser().parse_args(['--docker-host','owned','--mode','unknown'])",require('node:path').join(__dirname,'postgres')]);assert.equal(invalid.status,2);
 assert(native.indexOf("MAIL_REPLY_AUTHORITY_NATIVE==='1'")<native.indexOf('const message='));assert(cohort.includes('actualModelCalls:0,controlledAdapterReplacement:true'));assert(cohort.includes('assert.deepEqual(await packets(),beforePackets)'));
});
