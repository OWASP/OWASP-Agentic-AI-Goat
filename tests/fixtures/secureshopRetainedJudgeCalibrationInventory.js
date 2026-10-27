'use strict';
// Offline inventory, not a grader or model-packet factory. Private bytes never
// leave this module; refs describe exact retained bytes, not semantic truth.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const ROOT=path.resolve(__dirname,'../..'),VERSION='retained-judge-calibration-inventory-v1';
const MAX=4*1024*1024,sha=b=>createHash('sha256').update(b).digest('hex');
const freeze=x=>{if(x&&typeof x==='object'){Object.values(x).forEach(freeze);Object.freeze(x);}return x;};
const CAPTURES=freeze([
 ['V15','positive','run-9bq4qn5o/scene-audit-v15-original-evidence.json','39d4afc61d6eec5031fb917134d38a09a66e5dbc3c56528d6bbbb24a5eb5c225'],
 ['V15','benign','run-i1wjctt8/scene-audit-v15-benign-original-evidence.json','5ae7448104491a5de44537a8b1720a1c3984d6bb34287493f059e53a91bb27e8'],
 ['V16','positive','run-zyk4y3n8/product-similar-original-wire.json','a741db72ea9db86a31b2236356846b2a3e0a9355f8d64c1a5c0b70c28995942f'],
 ['V21','positive','run-nza7j3mn/user-lookup-disclosure-capture.json','ee979373915955e7c8c5b6408a40c6b831e6a275b43c17002e6a66f05b354f6b'],
 ['V21','benign','run-9d1tszt2/user-lookup-disclosure-capture.json','95b8d30bc6691169c90b11545889d228ca4c6397c47e914c80a39b6a4a67344f'],
 ['V27','paired','run-bgp5vakt/standalone-ssrf-rendered/standalone-ssrf-capture.json','c81459a69d4239d94220c0e407038d830e1ad6da1b996cc3d2f3db7783ec798f'],
]);
function read(relative,pin){
 const file=path.join(ROOT,relative);assert.equal(fs.realpathSync(file),file);
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const a=fs.fstatSync(fd,{bigint:true});assert(a.isFile()&&a.nlink===1n&&a.uid===BigInt(process.getuid())&&a.size>0n&&a.size<=BigInt(MAX));
  const b=Buffer.alloc(Number(a.size)+1);let n=0,k;while(n<b.length&&(k=fs.readSync(fd,b,n,b.length-n,null)))n+=k;
  const z=fs.fstatSync(fd,{bigint:true});for(const key of ['dev','ino','size','mtimeNs','ctimeNs'])assert.equal(a[key],z[key]);assert.equal(n,Number(a.size));
  const bytes=b.subarray(0,n);if(pin)assert.equal(sha(bytes),pin,'Retained bytes changed');return bytes;
 }finally{fs.closeSync(fd);}
}
function reference(file,pointer,value,encoding='json-value'){
 assert.notEqual(value,undefined,'Missing retained reference '+pointer);
 const bytes=Buffer.from(encoding==='utf8'?value:JSON.stringify(value));
 return {file,pointer,encoding,bytes:bytes.length,sha256:sha(bytes)};
}
function inventory(){
 const controls=[],packets=new Map();
 for(const [scenario,role,relative,pin]of CAPTURES){
  const file='tasks/qualification/'+relative,x=JSON.parse(read(file,pin));
  const transcriptPath=scenario==='V15'?'/observed/judgeTranscripts/0':scenario==='V16'?'/judgeTranscripts/0':'/transcripts/0';
  const t=(x.observed?.judgeTranscripts||x.judgeTranscripts||x.transcripts)?.[0];
  let packet=t?JSON.parse(t.header.packet):null;
  if(packet){assert(Array.isArray(packet.rubric.criteria)&&packet.rubric.criteria.length);packets.set(scenario,{file,path:transcriptPath,packet,t});}
  const row={scenario,role,origin:'retained-actor-capture',capture:{file,sha256:pin},
   qualificationAccepted:false,semanticTruthVerified:false,modelPacketAvailable:false,refs:[]};
  if(scenario==='V15'){
   const run=x.runs.vuln;assert.equal(run.judgeInput.packet,t.header.packet);
   for(const [name,id]of [['source','audit_log'],['response','audit_summary']]){
    const index=packet.evidence.findIndex(e=>e.id===id);assert(index>=0);
    row.refs.push(reference(file,transcriptPath+'/header/packet#json/evidence/'+index+'/content',packet.evidence[index].content,'utf8'));
   }
   assert.equal(sha(Buffer.from(run.artifactReads.messages.base64,'base64')),run.artifactRefs.messages.sha256);
   row.refs.push(reference(file,'/runs/vuln/artifactReads/messages',run.artifactReads.messages));
  }else if(scenario==='V16'){
   assert.equal(x.judgeInputs[0].packet,t.header.packet);
   row.refs.push(reference(file,'/summaryCapture/turns',x.summaryCapture.turns));
   row.additionalTurns='retained Fixed/replay turns are not admitted here as benign-source controls';
  }else if(scenario==='V21'){
   assert.equal(x.cases.length,1);const c=x.cases[0];assert.equal(c.saved.text,c.turn.result_json.text);
   for(const key of ['posted','lookup','saved','actorWireIndices'])row.refs.push(reference(file,'/cases/0/'+key,c[key]));
   assert(c.actorWireIndices.length>0);assert(c.actorWireIndices.every(i=>Number.isInteger(i)&&x.wire[i]));
   if(role==='benign'){assert.equal(x.transcripts.length,0);row.originalAssessmentPresent=false;}
  }else{
   assert.deepEqual(x.cases.map(c=>c.id),['baseline','attack']);
   for(const [i,c]of x.cases.entries()){
    assert.equal(c.request.policy_html,c.original.proof.request.policyHtml);assert.equal(sha(c.original.html),c.original.responseSha256);
    for(const key of ['request','original'])row.refs.push(reference(file,'/cases/'+i+'/'+key,c[key]));
   }
   row.arms=['baseline','attack'];
   assert.equal(x.transcripts.length,1);
   const selected=packet.evidence.find(e=>e.id==='policy_final_source').content,attack=x.cases[1];
   assert.equal(selected.policyBody,attack.request.policy_html);assert.equal(selected.finalResponse,attack.original.html);
   assert.equal(selected.policySha256,sha(Buffer.from(selected.policyBody)));
   assert.equal(selected.finalResponseSha256,sha(Buffer.from(selected.finalResponse)));
   assert.notEqual(selected.policySha256,sha(Buffer.from(x.cases[0].request.policy_html)));
   row.assessedArms=['attack'];
   row.armAssessments=[{arm:'baseline',originalAssessmentPresent:false},{arm:'attack',originalAssessmentPresent:true,
    packet:reference(file,transcriptPath+'/header/packet',t.header.packet,'utf8'),
    sourceSha256:selected.policySha256,responseSha256:selected.finalResponseSha256}];
  }
  const authority=packet?{file,path:transcriptPath,packet,t}:packets.get(scenario);assert(authority);
  row.contract={kind:scenario==='V15'?'source-effect-support':'direct-scoped-criteria',
   stages:scenario==='V15'?['source','effect','support']:[],criteria:authority.packet.rubric.criteria.map(c=>c.id),
   rubric:reference(authority.file,authority.path+'/header/packet#json/rubric',authority.packet.rubric),
   fullEvidenceAndTask:reference(authority.file,authority.path+'/header/packet',authority.t.header.packet,'utf8'),
   originalMaximumJudgeCalls:authority.t.header.maximumCalls,
   retainedCallOptions:reference(authority.file,authority.path+'/calls',authority.t.calls),
   authorityRelation:packet?'same-retained-assessment':'criterion-reference-only-not-a-negative-assessment'};
  if(!packet)row.contract.fullEvidenceAndTask=null; // Never pretend positive evidence is this negative's packet.
  if(scenario==='V27')row.contract.authorityRelation='attack-assessment-only-baseline-actor-evidence';
  controls.push(row);
 }
 const constructedFile='tests/postgres/secureshopProductSummaryRetainedDiagnostic.js',code=read(constructedFile);
 return freeze({version:VERSION,offlineOnly:true,executionAuthorized:false,qualificationAccepted:false,productionPromotion:false,
  controls,constructedControls:{scenario:'V16',origin:'constructed-response-variants',ids:['faithful-summary','refusal','quotation'],
   implementation:{file:constructedFile,sha256:sha(code)},genuineActorEvidence:false},
  gaps:[{scenario:'V16',kind:'missing-admitted-genuine-benign-source-negative',fixedTurnsAreNotSubstitutes:true}],
  limitations:['Exact retained hashes bind provenance; inventory does not independently requalify actor execution.',
   'Source classification is not a shared grading replacement; V21 tests disclosure, not instruction recognition.',
   'No model packet or expected verdict is emitted; roles are host-only inventory metadata.']});
}
function verify(value){assert.deepEqual(value,inventory(),'Inventory mutation or retained-source drift');return true;}
module.exports=Object.freeze({VERSION,inventory,verify});
