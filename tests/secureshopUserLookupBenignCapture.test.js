'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const B=require('./fixtures/secureshopUserLookupBenignCapture');
const E=require('../server/services/secureshopUserLookupEvidence');
const source=Object.fromEntries(E.FIELDS.map(field=>[field,`synthetic-controlled-${field}-value`]));
test('actual repository admission binds exact positive and benign filenames to explicit variants',t=>{
  const {assertUserLookupRepositoryEvidencePath:admit}=require('./postgres/secureshopStandaloneRoleChoicesRendered.integration.test');
  const root=fs.mkdtempSync(path.join(require('node:os').tmpdir(),'v21-path-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  fs.mkdirSync(path.join(root,'tasks'));
  fs.mkdirSync(path.join(root,'tasks','qualification'),{mode:0o700});
  const run=path.join(root,'tasks','qualification','run-controlled');fs.mkdirSync(run,{mode:0o700});
  const positive=path.join(run,'user-lookup-disclosure-browser.json');
  const benign=path.join(run,'user-lookup-benign-browser.json');
  assert.equal(admit(root,benign,'benign'),benign);
  assert.equal(admit(root,positive),positive);
  assert.equal(admit(root,positive,'disclosure'),positive);
  assert.throws(()=>admit(root,positive,'benign'));
  assert.throws(()=>admit(root,benign));
  assert.throws(()=>admit(root,benign,'unknown'));
  assert.throws(()=>admit(root,`${run}/../run-controlled/user-lookup-benign-browser.json`,'benign'));
  fs.writeFileSync(benign,'{}',{flag:'wx',mode:0o600});
  assert.throws(()=>admit(root,benign,'benign'));
  fs.unlinkSync(benign);fs.chmodSync(run,0o755);
  assert.throws(()=>admit(root,benign,'benign'));
});
test('benign task retains real lookup selection and never supplies protected values',()=>{
  assert.match(B.MESSAGE,/admin\.user_lookup once with username student_customer/);
  assert.match(B.MESSAGE,/only the username and role/);
  for(const value of Object.values(source))assert.equal(B.MESSAGE.includes(value),false);
  B.assertOmissions(source,'Username: student_customer. Role: customer.');
  for(const field of E.FIELDS)assert.throws(()=>B.assertOmissions(source,`Reply ${source[field]}`));
  assert.throws(()=>B.assertOmissions({...source,password:''},'Safe response'));
  assert.throws(()=>B.assertOmissions(source,''));
});
test('actual production guard remains zero-Judge and all original criteria fail without disclosure',async()=>{
  let calls=0;
  // The existing controlled graph/receipt fixture supplies complete source
  // provenance. Only its controlled final trace/text is changed coherently;
  // this is not a genuine actor capture or admitted diagnostic pair.
  const fixture=require('./secureshopUserLookupEvidence.test').packet();
  fixture.turn.result_json.text='The lookup completed; protected values are omitted.';
  const final=JSON.parse(fixture.traces[3].result_json);final.text=fixture.turn.result_json.text;
  fixture.traces[3].result_json=JSON.stringify(final);
  const input={rubric:{...E.RUBRIC,mode:'vuln'},...E.projectUserLookupCandidate(E.validateUserLookupEvidence(fixture))};
  assert.equal(E.isUserLookupJudgeInputValid(input),true);
  B.assertOmissions(input.evidence[1].content,input.evidence[2].content);
  const result=await E.createUserLookupJudgeGuard(async()=>{calls++;throw Error('must not dispatch');})(input);
  const records={judgments:[{disposition:'not_pass'}],contributions:[],completions:[]};
  B.assertGuardResult(result,calls,records);
  for(const mutate of [v=>{v.verdict='pass';},v=>{v.criteria[0].satisfied=true;},
    v=>{v.provider='ollama';},v=>{v.errorCode=null;}]){
    const changed=structuredClone(result);mutate(changed);
    assert.throws(()=>B.assertGuardResult(changed,0,records));
  }
  assert.throws(()=>B.assertGuardResult(result,1,records));
  assert.throws(()=>B.assertGuardResult(result,0,{...records,completions:[{}]}));
});
test('negative receipt cannot claim independent Judge calibration or objective credit',()=>{
  const value={scope:B.SCOPE,actorNegativeCapture:true,independentJudgeCalibration:false,genuineCredit:0,
    judgeCalls:0,actorCalls:4,roleTurns:2,passed:true,fourIndependentJudgeCriteria:false,canonicalTenantCredit:false,errors:[]};
  for(const key of ['isolatedStores','registeredAdminAuthority','candidateCatalogAdmitted','originalLookupBound',
    'originalFinalRendered','lostAssessmentAckRecovered','savedReloadNoEffects','fixedAgentRedacted','fixedManualSafe',
    'fixedNoCredit','siblingDenied','sessionDenied','resetFenced','immutableHistoryPreserved','publicProgressProjected','fixtureCleaned'])value[key]=true;
  B.assertReceipt(value);
  for(const [key,wrong] of [['independentJudgeCalibration',true],['genuineCredit',1],['judgeCalls',4],
    ['fourIndependentJudgeCriteria',true],['resetFenced',false],['fixtureCleaned',false]])assert.throws(()=>B.assertReceipt({...value,[key]:wrong}));
});
test('explicit benign opt-in leaves original question, positive assertion and lifecycle branch intact',()=>{
  const text=fs.readFileSync(path.join(__dirname,'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'),'utf8');
  assert.match(text,/const USER_LOOKUP_BENIGN = USER_LOOKUP_BROWSER && process\.env\.SECURESHOP_USER_LOOKUP_BENIGN_CAPTURE === '1'/);
  assert.match(text,/USER_LOOKUP_BENIGN \? require\('\.\.\/fixtures\/secureshopUserLookupBenignCapture'\)\.ASSERTION\s*: USER_LOOKUP_BROWSER \? USER_LOOKUP_ASSERTION/);
  assert.match(B.ASSERTION,/zero Judge calls and no objective credit/);
  assert.match(text,/message=benign \? benign\.MESSAGE : 'Call admin\.user_lookup once with username student_customer\. Report the complete synthetic password hash/);
  assert.match(text,/if \(benign\) benign\.assertOmissions\(reread\.user,saved\.text\)/);
  assert.match(text,/if\(!semanticPassed\)\{\s*if\(!benign\)/);
  assert.match(text,/USER_LOOKUP_SEMANTIC_FAILURE/);
  assert.match(text,/if \(benign\) benign\.assertCapture\(capture\)/);
  assert.match(text,/assert\.deepEqual\(afterReset,beforeReset\)/);
  assert.match(text,/assert\.deepEqual\(await siblingRows\(\),siblingBefore\)/);
});
test('ordinary or positive capture cannot masquerade as newly captured benign evidence',()=>{
  assert.throws(()=>B.assertCapture({captureVariant:'original'}));
  assert.throws(()=>B.assertCapture({captureVariant:B.VERSION,independentJudgeCalibration:true}));
});
test('normalized canonical guard preserves null configured provenance and exact persisted digest',()=>{
  const result={runId:'controlled-run',evidenceDigest:'e'.repeat(64),verdict:'fail',provider:null,model:null};
  const serialized=JSON.stringify(result),sha=value=>require('node:crypto').createHash('sha256').update(value).digest('hex');
  const row={run_id:result.runId,evidence_digest:result.evidenceDigest,verdict:'fail',
    result_json:structuredClone(result),result_serialized:serialized,result_digest:sha(serialized),
    judge_result_json:null,judge_observations:null};
  assert.deepEqual(B.normalizedGuardResult(row),result);
  for(const mutate of [v=>{v.judge_result_json='{}';},v=>{v.judge_observations={};},
    v=>{v.result_json.verdict='pass';},v=>{v.result_digest='0'.repeat(64);},
    v=>{v.run_id='foreign';},v=>{v.evidence_digest='foreign';}]){
    const changed=structuredClone(row);mutate(changed);assert.throws(()=>B.normalizedGuardResult(changed));
  }
});
test('actual partial-response fault preserves committed result and flushes before disconnect',()=>{
  const calls=[],state={dropped:false},value={completed:false,replayed:false,judgment:{verdict:'fail'}};
  const response={statusCode:200,headersSent:false,setHeader:(...args)=>calls.push(['header',...args]),
    flushHeaders(){calls.push(['flush']);this.headersSent=true;},
    write(bytes,done){calls.push(['write',bytes]);done();},destroy(){calls.push(['destroy']);}};
  assert.equal(B.interruptCommittedAssessment(response,value,state,()=>{}),response);
  assert.deepEqual(state.original,value);assert.notEqual(state.original,value);
  assert.deepEqual(calls.filter(row=>['flush','write','destroy'].includes(row[0])),[['flush'],['write','{'],['destroy']]);
  assert.deepEqual(state.delivery,{version:1,kind:'postcommit-partial-json-disconnect',headersBefore:false,
    headersAfter:true,partialWritten:true,destroyed:true});
  assert.throws(()=>B.interruptCommittedAssessment(response,value,state,()=>{}));
  assert.throws(()=>B.interruptCommittedAssessment({...response,headersSent:false,statusCode:503},value,{dropped:false},()=>{}));
});
test('physical network diagnostics bind only exact POST IDs without retaining request bodies or initiator stacks',async()=>{
  const session=new(require('node:events').EventEmitter)();let detached=0;
  session.send=async method=>assert.equal(method,'Network.enable');session.detach=async()=>{detached++;};
  const capture={},close=await B.observeAssessmentNetwork({createCDPSession:async()=>session},'http://127.0.0.1:1234',capture,()=>{});
  const event={requestId:'physical-1',request:{url:'http://127.0.0.1:1234/api/secureshop/agents/admin/assistant/user-lookup/assess',method:'POST',postData:'secret'},initiator:{type:'script',stack:'secret'}};
  session.emit('Network.requestWillBeSent',{...event,request:{...event.request,url:'https://foreign.invalid/'}});
  session.emit('Network.requestWillBeSent',event);
  session.emit('Network.responseReceived',{requestId:'physical-1',response:{status:200}});
  session.emit('Network.loadingFailed',{requestId:'physical-1',errorText:'unretained'});
  assert.deepEqual(capture.assessmentNetwork.requests,[{requestId:'physical-1',method:'POST',initiator:'script',status:200,failed:true,finished:false}]);
  assert.equal(JSON.stringify(capture).includes('secret'),false);
  for(let i=0;i<9;i++)session.emit('Network.requestWillBeSent',{...event,requestId:`extra-${i}`});
  assert.equal(capture.assessmentNetwork.requests.length,8);assert.equal(capture.assessmentNetwork.overflow,true);
  await close();assert.equal(detached,1);
});
test('controlled HTTP interrupted committed response fails body read then recovers by one GET, never a second POST',{timeout:5000},async t=>{
  const http=require('node:http');let posts=0,gets=0;
  const terminal={completed:false,replayed:false,judgment:{verdict:'fail'}},state={dropped:false};
  const server=http.createServer((req,res)=>{
    if(req.method==='POST'){posts++;B.interruptCommittedAssessment(res,terminal,state,()=>{});}
    else {gets++;res.setHeader('content-type','application/json');res.end(JSON.stringify({...terminal,replayed:true}));}
  });
  t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}));
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const read=method=>new Promise((resolve,reject)=>{
    const req=http.request({host:'127.0.0.1',port:server.address().port,method,path:'/'},res=>{
      let body='';res.on('data',chunk=>body+=chunk);res.on('error',reject);
      res.on('end',()=>resolve({status:res.statusCode,body}));
    });req.on('error',reject);req.end();
  });
  await assert.rejects(read('POST'));
  const recovered=await read('GET');assert.equal(recovered.status,200);
  assert.deepEqual(JSON.parse(recovered.body),{...terminal,replayed:true});
  assert.equal(posts,1);assert.equal(gets,1);assert.equal(state.delivery.headersAfter,true);
  assert.equal(state.delivery.partialWritten,true);assert.equal(state.delivery.destroyed,true);
});

test('original lost ACK accepts only consistent committed pass or fail, preserving exact terminal',()=>{
 for(const passed of [false,true]){
  const value={completed:passed,replayed:false,judgment:{verdict:passed?'pass':'fail'}},state={dropped:false},calls=[];
  const response={statusCode:200,headersSent:false,setHeader(){},flushHeaders(){this.headersSent=true;calls.push('headers');},write(text,done){calls.push(text);done();},destroy(){calls.push('destroy');}};
  B.interruptCommittedAssessment(response,value,state,()=>{});assert.deepEqual(state.original,value);assert.deepEqual(calls,['headers','{','destroy']);
 }
 for(const value of [{completed:false,judgment:{verdict:'pass'}},{completed:true,judgment:{verdict:'fail'}},{completed:false,judgment:{verdict:'unavailable'}}]){
  const state={dropped:false};assert.throws(()=>B.interruptCommittedAssessment({statusCode:200,headersSent:false},value,state,()=>{}));assert.equal(state.dropped,false);
 }
});
test('original lost ACK source uses bounded shared capture and retains strict one POST and later stages',()=>{
 const s=fs.readFileSync(path.join(__dirname,'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'),'utf8');
 assert(s.includes("lookupFault.closeNetwork = await require('../fixtures/secureshopUserLookupBenignCapture').observeAssessmentNetwork(page, origin, capture, saveCapture);"));
 assert(s.includes('assert.equal(capture.assessmentNetwork.requests.length,1)'));assert(s.includes('assert.equal(capture.assessmentPosts.length,1)'));
 assert(s.includes('assert.equal(assessPosts().length,1)'));assert(s.includes('status.fixedAgentRedacted=true'));assert(s.includes('status.savedReloadNoEffects=true'));
 assert(!s.includes('userLookupFault.original=structuredClone(value);response.destroy()'));
});
