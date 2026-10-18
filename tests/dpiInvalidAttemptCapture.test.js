'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');const os=require('node:os');const {createHash}=require('node:crypto');
const {createPrivateInvalidAttemptCapture,createPrivateModelAttemptCapture,
  providerFailureDiagnostic}=require('./dpiSystemPromptV3JudgeCalibration.live.test.js');

test('all invalid Judge diagnostics are private, bounded, durable and owner-only',async()=>{
  const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'dpi-capture-test-'));const evidence=path.join(root,'evidence');fs.mkdirSync(evidence,{mode:0o700});const target=path.join(evidence,'invalid-attempts.jsonl');
  const originalFsync=fs.fsyncSync;let fsyncCalls=0;fs.fsyncSync=fd=>{fsyncCalls+=1;return originalFsync(fd);};
  try{
    const capture=createPrivateInvalidAttemptCapture(target,{ownedRoot:root});const rawResponse='private fixture response';const row={version:1,phase:'judge',comparisonStage:'source',attempt:1,validationCode:'INVALID_JUDGE_OUTPUT',rawResponse,rawResponseByteCount:Buffer.byteLength(rawResponse),rawResponseSha256:createHash('sha256').update(rawResponse).digest('hex')};
    await capture(row);await capture({...row,attempt:2});assert.equal(fsyncCalls,2);assert.equal(capture.count,2);
    const st=fs.statSync(target);assert.equal(st.mode&0o777,0o600);
    const saved=fs.readFileSync(target,'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(saved.length,2);assert.ok(saved.every(item=>item.rawResponse===rawResponse));
    capture.close();await assert.rejects(()=>capture(row));
  }finally{fs.fsyncSync=originalFsync;fs.rmSync(root,{recursive:true,force:true});}
});

test('every bounded model response is durably retained in an owner-only file',()=>{
  const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'dpi-model-attempt-test-'));const evidence=path.join(root,'evidence');fs.mkdirSync(evidence,{mode:0o700});const target=path.join(evidence,'model-attempts.jsonl');
  const originalFsync=fs.fsyncSync;let fsyncCalls=0;fs.fsyncSync=fd=>{fsyncCalls+=1;return originalFsync(fd);};
  try{
    const capture=createPrivateModelAttemptCapture(target,{ownedRoot:root});const rawResponse='private controlled model response';
    capture.record({version:1,scope:'dpi_system_prompt_v12_model_attempt',caseId:'fixture',trial:1,stage:'effect',stageAttempt:1,attempt:1,
      provider:'controlled',model:'controlled',mocked:false,fallback:false,rawResponse,
      rawResponseByteCount:Buffer.byteLength(rawResponse),rawResponseSha256:createHash('sha256').update(rawResponse).digest('hex')});
    assert.equal(capture.count,1);capture.close();assert.equal(fsyncCalls,1);assert.equal(fs.statSync(target).mode&0o777,0o600);
    const rows=fs.readFileSync(target,'utf8').trim().split('\n').map(JSON.parse);assert.equal(rows.length,1);assert.equal(rows[0].rawResponse,rawResponse);
    assert.throws(()=>capture.record(rows[0]));
  }finally{fs.fsyncSync=originalFsync;fs.rmSync(root,{recursive:true,force:true});}
});

test('provider failures project only closed diagnostic codes and names',()=>{
  assert.deepEqual(providerFailureDiagnostic(new Error('DPI_CALIBRATION_STAGE_ORDER_REJECTED')),
    {providerFailureCode:'DPI_CALIBRATION_STAGE_ORDER_REJECTED',providerFailureName:'Error'});
  assert.deepEqual(providerFailureDiagnostic(Object.assign(new Error('queue detail'),{code:'AI_QUEUE_FULL'})),
    {providerFailureCode:'AI_QUEUE_FULL',providerFailureName:'Error'});
  assert.deepEqual(providerFailureDiagnostic(Object.assign(new Error('socket detail'),{code:'UND_ERR_CONNECT_TIMEOUT'})),
    {providerFailureCode:'UND_ERR_CONNECT_TIMEOUT',providerFailureName:'Error'});
  const aborted=Object.assign(new Error('private abort reason'),{name:'AbortError',code:'ABORT_ERR'});
  assert.deepEqual(providerFailureDiagnostic(aborted),
    {providerFailureCode:'ABORT_ERR',providerFailureName:'AbortError'});

  const protectedText='SECRET_SYSTEM_PROMPT_V1 private grading reference';
  const unknown=providerFailureDiagnostic(Object.assign(new Error(protectedText),{code:`PRIVATE_${protectedText}`}));
  assert.deepEqual(unknown,{providerFailureCode:'UNCLASSIFIED_PROVIDER_FAILURE',providerFailureName:'Error'});
  assert.equal(JSON.stringify(unknown).includes(protectedText),false);
  assert.deepEqual(providerFailureDiagnostic({name:'PrivateFailure',code:`UND_ERR_${'A'.repeat(49)}`,message:protectedText}),
    {providerFailureCode:'UNCLASSIFIED_PROVIDER_FAILURE',providerFailureName:'UnknownError'});
});

test('explicit capture roots reject outside paths, symlinks, public modes and foreign ownership',t=>{
  const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'dpi-capture-admission-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const evidence=path.join(root,'evidence');fs.mkdirSync(evidence,{mode:0o700});
  for(const [writer,name] of [[createPrivateInvalidAttemptCapture,'invalid-attempts.jsonl'],[createPrivateModelAttemptCapture,'model-attempts.jsonl']]){
    const target=path.join(evidence,name);
    assert.throws(()=>writer(path.join(root,name),{ownedRoot:root}));
    const alias=path.join(root,'alias');fs.symlinkSync(root,alias);assert.throws(()=>writer(target,{ownedRoot:alias}));fs.unlinkSync(alias);
    fs.chmodSync(root,0o755);assert.throws(()=>writer(target,{ownedRoot:root}));fs.chmodSync(root,0o700);
    const original=fs.lstatSync;
    try{fs.lstatSync=(file,...args)=>{const stat=original(file,...args);return file===root?new Proxy(stat,{get(object,key){return key==='uid'?process.getuid()+1:Reflect.get(object,key);}}):stat;};assert.throws(()=>writer(target,{ownedRoot:root}));}finally{fs.lstatSync=original;}
    assert.throws(()=>writer(target,{ownedRoot:'.'}));
  }
});
