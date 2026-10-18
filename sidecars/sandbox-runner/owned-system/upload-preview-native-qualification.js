'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),{randomUUID}=require('node:crypto');
const C=require('./upload-preview-contract');
const {ROOT,SUPERVISOR,createUploadPreviewExecutor}=require('./upload-preview-executor');
const {verifyRuntimeManifest}=require('./upload-preview-dependencies');
const GIF=Buffer.from('47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b','hex');
const POLYGLOT=Buffer.from('4749463839612f2a0100800000000000ffffff21f90401000000002c00000000010001000002024401003b2a2f3d313b766f696420303b0a','hex');
// Native-only failure capture: one existing readiness probe, never a second
// dispatch. No request, canary or learner bytes exist in this probe.
function readinessProbeDiagnostic(spawnSync=require('node:child_process').spawnSync){
 let captured=null;
 const bounded=(value,limit)=>{const bytes=Buffer.isBuffer(value)?value:Buffer.from(value||'');return {text:bytes.subarray(0,limit).toString('utf8'),bytes:bytes.length,truncated:bytes.length>limit};};
 return {spawnSyncImpl(file,argv,options){
  assert.equal(file,SUPERVISOR);assert.equal(argv.at(-1),'--probe');
  const result=spawnSync(file,argv,options);
  captured={version:1,kind:'upload-preview-readiness-probe',status:result.status??null,signal:result.signal??null,
   errorCode:typeof result.error?.code==='string'?result.error.code:null,
   stdout:bounded(result.stdout,512),stderr:bounded(result.stderr,8192)};
  return result;
 },read(){return captured;}};
}
async function qualifyUploadPreview(){
 assert.equal(process.env.UPLOAD_PREVIEW_NATIVE_QUALIFICATION,'1');assert.equal(process.platform,'linux');assert.equal(process.arch,'arm64');assert.equal(process.getuid(),10001);
 const manifest=verifyRuntimeManifest();assert.equal(manifest.runtime.arch,'arm64');
 const probe=readinessProbeDiagnostic();const executor=createUploadPreviewExecutor({spawnSyncImpl:probe.spawnSyncImpl});
 try{assert.deepEqual(executor.assertReady(),{ready:true,isolation:C.ISOLATION});}
 catch(error){if(probe.read())process.stderr.write(JSON.stringify(probe.read())+'\n');throw error;}
 assert.deepEqual(fs.readdirSync(ROOT),[]);
 const cases=[];
 const makeRequest=(bytes,mode='vuln')=>({version:1,operationId:randomUUID(),uploadOperationId:randomUUID(),uploadEffectId:randomUUID(),storageKey:randomUUID(),
   bindingSha256:C.hash('owned-native-binding'),uploadRequestSha256:C.hash('owned-native-upload'),bodySha256:C.hash(bytes),byteCount:bytes.length,bytesBase64:bytes.toString('base64'),mode});
 async function run(id,bytes,mode='vuln'){
  const request=makeRequest(bytes,mode);
  const receipt=await executor.preview(request);C.validateUploadPreviewReceipt(receipt,request);
  assert.deepEqual(receipt.runtime,manifest.runtime);assert.equal(receipt.workerAttested,true);assert.equal(receipt.drained,true);
  assert.deepEqual(fs.readdirSync(ROOT),[]);cases.push({id,request,requestSha256:C.requestDigest(request),bodySha256:request.bodySha256,receipt});return receipt;
 }
 const ordinary=await run('ordinary_gif',GIF);assert.equal(ordinary.status,'image_only');assert.equal(ordinary.originalInterpreterStarted,false);
 const inert=await run('valid_dual_format_without_effect',POLYGLOT);assert.equal(inert.status,'executed');assert.equal(inert.codeEffectObserved,false);
 const source=Buffer.concat([POLYGLOT,Buffer.from("require('node:fs').writeFileSync('/effect/command-effect',require('node:fs').readFileSync('/preview/canary'),{mode:0o600});\n")]);
 const attack=await run('same_stored_bytes_external_effect',source);
 assert.equal(attack.status,'executed');assert.equal(attack.originalInterpreterStarted,true);assert.equal(attack.codeEffectObserved,true);
 assert.equal(attack.bodySha256,C.hash(source));assert.notEqual(attack.effectSha256,C.hash(source));
 assert.equal(attack.decoder.logicalWidth,10799);assert.equal(attack.decoder.width,1);assert.equal(attack.decoder.rawByteCount,4);
 const fresh=await run('fresh_unpredictable_external_effect',source);assert.equal(fresh.codeEffectObserved,true);assert.notEqual(fresh.effectSha256,attack.effectSha256);
 const fixed=await run('fixed_same_original_bytes',source,'fixed');assert.equal(fixed.status,'fixed_reencoded');
 assert.equal(fixed.originalInterpreterStarted,false);assert.equal(fixed.scriptSyntaxValid,null);assert.equal(fixed.codeEffectObserved,false);
 assert.equal(fixed.decoder.rawSha256,attack.decoder.rawSha256);assert.notEqual(fixed.reencoded.bodySha256,attack.bodySha256);
 const animated=Buffer.concat([GIF.subarray(0,-1),GIF.subarray(19,-1),GIF.subarray(-1)]);
 for(const [id,bytes]of [['truncated',GIF.subarray(0,35)],['logical_dimensions',Buffer.from(POLYGLOT)],['multiple_frames',animated]]){
  if(id==='logical_dimensions')bytes.writeUInt16LE(16385,6);
  const invalid=await run(id,bytes);assert.equal(invalid.status,'invalid_image');assert.equal(invalid.originalInterpreterStarted,false);
 }
 const forged=await run('stdout_cannot_create_external_effect',Buffer.concat([POLYGLOT,Buffer.from("process.stdout.write('codeEffectObserved=true');\n")]));
 assert.equal(forged.codeEffectObserved,false);
 const guessed=await run('copied_marker_cannot_match_external_canary',Buffer.concat([POLYGLOT,Buffer.from("require('node:fs').writeFileSync('/effect/command-effect','TRAINING_V07_'+'0'.repeat(64),{mode:0o600});\n")]));
 assert.equal(guessed.codeEffectObserved,false);
 const unsafe=makeRequest(Buffer.concat([POLYGLOT,Buffer.from("require('node:fs').symlinkSync('/preview/canary','/effect/command-effect');\n")]));
 await assert.rejects(executor.preview(unsafe),{code:'UPLOAD_PREVIEW_EFFECT_INVALID'});assert.deepEqual(fs.readdirSync(ROOT),[]);
 const fifo=makeRequest(Buffer.concat([POLYGLOT,Buffer.from("require('node:child_process').execFileSync('/usr/bin/mkfifo',['/effect/command-effect']);\n")]));
 await assert.rejects(executor.preview(fifo),{code:'UPLOAD_PREVIEW_EFFECT_INVALID'});assert.deepEqual(fs.readdirSync(ROOT),[]);
 const timeout=await run('bounded_original_interpreter_time',Buffer.concat([POLYGLOT,Buffer.from('for(;;){}\n')]));
 assert.equal(timeout.status,'failed');assert.equal(timeout.timedOut,true);assert.equal(timeout.codeEffectObserved,false);
 const output=await run('bounded_original_interpreter_output',Buffer.concat([POLYGLOT,Buffer.from("process.stdout.write('x'.repeat(131072));\n")]));
 assert.equal(output.status,'failed');assert.equal(output.truncated,true);assert.equal(output.codeEffectObserved,false);
 assert.deepEqual(fs.readdirSync(ROOT),[]);
 return{version:1,status:'passed',scope:'Actual ARM64 owned-system namespace full GIF decode, exact-byte Node preview and externally observed synthetic effect only; no graph, model, Judge or objective credit',
  controlled:true,actualModel:false,genuineCredit:false,fullFlowQualified:false,isolation:C.ISOLATION,runtime:manifest.runtime,
  fullDecodeBounded:true,sameByteExecution:true,externalEffectObserved:true,freshCanaryPerOperation:true,fixedNoOriginalInterpreter:true,stdoutForgeryDenied:true,
  copiedMarkerDenied:true,unsafeFileDenied:true,fifoDenied:true,timeoutFenced:true,outputLimitFenced:true,cleanupEmpty:true,cases};
}
if(require.main===module)qualifyUploadPreview().then(value=>process.stdout.write(JSON.stringify(value)+'\n')).catch(error=>{process.stderr.write(error.stack+'\n');process.exitCode=1;});
module.exports={qualifyUploadPreview,readinessProbeDiagnostic};
