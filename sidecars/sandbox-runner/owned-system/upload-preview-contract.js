'use strict';
const {createHash}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const VERSION=1,ISOLATION='bwrap-upload-preview-v1';
const MAX_INPUT_BYTES=256*1024,MAX_DIMENSION=16384,MAX_PIXELS=1048576,MAX_RAW_BYTES=4*MAX_PIXELS;
const MAX_REENCODE_BYTES=MAX_RAW_BYTES+65536,MAX_OUTPUT_BYTES=64*1024,TIMEOUT_MS=5000;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const REQUEST_KEYS=['version','operationId','uploadOperationId','uploadEffectId','storageKey','bindingSha256','uploadRequestSha256','bodySha256','byteCount','bytesBase64','mode'];
const RECEIPT_KEYS=['version','operationId','uploadOperationId','uploadEffectId','storageKey','requestSha256','bindingSha256','bodySha256','mode','isolation','runtime','decoder','status','scriptSyntaxValid','originalInterpreterStarted','reencoded','exitCode','timedOut','truncated','drained','workerAttested','codeEffectObserved','effectSha256'];
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=()=>Object.assign(Error('Owned upload preview contract invalid'),{code:'UPLOAD_PREVIEW_INVALID'});
const need=value=>{if(!value)throw fail();};
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype&&equal(Object.keys(value).sort(),[...keys].sort());
function normalizeUploadPreviewRequest(raw){
 need(exact(raw,REQUEST_KEYS)&&raw.version===VERSION);
 for(const key of ['operationId','uploadOperationId','uploadEffectId','storageKey'])need(typeof raw[key]==='string'&&UUID.test(raw[key]));
 for(const key of ['bindingSha256','uploadRequestSha256','bodySha256'])need(typeof raw[key]==='string'&&SHA.test(raw[key]));
 need(['vuln','fixed'].includes(raw.mode)&&Number.isSafeInteger(raw.byteCount)&&raw.byteCount>0&&raw.byteCount<=MAX_INPUT_BYTES);
 need(typeof raw.bytesBase64==='string'&&raw.bytesBase64.length<=Math.ceil(MAX_INPUT_BYTES/3)*4&&/^[A-Za-z0-9+/]+={0,2}$/.test(raw.bytesBase64));
 const bytes=Buffer.from(raw.bytesBase64,'base64');
 need(bytes.toString('base64')===raw.bytesBase64&&bytes.length===raw.byteCount&&hash(bytes)===raw.bodySha256);
 return Object.freeze(Object.fromEntries(REQUEST_KEYS.map(key=>[key,raw[key]])));
}
const requestDigest=raw=>hash(JSON.stringify(normalizeUploadPreviewRequest(raw)));
function validateUploadPreviewReceipt(raw,input){
 const request=normalizeUploadPreviewRequest(input);
 need(exact(raw,RECEIPT_KEYS)&&raw.version===VERSION&&raw.isolation===ISOLATION);
 for(const key of ['operationId','uploadOperationId','uploadEffectId','storageKey','bindingSha256','bodySha256','mode'])need(raw[key]===request[key]);
 need(raw.requestSha256===requestDigest(request));
 need(exact(raw.runtime,['nodeVersion','platform','arch'])&&typeof raw.runtime.nodeVersion==='string'&&/^v\d+\.\d+\.\d+$/.test(raw.runtime.nodeVersion)
  &&raw.runtime.platform==='linux'&&['x64','arm64'].includes(raw.runtime.arch));
 need(['executed','image_only','fixed_reencoded','invalid_image','failed'].includes(raw.status));
 need([true,false,null].includes(raw.scriptSyntaxValid)&&typeof raw.originalInterpreterStarted==='boolean');
 need((raw.exitCode===null||Number.isInteger(raw.exitCode)&&raw.exitCode>=0&&raw.exitCode<=255)
  &&['timedOut','truncated','drained','workerAttested','codeEffectObserved'].every(key=>typeof raw[key]==='boolean'));
 need(raw.drained&&raw.workerAttested&&(!raw.codeEffectObserved||raw.originalInterpreterStarted));
 need(raw.effectSha256===null||SHA.test(raw.effectSha256||''));
 need(raw.codeEffectObserved===(raw.effectSha256!==null));
 if(raw.decoder!==null){
  const d=raw.decoder;need(exact(d,['sharpVersion','vipsVersion','logicalWidth','logicalHeight','width','height','pages','rawSha256','rawByteCount']));
  need(d.sharpVersion==='0.35.4'&&typeof d.vipsVersion==='string'&&/^\d+\.\d+\.\d+$/.test(d.vipsVersion));
  for(const key of ['logicalWidth','logicalHeight','width','height'])need(Number.isSafeInteger(d[key])&&d[key]>0&&d[key]<=MAX_DIMENSION);
  need(d.logicalWidth*d.logicalHeight<=MAX_PIXELS&&d.width*d.height<=MAX_PIXELS&&d.pages===1
   &&d.rawByteCount===d.width*d.height*4&&d.rawByteCount<=MAX_RAW_BYTES&&SHA.test(d.rawSha256||''));
 }
 if(raw.status==='invalid_image')need(raw.decoder===null&&raw.scriptSyntaxValid===null&&!raw.originalInterpreterStarted&&raw.reencoded===null&&raw.exitCode===null&&!raw.codeEffectObserved);
 if(raw.status==='image_only')need(request.mode==='vuln'&&raw.decoder!==null&&raw.scriptSyntaxValid===false&&!raw.originalInterpreterStarted&&raw.reencoded===null&&raw.exitCode===null&&!raw.codeEffectObserved);
 if(raw.status==='executed')need(request.mode==='vuln'&&raw.decoder!==null&&raw.scriptSyntaxValid===true&&raw.originalInterpreterStarted&&raw.exitCode===0&&raw.reencoded===null&&!raw.timedOut&&!raw.truncated);
 if(raw.status==='fixed_reencoded'){
  need(request.mode==='fixed'&&raw.decoder!==null&&exact(raw.reencoded,['format','bodySha256','byteCount'])
   &&raw.reencoded.format==='png'&&SHA.test(raw.reencoded.bodySha256||'')&&Number.isSafeInteger(raw.reencoded.byteCount)
   &&raw.reencoded.byteCount>0&&raw.reencoded.byteCount<=MAX_REENCODE_BYTES&&raw.reencoded.bodySha256!==request.bodySha256
   &&raw.scriptSyntaxValid===null&&!raw.originalInterpreterStarted&&raw.exitCode===null&&!raw.codeEffectObserved&&!raw.timedOut&&!raw.truncated);
 }
 if(raw.status!=='failed')need(!raw.timedOut&&!raw.truncated);
 if(raw.status!=='fixed_reencoded')need(raw.reencoded===null);
 if(request.mode==='fixed')need(raw.scriptSyntaxValid===null&&!raw.originalInterpreterStarted&&!raw.codeEffectObserved);
 if(raw.originalInterpreterStarted)need(request.mode==='vuln'&&raw.decoder!==null&&raw.scriptSyntaxValid===true);
 return Object.freeze(structuredClone(raw));
}
module.exports={VERSION,ISOLATION,MAX_INPUT_BYTES,MAX_DIMENSION,MAX_PIXELS,MAX_RAW_BYTES,MAX_REENCODE_BYTES,MAX_OUTPUT_BYTES,TIMEOUT_MS,REQUEST_KEYS,RECEIPT_KEYS,hash,normalizeUploadPreviewRequest,requestDigest,validateUploadPreviewReceipt};
