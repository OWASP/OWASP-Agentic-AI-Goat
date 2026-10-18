'use strict';
// Closed ASCII fields make this compact JSON encoding identical to the SQL encoder.
// Bytes/digests identify artifacts; they are not recovery proof capabilities.
const {createHash}=require('node:crypto');
const KINDS=Object.freeze(['administrator','ctf-authority','delivery','environment-publication','provisioning']);
const HEX=/^[a-f0-9]{64}$/,UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const invalid=()=>Object.assign(Error('Maintenance artifact encoding invalid'),{code:'APPLICATION_MAINTENANCE_ARTIFACT_INVALID'});
function encodeReplayArtifacts(input){
 if(!Array.isArray(input)||input.length!==5)throw invalid();
 const rows=input.map(row=>{
  const names=['kind','relativePath','schemaVersion','bindingSha256','contentSha256','artifactId'];
  if(!row||Object.getPrototypeOf(row)!==Object.prototype||Reflect.ownKeys(row).length!==names.length||names.some(k=>!Object.hasOwn(row,k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(row,k),'value')))throw invalid();
  const {kind,relativePath,schemaVersion,bindingSha256,contentSha256,artifactId}=row;
  if(!KINDS.includes(kind)||typeof bindingSha256!=='string'||bindingSha256.length!==64||!HEX.test(bindingSha256))throw invalid();
  const dynamic=['ctf-authority','environment-publication'].includes(kind);
  if(dynamic?(typeof artifactId!=='string'||artifactId.length!==36||!UUID.test(artifactId)):artifactId!==null)throw invalid();
  if(kind==='ctf-authority'?contentSha256!==null:typeof contentSha256!=='string'||contentSha256.length!==64||!HEX.test(contentSha256))throw invalid();
  const expected=kind==='environment-publication'?`additive-environment-${artifactId}.json`:`${kind==='ctf-authority'?'ctf-authority':kind==='delivery'?'ctf-delivery':kind}.json`;
  if(relativePath!==expected||schemaVersion!==(kind==='ctf-authority'?2:1))throw invalid();
  return {kind,relativePath,schemaVersion,bindingSha256,contentSha256,artifactId};
 }).sort((a,b)=>KINDS.indexOf(a.kind)-KINDS.indexOf(b.kind));
 if(rows.some((r,i)=>r.kind!==KINDS[i]))throw invalid();
 const canonical=JSON.stringify(rows);if(Buffer.byteLength(canonical)>16384)throw invalid();
 return Object.freeze({canonical,sha256:createHash('sha256').update(canonical).digest('hex')});
}
function encodeCtfReplayBinding(value){
 const keys=['workspaceId','provisioningSha256','identityStoreId','ctfStoreId','bootstrapId','activationId'];
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Reflect.ownKeys(value).length!==keys.length||keys.some(k=>!Object.hasOwn(value,k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(value,k),'value')||typeof value[k]!=='string'||value[k].length!==(keys.indexOf(k)<2?64:36)||!(keys.indexOf(k)<2?HEX:UUID).test(value[k]))||value.identityStoreId===value.ctfStoreId||value.bootstrapId===value.activationId)throw invalid();
 const canonical=JSON.stringify(Object.fromEntries(keys.map(k=>[k,value[k]])));
 return Object.freeze({canonical,sha256:createHash('sha256').update(canonical).digest('hex')});
}
module.exports={encodeReplayArtifacts,encodeCtfReplayBinding};
