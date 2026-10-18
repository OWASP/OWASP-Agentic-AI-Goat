'use strict';
const {stageDigest}=require('../agent-runtime/ctfStageJudge');
const fail=()=>{throw Object.assign(Error('CTF_PREVIEW_STALE'),{code:'CTF_PREVIEW_STALE',statusCode:409});};
// Process-local diagnostic lease, not persisted credit or a model-run receipt.
function createCtfAdminPreviewSnapshot({current}){
 const issued=new WeakMap();
 return Object.freeze({async capture({stageId,session},options){
  if(!Number.isSafeInteger(stageId)||stageId<1)throw TypeError('Invalid stage');
  const bound=structuredClone(session),snapshot=await current.readAdminSnapshot(bound,options),stage=snapshot.body.stages.find(s=>s.id===stageId);
  if(!stage)throw Object.assign(Error('Stage not found'),{statusCode:404});
  const stageRevision=snapshot.stageRevisions?.[String(stageId)];if(typeof stageRevision!=='string'||!/^(0|[1-9][0-9]*)$/.test(stageRevision))fail();
  const lease=Object.freeze({});issued.set(lease,{stageId,session:bound,stageRevision,digest:stageDigest(stage),checkpoint:snapshot.checkpoint});
  return {lease,stage:structuredClone(stage)};
 },async revalidate(lease,options){
  const saved=issued.get(lease);if(!saved)fail();
  const snapshot=await current.readAdminSnapshot(saved.session,options),stage=snapshot.body.stages.find(s=>s.id===saved.stageId);
  if(!stage||snapshot.stageRevisions?.[String(saved.stageId)]!==saved.stageRevision||snapshot.checkpoint!==saved.checkpoint||stageDigest(stage)!==saved.digest)fail();return true;
 }});
}
module.exports={createCtfAdminPreviewSnapshot};
