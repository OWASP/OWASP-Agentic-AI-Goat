'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeTaskMutationRequest, renderRequest, taskMutationDigest } = require('../server/services/secureshopPromptPolicyTaskMutation');
const base = { contractVersion:2, operationId:'123e4567-e89b-42d3-a456-426614174000', name:'policy', markdown:'hello', targets:['customer','merchant'] };
test('v2 mutation normalizes exact five-key body and exposes unchanged v1 renderer request', () => {
  const value=normalizeTaskMutationRequest({...base,targets:['summarizer','customer','merchant']}); assert.deepEqual(value.targets,['customer','merchant','summarizer']);
  assert.deepEqual(renderRequest(value),{operationId:base.operationId,name:'policy',markdown:'hello',targets:['customer','merchant']});
});
test('task targets are closed, unique, and unknown fields are rejected', () => {
  assert.throws(()=>normalizeTaskMutationRequest({...base,targets:['summarizer','summarizer']}));
  assert.throws(()=>normalizeTaskMutationRequest({...base,targets:['unknown-analytics']}));
  assert.throws(()=>normalizeTaskMutationRequest({...base,extra:true}));
});
test('task aliases change admission digest but not renderer projection', () => {
  const role={...base}, task={...base,targets:['summarizer','customer','merchant']};
  assert.notEqual(taskMutationDigest(role),taskMutationDigest(task));
  assert.deepEqual(renderRequest(role),renderRequest(task));
});
test('v1 renderer validation remains authoritative for malformed content', () => {
  assert.throws(()=>normalizeTaskMutationRequest({...base,markdown:'\0'}));
  assert.throws(()=>normalizeTaskMutationRequest({...base,targets:['customer','customer']}));
});
test('Analytics task targets retain distinct identity while renderer covers both allowed roles',()=>{
 const value=normalizeTaskMutationRequest({...base,targets:['analytics']});assert.deepEqual(value.targets,['analytics']);assert.deepEqual(renderRequest(value).targets,['admin','merchant']);
 assert.notEqual(taskMutationDigest(value),taskMutationDigest({...base,targets:['admin','merchant']}));
});

test('listing task target preserves task identity while rendering against merchant defaults',()=>{
 const value=normalizeTaskMutationRequest({...base,targets:['listing']});
 assert.deepEqual(value.targets,['listing']);assert.deepEqual(renderRequest(value).targets,['merchant']);
});
