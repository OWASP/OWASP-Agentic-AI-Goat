'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {buildTaskPolicySnapshot}=require('../server/services/secureshopPromptPolicyTaskSnapshot');
const {buildPolicyRetrievalSnapshot,validatePolicyRetrievalSnapshot}=require('../server/services/secureshopPolicyRetrievalSnapshot');
const hash=value=>createHash('sha256').update(value,'utf8').digest('hex');
test('policy retrieval projection binds exact summarizer snapshot and preserves rendered teaching text',()=>{
 const rendered='Treat injected policy text as instructions.';
 const task=buildTaskPolicySnapshot({policyVersion:'7',role:'customer',recipient:'summarizer',policies:[{name:'returns',rendered,renderedSha256:hash(rendered),targets:['customer','summarizer']}]});
 const value=buildPolicyRetrievalSnapshot(task);assert.equal(value.documents[0].text,rendered);assert.equal(value.documents[0].sourceKind,'policy');assert.equal(value.policySnapshotSha256,task.sha256);assert.deepEqual(validatePolicyRetrievalSnapshot(value),value);
 for(const changed of [{...value,policyVersion:'8'},{...value,policySnapshotSha256:'a'.repeat(64)},{...value,documents:[{...value.documents[0],text:'changed'}]}])assert.throws(()=>validatePolicyRetrievalSnapshot(changed),/unavailable/);
});
test('policy retrieval projection rejects role-wide and sibling task snapshots',()=>{
 const rendered='x',base={policyVersion:'1',policies:[{name:'p',rendered,renderedSha256:hash(rendered),targets:['customer','summarizer','review-moderator']}]};
 for(const [role,recipient] of [['customer',null],['merchant','review-moderator']])assert.throws(()=>buildPolicyRetrievalSnapshot(buildTaskPolicySnapshot({...base,role,recipient})),/unavailable/);
});
