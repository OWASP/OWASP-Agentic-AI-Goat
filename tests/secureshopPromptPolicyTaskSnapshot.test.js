'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildPolicySnapshot } = require('../server/services/secureshopPromptPolicySnapshot');
const { buildTaskPolicySnapshot, validateTaskPolicySnapshot, adaptV1PolicySnapshot } = require('../server/services/secureshopPromptPolicyTaskSnapshot');
const digest = text => require('node:crypto').createHash('sha256').update(text).digest('hex');
const rows = [
  { name:'role-wide', rendered:'base', renderedSha256:digest('base'), targets:['customer','merchant'] },
  { name:'summary-only', rendered:'summarize', renderedSha256:digest('summarize'), targets:['summarizer'] },
  { name:'review-only', rendered:'moderate', renderedSha256:digest('moderate'), targets:['review-moderator'] },
];
test('v2 includes role-wide and matching recipient rows with deterministic digest', () => {
  const summary=buildTaskPolicySnapshot({policyVersion:'3',role:'customer',recipient:'summarizer',policies:rows});
  assert.deepEqual(summary.policies.map(row=>row.name),['role-wide','summary-only']);
  assert.equal(validateTaskPolicySnapshot(summary).sha256,summary.sha256); assert.equal(summary.recipient,'summarizer');
});
test('same-role sibling task excludes task-specific rows while retaining role-wide rows', () => {
  const similar=buildTaskPolicySnapshot({policyVersion:'3',role:'customer',recipient:null,policies:rows});
  assert.deepEqual(similar.policies.map(row=>row.name),['role-wide']);
  const manual=buildTaskPolicySnapshot({policyVersion:'3',role:'merchant',recipient:null,policies:rows});
  assert.deepEqual(manual.policies.map(row=>row.name),['role-wide']);
});
test('wrong role and recipient are rejected and forged snapshot content fails', () => {
  assert.throws(()=>buildTaskPolicySnapshot({policyVersion:'1',role:'merchant',recipient:'summarizer',policies:rows}));
  assert.throws(()=>buildTaskPolicySnapshot({policyVersion:'1',role:'customer',recipient:'nope',policies:rows}));
  const value=buildTaskPolicySnapshot({policyVersion:'3',role:'merchant',recipient:'review-moderator',policies:rows});
  assert.throws(()=>validateTaskPolicySnapshot({...value,text:'forged'}));
});
test('explicit v1 adapter validates v1 bytes and produces role-wide v2 content', () => {
  const v1=buildPolicySnapshot({policyVersion:'4',role:'customer',policies:[{name:'base',rendered:'hello',renderedSha256:digest('hello'),targets:['customer']}]});
  const adapted=adaptV1PolicySnapshot(v1,'summarizer');
  assert.equal(adapted.recipient,'summarizer'); assert.deepEqual(adapted.policies[0].targets,['customer']); assert.equal(adapted.policies[0].rendered,'hello');
  assert.throws(()=>adaptV1PolicySnapshot(v1));
});


test('persisted JSONB object key order does not change validation while array order remains canonical', () => {
  const snapshot = buildTaskPolicySnapshot({policyVersion:'3',role:'customer',recipient:'summarizer',policies:rows});
  const persisted = {...snapshot, policies: snapshot.policies.map(row => ({
    targets: [...row.targets], renderedSha256: row.renderedSha256, rendered: row.rendered, name: row.name
  }))};
  assert.deepEqual(validateTaskPolicySnapshot(persisted), snapshot);
  assert.throws(() => validateTaskPolicySnapshot({...persisted, policies: [...persisted.policies].reverse()}));
  persisted.policies[0].targets.reverse();
  assert.throws(() => validateTaskPolicySnapshot(persisted));
});
test('Analytics accepts only merchant/admin with role OR task selection and immutable digest',()=>{
 const analytics={name:'analytics-only',rendered:'Owned analytics rule',renderedSha256:digest('Owned analytics rule'),targets:['analytics']};
 for(const role of ['merchant','admin']){const value=buildTaskPolicySnapshot({policyVersion:'4',role,recipient:'analytics',policies:[...rows,analytics]});assert.ok(value.policies.some(r=>r.name==='analytics-only'));assert.equal(value.policies.some(r=>r.name==='role-wide'),role==='merchant');assert.equal(value.policies.some(r=>r.name==='summary-only'||r.name==='review-only'),false);assert.equal(validateTaskPolicySnapshot(value).sha256,value.sha256);}
 assert.throws(()=>buildTaskPolicySnapshot({policyVersion:'4',role:'customer',recipient:'analytics',policies:[analytics]}));
 const ordinary=buildTaskPolicySnapshot({policyVersion:'4',role:'merchant',recipient:null,policies:[...rows,analytics]});assert.equal(ordinary.policies.some(r=>r.name==='analytics-only'),false);
});

test('inventory task recipient is merchant-only and excludes sibling task rules',()=>{const row={name:'stock-rule',rendered:'Only own retailer',renderedSha256:digest('Only own retailer'),targets:['inventory']};const value=buildTaskPolicySnapshot({policyVersion:'1',role:'merchant',recipient:'inventory',policies:[row]});assert.equal(value.policies.length,1);assert.equal(validateTaskPolicySnapshot(value).sha256,value.sha256);assert.throws(()=>buildTaskPolicySnapshot({policyVersion:'1',role:'admin',recipient:'inventory',policies:[row]}));assert.equal(buildTaskPolicySnapshot({policyVersion:'1',role:'merchant',recipient:'listing',policies:[row]}).policies.length,0);});
