'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID,createHash}=require('node:crypto');
const P=require('../server/services/secureshopRoleUserAdministrationProposal');
function fixture(action='set_role'){
 return{sessionId:randomUUID(),requestId:randomUUID(),step:2,callId:'call-admin',
 selected:{kind:'tenant_user',sourceId:42,choiceId:randomUUID(),snapshotSha256:'a'.repeat(64)},
 user:{id:42,username:'owned_user',identity_kind:'registered_account',role:'customer',banned_at:null,authority_version:'3'},
 administration:{roleBan:true,scopeKey:JSON.stringify(['owned-launch',7,13])},
 action,role:action==='set_role'?'merchant':null,reason:action==='ban'?'Explicit human reason':null,
 modeCapability:{version:1,featureId:'admin_assistant',policyVersion:'owned-admin-read-and-confirmation-v1',effectiveMode:'fixed',scope:{kind:'launch_feature',id:'admin_assistant'}}};
}
const reorder=v=>Array.isArray(v)?v.map(reorder):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).reverse().map(([k,x])=>[k,reorder(x)])):v;
test('deterministic operation and canonical public digest survive nested JSONB reordering',()=>{
 for(const action of ['set_role','ban']){const f=fixture(action),p=P.createRoleUserAdministrationProposal(f);
 assert.equal(p.proposalId,P.createRoleUserAdministrationProposal(f).proposalId);assert.equal(p.proposalId[14],'5');
 const publicValue=P.projectRoleUserAdministrationProposal(p,f),{requestSha256,...canonical}=publicValue;
 assert.equal(requestSha256,createHash('sha256').update(JSON.stringify(canonical)).digest('hex'));
 assert.deepEqual(P.validateRoleUserAdministrationProposal(reorder(p),f),p);
 assert.deepEqual(P.projectRoleUserAdministrationProposal(reorder(p),f),publicValue);
 assert.equal(publicValue.sourceSnapshotSha256,undefined);assert.equal(publicValue.origin,undefined);
 assert.equal(publicValue.target.email,undefined);
 assert.notEqual(P.createRoleUserAdministrationProposal({...f,callId:'other'}).proposalId,p.proposalId);
 }
});
test('choice source kind, identity, closed mode, action and explicit reason stay bounded',()=>{
 for(const mutate of [f=>f.selected.kind='merchant_product',f=>f.selected.sourceId=43,
 f=>f.selected.choiceId=[f.selected.choiceId],f=>f.selected.snapshotSha256=['a'.repeat(64)],f=>f.selected.snapshotSha256='bad',f=>f.administration.roleBan=false,
 f=>f.user.id=2147483648,f=>f.user.identity_kind='platform_user',f=>f.user.username='x'.repeat(101),
 f=>f.user.authority_version='9007199254740991',f=>f.user.authority_version='03',
 f=>f.user.banned_at='not-time',f=>f.modeCapability.featureId='review',
 f=>f.modeCapability.scope.extra=true,f=>f.role='owner',f=>f.reason='invented for set_role']){
 const f=fixture();mutate(f);assert.throws(()=>P.createRoleUserAdministrationProposal(f),{code:'ROLE_USER_ADMINISTRATION_PROPOSAL_INVALID'});
 }
 for(const reason of ['', '  ', '😀'.repeat(257), undefined])assert.throws(()=>P.createRoleUserAdministrationProposal({...fixture('ban'),reason}),{code:'ROLE_USER_ADMINISTRATION_PROPOSAL_INVALID'});
 const f=fixture('ban'),p=P.createRoleUserAdministrationProposal({...f,reason:'  exact text  '});assert.equal(p.reason,'  exact text  ');
});
test('private origin, public data, extra fields and source changes cannot bypass validation',()=>{
 const f=fixture(),p=P.createRoleUserAdministrationProposal(f);
 for(const mutate of [p=>p.origin.step=3,p=>p.target.userId=43,p=>p.target.extra='private',
 p=>p.reason='changed',p=>p.scopeKey='foreign',p=>p.modeCapability.effectiveMode='vuln',
 p=>p.sourceSnapshotSha256='bad',p=>p.extra=true]){
 const changed=structuredClone(p);mutate(changed);assert.throws(()=>P.validateRoleUserAdministrationProposal(changed,f),{code:'ROLE_USER_ADMINISTRATION_PROPOSAL_INVALID'});
 }
 assert.throws(()=>P.validateRoleUserAdministrationProposal(p,{...f,requestId:randomUUID()}),{code:'ROLE_USER_ADMINISTRATION_PROPOSAL_INVALID'});
});
