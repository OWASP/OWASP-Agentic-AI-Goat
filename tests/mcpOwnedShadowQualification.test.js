'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const q=require('../server/services/mcp/ownedQualification');
test('shadow capability is explicit and never implicitly enables production grading',()=>{
 const base=q.createOwnedQualification(true);
 assert.equal(q.withShadowQualification(base,{capability:q.SHADOW_CAPABILITY}),base);
 assert.equal(base.canGrade('mcp_shadow_server'),false);
 assert.throws(()=>q.withShadowQualification(base,{enabled:true,capability:'forged'}));
 assert.throws(()=>q.withShadowQualification({}, {enabled:true,capability:q.SHADOW_CAPABILITY}));
});
test('private shadow qualification preserves HTTP and admits registration, not arbitrary imported names',()=>{
 const base=q.createOwnedQualification(true,{httpCapability:q.HTTP_CAPABILITY});
 const value=q.withShadowQualification(base,{enabled:true,capability:q.SHADOW_CAPABILITY});
 assert.equal(value.canGrade('mcp_shadow_server'),true);assert.equal(value.canGrade('mcp_ssrf'),true);
 assert.equal(q.hasHttpQualification(value),true);assert.equal(q.isProductionQualification(value),true);
 const allow=q.createOwnedToolAuthorizer(value);
 assert.equal(allow('register_server'),true);assert.equal(allow('fetch_url'),true);
 assert.equal(allow('shadow_'+ 'a'.repeat(32)+'_read_policy'),false);
 assert.equal(q.createOwnedToolAuthorizer({...value})('register_server'),false);
 assert.equal(q.isProductionQualification({...value}),false);
 assert.equal(q.baseQualification(value),q.baseQualification(base));
});
