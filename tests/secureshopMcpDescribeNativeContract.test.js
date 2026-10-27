'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {projectFoundationActor}=require('./helpers/secureshopMcpDescribeFoundationActor');
const {createSecureShopBoundAclRepository}=require('../server/database/postgres/secureshopBoundAclRepository');
const {REGISTRY_SHA256,MCP_DESCRIBE_KEY,MCP_LIST_KEY}=require('../server/services/secureshopBoundAclRegistry');

test('native owner projection enters the genuine policy API without carrying a callable repository',async()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
 const owner={scope,persona:{id:3,role:'admin'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},repository(){}};
 const actor=projectFoundationActor(owner);
 assert.deepEqual(Object.keys(actor),['scope','persona','personaSession']);
 assert.doesNotThrow(()=>structuredClone(actor));
 assert.throws(()=>structuredClone(owner),{name:'DataCloneError'});
 let captures=0;
 const client={async query(sql){
  if(sql.startsWith('SET LOCAL')||sql.startsWith('INSERT INTO secureshop_agents.bound_tool_policy_heads'))return{rows:[]};
  if(sql.includes('FROM secureshop_agents.bound_tool_policy_heads'))return{rows:[{policy_version:'1',enforcement_enabled:false,registry_sha256:REGISTRY_SHA256}]};
  if(sql.includes('FROM secureshop_agents.bound_tool_policy_overrides'))return{rows:[]};
  throw new Error('Unexpected SQL in controlled API entry');
 }};
 const personaAuthority={async capture(request){
  captures++;
  return {binding:{...request.scope,personaId:request.personaId,role:request.role,
   sessionId:request.sessionId,authorityVersion:request.authorityVersion},
  async withPersonaEffect(work){return work(client);},async assertRemoteAdmission(){}};
 }};
 const repository=createSecureShopBoundAclRepository({personaAuthority,audit:{async append(){throw new Error('read-only API appended audit');}}});
 const policy=await repository.readPolicy(actor);
 assert.equal(captures,1);
 assert.equal(policy.rows.find(row=>row.toolKey===MCP_DESCRIBE_KEY).allowed.admin,true);
 assert.equal(policy.rows.find(row=>row.toolKey===MCP_LIST_KEY).allowed.admin,true);
 await assert.rejects(repository.readPolicy(owner),{name:'DataCloneError'});
 assert.equal(captures,1,'unprojected callable owner fails before authority capture');
});
