'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createSecureShopPersonaInboxRepository } = require('../server/database/postgres/secureshopPersonaInboxRepository');
const scope = { targetId:'10000000-0000-4000-8000-000000000001', launchId:'20000000-0000-4000-8000-000000000001',
  scenarioId:'30000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:1,platformSessionId:2 };
const operationId = '40000000-0000-4000-8000-000000000001';
function fixture({ denied=false, failAudit=false, staleAfterAudit=false }={}) {
  const calls=[], events=[]; let appended=false;
  const row = { event_id:operationId,message_id:7,owner_shop_user_id:12,owner_shop_role:'merchant',
    acl_mode:denied?'enforced':'advisory',acl_decision:'deny',acl_version:denied?2:1,
    cross_persona:true,disclosed:!denied,body:denied?null:'owned synthetic note',
    body_sha256:denied?null:crypto.createHash('sha256').update('owned synthetic note').digest(),subject:'note' };
  const client={ async query(sql){ calls.push(sql); return {rows:sql.includes('read_persona_inbox_message')?[row]:[]}; }, release(){calls.push('release');} };
  const pool={async connect(){return client;},async query(){throw new Error('outside transaction');}};
  const repository=createSecureShopPersonaInboxRepository(pool,{
    async checkCurrent(){if(appended&&staleAfterAudit)throw new Error('stale');},async checkAclTransition(){},async checkCleanup(){},
    auditStore:{async append(tx,event){assert.equal(tx,client);calls.push('audit');events.push(event);appended=true;if(failAudit)throw new Error('audit unavailable');}}
  });
  return {calls,events,read:()=>repository.read(scope,{id:3,role:'customer'},{messageId:7,operationId})};
}
test('inbox disclosure and denial journal the actual receipt in its transaction',async()=>{
  for(const denied of [false,true]){
    const f=fixture({denied}); const result=await f.read();
    assert.equal(result.disclosed,!denied);
    assert.equal(f.events[0].outcome,denied?'denied':'completed');
    assert.equal(f.events[0].eventId,operationId);
    assert.equal(f.events[0].sourceId,operationId);
    assert.deepEqual(f.events[0].persona,{id:3,role:'customer'});
    assert.equal(JSON.parse(f.events[0].paramsJson).disclosed,!denied);
    assert.equal(f.events[0].paramsJson.includes('owned synthetic note'),false);
    assert.deepEqual(f.calls.slice(-3),['audit','COMMIT','release']);
  }
});
test('audit failure or final authority loss rolls back the inbox access receipt',async()=>{
  for(const options of [{failAudit:true},{staleAfterAudit:true}]){
    const f=fixture(options);await assert.rejects(f.read(),/audit unavailable|stale/);
    assert.equal(f.calls.includes('COMMIT'),false);
    assert.deepEqual(f.calls.slice(-2),['ROLLBACK','release']);
  }
});
