'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSecureShopPersonaInboxRequestAuthority }
  = require('../server/services/secureshopPersonaInboxRequestAuthority');

const BINDING = Object.freeze({ launchId:'10000000-0000-4000-8000-000000000001',
  scenarioId:'20000000-0000-4000-8000-000000000001',generation:2,platformOwnerId:7,
  platformSessionId:8,shopUserId:12,role:'merchant' });
const SESSION='30000000-0000-4000-8000-000000000001';
const REQUEST='40000000-0000-4000-8000-000000000001';
const TARGET='50000000-0000-4000-8000-000000000001';

test('opaque authority binds immutable launch, persona, session, request, target and message coordinates',()=>{
  const authority=createSecureShopPersonaInboxRequestAuthority();
  const issued=authority.issue({binding:BINDING,sessionId:SESSION,requestId:REQUEST,targetId:TARGET,messageId:3});
  assert.equal(Object.isFrozen(issued.token),true);
  assert.deepEqual(authority.resolve(issued.token,{binding:BINDING,sessionId:SESSION,requestId:REQUEST}),
    {targetId:TARGET,messageId:3});
  for(const input of [
    {binding:{...BINDING,generation:3},sessionId:SESSION,requestId:REQUEST},
    {binding:BINDING,sessionId:'30000000-0000-4000-8000-000000000002',requestId:REQUEST},
    {binding:BINDING,sessionId:SESSION,requestId:'40000000-0000-4000-8000-000000000002'},
  ]) assert.throws(()=>authority.resolve(issued.token,input),{code:'PERSONA_INBOX_REQUEST_AUTHORITY_UNAVAILABLE'});
  issued.revoke();issued.revoke();
  assert.throws(()=>authority.resolve(issued.token,{binding:BINDING,sessionId:SESSION,requestId:REQUEST}),
    {code:'PERSONA_INBOX_REQUEST_AUTHORITY_UNAVAILABLE'});
});

test('concurrent request authorities remain distinct and cannot authorize each other',async()=>{
  const authority=createSecureShopPersonaInboxRequestAuthority();
  const secondRequest='40000000-0000-4000-8000-000000000002';
  const first=authority.issue({binding:BINDING,sessionId:SESSION,requestId:REQUEST,targetId:TARGET,messageId:1});
  const second=authority.issue({binding:BINDING,sessionId:SESSION,requestId:secondRequest,targetId:TARGET,messageId:3});
  const values=await Promise.all([
    Promise.resolve().then(()=>authority.resolve(first.token,{binding:BINDING,sessionId:SESSION,requestId:REQUEST})),
    Promise.resolve().then(()=>authority.resolve(second.token,{binding:BINDING,sessionId:SESSION,requestId:secondRequest})),
  ]);
  assert.deepEqual(values,[{targetId:TARGET,messageId:1},{targetId:TARGET,messageId:3}]);
  assert.throws(()=>authority.resolve(first.token,{binding:BINDING,sessionId:SESSION,requestId:secondRequest}),
    {code:'PERSONA_INBOX_REQUEST_AUTHORITY_UNAVAILABLE'});
});
