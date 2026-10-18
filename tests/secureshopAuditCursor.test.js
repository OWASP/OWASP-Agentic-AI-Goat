'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {encodeAuditCursor,decodeAuditCursor}=require('../server/services/secureshopAuditCursor');
const row={ts:'2026-09-19T01:02:03.123456Z',store:'review',eventId:'10000000-0000-4000-8000-000000000001'};
test('cursor round-trip preserves microsecond order and cross-store identity',()=>{
 for(const store of ['agents','review']){
  const source={...row,store};assert.deepEqual(decodeAuditCursor(encodeAuditCursor(source)),source);
 }
 assert.notEqual(encodeAuditCursor(row),encodeAuditCursor({...row,ts:'2026-09-19T01:02:03.123457Z'}));
});
test('cursor rejects authority fields, malformed dates, ambiguous encoding and unbounded input',()=>{
 for(const value of [{...row,owner:7},{...row,ts:'2026-02-30T01:02:03.123456Z'},
  {...row,ts:'2026-09-19T25:02:03.123456Z'},{...row,store:'identity'},{...row,eventId:'bad'}])
  assert.throws(()=>encodeAuditCursor(value),{code:'INVALID_ARGUMENT'});
 const valid=encodeAuditCursor(row);
 for(const value of [null,{},'a'.repeat(257),valid+'=',Buffer.from(JSON.stringify({...row,owner:7})).toString('base64url')])
  assert.throws(()=>decodeAuditCursor(value),{code:'INVALID_ARGUMENT'});
});
