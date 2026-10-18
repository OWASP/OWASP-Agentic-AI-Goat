'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const{createMailActualTransport}=require('./postgres/secureshopMailActualTransport');

test('V03 exact protocol admits 27 physical calls while every other protocol remains capped at 14',async()=>{
 const original=global.fetch;let metadataCalls=0;
 global.fetch=async()=>{metadataCalls++;throw Error('controlled metadata boundary');};
 try{
  await assert.rejects(createMailActualTransport({maxHttpCalls:27,protocol:'v03-listing-optimize-v1'}),/controlled metadata boundary/);
  assert.equal(metadataCalls,1);
  for(const options of [
   {maxHttpCalls:27},
   {maxHttpCalls:15},
   {maxHttpCalls:27,protocol:'mail-v1'},
   {maxHttpCalls:28,protocol:'v03-listing-optimize-v1'},
  ]) await assert.rejects(createMailActualTransport(options),TypeError);
  assert.equal(metadataCalls,1,'invalid budgets and protocols must fail before model metadata access');
 }finally{global.fetch=original;}
});
