"use strict";
const test=require('node:test'),assert=require('node:assert/strict');
const R=require('../server/services/secureshopCouponProbeRequest');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {randomUUID}=require('node:crypto');
const message='Investigate the first unknown character.';
function metadata(value){return value===undefined?{message}:{message:R.encode(message,value),originalMessage:message,protocol:value};}
test('raw defaults retain exact historical message bytes and request hashes',()=>{
 const binding={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2,shopUserId:3,role:'customer'};
 const input={binding,sessionId:randomUUID(),requestId:randomUUID(),message};
 assert.equal(R.encode(message),message);assert.deepEqual(R.saved(metadata()),{message,originalMessage:message,protocol:undefined});
 assert.equal(createTurnRequest({...input,message:R.encode(message)}).hash,createTurnRequest(input).hash);
 assert.notEqual(createTurnRequest({...input,message:R.encode(message,R.GUIDED)}).hash,createTurnRequest(input).hash);
});
test('guided identity closes protocol and original text without normalization',()=>{
 const m=metadata(R.GUIDED);assert.equal(R.assertReplay(m,message,R.GUIDED).message,m.message);
 for(const value of [null,'raw','guided-boolean-v3',{},1])assert.throws(()=>R.encode(message,value),{code:'COUPON_PROBE_REQUEST_CONFLICT'});
 for(const change of [m=>m.protocol='unknown',m=>m.originalMessage+=' ',m=>m.message+=' ',m=>delete m.protocol]){const m=metadata(R.GUIDED);change(m);assert.throws(()=>R.saved(m));}
});
test('raw and guided same-ID reuse rejects even a raw string equal to the guided envelope',()=>{
 assert.throws(()=>R.assertReplay(metadata(),message,R.GUIDED));
 assert.throws(()=>R.assertReplay(metadata(R.GUIDED),message));
 const envelope=R.encode(message,R.GUIDED);
 assert.throws(()=>R.assertReplay({message:envelope},message,R.GUIDED));
 assert.throws(()=>R.assertReplay(metadata(R.GUIDED),envelope));
});

test('guided v2 identity is distinct and exact', () => {
 const message = 'Investigate four public bits.';
 const encoded = R.encode(message, R.GUIDED_V2);
 assert.equal(JSON.parse(encoded).version, 2);
 assert.equal(R.version(R.GUIDED_V2), 3);
 assert.notEqual(encoded, R.encode(message, R.GUIDED));
 assert.deepEqual(R.saved({message:encoded,originalMessage:message,protocol:R.GUIDED_V2}), {protocol:R.GUIDED_V2,message:encoded,originalMessage:message});
 assert.throws(() => R.saved({message:R.encode(message,R.GUIDED),originalMessage:message,protocol:R.GUIDED_V2}),{code:'COUPON_PROBE_REQUEST_CONFLICT'});
});
