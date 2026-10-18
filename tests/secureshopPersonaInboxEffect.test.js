'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPersonaInboxEffect}=require('../server/services/secureshopPersonaInboxEffect');
test('candidate inbox effect shares the exact authority transaction and never calls pool-backed read',async()=>{
 const scope={launchId:'launch',scenarioId:'scenario',generation:1,platformOwnerId:1,platformSessionId:2},persona={id:3,role:'customer'};const client={query:async()=>({})};let held=false,calls=0;
 const fence={binding:{...scope,personaId:3,role:'customer'},withPersonaEffect:async work=>{held=true;try{return await work(client);}finally{held=false;}}};
 const wrapped=createPersonaInboxEffect({fence,repository:{read:async()=>{throw Error('would deadlock');},readWithClient:async(c,s,p,args)=>{assert.equal(c,client);assert.equal(held,true);assert.equal(s,scope);assert.equal(p,persona);calls++;return args;}}});
 assert.deepEqual(await wrapped.read(scope,persona,{operationId:'owned'}),{operationId:'owned'});assert.equal(calls,1);
 await assert.rejects(wrapped.read({...scope,platformOwnerId:9},persona,{}),{code:'SHOP_AUTH_INVALID'});assert.equal(calls,1);
});
