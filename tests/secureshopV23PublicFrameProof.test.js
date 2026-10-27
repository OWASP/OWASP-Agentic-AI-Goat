'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fixture=require('./postgres/secureshopV23PublicRendered.integration.test.js');
const body=fixture.runNative.toString();
test('public administrator composer is resolved inside actual child frame',async()=>{
 const seen=[];const frame={detached:false,async waitForSelector(selector,options){seen.push(['composer',selector,options]);}};
 const handle={async contentFrame(){return frame},async dispose(){seen.push(['dispose']);}};
 const page={async waitForSelector(selector,options){assert.equal(selector,'iframe[title="SecureShop"]');assert.equal(options.timeout,30000);return handle;}};
 assert.equal(await fixture.publicAdminFrame(page),frame);
 assert.deepEqual(seen,[['composer','[data-testid="admin-role-composer-slot"] textarea',{visible:true,timeout:30000}],['dispose']]);
 assert.match(body,/const frame=await publicAdminFrame\(page\)/);
 assert.match(body,/sendRenderedAdminTurn\(\{page,frame,origin/);
 assert.doesNotMatch(body,/frame:page/);
});
test('missing and detached frame deny without parent fallback',async()=>{
 await assert.rejects(fixture.publicAdminFrame({async waitForSelector(){return null;}}));
 let disposed=0;
 await assert.rejects(fixture.publicAdminFrame({async waitForSelector(){return {async contentFrame(){return {detached:true}},async dispose(){disposed++;}};}}));
 assert.equal(disposed,1);
});
test('frame composer timeout stays bounded and releases element handle',async()=>{
 const expected=Object.assign(new Error('private'),{name:'TimeoutError'});let disposed=0;
 await assert.rejects(fixture.publicAdminFrame({async waitForSelector(){return {async contentFrame(){return {detached:false,async waitForSelector(){throw expected;}}},async dispose(){disposed++;}};}}),e=>e===expected);
 assert.equal(disposed,1);
});
test('private proof module is not shadowed by per-turn result binding',()=>{
 const declaration=body.match(/let (privateProof|privateResult);/);assert(declaration);
 assert.match(body,/const proofReader=privateProof\.createPrivateProofReader/);
 const value={};const make=new Function('privateProof',`{const proofReader=privateProof.createPrivateProofReader({}); ${declaration[0]} return proofReader;}`);
 assert.equal(make({createPrivateProofReader:()=>value}),value);
 assert.match(body,/observation,privateProof:privateResult,evidence/);
 assert.match(body,/registrationReceipt:privateResult\.record/);
 assert.match(body,/const privateOrigin=privateResult\.privateOrigin/);
});
test('turn diagnostics retain bounded stage and safe error categories',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopV23PublicRendered.integration.test.js'),'utf8');
 const helper=source.slice(source.indexOf('function publicFailureDiagnostic('),source.indexOf('async function runPublicNative('));
 const diagnostic=new Function('require',helper+';return publicFailureDiagnostic;')(require);
 assert.equal(diagnostic('turn-proof',new ReferenceError('private')),'V23_PUBLIC_FAILURE:turn-proof:ReferenceError:unknown');
 assert.equal(diagnostic('turn-frame',Object.assign(new Error('private'),{name:'TimeoutError'})),'V23_PUBLIC_FAILURE:turn-frame:TimeoutError:unknown');
 const accessor={get name(){throw Error('forbidden')},get code(){throw Error('forbidden')}};
 assert.equal(diagnostic('turn-login',accessor),'V23_PUBLIC_FAILURE:turn-login:unknown:unknown');
 assert.equal(diagnostic('turn-submit',new Proxy({},{getOwnPropertyDescriptor(){throw Error('forbidden')}})),'V23_PUBLIC_FAILURE:turn-submit:unknown:unknown');
});
test('partial calls survive failure without duplication or role confusion',()=>{
 const first={requestSha256:'first'},second={requestSha256:'second'},judged={requestSha256:'judge'};
 const actor={calls:[first,second]},judge={calls:[judged]};
 const wire={actors:[first],judges:[judged]};
 fixture.retainObservedPublicCalls(wire,[actor,judge],judge);
 assert.deepEqual(wire,{actors:[first,second],judges:[judged]});
 fixture.retainObservedPublicCalls(wire,[actor,judge],judge);
 assert.equal(wire.actors.length,2);assert.equal(wire.judges.length,1);
 assert.notEqual(wire.actors[0],first);
 assert.match(body,/if\(primary\|\|secondary.length\)retainObservedPublicCalls\(wire,relays,judgeRelay\)/);
 const empty={actors:[],judges:[]};fixture.retainObservedPublicCalls(empty,[actor],undefined);
 assert.equal(empty.actors.length,2);assert.deepEqual(empty.judges,[]);
});
