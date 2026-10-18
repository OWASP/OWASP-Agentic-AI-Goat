import { afterEach, beforeEach, expect, test } from '@jest/globals';
import { attachShopStorage } from './shopStorage.mjs';
import { clearPracticePaymentReference, decodePracticePaymentOperation, decodePracticePaymentSetup,
  readPracticePaymentReference, savePracticePaymentReference } from './practicePaymentOperation.mjs';
const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', scope = 'b'.repeat(64);
let release;
beforeEach(() => { const values = new Map(); release = attachShopStorage({ getItem:k=>values.get(k)??null, setItem:(k,v)=>values.set(k,v), removeItem:k=>values.delete(k), flush:async()=>{} }); });
afterEach(() => release?.());
const ref = { version:1, scopeKey:scope, operationId:id, scenario:'approved' };
test('accepts only the closed model handoff and opaque parent reference', async () => {
 expect(decodePracticePaymentSetup({version:1,kind:'practice_payment_setup',suggestedScenario:'declined'})).toEqual({version:1,kind:'practice_payment_setup',suggestedScenario:'declined'});
 expect(() => decodePracticePaymentSetup({version:1,kind:'practice_payment_setup',suggestedScenario:'approved',scopeKey:scope})).toThrow();
 await savePracticePaymentReference(ref); expect(readPracticePaymentReference()).toEqual(ref); await clearPracticePaymentReference(ref); expect(readPracticePaymentReference()).toBeNull();
});
test('requires an exact scoped immutable operation receipt while retaining typed absence', () => {
 expect(decodePracticePaymentOperation({scopeKey:scope,operationId:id,status:'not_found'},ref)).toEqual({status:'not_found'});
 const receipt={scopeKey:scope,operationId:id,status:'completed',paymentScenario:'approved',receipt:{version:1,operationId:id,kind:'payment.create',status:'completed',result:{cards:[{version:1,kind:'payment_method',choiceId:id,title:'Approved practice payment',detail:'Synthetic only'}]},replayed:true}};
 expect(decodePracticePaymentOperation(receipt,ref).status).toBe('completed');
 expect(() => decodePracticePaymentOperation({...receipt,scopeKey:'c'.repeat(64)},ref)).toThrow();
 expect(() => decodePracticePaymentOperation({...receipt,paymentScenario:'declined'},ref)).toThrow();
});
