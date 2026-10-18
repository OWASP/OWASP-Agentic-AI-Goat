import {createCustomerCheckoutAuditReferenceStore,decodeCustomerCheckoutAuditReference,
 CUSTOMER_CHECKOUT_AUDIT_REFERENCE_KEY,CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY}
 from './customerCheckoutAuditReference.mjs';

const reference={shopUserId:7,sessionId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 requestId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
 checkoutOperationId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',startedAt:100};
function fixture(){
 const values=new Map(),flush=jest.fn(async()=>{});
 const storage={getItem:key=>values.get(key)??null,
  setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)};
 return{values,flush,store:createCustomerCheckoutAuditReferenceStore({storage,flush})};
}

test('checkout-audit reference is exact and contains IDs only',()=>{
 expect(decodeCustomerCheckoutAuditReference(null)).toBeNull();
 expect(decodeCustomerCheckoutAuditReference(JSON.stringify({version:1,...reference})))
  .toEqual({version:1,...reference});
 for(const value of [{...reference,teachingToken:'secret'},{...reference,checkoutOperationId:'bad'},
  {...reference,shopUserId:0}])
  expect(()=>decodeCustomerCheckoutAuditReference(JSON.stringify({version:1,...value}))).toThrow();
});

test('acknowledged save blocks a second model request and exact clear permits a new lesson',async()=>{
 const{store,flush,values}=fixture();await store.save(reference);
 expect(flush).toHaveBeenCalledTimes(1);
 expect(JSON.parse(values.get(CUSTOMER_CHECKOUT_AUDIT_REFERENCE_KEY)))
  .toEqual({version:1,...reference});
 await expect(store.save({...reference,requestId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd'}))
  .rejects.toThrow(/Check the saved/);
 await store.clear(reference);expect(store.read(7)).toBeNull();
});

test('assessment admission is a separate IDs-only acknowledgement cleared with the request',async()=>{
 const{store,values}=fixture();await store.save(reference);
 expect(store.readAssessment(reference)).toBeNull();
 await store.submitAssessment(reference);
 expect(JSON.parse(values.get(CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY)))
  .toEqual({version:1,...reference});
 await expect(store.submitAssessment(reference)).rejects.toThrow(/saved checkout-audit assessment/i);
 expect(()=>store.readAssessment({...reference,requestId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd'}))
  .toThrow(/assessment changed/i);
 await store.clear(reference);
 expect(values.has(CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY)).toBe(false);
});

test('an acknowledged assessment-only clear preserves the original request',async()=>{
 const{store,values,flush}=fixture();await store.save(reference);await store.submitAssessment(reference);
 await store.clearAssessment(reference);
 expect(flush).toHaveBeenCalledTimes(3);
 expect(store.read(7)).toEqual({version:1,...reference});
 expect(values.has(CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY)).toBe(false);
 await store.submitAssessment(reference);
 expect(store.readAssessment(reference)).toEqual({version:1,...reference});
});
