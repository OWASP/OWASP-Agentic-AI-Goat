import{createCustomerAvatarUploadAssessmentStore,createCustomerAvatarSvgAssessmentStore,CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY,CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY}from'./customerAvatarUploadAssessmentReference.mjs';
const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
test('avatar assessment admission stores IDs only and removal requires acknowledgement',async()=>{const values=new Map();
 const store=createCustomerAvatarUploadAssessmentStore({storage:{getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:async()=>{}});
 const ref=await store.submit({shopUserId:7,sessionId,requestId,startedAt:100});
 expect(JSON.parse(values.get(CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY))).toEqual({version:1,shopUserId:7,sessionId,requestId,startedAt:100});
 expect(JSON.stringify(ref)).not.toMatch(/file|path|token|operation/i);await store.clear(ref);
 expect(values.has(CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY)).toBe(false);
});
test('reload matches upload identity while retaining the assessment timestamp',async()=>{const values=new Map();
 const store=createCustomerAvatarUploadAssessmentStore({storage:{getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:async()=>{}});
 const grade=await store.submit({shopUserId:7,sessionId,requestId,startedAt:200});
 expect(store.read({version:1,shopUserId:7,sessionId,requestId,operationId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',startedAt:100})).toEqual(grade);
 expect(()=>store.read({shopUserId:8,sessionId,requestId,operationId:null,startedAt:100})).toThrow();
});

test('V06 and V08 assessment references remain distinct and IDs-only',async()=>{
 const values=new Map(),storage={getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush=async()=>{};
 const v06=createCustomerAvatarUploadAssessmentStore({storage,flush}),v08=createCustomerAvatarSvgAssessmentStore({storage,flush});expect(()=>createCustomerAvatarUploadAssessmentStore({storage,flush,key:CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY})).toThrow();expect(()=>createCustomerAvatarSvgAssessmentStore({storage,flush,key:CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY})).toThrow();
 const identity={shopUserId:7,sessionId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',startedAt:100};
 await v06.submit(identity);await v08.submit({...identity,startedAt:200});
 expect(values.has(CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY)).toBe(true);expect(values.has(CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY)).toBe(true);
 expect(()=>v08.read({...identity,shopUserId:8})).toThrow('changed');expect(()=>v08.read({...identity,sessionId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc'})).toThrow('changed');await v08.clear(v08.read(identity));
 expect(v06.read(identity)).toEqual(Object.freeze({version:1,...identity}));
});
