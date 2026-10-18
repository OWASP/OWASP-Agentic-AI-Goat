import{createCustomerAvatarTraversalReferenceStore,createCustomerAvatarTraversalAssessmentStore,
 decodeCustomerAvatarTraversalReference,CUSTOMER_AVATAR_TRAVERSAL_REFERENCE_KEY,CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY}from'./customerAvatarTraversalReference.mjs';
const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',operationId='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
function fixture(){const values=new Map(),storage={getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)};
 return{values,storage,reference:createCustomerAvatarTraversalReferenceStore({storage,flush:async()=>{}}),assessment:createCustomerAvatarTraversalAssessmentStore({storage,flush:async()=>{}})};}
test('V46 reference persists IDs only and cannot replace an acknowledged operation',async()=>{const f=fixture();const saved=await f.reference.saveIntent({shopUserId:46,sessionId,requestId,startedAt:1});
 const acknowledged=await f.reference.acknowledgeOperation(saved,operationId);expect(f.reference.read(46)).toEqual(acknowledged);
 expect(Object.keys(acknowledged).sort()).toEqual(['operationId','requestId','sessionId','shopUserId','startedAt','version']);
 await expect(f.reference.acknowledgeOperation(saved,'dddddddd-dddd-4ddd-8ddd-dddddddddddd')).rejects.toThrow(/changed/);
 expect(f.values.has(CUSTOMER_AVATAR_TRAVERSAL_REFERENCE_KEY)).toBe(true);});
test('V46 assessment reference is exact and independently retired',async()=>{const f=fixture();const saved=await f.reference.saveIntent({shopUserId:46,sessionId,requestId,startedAt:1});
 const grade=await f.assessment.submit({shopUserId:46,sessionId,requestId,startedAt:2});expect(f.assessment.read(saved)).toEqual(grade);
 expect(f.values.has(CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY)).toBe(true);await f.assessment.clear(grade);expect(f.assessment.read(saved)).toBeNull();expect(f.reference.read(46)).toEqual(saved);});
test('V46 decoder rejects client evidence, unknown fields, foreign owners and oversized values',()=>{expect(()=>decodeCustomerAvatarTraversalReference(JSON.stringify({version:1,shopUserId:46,sessionId,requestId,operationId:null,startedAt:1,evidence:'client'}))).toThrow();
 const f=fixture();expect(()=>f.reference.read(0)).toThrow();expect(()=>decodeCustomerAvatarTraversalReference('x'.repeat(641))).toThrow();});
