import{createCustomerAvatarUploadReferenceStore,decodeCustomerAvatarUploadReference,
 CUSTOMER_AVATAR_UPLOAD_REFERENCE_KEY}from'./customerAvatarUploadReference.mjs';
const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
 operationId='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
function fixture(){const values=new Map();return{values,store:createCustomerAvatarUploadReferenceStore({storage:{
 getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:async()=>{}})}}
test('avatar reference persists IDs only before multipart and acknowledges the returned operation',async()=>{
 const{values,store}=fixture();const intent={shopUserId:7,sessionId,requestId,startedAt:100};
 const saved=await store.saveIntent(intent);expect(saved.operationId).toBeNull();
 expect(JSON.parse(values.get(CUSTOMER_AVATAR_UPLOAD_REFERENCE_KEY))).toEqual({version:1,...intent,operationId:null});
 const acknowledged=await store.acknowledgeOperation(saved,operationId);
 expect(acknowledged.operationId).toBe(operationId);expect(JSON.stringify(acknowledged)).not.toMatch(/file|message|asset|token/i);
 await store.clear(acknowledged);expect(values.has(CUSTOMER_AVATAR_UPLOAD_REFERENCE_KEY)).toBe(false);
});
test('avatar reference rejects private fields and changed acknowledgement',async()=>{
 expect(()=>decodeCustomerAvatarUploadReference(JSON.stringify({version:1,shopUserId:7,sessionId,requestId,
  operationId:null,startedAt:100,filename:'private.svg'}))).toThrow();
 const{store}=fixture();const saved=await store.saveIntent({shopUserId:7,sessionId,requestId,startedAt:100});
 await expect(store.acknowledgeOperation({...saved,requestId:operationId},operationId)).rejects.toThrow(/changed/);
});
