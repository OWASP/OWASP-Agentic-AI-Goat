import{createCustomerFilePathSummaryStore,createCustomerFilePathSummaryAssessmentStore,CUSTOMER_FILE_PATH_SUMMARY_KEY,CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY}from'./customerFilePathSummaryReference.mjs';
const ref={shopUserId:7,sessionId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',startedAt:100};
function memory(){const values=new Map();return{values,storage:{getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:async()=>{}};}
test('file-path-summary stores persist only exact IDs and reject cross-key wiring',async()=>{const state=memory(),run=createCustomerFilePathSummaryStore(state),assessment=createCustomerFilePathSummaryAssessmentStore(state);
 await run.submit(ref);await assessment.submit({...ref,startedAt:101});expect(run.read(7)).toEqual({version:1,...ref});expect(assessment.read(7)).toEqual({version:1,...ref,startedAt:101});
 for(const raw of state.values.values()){expect(raw).not.toMatch(/filename|message|operationId|bytes|authority/);}
 expect(()=>createCustomerFilePathSummaryStore({...state,key:CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY})).toThrow();expect(()=>createCustomerFilePathSummaryAssessmentStore({...state,key:CUSTOMER_FILE_PATH_SUMMARY_KEY})).toThrow();
});
test('delayed clear never restores an old reference over newer identity or after authority invalidation',async()=>{const old={version:1,...ref},newer={...old,requestId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',startedAt:200};
 for(const scenario of['newer','invalidated']){const values=new Map([[CUSTOMER_FILE_PATH_SUMMARY_KEY,JSON.stringify(old)]]);let release,current=true;const state={storage:{getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:()=>new Promise(resolve=>{release=resolve})},run=createCustomerFilePathSummaryStore(state),clearing=run.clear(old,()=>current);expect(values.has(CUSTOMER_FILE_PATH_SUMMARY_KEY)).toBe(false);
  if(scenario==='newer')values.set(CUSTOMER_FILE_PATH_SUMMARY_KEY,JSON.stringify(newer));else current=false;release();await expect(clearing).rejects.toThrow();expect(values.get(CUSTOMER_FILE_PATH_SUMMARY_KEY)??null).toBe(scenario==='newer'?JSON.stringify(newer):null);
 }
});

test('V44 rejects secret/path-bearing, malformed and foreign-key references without overwriting another owner',async()=>{
 const state=memory(),run=createCustomerFilePathSummaryStore(state);
 for(const extra of[{authorityKey:'jwt'},{path:'../etc/passwd'},{nativePath:'/private/root'},{operationId:ref.requestId}])await expect(run.submit({...ref,...extra})).rejects.toThrow();
 await run.submit(ref);expect(run.read(8)).toBeNull();await expect(run.submit({...ref,shopUserId:8})).rejects.toThrow();expect(run.read(7)).toEqual({version:1,...ref});
 expect(()=>createCustomerFilePathSummaryStore({...state,key:'secureshop.customer-file-summary.lesson.v1'})).toThrow();
});
