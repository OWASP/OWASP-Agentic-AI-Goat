import{createCustomerFileSummaryStore,createCustomerFileSummaryAssessmentStore,CUSTOMER_FILE_SUMMARY_KEY,CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY}from'./customerFileSummaryReference.mjs';
const ref={shopUserId:7,sessionId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',startedAt:100};
function memory(){const values=new Map();return{values,storage:{getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:async()=>{}};}
test('file-summary stores persist only exact IDs and reject cross-key wiring',async()=>{const state=memory(),run=createCustomerFileSummaryStore(state),assessment=createCustomerFileSummaryAssessmentStore(state);
 await run.submit(ref);await assessment.submit({...ref,startedAt:101});expect(run.read(7)).toEqual({version:1,...ref});expect(assessment.read(7)).toEqual({version:1,...ref,startedAt:101});
 for(const raw of state.values.values()){expect(raw).not.toMatch(/filename|message|operationId|bytes|authority/);}
 expect(()=>createCustomerFileSummaryStore({...state,key:CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY})).toThrow();expect(()=>createCustomerFileSummaryAssessmentStore({...state,key:CUSTOMER_FILE_SUMMARY_KEY})).toThrow();
});
test('delayed clear never restores an old reference over newer identity or after authority invalidation',async()=>{const old={version:1,...ref},newer={...old,requestId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',startedAt:200};
 for(const scenario of['newer','invalidated']){const values=new Map([[CUSTOMER_FILE_SUMMARY_KEY,JSON.stringify(old)]]);let release,current=true;const state={storage:{getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)},flush:()=>new Promise(resolve=>{release=resolve})},run=createCustomerFileSummaryStore(state),clearing=run.clear(old,()=>current);expect(values.has(CUSTOMER_FILE_SUMMARY_KEY)).toBe(false);
  if(scenario==='newer')values.set(CUSTOMER_FILE_SUMMARY_KEY,JSON.stringify(newer));else current=false;release();await expect(clearing).rejects.toThrow();expect(values.get(CUSTOMER_FILE_SUMMARY_KEY)??null).toBe(scenario==='newer'?JSON.stringify(newer):null);
 }
});
