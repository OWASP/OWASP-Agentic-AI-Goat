import { readForgettablePolicyReferences, forgetPolicyReference, policyRequestDigest, policyMutationDigests, assertPolicyReceipt, savePolicyPending, assertPolicyPendingCurrent, readPolicyState, acknowledgePolicyPending, clearPolicyPending, markPolicyRevisionConflict } from './policyOperation.js';
import { SHOP_PROMPT_POLICY_KEY } from '../../utils/shopStorage.mjs';
const {createHash,webcrypto,randomUUID}=require('node:crypto');
const {TextEncoder}=require('node:util');
beforeEach(()=>{localStorage.clear();global.TextEncoder=TextEncoder;Object.defineProperty(global.crypto,'subtle',{configurable:true,value:webcrypto.subtle});});
const request=()=>({operationId:randomUUID(),name:'policy',markdown:'Unchanged {{ teaching }}',injected_into:['merchant','admin']});
const metadata=()=>({scopeKey:'a'.repeat(64),operationId:randomUUID(),expectedVersion:'1',action:'save',name:'policy',requestSha256:'b'.repeat(64)});
const hash=text=>createHash('sha256').update(text).digest('hex');
test('browser digest matches exact backend canonical request with sorted targets',async()=>{
 const value=request();expect(await policyRequestDigest(value)).toBe(hash(JSON.stringify({version:1,operationId:value.operationId,name:value.name,markdown:value.markdown,targets:['admin','merchant']})));
});
test('task mutation digests bind original targets while renderer digest binds role projection',async()=>{
 const value={...request(),injected_into:['summarizer','merchant','review-moderator']};
 const actual=await policyMutationDigests(value,['summarizer','review-moderator']);
 expect(actual.requestSha256).toBe(hash(JSON.stringify({version:1,operationId:value.operationId,name:value.name,markdown:value.markdown,targets:['customer','merchant']})));
 expect(actual.policyRequestSha256).toBe(hash(JSON.stringify({version:2,request:{contractVersion:2,operationId:value.operationId,name:value.name,markdown:value.markdown,targets:['merchant','review-moderator','summarizer']}})));
 const roleOnly=request();expect(await policyMutationDigests(roleOnly,[])).toEqual({requestSha256:await policyRequestDigest(roleOnly)});
});
test.each([
 [{...request(),injected_into:['summarizer']},[]],
 [{...request(),injected_into:['analytics']},['summarizer']],
 [{...request(),injected_into:['summarizer','summarizer']},['summarizer']],
 [request(),['summarizer','summarizer']],
])('task mutation digest rejects unadvertised, unsupported, duplicate input: %p',async(input,tasks)=>{
 await expect(policyMutationDigests(input,tasks)).rejects.toThrow();
});
test.each([{operationId:'not-a-uuid'},{name:'bad\u0000name'},{name:'bad\ud800'},{markdown:'bad\udc00'},{injected_into:new Array(1)},{injected_into:['admin',,'merchant']},{injected_into:['admin','admin']}])('malformed renderer input rejects before hashing: %p',async patch=>{
 await expect(policyRequestDigest({...request(),...patch})).rejects.toThrow();
});
test.each([{expectedVersion:'9223372036854775808'},{expectedVersion:1},{scopeKey:'not-a-scope'},{name:'bad\u0001name'},{name:'bad\ud800'}])('durable metadata rejects malformed primitive: %p',async patch=>{
 await expect(savePolicyPending({...metadata(),...patch})).rejects.toThrow();expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBeNull();
});
test.each(['bad\u0000text','bad\ud800','bad\udc00'])('rendered receipt rejects malformed text despite matching byte hash',async rendered=>{
 const operation=metadata(),receipt={operationId:operation.operationId,version:'2',requestSha256:operation.requestSha256,renderResult:{version:1,operationId:operation.operationId,requestSha256:operation.requestSha256,isolation:'bwrap-policy-template-v1',rendered,renderedSha256:hash(rendered),exitCode:0,timedOut:false,truncated:false,drained:true}};
 await expect(assertPolicyReceipt(receipt,operation)).rejects.toThrow();
});
test('optional task digest survives storage and must have exact receipt presence and value',async()=>{
 const operation={...metadata(),policyRequestSha256:'c'.repeat(64)};
 await savePolicyPending(operation);expect(readPolicyState(operation.scopeKey).pending).toEqual(operation);
 const rendered='ok',base={operationId:operation.operationId,version:'2',requestSha256:operation.requestSha256,
  renderResult:{version:1,operationId:operation.operationId,requestSha256:operation.requestSha256,isolation:'bwrap-policy-template-v1',rendered,renderedSha256:hash(rendered),exitCode:0,timedOut:false,truncated:false,drained:true}};
 await expect(assertPolicyReceipt(base,operation)).rejects.toThrow();
 await expect(assertPolicyReceipt({...base,policyRequestSha256:'d'.repeat(64)},operation)).rejects.toThrow();
 await expect(assertPolicyReceipt({...base,policyRequestSha256:operation.policyRequestSha256},operation)).resolves.toBeTruthy();
 await expect(assertPolicyReceipt({...base,policyRequestSha256:operation.policyRequestSha256},metadata())).rejects.toThrow();
 await expect(savePolicyPending({...metadata(),action:'delete',requestSha256:null,policyRequestSha256:'c'.repeat(64)})).rejects.toThrow();
});
test('v2 literal and isolated policy results validate closed evidence without treating text as an effect',async()=>{
 const operation=metadata(),rendered='Policy <img src=x> {{ text }}';
 const common={version:2,operationId:operation.operationId,requestSha256:operation.requestSha256,
  executionSha256:'c'.repeat(64),rendered,renderedSha256:hash(rendered)};
 const outer=renderResult=>({operationId:operation.operationId,version:'2',requestSha256:operation.requestSha256,renderResult});
 await expect(assertPolicyReceipt(outer({...common,kind:'literal'}),operation)).resolves.toBeTruthy();
 const witness={version:1,workerAttested:true,commandEffectObserved:true,effectSha256:'d'.repeat(64),
  compilerSha256:'e'.repeat(64),workerSha256:'f'.repeat(64)};
 const isolated={...common,kind:'isolated_template',isolation:'bwrap-policy-template-v1',exitCode:0,
  timedOut:false,truncated:false,drained:true,effectWitness:witness};
 await expect(assertPolicyReceipt(outer(isolated),operation)).resolves.toBeTruthy();
 await expect(assertPolicyReceipt(outer({...isolated,effectWitness:{...witness,commandEffectObserved:false}}),operation)).rejects.toThrow();
 await expect(assertPolicyReceipt(outer({...isolated,effectWitness:{...witness,workerAttested:false}}),operation)).rejects.toThrow();
 await expect(assertPolicyReceipt(outer({...common,kind:'literal',effectWitness:witness}),operation)).rejects.toThrow();
 await expect(assertPolicyReceipt(outer({...isolated,renderedSha256:'0'.repeat(64)}),operation)).rejects.toThrow();
 await expect(assertPolicyReceipt(outer({...isolated,extra:'unexpected'}),operation)).rejects.toThrow();
});
test('outer policy receipt is action-aware and rejects extra or malformed replay fields', async () => {
 const operation=metadata(),rendered='ok';
 const result={version:1,operationId:operation.operationId,requestSha256:operation.requestSha256,
  isolation:'bwrap-policy-template-v1',rendered,renderedSha256:hash(rendered),exitCode:0,
  timedOut:false,truncated:false,drained:true};
 const receipt={operationId:operation.operationId,version:'2',requestSha256:operation.requestSha256,renderResult:result};
 await expect(assertPolicyReceipt(receipt,operation)).resolves.toBeTruthy();
 await expect(assertPolicyReceipt({...receipt,replayed:true},operation)).resolves.toBeTruthy();
 for(const malformed of [{...receipt,replayed:false},{...receipt,replayed:'true'},
  {...receipt,deleted:true},{...receipt,source:'unexpected'}])
  await expect(assertPolicyReceipt(malformed,operation)).rejects.toThrow();
 const deletion={...operation,action:'delete',requestSha256:null};
 const deleted={operationId:deletion.operationId,version:'2',requestSha256:'c'.repeat(64),deleted:true};
 await expect(assertPolicyReceipt(deleted,deletion)).resolves.toBeTruthy();
 await expect(assertPolicyReceipt({...deleted,replayed:true},deletion)).resolves.toBeTruthy();
 for(const malformed of [{...deleted,renderResult:result},{...deleted,deleted:false},{...deleted,replayed:false}])
  await expect(assertPolicyReceipt(malformed,deletion)).rejects.toThrow();
 const preview={...operation,action:'preview'};
 await expect(assertPolicyReceipt({...receipt,version:'1'},preview)).resolves.toBeTruthy();
 await expect(assertPolicyReceipt(receipt,preview)).rejects.toThrow();
});
test('bounded unknown history preserves earlier IDs and clearing history cannot erase current pending',async()=>{
 const old=metadata();await savePolicyPending(old);await acknowledgePolicyPending(old);const next=metadata();await savePolicyPending(next);await clearPolicyPending(old);expect(readPolicyState(old.scopeKey)).toEqual({pending:next,history:[]});
 await acknowledgePolicyPending(next);for(let i=0;i<7;i++){const entry=metadata();await savePolicyPending(entry);await acknowledgePolicyPending(entry);}const ninth=metadata();await savePolicyPending(ninth);await expect(acknowledgePolicyPending(ninth)).rejects.toThrow('Eight');expect(readPolicyState(old.scopeKey).history).toHaveLength(8);
});
test('switching scopes preserves unknown operations and clearing one cannot erase another',async()=>{
 const a=metadata(),b={...metadata(),scopeKey:'c'.repeat(64)};
 await savePolicyPending(a);await acknowledgePolicyPending(a);await savePolicyPending(b);
 expect(readPolicyState(a.scopeKey)).toEqual({pending:null,history:[a]});
 expect(readPolicyState(b.scopeKey)).toEqual({pending:b,history:[]});
 await clearPolicyPending(b);expect(readPolicyState(a.scopeKey)).toEqual({pending:null,history:[a]});
 await clearPolicyPending(a);expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBeNull();
});
test('legacy single-scope pending survives migration on another scope write',async()=>{
 const a=metadata(),b={...metadata(),scopeKey:'c'.repeat(64)};
 localStorage.setItem(SHOP_PROMPT_POLICY_KEY,JSON.stringify({version:1,scopeKey:a.scopeKey,pending:a,history:[]}));
 await savePolicyPending(b);expect(readPolicyState(a.scopeKey).pending).toEqual(a);
 expect(JSON.parse(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).version).toBe(2);
});
test('multi-scope capacity fails before overwriting retained recovery metadata',async()=>{
 let before,failed=false;
 for(let i=0;i<100;i++){
  const operation={...metadata(),scopeKey:hash(String(i))};before=localStorage.getItem(SHOP_PROMPT_POLICY_KEY);
  try{await savePolicyPending(operation);}catch(error){expect(error.message).toMatch(/limit/);failed=true;break;}
 }
 expect(failed).toBe(true);expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBe(before);
});

test('closed known-conflict metadata preserves other scopes and never enters unknown history',async()=>{
 const operation=metadata(),sibling={...metadata(),scopeKey:'c'.repeat(64)};await savePolicyPending(operation);await savePolicyPending(sibling);await markPolicyRevisionConflict(operation);
 expect(readPolicyState(operation.scopeKey).pending).toEqual({...operation,outcome:'revision_conflict'});expect(readPolicyState(sibling.scopeKey).pending).toEqual(sibling);
 await expect(acknowledgePolicyPending(operation)).rejects.toThrow('Known conflict');await clearPolicyPending(operation);expect(readPolicyState(sibling.scopeKey).pending).toEqual(sibling);
});
test('exact pending comparison refuses same-UUID replacement before send or clear',async()=>{
 const original=metadata();await savePolicyPending(original);
 expect(assertPolicyPendingCurrent(original)).toBe(true);
 const replacement={...original,expectedVersion:'2'};
 await savePolicyPending(replacement);
 expect(()=>assertPolicyPendingCurrent(original)).toThrow('changed');
 await expect(clearPolicyPending(original)).rejects.toThrow('changed');
 await expect(acknowledgePolicyPending(original)).rejects.toThrow('changed');
 expect(readPolicyState(original.scopeKey).pending).toEqual(replacement);
});
test('unknown outcome enums and changed request cannot manufacture known-conflict metadata',async()=>{
 const operation=metadata();await expect(savePolicyPending({...operation,outcome:'completed'})).rejects.toThrow();await savePolicyPending(operation);await expect(markPolicyRevisionConflict({...operation,expectedVersion:'2'})).rejects.toThrow();expect(readPolicyState(operation.scopeKey).pending).toEqual(operation);
});
test('forget exact history or foreign pending preserves current pending and sibling references',async()=>{
 const current=metadata(),old={...metadata(),scopeKey:'c'.repeat(64)},sibling={...metadata(),scopeKey:'d'.repeat(64)};
 await savePolicyPending(current);await savePolicyPending(old);await savePolicyPending(sibling);
 const references=readForgettablePolicyReferences(current.scopeKey);expect(references.map(r=>r.operation)).toEqual([old,sibling]);
 await expect(forgetPolicyReference({kind:'pending',operation:current},current.scopeKey)).rejects.toThrow('Dismiss');
 await expect(forgetPolicyReference({kind:'pending',operation:{...old,expectedVersion:'2'}},current.scopeKey)).rejects.toThrow('changed');
 await forgetPolicyReference(references[0],current.scopeKey);expect(readPolicyState(old.scopeKey).pending).toBeNull();expect(readPolicyState(current.scopeKey).pending).toEqual(current);expect(readPolicyState(sibling.scopeKey).pending).toEqual(sibling);
 await acknowledgePolicyPending(current);const history=readForgettablePolicyReferences(current.scopeKey).find(r=>r.kind==='history');await forgetPolicyReference(history,current.scopeKey);expect(readPolicyState(current.scopeKey).history).toEqual([]);
 await expect(forgetPolicyReference(history,current.scopeKey)).rejects.toThrow('changed');
});
test('explicit exact removal frees bounded capacity with no automatic eviction',async()=>{
 let rejected;
 for(let i=0;i<100;i++){const operation={...metadata(),scopeKey:hash(String(i))};try{await savePolicyPending(operation);}catch{rejected=operation;break;}}
 const before=localStorage.getItem(SHOP_PROMPT_POLICY_KEY);await expect(savePolicyPending(rejected)).rejects.toThrow('limit');expect(localStorage.getItem(SHOP_PROMPT_POLICY_KEY)).toBe(before);
 const [reference]=readForgettablePolicyReferences('f'.repeat(64));await forgetPolicyReference(reference,'f'.repeat(64));await savePolicyPending(rejected);expect(readPolicyState(rejected.scopeKey).pending).toEqual(rejected);
});
test('listing target is available only when advertised and renders under merchant role',async()=>{
 const value={...request(),injected_into:['listing']};
 await expect(policyMutationDigests(value,[])).rejects.toThrow();
 const result=await policyMutationDigests(value,['listing']);
 expect(result.requestSha256).toBe(hash(JSON.stringify({version:1,operationId:value.operationId,name:value.name,markdown:value.markdown,targets:['merchant']})));
 expect(result.policyRequestSha256).toBeDefined();
});
