const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const KEYS=['version','shopUserId','sessionId','requestId','startedAt'];
export const CUSTOMER_FILE_SUMMARY_KEY='secureshop.customer-file-summary.lesson.v1';
export const CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY='secureshop.customer-file-summary.assessment.v1';
const invalid=()=>{throw new Error('Invalid saved file-summary request');};
const same=(a,b)=>!!a&&!!b&&KEYS.every(key=>a[key]===b[key]);
export function decodeCustomerFileSummaryReference(raw){
 if(raw===null)return null;if(typeof raw!=='string'||new TextEncoder().encode(raw).byteLength>512)invalid();
 let value;try{value=JSON.parse(raw);}catch{invalid();}
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!==[...KEYS].sort().join(',')
  ||value.version!==1||!Number.isSafeInteger(value.shopUserId)||value.shopUserId<1
  ||![value.sessionId,value.requestId].every(id=>typeof id==='string'&&UUID.test(id))
  ||!Number.isSafeInteger(value.startedAt)||value.startedAt<1)invalid();
 return Object.freeze(value);
}
function createStore({storage,flush,key}={},expectedKey){
 if(typeof storage?.getItem!=='function'||typeof storage?.setItem!=='function'||typeof storage?.removeItem!=='function'
  ||typeof flush!=='function'||key!==expectedKey)throw new TypeError('Acknowledged file-summary storage required');
 const raw=()=>decodeCustomerFileSummaryReference(storage.getItem(key));
 return Object.freeze({
  read(shopUserId){if(!Number.isSafeInteger(shopUserId)||shopUserId<1)invalid();const value=raw();return value?.shopUserId===shopUserId?value:null;},
  async submit(reference,current=()=>true,written=()=>{}){const value=decodeCustomerFileSummaryReference(JSON.stringify({version:1,...reference}));
   if(current()!==true||raw()!==null)throw Error('Check the saved file-summary request');storage.setItem(key,JSON.stringify(value));written(value);await flush();
   if(current()!==true||!same(raw(),value))throw Error('Saved file-summary request changed');return value;},
  async clear(reference,current=()=>true){const value=decodeCustomerFileSummaryReference(JSON.stringify({version:1,...reference}));
   if(current()!==true||!same(raw(),value))throw Error('Saved file-summary request changed');storage.removeItem(key);
   try{await flush();if(current()!==true||raw()!==null)throw Error('Saved file-summary request changed');}
   catch(error){if(current()===true&&raw()===null){storage.setItem(key,JSON.stringify(value));try{await flush();}catch{}}throw error;}return true;}
 });
}
export function createCustomerFileSummaryStore(options={}){return createStore({...options,
 key:Object.hasOwn(options,'key')?options.key:CUSTOMER_FILE_SUMMARY_KEY},CUSTOMER_FILE_SUMMARY_KEY);}
export function createCustomerFileSummaryAssessmentStore(options={}){return createStore({...options,
 key:Object.hasOwn(options,'key')?options.key:CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY},CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY);}
