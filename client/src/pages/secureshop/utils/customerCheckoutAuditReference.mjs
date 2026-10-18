const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const KEYS = ['version','shopUserId','sessionId','requestId','checkoutOperationId','startedAt'];
const MAX_BYTES = 640;
export const CUSTOMER_CHECKOUT_AUDIT_REFERENCE_KEY = 'secureshop.customer-checkout-audit.lesson.v1';
export const CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY = 'secureshop.customer-checkout-audit.assessment.v1';
const invalid = () => { throw new Error('Invalid saved checkout-audit lesson request'); };
const same = (left,right) => !!left&&!!right&&KEYS.every(key=>left[key]===right[key]);

export function decodeCustomerCheckoutAuditReference(raw){
 if(raw===null)return null;
 if(typeof raw!=='string'||new TextEncoder().encode(raw).byteLength>MAX_BYTES)invalid();
 let value;try{value=JSON.parse(raw);}catch{invalid();}
 if(!value||Object.getPrototypeOf(value)!==Object.prototype
  ||Object.keys(value).sort().join(',')!==[...KEYS].sort().join(',')
  ||value.version!==1||!Number.isSafeInteger(value.shopUserId)||value.shopUserId<1
  ||![value.sessionId,value.requestId,value.checkoutOperationId]
   .every(item=>typeof item==='string'&&UUID.test(item))
  ||!Number.isSafeInteger(value.startedAt)||value.startedAt<1)invalid();
 return Object.freeze(value);
}

export function createCustomerCheckoutAuditReferenceStore({storage,flush,
 key=CUSTOMER_CHECKOUT_AUDIT_REFERENCE_KEY,
 assessmentKey=CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY}={}){
 if(typeof storage?.getItem!=='function'||typeof storage?.setItem!=='function'
  ||typeof storage?.removeItem!=='function'||typeof flush!=='function'
  ||key!==CUSTOMER_CHECKOUT_AUDIT_REFERENCE_KEY
  ||assessmentKey!==CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY)
  throw new TypeError('Acknowledged checkout-audit storage required');
 const readRaw=()=>decodeCustomerCheckoutAuditReference(storage.getItem(key));
 const readAssessmentRaw=()=>decodeCustomerCheckoutAuditReference(storage.getItem(assessmentKey));
 return Object.freeze({
  read(shopUserId){
   if(!Number.isSafeInteger(shopUserId)||shopUserId<1)invalid();
   const value=readRaw();return value?.shopUserId===shopUserId?value:null;
  },
  readAssessment(reference){
   const value=decodeCustomerCheckoutAuditReference(JSON.stringify({version:1,...reference}));
   const saved=readAssessmentRaw();
   if(saved!==null&&!same(saved,value))throw Error('Saved checkout-audit assessment changed');
   return saved;
  },
  async save(reference,current=()=>true){
   const value=decodeCustomerCheckoutAuditReference(JSON.stringify({version:1,...reference}));
   if(current()!==true)throw Error('Checkout-audit authority changed');
   if(readRaw()!==null)throw Error('Check the saved checkout-audit request first');
   storage.setItem(key,JSON.stringify(value));await flush();
   if(current()!==true||!same(readRaw(),value))throw Error('Saved checkout-audit request changed');
   return value;
  },
  async submitAssessment(reference,current=()=>true,written=()=>{}){
   const value=decodeCustomerCheckoutAuditReference(JSON.stringify({version:1,...reference}));
   if(typeof written!=='function')throw new TypeError('Assessment write observer required');
   if(current()!==true||!same(readRaw(),value))throw Error('Checkout-audit authority changed');
   if(readAssessmentRaw()!==null)throw Error('Check the saved checkout-audit assessment');
   storage.setItem(assessmentKey,JSON.stringify(value));written(value);await flush();
   if(current()!==true||!same(readAssessmentRaw(),value))throw Error('Saved checkout-audit assessment changed');
   return value;
  },
  async clearAssessment(reference,current=()=>true){
   const value=decodeCustomerCheckoutAuditReference(JSON.stringify({version:1,...reference}));
   if(current()!==true||!same(readRaw(),value)||!same(readAssessmentRaw(),value))
    throw Error('Saved checkout-audit assessment changed');
   try{
    storage.removeItem(assessmentKey);await flush();
    if(current()!==true||readAssessmentRaw()!==null)
     throw Error('Saved checkout-audit assessment changed');
   }catch(error){
    if(current()===true)try{
     if(readAssessmentRaw()===null){storage.setItem(assessmentKey,JSON.stringify(value));await flush();}
    }catch{}
    throw error;
   }
  },
  async clear(reference,current=()=>true){
   const value=decodeCustomerCheckoutAuditReference(JSON.stringify({version:1,...reference}));
   if(current()!==true||!same(readRaw(),value))throw Error('Saved checkout-audit request changed');
   const assessment=readAssessmentRaw();
   if(assessment!==null&&!same(assessment,value))throw Error('Saved checkout-audit assessment changed');
   try{
    storage.removeItem(key);storage.removeItem(assessmentKey);await flush();
    if(current()!==true||readRaw()!==null||readAssessmentRaw()!==null)
     throw Error('Saved checkout-audit request changed');
   }catch(error){
    if(current()===true)try{
     if(readRaw()===null){storage.setItem(key,JSON.stringify(value));await flush();}
     if(assessment!==null&&readAssessmentRaw()===null){storage.setItem(assessmentKey,JSON.stringify(assessment));await flush();}
    }catch{}
    throw error;
   }
  },
 });
}
