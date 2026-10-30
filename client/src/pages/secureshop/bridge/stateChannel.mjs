import { SHOP_MCP_REGISTRY_KEY, SHOP_USER_ADMIN_KEY, SHOP_REVIEW_DECISION_KEY, SHOP_ACL_KEY, SHOP_PASSWORD_RESET_KEY, SHOP_PROMPT_POLICY_KEY, SHOP_SYSTEM_CONFIG_KEY, SHOP_SYSTEM_DIAGNOSTIC_KEY, SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY, SHOP_SYSTEM_RESTART_KEY, SHOP_SYSTEM_REBUILD_KEY, SHOP_ANALYTICS_KEY, SHOP_PRICING_KEY, SHOP_LISTINGS_KEY, SHOP_MAIL_KEY, SHOP_INVENTORY_KEY, SHOP_LISTING_EDIT_KEY, SHOP_LISTING_CREATE_KEY, SHOP_PRACTICE_PAYMENT_KEY, SHOP_ADDRESS_SETUP_KEY, SHOP_PROFILE_KEY, SHOP_COUPON_KEY, SHOP_CHECKOUT_KEY, SHOP_REFUND_KEY, SHOP_CUSTOMER_CHAT_KEY, SHOP_CUSTOMER_CHAT_COMPLETED_KEY, SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY, SHOP_CUSTOMER_COUPON_PROBE_KEY, SHOP_CUSTOMER_PRODUCT_SEARCH_KEY, SHOP_CUSTOMER_ORDER_STATUS_KEY, SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY, SHOP_ADMIN_TICKET_ASSESSMENT_KEY, SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY, SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY, SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY, SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_UPLOAD_KEY, SHOP_ACCOUNT_AVATAR_PENDING_KEY, SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY, SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY, SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY, SHOP_CUSTOMER_FILE_SUMMARY_KEY, SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY, SHOP_POLICY_FINAL_HTML_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY, SHOP_CUSTOMER_IDOR_KEY, SHOP_PRODUCT_SIMILAR_KEY, SHOP_PRODUCT_MANUAL_KEY, SHOP_PRODUCT_SUMMARY_KEY, SHOP_CHAT_CART_KEY, SHOP_AUDIT_JOB_KEY, SHOP_ROLE_ASSISTANT_KEY, SHOP_ROLE_ASSISTANT_COMPLETED_KEY, SHOP_REGISTERED_ADMIN_CHAT_KEY, SHOP_REGISTERED_ADMIN_COMPLETED_KEY } from '../utils/shopStorage.mjs';
import { validateShopSnapshot } from './stateStore.mjs';
import { SHOP_REVIEW_MODERATION_KEY } from '../utils/shopStorage.mjs';

const channel = 'owasp-ai-goat-shop-state-v1';
const failed = () => new Error('Shop state was not saved');
const cancelled = () => new DOMException('Shop state disconnected', 'AbortError');
const validId = id => Number.isSafeInteger(id) && id > 0;
const exact = (data, keys) => data && typeof data === 'object' && !Array.isArray(data)
  && Object.keys(data).length === keys.length && keys.every(key => Object.hasOwn(data,key));
const send = (port, value) => { try { port.postMessage(value);return true; } catch { return false; } };

// A dedicated port keeps storage sequence numbers separate from HTTP requests.
export function createHostShopStateChannel({port, store}) {
  let closed=false;let lastId=0;
  const listener=event=>{
    const data=event.data;
    if(closed || data?.channel!==channel || !validId(data.id) || data.id<=lastId) return;
    lastId=data.id;
    try {
      if(data.action==='read' && exact(data,['channel','id','action'])) {
        const snapshot=validateShopSnapshot(store.read());
        send(port,{channel,id:data.id,ok:true,snapshot});
      } else if(data.action==='replace' && exact(data,['channel','id','action','snapshot'])) {
        store.replace(validateShopSnapshot(data.snapshot));
        send(port,{channel,id:data.id,ok:true});
      } else throw failed();
    } catch {send(port,{channel,id:data.id,ok:false});}
  };
  port.addEventListener('message',listener);port.start();
  return Object.freeze({close(){
    if(closed)return;send(port,{channel,shutdown:true});closed=true;
    port.removeEventListener('message',listener);port.close();store.close();
  }});
}

export async function connectFrameShopState({port,timeoutMs=10000,signal}) {
  if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1)throw new TypeError('Positive state timeout required');
  if(signal?.aborted){port.close();throw cancelled();}
  let closed=false;let nextId=0;let failure;let memory;
  const pending=new Map();const writes=new Set();
  const settle=(id,error,snapshot)=>{
    const item=pending.get(id);if(!item)return;
    pending.delete(id);clearTimeout(item.timer);
    if(error)item.reject(error);else item.resolve(snapshot);
  };
  const close=()=>{
    if(closed)return;closed=true;
    for(const id of [...pending.keys()])settle(id,cancelled());
    signal?.removeEventListener('abort',close);
    port.removeEventListener('message',listener);port.close();
  };
  const listener=event=>{
    const data=event.data;
    if(data?.channel!==channel)return;
    if(exact(data,['channel','shutdown'])&&data.shutdown===true){close();return;}
    const item=pending.get(data.id);if(!item)return;
    try {
      if(data.ok===false&&exact(data,['channel','id','ok']))throw failed();
      if(data.ok!==true)throw failed();
      if(item.action==='read'&&exact(data,['channel','id','ok','snapshot']))settle(data.id,null,validateShopSnapshot(data.snapshot));
      else if(item.action==='replace'&&exact(data,['channel','id','ok']))settle(data.id);
      else throw failed();
    }catch(error){settle(data.id,error);}
  };
  const request=(action,snapshot)=>{
    if(closed || pending.size>=32) return Promise.reject(failed());
    const id=++nextId;
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>settle(id,failed()),timeoutMs);
      pending.set(id,{resolve,reject,timer,action});
      if(!send(port,{channel,id,action,...(snapshot===undefined?{}:{snapshot})}))settle(id,failed());
    });
  };
  signal?.addEventListener('abort',close,{once:true});
  port.addEventListener('message',listener);port.start();
  try {memory=await request('read');}catch(error){close();throw error;}
  const replace=(key,value)=>{
    if(closed)throw cancelled();
    if(failure)throw failure;
    if(pending.size>=32)throw failed();
    const next={...memory,[key]:value};
    if((key===SHOP_CUSTOMER_CHAT_KEY||key===SHOP_CUSTOMER_CHAT_COMPLETED_KEY||key===SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY||key===SHOP_CUSTOMER_COUPON_PROBE_KEY||key===SHOP_CUSTOMER_PRODUCT_SEARCH_KEY||key===SHOP_CUSTOMER_ORDER_STATUS_KEY||key===SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY||key===SHOP_ADMIN_TICKET_ASSESSMENT_KEY||key===SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY||key===SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY||key===SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY||key===SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY||key===SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY||key===SHOP_CUSTOMER_AVATAR_UPLOAD_KEY||key===SHOP_ACCOUNT_AVATAR_PENDING_KEY||key===SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY||key===SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY||key===SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY||key===SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY||key===SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY||key===SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY||key===SHOP_CUSTOMER_FILE_SUMMARY_KEY||key===SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY||key===SHOP_POLICY_FINAL_HTML_KEY||key===SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY||key===SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY||key===SHOP_CUSTOMER_IDOR_KEY||key===SHOP_PRODUCT_SIMILAR_KEY||key===SHOP_PRODUCT_MANUAL_KEY||key===SHOP_REVIEW_MODERATION_KEY||key===SHOP_PRODUCT_SUMMARY_KEY||key===SHOP_CHAT_CART_KEY||key===SHOP_AUDIT_JOB_KEY||key===SHOP_ROLE_ASSISTANT_KEY||key===SHOP_ROLE_ASSISTANT_COMPLETED_KEY || key===SHOP_REGISTERED_ADMIN_CHAT_KEY || key === SHOP_REGISTERED_ADMIN_COMPLETED_KEY||key===SHOP_LISTING_EDIT_KEY||key===SHOP_LISTING_CREATE_KEY||key===SHOP_PRACTICE_PAYMENT_KEY||key===SHOP_ADDRESS_SETUP_KEY||key===SHOP_PROFILE_KEY)&&value===null)delete next[key];
    const snapshot=validateShopSnapshot(next);
    memory=snapshot;
    const write=request('replace',snapshot);writes.add(write);
    write.then(()=>writes.delete(write),error=>{writes.delete(write);failure=error;});
  };
  return Object.freeze({
    getItem(key){if(closed)throw cancelled();if((key===SHOP_MCP_REGISTRY_KEY||key===SHOP_USER_ADMIN_KEY||key===SHOP_REVIEW_DECISION_KEY||key===SHOP_ACL_KEY||key===SHOP_PASSWORD_RESET_KEY||key===SHOP_PROMPT_POLICY_KEY||key===SHOP_SYSTEM_CONFIG_KEY||key===SHOP_SYSTEM_DIAGNOSTIC_KEY||key===SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY||key===SHOP_SYSTEM_RESTART_KEY||key===SHOP_SYSTEM_REBUILD_KEY||key===SHOP_ANALYTICS_KEY||key===SHOP_PRICING_KEY||key===SHOP_LISTINGS_KEY||key===SHOP_MAIL_KEY||key===SHOP_INVENTORY_KEY||key===SHOP_LISTING_EDIT_KEY||key===SHOP_LISTING_CREATE_KEY||key===SHOP_PRACTICE_PAYMENT_KEY||key===SHOP_ADDRESS_SETUP_KEY||key===SHOP_PROFILE_KEY||key===SHOP_COUPON_KEY||key===SHOP_CHECKOUT_KEY||key===SHOP_REFUND_KEY||key===SHOP_CUSTOMER_CHAT_KEY||key===SHOP_CUSTOMER_CHAT_COMPLETED_KEY||key===SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY||key===SHOP_CUSTOMER_COUPON_PROBE_KEY||key===SHOP_CUSTOMER_PRODUCT_SEARCH_KEY||key===SHOP_CUSTOMER_ORDER_STATUS_KEY||key===SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY||key===SHOP_ADMIN_TICKET_ASSESSMENT_KEY||key===SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY||key===SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY||key===SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY||key===SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY||key===SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY||key===SHOP_CUSTOMER_AVATAR_UPLOAD_KEY||key===SHOP_ACCOUNT_AVATAR_PENDING_KEY||key===SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY||key===SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY||key===SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY||key===SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY||key===SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY||key===SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY||key===SHOP_CUSTOMER_FILE_SUMMARY_KEY||key===SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY||key===SHOP_POLICY_FINAL_HTML_KEY||key===SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY||key===SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY||key===SHOP_CUSTOMER_IDOR_KEY||key===SHOP_PRODUCT_SIMILAR_KEY||key===SHOP_PRODUCT_MANUAL_KEY||key===SHOP_REVIEW_MODERATION_KEY||key===SHOP_PRODUCT_SUMMARY_KEY||key===SHOP_CHAT_CART_KEY||key===SHOP_AUDIT_JOB_KEY||key===SHOP_ROLE_ASSISTANT_KEY||key===SHOP_ROLE_ASSISTANT_COMPLETED_KEY || key===SHOP_REGISTERED_ADMIN_CHAT_KEY || key === SHOP_REGISTERED_ADMIN_COMPLETED_KEY)&&!Object.hasOwn(memory,key))return null;if(!Object.hasOwn(memory,key))throw new TypeError('Unsupported shop key');return memory[key];},
    setItem(key,value){if(typeof value!=='string')throw new TypeError('Shop values must be strings');replace(key,value);},
    removeItem(key){replace(key,null);},
    async flush(){if(closed)throw cancelled();if(failure)throw failure;await Promise.all([...writes]);if(failure)throw failure;},
    close,
  });
}
