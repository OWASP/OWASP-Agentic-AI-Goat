import {shopStorage,flushShopStorage,SHOP_REVIEW_DECISION_KEY} from './shopStorage.mjs';
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function readManualPending(scopeKey){const raw=shopStorage.getItem(SHOP_REVIEW_DECISION_KEY);if(raw===null)return null;const p=JSON.parse(raw);if(p.scopeKey!==scopeKey)return null;if(!uuid.test(p.operationId)||!Number.isSafeInteger(p.reviewId)||p.reviewId<1||!['approve','reject'].includes(p.action)||(p.reason!==null&&typeof p.reason!=='string')||(typeof p.reason==='string'&&p.reason.length>16384)||(p.action==='approve'&&p.reason!==null))throw Error('Saved review operation unavailable');return p;}
export async function saveManualPending(p){shopStorage.setItem(SHOP_REVIEW_DECISION_KEY,JSON.stringify(p));await flushShopStorage();}
export async function clearManualPending(p){const saved=readManualPending(p.scopeKey);if(!saved||JSON.stringify(saved)!==JSON.stringify(p))throw Error('Saved review operation changed');shopStorage.removeItem(SHOP_REVIEW_DECISION_KEY);await flushShopStorage();}
export function verifyManualReceipt(receipt,p,executionScopeKey){
 const s=receipt?.scope,a=receipt?.actor;
 let current;try{current=JSON.parse(p.scopeKey)}catch{}
 if(!s||!a||executionScopeKey!==p.scopeKey||!Array.isArray(current)||current.length!==6
  ||receipt.operationId!==p.operationId||receipt.kind!=='manual'||receipt.moderatorKind!=='manual'
  ||receipt.reviewId!==p.reviewId||receipt.decision!==(p.action==='approve'?'approved':'rejected')||receipt.notes!==p.reason
  ||typeof receipt.applied!=='boolean'||!['pending','approved','rejected'].includes(receipt.resultStatus)||(receipt.applied&&receipt.resultStatus!==receipt.decision)
  ||!uuid.test(s.targetId)||!uuid.test(s.launchId)||!uuid.test(s.scenarioId)||!Number.isSafeInteger(s.generation)||s.generation<1
  ||!Number.isSafeInteger(s.platformSessionId)||s.platformSessionId<1||s.platformOwnerId!==current[2]
  ||a.id!==current[4]||a.role!=='merchant'||a.personaSessionId!==current[5])throw Error('Review acknowledgement could not be verified');return receipt;
}
export async function recoverManualPending(p,fetcher){const r=await fetcher('/api/secureshop/merchant/reviews/operations/'+p.operationId);if(r.status===404)throw Object.assign(Error('No committed receipt observed. Retry only the same saved decision.'),{code:'NOT_OBSERVED'});if(!r.ok)throw Error('Review outcome is unknown. Sign in again if authority changed.');const value=await r.json();if(value?.ok!==true)throw Error('Review outcome is unknown');return verifyManualReceipt(value.receipt,p,value.executionScopeKey);}
