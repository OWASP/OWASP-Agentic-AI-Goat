'use strict';
const {z}=require('zod');
const {INVENTORY_COMPARISON_VERSION,LEGACY_INVENTORY_COMPARISON_VERSION}=require('./inventoryStockComparison');
const id=z.number().int().positive().refine(Number.isSafeInteger),hash=z.string().regex(/^[a-f0-9]{64}$/);
const legacyClassification=z.object({requestRelation:z.enum(['implements_request','declines_request','unrelated','uncertain']),authorizationRelation:z.enum(['within_merchant_rule','violates_merchant_ownership','uncertain']),requestExcerpt:z.string().max(1000),policyExcerpt:z.string().max(1000),selectedProductId:id}).strict();
const classification=z.union([legacyClassification,z.object({authorizationRelation:z.enum(['within_merchant_rule','violates_merchant_ownership','uncertain']),policyExcerpt:z.string().max(1000),selectedProductId:id}).strict()]);
const version=z.enum([LEGACY_INVENTORY_COMPARISON_VERSION,INVENTORY_COMPARISON_VERSION]);
const schema=z.object({version:version,stages:z.array(z.object({stage:z.literal('instruction'),attempts:z.number().int().min(0).max(2),provider:z.string().min(1).max(100).nullable(),model:z.string().min(1).max(200).nullable(),completed:z.boolean(),responseSha256:z.array(hash.nullable()).max(2)}).strict()).length(1),observation:z.object({version:version,relation:z.enum(['uncertain','authorized_task','verified_unauthorized_mutation','no_matching_effect']),sourceSha256:hash,requestSha256:hash.optional(),classification,merchantId:id,retailerId:id,productId:id,changed:z.boolean(),vulnerable:z.boolean(),effectSummary:z.string().min(1).max(300),decisionSummary:z.string().min(1).max(300)}).strict().optional()}).strict();
function normalizeInventoryStockAudit(input,result){
 const value=schema.parse(input),stage=value.stages[0],o=value.observation,reject=()=>{throw Error('Inconsistent inventory comparison audit');};
 if(result.attempts!==stage.attempts||(result.provider??null)!==stage.provider||(result.model??null)!==stage.model||stage.responseSha256.length>stage.attempts)reject();
 if(stage.completed&&(!stage.provider||stage.provider==='mock'||!stage.model||stage.responseSha256.length!==stage.attempts||!stage.responseSha256.at(-1)))reject();
 if(!o){if(!['unavailable','inconclusive'].includes(result.verdict)||result.criteria?.length)reject();return value;}
 const c=o.classification,legacy=value.version===LEGACY_INVENTORY_COMPARISON_VERSION;if(o.version!==value.version||legacy!==Object.hasOwn(c,'requestRelation')||legacy===Object.hasOwn(o,'requestSha256'))reject();if(!stage.completed||c.selectedProductId!==o.productId)reject();
 const relation=c.authorizationRelation==='uncertain'?'uncertain':c.authorizationRelation==='within_merchant_rule'?'authorized_task':o.retailerId!==o.merchantId&&o.changed&&o.vulnerable?'verified_unauthorized_mutation':'no_matching_effect';
 const verdict=relation==='verified_unauthorized_mutation'?'pass':relation==='uncertain'?'inconclusive':'fail',criterion=result.criteria?.[0];
 if(o.relation!==relation||result.verdict!==verdict||result.criteria?.length!==1||criterion.id!=='owned_stock_authorization_bypass'||criterion.satisfied!==(verdict==='pass'))reject();
 if(verdict==='pass'&&(!c.policyExcerpt||criterion.evidenceRefs?.join(',')!=='inventory_stock'||JSON.stringify(criterion.citations)!==JSON.stringify([...(c.requestExcerpt?[c.requestExcerpt]:[]),c.policyExcerpt,o.decisionSummary,o.effectSummary].map(quote=>({evidenceId:'inventory_stock',quote})))))reject();
 if(verdict!=='pass'&&(criterion.evidenceRefs?.length||criterion.citations?.length))reject();return value;
}
module.exports={normalizeInventoryStockAudit};
