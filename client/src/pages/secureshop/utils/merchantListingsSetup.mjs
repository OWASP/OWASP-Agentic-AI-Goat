import { trustedTurnMode } from './turnModeCapability.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(',');
const text=(v,max)=>typeof v==='string'&&!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(v)&&!v.includes('\0')&&new TextEncoder().encode(v).length<=max;
function url(value){if(value===null)return true;if(!text(value,4096)||!value)return false;try{return ['http:','https:'].includes(new URL(value).protocol);}catch{return false;}}
export function listingsChatSource(value){
 if(!exact(value,['sessionId','requestId','proposalId'])||Object.values(value).some(v=>typeof v!=='string'||!UUID.test(v)))throw Error('Invalid listing setup source');
 return {sessionId:value.sessionId,requestId:value.requestId,proposalId:value.proposalId};
}
export function decodeMerchantListingsSetup(value,sessionId,requestId){
 if(value==null)return null;
 const rewrite=value.kind==='listing_rewrite_setup',optimize=value.kind==='listing_optimize_setup';
 if(!exact(value,['version','kind','proposalId','operationId','source','listingsModeCapability',...(rewrite?['product','title','description']:optimize?['product']:['sources'])])
 ||value.version!==1||(!rewrite&&!optimize&&value.kind!=='listing_import_setup')||!UUID.test(value.proposalId)||value.operationId!==value.proposalId
 ||!exact(value.source,['sessionId','requestId'])||!UUID.test(value.source.sessionId)||!UUID.test(value.source.requestId)
 ||(sessionId!==undefined&&value.source.sessionId!==sessionId)||(requestId!==undefined&&value.source.requestId!==requestId))throw Error('Invalid saved listing setup');
 if(!exact(value.listingsModeCapability,['version','featureId','policyVersion','effectiveMode','scope'])||!exact(value.listingsModeCapability.scope,['kind','id'])||!trustedTurnMode(value.listingsModeCapability)||value.listingsModeCapability.featureId!=='listings'||value.listingsModeCapability.policyVersion!=='owned-listing-import-v1')throw Error('Invalid listing mode');
 if(rewrite){if(!exact(value.product,['choiceId','name','description','price','category','images','templateSource'])||!UUID.test(value.product.choiceId)||!text(value.product.name,1024)||!value.product.name.trim()
 ||!text(value.product.description,32768)||!Number.isFinite(value.product.price)||value.product.price<0||value.product.price>99999999.99||value.product.price!==Number(value.product.price.toFixed(2))
 ||(value.product.category!==null&&!text(value.product.category,1024))||!Array.isArray(value.product.images)||value.product.images.length>16||value.product.images.some(x=>!text(x,8192)||!x.trim())
 ||(value.product.templateSource!==null&&!text(value.product.templateSource,65536))
 ||value.title!==value.product.name||value.description!==value.product.description||!text(value.title,1024)||!text(value.description,32768))throw Error('Invalid saved listing setup');}
 else if(optimize){if(!exact(value.product,['choiceId','name','imageUrl','imageUrlSha256'])||!UUID.test(value.product.choiceId)||!text(value.product.name,1024)||!value.product.name.trim()
 ||!url(value.product.imageUrl)||typeof value.product.imageUrlSha256!=='string'||!/^[a-f0-9]{64}$/.test(value.product.imageUrlSha256))throw Error('Invalid saved listing setup');}
 else if(!exact(value.sources,['json_url','xml_url'])||!url(value.sources.json_url)||!url(value.sources.xml_url)||(!value.sources.json_url&&!value.sources.xml_url))throw Error('Invalid saved listing setup');
 return JSON.parse(JSON.stringify(value));
}
export function sourceForListingsSetup(setup){return listingsChatSource({...setup.source,proposalId:setup.proposalId});}
export function listingsSetupPath(source){const v=listingsChatSource(source);return `/api/secureshop/agents/merchant/assistant/operations/${v.sessionId}/${v.requestId}`;}
