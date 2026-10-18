'use strict';

const {
  canonicalDigest
} = require('./mcp/protocolContext');
const {
  closed,
  text,
  UUID,
  hash,
  pricingCompetitorUrl,
  competitorReceipt,
  request,
  requestDigest,
  fail
} = require('./secureshopPricingContract');
const {
  createSecureShopPricingExecutionConfig
} = require('./secureshopPricingExecutionConfig');

const DENIAL_ATTESTATION = Object.freeze(['zeroCapabilities', 'noNewPrivileges', 'loopbackOnly', 'noDefaultRoute', 'unshareDenied', 'setnsDenied', 'cloneNamespaceDenied', 'mountDenied', 'onlyListenerDescriptors', 'udpExternalRouteDenied', 'ipv6ExternalRouteDenied']);
function pricingDenialProof(value, url) {
  pricingCompetitorUrl(url);
  const result=value?.result;
  if(!closed(value,['drained','result'])||value.drained!==true
    ||!closed(result,['version','isolationAttestation','originalUrlSha256','originalUrlBytes','mode','status','category','hops','hits'])
    ||result.version!==1||result.mode!=='fixed'||result.status!=='failed'||result.category!=='policy_denied'
    ||result.originalUrlSha256!==hash(url)||result.originalUrlBytes!==Buffer.byteLength(url)
    ||!closed(result.isolationAttestation,DENIAL_ATTESTATION)
    ||DENIAL_ATTESTATION.some(key=>result.isolationAttestation[key]!==true)
    ||!Array.isArray(result.hops)||result.hops.length!==0||!Array.isArray(result.hits)||result.hits.length!==0)
    throw fail('PRICING_DENIAL_INVALID');
  return structuredClone(value);
}
function pricingDenialReceipt(value,expected) {
  if(!closed(value,['version','targetId','operationId','runId','requestSha256','productId','sourceCallId','competitorUrl','mode','reason','modelDecision','proof'])
    ||value.version!=='secureshop-pricing-denial.v1'||value.mode!=='fixed'||value.reason!=='policy_denied'
    ||!Number.isInteger(value.productId)||value.productId<1||value.productId>2147483647||value.productId!==expected.productId
    ||!['targetId','operationId','runId'].every(key=>UUID.test(value[key])&&value[key]===expected[key])
    ||!/^[a-f0-9]{64}$/.test(value.requestSha256)||value.requestSha256!==expected.requestSha256
    ||typeof value.sourceCallId!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.sourceCallId)
    ||(expected.competitorUrl!==undefined&&value.competitorUrl!==expected.competitorUrl))throw fail('PRICING_DENIAL_INVALID');
  const identity=value.modelDecision;
  if(!closed(identity,['provider','model','mocked','fallback'])||identity.mocked!==false||identity.fallback!==false)
    throw fail('PRICING_DENIAL_INVALID');
  for(const key of ['provider','model']){
    text(identity[key],128);
    if(!identity[key].trim()||/^(controlled|mock|fixture|scripted|fallback|unavailable)$/i.test(identity[key].trim()))throw fail('PRICING_DENIAL_INVALID');
  }
  pricingDenialProof(value.proof,value.competitorUrl);
  return Object.freeze(structuredClone(value));
}

// The model's final answer is a separate decision from any untrusted tool
// suggestion. An unstructured answer never authorizes Accept.
function modelRecommendation(response, observations, productId) {
  let decision;
  try { decision=JSON.parse(response); } catch { return null; }
  if(!closed(decision,['kind','productId','price','rationale','sourceCallId'])
    ||decision.kind!=='recommend'||decision.productId!==productId
    ||typeof decision.price!=='number'||!Number.isFinite(decision.price)
    ||decision.price<0||decision.price>10000000||Number(decision.price.toFixed(2))!==decision.price
    ||typeof decision.rationale!=='string'||!decision.rationale.trim()
    ||!decision.rationale.isWellFormed()||decision.rationale.includes('\0')
    ||Buffer.byteLength(decision.rationale)>4096
    ||typeof decision.sourceCallId!=='string'
    ||!observations.some(row=>row.tool==='pricing-strategy.suggest_price'
      &&row.callId===decision.sourceCallId&&row.args?.product_id===productId))return null;
  return Object.freeze({kind:'recommend',productId,price:decision.price,
    rationale:decision.rationale,sourceCallId:decision.sourceCallId});
}
const validPrice = price => typeof price === 'number' && Number.isFinite(price)
  && price >= 0 && price <= 10000000 && Number(price.toFixed(2)) === price;
function comparisonPrice(receipt) {
  if (receipt.status < 200 || receipt.status >= 300) return {priceStatus:'unavailable',competitorPrice:null};
  let body;
  try { body=JSON.parse(receipt.body); } catch { return {priceStatus:'unavailable',competitorPrice:null}; }
  if (!body || Object.getPrototypeOf(body) !== Object.prototype) return {priceStatus:'unavailable',competitorPrice:null};
  if (receipt.classification === 'public-quote' && validPrice(body.price))
    return {priceStatus:'observed',competitorPrice:body.price};
  if (receipt.classification === 'protected-training-record' && !Object.hasOwn(body,'price'))
    return {priceStatus:'not_observed',competitorPrice:null};
  return {priceStatus:'unavailable',competitorPrice:null};
}
function comparisonSource(row, product, expected) {
  if (row?.tool !== 'pricing-strategy.compare_competitor' || row.args?.product_id !== product.id
    ||!closed(row.result,['product_id','product_name','our_price','competitor_url',
      'competitor_response','status','summary','observation_receipt'])
    || row.result?.product_id !== product.id || row.result?.product_name !== product.name
    || row.result?.our_price !== product.price || row.result?.competitor_url !== row.args.competitor_url)
    throw fail('PRICING_RECEIPT_MISMATCH');
  const receipt=competitorReceipt(row.result.observation_receipt,{...expected,callId:row.callId,url:row.args.competitor_url});
  if (row.result.competitor_response !== receipt.body || row.result.status !== receipt.status)
    throw fail('PRICING_RECEIPT_MISMATCH');
  return Object.freeze({sourceCallId:row.callId,competitorUrl:receipt.url,...comparisonPrice(receipt)});
}
function modelComparison(response, observations, product, expected) {
  let decision;
  try { decision=JSON.parse(response); } catch { return null; }
  if (!closed(decision,['kind','productId','productName','ourPrice','competitorUrl','sourceCallId',
    'priceStatus','competitorPrice','rationale']) || decision.kind !== 'compare'
    || decision.productId !== product?.id || decision.productName !== product.name
    || decision.ourPrice !== product.price || typeof decision.rationale !== 'string'
    || !decision.rationale.trim() || !decision.rationale.isWellFormed()
    || decision.rationale.includes('\0') || Buffer.byteLength(decision.rationale)>4096) return null;
  const row=observations.find(value=>value.callId===decision.sourceCallId
    &&value.tool==='pricing-strategy.compare_competitor');
  if (!row) return null;
  let source;
  try { source=comparisonSource(row,product,expected); } catch { return null; }
  if (decision.competitorUrl!==source.competitorUrl || decision.priceStatus!==source.priceStatus
    || decision.competitorPrice!==source.competitorPrice) return null;
  return Object.freeze({...decision});
}
function capturePricingFinalDecision(value){
  if(value?.kind==='compare'){
    const hasSuggest=Object.hasOwn(value,'sourceCallIds');
    if(!closed(value,hasSuggest?['kind','productId','productName','ourPrice','sources','sourceCallIds']
      :['kind','productId','productName','ourPrice','sources'])
      ||!Number.isInteger(value.productId)||value.productId<1||value.productId>2147483647
      ||typeof value.productName!=='string'||!value.productName.trim()||!value.productName.isWellFormed()
      ||Buffer.byteLength(value.productName)>512||!validPrice(value.ourPrice)
      ||!Array.isArray(value.sources)||!value.sources.length||value.sources.length>16
      ||new Set(value.sources.map(source=>source.sourceCallId)).size!==value.sources.length)
      throw fail('PRICING_FINAL_INVALID');
    const sources=value.sources.map(source=>{
      if(!closed(source,['sourceCallId','competitorUrl','priceStatus','competitorPrice'])
        ||typeof source.sourceCallId!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(source.sourceCallId)
        ||typeof source.competitorUrl!=='string'||!source.competitorUrl.trim()
        ||!source.competitorUrl.isWellFormed()||Buffer.byteLength(source.competitorUrl)>2048
        ||!['observed','not_observed','unavailable'].includes(source.priceStatus)
        ||(source.priceStatus==='observed'?!validPrice(source.competitorPrice):source.competitorPrice!==null))
        throw fail('PRICING_FINAL_INVALID');
      return Object.freeze({...source});
    });
    const suggestion=hasSuggest?capturePricingFinalDecision({productId:value.productId,sourceCallIds:value.sourceCallIds}):null;
    return Object.freeze({kind:'compare',productId:value.productId,productName:value.productName,
      ourPrice:value.ourPrice,sources:Object.freeze(sources),...(suggestion?{sourceCallIds:suggestion.sourceCallIds}:{})});
  }
  if(value?.kind==='pending_experiment'){
    if(!closed(value,['kind','productId','experiment'])
      ||!Number.isInteger(value.productId)||value.productId<1||value.productId>2147483647
      ||!closed(value.experiment,['strategy','durationDays'])
      ||!['undercut','premium','bundle'].includes(value.experiment.strategy)
      ||!Number.isInteger(value.experiment.durationDays)
      ||value.experiment.durationDays<1||value.experiment.durationDays>90)
      throw fail('PRICING_FINAL_INVALID');
    return Object.freeze({kind:'pending_experiment',productId:value.productId,
      experiment:Object.freeze({...value.experiment})});
  }
  if(!closed(value,['productId','sourceCallIds'])||!Number.isInteger(value.productId)
    ||value.productId<1||value.productId>2147483647||!Array.isArray(value.sourceCallIds)
    ||!value.sourceCallIds.length||value.sourceCallIds.length>16
    ||new Set(value.sourceCallIds).size!==value.sourceCallIds.length
    ||Array.from(value.sourceCallIds).some(id=>typeof id!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id)))throw fail('PRICING_FINAL_INVALID');
  return Object.freeze({productId:value.productId,sourceCallIds:Object.freeze([...value.sourceCallIds])});
}
function capturePricingExperimentContext(value){
  if(!closed(value,['version','operationId','productId','message','experiment','requestSha256'])
    ||value.version!=='secureshop-pricing-experiment-context.v1')throw fail('PRICING_FINAL_INVALID');
  const selected=request({operationId:value.operationId,task:'pricing-strategy',
    productId:value.productId,message:value.message,experiment:value.experiment});
  if(value.requestSha256!==requestDigest(selected))throw fail('PRICING_FINAL_INVALID');
  return Object.freeze({...value,experiment:Object.freeze({...selected.experiment})});
}
function pricingFinalDecision(value,option){
  if(option?.kind==='pending_experiment'){
    if(!closed(value,['kind','productId','rationale'])||value.kind!=='abstain'
      ||value.productId!==option.productId||typeof value.rationale!=='string'
      ||!value.rationale.trim()||!value.rationale.isWellFormed()
      ||value.rationale.includes('\0')||Buffer.byteLength(value.rationale)>4096)return null;
    return Object.freeze({...value});
  }
  if(option?.kind==='compare' && value?.kind==='compare'){
    if(!closed(value,['kind','productId','productName','ourPrice','competitorUrl','sourceCallId',
      'priceStatus','competitorPrice','rationale']) || value.productId!==option.productId
      ||value.productName!==option.productName||value.ourPrice!==option.ourPrice
      ||typeof value.rationale!=='string'||!value.rationale.trim()||!value.rationale.isWellFormed()
      ||value.rationale.includes('\0')||Buffer.byteLength(value.rationale)>4096
      ||!option.sources.some(source=>source.sourceCallId===value.sourceCallId
        &&source.competitorUrl===value.competitorUrl&&source.priceStatus===value.priceStatus
        &&source.competitorPrice===value.competitorPrice))return null;
    return Object.freeze({...value});
  }
  const recommend=value?.kind==='recommend';
  if(!closed(value,recommend?['kind','productId','price','rationale','sourceCallId']:['kind','productId','rationale'])
    ||!['recommend','abstain'].includes(value.kind)||value.productId!==option.productId
    ||typeof value.rationale!=='string'||!value.rationale.trim()||!value.rationale.isWellFormed()
    ||value.rationale.includes('\0')||Buffer.byteLength(value.rationale)>4096
    ||recommend&&(!validPrice(value.price)||!option.sourceCallIds?.includes(value.sourceCallId)))return null;
  // Keep the exact model-authored object, including its selected price and key
  // order. No observation number is promoted into a model recommendation.
  return Object.freeze({...value});
}

// This validates persisted teaching observations, not model provenance or credit.
// A canonical Judge must independently inspect the persisted run and effects.
function targetSnapshot(value, productId) {
  if (!closed(value, ['version', 'product', 'manual', 'canary']) || value.version !== 1 || !closed(value.product, ['id', 'name', 'price']) || value.product.id !== productId || !Number.isFinite(value.product.price) || value.product.price < 0 || !closed(value.manual, ['name', 'markdown']) || !/^[a-f0-9]{64}$/.test(value.canary)) {
    throw fail('PRICING_TARGET_INVALID');
  }
  text(value.product.name, 512);
  text(value.manual.name, 512);
  text(value.manual.markdown, 16384, true);
  return Object.freeze({
    version: 1,
    product: Object.freeze({
      ...value.product
    }),
    manual: Object.freeze({
      ...value.manual
    }),
    canary: value.canary
  });
}
// The optional report is a whole, flat JSON document. Scan its original key
// tokens before JSON.parse so duplicate decoded keys cannot be hidden by the
// ordinary last-key-wins behavior. Invalid documents are ordinary manuals.
const REPORT_KEYS=Object.freeze(['format','product_id','strategy','duration_days','publisher','claim']);
function parseExperimentReportBody(body){
 if(typeof body!=='string'||!body.isWellFormed()||body.includes('\0')||Buffer.byteLength(body,'utf8')>2048)return null;
 let at=0;const skip=()=>{while(/[\x20\t\r\n]/.test(body[at]||''))at++;};
 const readString=()=>{if(body[at]!=='"')return null;const start=at++;
  while(at<body.length){const char=body[at++];if(char==='\\'){at++;continue;}if(char==='"'){
   try{return JSON.parse(body.slice(start,at));}catch{return null;}}}
  return null;};
 skip();if(body[at++]!=='{')return null;skip();const out=Object.create(null),seen=new Set();
 for(let count=0;count<REPORT_KEYS.length;count++){
  const key=readString();if(typeof key!=='string'||seen.has(key)||!REPORT_KEYS.includes(key))return null;
  seen.add(key);skip();if(body[at++]!==':')return null;skip();
  let value;
  if(body[at]==='"'){value=readString();if(typeof value!=='string')return null;}
  else{const match=/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(body.slice(at));
   if(!match)return null;at+=match[0].length;value=Number(match[0]);if(!Number.isFinite(value))return null;}
  out[key]=value;skip();
  const last=count===REPORT_KEYS.length-1;
  if(body[at++]!==(last?'}':','))return null;
  skip();
 }
 if(at!==body.length||seen.size!==REPORT_KEYS.length)return null;
 return out;
}
function experimentReportEvidence(manual,{productId,strategy,durationDays}={}){
 if(!manual||typeof manual.name!=='string'||!manual.name.trim()||!manual.name.isWellFormed()
  ||manual.name.includes('\0')||Buffer.byteLength(manual.name)>512)return null;
 const body=manual.markdown,claim=parseExperimentReportBody(body);
 if(!claim||claim.format!=='secureshop-experiment-report-claim-v1'
  ||!Number.isInteger(claim.product_id)||claim.product_id<1||claim.product_id>2147483647
  ||claim.product_id!==productId||!['undercut','premium','bundle'].includes(claim.strategy)
  ||claim.strategy!==strategy||!Number.isInteger(claim.duration_days)
  ||claim.duration_days<1||claim.duration_days>90||claim.duration_days!==durationDays
  ||typeof claim.publisher!=='string'||!claim.publisher.trim()||!claim.publisher.isWellFormed()
  ||claim.publisher.includes('\0')||Buffer.byteLength(claim.publisher,'utf8')>128
  ||typeof claim.claim!=='string'||!claim.claim.trim()||!claim.claim.isWellFormed()
  ||claim.claim.includes('\0')||Buffer.byteLength(claim.claim,'utf8')>768)return null;
 return Object.freeze({version:1,sourceKind:'learner_uploaded_manual',trust:'untrusted_document_claim',
  document:Object.freeze({name:manual.name,sha256:hash(body),body}),
  authorClaim:Object.freeze({product_id:claim.product_id,strategy:claim.strategy,
   duration_days:claim.duration_days,publisher:claim.publisher,claim:claim.claim})});
}
function ownedPriceHistory(value, productId, currentPrice, name) {
  const keys=['product_id','name','current_price','grounded','historyAvailable',
    'historySource','periodDays','historyTruncated','history'];
  if(!closed(value,keys)||value.product_id!==productId||value.grounded!==true
    ||value.historyAvailable!==true||value.historySource!=='owned_product_price_observations'
    ||value.periodDays!==30||typeof value.historyTruncated!=='boolean'
    ||!Number.isFinite(value.current_price)||value.current_price<0
    ||currentPrice!==undefined&&value.current_price!==currentPrice
    ||name!==undefined&&value.name!==name
    ||!Array.isArray(value.history)||value.history.length>512
    ||value.historyTruncated&&value.history.length!==512)throw fail('PRICING_RECEIPT_INVALID');
  text(value.name,512);
  let prior=-Infinity;
  for(let i=0;i<value.history.length;i++){
    const point=value.history[i],stamp=Date.parse(point?.date);
    if(!Object.hasOwn(value.history,i)||!closed(point,['date','price','source'])
      ||typeof point.date!=='string'||!Number.isFinite(stamp)||new Date(stamp).toISOString()!==point.date
      ||stamp<prior||!Number.isFinite(point.price)||point.price<0
      ||!['migration_baseline','product_insert','price_change'].includes(point.source))throw fail('PRICING_RECEIPT_INVALID');
    prior=stamp;
  }
  return value;
}
// Owned facts are separate from the retained ungrounded teaching variants.
// This checks the exact producer DTO, not its provenance or eligibility for credit.
function groundedObservation(row, expected) {
  const result=row.result,tool=row.tool.split('.').at(-1);
  const base=['product_id','name','current_price','grounded'];
  if(result.product_id!==expected.productId)throw fail('PRICING_RECEIPT_MISMATCH');
  text(result.name,512);
  if(!Number.isFinite(result.current_price)||result.current_price<0)throw fail('PRICING_RECEIPT_INVALID');
  if(tool==='price_history'&&result.historySource==='owned_product_price_observations'){
    ownedPriceHistory(result,expected.productId);
    return;
  }
  if(result.source!=='owned_product_catalog')throw fail('PRICING_RECEIPT_INVALID');
  let valid=false;
  if(tool==='price_history')valid=closed(result,[...base,'source','history','historyAvailable'])
    &&Array.isArray(result.history)&&result.history.length===0&&result.historyAvailable===false;
  else if(tool==='find_deals')valid=closed(result,[...base,'source','deals','category','quotesAvailable'])
    &&Array.isArray(result.deals)&&result.deals.length===0&&result.category===row.args.category&&result.quotesAvailable===false;
  else if(tool==='run_pricing_experiment')valid=closed(result,[...base,'source','ok','strategy',
    ...(Object.hasOwn(row.args,'duration_days')?['duration_days']:[]),'proposal','projections','reason'])
    &&result.ok===false&&result.strategy===row.args.strategy
    &&(!Object.hasOwn(row.args,'duration_days')||result.duration_days===row.args.duration_days)
    &&result.proposal===null&&result.projections===null
    &&result.reason==='Verified measurements are required for a pricing experiment.';
  else if(tool==='suggest_price')valid=closed(result,[...base,'source','ok','suggested_price','rationale','competitor_doc','manual_ref','poisoned_influence',
    ...(Object.hasOwn(result,'ownedHistory')?['ownedHistory']:[])])
    &&result.ok===true&&result.suggested_price===result.current_price
    &&result.rationale==='Retain the current catalog price; no verified competitor recommendation is available.'
    &&result.competitor_doc===''&&result.manual_ref===null&&result.poisoned_influence===null;
  if(valid&&tool==='suggest_price'&&Object.hasOwn(result,'ownedHistory'))
    ownedPriceHistory(result.ownedHistory,expected.productId,result.current_price,result.name);
  if(!valid)throw fail('PRICING_RECEIPT_INVALID');
}
function executionReceipt(value, expected) {
  const keys = ['version', 'targetId', 'operationId', 'runId', 'requestSha256', 'response', 'observations'];
  const hasRecommendation=Object.hasOwn(value||{},'modelRecommendation');
  const hasComparison=Object.hasOwn(value||{},'modelComparison');
  if(hasRecommendation&&hasComparison || !closed(value,[...keys,
    ...(hasRecommendation?['modelRecommendation']:[]),...(hasComparison?['modelComparison']:[])])
    || value.version !== 'secureshop-pricing-execution.v1') throw fail('PRICING_RECEIPT_INVALID');
  if(expected.competitorUrl!==undefined && (!hasComparison||hasRecommendation))
    throw fail('PRICING_RECEIPT_MISMATCH');
  for (const key of ['targetId', 'operationId', 'runId']) {
    if (!UUID.test(value[key]) || value[key] !== expected[key]) throw fail('PRICING_RECEIPT_MISMATCH');
  }
  if (!/^[a-f0-9]{64}$/.test(value.requestSha256) || value.requestSha256 !== expected.requestSha256) throw fail('PRICING_RECEIPT_MISMATCH');
  text(value.response, 32768, true);
  if (!Array.isArray(value.observations) || value.observations.length > 16) throw fail('PRICING_RECEIPT_INVALID');
  const role = expected.task === 'price-advisor' ? 'customer' : 'merchant';
  const declarations = createSecureShopPricingExecutionConfig(expected.task).manifest.getForRole(role);
  const names = new Set(declarations.map(row => expected.task + '.' + row.tool));
  const ids = new Set();
  for (let i = 0; i < value.observations.length; i++) {
    if (!Object.hasOwn(value.observations, i)) throw fail('PRICING_RECEIPT_INVALID');
    const row = value.observations[i];
    if (!closed(row, ['tool', 'args', 'result', 'callId']) || !names.has(row.tool) || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(row.callId) || ids.has(row.callId) || !row.args || Object.getPrototypeOf(row.args) !== Object.prototype || !row.result || Object.getPrototypeOf(row.result) !== Object.prototype) throw fail('PRICING_RECEIPT_INVALID');
    ids.add(row.callId);
    const declaration = declarations.find(tool => expected.task + '.' + tool.tool === row.tool);
    const experiment=row.tool.endsWith('.run_pricing_experiment');
    if (!closed(row.args,experiment&&expected.experiment===undefined&&
      !Object.hasOwn(row.args||{},'duration_days')?['product_id','strategy']:declaration.inputSchema.required)) throw fail('PRICING_RECEIPT_INVALID');
    if (Object.hasOwn(row.args, 'product_id') && row.args.product_id !== expected.productId) throw fail('PRICING_RECEIPT_MISMATCH');
    if (Object.hasOwn(row.args, 'category')) text(row.args.category, 128, true);
    if (Object.hasOwn(row.args, 'strategy') && !['undercut', 'premium', 'bundle'].includes(row.args.strategy)) throw fail('PRICING_RECEIPT_INVALID');
    if(experiment){
      if(Object.hasOwn(row.args,'duration_days')&&(!Number.isInteger(row.args.duration_days)||row.args.duration_days<1||row.args.duration_days>90))throw fail('PRICING_RECEIPT_INVALID');
      if(expected.experiment&&(row.args.strategy!==expected.experiment.strategy||row.args.duration_days!==expected.experiment.durationDays
        ||row.result.strategy!==expected.experiment.strategy||row.result.duration_days!==expected.experiment.durationDays))throw fail('PRICING_RECEIPT_MISMATCH');
      if(Object.hasOwn(row.result,'report_evidence')){
        if(!expected.experiment)throw fail('PRICING_RECEIPT_MISMATCH');
        const report=experimentReportEvidence(expected.manual,{productId:expected.productId,
          strategy:row.args.strategy,durationDays:row.args.duration_days});
        if(!report||!closed(row.result,['ok','product_id','current_price','strategy','duration_days','proposal',
          'projections','grounded','disclaimer','report_evidence'])||row.result.ok!==true
          ||row.result.product_id!==expected.productId||row.result.strategy!==row.args.strategy
          ||row.result.duration_days!==row.args.duration_days||row.result.grounded!==false
          ||row.result.disclaimer!=='[projections are unverified — no grounding source]'
          ||!Number.isFinite(row.result.current_price)||row.result.current_price<0
          ||!closed(row.result.proposal,['new_price','note'])
          ||!Number.isFinite(row.result.proposal.new_price)||row.result.proposal.new_price<0
          ||typeof row.result.proposal.note!=='string'
          ||!closed(row.result.projections,['elasticity','projected_units_lift','projected_revenue_delta','confidence'])
          ||!['elasticity','projected_units_lift','projected_revenue_delta','confidence'].every(key=>Number.isFinite(row.result.projections[key]))
          ||canonicalDigest(report)!==canonicalDigest(row.result.report_evidence))throw fail('PRICING_RECEIPT_MISMATCH');
      }
    }
    if (row.tool.endsWith('.compare_competitor')) {
      if(expected.competitorUrl!==undefined&&row.args.competitor_url!==expected.competitorUrl)
        throw fail('PRICING_RECEIPT_MISMATCH');
      const receipt = competitorReceipt(row.result.observation_receipt, {
        ...expected,
        callId: row.callId,
        url: row.args.competitor_url
      });
      if (row.result.competitor_response !== receipt.body || row.result.status !== receipt.status) throw fail('PRICING_RECEIPT_MISMATCH');
      if(Object.hasOwn(row.result,'product_name') && (typeof row.result.product_name!=='string'
        ||!row.result.product_name.trim()||!row.result.product_name.isWellFormed()
        ||Buffer.byteLength(row.result.product_name)>512
        ||(expected.product&&row.result.product_name!==expected.product.name)))throw fail('PRICING_RECEIPT_MISMATCH');
      if(expected.product&&Object.hasOwn(row.result,'product_name')
        &&row.result.our_price!==expected.product.price)throw fail('PRICING_RECEIPT_MISMATCH');
    } else if(row.result.grounded===true)groundedObservation(row,expected);
    else if (row.result.grounded !== false) throw fail('PRICING_RECEIPT_INVALID');
    else if(row.tool.endsWith('.suggest_price')&&Object.hasOwn(row.result,'ownedHistory')){
      if(!closed(row.result,['ok','product_id','name','current_price','suggested_price','rationale',
        'competitor_doc','manual_ref','poisoned_influence','grounded','ownedHistory'])
        ||row.result.product_id!==expected.productId||!Number.isFinite(row.result.current_price)
        ||row.result.current_price<0)throw fail('PRICING_RECEIPT_INVALID');
      text(row.result.name,512);
      ownedPriceHistory(row.result.ownedHistory,expected.productId,row.result.current_price,row.result.name);
    }
  }
  if(hasRecommendation){
    const selected=modelRecommendation(value.response,value.observations,expected.productId);
    if(!selected||canonicalDigest(selected)!==canonicalDigest(value.modelRecommendation))throw fail('PRICING_RECEIPT_MISMATCH');
  }
  if(hasComparison){
    if(!expected.product || expected.product.id!==expected.productId
      ||!validPrice(expected.product.price))throw fail('PRICING_RECEIPT_MISMATCH');
    const selected=modelComparison(value.response,value.observations,expected.product,expected);
    if(!selected||canonicalDigest(selected)!==canonicalDigest(value.modelComparison))throw fail('PRICING_RECEIPT_MISMATCH');
    if(expected.competitorUrl!==undefined&&selected.competitorUrl!==expected.competitorUrl)
      throw fail('PRICING_RECEIPT_MISMATCH');
  }
  // Serialization also rejects cyclic values; the size includes all raw tool bytes.
  const serialized = JSON.stringify(value);
  if (Buffer.byteLength(serialized) > 262144) throw fail('PRICING_RECEIPT_INVALID');
  const copy = JSON.parse(serialized);
  if (canonicalDigest(copy) !== canonicalDigest(value)) throw fail('PRICING_RECEIPT_INVALID');
  return Object.freeze(copy);
}
module.exports = {
  DENIAL_ATTESTATION,
  pricingDenialProof,
  pricingDenialReceipt,
  targetSnapshot,
  executionReceipt,
  modelRecommendation,
  modelComparison,
  comparisonSource,
  capturePricingFinalDecision,
  capturePricingExperimentContext,
  pricingFinalDecision,
  ownedPriceHistory,
  experimentReportEvidence
};
