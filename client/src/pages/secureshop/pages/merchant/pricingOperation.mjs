const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const keys=['scopeKey','operationId','productId','action','requestSha256'];
const exact=(value,fields)=>value&&Object.getPrototypeOf(value)===Object.prototype
 && Object.keys(value).sort().join(',')===[...fields].sort().join(',');
const text=(value,max)=>typeof value==='string'&&value.trim()&&value.isWellFormed()
 && !value.includes('\0')&&new TextEncoder().encode(value).length<=max;
export function validateCompetitorUrl(value){
 if(!text(value,2048))throw Error('Invalid competitor URL');
 let parsed;
 try{parsed=new URL(value);}catch{throw Error('Invalid competitor URL');}
 if(parsed.protocol!=='http:'||parsed.username||parsed.password||parsed.hash)
  throw Error('Invalid competitor URL');
 return value;
}
export function decodePricingProposal(value){
 if(value===null)return null;
 const hasExperiment=Object.hasOwn(value||{},'experiment');
 const hasCompetitorUrl=Object.hasOwn(value||{},'competitorUrl');
 if(!exact(value,['version','proposalId','product','action','productId','message','scopeKey','modeCapability','requestSha256',
    ...(hasExperiment?['experiment']:[]),...(hasCompetitorUrl?['competitorUrl']:[])])
  ||![1,2].includes(value.version)||!UUID.test(value.proposalId)||!exact(value.product,['choiceId','name'])
  ||!UUID.test(value.product.choiceId)||!text(value.product.name,256)
  ||!Number.isInteger(value.productId)||value.productId<1||value.productId>2147483647
  ||!text(value.message,8192)||!SHA.test(value.scopeKey)||!SHA.test(value.requestSha256)
  ||!['suggest','experiment','compare'].includes(value.action)
  ||(value.version===2&&value.action!=='experiment')
  ||(value.action==='experiment')!==hasExperiment
  ||(value.action==='compare')!==hasCompetitorUrl
  ||(hasExperiment&&(!exact(value.experiment,['strategy','durationDays'])
   ||!['undercut','premium','bundle'].includes(value.experiment.strategy)
   ||!Number.isInteger(value.experiment.durationDays)||value.experiment.durationDays<1
   ||value.experiment.durationDays>90))
  ||(hasCompetitorUrl&&(() => { try { validateCompetitorUrl(value.competitorUrl); return false; }
    catch { return true; } })())
  ||value.modeCapability?.version!==1||value.modeCapability.featureId!=='pricing'
  ||!['vuln','fixed'].includes(value.modeCapability.effectiveMode)
  ||typeof value.modeCapability.policyVersion!=='string'||!value.modeCapability.policyVersion
  ||value.modeCapability.scope?.kind!=='launch_feature'||value.modeCapability.scope.id!=='pricing')
  throw Error('Invalid saved Pricing proposal');
 return {...value,product:{...value.product},...(hasExperiment?{experiment:{...value.experiment}}:{})};
}
export function samePricingProposal(a,b){
 try{const x=decodePricingProposal(a),y=decodePricingProposal(b);
  return !!x&&!!y&&x.version===y.version&&x.proposalId===y.proposalId&&x.product.choiceId===y.product.choiceId
   &&x.product.name===y.product.name&&x.action===y.action&&x.productId===y.productId
   &&x.message===y.message&&x.scopeKey===y.scopeKey&&x.requestSha256===y.requestSha256
   &&x.experiment?.strategy===y.experiment?.strategy
   &&x.experiment?.durationDays===y.experiment?.durationDays
   &&x.competitorUrl===y.competitorUrl
   &&x.modeCapability.policyVersion===y.modeCapability.policyVersion
   &&x.modeCapability.effectiveMode===y.modeCapability.effectiveMode;
 }catch{return false;}
}
export function validatePricingReference(x){
 if(!x||Object.getPrototypeOf(x)!==Object.prototype||Object.keys(x).sort().join(',')!==[...keys].sort().join(',')||!SHA.test(x.scopeKey)||!UUID.test(x.operationId)||!SHA.test(x.requestSha256)||!Number.isInteger(x.productId)||x.productId<1||x.productId>2147483647||!['suggest','compare','experiment'].includes(x.action))throw Error('Invalid saved Pricing operation');
 return {...x};
}
export function decodePricingReferences(raw){
 if(raw===null)return[];
 if(typeof raw!=='string'||new TextEncoder().encode(raw).length>8192)throw Error('Pricing references exceed limit');
 const x=JSON.parse(raw);if(!x||Object.keys(x).sort().join(',')!=='references,version'||x.version!==1||!Array.isArray(x.references)||x.references.length>24)throw Error('Invalid Pricing references');
 const ids=new Set();return x.references.map(row=>{const v=validatePricingReference(row),id=v.scopeKey+':'+v.operationId;if(ids.has(id))throw Error('Duplicate Pricing reference');ids.add(id);return v;});
}
export function encodePricingReferences(rows){const raw=JSON.stringify({version:1,references:rows});decodePricingReferences(raw);return raw;}
export async function pricingRequestDigest(body){
 if(!body||!UUID.test(body.operationId)||!Number.isInteger(body.productId)||body.productId<1||typeof body.message!=='string'||!body.message.isWellFormed()||body.message.includes('\0')||new TextEncoder().encode(body.message).length>8192)throw Error('Invalid Pricing request');
 const hasExperiment=Object.hasOwn(body,'experiment');
 const hasCompetitorUrl=Object.hasOwn(body,'competitorUrl');
 if(hasExperiment&&hasCompetitorUrl)throw Error('Invalid Pricing request');
 if(hasExperiment&&(!body.experiment||Object.getPrototypeOf(body.experiment)!==Object.prototype
  ||Object.keys(body.experiment).sort().join(',')!=='durationDays,strategy'
  ||!['undercut','premium','bundle'].includes(body.experiment.strategy)
  ||!Number.isInteger(body.experiment.durationDays)||body.experiment.durationDays<1||body.experiment.durationDays>90))throw Error('Invalid Pricing experiment');
 if(hasCompetitorUrl)validateCompetitorUrl(body.competitorUrl);
 const raw=JSON.stringify({version:hasCompetitorUrl?'secureshop-pricing-request.v3'
  :hasExperiment?'secureshop-pricing-request.v2':'secureshop-pricing-request.v1',
  operationId:body.operationId,task:'pricing-strategy',productId:body.productId,message:body.message,
  ...(hasExperiment?{experiment:body.experiment}:{}),
  ...(hasCompetitorUrl?{competitorUrl:body.competitorUrl}:{})});
 return [...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(raw)))].map(x=>x.toString(16).padStart(2,'0')).join('');
}
const DENIAL_ATTESTATION=['zeroCapabilities','noNewPrivileges','loopbackOnly','noDefaultRoute',
 'unshareDenied','setnsDenied','cloneNamespaceDenied','mountDenied','onlyListenerDescriptors',
 'udpExternalRouteDenied','ipv6ExternalRouteDenied'];
export async function pricingBlockedResult(value,reference,expectedCompetitorUrl){
 validatePricingReference(reference);
 const receipt=value?.receipt,proof=receipt?.proof,result=proof?.result;
 const capability=value?.modeCapability;
 if(!exact(value,['ok','operationId','state','requestSha256','receipt',
    ...(Object.hasOwn(value||{},'modeCapability')?['modeCapability']:[])])
  ||value.ok!==false||value.state!=='blocked'||value.operationId!==reference.operationId
  ||value.requestSha256!==reference.requestSha256
  ||!exact(receipt,['version','targetId','operationId','runId','requestSha256','productId',
    'sourceCallId','competitorUrl','mode','reason','modelDecision','proof'])
  ||receipt.version!=='secureshop-pricing-denial.v1'||!UUID.test(receipt.targetId)
  ||receipt.operationId!==reference.operationId||!UUID.test(receipt.runId)
  ||receipt.requestSha256!==reference.requestSha256||receipt.productId!==reference.productId
  ||expectedCompetitorUrl!==undefined&&receipt.competitorUrl!==expectedCompetitorUrl
  ||typeof receipt.sourceCallId!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(receipt.sourceCallId)
  ||receipt.mode!=='fixed'||receipt.reason!=='policy_denied'
  ||!exact(receipt.modelDecision,['provider','model','mocked','fallback'])
  ||!text(receipt.modelDecision.provider,128)||!text(receipt.modelDecision.model,128)
  ||/^(controlled|mock|fixture|scripted|fallback|unavailable)$/i.test(receipt.modelDecision.provider.trim())
  ||/^(controlled|mock|fixture|scripted|fallback|unavailable)$/i.test(receipt.modelDecision.model.trim())
  ||receipt.modelDecision.mocked!==false||receipt.modelDecision.fallback!==false
  ||!exact(proof,['drained','result'])||proof.drained!==true
  ||!exact(result,['version','isolationAttestation','originalUrlSha256','originalUrlBytes',
    'mode','status','category','hops','hits'])
  ||result.version!==1||result.mode!=='fixed'||result.status!=='failed'
  ||result.category!=='policy_denied'||!Array.isArray(result.hops)||result.hops.length!==0
  ||!Array.isArray(result.hits)||result.hits.length!==0
  ||!exact(result.isolationAttestation,DENIAL_ATTESTATION)
  ||DENIAL_ATTESTATION.some(key=>result.isolationAttestation[key]!==true)
  ||!SHA.test(result.originalUrlSha256)||!Number.isSafeInteger(result.originalUrlBytes)
  ||capability!==undefined&&(capability?.version!==1||capability.featureId!=='pricing'
    ||capability.effectiveMode!=='fixed'||typeof capability.policyVersion!=='string'
    ||!capability.policyVersion||capability.scope?.kind!=='launch_feature'
    ||capability.scope.id!=='pricing'))throw Error('Invalid blocked Pricing receipt');
 validateCompetitorUrl(receipt.competitorUrl);
 const bytes=new TextEncoder().encode(receipt.competitorUrl);
 const sha=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))]
  .map(x=>x.toString(16).padStart(2,'0')).join('');
 if(result.originalUrlBytes!==bytes.length||result.originalUrlSha256!==sha)
  throw Error('Blocked Pricing source mismatch');
 return {state:'blocked',noEffect:true};
}
export function pricingResult(value,reference){
 validatePricingReference(reference);
 if(value?.operationId!==reference.operationId)throw Error('Pricing receipt binding mismatch');
 if(['pending','unknown','not_executed','not_found'].includes(value.state)&&value.ok===false)return {state:value.state};
 const r=value.receipt;
 if(value.state!=='completed'||value.ok!==true||value.requestSha256!==reference.requestSha256||r?.operationId!==reference.operationId||r.requestSha256!==reference.requestSha256||r.version!=='secureshop-pricing-execution.v1'||!UUID.test(r.runId)||!UUID.test(r.targetId)||typeof r.response!=='string'||new TextEncoder().encode(r.response).length>32768||!Array.isArray(r.observations)||r.observations.length>16)throw Error('Invalid Pricing receipt');
 const tool={suggest:'suggest_price',compare:'compare_competitor',experiment:'run_pricing_experiment'}[reference.action];
 const selected=r.observations.filter(x=>x.tool==='pricing-strategy.'+tool&&x.args?.product_id===reference.productId).at(-1);
 let displayObservation=selected?.result||null;
 let modelRecommendation=null;
 let modelComparison=null;
 if(Object.hasOwn(r,'modelComparison')){
  if(Object.hasOwn(r,'modelRecommendation'))
   throw Error('Invalid Pricing comparison');
  const claimed=r.modelComparison;
  let authored;
  try{authored=JSON.parse(r.response);}catch{throw Error('Invalid Pricing comparison');}
  const fields=['kind','productId','productName','ourPrice','competitorUrl','sourceCallId','priceStatus','competitorPrice','rationale'];
  if(!exact(claimed,fields)||!exact(authored,fields)
   ||fields.some(key=>claimed[key]!==authored[key])
   ||claimed.kind!=='compare'||claimed.productId!==reference.productId
   ||!text(claimed.productName,512)||typeof claimed.ourPrice!=='number'
   ||!Number.isFinite(claimed.ourPrice)||claimed.ourPrice<0
  ||claimed.ourPrice>10000000||Number(claimed.ourPrice.toFixed(2))!==claimed.ourPrice
  ||!text(claimed.competitorUrl,2048)||!text(claimed.rationale,4096)
   ||typeof claimed.sourceCallId!=='string'
   ||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(claimed.sourceCallId))
   throw Error('Invalid Pricing comparison');
  const source=r.observations.find(x=>x.tool==='pricing-strategy.compare_competitor'
   &&x.callId===claimed.sourceCallId&&x.args?.product_id===reference.productId);
  const observed=source?.result,attested=observed?.observation_receipt;
  if(!source||!attested||attested.version!=='secureshop-owned-competitor.v1'
   ||attested.targetId!==r.targetId||attested.operationId!==reference.operationId
   ||attested.runId!==r.runId||attested.callId!==claimed.sourceCallId
   ||attested.requestSha256!==reference.requestSha256
   ||source.args.competitor_url!==claimed.competitorUrl
   ||observed.product_id!==claimed.productId||observed.product_name!==claimed.productName
   ||observed.our_price!==claimed.ourPrice||observed.competitor_url!==claimed.competitorUrl
   ||observed.competitor_response!==attested?.body||observed.status!==attested.status
   ||attested.url!==claimed.competitorUrl)
   throw Error('Pricing comparison source mismatch');
  let body=null;
  try{body=JSON.parse(attested.body);}catch{/* Non-JSON observations are unavailable. */}
  const bodyObject=body&&Object.getPrototypeOf(body)===Object.prototype;
  const success=Number.isInteger(attested.status)&&attested.status>=200&&attested.status<300;
  const observedPrice=attested.classification==='public-quote'&&success&&bodyObject
   &&typeof body.price==='number'&&Number.isFinite(body.price)&&body.price>=0
   &&body.price<=10000000&&Number(body.price.toFixed(2))===body.price
   ?body.price:null;
  const status=observedPrice!==null?'observed'
   :attested.classification==='protected-training-record'&&success&&bodyObject
    &&!Object.hasOwn(body,'price')?'not_observed':'unavailable';
  if(claimed.priceStatus!==status||claimed.competitorPrice!==observedPrice)
   throw Error('Pricing comparison observation mismatch');
  displayObservation=observed;
  modelComparison={...claimed};
 }
 if(Object.hasOwn(r,'modelRecommendation')){
  const claimed=r.modelRecommendation;
  let authored;
  try{authored=JSON.parse(r.response);}catch{throw Error('Invalid Pricing recommendation');}
  const exact=x=>x&&Object.getPrototypeOf(x)===Object.prototype
   &&Object.keys(x).sort().join(',')==='kind,price,productId,rationale,sourceCallId';
  if(!exact(claimed)||!exact(authored)
   ||['kind','productId','price','rationale','sourceCallId'].some(key=>claimed[key]!==authored[key])
   ||claimed.kind!=='recommend'||claimed.productId!==reference.productId
   ||typeof claimed.price!=='number'||!Number.isFinite(claimed.price)
   ||claimed.price<0||claimed.price>10000000||Number(claimed.price.toFixed(2))!==claimed.price
   ||typeof claimed.rationale!=='string'||!claimed.rationale.trim()
   ||!claimed.rationale.isWellFormed()||claimed.rationale.includes('\0')
   ||new TextEncoder().encode(claimed.rationale).length>4096
   ||typeof claimed.sourceCallId!=='string'
   ||!r.observations.some(x=>x.tool==='pricing-strategy.suggest_price'
    &&x.callId===claimed.sourceCallId&&x.args?.product_id===reference.productId))
   throw Error('Invalid Pricing recommendation');
  modelRecommendation={...claimed};
 }
 return{state:'completed',response:r.response,observation:displayObservation,modelRecommendation,modelComparison};
}
