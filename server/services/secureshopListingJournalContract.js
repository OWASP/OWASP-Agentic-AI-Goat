'use strict';
// Draft operation contract: no executor dispatch or objective credit occurs here.
const { createHash } = require('node:crypto');
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const { normalizeListingRequest, listingRequestDigest } = require('./secureshopListingRequestContract');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HEX = /^[a-f0-9]{64}$/;
const fail = code => Object.assign(new Error('Owned listing operation unavailable'), { code });
const hash = value => createHash('sha256').update(value).digest('hex');
function closed(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) throw fail('INVALID_ARGUMENT');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== keys.length || keys.some(key => !Object.hasOwn(descriptors[key] || {}, 'value'))) throw fail('INVALID_ARGUMENT');
}
function denseArray(value, max) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value)!==Array.prototype || value.length>max) throw fail('LISTING_RECEIPT_MISMATCH');
  const descriptors=Object.getOwnPropertyDescriptors(value);
  if(Reflect.ownKeys(descriptors).length!==value.length+1)throw fail('LISTING_RECEIPT_MISMATCH');
  for(let i=0;i<value.length;i++)if(!Object.hasOwn(descriptors[i]||{},'value'))throw fail('LISTING_RECEIPT_MISMATCH');
}
function text(value, max, empty = false) {
  if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0') || (!empty && !value.trim()) || Buffer.byteLength(value) > max) throw fail('INVALID_ARGUMENT');
  return value;
}
function prepareListingRecovery(raw) {
  closed(raw, ['scope', 'persona', 'personaSession', 'operationId']);
  const scope = createLaunchScope(raw.scope);
  closed(raw.persona, ['id', 'role']); closed(raw.personaSession, ['sessionId', 'authorityVersion']);
  createConversationBinding(scope, raw.persona);
  if (raw.persona.role !== 'merchant' || !UUID.test(raw.operationId) || !UUID.test(raw.personaSession.sessionId)
      || typeof raw.personaSession.authorityVersion !== 'string' || !/^[1-9]\d{0,15}$/.test(raw.personaSession.authorityVersion)
      || BigInt(raw.personaSession.authorityVersion) > 9007199254740991n) throw fail('INVALID_ARGUMENT');
  return Object.freeze({ binding: Object.freeze({ scope, persona: Object.freeze({ ...raw.persona }),
    personaSession: Object.freeze({ ...raw.personaSession }) }), request: Object.freeze({ operationId: raw.operationId }) });
}
function prepareListingAdmission(raw) {
  closed(raw, ['scope', 'persona', 'personaSession', 'targetId', 'mode', 'catalogRevision', 'request']);
  const scope = createLaunchScope(raw.scope);
  closed(raw.persona, ['id', 'role']);
  closed(raw.personaSession, ['sessionId', 'authorityVersion']);
  createConversationBinding(scope, raw.persona);
  if (raw.persona.role !== 'merchant' || !UUID.test(raw.targetId) || !UUID.test(raw.personaSession.sessionId)
      || !['vuln', 'fixed'].includes(raw.mode) || typeof raw.catalogRevision !== 'string'
      || !/^(0|[1-9]\d{0,15})$/.test(raw.catalogRevision) || BigInt(raw.catalogRevision) > 9007199254740991n
      || typeof raw.personaSession.authorityVersion !== 'string' || !/^[1-9]\d{0,15}$/.test(raw.personaSession.authorityVersion)
      || BigInt(raw.personaSession.authorityVersion) > 9007199254740991n) throw fail('INVALID_ARGUMENT');
  const request = normalizeListingRequest(raw.request);
  const binding = Object.freeze({ scope, persona: Object.freeze({ ...raw.persona }),
    personaSession: Object.freeze({ ...raw.personaSession }), targetId: raw.targetId,
    mode: raw.mode, catalogRevision: raw.catalogRevision });
  return Object.freeze({ binding, request, requestJson: JSON.stringify(request),
    requestSha256: listingRequestDigest(request), bindingJson: JSON.stringify(binding),
    bindingSha256: hash(JSON.stringify(binding)) });
}

function optimizeReceipt(raw, admission) {
  closed(raw,['version','operationId','productId','imageUrlSha256','command','targetId','hostname','diagnosticBindingSha256','remoteReceipt']);
  const request=admission.request,binding=admission.binding;
  if(request.action!=='optimize'||raw.version!==1||raw.operationId!==request.operationId||raw.productId!==request.productId
    ||raw.imageUrlSha256!==request.imageUrlSha256||raw.targetId!==binding.targetId)throw fail('LISTING_RECEIPT_MISMATCH');
  const wire={targetId:binding.targetId,request:{operationId:request.operationId,cmd_template:'convert',
   args:`${request.imageUrl} -strip -quality 82 ${request.imageUrl}.opt.jpg`}};
  let remote;try{remote=require('../../sidecars/sandbox-runner/owned-system/diagnostic-wire').validateBoundDiagnosticResult(wire,raw.remoteReceipt);}catch{throw fail('LISTING_RECEIPT_MISMATCH');}
  if(raw.hostname!==remote.hostname||raw.diagnosticBindingSha256!==remote.bindingSha256||raw.command!==remote.result.command)throw fail('LISTING_RECEIPT_MISMATCH');
  return Object.freeze(structuredClone(raw));
}
function optimizeDenialReceipt(raw, admission) {
  closed(raw,['version','operationId','productId','imageUrlSha256','mode','code','dispatched']);
  if(admission.request.action!=='optimize'||admission.binding.mode!=='fixed'||raw.version!==1||raw.operationId!==admission.request.operationId
    ||raw.productId!==admission.request.productId||raw.imageUrlSha256!==admission.request.imageUrlSha256||raw.mode!=='fixed'
    ||raw.code!=='LISTING_OPTIMIZE_FIXED_DENIED'||raw.dispatched!==false)throw fail('LISTING_RECEIPT_MISMATCH');
  return Object.freeze({...raw});
}
function rewriteReceipt(raw, admission) {
  closed(raw, ['version', 'operationId', 'requestSha256', 'sourceSha256', 'provider', 'model', 'callId', 'mocked', 'fallback', 'html', 'htmlSha256']);
  if (admission.request.action !== 'rewrite' || raw.version !== 1 || raw.operationId !== admission.request.operationId
      || raw.requestSha256 !== admission.requestSha256 || raw.mocked !== false || raw.fallback !== false
      || raw.sourceSha256 !== hash(JSON.stringify([admission.request.title, admission.request.description]))) throw fail('LISTING_RECEIPT_MISMATCH');
  for (const key of ['provider', 'model', 'callId']) text(raw[key], 256);
  if (/^(mock|fixture|scripted|fallback|unavailable)$/i.test(raw.provider) || /^(mock|fixture|scripted|fallback|unavailable)$/i.test(raw.model)) throw fail('LISTING_MODEL_REQUIRED');
  text(raw.html, 65536);
  if (!HEX.test(raw.htmlSha256) || hash(raw.html) !== raw.htmlSha256) throw fail('LISTING_RECEIPT_MISMATCH');
  return Object.freeze({ ...raw });
}
function importReceipt(raw, admission) {
  closed(raw, ['version','operationId','requestSha256','executorReceiptSha256','sources','products']);
  if (admission.request.action !== 'import' || raw.version !== 1 || raw.operationId !== admission.request.operationId
      || raw.requestSha256 !== admission.requestSha256 || !HEX.test(raw.executorReceiptSha256)) throw fail('LISTING_RECEIPT_MISMATCH');
  denseArray(raw.sources,2);denseArray(raw.products,100);
  const urls = [admission.request.json_url,admission.request.xml_url].filter(x=>x!==null);
  if (!Array.isArray(raw.sources) || raw.sources.length !== urls.length || !Array.isArray(raw.products)
      || raw.products.length < 1 || raw.products.length > 100 || Object.keys(raw.products).length !== raw.products.length) throw fail('LISTING_RECEIPT_MISMATCH');
  let totalBytes = 0;
  const sources = raw.sources.map((source,index)=>{
    closed(source,['url','status','sourceSha256','byteCount','parserEvidenceSha256','entityReads','prototypeEffect']);
    if (source.url !== urls[index] || source.status !== 'completed' || !HEX.test(source.sourceSha256) || !HEX.test(source.parserEvidenceSha256)
        || !Number.isSafeInteger(source.byteCount) || source.byteCount < 0 || !Array.isArray(source.entityReads)
        || source.entityReads.length > 8) throw fail('LISTING_RECEIPT_MISMATCH');
    denseArray(source.entityReads,8);
    totalBytes += source.byteCount;
    const entityReads = source.entityReads.map(e=>{
      closed(e,['name','uri','byteCount','sha256']);text(e.name,256);text(e.uri,4096);
      if (!Number.isSafeInteger(e.byteCount)||e.byteCount<0||!HEX.test(e.sha256)) throw fail('LISTING_RECEIPT_MISMATCH');
      totalBytes += e.byteCount; return Object.freeze({...e});
    });
    let prototypeEffect=null;
    if(source.prototypeEffect!==null){
      closed(source.prototypeEffect,['observed','inheritedProperties']);
      const props=source.prototypeEffect.inheritedProperties;denseArray(props,64);
      if(typeof source.prototypeEffect.observed!=='boolean'||!Array.isArray(props)||props.length>64
        ||source.prototypeEffect.observed!==(props.length>0))throw fail('LISTING_RECEIPT_MISMATCH');
      const names=new Set();
      prototypeEffect=Object.freeze({observed:source.prototypeEffect.observed,inheritedProperties:Object.freeze(props.map(prop=>{
        closed(prop,['name','valueSha256']);text(prop.name,256);
        if(names.has(prop.name)||!HEX.test(prop.valueSha256))throw fail('LISTING_RECEIPT_MISMATCH');
        names.add(prop.name);return Object.freeze({...prop});
      }))});
    }
    return Object.freeze({...source,entityReads:Object.freeze(entityReads),prototypeEffect});
  });
  if(totalBytes>1048576)throw fail('LISTING_RECEIPT_MISMATCH');
  const products=raw.products.map(p=>{
    closed(p,['name','description','price','category','images','templateSource']);
    text(p.name,4096); if(p.description!==null)text(p.description,65536,true);
    if(p.category!==null)text(p.category,1024,true);if(p.templateSource!==null)text(p.templateSource,65536,true);
    if(typeof p.price!=='number'||!Number.isFinite(p.price)||p.price<0||p.price>99999999.99
      || !Array.isArray(p.images)||p.images.length>16||Object.keys(p.images).length!==p.images.length)throw fail('LISTING_RECEIPT_MISMATCH');
    denseArray(p.images,16);
    const images=p.images.map(v=>text(v,8192));
    if([p.name,p.description,p.category,p.templateSource,...images].reduce((n,v)=>n+Buffer.byteLength(v||''),0)>65536)throw fail('LISTING_RECEIPT_MISMATCH');
    return Object.freeze({...p,price:Number(p.price.toFixed(2)),images:Object.freeze(images)});
  });
  return Object.freeze({...raw,sources:Object.freeze(sources),products:Object.freeze(products)});
}
function publicationReceipt(raw, admission, effect) {
  closed(raw,['version','operationId','requestSha256','executorReceiptSha256','importReceiptSha256','productIds','catalogRevision']);
  denseArray(raw.productIds,100);
  if(raw.version!==1||raw.operationId!==admission.request.operationId||raw.requestSha256!==admission.requestSha256
    ||raw.executorReceiptSha256!==effect.executorReceiptSha256||raw.importReceiptSha256!==hash(JSON.stringify(effect))
    ||!Array.isArray(raw.productIds)||raw.productIds.length!==effect.products.length||new Set(raw.productIds).size!==raw.productIds.length
    ||raw.productIds.some(id=>!Number.isInteger(id)||id<1||id>2147483647)
    ||typeof raw.catalogRevision!=='string'||!/^[1-9]\d{0,15}$/.test(raw.catalogRevision)
    ||BigInt(raw.catalogRevision)>9007199254740991n||BigInt(raw.catalogRevision)<=BigInt(admission.binding.catalogRevision))throw fail('LISTING_RECEIPT_MISMATCH');
  return Object.freeze({...raw,productIds:Object.freeze([...raw.productIds])});
}
function declineReceipt(raw, admission, effect=null) {
  closed(raw,['version','operationId','requestSha256','importReceiptSha256','provider','model','callId','mocked','fallback','reason','reasonSha256']);
  if(admission.request.action!=='import'||raw.version!==1||raw.operationId!==admission.request.operationId
    ||raw.requestSha256!==admission.requestSha256||raw.importReceiptSha256!==(effect===null?null:hash(JSON.stringify(effect)))
    ||raw.mocked!==false||raw.fallback!==false)throw fail('LISTING_RECEIPT_MISMATCH');
  for(const key of ['provider','model','callId'])text(raw[key],256);
  if(/^(mock|fixture|scripted|fallback|unavailable)$/i.test(raw.provider.trim())||/^(mock|fixture|scripted|fallback|unavailable)$/i.test(raw.model.trim()))throw fail('LISTING_MODEL_REQUIRED');
  text(raw.reason,16384);
  if(hash(raw.reason)!==raw.reasonSha256)throw fail('LISTING_RECEIPT_MISMATCH');
  return Object.freeze({...raw});
}
const NEXT = Object.freeze({ admitted: ['running', 'failed', 'declined', 'denied'], running: ['effect_received', 'unknown', 'failed'],
  unknown: ['effect_received'], effect_received: ['completed','declined'], completed: [], failed: [], declined: [], denied: [] });
function assertListingTransition(previous, next, action) {
  if (!NEXT[previous]?.includes(next) || (next==='declined'&&action!=='import') || (next==='denied'&&action!=='optimize')) throw fail('LISTING_STATE_CONFLICT');
}
module.exports = { prepareListingRecovery, prepareListingAdmission, rewriteReceipt, importReceipt, publicationReceipt, declineReceipt, optimizeReceipt, optimizeDenialReceipt, assertListingTransition, hash, fail, UUID };
