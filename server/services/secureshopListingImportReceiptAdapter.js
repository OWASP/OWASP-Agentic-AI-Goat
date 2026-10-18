'use strict';

// Unmounted draft. Consume a receipt handle through a server-owned attestation
// store; this API deliberately accepts no caller-supplied replacement products.
const { prepareListingAdmission, importReceipt, hash, UUID } = require('./secureshopListingJournalContract');
const HEX = /^[a-f0-9]{64}$/;
const failure = code => Object.assign(new Error('Owned listing import receipt unavailable'), { code });
function closed(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) throw failure('LISTING_IMPORT_RECEIPT_INVALID');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== keys.length
      || keys.some(key => !Object.hasOwn(descriptors[key] || {}, 'value'))) throw failure('LISTING_IMPORT_RECEIPT_INVALID');
}
function optionalText(value, max) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0') || Buffer.byteLength(value)>max) throw failure('LISTING_IMPORT_RECEIPT_INVALID');
  return value;
}
const MUTATION_FIELDS = new Set(['__proto__','constructor','prototype']);
const PRODUCT_FIELDS = new Set(['name','description','price','category','images','image_url','templateSource','template_source']);
function product(raw) {
  if (!raw || Object.getPrototypeOf(raw)!==Object.prototype) throw failure('LISTING_IMPORT_RECEIPT_INVALID');
  const descriptors=Object.getOwnPropertyDescriptors(raw), keys=Reflect.ownKeys(descriptors);
  if(keys.some(key=>typeof key!=='string'||!Object.hasOwn(descriptors[key],'value')
    ||(!PRODUCT_FIELDS.has(key)&&!MUTATION_FIELDS.has(key))))throw failure('LISTING_IMPORT_RECEIPT_INVALID');
  // Polluting fields have already acted inside the disposable executor. Do not
  // merge them again into the application; retain their executor evidence.
  const own=key=>Object.hasOwn(descriptors,key)?descriptors[key].value:undefined;
  const name=optionalText(own('name'),4096);
  if(!name||!name.trim())throw failure('LISTING_IMPORT_RECEIPT_INVALID');
  let price=own('price');
  if(price===undefined)price=0;
  else if(typeof price==='string'){
    if(!/^(?:0|[1-9]\d{0,7})(?:\.\d{1,2})?$/.test(price))throw failure('LISTING_IMPORT_RECEIPT_INVALID');
    price=Number(price);
  }
  // Publication uses NUMERIC(10,2). Reject extra precision rather than quietly
  // changing an observed supplier price while preserving its original digest.
  if(typeof price!=='number'||!Number.isFinite(price)||price<0||price>99999999.99
    ||price!==Number(price.toFixed(2)))throw failure('LISTING_IMPORT_RECEIPT_INVALID');
  if(Object.hasOwn(descriptors,'templateSource')&&Object.hasOwn(descriptors,'template_source'))throw failure('LISTING_IMPORT_RECEIPT_INVALID');
  if(Object.hasOwn(descriptors,'images')&&Object.hasOwn(descriptors,'image_url'))throw failure('LISTING_IMPORT_RECEIPT_INVALID');
  const images=own('images')===undefined?(own('image_url')==null?[]:[own('image_url')]):own('images');
  if(!Array.isArray(images)||images.length>16)throw failure('LISTING_IMPORT_RECEIPT_INVALID');
  return {name,description:optionalText(own('description'),65536),price,category:optionalText(own('category'),1024),
    images:images.map(value=>{const image=optionalText(value,8192);if(!image)throw failure('LISTING_IMPORT_RECEIPT_INVALID');return image;}),
    templateSource:optionalText(own('templateSource')??own('template_source'),65536)};
}
function createListingImportReceiptAdapter({ attestations } = {}) {
  if(typeof attestations?.readVerifiedResult!=='function')throw new TypeError('Trusted Listings attestation store required');
  return Object.freeze({
    async normalize(receiptHandle, prepared) {
      if(typeof receiptHandle!=='string'||!UUID.test(receiptHandle))throw failure('LISTING_IMPORT_ATTESTATION_REQUIRED');
      const admission=prepareListingAdmission({...prepared?.binding,request:prepared?.request});
      if(admission.request.action!=='import')throw failure('LISTING_IMPORT_RECEIPT_INVALID');
      const expected=Object.freeze({operationId:admission.request.operationId,requestSha256:admission.requestSha256,
        bindingSha256:admission.bindingSha256,targetId:admission.binding.targetId,mode:admission.binding.mode});
      // This store must verify the managed executor signature/channel and package
      // identity before returning bytes. A supplied JSON object is never attestation.
      const verified=await attestations.readVerifiedResult(receiptHandle,expected);
      closed(verified,['bytes','context']);
      closed(verified.context,[...Object.keys(expected),'receiptHandle','executorId','packageSha256','isolation']);
      if(Object.keys(expected).some(key=>verified.context[key]!==expected[key])
        ||verified.context.receiptHandle!==receiptHandle||!UUID.test(verified.context.executorId)
        ||!HEX.test(verified.context.packageSha256)||verified.context.isolation!=='owned-listings.v1'
        ||!Buffer.isBuffer(verified.bytes)||verified.bytes.length<1||verified.bytes.length>2*1024*1024)throw failure('LISTING_IMPORT_ATTESTATION_MISMATCH');
      const bytes=Buffer.from(verified.bytes);
      let raw;
      try {raw=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
      catch {throw failure('LISTING_IMPORT_RECEIPT_INVALID');}
      closed(raw,['version','operationId','requestSha256','mode','products','sources']);
      if(raw.version!==1||raw.operationId!==expected.operationId||raw.requestSha256!==expected.requestSha256||raw.mode!==expected.mode
        ||!Array.isArray(raw.products)||raw.products.length<1||raw.products.length>100||!Array.isArray(raw.sources))throw failure('LISTING_IMPORT_RECEIPT_INVALID');
      const selected=[['json',admission.request.json_url],['xml',admission.request.xml_url]].filter(([,uri])=>uri!==null);
      if(raw.sources.length!==selected.length)throw failure('LISTING_IMPORT_RECEIPT_INVALID');
      const sources=raw.sources.map((source,index)=>{
        const [kind,uri]=selected[index];
        closed(source,['kind','uri','byteCount','sourceSha256',kind==='json'?'prototypeEffect':'entityReads']);
        if(source.kind!==kind||source.uri!==uri)throw failure('LISTING_IMPORT_RECEIPT_INVALID');
        if(expected.mode==='fixed'&&kind==='json'&&source.prototypeEffect?.observed!==false)throw failure('LISTING_IMPORT_RECEIPT_INVALID');
        if(expected.mode==='fixed'&&kind==='xml'&&source.entityReads?.length!==0)throw failure('LISTING_IMPORT_RECEIPT_INVALID');
        return {url:uri,status:'completed',sourceSha256:source.sourceSha256,byteCount:source.byteCount,
          parserEvidenceSha256:hash(JSON.stringify(source)),entityReads:kind==='xml'?source.entityReads:[],prototypeEffect:kind==='json'?source.prototypeEffect:null};
      });
      const normalized=importReceipt({version:1,operationId:expected.operationId,requestSha256:expected.requestSha256,
        executorReceiptSha256:hash(bytes),sources,products:raw.products.map(product)},admission);
      if(Buffer.byteLength(JSON.stringify(normalized))>1024*1024)throw failure('LISTING_IMPORT_RECEIPT_LIMIT');
      return normalized;
    },
  });
}
module.exports={createListingImportReceiptAdapter};
