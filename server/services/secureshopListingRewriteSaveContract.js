'use strict';
const { prepareListingAdmission, hash, UUID } = require('./secureshopListingJournalContract');
const fail = () => Object.assign(new Error('Invalid rewrite save'), { code: 'LISTING_SAVE_INVALID' });
function closed(raw, keys) {
 if (!raw || Object.getPrototypeOf(raw) !== Object.prototype) throw fail();
 const descriptors=Object.getOwnPropertyDescriptors(raw);
 if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!Object.hasOwn(descriptors[key]||{},'value')))throw fail();
}
function images(raw){
 if(!Array.isArray(raw)||Object.getPrototypeOf(raw)!==Array.prototype||raw.length>16)throw fail();
 const descriptors=Object.getOwnPropertyDescriptors(raw);
 if(Reflect.ownKeys(descriptors).length!==raw.length+1)throw fail();
 const values=[];for(let i=0;i<raw.length;i++){if(!Object.hasOwn(descriptors[i]||{},'value'))throw fail();values.push(text(descriptors[i].value,8192));}
 return values;
}
function text(value,max,nullable=false){if(value===null&&nullable)return null;if(typeof value!=='string'||!value.isWellFormed()||value.includes('\0')||Buffer.byteLength(value)>max)throw fail();return value;}
function prepareListingRewriteSave(raw){
 closed(raw,['admission','saveOperationId','productId','item']);
 const admission=prepareListingAdmission({...raw.admission?.binding,request:raw.admission?.request});
 if(admission.request.action!=='rewrite'||!UUID.test(raw.saveOperationId)||(raw.productId!==null&&(!Number.isInteger(raw.productId)||raw.productId<1||raw.productId>2147483647)))throw fail();
 closed(raw.item,['name','description','price','category','images','templateSource']);
 const item=raw.item;
 if(item.name!==admission.request.title||item.description!==admission.request.description||typeof item.price!=='number'||!Number.isFinite(item.price)||item.price<0||item.price>99999999.99||item.price!==Number(item.price.toFixed(2))||!Array.isArray(item.images)||item.images.length>16||Object.keys(item.images).length!==item.images.length)throw fail();
 const normalized={name:text(item.name,4096),description:text(item.description,65536),price:item.price,category:text(item.category,1024,true),images:images(item.images),templateSource:text(item.templateSource,65536,true)};
 if(normalized.images.some(v=>!v.trim()))throw fail();
 Object.freeze(normalized.images);Object.freeze(normalized);
 const itemJson=JSON.stringify(normalized);
 return Object.freeze({admission,saveOperationId:raw.saveOperationId,productId:raw.productId,item:normalized,itemJson,itemSha256:hash(itemJson),sourceSha256:hash(JSON.stringify([item.name,item.description]))});
}
module.exports={prepareListingRewriteSave};
