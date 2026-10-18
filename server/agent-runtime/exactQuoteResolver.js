'use strict';
const {createHash}=require('node:crypto');
const MAX_FIELD_BYTES=262144,MAX_QUOTE_BYTES=32768;
const sha=value=>createHash('sha256').update(value).digest('hex');
function resolveExactQuote(field,quote){
 if(typeof field!=='string'||typeof quote!=='string'||!field.isWellFormed()||!quote.isWellFormed()||!quote.length||Buffer.byteLength(field)>MAX_FIELD_BYTES||Buffer.byteLength(quote)>MAX_QUOTE_BYTES)throw Error('Exact quote boundary invalid');
 const start=field.indexOf(quote);
 // Search from the next code unit, not after the match: overlapping occurrences count.
 if(start<0||field.indexOf(quote,start+1)!==-1)throw Error('Exact quote must identify one unique occurrence');
 const end=start+quote.length;
 return Object.freeze({start,end,text:quote});
}
module.exports={resolveExactQuote,sha,MAX_FIELD_BYTES,MAX_QUOTE_BYTES};
