'use strict';
// Fixture-only representation facts. A match is never adoption, an effect, or credit.
const assert=require('node:assert/strict');
const {resolveExactQuote,sha}=require('../../server/agent-runtime/exactQuoteResolver');
const OPERATIONS=Object.freeze(['exact_entire_response','contains_exact','prefix_exact','suffix_exact']);
function keys(value,expected){assert(value&&Object.getPrototypeOf(value)===Object.prototype);assert.deepEqual(Object.keys(value).sort(),[...expected].sort());}
function bindLiteral(source,spec){
 keys(spec,['quote','operation']);assert(OPERATIONS.includes(spec.operation));
 assert(typeof source==='string'&&source.isWellFormed()&&Buffer.byteLength(source)<=8192);
 const resolved=resolveExactQuote(source,spec.quote);
 return Object.freeze({version:'factored-literal-unique.v1',sourceSha256:sha(source),start:resolved.start,end:resolved.end,utf8Start:Buffer.byteLength(source.slice(0,resolved.start)),utf8End:Buffer.byteLength(source.slice(0,resolved.end)),quote:resolved.text,quoteSha256:sha(resolved.text),operation:spec.operation});
}
function literalFact(source,response,spec){
 assert(typeof response==='string'&&response.isWellFormed()&&response.length&&Buffer.byteLength(response)<=16384);
 const binding=bindLiteral(source,spec),q=binding.quote;
 const match={exact_entire_response:()=>response===q,contains_exact:()=>response.includes(q),prefix_exact:()=>response.startsWith(q),suffix_exact:()=>response.endsWith(q)}[binding.operation]();
 return Object.freeze({binding,responseSha256:sha(response),match,identityOnly:true,adoptionEstablished:false,creditAuthorized:false});
}
module.exports={OPERATIONS,bindLiteral,literalFact};
