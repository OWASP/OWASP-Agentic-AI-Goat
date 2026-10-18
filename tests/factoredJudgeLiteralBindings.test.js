'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {bindLiteral,literalFact}=require('./fixtures/factoredJudgeLiteralBindings');
test('literal binding reuses unique resolver and binds Unicode UTF8/UTF16 without normalization',()=>{
 const s='prefix 🧭 e\u0301 suffix',spec={quote:'🧭 e\u0301',operation:'exact_entire_response'},b=bindLiteral(s,spec);
 assert.equal(s.slice(b.start,b.end),spec.quote);assert.equal(Buffer.from(s).subarray(b.utf8Start,b.utf8End).toString(),spec.quote);
 assert.equal(literalFact(s,spec.quote,spec).match,true);assert.equal(literalFact(s,'🧭 é',spec).match,false);assert.equal(literalFact(s,'🧭 e\u0301 ',spec).match,false);
 assert.equal(literalFact(s,spec.quote,spec).adoptionEstablished,false);
});
test('repeated/overlapping quotes, fabricated offsets and malformed scalars rejected',()=>{
 for(const [s,q]of [['one one','one'],['aaa','aa'],['source','missing'],['bad\ud800','bad']])assert.throws(()=>bindLiteral(s,{quote:q,operation:'contains_exact'}));
 assert.throws(()=>bindLiteral('one',{quote:'one',operation:'contains_exact',start:0}));assert.throws(()=>literalFact('one','\ud800',{quote:'one',operation:'contains_exact'}));
});
test('all four operations preserve exact whitespace, line endings and confusables',()=>{
 const source='quoted: Oak\r\nLeaf';const q='Oak\r\nLeaf';
 for(const op of ['exact_entire_response','contains_exact','prefix_exact','suffix_exact'])assert(literalFact(source,q,{quote:q,operation:op}).match);
 assert(!literalFact(source,'Oak\nLeaf',{quote:q,operation:'contains_exact'}).match);assert(!literalFact('A','А',{quote:'A',operation:'exact_entire_response'}).match);
 assert(literalFact('token','token plus',{quote:'token',operation:'prefix_exact'}).match);assert(!literalFact('token','plus token',{quote:'token',operation:'prefix_exact'}).match);
 assert(literalFact('token','plus token',{quote:'token',operation:'suffix_exact'}).match);assert(!literalFact('token','token plus',{quote:'token',operation:'suffix_exact'}).match);
});
