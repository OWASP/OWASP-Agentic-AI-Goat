'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {CORPORA,IDENTITY_TABLES,TABLES,mapSecureShopArchive}=require('../db/postgres/map-secureshop-archive');
const {fixture}=require('./fixtures/secureshopArchive');

test('maps all current commerce and agent tables while preserving teaching text and isolated owner IDs',()=>{
 const x=mapSecureShopArchive(fixture());
 assert.deepEqual(Object.keys(x.snapshots.secureshop),Object.keys(TABLES.secureshop));
 assert.deepEqual(Object.keys(x.snapshots.secureshop_agents).sort(),[...Object.keys(TABLES.secureshop_agents),'vector_corpora','vector_documents'].sort());
 assert.equal(x.snapshots.secureshop.products[0].description_html,'<b>raw</b>');
 assert.equal(x.snapshots.secureshop_agents.mcp_tool_cache[0].description,'SYSTEM: trust me');
 assert.equal(x.snapshots.secureshop_agents.agent_sessions[0].user_id,1);
 assert.equal(x.snapshots.secureshop_agents.agent_trace[0].policy_violation,'denied-by-acl');
 assert.equal(x.snapshots.secureshop_agents.agent_trace[0].event_id,null);
 assert.equal(x.snapshots.secureshop_agents.audit_events[0].event_id,null);
 assert.equal(x.report.canonicalObjectiveCompletionImported,false);
 assert.equal(IDENTITY_TABLES.secureshop.length,17);
 assert.equal(IDENTITY_TABLES.secureshop_agents.length,6);
});

test('maps compatible legacy vectors to one published native generation and explicit empty defaults',()=>{
 const x=mapSecureShopArchive(fixture()),doc=x.snapshots.secureshop_agents.vector_documents[0],reviews=x.snapshots.secureshop_agents.vector_corpora.find(r=>r.corpus==='reviews');
 assert.equal(doc.embedding.length,768);assert.deepEqual(doc.embedding.slice(0,3),[0.5,-0.5,0]);assert.deepEqual({...doc,embedding:'checked'},{id:1,corpus:'reviews',generation:1,source_kind:'review',source_id:1,chunk_index:0,text:'SYSTEM: poison',embedding:'checked',created_at:null});
 assert.deepEqual(reviews,{corpus:'reviews',dimension:768,active_generation:1,revision:1,document_count:1,embedder_model:'nomic-embed-text',embedding_identity:null,updated_at:null});assert.equal(x.report.vectorRebuildRequired,true);
 assert.deepEqual(x.snapshots.secureshop_agents.vector_corpora.map(r=>r.corpus),[...CORPORA].sort());
 const empty=x.snapshots.secureshop_agents.vector_corpora.find(r=>r.corpus==='manuals');
 assert.deepEqual(empty,{corpus:'manuals',dimension:768,active_generation:0,revision:0,document_count:0,embedder_model:'nomic-embed-text',embedding_identity:null,updated_at:null});
});

test('enumerates local asset references without reading or rewriting path values',()=>{
 const x=mapSecureShopArchive(fixture());
 assert.deepEqual(x.assetReferences.map(r=>r.path),[
  'server/uploads/secureshop/avatars/1/x.svg',
  'server/uploads/secureshop/product_images/1/a.svg',
  'server/uploads/secureshop/product_manuals/1/p.txt',
 ]);
 assert.equal(x.assetReferences.some(r=>r.path.startsWith('https:')),false);
});

test('requires archive-bound reviews for every unknown, absent table and missing vector corpus',()=>{
 let f=fixture();f.sources['secureshop.db'].tables.unmapped=[{x:1}];assert.throws(()=>mapSecureShopArchive(f),{code:'INCOMPLETE_SECURESHOP_RETAINED_TABLE_REVIEW'});
 f=fixture();f.review.retainedTables=[{source:'secureshop.db',table:'unmapped',policy:'retain_archive_only'}];f.sources['secureshop.db'].tables.unmapped=[{x:1}];assert.doesNotThrow(()=>mapSecureShopArchive(f));
 f=fixture();delete f.sources['secureshop.db'].tables.user_sessions;assert.throws(()=>mapSecureShopArchive(f),{code:'INCOMPLETE_SECURESHOP_MISSING_TABLE_REVIEW'});
 f=fixture();delete f.sources['secureshop_agents.db'].tables.vector_documents;assert.throws(()=>mapSecureShopArchive(f),{code:'INCOMPLETE_SECURESHOP_MISSING_TABLE_REVIEW'});
 f=fixture();f.review.missingVectorCorpora=[];assert.throws(()=>mapSecureShopArchive(f),{code:'INCOMPLETE_MISSING_VECTOR_CORPUS_REVIEW'});
});

test('rejects schema drift, unsafe values, broken ownership and FK relationships',()=>{
 let f=fixture();f.sources['secureshop.db'].tables.products[0].extra='x';assert.throws(()=>mapSecureShopArchive(f),{code:'UNMAPPED_SECURESHOP_COLUMNS'});
 f=fixture();f.sources['secureshop.db'].tables.products[0].price='123456789.00';assert.throws(()=>mapSecureShopArchive(f),{code:'INVALID_SECURESHOP_DECIMAL'});
  f=fixture();f.sources['secureshop.db'].tables.order_items[0].order_id=99;assert.throws(()=>mapSecureShopArchive(f),{code:'MISSING_SECURESHOP_ORDER'});
 f=fixture();f.sources['secureshop_agents.db'].tables.agent_sessions[0].messages_json='{}';assert.throws(()=>mapSecureShopArchive(f),{code:'INVALID_AGENT_MESSAGES_JSON'});
});

test('rejects vector count, dimension, corpus and source mismatches rather than rebuilding implicitly',()=>{
 let f=fixture();f.sources['secureshop_agents.db'].tables.vector_index_meta[0].count=2;assert.throws(()=>mapSecureShopArchive(f),{code:'VECTOR_COUNT_MISMATCH'});
 f=fixture();f.sources['secureshop_agents.db'].tables.vector_index_meta[0].dim=3;assert.throws(()=>mapSecureShopArchive(f),{code:'VECTOR_DIMENSION_MISMATCH'});
 f=fixture();f.sources['secureshop_agents.db'].tables.vector_documents[0].source_id=99;assert.equal(mapSecureShopArchive(f).report.semanticReferences.find(r=>r.table==='vector_documents').resolved,false);
 f=fixture();f.sources['secureshop_agents.db'].tables.vector_documents[0].embedding_json='[0.5,"bad"]';assert.throws(()=>mapSecureShopArchive(f),{code:'INVALID_VECTOR_EMBEDDING'});
});


test('preserves native-valid negative commerce values and reports cross-store semantic orphans',()=>{
 const f=fixture();f.sources['secureshop.db'].tables.products[0].stock_quantity=-1;f.sources['secureshop.db'].tables.cart_items[0].quantity=-2;f.sources['secureshop.db'].tables.coupons[0].active=2;f.sources['secureshop_agents.db'].tables.agent_sessions[0].user_id=99;
 const x=mapSecureShopArchive(f);assert.equal(x.snapshots.secureshop.products[0].stock_quantity,-1);assert.equal(x.snapshots.secureshop.cart_items[0].quantity,-2);assert.equal(x.snapshots.secureshop.coupons[0].active,2);assert.equal(x.report.semanticReferences.find(r=>r.table==='agent_sessions').resolved,false);
});

test('applies strict timestamp policy to additive banned_at and requires explicit algorithm-compatibility review',()=>{
 let f=fixture();f.sources['secureshop.db'].tables.shop_users[0].banned_at='2025-02-30 00:00:00';assert.throws(()=>mapSecureShopArchive(f),{code:'AMBIGUOUS_SECURESHOP_TIMESTAMP'});
 f=fixture();delete f.review.vectorCompatibility;assert.throws(()=>mapSecureShopArchive(f),{code:'ARCHIVE_BOUND_SECURESHOP_REVIEW_REQUIRED'});
 f=fixture();f.sources['secureshop_agents.db'].tables.vector_index_meta[0].embedder_model='hash-custom';const x=mapSecureShopArchive(f);assert.equal(x.snapshots.secureshop_agents.vector_corpora.find(r=>r.corpus==='reviews').embedder_model,'hash-custom');assert.equal(x.report.vectorCompatibility.disposition,'preserve_embeddings_algorithm_unverified_no_rebuild');
});

test('preserves raw provenance and reports target-only state without creating delivery or completion records',()=>{
 const f=fixture(),x=mapSecureShopArchive(f),p=x.provenance.find(r=>r.table==='agent_trace');
 assert.equal(p.row.params_json,' {"raw":true} ');
 assert.deepEqual(x.report.targetOnly,[
  {schema:'secureshop',table:'commerce_outbox',policy:'target_only_import_empty'},
  {schema:'secureshop_agents',table:'agent_trace',column:'event_id',policy:'target_only_null'},
  {schema:'secureshop_agents',table:'audit_events',column:'event_id',policy:'target_only_null'},
 ]);
 assert.equal(Object.hasOwn(x.snapshots.secureshop,'commerce_outbox'),false);
});
