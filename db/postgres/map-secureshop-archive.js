'use strict';

const { timestamp } = require('../../server/database/postgres/identityValidation');

const CORPORA = Object.freeze(['reviews', 'manuals', 'policies', 'products']);
const TABLES = Object.freeze({
  secureshop: Object.freeze({
    shop_users: 'id username email password role full_name phone address created_at updated_at avatar_path session_token api_key pii_json banned_at',
    products: 'id name description price category image_url stock_quantity retailer_id status created_at updated_at template_source description_html',
    cart_items: 'id user_id product_id quantity added_at',
    orders: 'id customer_id total_amount status payment_method payment_status shipping_address order_date shipped_date delivered_date',
    order_items: 'id order_id product_id quantity price',
    chat_messages: 'id user_id message response message_type status created_at agent_trace_id',
    categories: 'id name description created_at',
    product_images: 'id product_id path mime uploaded_by uploaded_at',
    product_manuals: 'id product_id path mime vector_ref uploaded_by uploaded_at',
    reviews: 'id product_id author_id body rating status moderator_kind moderator_notes created_at moderated_at',
    coupons: 'id code discount_percent active created_at',
    support_tickets: 'id customer_id subject body attachments_json status created_at',
    email_threads: 'id subject participants_json created_at',
    emails: 'id thread_id from_addr to_addr subject body_markdown body_html headers_raw created_at',
    policies: 'id name markdown_source injected_into_json updated_at',
    user_addresses: 'id user_id label line1 line2 city state zip phone is_default created_at',
    user_sessions: 'id user_id ip user_agent token_jti created_at last_seen_at revoked_at',
  }),
  secureshop_agents: Object.freeze({
    agent_sessions: 'id user_id role messages_json token_budget_used created_at updated_at',
    agent_trace: 'id session_id step actor kind agent_ns tool_name params_json result_json latency_ms tokens_in tokens_out provider ts policy_violation',
    mcp_registry: 'id name url transport stdio_cmd status last_schema_hash added_by added_at',
    mcp_tool_cache: 'id server_name tool_name description input_schema_json cached_at',
    audit_events: 'id actor action target params_json ip user_agent ts',
    background_jobs: 'id kind payload_json status result_json error_text created_at started_at finished_at',
    agent_provider_state: 'role active_provider last_success_at fallback_cursor',
    mcp_schema_history: 'id name schema_hash tools_json ts',
    tool_permissions: 'tool_name role allowed reason updated_at',
    system_config: 'key value updated_at updated_by',
  }),
});
const SOURCE_FOR_SCHEMA = Object.freeze({ secureshop: 'secureshop.db', secureshop_agents: 'secureshop_agents.db' });
const IDENTITY_TABLES = Object.freeze({
  secureshop: Object.freeze(Object.keys(TABLES.secureshop)),
  secureshop_agents: Object.freeze(['agent_trace', 'mcp_registry', 'mcp_tool_cache', 'audit_events', 'mcp_schema_history', 'vector_documents']),
});
const VECTOR_TABLES = new Set(['vector_documents', 'vector_index_meta']);
const SOURCE_TABLES = new Set([...Object.keys(TABLES.secureshop_agents), ...VECTOR_TABLES]);
const INTEGER_COLUMNS = new Set('id user_id product_id retailer_id customer_id order_id thread_id author_id uploaded_by quantity stock_quantity rating discount_percent active is_default step latency_ms tokens_in tokens_out added_by token_budget_used fallback_cursor'.split(' '));
const FLAGS = new Set(['active', 'is_default', 'allowed']);
const TIMESTAMP_COLUMNS = new Set('created_at updated_at added_at order_date shipped_date delivered_date uploaded_at moderated_at revoked_at last_seen_at ts cached_at started_at finished_at last_success_at banned_at'.split(' '));
const DECIMAL_COLUMNS = new Set(['price', 'total_amount']);
const REQUIRED = Object.freeze({
  shop_users:['id','username','email','password'], products:['id','name','price'], cart_items:['id','user_id','product_id'],
  orders:['id','customer_id','total_amount'], order_items:['id','order_id','product_id','quantity','price'], chat_messages:['id','user_id','message'], categories:['id','name'],
  product_images:['id','product_id','path'], product_manuals:['id','product_id','path'], reviews:['id','product_id','body'], coupons:['id','code'],
  support_tickets:['id','customer_id','subject','body'], email_threads:['id','subject'], emails:['id','thread_id','from_addr','to_addr','subject','body_markdown','body_html'],
  policies:['id','name','markdown_source'], user_addresses:['id','user_id','line1'], user_sessions:['id','user_id'],
  agent_sessions:['id','user_id','role','messages_json','token_budget_used'], agent_trace:['id','session_id','step','actor','kind'],
  mcp_registry:['id','name','transport'], mcp_tool_cache:['id','server_name','tool_name'], audit_events:['id','actor','action'],
  background_jobs:['id','kind'], agent_provider_state:['role'], mcp_schema_history:['id','name','schema_hash','tools_json'],
  tool_permissions:['tool_name','role','allowed'], system_config:['key','value'],
});

function reject(code, location) { throw Object.assign(new Error(code), { code, location }); }
function typedInteger(value, location, { positive = false, nonnegative = false } = {}) {
  if (value && typeof value === 'object' && !Array.isArray(value)
      && Object.keys(value).sort().join(',') === 'type,value' && value.type === 'integer'
      && typeof value.value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(value.value)) value = Number(value.value);
  if (!Number.isSafeInteger(value) || value < -2147483648 || value > 2147483647
      || (positive && value < 1) || (nonnegative && value < 0)) reject('INVALID_SECURESHOP_INTEGER', location);
  return value;
}
function bigint(value, location, { positive = false } = {}) {
  if (value && typeof value === 'object' && !Array.isArray(value)
      && Object.keys(value).sort().join(',') === 'type,value' && value.type === 'integer') value = value.value;
  else if (Number.isSafeInteger(value)) value = String(value);
  if (typeof value !== 'string' || !/^-?(0|[1-9][0-9]*)$/.test(value)) reject('INVALID_SECURESHOP_BIGINT', location);
  const number = BigInt(value);
  if (number < -(2n ** 63n) || number > 2n ** 63n - 1n || (positive && number < 1n)) reject('INVALID_SECURESHOP_BIGINT', location);
  return number <= BigInt(Number.MAX_SAFE_INTEGER) && number >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(number) : value;
}
function exact(row, columns, location) {
  if (!row || typeof row !== 'object' || Array.isArray(row)
      || Object.keys(row).sort().join(',') !== columns.slice().sort().join(',')) reject('UNMAPPED_SECURESHOP_COLUMNS', location);
}
function text(value, location) {
  if (typeof value !== 'string' || value.includes('\0')) reject('INVALID_SECURESHOP_TEXT', location);
  return value;
}
function instant(value, location, policy) {
  value = text(value, location);
  if (!/(Z|[+-]\d{2}:\d{2})$/.test(value) && policy !== 'UTC') reject('AMBIGUOUS_SECURESHOP_TIMESTAMP', location);
  try { return timestamp(value, false); } catch { reject('INVALID_SECURESHOP_TIMESTAMP', location); }
}
function decimal(value, location) {
  if (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === 'type,value') {
    if (value.type === 'integer' && /^-?(0|[1-9][0-9]*)$/.test(value.value)) value = value.value;
    else if (value.type === 'real' && typeof value.value === 'number' && Number.isFinite(value.value)) value = String(value.value);
    else reject('INVALID_SECURESHOP_DECIMAL', location);
  } else if (typeof value === 'number' && Number.isFinite(value)) value = String(value);
  else if (typeof value !== 'string') reject('INVALID_SECURESHOP_DECIMAL', location);
  if (!/^-?(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{1,2})?$/.test(value)) reject('INVALID_SECURESHOP_DECIMAL', location);
  return value;
}
function stableList(rows) { return rows.map(row => JSON.stringify(row, Object.keys(row).sort())).sort(); }
function reviewMatches(actual, supplied, code) {
  if (!Array.isArray(supplied) || JSON.stringify(stableList(actual)) !== JSON.stringify(stableList(supplied))) reject(code, 'review');
}
function keyFor(table, row) {
  if (row.id !== undefined) return String(row.id);
  if (table === 'tool_permissions') return JSON.stringify([row.tool_name, row.role]);
  return String(row.role ?? row.key);
}
function isOpaqueLocalPath(value) {
  if (typeof value !== 'string' || !value.length || value.startsWith('data:')) return false;
  try { const u = new URL(value); return !['http:', 'https:'].includes(u.protocol); } catch { return true; }
}
function addAssetReference(list, source, table, key, column, value) {
  if (value !== null && isOpaqueLocalPath(value)) list.push({ source, table, key, column, path: value });
}

function mapSecureShopArchive(raw = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
      || Object.keys(raw).some(key => !['sources','archiveDigest','naiveTimestamps','review'].includes(key))) reject('INVALID_SECURESHOP_ARCHIVE_INPUT', 'input');
  const { sources, archiveDigest, naiveTimestamps = 'reject', review } = raw;
  if (typeof archiveDigest !== 'string' || !/^[a-f0-9]{64}$/.test(archiveDigest)) reject('ARCHIVE_DIGEST_REQUIRED', 'archiveDigest');
  if (!['reject','UTC'].includes(naiveTimestamps)) reject('INVALID_TIMESTAMP_POLICY', 'naiveTimestamps');
  if (!sources || typeof sources !== 'object' || Array.isArray(sources)
      || Object.keys(sources).some(source => !['secureshop.db','secureshop_agents.db'].includes(source))) reject('INVALID_SECURESHOP_SOURCES', 'sources');
  if (!review || typeof review !== 'object' || Array.isArray(review)
      || Object.keys(review).sort().join(',') !== 'archiveDigest,missingTables,missingVectorCorpora,retainedTables,vectorCompatibility'
      || review.archiveDigest !== archiveDigest
      || !review.vectorCompatibility || review.vectorCompatibility.archiveDigest !== archiveDigest
      || review.vectorCompatibility.disposition !== 'preserve_embeddings_algorithm_unverified_no_rebuild'
      || Object.keys(review.vectorCompatibility).sort().join(',') !== 'archiveDigest,disposition') reject('ARCHIVE_BOUND_SECURESHOP_REVIEW_REQUIRED', 'review');

  const snapshots = { secureshop: {}, secureshop_agents: { vector_corpora: [], vector_documents: [] } };
  const provenance = [], assetReferences = [], retainedTables = [], missingTables = [];
  for (const schema of Object.keys(TABLES)) {
    const source = SOURCE_FOR_SCHEMA[schema], envelope = sources[source];
    if (!envelope || !envelope.tables || typeof envelope.tables !== 'object' || Array.isArray(envelope.tables)) reject('INVALID_SECURESHOP_SOURCE', source);
    const known = schema === 'secureshop' ? new Set(Object.keys(TABLES[schema])) : SOURCE_TABLES;
    for (const [table, rows] of Object.entries(envelope.tables)) {
      if (!Array.isArray(rows)) reject('INVALID_SECURESHOP_TABLE', `${source}.${table}`);
      if (!known.has(table)) retainedTables.push({ source, table, policy: 'retain_archive_only' });
    }
    if (schema === 'secureshop_agents') {
      for (const table of VECTOR_TABLES) if (envelope.tables[table] === undefined) {
        missingTables.push({ source, table, policy: 'source_table_absent_import_empty' });
      }
    }
    for (const [table, columnsText] of Object.entries(TABLES[schema])) {
      const rows = envelope.tables[table];
      if (rows === undefined) { missingTables.push({ source, table, policy: 'source_table_absent_import_empty' }); snapshots[schema][table] = []; continue; }
      const columns = columnsText.split(' '), required = new Set(REQUIRED[table] || []), seen = new Set();
      snapshots[schema][table] = rows.map((original, index) => {
        const at = `${source}.${table}[${index}]`; exact(original, columns, at); const row = {};
        for (const column of columns) {
          const location = `${at}.${column}`, value = original[column];
          if (value === null) { if (required.has(column)) reject('NULL_SECURESHOP_REQUIRED_VALUE', location); row[column] = null; continue; }
          if (DECIMAL_COLUMNS.has(column)) row[column] = decimal(value, location);
          else if ((INTEGER_COLUMNS.has(column) && !(column === 'id' && ['agent_sessions','background_jobs'].includes(table))) || FLAGS.has(column)) {
            row[column] = typedInteger(value, location, { positive: column === 'id' });
          } else if (TIMESTAMP_COLUMNS.has(column)) row[column] = instant(value, location, naiveTimestamps);
          else row[column] = text(value, location);
        }
        if (table === 'agent_sessions') { let parsed; try { parsed = JSON.parse(row.messages_json); } catch { reject('INVALID_AGENT_MESSAGES_JSON', `${at}.messages_json`); } if (!Array.isArray(parsed)) reject('INVALID_AGENT_MESSAGES_JSON', `${at}.messages_json`); }
        const key = keyFor(table, row); if (seen.has(key)) reject('DUPLICATE_SECURESHOP_SOURCE_KEY', at); seen.add(key);
        if (table === 'shop_users') addAssetReference(assetReferences, source, table, key, 'avatar_path', row.avatar_path);
        if (table === 'products') addAssetReference(assetReferences, source, table, key, 'image_url', row.image_url);
        if (table === 'product_images' || table === 'product_manuals') addAssetReference(assetReferences, source, table, key, 'path', row.path);
        const target = { ...row };
        if (table === 'agent_trace' || table === 'audit_events') target.event_id = null;
        provenance.push({ schema, source, table, key, row: structuredClone(original) });
        return target;
      });
    }
  }
  reviewMatches(retainedTables, review.retainedTables, 'INCOMPLETE_SECURESHOP_RETAINED_TABLE_REVIEW');
  reviewMatches(missingTables, review.missingTables, 'INCOMPLETE_SECURESHOP_MISSING_TABLE_REVIEW');

  validateCommerce(snapshots.secureshop);
  const agentReferences = validateAgents(snapshots.secureshop_agents, snapshots.secureshop);
  const vectorReport = mapVectors(sources['secureshop_agents.db'].tables, snapshots, provenance, archiveDigest, naiveTimestamps, review.missingVectorCorpora);
  return {
    snapshots, provenance, assetReferences,
    report: {
      archiveDigest,
      counts: {
        secureshop: Object.fromEntries(Object.entries(snapshots.secureshop).map(([table, rows]) => [table, rows.length])),
        secureshop_agents: Object.fromEntries(Object.entries(snapshots.secureshop_agents).map(([table, rows]) => [table, rows.length])),
      },
      retainedTables, missingTables, missingVectorCorpora: vectorReport.missing,
      targetOnly: [
        { schema:'secureshop', table:'commerce_outbox', policy:'target_only_import_empty' },
        { schema:'secureshop_agents', table:'agent_trace', column:'event_id', policy:'target_only_null' },
        { schema:'secureshop_agents', table:'audit_events', column:'event_id', policy:'target_only_null' },
      ],
      vectorTimestampPolicy: 'legacy null timestamps remain null; acknowledged missing corpora use native empty defaults with null updated_at',
      semanticReferences: [...agentReferences, ...vectorReport.references],
      vectorCompatibility: review.vectorCompatibility,
      vectorRebuildRequired: vectorReport.references.length > 0,
      canonicalObjectiveCompletionImported: false,
    },
  };
}

function validateCommerce(t) {
  const ids = table => new Set(t[table].map(row => row.id));
  const users=ids('shop_users'), products=ids('products'), orders=ids('orders'), threads=ids('email_threads');
  const requireRef=(rows,column,set,code)=>rows.forEach((row,index)=>{if(row[column]!==null&&!set.has(row[column]))reject(code,`${index}.${column}`);});
  requireRef(t.products,'retailer_id',users,'MISSING_SECURESHOP_USER');
  for(const table of ['cart_items','chat_messages','user_addresses','user_sessions'])requireRef(t[table],'user_id',users,'MISSING_SECURESHOP_USER');
  requireRef(t.orders,'customer_id',users,'MISSING_SECURESHOP_USER'); requireRef(t.support_tickets,'customer_id',users,'MISSING_SECURESHOP_USER');
  for(const table of ['cart_items','product_images','product_manuals','reviews'])requireRef(t[table],'product_id',products,'MISSING_SECURESHOP_PRODUCT');
  requireRef(t.order_items,'order_id',orders,'MISSING_SECURESHOP_ORDER'); requireRef(t.order_items,'product_id',products,'MISSING_SECURESHOP_PRODUCT');
  requireRef(t.product_images,'uploaded_by',users,'MISSING_SECURESHOP_USER'); requireRef(t.product_manuals,'uploaded_by',users,'MISSING_SECURESHOP_USER'); requireRef(t.reviews,'author_id',users,'MISSING_SECURESHOP_USER');
  requireRef(t.emails,'thread_id',threads,'MISSING_SECURESHOP_EMAIL_THREAD');
  const unique=(rows,key,code)=>{const seen=new Set();for(const row of rows){const value=key(row);if(seen.has(value))reject(code,String(value));seen.add(value);}};
  unique(t.shop_users,r=>r.username,'DUPLICATE_SECURESHOP_USERNAME'); unique(t.shop_users,r=>r.email,'DUPLICATE_SECURESHOP_EMAIL');
  unique(t.categories,r=>r.name,'DUPLICATE_SECURESHOP_CATEGORY'); unique(t.coupons,r=>r.code,'DUPLICATE_SECURESHOP_COUPON'); unique(t.policies,r=>r.name,'DUPLICATE_SECURESHOP_POLICY');
}
function validateAgents(a, commerce) {
  const users=new Set(commerce.shop_users.map(row=>row.id)), sessions=new Set(a.agent_sessions.map(row=>row.id)), references=[];
  a.agent_sessions.forEach((row,index)=>references.push({source:'secureshop_agents.db',table:'agent_sessions',key:row.id,column:'user_id',target:'secureshop.shop_users',value:row.user_id,resolved:users.has(row.user_id)}));
  a.mcp_registry.forEach((row)=>{if(row.added_by!==null)references.push({source:'secureshop_agents.db',table:'mcp_registry',key:String(row.id),column:'added_by',target:'secureshop.shop_users',value:row.added_by,resolved:users.has(row.added_by)});});
  a.agent_trace.forEach((row,index)=>{if(!sessions.has(row.session_id))reject('MISSING_AGENT_SESSION',`agent_trace[${index}].session_id`);});
  const unique=(rows,key,code)=>{const seen=new Set();for(const row of rows){const value=key(row);if(seen.has(value))reject(code,String(value));seen.add(value);}};
  unique(a.mcp_registry,r=>r.name,'DUPLICATE_MCP_REGISTRY_NAME'); unique(a.mcp_tool_cache,r=>JSON.stringify([r.server_name,r.tool_name]),'DUPLICATE_MCP_TOOL_CACHE');
  unique(a.tool_permissions,r=>JSON.stringify([r.tool_name,r.role]),'DUPLICATE_TOOL_PERMISSION');
  return references;
}
function mapVectors(sourceTables, snapshots, provenance, archiveDigest, policy, suppliedMissing) {
  const docs = sourceTables.vector_documents || [], meta = sourceTables.vector_index_meta || [];
  if (!Array.isArray(docs) || !Array.isArray(meta)) reject('INVALID_SECURESHOP_VECTOR_TABLE', 'vectors');
  const metaByCorpus=new Map(), docsByCorpus=new Map(CORPORA.map(name=>[name,[]]));
  for (let index=0;index<meta.length;index++) {
    const original=meta[index], at=`secureshop_agents.db.vector_index_meta[${index}]`;
    exact(original, 'corpus dim count last_rebuilt_at embedder_model'.split(' '), at);
    const name=text(original.corpus,`${at}.corpus`); if(!CORPORA.includes(name)||metaByCorpus.has(name))reject('INVALID_VECTOR_CORPUS',at);
    const dim=typedInteger(original.dim,`${at}.dim`,{positive:true}), count=typedInteger(original.count,`${at}.count`,{nonnegative:true});
    if(dim>4096)reject('INVALID_VECTOR_DIMENSION',`${at}.dim`); const model=text(original.embedder_model,`${at}.embedder_model`); if(!model)reject('INVALID_VECTOR_MODEL',`${at}.embedder_model`);
    const rebuilt=original.last_rebuilt_at===null?null:instant(original.last_rebuilt_at,`${at}.last_rebuilt_at`,policy);
    metaByCorpus.set(name,{corpus:name,dimension:dim,active_generation:1,revision:1,document_count:count,embedder_model:model,embedding_identity:null,updated_at:rebuilt});
    provenance.push({schema:'secureshop_agents',source:'secureshop_agents.db',table:'vector_index_meta',key:name,row:structuredClone(original)});
  }
  const sourceKinds={review:'reviews',manual:'manuals',policy:'policies',product_desc:'products',product:'products'};
  const commerceSets={reviews:new Set(snapshots.secureshop.reviews.map(r=>r.id)),manuals:new Set(snapshots.secureshop.products.map(r=>r.id)),policies:new Set(snapshots.secureshop.policies.map(r=>r.id)),products:new Set(snapshots.secureshop.products.map(r=>r.id))};
  const seenIds=new Set(), references=[];
  for(let index=0;index<docs.length;index++){
    const original=docs[index],at=`secureshop_agents.db.vector_documents[${index}]`;
    exact(original,'id source_kind source_id chunk_index text embedding_json created_at'.split(' '),at);
    const id=bigint(original.id,`${at}.id`,{positive:true});if(seenIds.has(id))reject('DUPLICATE_VECTOR_ID',at);seenIds.add(id);
    const kind=text(original.source_kind,`${at}.source_kind`),name=sourceKinds[kind];if(!name)reject('UNKNOWN_VECTOR_SOURCE_KIND',`${at}.source_kind`);
    const sourceId=bigint(original.source_id,`${at}.source_id`),chunkIndex=typedInteger(original.chunk_index,`${at}.chunk_index`,{nonnegative:true});
    let embedding;try{embedding=JSON.parse(text(original.embedding_json,`${at}.embedding_json`));}catch{reject('INVALID_VECTOR_EMBEDDING',`${at}.embedding_json`);}
    if(!Array.isArray(embedding)||!embedding.length||embedding.some(value=>typeof value!=='number'||!Number.isFinite(value)))reject('INVALID_VECTOR_EMBEDDING',`${at}.embedding_json`);
    const state=metaByCorpus.get(name);if(!state)reject('MISSING_VECTOR_METADATA',at);if(embedding.length!==state.dimension)reject('VECTOR_DIMENSION_MISMATCH',at);
    const row={id,corpus:name,generation:1,source_kind:kind,source_id:sourceId,chunk_index:chunkIndex,text:text(original.text,`${at}.text`),embedding,created_at:original.created_at===null?null:instant(original.created_at,`${at}.created_at`,policy)};
    docsByCorpus.get(name).push(row);snapshots.secureshop_agents.vector_documents.push(row);
    references.push({source:'secureshop_agents.db',table:'vector_documents',key:String(id),column:'source_id',target:`secureshop.${name==='manuals'?'products':name}`,value:sourceId,resolved:commerceSets[name].has(sourceId)});
    provenance.push({schema:'secureshop_agents',source:'secureshop_agents.db',table:'vector_documents',key:String(id),row:structuredClone(original)});
  }
  for(const [name,state] of metaByCorpus){if(state.document_count!==docsByCorpus.get(name).length)reject('VECTOR_COUNT_MISMATCH',name);snapshots.secureshop_agents.vector_corpora.push(state);}
  const missing=[];for(const name of CORPORA)if(!metaByCorpus.has(name)){if(docsByCorpus.get(name).length)reject('MISSING_VECTOR_METADATA',name);missing.push({corpus:name,policy:'source_meta_absent_import_empty'});snapshots.secureshop_agents.vector_corpora.push({corpus:name,dimension:768,active_generation:0,revision:0,document_count:0,embedder_model:'nomic-embed-text',embedding_identity:null,updated_at:null});}
  reviewMatches(missing,suppliedMissing,'INCOMPLETE_MISSING_VECTOR_CORPUS_REVIEW');
  snapshots.secureshop_agents.vector_corpora.sort((a,b)=>a.corpus.localeCompare(b.corpus));
  return {missing,references};
}

module.exports={CORPORA,IDENTITY_TABLES,TABLES,mapSecureShopArchive};
