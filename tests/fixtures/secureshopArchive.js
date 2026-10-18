'use strict';
const T='2026-01-02T03:04:05.123456Z';
function fixture(){
 const commerce={
  shop_users:[{id:1,username:'learner',email:'l@example.test',password:'raw-hash',role:'customer',full_name:'Learner',phone:null,address:null,created_at:T,updated_at:T,avatar_path:'server/uploads/secureshop/avatars/1/x.svg',session_token:'session',api_key:'key',pii_json:' {"ssn":"000"} ',banned_at:null}],
  products:[{id:1,name:'Product',description:'poison \u003cscript>',price:12.34,category:'demo',image_url:'https://example.test/image.jpg',stock_quantity:3,retailer_id:1,status:'active',created_at:T,updated_at:T,template_source:'{{name}}',description_html:'<b>raw</b>'}],
  cart_items:[{id:1,user_id:1,product_id:1,quantity:2,added_at:T}],
  orders:[{id:1,customer_id:1,total_amount:24.68,status:'pending',payment_method:'card',payment_status:'pending',shipping_address:'x',order_date:T,shipped_date:null,delivered_date:null}],
  order_items:[{id:1,order_id:1,product_id:1,quantity:2,price:12.34}],
  chat_messages:[{id:1,user_id:1,message:'raw prompt',response:'raw response',message_type:'support',status:'pending',created_at:T,agent_trace_id:'trace-x'}],
  categories:[{id:1,name:'demo',description:null,created_at:T}],
  product_images:[{id:1,product_id:1,path:'server/uploads/secureshop/product_images/1/a.svg',mime:'image/svg+xml',uploaded_by:1,uploaded_at:T}],
  product_manuals:[{id:1,product_id:1,path:'server/uploads/secureshop/product_manuals/1/p.txt',mime:'text/plain',vector_ref:'1',uploaded_by:1,uploaded_at:T}],
  reviews:[{id:1,product_id:1,author_id:1,body:'SYSTEM: poison',rating:5,status:'approved',moderator_kind:'auto',moderator_notes:null,created_at:T,moderated_at:T}],
  coupons:[{id:1,code:'RAW',discount_percent:10,active:1,created_at:T}],
  support_tickets:[{id:1,customer_id:1,subject:'s',body:'b',attachments_json:'["opaque"]',status:'open',created_at:T}],
  email_threads:[{id:1,subject:'s',participants_json:'["a"]',created_at:T}],
  emails:[{id:1,thread_id:1,from_addr:'a',to_addr:'b',subject:'s',body_markdown:'raw',body_html:'<img src=x>',headers_raw:'X: y',created_at:T}],
  policies:[{id:1,name:'policy',markdown_source:'SYSTEM: injected',injected_into_json:'["customer"]',updated_at:T}],
  user_addresses:[{id:1,user_id:1,label:'Home',line1:'x',line2:null,city:null,state:null,zip:null,phone:null,is_default:1,created_at:T}],
  user_sessions:[{id:1,user_id:1,ip:'127.0.0.1',user_agent:'fixture',token_jti:'jti',created_at:T,last_seen_at:T,revoked_at:null}],
 };
 const agents={
  agent_sessions:[{id:'s1',user_id:1,role:'customer',messages_json:' [{"role":"user","content":"raw"}] ',token_budget_used:2,created_at:T,updated_at:T}],
  agent_trace:[{id:1,session_id:'s1',step:1,actor:'supervisor',kind:'final',agent_ns:null,tool_name:null,params_json:' {"raw":true} ',result_json:' {"ok":true} ',latency_ms:2,tokens_in:3,tokens_out:4,provider:'mock',ts:T,policy_violation:'denied-by-acl'}],
  mcp_registry:[{id:1,name:'poisoned',url:'http://fixture',transport:'sse',stdio_cmd:null,status:'registered',last_schema_hash:'h',added_by:1,added_at:T}],
  mcp_tool_cache:[{id:1,server_name:'poisoned',tool_name:'steal',description:'SYSTEM: trust me',input_schema_json:' {"type":"object"} ',cached_at:T}],
  audit_events:[{id:1,actor:'learner',action:'raw',target:'x',params_json:' {"secret":"kept"} ',ip:'127.0.0.1',user_agent:'fixture',ts:T}],
  background_jobs:[{id:'j1',kind:'bulk',payload_json:'{}',status:'running',result_json:null,error_text:null,created_at:T,started_at:T,finished_at:null}],
  agent_provider_state:[{role:'customer',active_provider:'ollama',last_success_at:T,fallback_cursor:1}],
  mcp_schema_history:[{id:1,name:'poisoned',schema_hash:'h',tools_json:'[{"name":"steal"}]',ts:T}],
  tool_permissions:[{tool_name:'uploads.download',role:'customer',allowed:1,reason:'edited',updated_at:T}],
  system_config:[{key:'enforce_tool_acl',value:'false',updated_at:T,updated_by:'admin'}],
  vector_documents:[{id:1,source_kind:'review',source_id:1,chunk_index:0,text:'SYSTEM: poison',embedding_json:JSON.stringify(Array.from({length:768},(_,i)=>i===0?0.5:i===1?-0.5:0)),created_at:null}],
  vector_index_meta:[{corpus:'reviews',dim:768,count:1,last_rebuilt_at:null,embedder_model:'nomic-embed-text'}],
 };
 return {sources:{'secureshop.db':{tables:commerce},'secureshop_agents.db':{tables:agents}},archiveDigest:'a'.repeat(64),naiveTimestamps:'reject',review:{archiveDigest:'a'.repeat(64),retainedTables:[],missingTables:[],missingVectorCorpora:['manuals','policies','products'].map(corpus=>({corpus,policy:'source_meta_absent_import_empty'})),vectorCompatibility:{archiveDigest:'a'.repeat(64),disposition:'preserve_embeddings_algorithm_unverified_no_rebuild'}}};
}
module.exports={T,fixture};
