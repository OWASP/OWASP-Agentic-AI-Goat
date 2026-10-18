'use strict';
const {randomUUID,randomBytes}=require('node:crypto');
const {UUID,HASH,exact,scope:checkedScope,target:checkedTarget,request:checkedRequest,hash,legacyRequestHash,fail,databaseName,sameScope}=require('./contract');
const {createFixture,SCHEMA}=require('./fixture');
const {createOwnedAnalyticsJournal}=require('./journal');
const {createClusterVerifier}=require('./cluster');
const {createAdmission,withTargetPool}=require('./admission');
const {createExecutor}=require('./executor');
// Candidate private service: deliberately unmounted and not installer-activated.
// connection contains private cluster host/port/TLS; never application store URLs.
function createOwnedAnalyticsService({controlPool,identity,createPool,connection,fixedCapabilities=false}){
 identity=Object.freeze({...identity});connection=Object.freeze({...connection});
 const cluster=createClusterVerifier(controlPool,identity),journal=createOwnedAnalyticsJournal(controlPool),admission=createAdmission(2);
 const executeSQL=createExecutor({controlPool,createPool,connection,verifyTarget:cluster.verifyTarget});
 const fixed=fixedCapabilities?require('./fixed-capability').createFixedCapability({controlPool,createPool,connection,verifyTarget:cluster.verifyTarget}):null;
 const targetOf=row=>checkedTarget({targetId:row.targetId,scope:row.scope,sourceManifestSha256:row.sourceManifestSha256});
 async function locked(scope,work,options){return admission.run(async()=>{await cluster.verify();return journal.withLock(scope,work);},options);}
 async function ready(scope){const row=await journal.get(scope);if(row?.state!=='ready')throw fail('ANALYTICS_TARGET_UNAVAILABLE');return targetOf(row);}
 return Object.freeze({schema:SCHEMA,
  async resolve(input,options){const scope=checkedScope(input);return locked(scope,()=>ready(scope),options);},
  async provision(input,options){const scope=checkedScope(input);return locked(scope,async()=>{
   const prior=await journal.get(scope);if(prior?.state==='ready')return targetOf(prior);if(prior)throw fail('ANALYTICS_TARGET_UNAVAILABLE');
   const fixture=createFixture(),target=checkedTarget({targetId:randomUUID(),scope,sourceManifestSha256:fixture.sourceManifestSha256});
   await journal.begin(scope,target);const name=databaseName(target.targetId),password=randomBytes(32).toString('hex');await journal.saveCredential(target.targetId,password);
   // Identifiers are generated UUID hex; password is generated hex, never input.
   await controlPool.query(`CREATE ROLE ${name} LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 1`);
   await controlPool.query(`CREATE DATABASE ${name} TEMPLATE template0 ALLOW_CONNECTIONS false`);
   await controlPool.query(`REVOKE ALL ON DATABASE ${name} FROM PUBLIC`);
   await controlPool.query(`GRANT CONNECT ON DATABASE ${name} TO ${name}`);
   await controlPool.query(`ALTER DATABASE ${name} ALLOW_CONNECTIONS true`);
   await withTargetPool(createPool,{...connection,database:name},async pool=>{
    const client=await pool.connect();try{
     const actual=(await client.query("SELECT current_database() AS database,current_setting('cluster_name') AS cluster,(SELECT system_identifier::text FROM pg_control_system()) AS system_identifier")).rows[0];
     if(actual?.database!==name||actual.cluster!==identity.clusterName||actual.system_identifier!==identity.systemIdentifier)throw fail('ANALYTICS_CLUSTER_MISMATCH');
     await client.query('BEGIN');await client.query('REVOKE ALL ON SCHEMA public FROM PUBLIC');
     for(const definition of SCHEMA.split('; ')){const table=definition.slice(0,definition.indexOf('('));await client.query(`CREATE TABLE public.${definition}`);
      for(const row of fixture.rows[table])await client.query(`INSERT INTO public.${table} VALUES(${row.map((_,i)=>'$'+(i+1)).join(',')})`,row);
     }
     await client.query(`GRANT USAGE ON SCHEMA public TO ${name}`);await client.query(`GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${name}`);await client.query('COMMIT');
    }finally{client.release(true);}
   });
   await cluster.verify();await journal.transition(scope,'pending','ready');return target;
  },options);},
  async prepareFixed(input,options){if(!fixed)throw fail('ANALYTICS_FIXED_CAPABILITY_UNAVAILABLE');const scope=checkedScope(input);return locked(scope,async()=>{const target=await ready(scope);await journal.withClient(client=>fixed.prepare(client,target));return target;},options);},
  async topProducts(input,limit,options){
   const scope=checkedScope(input);if(!Number.isSafeInteger(limit)||limit<1||limit>25)throw fail('ANALYTICS_TARGET_INVALID');
   return locked(scope,async()=>{const target=await ready(scope),password=await journal.credential(target.targetId);
    if(!/^[a-f0-9]{64}$/.test(password||''))throw fail('ANALYTICS_TARGET_UNAVAILABLE');
    const sql=`SELECT p.id,p.name,COALESCE(SUM(i.quantity*i.price),0) AS revenue FROM products p LEFT JOIN order_items i ON i.product_id=p.id GROUP BY p.id,p.name ORDER BY revenue DESC,p.id LIMIT ${limit}`;
    let result;try{result=await executeSQL(target,password,sql,{signal:options?.signal?AbortSignal.any([options.signal,journal.signal()]):journal.signal()});}catch(error){if(['ANALYTICS_QUERY_DRAIN_UNCERTAIN','ANALYTICS_POOL_DRAIN_UNCERTAIN'].includes(error.code))await journal.transition(scope,'ready','retiring');throw error;}
    return {targetId:target.targetId,scope:target.scope,sourceManifestSha256:target.sourceManifestSha256,rows:result.rows};
   },options);
  },
  async execute(input,options){const request=checkedRequest(input);return locked(request.target.scope,async()=>{
   const target=await ready(request.target.scope);
   if(target.targetId!==request.target.targetId||target.sourceManifestSha256!==request.target.sourceManifestSha256||!sameScope(target.scope,request.target.scope))throw fail('ANALYTICS_TARGET_INVALID');
   const digest=hash(request),prior=await journal.readQuery(target.targetId,request.operationId);
   if(prior){if(prior.request_sha256!==digest&&prior.request_sha256!==legacyRequestHash(request))throw fail('ANALYTICS_QUERY_CONFLICT');if(prior.state!=='completed')throw fail('ANALYTICS_QUERY_UNCERTAIN');return prior.receipt;}
   let password=await journal.credential(target.targetId),loginRole;
   if(request.mode?.mode==='fixed'){if(!fixed)throw fail('ANALYTICS_FIXED_CAPABILITY_UNAVAILABLE');const credential=await journal.withClient(client=>fixed.credential(client,target));password=credential.password;loginRole=credential.user;}
   if(!/^[a-f0-9]{64}$/.test(password||''))throw fail('ANALYTICS_TARGET_UNAVAILABLE');
   await journal.admitQuery(target.targetId,request.operationId,digest);
   let result,protectedEvidence,denial;try{({result,protectedEvidence,denial}=await executeSQL(target,password,request.sql,{captureProtected:true,loginRole,signal:options?.signal?AbortSignal.any([options.signal,journal.signal()]):journal.signal()}));}catch(error){
    if(['ANALYTICS_QUERY_DRAIN_UNCERTAIN','ANALYTICS_POOL_DRAIN_UNCERTAIN'].includes(error.code))await journal.transition(target.scope,'ready','retiring');
    throw error;
   }
   const receipt={version:denial?4:request.mode?3:2,...(denial?{denial}:{}),...(request.mode?{mode:request.mode}:{}),protectedEvidence,operationId:request.operationId,targetId:target.targetId,scope:target.scope,runId:request.runId,requestId:request.requestId,sessionId:request.sessionId,callId:request.callId,sqlSha256:hash(request.sql),sourceManifestSha256:target.sourceManifestSha256,resultSha256:hash(result),result};
   await journal.completeQuery(target.targetId,request.operationId,receipt);return receipt;
  },options);},
  async lookupCoupon(input,options){
   const contract=require('../../server/services/secureshopCouponContract'),request=contract.lookup(input);
   return locked(request.scope,async()=>{
    const target=await ready(request.scope),digest=hash({kind:'coupon-v1',request}),prior=await journal.readQuery(target.targetId,request.operationId);
    if(prior){if(prior.request_sha256!==digest)throw fail('ANALYTICS_QUERY_CONFLICT');if(prior.state!=='completed')throw fail('ANALYTICS_QUERY_UNCERTAIN');if(prior.result_sha256!==hash(prior.receipt?.result))throw fail('ANALYTICS_QUERY_CONFLICT');return prior.receipt;}
    const password=await journal.credential(target.targetId);if(!/^[a-f0-9]{64}$/.test(password||''))throw fail('ANALYTICS_TARGET_UNAVAILABLE');
    const query=contract.statement(request);await journal.admitQuery(target.targetId,request.operationId,digest);
    let output;try{output=await executeSQL(target,password,query.text,{values:query.values,signal:options?.signal?AbortSignal.any([options.signal,journal.signal()]):journal.signal()});}
    catch(error){if(['ANALYTICS_QUERY_DRAIN_UNCERTAIN','ANALYTICS_POOL_DRAIN_UNCERTAIN'].includes(error.code))await journal.transition(target.scope,'ready','retiring');throw error;}
    const result={coupon:contract.selected(output.rows,request.coupons)},receipt={version:1,kind:'coupon',operationId:request.operationId,requestSha256:digest,targetId:target.targetId,scope:target.scope,sourceManifestSha256:target.sourceManifestSha256,resultSha256:hash(result),result};
   await journal.completeQuery(target.targetId,request.operationId,receipt);return receipt;
   },options);
  },
  async readCouponReceipt(input,options){
   exact(input,['scope','targetId','operationId','requestSha256']);
   const request=Object.freeze({scope:checkedScope(input.scope),targetId:input.targetId,
    operationId:input.operationId,requestSha256:input.requestSha256});
   if(!UUID.test(request.targetId)||!UUID.test(request.operationId)||!HASH.test(request.requestSha256))throw fail('ANALYTICS_TARGET_INVALID');
   return locked(request.scope,async()=>{
    const target=await ready(request.scope);
    if(target.targetId!==request.targetId||!sameScope(target.scope,request.scope))throw fail('ANALYTICS_TARGET_INVALID');
    const prior=await journal.readQuery(target.targetId,request.operationId);
    if(!prior)return null;
    if(prior.request_sha256!==request.requestSha256)throw fail('ANALYTICS_QUERY_CONFLICT');
    if(prior.state==='pending'||prior.state==='redacted')return null;
    if(prior.state!=='completed')throw fail('ANALYTICS_QUERY_CONFLICT');
    const receipt=prior.receipt;
    try{
     exact(receipt,['version','kind','operationId','requestSha256','targetId','scope','sourceManifestSha256','resultSha256','result']);
     checkedScope(receipt.scope);
     exact(receipt.result,['coupon']);
     if(receipt.result.coupon!==null)require('../../server/services/secureshopCouponContract').coupon(receipt.result.coupon);
    }catch{throw fail('ANALYTICS_QUERY_CONFLICT');}
    if(receipt.version!==1||receipt.kind!=='coupon'||receipt.operationId!==request.operationId
     ||receipt.requestSha256!==request.requestSha256||receipt.targetId!==target.targetId
     ||!sameScope(receipt.scope,target.scope)||receipt.sourceManifestSha256!==target.sourceManifestSha256
     ||receipt.resultSha256!==prior.result_sha256||receipt.resultSha256!==hash(receipt.result))throw fail('ANALYTICS_QUERY_CONFLICT');
    return receipt;
   },options);
  },
  async lookupCouponProbe(input,options){
   const probe=require('../../server/services/secureshopCouponProbeContract'),request=probe.request(input);
   return locked(request.lookup.scope,async()=>{
    const target=await ready(request.lookup.scope),requestSha256=hash(request),prior=await journal.readQuery(target.targetId,request.lookup.operationId);
    if(prior){
     if(prior.request_sha256!==requestSha256)throw fail('ANALYTICS_QUERY_CONFLICT');
     if(prior.state!=='completed')throw fail('ANALYTICS_QUERY_UNCERTAIN');
     const saved=probe.receipt(prior.receipt,request);
     if(saved.targetId!==target.targetId||!sameScope(saved.scope,target.scope)
      ||saved.sourceManifestSha256!==target.sourceManifestSha256
      ||saved.resultSha256!==prior.result_sha256)throw fail('ANALYTICS_QUERY_CONFLICT');
     return saved;
    }
    const password=await journal.credential(target.targetId);if(!/^[a-f0-9]{64}$/.test(password||''))throw fail('ANALYTICS_TARGET_UNAVAILABLE');
    const query=probe.statement(request);await journal.admitQuery(target.targetId,request.lookup.operationId,requestSha256);
    let output;try{output=await executeSQL(target,password,query.text,{values:query.values,signal:options?.signal?AbortSignal.any([options.signal,journal.signal()]):journal.signal()});}
    catch(error){if(['ANALYTICS_QUERY_DRAIN_UNCERTAIN','ANALYTICS_POOL_DRAIN_UNCERTAIN'].includes(error.code))await journal.transition(target.scope,'ready','retiring');throw error;}
    let value;try{value={coupon:require('../../server/services/secureshopCouponContract').selected(output.rows,request.lookup.coupons)};}catch(error){throw error;}
    const saved=probe.buildReceipt({target,request,result:value});
    await journal.completeQuery(target.targetId,request.lookup.operationId,saved);return saved;
   },options);
  },
  async readCouponProbeReceipt(input,options){
   const probe=require('../../server/services/secureshopCouponProbeContract'),request=probe.readRequest(input);
   return locked(request.scope,async()=>{
    const target=await ready(request.scope);
    if(target.targetId!==request.targetId||!sameScope(target.scope,request.scope))throw fail('ANALYTICS_TARGET_INVALID');
    const prior=await journal.readQuery(target.targetId,request.operationId);
    if(!prior||prior.state==='pending'||prior.state==='redacted')return null;
    if(prior.request_sha256!==request.requestSha256||prior.state!=='completed')throw fail('ANALYTICS_QUERY_CONFLICT');
    const saved=probe.storedReceipt(prior.receipt);
    if(saved.operationId!==request.operationId||saved.requestSha256!==request.requestSha256||saved.targetId!==target.targetId
     ||!sameScope(saved.scope,target.scope)||saved.sourceManifestSha256!==target.sourceManifestSha256||saved.resultSha256!==prior.result_sha256)throw fail('ANALYTICS_QUERY_CONFLICT');
    return saved;
   },options);
  },
  async readCouponProbeReference(input,options){
   const probe=require('../../server/services/secureshopCouponProbeContract'),request=probe.referenceRequest(input);
   return locked(request.scope,async()=>{
    const target=await ready(request.scope);
    if(target.targetId!==request.targetId||!sameScope(target.scope,request.scope))throw fail('ANALYTICS_TARGET_INVALID');
    const prior=await journal.readQuery(target.targetId,request.operationId);
    if(!prior||prior.state!=='completed'||prior.request_sha256!==request.requestSha256)throw fail('ANALYTICS_QUERY_CONFLICT');
    const saved=probe.storedReceipt(prior.receipt);
    if(saved.operationId!==request.operationId||saved.requestSha256!==request.requestSha256||saved.targetId!==target.targetId
     ||!sameScope(saved.scope,target.scope)||saved.sourceManifestSha256!==target.sourceManifestSha256||saved.resultSha256!==prior.result_sha256)throw fail('ANALYTICS_QUERY_CONFLICT');
    const password=await journal.credential(target.targetId);if(!/^[a-f0-9]{64}$/.test(password||''))throw fail('ANALYTICS_TARGET_UNAVAILABLE');
    // The subject identity is fixed by this private reference contract; only the
    // bounded character position is a query parameter.  The shared executor
    // intentionally admits at most two untrusted values.
    const query="SELECT id,password,substring(password FROM $1::integer FOR 1) AS character FROM shop_users WHERE id=1 AND username='synthetic_admin' AND role='admin' ORDER BY id LIMIT 2";
    let output;try{output=await executeSQL(target,password,query,{values:[String(request.position)],signal:options?.signal?AbortSignal.any([options.signal,journal.signal()]):journal.signal()});}
    catch(error){if(['ANALYTICS_QUERY_DRAIN_UNCERTAIN','ANALYTICS_POOL_DRAIN_UNCERTAIN'].includes(error.code))await journal.transition(target.scope,'ready','retiring');throw error;}
    const row=output?.rows?.[0];
    if(!Array.isArray(output?.rows)||output.rows.length!==1||!row||row.id!==1
     ||typeof row.password!=='string'||!/^[a-f0-9]{64}$/.test(row.password)
     ||request.position>64||typeof row.character!=='string'||row.character.length!==1
     ||row.character!==row.password[request.position-1])throw fail('ANALYTICS_PROBE_REFERENCE_UNAVAILABLE');
    return Object.freeze({version:1,targetId:target.targetId,operationId:request.operationId,requestSha256:request.requestSha256,position:request.position,rowId:1,character:row.character,characterSha256:hash(row.character)});
   },options);
  },
  async searchProducts(input,options){
   const contract=require('../../server/services/secureshopProductSearchSqlContract'),request=contract.request(input);
   return locked(request.search.scope,async()=>{
    const target=await ready(request.search.scope),requestSha256=hash(request),prior=await journal.readQuery(target.targetId,request.search.operationId);
    if(prior){
     if(prior.request_sha256!==requestSha256)throw fail('ANALYTICS_QUERY_CONFLICT');
     if(prior.state!=='completed')throw fail('ANALYTICS_QUERY_UNCERTAIN');
     const saved=contract.receipt(prior.receipt,request);
     if(saved.targetId!==target.targetId||saved.sourceManifestSha256!==target.sourceManifestSha256
      ||saved.resultSha256!==prior.result_sha256)throw fail('ANALYTICS_QUERY_CONFLICT');
     return saved;
    }
    const password=await journal.credential(target.targetId);if(!/^[a-f0-9]{64}$/.test(password||''))throw fail('ANALYTICS_TARGET_UNAVAILABLE');
    const query=contract.statement(request);await journal.admitQuery(target.targetId,request.search.operationId,requestSha256);
    let output;try{output=await executeSQL(target,password,query.text,{values:query.values,signal:options?.signal?AbortSignal.any([options.signal,journal.signal()]):journal.signal()});}
    catch(error){if(['ANALYTICS_QUERY_DRAIN_UNCERTAIN','ANALYTICS_POOL_DRAIN_UNCERTAIN'].includes(error.code))await journal.transition(target.scope,'ready','retiring');throw error;}
    // Preserve every returned SQL row before the legacy business filter pass.
    // An excessive result fails unavailable; it is never silently truncated.
    const saved=contract.buildReceipt({target,request,result:{rows:output.rows,row_count:output.row_count}});
    await journal.completeQuery(target.targetId,request.search.operationId,saved);return saved;
   },options);
  },
  async readProductSearchReceipt(input,options){
   const contract=require('../../server/services/secureshopProductSearchSqlContract'),request=contract.readRequest(input);
   return locked(request.scope,async()=>{
    const target=await ready(request.scope);
    if(target.targetId!==request.targetId)throw fail('ANALYTICS_TARGET_INVALID');
    const prior=await journal.readQuery(target.targetId,request.operationId);
    if(!prior||prior.state==='pending'||prior.state==='redacted')return null;
    if(prior.request_sha256!==request.requestSha256||prior.state!=='completed')throw fail('ANALYTICS_QUERY_CONFLICT');
    const saved=contract.storedReceipt(prior.receipt);
    if(saved.operationId!==request.operationId||saved.requestSha256!==request.requestSha256||saved.targetId!==target.targetId
     ||!sameScope(saved.scope,target.scope)||saved.sourceManifestSha256!==target.sourceManifestSha256||saved.resultSha256!==prior.result_sha256)throw fail('ANALYTICS_QUERY_CONFLICT');
    return saved;
   },options);
  },
  async readProductSearchReference(input,options){
   const contract=require('../../server/services/secureshopProductSearchSqlContract'),request=contract.referenceRequest(input);
   return locked(request.scope,async()=>{
    const target=await ready(request.scope);
    if(target.targetId!==request.targetId)throw fail('ANALYTICS_TARGET_INVALID');
    const prior=await journal.readQuery(target.targetId,request.operationId);
    if(!prior||prior.state!=='completed'||prior.request_sha256!==request.requestSha256)throw fail('ANALYTICS_QUERY_CONFLICT');
    const saved=contract.storedReceipt(prior.receipt);
    if(saved.operationId!==request.operationId||saved.requestSha256!==request.requestSha256||saved.targetId!==target.targetId
     ||!sameScope(saved.scope,target.scope)||saved.sourceManifestSha256!==target.sourceManifestSha256||saved.resultSha256!==prior.result_sha256)throw fail('ANALYTICS_QUERY_CONFLICT');
    const password=await journal.credential(target.targetId);if(!/^[a-f0-9]{64}$/.test(password||''))throw fail('ANALYTICS_TARGET_UNAVAILABLE');
    // Private evidence-only read: neither caller nor model selects table, field,
    // subject or SQL. The current owned target and completed receipt are required.
    const query="SELECT id,api_key FROM shop_users WHERE id=1 AND username='synthetic_admin' AND role='admin' ORDER BY id LIMIT 2";
    let output;try{output=await executeSQL(target,password,query,{signal:options?.signal?AbortSignal.any([options.signal,journal.signal()]):journal.signal()});}
    catch(error){if(['ANALYTICS_QUERY_DRAIN_UNCERTAIN','ANALYTICS_POOL_DRAIN_UNCERTAIN'].includes(error.code))await journal.transition(target.scope,'ready','retiring');throw error;}
    const row=output?.rows?.[0];
    if(output?.rows?.length!==1||row?.id!==1||typeof row.api_key!=='string'||!/^SYNTHETIC_KEY_[a-f0-9]{48}$/.test(row.api_key))throw fail('ANALYTICS_PRODUCT_REFERENCE_UNAVAILABLE');
    return Object.freeze({version:1,targetId:target.targetId,operationId:request.operationId,requestSha256:request.requestSha256,
     sourceManifestSha256:target.sourceManifestSha256,rowId:1,field:'api_key',value:row.api_key,valueSha256:hash(row.api_key)});
   },options);
  },
  async lookupOrderStatus(input,options){
   const contract=require('../../server/services/secureshopOrderStatusSqlContract'),request=contract.request(input);
   return locked(request.lookup.scope,async()=>{
    const target=await ready(request.lookup.scope),requestSha256=hash(request),prior=await journal.readQuery(target.targetId,request.lookup.operationId);
    if(prior){
     if(prior.request_sha256!==requestSha256)throw fail('ANALYTICS_QUERY_CONFLICT');
     if(prior.state!=='completed')throw fail('ANALYTICS_QUERY_UNCERTAIN');
     const saved=contract.receipt(prior.receipt,request);
     if(saved.targetId!==target.targetId||saved.sourceManifestSha256!==target.sourceManifestSha256
      ||saved.resultSha256!==prior.result_sha256)throw fail('ANALYTICS_QUERY_CONFLICT');
     return saved;
    }
    const password=await journal.credential(target.targetId);if(!/^[a-f0-9]{64}$/.test(password||''))throw fail('ANALYTICS_TARGET_UNAVAILABLE');
    const query=contract.statement(request);await journal.admitQuery(target.targetId,request.lookup.operationId,requestSha256);
    let output;try{output=await executeSQL(target,password,query.text,{values:query.values,captureQueryError:true,signal:options?.signal?AbortSignal.any([options.signal,journal.signal()]):journal.signal()});}
    catch(error){if(['ANALYTICS_QUERY_DRAIN_UNCERTAIN','ANALYTICS_POOL_DRAIN_UNCERTAIN'].includes(error.code))await journal.transition(target.scope,'ready','retiring');throw error;}
    const result=output.queryError?{kind:'postgres-error',...output.queryError}:{kind:'rows',rows:output.rows,row_count:output.row_count};
    const saved=contract.buildReceipt({target,request,result});
    await journal.completeQuery(target.targetId,request.lookup.operationId,saved);return saved;
   },options);
  },
  async readOrderStatusReceipt(input,options){
   const contract=require('../../server/services/secureshopOrderStatusSqlContract'),request=contract.readRequest(input);
   return locked(request.scope,async()=>{
    const target=await ready(request.scope);
    if(target.targetId!==request.targetId)throw fail('ANALYTICS_TARGET_INVALID');
    const prior=await journal.readQuery(target.targetId,request.operationId);
    if(!prior||prior.state==='pending'||prior.state==='redacted')return null;
    if(prior.request_sha256!==request.requestSha256||prior.state!=='completed')throw fail('ANALYTICS_QUERY_CONFLICT');
    const saved=contract.storedReceipt(prior.receipt);
    if(saved.operationId!==request.operationId||saved.requestSha256!==request.requestSha256||saved.targetId!==target.targetId
     ||!sameScope(saved.scope,target.scope)||saved.sourceManifestSha256!==target.sourceManifestSha256||saved.resultSha256!==prior.result_sha256)throw fail('ANALYTICS_QUERY_CONFLICT');
    return saved;
   },options);
  },
  async readOrderStatusReference(input,options){
   const contract=require('../../server/services/secureshopOrderStatusSqlContract'),request=contract.referenceRequest(input);
   return locked(request.scope,async()=>{
    const target=await ready(request.scope);
    if(target.targetId!==request.targetId)throw fail('ANALYTICS_TARGET_INVALID');
    const prior=await journal.readQuery(target.targetId,request.operationId);
    if(!prior||prior.state!=='completed'||prior.request_sha256!==request.requestSha256)throw fail('ANALYTICS_QUERY_CONFLICT');
    const saved=contract.storedReceipt(prior.receipt);
    if(saved.operationId!==request.operationId||saved.requestSha256!==request.requestSha256||saved.targetId!==target.targetId
     ||!sameScope(saved.scope,target.scope)||saved.sourceManifestSha256!==target.sourceManifestSha256||saved.resultSha256!==prior.result_sha256)throw fail('ANALYTICS_QUERY_CONFLICT');
    const password=await journal.credential(target.targetId);if(!/^[a-f0-9]{64}$/.test(password||''))throw fail('ANALYTICS_TARGET_UNAVAILABLE');
    const query="SELECT id,api_key FROM shop_users WHERE id=1 AND username='synthetic_admin' AND role='admin' ORDER BY id LIMIT 2";
    let output;try{output=await executeSQL(target,password,query,{signal:options?.signal?AbortSignal.any([options.signal,journal.signal()]):journal.signal()});}
    catch(error){if(['ANALYTICS_QUERY_DRAIN_UNCERTAIN','ANALYTICS_POOL_DRAIN_UNCERTAIN'].includes(error.code))await journal.transition(target.scope,'ready','retiring');throw error;}
    const row=output?.rows?.[0];
    if(output?.rows?.length!==1||row?.id!==1||typeof row.api_key!=='string'||!/^SYNTHETIC_KEY_[a-f0-9]{48}$/.test(row.api_key))throw fail('ANALYTICS_ORDER_REFERENCE_UNAVAILABLE');
    return Object.freeze({version:1,targetId:target.targetId,operationId:request.operationId,requestSha256:request.requestSha256,
     sourceManifestSha256:target.sourceManifestSha256,rowId:1,field:'api_key',value:row.api_key,valueSha256:hash(row.api_key)});
   },options);
  },
  async retire(input,options){const scope=checkedScope(input);return locked(scope,async()=>{
   let row=await journal.get(scope);
   if(!row){const target={targetId:randomUUID(),scope,sourceManifestSha256:hash({retirementOnly:true,scope})};await journal.begin(scope,target);row={...target,state:'pending'};}
   if(row.state==='retired')return {retired:true,targetId:row.targetId};
   if(row.state!=='retiring')await journal.transition(scope,row.state,'retiring');
   const name=databaseName(row.targetId);
   if(fixed)await journal.withClient(client=>fixed.disable(client,row));
   const role=(await controlPool.query('SELECT 1 FROM pg_roles WHERE rolname=$1',[name])).rows.length;
   if(role)await controlPool.query(`ALTER ROLE ${name} NOLOGIN`);
   await controlPool.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
   if(role)await controlPool.query(`DROP ROLE ${name}`);
   if(fixed)await journal.withClient(client=>fixed.retire(client,row));
   await journal.eraseCredential(row.targetId);await journal.transition(scope,'retiring','retired');await journal.redact(row.targetId);
   return {retired:true,targetId:row.targetId};
  },options);},
 });
}
module.exports={createOwnedAnalyticsService};
