'use strict';

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');

const sha256 = value => createHash('sha256').update(value).digest('hex');
const RECEIPT_PATH = '/uploads/product-manual/receipt';
const {createLaunchScope} = require('../../server/services/secureshopConversationBinding');
const {executionScope} = require('../../server/services/secureshopSceneBinding');
const {isDeepStrictEqual:equal} = require('node:util');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function assertUploaderActor({spans,calls,productId,filename,fileBytes,fileSha256,upload,manualRows,model,actorCap}) {
  assert.ok(Number.isSafeInteger(productId)&&productId>0);
  assert.ok(Number.isSafeInteger(fileBytes)&&fileBytes>0);
  assert.match(fileSha256,/^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(actorCap)&&actorCap>=2);
  assert.ok(Array.isArray(calls)&&calls.length>=2&&calls.length<=actorCap);
  assert.equal(spans?.length,2);
  assert.equal(spans[0].method,'chat');assert.equal(spans[1].method,'finalResponse');
  const config=require('../../server/services/secureshopManualExecutionConfig').createSecureShopManualExecutionConfig();
  const expectedTask=`Store and index this manual for product ${productId}. File metadata: ${JSON.stringify({
    filename,mime:'text/plain',bytes:fileBytes,sha256:fileSha256})}`;
  let next=0;
  for(let index=0;index<2;index++){
    const span=spans[index],wires=span.wires;
    assert.ok(Array.isArray(wires)&&wires.length>=1&&wires.length<=2,
      'Only the configured single provider correction is admitted');
    assert.equal(span.result?.provider,'ollama');assert.equal(span.result.model,model);
    assert.equal(span.result.mocked,false);
    const requests=[],generated=[];
    for(let attempt=0;attempt<wires.length;attempt++){
      const wire=calls[next];
      assert.ok(equal(wires[attempt],wire),'Uploader span must own the next exact physical wire');
      assert.equal(wire.index,next+1);assert.equal(wire.kind,'actor');assert.equal(wire.model,model);
      assert.equal(wire.status,200);assert.equal(wire.responseComplete,true);
      assert.equal(wire.responseCaptureTruncated,false);assert.equal(wire.terminalReason,'end');
      assert.equal(wire.requestBytes,Buffer.byteLength(wire.request));
      assert.equal(wire.requestSha256,sha256(wire.request));
      assert.equal(wire.responseBytes,Buffer.byteLength(wire.response));
      assert.equal(wire.responseObservedBytes,wire.responseBytes);
      assert.equal(wire.responseSha256,sha256(wire.response));
      const frames=wire.response.trimEnd().split('\n').map(line=>JSON.parse(line));
      assert.ok(frames.length>0&&frames.length<=256);
      assert.ok(frames.slice(0,-1).every(frame=>frame.done===false));
      assert.equal(frames.at(-1).done,true);
      assert.ok(frames.every(frame=>frame.model===model&&frame.message?.role==='assistant'));
      generated.push(frames.map(frame=>frame.message.content).join(''));
      const request=JSON.parse(wire.request);requests.push(request);
      assert.equal(request.model,model);assert.equal(request.stream,true);
      assert.ok(equal(request.format,index===0
        ?require('../../server/services/secureshop/providers/ollamaProvider')
          .closedDecisionSchema(config.manifest.getForRole('merchant'))
        :require('../../server/agent-runtime/providers/finalResponseContract').FINAL_RESPONSE_SCHEMA));
      assert.ok(request.messages?.[0]?.content?.startsWith(config.buildBasePrompt('merchant')));
      assert.equal(request.messages?.[1]?.role,'user');assert.equal(request.messages[1].content,expectedTask);
      assert.equal(request.options.num_ctx,8192);assert.equal(request.options.temperature,0);
      assert.ok(Number.isSafeInteger(request.options.num_predict)&&request.options.num_predict>0
        &&request.options.num_predict<=2048);
      next++;
    }
    const request=requests.at(-1),raw=generated.at(-1);
    if(wires.length===2){
      const prior=requests[0],correction=request.messages;
      assert.ok(equal(correction.slice(0,prior.messages.length),prior.messages));
      assert.equal(correction.length,prior.messages.length+2);
      assert.ok(equal(correction.at(-2),{role:'assistant',content:generated[0]}));
      assert.equal(correction.at(-1).role,'user');
      if(index===0){
        assert.equal(require('../../server/services/secureshop/providers/ollamaProvider').parseDecision(generated[0]),null);
        assert.equal(correction.at(-1).content,
          'The previous decision was not a valid single JSON object matching the requested schema. No tool was executed from that output. Return exactly one corrected decision, without commentary or additional objects.');
        assert.equal(prior.options.num_predict,2048);assert.equal(request.options.num_predict,2048);
      }else{
        assert.equal(require('../../server/agent-runtime/providers/finalResponseContract').parseFinalResponse(generated[0]),null);
        assert.equal(correction.at(-1).content,
          'The previous response did not match the required answer-only JSON schema. Return exactly one object with one nonempty answer string. Do not return a tool call or any other key.');
        const firstUsage=JSON.parse(wires[0].response.trimEnd().split('\n').at(-1)).eval_count;
        assert.ok(Number.isSafeInteger(firstUsage)&&firstUsage>=0&&firstUsage<2048);
        assert.equal(prior.options.num_predict,2048);
        assert.equal(request.options.num_predict,2048-firstUsage);
      }
    }else assert.equal(request.options.num_predict,2048);
    if(index===0){
      const schema=require('../../server/services/secureshop/providers/ollamaProvider')
        .closedDecisionSchema(config.manifest.getForRole('merchant'));
      assert.ok(equal(request.format,schema),'Uploader decision schema changed');
      assert.equal(request.messages.length,wires.length===2?4:2);
      const decision=require('../../server/services/secureshop/providers/ollamaProvider').parseDecision(raw);
      assert.ok(equal(decision,{tool_calls:[{agent:'uploads',tool:'upload_product_manual',
        args:{product_id:productId}}]}));
      assert.equal(span.result.stop_reason,'tool_use');assert.equal(span.result.tool_uses?.length,1);
      assert.equal(span.result.tool_uses[0].name,'uploads.upload_product_manual');
      assert.ok(equal(span.result.tool_uses[0].args,{product_id:productId}));
      assert.ok(typeof span.result.tool_uses[0].id==='string'&&span.result.tool_uses[0].id.length>0);
    }else{
      const schema=require('../../server/agent-runtime/providers/finalResponseContract').FINAL_RESPONSE_SCHEMA;
      assert.ok(equal(request.format,schema),'Uploader final schema changed');
      assert.ok(equal(request.messages.slice(0,4).map(message=>message.role),['system','user','assistant','user']));
      assert.equal(request.messages.length,wires.length===2?6:4);
      const selected=spans[0].result.tool_uses[0];
      assert.ok(equal(JSON.parse(request.messages[2].content),{tool_calls:[{
        id:selected.id,agent:'uploads',tool:'upload_product_manual',args:{product_id:productId}}]}));
      const observation=request.messages[3].content;
      assert.ok(observation.startsWith(`Tool observation for completed call ${JSON.stringify(selected.id)} (tool result):\n`));
      const observed=JSON.parse(observation.slice(observation.indexOf('\n')+1));
      const {provider,model:uploadModel,...effect}=upload;
      assert.equal(provider,'ollama');assert.equal(uploadModel,model);
      assert.ok(equal(observed,effect),'Uploader observation must match committed effect');
      assert.ok(equal(require('../../server/agent-runtime/providers/finalResponseContract')
        .parseFinalResponse(raw),{answer:span.result.text}));
      assert.equal(span.result.stop_reason,'end_turn');assert.equal(span.result.responseMode,'structured_final');
    }
  }
  assert.equal(next,calls.length,'Every physical actor call must belong to the uploader');
  assert.equal(upload?.kind,'product_manual');assert.equal(upload.ok,true);
  assert.equal(upload.scope_id,productId);assert.match(upload.operationId,UUID);
  assert.equal(upload.filename,filename);assert.equal(upload.size_bytes,fileBytes);
  assert.equal(manualRows?.length,1);
  const row=manualRows[0].row;
  assert.equal(row.operation_id,upload.operationId);assert.equal(row.product_id,productId);
  assert.equal(row.filename,filename);assert.equal(row.byte_count,fileBytes);
  assert.equal(row.file_sha256,`\\x${fileSha256}`);assert.equal(row.receipt_version,2);
  return Object.freeze({physicalActorCalls:calls.length,spanMethods:Object.freeze(['chat','finalResponse']),
    tool:'uploads.upload_product_manual',operationId:upload.operationId});
}

async function peerManualAuthority({personaAuthority,scope,actor}) {
  assert.equal(typeof personaAuthority?.capture,'function');
  assert.equal(actor?.user?.role,'merchant');
  assert.ok(Number.isSafeInteger(actor.user.id)&&actor.user.id>0);
  assert.match(actor.sessionId,UUID);
  assert.match(actor.authorityVersion,/^[1-9]\d*$/);
  const persona=Object.freeze({id:actor.user.id,role:'merchant'});
  const personaSession=Object.freeze({sessionId:actor.sessionId,authorityVersion:actor.authorityVersion});
  const fence=await personaAuthority.capture({scope,personaId:persona.id,role:persona.role,...personaSession});
  const personaEffect=require('../../server/services/secureshopPersonaProductEffect').createPersonaProductEffect(fence);
  await personaEffect.check(scope);
  return Object.freeze({persona,personaSession,personaEffect});
}

async function enterMerchantListingsWithAuthority({frame,requests,authorityByRequest,observed,merchantId,productId}) {
  assert.equal(typeof frame?.waitForSelector,'function');
  assert.equal(typeof frame?.click,'function');
  assert.ok(Array.isArray(requests));
  assert.equal(typeof authorityByRequest?.has,'function');
  assert.equal(typeof observed,'function');
  assert.ok(Number.isSafeInteger(merchantId)&&merchantId>0);
  assert.ok(Number.isSafeInteger(productId)&&productId>0);
  const link='a[href="/secureshop/merchant/listings"]';
  await frame.waitForSelector(link,{visible:true});
  await frame.click(link);
  const listing=await observed(()=>requests.find(row=>row.method==='GET'
    &&row.pathname==='/merchant/products'&&authorityByRequest.has(row)),
  'physical owned merchant product list authority',20000);
  assert.equal(listing?.status,200);assert.equal(listing.error,null);
  assert.equal(listing.query?.retailer_id,String(merchantId));
  const projection=JSON.parse(listing.response);
  assert.ok(Array.isArray(projection?.products));
  assert.ok(projection.products.some(row=>row.id===productId),'Physical listing must contain the owned product');
  const authority=authorityByRequest.get(listing);
  assert.ok(authority?.scope && authority.persona?.role==='merchant');
  assert.equal(authority.persona.id,merchantId);
  return {listing,authority};
}

// Read the already granted owner scene. A sibling setup must not provision or
// infer its comparison target from a later upload request.
async function assertDistinctOwnedTargets({scenes,setupScope,setupTarget,ownerScope,ownerTarget,peerScope,peerTarget}) {
  assert.equal(typeof scenes?.readRetained,'function');
  assert.ok(setupTarget?.scene,'Prelogout owner storage witness required');
  assert.ok(ownerTarget?.scene,'Owner scene must exist before sibling provisioning');
  const owner=await scenes.readRetained(ownerScope);
  assert.ok(owner?.scene,'Existing owner scene grant required before sibling write');
  assert.ok(peerTarget?.scene,'Existing sibling scene grant required before sibling write');
  const ownerLaunch=createLaunchScope(ownerScope),peerLaunch=createLaunchScope(peerScope);
  assert.deepEqual(createLaunchScope(executionScope(setupTarget)),createLaunchScope(setupScope));
  assert.deepEqual(createLaunchScope(executionScope(owner)),ownerLaunch);
  assert.deepEqual(createLaunchScope(executionScope(ownerTarget)),ownerLaunch);
  assert.deepEqual(createLaunchScope(executionScope(peerTarget)),peerLaunch);
  assert.deepEqual(createLaunchScope(ownerTarget),createLaunchScope(owner),
    'Retained owner target must preserve its storage birth');
  assert.deepEqual(createLaunchScope(ownerTarget),createLaunchScope(setupTarget),
    'Physical merchant launch must retain setup storage birth');
  assert.match(owner.targetId,UUID);assert.match(peerTarget.targetId,UUID);
  assert.equal(ownerTarget.targetId,owner.targetId,'Owner target must remain current during sibling setup');
  assert.equal(ownerTarget.targetId,setupTarget.targetId,'Physical merchant launch must retain setup target');
  assert.equal(ownerTarget.scene.sceneId,owner.scene.sceneId);
  assert.equal(ownerTarget.scene.sceneId,setupTarget.scene.sceneId);
  assert.notEqual(ownerLaunch.platformOwnerId,peerLaunch.platformOwnerId);
  assert.notEqual(ownerLaunch.launchId,peerLaunch.launchId);
  assert.notEqual(owner.targetId,peerTarget.targetId);
  return owner;
}

function assertUploadedOwnerTarget({ownerScope,ownerTarget,uploadScope,uploadedScene}) {
  assert.ok(ownerTarget?.scene && uploadedScene?.scene);
  assert.deepEqual(createLaunchScope(uploadScope),createLaunchScope(ownerScope));
  assert.deepEqual(createLaunchScope(executionScope(ownerTarget)),createLaunchScope(ownerScope));
  assert.deepEqual(createLaunchScope(executionScope(uploadedScene)),createLaunchScope(ownerScope));
  assert.deepEqual(createLaunchScope(uploadedScene),createLaunchScope(ownerTarget),
    'Uploaded target must retain the same storage birth');
  assert.equal(uploadedScene.targetId,ownerTarget.targetId);
  assert.equal(uploadedScene.scene.sceneId,ownerTarget.scene.sceneId);
  return true;
}

// The actual bound route calls res.end only after upload/indexing has returned.
// Keep its complete, original reply privately, but let the browser consume one
// byte of the real HTTP 200 and a broken connection. This is not a mock 502.
function loseUploadAckAfterCommit(req, res, record) {
  assert.equal(req.method, 'POST');
  assert.equal(req.path, '/uploads');
  assert.equal(typeof record, 'function');
  let used = false;
  res.end = function(chunk, encoding) {
    assert.equal(used, false, 'Only one owned upload reply may be lost');
    used = true;
    const bytes = Buffer.isBuffer(chunk) ? Buffer.from(chunk)
      : Buffer.from(chunk || '', typeof encoding === 'string' ? encoding : 'utf8');
    assert.equal(res.statusCode, 200);
    const body = JSON.parse(bytes.toString('utf8'));
    assert.equal(body?.ok, true);
    assert.equal(body.kind, 'product_manual');
    assert.match(body.operationId, /^[a-f0-9-]{36}$/);
    assert.ok(req.file && Buffer.isBuffer(req.file.buffer));
    assert.deepEqual(Object.keys(req.body).sort(),
      ['kind','scope_id','mime','public','recoveryScopeKey'].sort());
    const request={fields:Object.fromEntries(Object.entries(req.body)),
      filename:req.file.originalname,fileSha256:sha256(req.file.buffer),fileBytes:req.file.buffer.length};
    assert.equal(request.fields.kind,'product_manual');
    assert.equal(request.fields.scope_id,String(body.scope_id));
    record({body, raw:bytes.toString('utf8'), bytes:bytes.length, sha256:sha256(bytes),request});
    // res.json has already set the full Content-Length. The short body plus
    // connection loss is an incomplete response, never a completed ACK.
    res.write('{');
    setImmediate(() => res.destroy());
    return this;
  };
  return () => used;
}

function receiptQuery(row) {
  assert.equal(row?.method, 'GET');
  assert.equal(row.pathname, RECEIPT_PATH);
  assert.equal(typeof row.query, 'object');
  const query = row.query;
  assert.deepEqual(Object.keys(query).sort(), ['filename','mime','productId','public',
    'recoveryScopeKey','sha256','sizeBytes'].sort());
  return query;
}

function assertRecovery({requests,descriptor,operationId,recoveryScopeKey,postCount=1,
  beforeGetCount=1,actorBefore=0,actorAfter=0,judgeBefore=0,judgeAfter=0}) {
  assert.match(operationId,/^[a-f0-9-]{36}$/);
  assert.match(recoveryScopeKey,/^[a-f0-9]{64}$/);
  const posts=requests.filter(row=>row.method==='POST'&&row.pathname==='/uploads');
  assert.equal(posts.length,postCount);
  const gets=requests.filter(row=>row.method==='GET'&&row.pathname===RECEIPT_PATH);
  assert.equal(gets.length,beforeGetCount+1,'Exactly one explicit saved GET follows remount');
  const recovery=gets.at(-1),query=receiptQuery(recovery);
  assert.deepEqual(query,{...descriptor,recoveryScopeKey});
  assert.equal(recovery.status,200);assert.equal(recovery.error,null);
  const lookup=JSON.parse(recovery.response);
  assert.equal(lookup.state,'indexed');assert.equal(lookup.operationId,operationId);
  assert.equal(lookup.recoveryScopeKey,recoveryScopeKey);
  assert.equal(lookup.receipt.productId,Number(descriptor.productId));
  assert.equal(lookup.receipt.sha256,descriptor.sha256);
  assert.equal(lookup.receipt.sizeBytes,Number(descriptor.sizeBytes));
  assert.equal(lookup.receipt.filename,descriptor.filename);
  assert.equal(lookup.receipt.mime,descriptor.mime);
  assert.equal(lookup.receipt.isPublic,descriptor.public==='true');
  assert.equal(actorAfter,actorBefore);assert.equal(judgeAfter,judgeBefore);
  return lookup;
}

function assertSiblingSource(before, after) {
  for (const snapshot of [before, after]) {
    assert.ok(snapshot && typeof snapshot === 'object');
    assert.match(snapshot.targetId, /^[a-f0-9-]{36}$/);
    assert.ok(Array.isArray(snapshot.products) && snapshot.products.length >= 125);
    assert.ok(Array.isArray(snapshot.ingests) && snapshot.ingests.length === 1);
    assert.ok(Array.isArray(snapshot.documents) && snapshot.documents.length >= 1);
    assert.equal(snapshot.documents.some(row => row.row?.source_kind === 'manual'), true);
    assert.match(snapshot.file?.sha256, /^[a-f0-9]{64}$/);
    assert.ok(Number.isSafeInteger(snapshot.file?.bytes) && snapshot.file.bytes > 0);
    assert.equal(snapshot.ingests[0].row?.operation_id, snapshot.file.operationId);
    assert.equal(snapshot.ingests[0].row?.file_sha256, `\\x${snapshot.file.sha256}`);
    assert.equal(snapshot.ingests[0].row?.file_target_id, snapshot.file.targetId);
    assert.equal(snapshot.ingests[0].row?.virtual_path, snapshot.file.virtualPath);
    assert.equal(snapshot.ingests[0].row?.byte_count, snapshot.file.bytes);
    assert.notEqual(snapshot.file.targetId, snapshot.targetId);
    assert.ok(snapshot.products.every(row => row.row?.target_id === snapshot.targetId));
    assert.equal(snapshot.ingests[0].row?.target_id, snapshot.targetId);
    assert.ok(snapshot.documents.every(row => row.row?.target_id === snapshot.targetId));
    assert.ok(snapshot.documents.every(row => row.row?.source_id === snapshot.ingests[0].row?.manual_source_id));
  }
  assert.deepEqual(after, before, 'Existing sibling manual, documents and file must be unchanged');
  return true;
}

module.exports={RECEIPT_PATH,enterMerchantListingsWithAuthority,peerManualAuthority,assertUploaderActor,assertDistinctOwnedTargets,assertUploadedOwnerTarget,
  loseUploadAckAfterCommit,receiptQuery,assertRecovery,assertSiblingSource};
