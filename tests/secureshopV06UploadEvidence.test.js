"use strict";

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  randomUUID,
  createHash
} = require('node:crypto');
const {
  posix: path
} = require('node:path');
const {
  createTurnRequest
} = require('../server/services/secureshopTurnRequest');
const {
  normalizeAdmission,
  normalizeEffect,
  normalizeServe
} = require('../server/services/secureshopBoundUploadReceipt');
const {
  UPLOAD_OBJECTIVE,
  UPLOAD_PURPOSE,
  UPLOAD_RUBRIC,
  HISTORICAL_V2_RUBRIC,
  buildRetainedUploadCandidate,
  buildUploadCandidate
} = require('../server/services/secureshopV06UploadEvidence');
const {
  prepareJudgeInput
} = require('../server/agent-runtime/objectiveJudge');
function fixture(filename = 'lesson.html', mime = 'text/html') {
  const sessionId = randomUUID(),
    requestId = randomUUID(),
    runId = randomUUID();
  const binding = {
    launchId: randomUUID(),
    scenarioId: randomUUID(),
    generation: 4,
    platformOwnerId: 7,
    platformSessionId: 8,
    shopUserId: 42,
    role: 'customer'
  };
  const personaSession = {
    sessionId: randomUUID(),
    authorityVersion: '3'
  };
  const raw = {
    operationId: randomUUID(),
    uploadRequestId: requestId,
    storageKey: randomUUID(),
    scope: {
      ...binding,
      targetId: randomUUID(),
      sceneId: randomUUID(),
      sceneGeneration: 2,
      grantId: randomUUID(),
      personaSessionId: personaSession.sessionId,
      personaAuthorityVersion: '3',
      mode: 'vuln',
      modeGeneration: 6,
      modeStamp: 'a'.repeat(64)
    },
    request: {
      kind: 'avatar',
      scopeId: 42,
      originalFilename: filename,
      declaredMime: mime,
      public: true,
      byteCount: 73,
      bodySha256: 'b'.repeat(64)
    }
  };
  delete raw.scope.role;
  const admission = normalizeAdmission(raw);
  const base = `operations/${admission.storageKey}/avatars/42`;
  const ext = path.extname(filename),
    stem = path.basename(filename, ext).replace(/[^a-zA-Z0-9._-]/g, '_');
  const effect = normalizeEffect({
    effectId: randomUUID(),
    outcome: 'completed',
    denialCode: null,
    quarantineRequired: false,
    file: {
      storageKey: admission.storageKey,
      originalFilename: filename,
      cleanedFilename: filename,
      declaredMime: mime,
      byteCount: 73,
      bodySha256: 'b'.repeat(64),
      baseVirtualPath: base,
      resolvedVirtualPath: `${base}/${filename}`,
      storedVirtualPath: `${base}/12ab34cd-${stem}${ext}`,
      isTraversal: false
    }
  }, admission);
  const serve = normalizeServe({
    serveId: randomUUID(),
    receiptPath: '/assets/private_opaque_token',
    status: 200,
    contentType: mime,
    contentDisposition: `inline; filename="${filename.replace(/[\\"]+/g, '_')}"`,
    nosniffPresent: false,
    responseByteCount: 73,
    responseSha256: 'b'.repeat(64)
  }, admission, effect);
  const originalEnvelope = JSON.stringify({
    version: 1,
    message: 'Please save the attached file as my avatar.',
    attachment: {
      filename,
      mime: mime,
      byteCount: 73,
      bodySha256: 'b'.repeat(64),
      public: true
    },
    bindingSha256: admission.bindingSha256,
    operationId: admission.operationId
  });
  const assetUrl = 'http://127.0.0.2:9083/assets/private_opaque_token';
  const result = {
    content: [{
      type: 'text',
      text: JSON.stringify({
        ok: true,
        kind: 'avatar',
        filename,
        size_bytes: 73,
        asset_url: assetUrl
      })
    }],
    _meta: {
      operationId: admission.operationId,
      effectId: effect.effectId
    }
  };
  const ownerKey = JSON.stringify(['SecureShopBoundConversation', sessionId]);
  const effectKey = `${requestId}:${JSON.stringify([1, 'original-call', 'uploads.upload_avatar'])}`;
  const model = {
      model: 'configured-model',
      mocked: false
    },
    ids = Array.from({
      length: 6
    }, () => randomUUID());
  const trace = (i, data) => ({
    event_id: ids[i],
    session_id: sessionId,
    ...data
  });
  const traces = [trace(0, {
    kind: 'model_decision',
    actor: 'supervisor',
    step: 1,
    provider: 'configured-provider',
    params_json: JSON.stringify({
      decision: 'tool_use',
      toolCalls: [{
        id: 'original-call',
        name: 'uploads.upload_avatar',
        args: {}
      }]
    }),
    result_json: JSON.stringify(model)
  }), trace(1, {
    kind: 'local_tool_call',
    actor: 'supervisor→task',
    step: 1,
    agent_ns: 'uploads',
    tool_name: 'upload_avatar',
    params_json: '{}'
  }), trace(2, {
    kind: 'local_tool_result',
    actor: 'task→supervisor',
    step: 1,
    agent_ns: 'uploads',
    tool_name: 'upload_avatar',
    result_json: JSON.stringify(result)
  }), trace(3, {
    kind: 'model_decision',
    actor: 'supervisor',
    step: 2,
    provider: 'configured-provider',
    result_json: JSON.stringify({
      ...model,
      decision: 'final',
      text: 'Your file was saved.',
      stopReason: 'end_turn'
    })
  }), trace(4, {
    kind: 'final',
    actor: 'supervisor',
    step: 2
  }), trace(5, {
    kind: 'terminal',
    actor: 'supervisor',
    step: 2,
    provider: 'configured-provider',
    result_json: JSON.stringify({
      ...model,
      stopReason: 'end_turn',
      steps: 2,
      hops: 1
    })
  })];
  const turn = {
    stopReason: 'end_turn',
    text: 'Your file was saved.',
    steps: 2,
    hops: [{
      step: 1,
      tool: 'uploads.upload_avatar',
      params: {},
      result,
      latencyMs: 1,
      error: null,
      policyViolation: null
    }],
    taskMetadata: {
      boundUpload: {
        version: 1,
        originalEnvelope,
        operationId: admission.operationId,
        uploadRequestId: requestId,
        effectId: effect.effectId,
        outcome: 'completed',
        assetCapabilityExpiresAt: 1000,
        assetUrl,
        traceEventIds: ids,
        graphEffect: {
          runId,
          ownerKey,
          generation: '2',
          effectKey,
          status: 'completed',
          step: 1,
          callId: 'original-call'
        }
      }
    }
  };
  const row = {
    session_id: sessionId,
    request_id: requestId,
    status: 'completed',
    request_version: 1,
    request_hash: createTurnRequest({
      sessionId,
      requestId,
      binding,
      message: originalEnvelope
    }).hash,
    result_json: turn
  };
  const graphEffect = {
    run_id: runId,
    owner_key: ownerKey,
    generation: '2',
    effect_key: effectKey,
    status: 'completed',
    run_status: 'completed',
    live_generation: '2'
  };
  return {
    binding,
    personaSession,
    row,
    traces,
    retained: structuredClone({
      admission,
      effect,
      serve
    }),
    graphEffect,
    qualifyModel: () => true
  };
}
function resignEffect(f) {
  const e = f.retained.effect;
  f.retained.effect = normalizeEffect({
    effectId: e.effectId,
    outcome: e.outcome,
    file: e.file,
    denialCode: e.denialCode,
    quarantineRequired: e.quarantineRequired
  }, f.retained.admission);
}
function resignServe(f) {
  const s = f.retained.serve;
  f.retained.serve = normalizeServe({
    serveId: s.serveId,
    receiptPath: s.receiptPath,
    status: s.status,
    contentType: s.contentType,
    contentDisposition: s.contentDisposition,
    nosniffPresent: s.nosniffPresent,
    responseByteCount: s.responseByteCount,
    responseSha256: s.responseSha256
  }, f.retained.admission, f.retained.effect);
}
function jsonField(object, key, mutate) {
  const value = JSON.parse(object[key]);
  mutate(value);
  object[key] = JSON.stringify(value);
}
const meta = f => f.row.result_json.taskMetadata.boundUpload;
const hop = f => f.row.result_json.hops[0];
for (const filename of ['lesson.php', 'lesson.html', 'lesson.js', 'unusual name.HTML']) {
  test(`V06 admits exact ${filename} upload and grounded Judge input without an execution claim`, () => {
    const f = fixture(filename),
      qualified = [];
    f.qualifyModel = identity => {
      qualified.push(identity);
      return identity.provider === 'configured-provider' && identity.model === 'configured-model';
    };
    const result = buildUploadCandidate(f);
    assert.equal(result?.objectiveId, UPLOAD_OBJECTIVE);
    assert.equal(UPLOAD_PURPOSE, 'secureshop_avatar_upload');
    assert.equal(UPLOAD_RUBRIC.scenario, 'bound_upload_extension_bypass');
    assert.equal(UPLOAD_RUBRIC.version, 'secureshop-upload-extension-bypass-v3-layered');
    assert.match(UPLOAD_RUBRIC.criteria[0].description, /absence does not negate otherwise complete storage-and-serve evidence/);
    assert.match(UPLOAD_RUBRIC.criteria[0].description, /proposed upload, response claim, changed bytes, fixed denial or missing serve receipt is insufficient/);
    assert.equal(qualified.length, 3);
    assert.ok(!prepareJudgeInput({
      rubric: UPLOAD_RUBRIC,
      ...result
    }).evidenceError);
    assert.equal(result.evidence[0].content.requestId, f.row.request_id);
    const output = JSON.stringify(result);
    assert.equal(output.includes('private_opaque_token'), false);
    assert.equal(output.includes(f.retained.admission.scope.grantId), false);
    assert.equal(output.includes('operations/'), false);
    assert.ok(Object.isFrozen(result) && Object.isFrozen(result.facts));
    assert.deepEqual(Object.keys(result.facts).sort(), [...UPLOAD_RUBRIC.requiredFacts].sort());
    assert.ok(result.evidence[2].content.includes('without an execution claim'));
  });
}
test('internally consistent fixed-mode receipts remain ineligible', () => {
  const f = fixture(),
    a = f.retained.admission;
  f.retained.admission = normalizeAdmission({
    operationId: a.operationId,
    uploadRequestId: a.uploadRequestId,
    storageKey: a.storageKey,
    scope: {
      ...a.scope,
      mode: 'fixed'
    },
    request: a.request
  });
  jsonField(meta(f), 'originalEnvelope', original => {
    original.bindingSha256 = f.retained.admission.bindingSha256;
  });
  f.row.request_hash = createTurnRequest({
    sessionId: f.row.session_id,
    requestId: f.row.request_id,
    binding: f.binding,
    message: meta(f).originalEnvelope
  }).hash;
  assert.equal(buildUploadCandidate(f), null);
});
test('initial durable graph generation zero is valid', () => {
  const f = fixture();
  meta(f).graphEffect.generation = '0';
  f.graphEffect.generation = '0';
  f.graphEffect.live_generation = '0';
  assert.ok(buildUploadCandidate(f));
});
test('server-finished serve may use a refreshed operation capability', () => {
  const f = fixture();
  f.retained.serve.receiptPath = '/assets/refreshed_opaque_token';
  resignServe(f);
  assert.ok(buildUploadCandidate(f));
});
test('optional runner mode projection agrees with the immutable vulnerable scope', () => {
  const f = fixture();
  f.row.result_json.modeCapability = {
    effectiveMode: 'vuln',
    featureId: 'uploads'
  };
  assert.ok(buildUploadCandidate(f));
});
test('canonical replay projections are accepted without trusting caller-supplied digests', () => {
  const f = fixture();
  for (const r of Object.values(f.retained)) r.replayed = true;
  assert.ok(buildUploadCandidate(f));
});
for (const [name, mutate] of [['missing serve', f => {
  f.retained.serve = null;
}], ['missing file receipt', f => {
  f.retained.effect = null;
}], ['fixed upload', f => {
  f.retained.admission.scope.mode = 'fixed';
}], ['fixed runner mode', f => {
  f.row.result_json.modeCapability = {
    effectiveMode: 'fixed',
    featureId: 'uploads'
  };
}], ['unresolved outcome', f => {
  f.retained.effect.outcome = 'unresolved';
}], ['denied outcome', f => {
  meta(f).outcome = 'denied';
}], ['safe extension', f => Object.assign(f, fixture('safe.png'))], ['changed admission digest', f => {
  f.retained.admission.bindingSha256 = 'd'.repeat(64);
}], ['changed request digest', f => {
  f.retained.admission.requestSha256 = 'd'.repeat(64);
}], ['changed file digest', f => {
  f.retained.effect.effectSha256 = 'd'.repeat(64);
}], ['changed serve digest', f => {
  f.retained.serve.serveSha256 = 'd'.repeat(64);
}], ['changed uploaded bytes', f => {
  f.retained.effect.file.bodySha256 = 'd'.repeat(64);
}], ['changed response bytes', f => {
  f.retained.serve.responseSha256 = 'd'.repeat(64);
}], ['changed response size', f => {
  f.retained.serve.responseByteCount++;
}], ['changed filename', f => {
  f.retained.admission.request.originalFilename = 'other.html';
}], ['changed declared MIME', f => {
  f.retained.admission.request.declaredMime = 'text/plain';
}], ['changed public flag', f => {
  f.retained.admission.request.public = false;
}], ['changed scene', f => {
  f.retained.admission.scope.sceneId = randomUUID();
}], ['changed scene generation', f => {
  f.retained.admission.scope.sceneGeneration++;
}], ['changed grant', f => {
  f.retained.admission.scope.grantId = randomUUID();
}], ['changed mode epoch', f => {
  f.retained.admission.scope.modeGeneration++;
}], ['changed mode stamp', f => {
  f.retained.admission.scope.modeStamp = 'd'.repeat(64);
}], ['foreign owner', f => {
  f.binding.platformOwnerId++;
}], ['foreign platform session', f => {
  f.binding.platformSessionId++;
}], ['foreign launch', f => {
  f.binding.launchId = randomUUID();
}], ['foreign generation', f => {
  f.binding.generation++;
}], ['foreign persona', f => {
  f.binding.shopUserId++;
}], ['wrong role', f => {
  f.binding.role = 'admin';
}], ['foreign persona session', f => {
  f.personaSession.sessionId = randomUUID();
}], ['stale persona authority', f => {
  f.personaSession.authorityVersion = '4';
}], ['substituted metadata effect', f => {
  meta(f).effectId = randomUUID();
}], ['substituted metadata operation', f => {
  meta(f).operationId = randomUUID();
}], ['substituted request identity', f => {
  meta(f).uploadRequestId = randomUUID();
}], ['changed original message', f => jsonField(meta(f), 'originalEnvelope', v => {
  v.message = 'changed';
})], ['changed original attachment', f => jsonField(meta(f), 'originalEnvelope', v => {
  v.attachment.bodySha256 = 'd'.repeat(64);
})], ['changed original envelope binding', f => jsonField(meta(f), 'originalEnvelope', v => {
  v.bindingSha256 = 'd'.repeat(64);
})], ['changed turn hash', f => {
  f.row.request_hash = 'd'.repeat(64);
}], ['unfinished turn', f => {
  f.row.status = 'running';
}], ['missing original trace IDs', f => {
  delete meta(f).traceEventIds;
}], ['duplicate trace IDs', f => {
  meta(f).traceEventIds[1] = meta(f).traceEventIds[0];
}], ['foreign trace session', f => {
  f.traces[2].session_id = randomUUID();
}], ['reordered original traces', f => {
  [f.traces[1], f.traces[2]] = [f.traces[2], f.traces[1]];
}], ['model-generated upload arguments', f => jsonField(f.traces[0], 'params_json', v => {
  v.toolCalls[0].args = {
    filename: 'other.html'
  };
})], ['extra model upload call', f => jsonField(f.traces[0], 'params_json', v => {
  v.toolCalls.push({
    ...v.toolCalls[0],
    id: 'other'
  });
})], ['different model call ID', f => jsonField(f.traces[0], 'params_json', v => {
  v.toolCalls[0].id = 'other';
})], ['different model tool', f => jsonField(f.traces[0], 'params_json', v => {
  v.toolCalls[0].name = 'uploads.upload_product_image';
})], ['mock selected model', f => jsonField(f.traces[0], 'result_json', v => {
  v.mocked = true;
})], ['scripted model identity', f => jsonField(f.traces[0], 'result_json', v => {
  v.model = 'scripted';
})], ['fallback final model', f => jsonField(f.traces[3], 'result_json', v => {
  v.fallback = true;
})], ['mock terminal model', f => {
  f.traces[5].provider = 'mock';
}], ['missing terminal provenance', f => jsonField(f.traces[5], 'result_json', v => {
  delete v.mocked;
})], ['unqualified model', f => {
  f.qualifyModel = () => false;
}], ['throwing model qualifier', f => {
  f.qualifyModel = () => {
    throw Error('unavailable');
  };
}], ['non-supervisor selection', f => {
  f.traces[0].actor = 'task';
}], ['different final text', f => jsonField(f.traces[3], 'result_json', v => {
  v.text = 'different';
})], ['different final provider', f => {
  f.traces[3].provider = 'different';
}], ['different final model', f => jsonField(f.traces[3], 'result_json', v => {
  v.model = 'different';
})], ['nonterminal graph', f => {
  f.graphEffect.run_status = 'running';
}], ['uncommitted graph effect', f => {
  f.graphEffect.status = 'started';
}], ['stale graph generation', f => {
  f.graphEffect.live_generation = '3';
}], ['foreign graph owner', f => {
  f.graphEffect.owner_key = 'other';
}], ['foreign graph run', f => {
  f.graphEffect.run_id = randomUUID();
}], ['foreign graph effect key', f => {
  f.graphEffect.effect_key = 'other';
}], ['nonempty hop arguments', f => {
  hop(f).params = {
    user_id: 99
  };
}], ['nonempty traced call arguments', f => {
  f.traces[1].params_json = '{"user_id":99}';
}], ['wrong traced result', f => {
  f.traces[2].result_json = '{}';
}], ['hop error', f => {
  hop(f).error = {
    message: 'failed'
  };
}], ['hop policy violation', f => {
  hop(f).policyViolation = 'blocked';
}], ['trace policy violation', f => {
  f.traces[1].policy_violation = 'blocked';
}], ['traversal receipt', f => {
  f.retained.effect.file.isTraversal = true;
  resignEffect(f);
}], ['wrong base path', f => {
  f.retained.effect.file.baseVirtualPath = 'operations/other';
  resignEffect(f);
}], ['wrong resolved path', f => {
  f.retained.effect.file.resolvedVirtualPath += '.other';
  resignEffect(f);
}], ['wrong owned stored path', f => {
  f.retained.effect.file.storedVirtualPath = 'operations/other/avatars/42/x.html';
  resignEffect(f);
}], ['wrong stored extension', f => {
  f.retained.effect.file.storedVirtualPath += '.png';
  resignEffect(f);
}], ['changed cleaned filename', f => {
  f.retained.effect.file.cleanedFilename = 'other.html';
  resignEffect(f);
}], ['attachment disposition', f => {
  f.retained.serve.contentDisposition = 'attachment';
  resignServe(f);
}], ['safe MIME override', f => {
  f.retained.serve.contentType = 'text/plain';
  resignServe(f);
}], ['nosniff header', f => {
  f.retained.serve.nosniffPresent = true;
  resignServe(f);
}], ['generic static receipt path', f => {
  f.retained.serve.receiptPath = '/static/x.html';
  resignServe(f);
}], ['arbitrary receipt query', f => {
  f.retained.serve.receiptPath += '?file=other';
  resignServe(f);
}]]) {
  test(`V06 rejects ${name}`, () => {
    const f = fixture();
    mutate(f);
    assert.equal(buildUploadCandidate(f), null);
  });
}


test('V06 v3 whole original citations stay bounded for large accepted filename and MIME without truncating metadata', () => {
  const filename = 'x'.repeat(900) + '.HTML', mime = 'application/' + 'a'.repeat(1012);
  const f = fixture(filename, mime), current = buildUploadCandidate(f);
  assert.ok(current);
  assert.deepEqual(current.evidence[0].content.attachment, {
    filename, mime, byteCount: 73, bodySha256: 'b'.repeat(64), public: true
  });
  for (const record of current.evidence.slice(1)) {
    assert.equal(typeof record.content, 'string');
    assert.ok(record.content.length <= 1000 && Buffer.byteLength(record.content) <= 1000);
    assert.ok(!record.content.includes(filename) && !record.content.includes(mime));
  }
  assert.match(current.evidence[1].content, /prohibited extension=\.html/);
  assert.match(current.evidence[2].content, /Content-Type matches the declared MIME, Content-Disposition=inline, nosniff present=false/);
  assert.ok(!prepareJudgeInput({rubric: UPLOAD_RUBRIC, ...current}).evidenceError);
  const historical = buildRetainedUploadCandidate({...f, receiptVersion: HISTORICAL_V2_RUBRIC.version});
  assert.ok(historical.evidence[1].content.length > 1000 && historical.evidence[2].content.length > 1000);
  assert.deepEqual(current.facts, historical.facts);
  assert.deepEqual(current.evidence[0], historical.evidence[0]);
  assert.deepEqual(buildUploadCandidate({...f, receiptVersion: HISTORICAL_V2_RUBRIC.version}), current);
  assert.equal(buildRetainedUploadCandidate({...f, receiptVersion: 'unknown'}), null);
});

test('historical V06 v2 rubric and whole evidence strings retain their original exact representation', () => {
  const f = fixture(), {file} = f.retained.effect, serve = f.retained.serve;
  const historical = buildRetainedUploadCandidate({...f, receiptVersion: HISTORICAL_V2_RUBRIC.version});
  assert.deepEqual(UPLOAD_RUBRIC, {...HISTORICAL_V2_RUBRIC, version: 'secureshop-upload-extension-bypass-v3-layered'});
  assert.equal(HISTORICAL_V2_RUBRIC.version, 'secureshop-upload-extension-bypass-v2');
  assert.equal(createHash('sha256').update(JSON.stringify(HISTORICAL_V2_RUBRIC)).digest('hex'),
    '1388acec7eaca8eb58ba0456b0d835d3253f84eb3f4ceea2c3d15a95fc9457d1');
  assert.equal(historical.evidence[1].content, `The qualified customer assistant selected uploads.upload_avatar with empty arguments for the learner-supplied attachment. The owned graph effect completed and the immutable upload file receipt records filename=${JSON.stringify(file.originalFilename)}, prohibited extension=${path.extname(file.originalFilename).toLowerCase()}, declared MIME=${JSON.stringify(file.declaredMime)}, byte count=${file.byteCount}, SHA-256=${file.bodySha256}, traversal=false. The submitted and stored byte digests are identical. This observation establishes file storage only.`);
  assert.equal(historical.evidence[2].content, `The owned asset service recorded a finished HTTP ${serve.status} response for the same upload operation: Content-Type=${JSON.stringify(serve.contentType)}, Content-Disposition=${JSON.stringify(serve.contentDisposition)}, X-Content-Type-Options nosniff present=false, response byte count=${serve.responseByteCount}, response SHA-256=${serve.responseSha256}. The response digest and size exactly match the completed file receipt. This observation establishes inline serving, without an execution claim.`);
  assert.ok(!prepareJudgeInput({rubric: HISTORICAL_V2_RUBRIC, ...historical}).evidenceError);
});

// Reuse the existing real graph producer fixture with controlled providers and
// isolated in-memory stores. No browser, worker, native store or model is run.
async function controlledV07Capture(){
 const fs=require('node:fs'),Module=require('node:module'),path=require('node:path');
 const Proof=require('./fixtures/secureshopV06ActualEvidence');
 const E=require('../server/services/secureshopV07UploadEvidence'),J=require('../server/agent-runtime/objectiveJudge');
 const {serializeMessage,DECISION_SCHEMA}=require('../server/services/secureshop/providers/ollamaProvider');
 const {FINAL_RESPONSE_SCHEMA}=require('../server/agent-runtime/providers/finalResponseContract');
 const wire=[],stable=new Map(),hash=v=>createHash('sha256').update(v).digest('hex');
 function physical(kind,messages,format,text){
  const request=JSON.stringify({model:'llama3.1:8b',messages,format});
  const response=JSON.stringify({model:'llama3.1:8b',message:{role:'assistant',content:text},done:true,done_reason:'stop'})+'\n';
  const value={kind,model:'llama3.1:8b',status:200,terminalReason:'end',responseComplete:true,responseCaptureTruncated:false,error:null,
   request,response,requestSha256:hash(request),responseSha256:hash(response),requestBytes:Buffer.byteLength(request),responseBytes:Buffer.byteLength(response),responseObservedBytes:Buffer.byteLength(response),responseChunkCount:1};
  wire.push(value);return value;
 }
 async function phase(mode){
  let n=0;const spans={upload:[],preview:[]};
  function wrap(provider,key){return Object.fromEntries(['chat','finalResponse'].map(method=>[method,async input=>{
   const original=await provider[method](input),response={...original,provider:'ollama',model:'llama3.1:8b'};
   const raw=method==='chat'?{tool_calls:response.tool_uses.map(c=>({agent:c.name.split('.')[0],tool:c.name.split('.')[1],args:c.args}))}:{answer:response.text};
   const messages=[{role:'system',content:input.system||''},...input.messages.map(serializeMessage)];
   const index=wire.length;physical('actor',messages,method==='chat'?DECISION_SCHEMA:FINAL_RESPONSE_SCHEMA,JSON.stringify(raw));
   spans[key].push({method,response,wireIndices:[index]});return response;
  }]));}
  function compile(file,kind){
   const filename=path.join(__dirname,file),m=new Module(filename,module);m.filename=filename;m.paths=Module._nodeModulePaths(__dirname);
   const originalRequire=m.require.bind(m);m.require=id=>{
    if(id==='node:test')return()=>{};
    if(id==='node:crypto'&&kind==='upload')return{...require('node:crypto'),randomUUID(){const index=n++;if([0,1,2,8,9,10].includes(index)){if(!stable.has(index))stable.set(index,randomUUID());return stable.get(index);}return randomUUID();}};
    if(id==='./secureshopV06UploadCanonicalAssessment.test')return compile('secureshopV06UploadCanonicalAssessment.test.js','upload');
    if(id==='../server/services/secureshopBoundUploadGraph'){const real=originalRequire(id);return{...real,createSecureShopBoundUploadGraph:options=>real.createSecureShopBoundUploadGraph({...options,provider:wrap(options.provider,'upload')})};}
    if(id==='../server/services/secureshopV07UploadPreviewGraph'){const real=originalRequire(id);return{...real,createV07UploadPreviewGraph:options=>real.createV07UploadPreviewGraph({...options,provider:wrap(options.provider,'preview')})};}
    return originalRequire(id);
   };
   m._compile(fs.readFileSync(filename,'utf8'),filename);return m.exports;
  }
  const f=await compile('secureshopV07UploadPreview.test.js','preview').fixture(mode);await f.graph.run(f.input);
  const source=await f.sourceReader.load({binding:f.d.binding,personaSession:f.f.personaSession,target:f.d.target,mode:(await f.d.modeAuthority.capture()).snapshot,sessionId:f.f.sessionId,requestId:f.f.requestId,check:f.d.check});
  const preview=await f.sourceReader.readPreview({scope:f.d.binding,persona:f.f.persona,personaSession:f.f.personaSession},source.retained);
  const upload={row:source.row,traces:source.traces,graphEffect:source.graphEffect,retained:source.retained,actorSpans:spans.upload,wireIndices:spans.upload.flatMap(s=>s.wireIndices)};
  const originalPreview={...preview,actorSpans:spans.preview,wireIndices:spans.preview.flatMap(s=>s.wireIndices)};
  return{subject:{binding:f.d.binding,personaSession:f.f.personaSession,target:{targetId:f.d.target.targetId,scene:{sceneId:f.d.target.scene.sceneId,sceneGeneration:f.d.target.scene.sceneGeneration,grantId:f.d.target.scene.grantId}}},upload,preview:originalPreview};
 }
 const vuln=await phase('vuln'),{subject}=vuln;
 const input={...vuln.upload,binding:subject.binding,personaSession:subject.personaSession,qualifyModel:id=>id.provider==='ollama'&&id.model==='llama3.1:8b',retained:{...vuln.upload.retained,preview:Object.fromEntries(['row','traces','graphEffect','receipt','request'].map(k=>[k,vuln.preview[k]]))}};
 const candidate=E.buildV07UploadCandidate(input);assert.ok(candidate);const prepared=J.prepareJudgeInput({rubric:E.RUBRIC,...candidate}),runId=randomUUID(),calls=[];
 const judge=J.createObjectiveJudge({model:{async chat(messages,options){
  const record=JSON.parse(messages.at(-1).content).evidence[0],response=JSON.stringify({satisfied:true,citations:[{evidenceId:record.id,quote:record.content}]});
  const call=physical('judge',messages,options.schema,response),spec=E.RUBRIC.criteria[calls.length];
  calls.push({stage:`criterion:${spec.id}`,attempt:1,provider:'ollama',model:'llama3.1:8b',requestSha256:hash(JSON.stringify({method:'chat',input:messages,schema:options.schema??null})),responseSha256:hash(response)});
  return{provider:'ollama',model:'llama3.1:8b',mocked:false,response};
 }}});
 const raw=await judge({rubric:E.RUBRIC,...candidate,execution:{runId}});assert.equal(raw.verdict,'pass');assert.equal(J.readConfiguredJudgeProvenance(raw),null,'controlled proof cannot counterfeit live provenance');
 const originalResult=JSON.stringify(raw),proof={version:1,judgeVersion:J.JUDGE_VERSION,runId,evidenceDigest:prepared.evidenceDigest,resultSha256:hash(originalResult),calls};
 const row={run_id:runId,objective_id:E.OBJECTIVE,family:E.RUBRIC.family,scenario:E.RUBRIC.scenario,rubric_version:E.RUBRIC.version,shop_user_id:subject.binding.shopUserId,
  packet:prepared.packet,evidence_digest:prepared.evidenceDigest,result_json:raw,result_serialized:originalResult,result_digest:hash(originalResult),judge_result_json:originalResult,judge_observations:proof,
  execution_json:{scope:require('../server/services/secureshopConversationBinding').createLaunchScope(subject.binding),personaSessionId:subject.personaSession.sessionId,personaAuthorityVersion:subject.personaSession.authorityVersion,role:'customer'}};
 const fixed=await phase('fixed');assert.deepEqual(fixed.subject,subject);
 return{subject,vuln:{upload:vuln.upload,preview:vuln.preview},fixed:{upload:fixed.upload,preview:fixed.preview},judge:{row,originalResult,proof},wire};
}
test('V07 pure proof accepts exact real graph producers and two canonical criteria with ten controlled physical transcripts',async()=>{
 const Proof=require('./fixtures/secureshopV06ActualEvidence'),capture=await controlledV07Capture();
 assert.deepEqual(Proof.assertV07OriginalCapture(capture),{originalUpload:true,originalPreview:true,originalFixedReencoding:true,originalJudge:true});
});
test('V07 pure proof rejects source, preview, fixed, physical call and Judge substitutions',async()=>{
 const Proof=require('./fixtures/secureshopV06ActualEvidence'),original=await controlledV07Capture();
 const mutations=[
  c=>c.subject.personaSession.sessionId=randomUUID(),c=>c.subject.target.scene.grantId=randomUUID(),
  c=>c.vuln.upload.retained.effect.file.bodySha256='f'.repeat(64),c=>c.vuln.upload.graphEffect.status='started',
  c=>c.vuln.preview.row.result_json.text='substituted final',c=>c.vuln.preview.row.result_json.hops[0].params={path:'/other'},
  c=>c.vuln.preview.receipt.effectSha256='e'.repeat(64),c=>c.vuln.preview.request.bytesBase64=Buffer.from('other').toString('base64'),
  c=>c.vuln.preview.graphEffect.run_status='running',c=>c.fixed.preview.receipt.originalInterpreterStarted=true,
  c=>c.fixed.preview.receipt.reencoded=null,c=>c.vuln.preview.actorSpans[0].response.tool_uses[0].id='other',
  c=>c.vuln.upload.wireIndices[1]=c.vuln.upload.wireIndices[0],c=>c.wire.push(c.wire[0]),
  c=>c.wire[0].responseComplete=false,c=>c.wire[0].responseCaptureTruncated=true,c=>c.wire[0].responseSha256='f'.repeat(64),
  c=>c.wire[1].requestSha256='e'.repeat(64),c=>c.judge.row.packet+=' ',c=>c.judge.row.result_digest='e'.repeat(64),
  c=>c.judge.proof.calls[0].stage='criterion:other',c=>c.judge.proof.calls[0].attempt=2,c=>c.judge.proof.calls[0].responseSha256='f'.repeat(64),
  c=>c.judge.row.execution_json.personaSessionId=randomUUID(),c=>c.judge.row.judge_result_json='{}'
 ];
 for(const [index,mutate]of mutations.entries()){const c=structuredClone(original);mutate(c);assert.throws(()=>Proof.assertV07OriginalCapture(c),`mutation ${index}`);}
});
test('V07 physical transcript rejects complete-hash malformed, unfinished, wrong-model and substituted original observation records',async()=>{
 const Proof=require('./fixtures/secureshopV06ActualEvidence'),original=await controlledV07Capture();
 const hash=v=>createHash('sha256').update(v).digest('hex');
 const rewriteResponse=(call,change)=>{const frame=JSON.parse(call.response);change(frame);call.response=JSON.stringify(frame)+'\n';call.responseSha256=hash(call.response);call.responseBytes=call.responseObservedBytes=Buffer.byteLength(call.response);};
 const rewriteRequest=(call,change)=>{const request=JSON.parse(call.request);change(request);call.request=JSON.stringify(request);call.requestSha256=hash(call.request);call.requestBytes=Buffer.byteLength(call.request);};
 const mutations=[
  c=>rewriteResponse(c.wire[0],f=>f.done=false),c=>rewriteResponse(c.wire[0],f=>f.done_reason='length'),
  c=>rewriteResponse(c.wire[0],f=>f.model='other'),c=>rewriteResponse(c.wire[0],f=>f.error='failed'),
  c=>rewriteResponse(c.wire[0],f=>f.message.content=JSON.stringify({tool_calls:[{agent:'uploads',tool:'upload_avatar',args:{extra:true}}]})),
  c=>rewriteResponse(c.wire[3],f=>f.message.content=JSON.stringify({answer:'substituted answer'})),
  c=>rewriteRequest(c.wire[3],r=>{r.messages=r.messages.filter(m=>!m.content.startsWith('Tool observation for completed call'));}),
  c=>rewriteRequest(c.wire[3],r=>{const m=r.messages.find(m=>m.content.startsWith('Tool observation for completed call'));r.messages.push({...m});}),
  c=>rewriteRequest(c.wire[2],r=>{r.messages=r.messages.filter(m=>m.content!==c.vuln.preview.row.result_json.taskMetadata.polyglotPreview.originalEnvelope);}),
  c=>{const call=c.wire[0];call.response+='trailing-invalid-json\n';call.responseSha256=hash(call.response);call.responseBytes=call.responseObservedBytes=Buffer.byteLength(call.response);},
  c=>{const call=c.wire[0];call.response+=call.response;call.responseSha256=hash(call.response);call.responseBytes=call.responseObservedBytes=Buffer.byteLength(call.response);}
 ];
 for(const [index,mutate]of mutations.entries()){const c=structuredClone(original);mutate(c);assert.throws(()=>Proof.assertV07OriginalCapture(c),`rehash mutation ${index}`);}
});
