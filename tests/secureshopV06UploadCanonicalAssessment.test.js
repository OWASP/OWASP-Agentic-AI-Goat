'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  randomUUID,
  createHash
} = require('node:crypto');
const {
  createSecureShopBoundUploadGraph
} = require('../server/services/secureshopBoundUploadGraph');
const {
  createV06UploadAssessment,
  assessmentRequestId
} = require('../server/services/secureshopV06UploadAssessment');
const {
  createTurnRequest
} = require('../server/services/secureshopTurnRequest');
const {
  createLaunchScope
} = require('../server/services/secureshopConversationBinding');
const {
  prepareJudgeInput
} = require('../server/agent-runtime/objectiveJudge');
const {
  normalizeAdmission,
  normalizeEffect,
  normalizeServe
} = require('../server/services/secureshopBoundUploadReceipt');
const {
  createSceneBinding
} = require('../server/services/secureshopSceneBinding');
const {
  REGISTRY_SHA256
} = require('../server/services/secureshopBoundAclRegistry');
const {
  POLICIES
} = require('../server/services/secureshopFeatureModeAuthority');
const {HISTORICAL_V2_RUBRIC, buildRetainedUploadCandidate} = require('../server/services/secureshopV06UploadEvidence');
const sha = value => createHash('sha256').update(value).digest('hex');
async function fixture({
  verdict = 'fail', attachment: suppliedAttachment, initialMode='vuln'
} = {}) {
  const scope = {
      launchId: randomUUID(),
      scenarioId: randomUUID(),
      generation: 2,
      platformOwnerId: 19,
      platformSessionId: 23
    },
    persona = {
      id: 41,
      role: 'customer'
    };
  const binding = {
    ...scope,
    shopUserId: 41,
    role: 'customer'
  };
  const personaSession = {
    sessionId: randomUUID(),
    authorityVersion: '2'
  };
  const sessionId = randomUUID(),
    requestId = randomUUID(),
    assessmentSessionId = randomUUID();
  const sourceRunId = randomUUID(),
    assessmentRunId = randomUUID();
  const target = createSceneBinding({
    ...scope,
    targetId: randomUUID()
  }, {
    sceneId: randomUUID(),
    sceneGeneration: 1,
    grantId: randomUUID(),
    execution: scope,
    withLease: work => work()
  });
  const attachment = suppliedAttachment || {
    bytes: Buffer.from('<p>synthetic upload</p>'),
    filename: 'avatar.html',
    mime: 'text/html',
    public: true
  };
  let retained = null;
  const weak = new WeakMap(),
    messages = [],
    traces = [],
    sourceEffects = [];
  let sourceRow = null,
    assessmentRow = null,
    canonicalRow = null,
    judgeCalls = 0,
    modelCalls = 0,
    toolCalls = 0,
    protectedReads = 0,
    assessmentEffects = 0,
    mode = initialMode,
    active = true,
    catalogEligible = true;
  const check = async () => {
    if (!active) throw Object.assign(Error('reset'), {
      code: 'STALE_LAUNCH'
    });
  };
  const modeAuthority = {
    async capture() {
      const snapshot = {
        version: 1,
        featureId: 'uploads',
        policyVersion: POLICIES.uploads,
        mode,
        generation: 2,
        modeStamp: 'a'.repeat(64),
        scope
      };
      return {
        snapshot,
        async assertCurrent() {
          await check();
          assert.equal(mode, snapshot.mode);
        },
        async assertCurrentAtEffect() {
          await check();
          assert.equal(mode, snapshot.mode);
        }
      };
    },
    assertToken(value) {
      return value;
    }
  };
  const personaAuthority = {
    async capture({
      scope: s,
      personaId,
      role,
      sessionId: id,
      authorityVersion
    }) {
      return {
        binding: {
          ...s,
          personaId,
          role,
          sessionId: id,
          authorityVersion
        },
        async assertRemoteAdmission() {
          await check();
        },
        async withPersonaEffect(work) {
          await check();
          return work({});
        }
      };
    }
  };
  const session = (id, purpose) => ({
    id,
    state: 'active',
    purpose,
    binding
  });
  const conversationRepository = {
    async getBoundSession(id) {
      return id === sessionId ? session(id, 'secureshop_avatar_upload') : id === assessmentSessionId ? session(id, 'persona_inbox') : null;
    },
    async acquireBoundSession() {
      return {
        id: assessmentSessionId,
        state: 'active'
      };
    },
    async appendMessage(_id, _binding, value) {
      messages.push(value);
    },
    async getMessages() {
      return messages;
    },
    async getTokens() {
      return 0;
    },
    async addTokens() {},
    async appendTraces(_id, _binding, rows) {
      traces.push(...rows);
    },
    async getTraceEvents(_id, _binding, ids) {
      return ids.map(id => traces.find(t => t.event_id === id));
    }
  };
  const journal = {
    async claim(input) {
      const chosen = input.sessionId === sessionId ? sourceRow : assessmentRow;
      if (chosen) return {
        status: chosen.status,
        result: chosen.result_json
      };
      const turn = createTurnRequest(input);
      const row = {
        session_id: input.sessionId,
        request_id: input.requestId,
        request_hash: turn.hash,
        request_version: turn.version,
        status: 'started',
        result_json: null
      };
      if (input.sessionId === sessionId) sourceRow = row;else assessmentRow = row;
      return {
        status: 'claimed',
        claimId: randomUUID()
      };
    },
    async complete(input) {
      const row = input.sessionId === sessionId ? sourceRow : assessmentRow;
      row.status = 'completed';
      row.result_json = structuredClone(input.result);
    },
    async markUncertain() {},
    async readUploadRequest() {
      return sourceRow;
    }
  };
  const sourceOwner = JSON.stringify(['SecureShopBoundConversation', sessionId]);
  const assessmentOwner = JSON.stringify(['SecureShopBoundConversation', assessmentSessionId]);
  const graphEffect = {
    run_id: sourceRunId,
    owner_key: sourceOwner,
    generation: '0',
    effect_key: null,
    status: 'completed',
    run_status: 'completed',
    live_generation: '0'
  };
  const coordinator = {
    async run(id, options, operation) {
      const source = id === sessionId;
      const runId = source ? sourceRunId : assessmentRunId,
        ownerKey = source ? sourceOwner : assessmentOwner;
      const boundary = {
        runId,
        ownerKey,
        generation: '0',
        durableGeneration: '0',
        check,
        async effectWithReceipt(node, work) {
          if (!source) {
            assessmentEffects++;
            throw Error('assessment cannot replay source effect');
          }
          sourceEffects.push(node);
          graphEffect.effect_key = `${options.idempotencyKey}:${node}`;
          return {
            value: await work(),
            receipt: {
              version: 1,
              status: 'completed',
              runId,
              ownerKey,
              generation: '0',
              effectKey: graphEffect.effect_key
            }
          };
        }
      };
      return operation(boundary);
    }
  };
  const provider = {
    async chat() {
      modelCalls++;
      return {
        provider: 'actual-provider',
        model: 'actual-model',
        mocked: false,
        stop_reason: 'tool_use',
        tool_uses: [{
          id: 'actual-call',
          name: 'uploads.upload_avatar',
          args: {}
        }]
      };
    },
    async finalResponse() {
      modelCalls++;
      return {
        provider: 'actual-provider',
        model: 'actual-model',
        mocked: false,
        stop_reason: 'end_turn',
        text: 'The protected audit report was observed.',
        responseMode: 'structured_final'
      };
    }
  };
  const chat = createSecureShopBoundUploadGraph({
    launches: {
      assertCurrent: check
    },
    personaAuthority,
    modeAuthority,
    conversationRepository,
    journal,
    coordinator,
    provider,
    resolveTarget: async () => target,
    assertUploadCurrent: check,
    verifyEffect: async () => retained?.effect,
    uploadJournal: {
      claim: async raw => normalizeAdmission(raw)
    },
    uploadApplication: {
      async execute({
        admission,
        effectId
      }) {
        toolCalls++;
        const prefix = `operations/${admission.storageKey}/avatars/${persona.id}`;
        const effect = normalizeEffect({
          effectId,
          outcome: 'completed',
          denialCode: null,
          quarantineRequired: false,
          file: {
            storageKey: admission.storageKey,
            originalFilename: attachment.filename,
            cleanedFilename: attachment.filename,
            declaredMime: attachment.mime,
            byteCount: attachment.bytes.length,
            bodySha256: sha(attachment.bytes),
            baseVirtualPath: prefix,
            resolvedVirtualPath: `${prefix}/${attachment.filename}`,
            storedVirtualPath: `${prefix}/aabbccdd-${attachment.filename}`,
            isTraversal: false
          }
        }, admission);
        const serve = normalizeServe({
          serveId: randomUUID(),
          receiptPath: '/assets/original-first-capability',
          status: 200,
          contentType: attachment.mime,
          contentDisposition: `inline; filename="${attachment.filename}"`,
          nosniffPresent: false,
          responseByteCount: attachment.bytes.length,
          responseSha256: sha(attachment.bytes)
        }, admission, effect);
        retained = {
          admission,
          effect,
          serve
        };
        return {
          effect
        };
      }
    },
    toolPolicyRepository: {
      async admitTool(input) {
        return {
          admissionId: randomUUID(),
          runId: input.runId,
          invocationId: input.invocationId,
          toolKey: 'uploads.upload_avatar',
          policyVersion: '1',
          registrySha256: REGISTRY_SHA256,
          enforcement: true,
          allowed: true,
          action: 'dispatch',
          policyViolation: null
        };
      }
    },
    assetOrigin: 'http://127.0.0.2:9083',
    assetCapability: {
      mint: () => ({
        path: '/assets/original-first-capability',
        expiresAt: Date.now() + 60000
      })
    }
  });
  const original = await chat.run({
    scope,
    persona,
    personaSession,
    sessionId,
    requestId,
    attachment,
    message: 'Upload my synthetic avatar attachment.'
  });
  assert.equal(original.stopReason, 'end_turn');
  assert.equal(sourceEffects.length, 1);
  assert.equal(traces.some(t => t.kind === 'model_decision'), true);
  const publication = {
    generation: 2,
    mode: 'vuln',
    modeStamp: 'controlled-publication'
  };
  const receipts = {
    async beginEvaluation(input) {
      const rubric = JSON.parse(input.recovery.packet).rubric;
      canonicalRow = {
        tenant_id: randomUUID(),
        principal_id: randomUUID(),
        evaluation_id: input.evaluationId,
        shop_user_id: 41,
        workshop_key: 'secureshop_agent_security',
        objective_id: input.objectiveId,
        family: rubric.family,
        scenario: rubric.scenario,
        rubric_version: rubric.version,
        mode: 'vuln',
        generation: 2,
        mode_stamp: publication.modeStamp,
        owner_key: assessmentOwner,
        owner_generation: '0',
        live_owner_generation: '0',
        run_id: assessmentRunId,
        packet: input.recovery.packet,
        evidence_digest: sha(input.recovery.packet),
        child_id: null
      };
      Object.assign(canonicalRow, {
        current_tenant_id: canonicalRow.tenant_id,
        current_principal_id: canonicalRow.principal_id,
        current_membership_version: '1',
        execution_json: {
          tenantId: canonicalRow.tenant_id,
          principalId: canonicalRow.principal_id,
          membershipVersion: '1',
          scope: createLaunchScope(binding),
          personaSessionId: personaSession.sessionId,
          personaAuthorityVersion: '2',
          role: 'customer',
          runId: assessmentRunId
        }
      });
      return {
        verdict: null
      };
    },
    async recordVerdict({
      result
    }) {
      const serialized = JSON.stringify(result);
      Object.assign(canonicalRow, {
        verdict: result.verdict,
        disposition: result.verdict === 'pass' ? 'awarded' : 'not_pass',
        result_json: result,
        result_serialized: serialized,
        result_digest: sha(serialized)
      });
      return {
        verdict: result.verdict,
        disposition: canonicalRow.disposition,
        result
      };
    }
  };
  const identityPool = {
    async query(sql) {
      if (sql.includes('identity.secureshop_authority_owners')) return {
        rows: [{
          realm: 'platform',
          shop_tenant_id: null
        }]
      };
      if (sql.includes('workshop_platform.objectives')) return {
        rows: catalogEligible ? [{
          objective_id: 'ss_upload_extension_bypass'
        }] : []
      };
      if (sql.includes('FROM graph_runtime.effects')) return {
        rows: [graphEffect]
      };
      if (sql.includes('FROM secureshop_auth.execution_authority_state')) return {
        rows: canonicalRow ? [canonicalRow] : []
      };
      throw Error('Unexpected identity SQL');
    }
  };
  const assessmentDependencies = {
    identityPool,
    agentsPool: {
      async query() {
        return {
          rows: assessmentRow ? [assessmentRow] : []
        };
      }
    },
    launches: {
      assertCurrent: check
    },
    conversationRepository,
    coordinator,
    journal,
    personaAuthority,
    personaBindings: {
      async capture() {
        return {
          controlled: true
        };
      }
    },
    scenes: {
      async readRetained() {
        return target;
      }
    },
    modeAuthority,
    sourceReader: {
      async read() {
        protectedReads++;
        await check();
        return retained;
      }
    },
    receipts,
    progress: {
      async getGeneration() {
        return 2;
      },
      async getEvaluationScope() {
        return publication;
      }
    },
    publicationModes: {
      async getEvaluationScope() {
        return publication;
      }
    },
    async judge(input) {
      judgeCalls++;
      assert.ok(prepareJudgeInput(input).packet);
      return {
        verdict,
        explanation: 'Controlled independent Judge verdict',
        criteria: []
      };
    },
    qualifyModel: () => true
  };
  const service = createV06UploadAssessment(assessmentDependencies);
  return {
    service,assessmentDependencies,
    dependencies:{identityPool,conversationRepository,journal,coordinator,provider,personaAuthority,modeAuthority,target,binding,check,attachment},
    scope,
    persona,
    personaSession,
    sessionId,
    requestId,
    counts: () => ({
      modelCalls,
      toolCalls,
      protectedReads,
      assessmentEffects,
      judgeCalls
    }),
    trace: traces,
    graphEffect,
    sourceRow: () => sourceRow,
    setRetained: value => {
      retained = value;
    },
    retained: () => retained,
    canonicalRow: () => canonicalRow,
    assessmentRow: () => assessmentRow,
    historicalPacket: () => prepareJudgeInput({rubric: HISTORICAL_V2_RUBRIC,
      ...buildRetainedUploadCandidate({binding, personaSession, row: sourceRow, traces, retained,
        graphEffect, qualifyModel: () => true, receiptVersion: HISTORICAL_V2_RUBRIC.version})}),
    revoke: () => {
      active = false;
    },
    setMode: value => {
      mode = value;
    },
    disableCatalog: () => {
      catalogEligible = false;
    }
  };
}
test('actual bound graph trace enters canonical Judge once; saved failure replays without model or effect', async () => {
  const f = await fixture(),
    input = {
      scope: f.scope,
      persona: f.persona,
      personaSession: f.personaSession,
      sessionId: f.sessionId,
      requestId: f.requestId
    };
  assert.deepEqual(await f.service.readOutcome(input), {
    completed: false,
    status: 'unconfirmed',
    modelEvaluated: false
  });
  const outcome = await f.service.runAttempt(input);
  assert.equal(outcome.completed, false);
  assert.equal(outcome.judgment.verdict, 'fail');
  assert.equal(f.counts().judgeCalls, 1);
  assert.equal(f.counts().modelCalls, 2);
  assert.equal(f.counts().toolCalls, 1);
  assert.equal(f.counts().assessmentEffects, 0);
  assert.equal(f.canonicalRow().run_id !== f.sourceRow().result_json.taskMetadata.boundUpload.graphEffect.runId, true);
  assert.deepEqual(await f.service.readOutcome(input), {
    ...outcome,
    replayed: true
  });
  assert.deepEqual(await f.service.runAttempt(input), {
    ...outcome,
    replayed: true
  });
  assert.equal(f.counts().judgeCalls, 1);
  assert.equal(f.counts().toolCalls, 1);
  const guard = await f.service.assertRetainedPacket({
    ...input,
    packet: f.canonicalRow().packet
  });
  await guard.assertCurrent();
});
test('controlled Judge pass commits canonical receipt and saved completion projection', async () => {
  const f = await fixture({
      verdict: 'pass'
    }),
    input = {
      scope: f.scope,
      persona: f.persona,
      personaSession: f.personaSession,
      sessionId: f.sessionId,
      requestId: f.requestId
    };
  const result = await f.service.runAttempt(input);
  assert.equal(result.completed, true);
  assert.equal(result.judgment.verdict, 'pass');
  assert.equal(f.canonicalRow().disposition, 'awarded');
  assert.deepEqual(await f.service.readOutcome(input), {
    ...result,
    replayed: true
  });
  assert.equal(f.counts().judgeCalls, 1);
  assert.equal(f.counts().modelCalls, 2);
  assert.equal(f.counts().toolCalls, 1);
  assert.equal(f.counts().assessmentEffects, 0);
});
test('mutated completed source effect cannot reach canonical Judge', async () => {
  const f = await fixture(),
    input = {
      scope: f.scope,
      persona: f.persona,
      personaSession: f.personaSession,
      sessionId: f.sessionId,
      requestId: f.requestId
    };
  f.graphEffect.status = 'started';
  assert.deepEqual(await f.service.runAttempt(input), {
    completed: false,
    status: 'ineligible',
    modelEvaluated: false
  });
  assert.equal(f.counts().judgeCalls, 0);
});
for (const [name, mutate] of [['selected actor', f => {
  const i = f.trace.findIndex(t => t.kind === 'model_decision');
  f.trace[i] = {
    ...f.trace[i],
    actor: 'task'
  };
}], ['final step', f => {
  const i = f.trace.findLastIndex(t => t.kind === 'model_decision');
  f.trace[i] = {
    ...f.trace[i],
    step: 99
  };
}], ['terminal step', f => {
  f.trace[f.trace.length - 1] = {
    ...f.trace.at(-1),
    step: 99
  };
}], ['extra local call', f => {
  const extra = {
    ...f.trace.find(t => t.kind === 'local_tool_call'),
    event_id: randomUUID()
  };
  f.trace.splice(-1, 0, extra);
  f.sourceRow().result_json.taskMetadata.boundUpload.traceEventIds.splice(-1, 0, extra.event_id);
}]]) test(`actual graph trace mutation ${name} cannot reach Judge`, async () => {
  const f = await fixture(),
    input = {
      scope: f.scope,
      persona: f.persona,
      personaSession: f.personaSession,
      sessionId: f.sessionId,
      requestId: f.requestId
    };
  mutate(f);
  assert.deepEqual(await f.service.runAttempt(input), {
    completed: false,
    status: 'ineligible',
    modelEvaluated: false
  });
  assert.equal(f.counts().judgeCalls, 0);
  assert.equal(f.counts().toolCalls, 1);
});
test('actual assessment service enters POST route and saved GET with bounded canonical DTO', async () => {
  const {
    EventEmitter
  } = require('node:events');
  const {
    createBoundAvatarUploadRouter
  } = require('../server/routes/secureshop/boundAvatarUpload');
  const f = await fixture({
    verdict: 'pass'
  });
  const runtime = Object.fromEntries(['createSession', 'issueToken', 'readRequest', 'run'].map(name => [name, () => {
    throw Error(`Unexpected ${name}`);
  }]));
  const router = createBoundAvatarUploadRouter({
    launches: {
      resolveCapability() {}
    },
    authenticatePersona(_req, _res, next) {
      next();
    },
    graph: runtime,
    saved: {
      async read() {},
      async asset() {}
    },
    assessment: f.service,
    svgAssessment: {runAttempt() {throw Error("Unexpected SVG assessment");}, readOutcome() {throw Error("Unexpected SVG saved outcome");}}
  });
  const handler = (method, path) => {
    const row = router.stack.find(layer => layer.route?.path === path && layer.route.methods[method]);
    assert.ok(row);
    return row.route.stack.at(-1).handle;
  };
  const req = (body = {}, params = {}) => Object.assign(new EventEmitter(), {
    aborted: false,
    ssLaunch: f.scope,
    ssUser: f.persona,
    ssPersonaSession: f.personaSession,
    body,
    params,
    query: {},
    is: () => true
  });
  const res = () => Object.assign(new EventEmitter(), {
    writableEnded: false,
    destroyed: false,
    set() {
      return this;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(value) {
      this.body = value;
      this.writableEnded = true;
      return this;
    }
  });
  const posted = res(),
    saved = res();
  await handler('post', '/agents/customer/avatar-upload/assess')(req({
    sessionId: f.sessionId,
    requestId: f.requestId
  }), posted);
  assert.equal(posted.statusCode, 200);
  assert.deepEqual(Object.keys(posted.body).sort(), ['completed', 'judgment', 'replayed']);
  assert.equal(posted.body.completed, true);
  assert.equal(posted.body.replayed, false);
  assert.equal(posted.body.judgment.verdict, 'pass');
  assert.deepEqual(Object.keys(posted.body.judgment).sort(), ['canRetry', 'evaluationId', 'verdict']);
  await handler('get', '/agents/customer/avatar-upload/assess/:sessionId/:requestId')(req({}, {
    sessionId: f.sessionId,
    requestId: f.requestId
  }), saved);
  assert.equal(saved.statusCode, 200);
  assert.deepEqual(saved.body, {
    ...posted.body,
    replayed: true
  });
  assert.equal(f.counts().judgeCalls, 1);
  assert.equal(f.counts().toolCalls, 1);
});
test('missing canonical first serve, fixed mode and reset cannot reach Judge', async () => {
  for (const negative of ['missing-serve', 'fixed', 'reset']) {
    const f = await fixture(),
      input = {
        scope: f.scope,
        persona: f.persona,
        personaSession: f.personaSession,
        sessionId: f.sessionId,
        requestId: f.requestId
      };
    if (negative === 'missing-serve') f.setRetained(null);
    if (negative === 'fixed') f.setMode('fixed');
    if (negative === 'reset') f.revoke();
    if (negative === 'reset') await assert.rejects(f.service.runAttempt(input));else assert.deepEqual(await f.service.runAttempt(input), {
      completed: false,
      status: 'ineligible',
      modelEvaluated: false
    });
    assert.equal(f.counts().judgeCalls, 0);
    assert.equal(f.counts().toolCalls, 1);
  }
});
test('disabled pending catalog reaches no Judge or canonical publication', async () => {
  const f = await fixture({
    verdict: 'pass'
  });
  f.disableCatalog();
  const input = {
    scope: f.scope,
    persona: f.persona,
    personaSession: f.personaSession,
    sessionId: f.sessionId,
    requestId: f.requestId
  };
  assert.deepEqual(await f.service.runAttempt(input), {
    completed: false,
    status: 'ineligible',
    modelEvaluated: false
  });
  assert.equal(f.counts().judgeCalls, 0);
  assert.equal(f.canonicalRow(), null);
});


test('completed historical V06 v2 pass and false outcomes replay exact packets without regrading; v2 retries are refused', async () => {
  for (const verdict of ['pass', 'fail']) {
    const f = await fixture({verdict});
    const input = {scope: f.scope, persona: f.persona, personaSession: f.personaSession,
      sessionId: f.sessionId, requestId: f.requestId};
    const outcome = await f.service.runAttempt(input), row = f.canonicalRow();
    const prepared = f.historicalPacket();
    assert.ok(prepared.packet && !prepared.evidenceError);
    Object.assign(row, {packet: prepared.packet, evidence_digest: prepared.evidenceDigest,
      rubric_version: HISTORICAL_V2_RUBRIC.version});
    const before = JSON.stringify(row), counts = f.counts();
    assert.deepEqual(await f.service.readOutcome(input), {...outcome, replayed: true});
    assert.deepEqual(await f.service.runAttempt(input), {...outcome, replayed: true});
    assert.equal(JSON.stringify(row), before);
    for (const key of ['modelCalls', 'toolCalls', 'assessmentEffects', 'judgeCalls'])
      assert.equal(f.counts()[key], counts[key]);
    await assert.rejects(f.service.assertRetainedPacket({...input, packet: row.packet}));
    assert.equal(JSON.stringify(row), before);
    assert.equal(f.counts().judgeCalls, counts.judgeCalls);
  }
});

test('historical V06 v2 read rejects altered original quotes, unknown versions and stale authority without Judge work', async () => {
  for (const mutation of ['quote', 'digest', 'version', 'reset', 'fixed', 'foreign']) {
    const f = await fixture(), input = {scope: f.scope, persona: f.persona,
      personaSession: f.personaSession, sessionId: f.sessionId, requestId: f.requestId};
    await f.service.runAttempt(input);
    const row = f.canonicalRow(), original = f.historicalPacket();
    Object.assign(row, {packet: original.packet, evidence_digest: original.evidenceDigest,
      rubric_version: HISTORICAL_V2_RUBRIC.version});
    if (mutation === 'quote') {
      const packet = JSON.parse(row.packet); packet.evidence[1].content += ' altered';
      const changed = prepareJudgeInput(packet);
      Object.assign(row, {packet: changed.packet, evidence_digest: changed.evidenceDigest});
    }
    if (mutation === 'digest') row.evidence_digest = 'f'.repeat(64);
    if (mutation === 'version') row.rubric_version = 'secureshop-upload-extension-bypass-v1';
    if (mutation === 'reset') f.revoke();
    if (mutation === 'fixed') f.setMode('fixed');
    if (mutation === 'foreign') input.personaSession = {...input.personaSession, sessionId: randomUUID()};
    const before = JSON.stringify(row), calls = f.counts().judgeCalls;
    if (['fixed', 'foreign'].includes(mutation)) assert.equal((await f.service.readOutcome(input)).status, 'ineligible', mutation);
    else await assert.rejects(f.service.readOutcome(input));
    assert.equal(JSON.stringify(row), before); assert.equal(f.counts().judgeCalls, calls);
  }
});

module.exports={fixture};
