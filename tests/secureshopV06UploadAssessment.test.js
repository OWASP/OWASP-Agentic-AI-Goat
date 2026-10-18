'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  randomUUID
} = require('node:crypto');
const {
  createV06UploadAssessment,
  assessmentRequestId,
  assessmentRequestIdFor
} = require('../server/services/secureshopV06UploadAssessment');
const {
  createSecureShopV46TraversalAssessment,
  TRAVERSAL_EVIDENCE_CONTRACT
} = require('../server/services/secureshopV46TraversalAssessment');
function fixture(createAssessment = createV06UploadAssessment) {
  const scope = {
    launchId: randomUUID(),
    scenarioId: randomUUID(),
    generation: 2,
    platformOwnerId: 19,
    platformSessionId: 23
  };
  const persona = {
      id: 41,
      role: 'customer'
    },
    personaSession = {
      sessionId: randomUUID(),
      authorityVersion: '2'
    };
  const sessionId = randomUUID(),
    requestId = randomUUID(),
    binding = {
      ...scope,
      shopUserId: 41,
      role: 'customer'
    };
  const scene = require('../server/services/secureshopSceneBinding').createSceneBinding({
    ...scope,
    targetId: randomUUID()
  }, {
    sceneId: randomUUID(),
    sceneGeneration: 1,
    grantId: randomUUID(),
    execution: scope,
    withLease: work => work()
  });
  let mode = 'fixed',
    reads = 0,
    modelCalls = 0,
    judgeCalls = 0;
  const service = createAssessment({
    identityPool: {
      async query() {
        throw Error('fixed mode must not query assessment');
      }
    },
    agentsPool: {
      async query() {
        throw Error('fixed mode must not query assessment turns');
      }
    },
    launches: {
      async assertCurrent(value) {
        assert.equal(value.launchId, scope.launchId);
      }
    },
    conversationRepository: {
      async getBoundSession(id) {
        return {
          id,
          state: 'active',
          purpose: 'secureshop_avatar_upload',
          binding
        };
      },
      async acquireBoundSession() {
        throw Error('fixed mode cannot create assessment session');
      },
      async getTraceEvents() {
        throw Error('fixed mode cannot read traces');
      }
    },
    coordinator: {
      async run() {
        throw Error('fixed mode cannot run coordinator');
      }
    },
    journal: {
      async readUploadRequest() {
        reads++;
        throw Error('fixed mode cannot read original');
      },
      async claim() {
        throw Error('fixed mode cannot claim turn');
      },
      async complete() {},
      async markUncertain() {}
    },
    personaAuthority: {
      capture({
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
          async assertRemoteAdmission() {}
        };
      }
    },
    personaBindings: {
      async capture() {
        throw Error('fixed mode cannot capture assessment persona');
      }
    },
    scenes: {
      async readRetained() {
        return scene;
      }
    },
    modeAuthority: {
      async capture() {
        const captured = mode;
        return {
          snapshot: {
            featureId: 'uploads',
            mode: captured
          },
          async assertCurrent() {
            assert.equal(mode, captured);
          }
        };
      },
      assertToken(value) {
        return value;
      }
    },
    sourceReader: {
      async read() {
        reads++;
        throw Error('fixed mode cannot read audit');
      }
    },
    receipts: {
      async beginEvaluation() {
        throw Error('fixed mode cannot begin evaluation');
      },
      async recordVerdict() {}
    },
    progress: {
      async getGeneration() {
        throw Error('fixed mode cannot read progress');
      }
    },
    publicationModes: {
      async getEvaluationScope() {
        return {
          mode,
          generation: 2,
          modeStamp: 'test'
        };
      }
    },
    async judge() {
      judgeCalls++;
      throw Error('fixed mode cannot call Judge');
    },
    qualifyModel() {
      modelCalls++;
      return true;
    }
  });
  return {
    service,
    scope,
    persona,
    personaSession,
    sessionId,
    requestId,
    counts: () => ({
      reads,
      modelCalls,
      judgeCalls
    }),
    setMode: value => {
      mode = value;
    }
  };
}
test('fixed upload assessment denies before original protected read or Judge', async () => {
  const f = fixture();
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
  assert.deepEqual(await f.service.readOutcome(input), {
    completed: false,
    status: 'ineligible',
    modelEvaluated: false
  });
  assert.deepEqual(f.counts(), {
    reads: 0,
    modelCalls: 0,
    judgeCalls: 0
  });
});
test('sibling owner cannot inspect original upload turn or invoke Judge', async () => {
  const f = fixture();
  await assert.rejects(f.service.runAttempt({
    scope: {
      ...f.scope,
      platformOwnerId: 20
    },
    persona: f.persona,
    personaSession: f.personaSession,
    sessionId: f.sessionId,
    requestId: f.requestId
  }));
  assert.deepEqual(f.counts(), {
    reads: 0,
    modelCalls: 0,
    judgeCalls: 0
  });
});

test('V46 fixed traversal assessment denies before protected source or Judge and owns a distinct request id', async () => {
  const f = fixture(createSecureShopV46TraversalAssessment);
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
  assert.deepEqual(await f.service.readOutcome(input), {
    completed: false,
    status: 'ineligible',
    modelEvaluated: false
  });
  assert.deepEqual(f.counts(), { reads: 0, modelCalls: 0, judgeCalls: 0 });
  assert.equal(f.service.objectiveId, TRAVERSAL_EVIDENCE_CONTRACT.objectiveId);
  assert.notEqual(
    assessmentRequestId(f.sessionId, f.requestId),
    assessmentRequestIdFor(TRAVERSAL_EVIDENCE_CONTRACT.objectiveId, f.sessionId, f.requestId)
  );
});

test('V46 retained packet rejects a sibling original conversation at canonical authority before source or Judge', async () => {
  const f = fixture(createSecureShopV46TraversalAssessment);
  const before = f.counts();
  await assert.rejects(f.service.assertRetainedPacket({
    scope: f.scope, persona: { ...f.persona, id: f.persona.id + 1 }, personaSession: f.personaSession,
    packet: JSON.stringify({ evidence: [{ content: { sessionId: f.sessionId, requestId: f.requestId } }] })
  }), { code: 'CONVERSATION_UNAVAILABLE' });
  assert.deepEqual(f.counts(), before);
});
