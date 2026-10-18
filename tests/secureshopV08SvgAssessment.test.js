'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  randomUUID
} = require('node:crypto');
const {
  createV08SvgAssessment
} = require('../server/services/secureshopV08SvgAssessment');
function fixture() {
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
    judgeCalls = 0,
    browserCalls = 0;
  const service = createV08SvgAssessment({
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
      async read() { reads++; throw Error('fixed mode cannot read SVG source'); },
      async mint() { throw Error('fixed mode cannot mint SVG capability'); }
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
    },
    browserQualification: { async qualify() { browserCalls++; throw Error('fixed mode cannot invoke browser'); } }
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
      judgeCalls,
      browserCalls
    }),
    setMode: value => {
      mode = value;
    }
  };
}
test('fixed SVG assessment denies before original protected read or Judge', async () => {
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
    judgeCalls: 0,
    browserCalls: 0
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
    judgeCalls: 0,
    browserCalls: 0
  });
});
