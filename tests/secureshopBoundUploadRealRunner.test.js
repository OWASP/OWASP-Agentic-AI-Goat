'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createBoundAgentRunner
} = require(process.cwd() + '/server/services/secureshopBoundAgentRunner');
const {
  createSecureShopUploadExecutionConfig,
  UPLOAD_TOOL
} = require('../server/services/secureshopUploadExecutionConfig');
const scope = {
    launchId: '91000000-0000-4000-8000-000000000001',
    scenarioId: '91000000-0000-4000-8000-000000000002',
    generation: 3,
    platformOwnerId: 71,
    platformSessionId: 81
  },
  persona = {
    id: 91,
    role: 'customer'
  },
  sid = '81000000-0000-4000-8000-000000000001',
  rid = '82000000-0000-4000-8000-000000000001';
test('real BoundAgentRunner executes one closed local upload tool under its coordinator effect', async () => {
  const messages = [],
    effects = [],
    observed = [];
  const conversations = {
    async assertOwned() {},
    async getMessages() {
      return messages;
    }
  };
  const repository = {
    async appendMessage(_s, _b, m) {
      messages.push(m);
    },
    async getTokens() {
      return 0;
    },
    async addTokens() {},
    async appendTraces() {}
  };
  const journal = {
    async claim() {
      return {
        status: 'claimed'
      };
    },
    async complete() {},
    async markUncertain() {}
  };
  const turns = {
    async run(_s, _b, _p, _o, work) {
      return work({
        identity: {
          runId: 'run',
          ownerKey: 'owner',
          generation: 1,
          durableGeneration: '2'
        },
        async check() {},
        async effectWithReceipt(key, fn) {
          return {
            value: await fn(),
            receipt: {
              version: 1,
              runId: 'run',
              ownerKey: 'owner',
              generation: '2',
              effectKey: `${rid}:${key}`,
              status: 'completed'
            }
          };
        },
        async trace() {}
      });
    }
  };
  const responses = [{
    stop_reason: 'tool_use',
    tool_uses: [{
      id: 'call',
      name: UPLOAD_TOOL,
      args: {}
    }]
  }, {
    stop_reason: 'end_turn',
    text: 'uploaded'
  }];
  const config = createSecureShopUploadExecutionConfig({
    filename: 'lesson.php',
    byteCount: 4
  });
  let writes = 0;
  const runner = createBoundAgentRunner({
    turns,
    conversations,
    repository,
    journal,
    ...config,
    provider: {
      async chat() {
        return responses.shift();
      },
      async finalResponse() {
        return responses.shift();
      }
    },
    pool: {
      async callTool() {
        throw Error('external forbidden');
      }
    },
    createLocalTools: () => new Map([[UPLOAD_TOOL, async args => {
      assert.deepEqual(args, {});
      writes++;
      return {
        content: [{
          type: 'text',
          text: '{"ok":true}'
        }]
      };
    }]]),
    observeLocalTool: p => observed.push(p)
  });
  const out = await runner.run({
    sessionId: sid,
    requestId: rid,
    scope,
    persona,
    message: 'upload attached file'
  });
  assert.equal(out.text, 'uploaded');
  assert.equal(writes, 1);
  assert.equal(observed.length, 1);
  assert.equal(observed[0].observation.tool, UPLOAD_TOOL);
  assert.deepEqual(observed[0].observation.args, {});
  assert.equal(JSON.stringify(observed).includes('lesson.php'), false);
});
