'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  randomUUID
} = require('node:crypto');
const {
  createV19FileSummaryTurnReader
} = require('../server/database/postgres/secureshopV19FileSummaryTurnReader');
test('original file summary reader uses exact purpose, owner, session and generation predicates', async () => {
  const sessionId = randomUUID(),
    requestId = randomUUID(),
    binding = {
      launchId: randomUUID(),
      scenarioId: randomUUID(),
      generation: 2,
      platformOwnerId: 5,
      platformSessionId: 6,
      shopUserId: 7,
      role: 'customer'
    };
  const row = {
    session_id: sessionId,
    request_id: requestId,
    status: 'completed',
    request_hash: 'a'.repeat(64),
    request_version: 1,
    result_json: {}
  };
  let released = 0,
    queries = 0;
  const reader = createV19FileSummaryTurnReader({
    pool: {
      async connect() {
        return {
          async query(sql, args) {
            queries++;
            for (const field of ['platform_launch_id', 'platform_scenario_id', 'platform_launch_generation', 'original_platform_owner_id', 'original_platform_session_id', 'user_id', 'role', 'conversation_purpose']) assert.ok(sql.includes(field));
            assert.deepEqual(args, [sessionId, requestId, 'secureshop_file_summary', binding.launchId, binding.scenarioId, 2, 5, 6, 7, 'customer']);
            return {
              rows: [row]
            };
          },
          release() {
            released++;
          }
        };
      }
    }
  });
  assert.equal(await reader.readFileSummaryRequest({
    sessionId,
    requestId,
    binding,
    purpose: 'secureshop_file_summary'
  }), row);
  await assert.rejects(reader.readFileSummaryRequest({
    sessionId,
    requestId,
    binding,
    purpose: 'persona_inbox'
  }));
  assert.equal(queries, 1);
  assert.equal(released, 1);
});
