'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createWorkshopTimeHandlers } = require('../server/routes/workshopTimeHandlers');

test('heartbeat reports invalid and stale scope distinctly from storage failures', async () => {
  for (const [code, expected] of Object.entries({ BAD_REQUEST: 400, AUTH_REQUIRED: 401,
    NOT_FOUND: 404, STALE_GENERATION: 409, INSTANCE_SCOPE_REQUIRED: 409,
    GRADE_STORE_NOT_READY: 503, INTERNAL_DB_ERROR: 500, constructor: 500, toString: 500,
    ['__proto__']: 500 })) {
    let status, body;
    const handler = createWorkshopTimeHandlers({ timeService: {
      async recordHeartbeat(input) {
        assert.equal(input.userId, 19);
        assert.equal(input.instanceScope, undefined);
        throw Object.assign(new Error('private failure details'), { code });
      },
    } });
    await handler.recordHeartbeat({ user: { id: 19 }, body: { workshopKey: 'secureshop_agent_security',
      instanceScope: { launchId: 'learner supplied' } } }, {
      status(value) { status = value; return this; }, json(value) { body = value; },
    });
    assert.equal(status, expected, code);
    assert.equal(body.code, code);
    assert.equal(body.error, expected < 500 ? 'private failure details' : 'Failed to record workshop time');
  }
});
