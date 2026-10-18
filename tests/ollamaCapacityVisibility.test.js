'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { OllamaService } = require('../server/services/ollamaService');

test('Ollama health and stats expose configured scheduler capacity without contacting a model', async () => {
  const service = new OllamaService('http://owned-capacity.fixture');
  service.scheduler = {
    snapshot: () => ({ active: 2, queued: 5, concurrency: 3, queueLimit: 17 }),
  };
  service.connectionPool.get = async () => ({ data: { models: [{ name: 'llama3.1:8b' }] } });

  const healthy = await service.healthCheck();
  assert.equal(healthy.status, 'healthy');
  assert.deepEqual(
    { concurrent_requests: healthy.concurrent_requests, max_concurrent: healthy.max_concurrent, queue_length: healthy.queue_length, queue_limit: healthy.queue_limit },
    { concurrent_requests: 2, max_concurrent: 3, queue_length: 5, queue_limit: 17 },
  );

  service.connectionPool.get = async () => { throw new Error('owned health failure'); };
  const unhealthy = await service.healthCheck();
  assert.equal(unhealthy.status, 'unhealthy');
  assert.equal(unhealthy.error, 'owned health failure');
  assert.deepEqual(
    { concurrent_requests: unhealthy.concurrent_requests, max_concurrent: unhealthy.max_concurrent, queue_length: unhealthy.queue_length, queue_limit: unhealthy.queue_limit },
    { concurrent_requests: 2, max_concurrent: 3, queue_length: 5, queue_limit: 17 },
  );

  assert.deepEqual(
    (({ concurrent_requests, max_concurrent, queue_length, queue_limit }) => ({ concurrent_requests, max_concurrent, queue_length, queue_limit }))(service.getStats()),
    { concurrent_requests: 2, max_concurrent: 3, queue_length: 5, queue_limit: 17 },
  );
});
