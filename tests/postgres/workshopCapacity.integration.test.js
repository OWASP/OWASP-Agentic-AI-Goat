'use strict';

// This gate measures authenticated dashboard traffic on real PostgreSQL. It
// deliberately makes no claim about actor/Judge inference or cloud capacity.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const bcrypt = require('bcryptjs');
const { performance } = require('node:perf_hooks');
const { createPool } = require('../../server/database/postgres');
const { initializeIdentityRepository, createIdentityRepository } = require('../../server/database/postgres/identityRepository');
const { seedWorkshopPlatform } = require('../../server/database/postgres/workshopPlatformSeed');
const { createWorkshopProgressRepository } = require('../../server/database/postgres/workshopProgressRepository');
const { createWorkshopConfigRepository } = require('../../server/database/postgres/workshopConfigRepository');
const { createPostgresIdentityAdapter } = require('../../server/services/postgresIdentityAdapter');
const { createPostgresAdminAuth } = require('../../server/middleware/postgresAdminAuth');
const { createPostgresWorkshopRouter } = require('../../server/routes/postgresWorkshop');

const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && process.env.OWASP_AI_GOAT_CAPACITY_QUALIFICATION === 'yes';

test('200 real PostgreSQL sessions preserve dashboard ownership and projection parity under a burst',
  { skip: !enabled, timeout: 180000 }, async () => {
    const urls = ['PG_CAPACITY_MIGRATION_URL', 'PG_CAPACITY_RUNTIME_URL'].map(key => new URL(process.env[key]));
    for (const url of urls) {
      assert.equal(url.hostname, '127.0.0.1');
      assert.match(url.pathname, /^\/owasp_ai_goat_test_capacity_[a-z0-9_]+$/);
    }
    assert.equal(urls[0].host, urls[1].host);
    assert.equal(urls[0].pathname, urls[1].pathname);
    const migration = createPool(process.env, 'PG_CAPACITY_MIGRATION_URL', { purpose: 'migration' });
    const pool = createPool(process.env, 'PG_CAPACITY_RUNTIME_URL', { purpose: 'control' });
    let server;
    try {
      await initializeIdentityRepository(pool, migration);
      await seedWorkshopPlatform(migration);
      const repository = createIdentityRepository(pool);
      const progress = createWorkshopProgressRepository(pool);
      const config = createWorkshopConfigRepository(pool);
      const adapter = createPostgresIdentityAdapter({ repository, progress, jwtSecret: 'owned-capacity-fixture-secret' });
      const passwordHash = await bcrypt.hash('OwnedCapacityFixture', 4);
      const learners = [];
      // Provisioning is excluded from timing; this is session-authenticated
      // request capacity, not a benchmark of password hashing or registration.
      for (let index = 0; index < 200; index++) {
        const user = await repository.createUser({ username: `capacity-${index}`,
          email: `capacity-${index}@example.test`, passwordHash });
        const session = await adapter.createSession(await repository.findCredentialById(user.id),
          { get: () => null, ip: '127.0.0.1' });
        const seconds = index + 1;
        await migration.query(`INSERT INTO workshop_platform.time_tracking
          (user_id,workshop_key,session_start,last_heartbeat,duration_seconds)
          VALUES($1,'sql_injection_workshop',now()-interval '10 minutes',now(),$2)`, [user.id, seconds]);
        learners.push({ token: session.token, seconds });
      }
      const app = express();
      let inFlight = 0, maxInFlight = 0;
      app.use((_req, res, next) => {
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        let retired = false;
        const retire = () => { if (!retired) { retired = true; inFlight--; } };
        res.once('finish', retire);
        res.once('close', retire);
        next();
      });
      app.use('/api/workshop', createPostgresWorkshopRouter({ stores: { pool, progress, config },
        authenticateToken: createPostgresAdminAuth(adapter).authenticateToken }));
      server = app.listen(0, '127.0.0.1');
      await new Promise(resolve => server.once('listening', resolve));
      const base = `http://127.0.0.1:${server.address().port}/api/workshop`;
      const latencies = [], failures = [];
      let maxConnections = 0, maxWaiting = 0;
      const sampler = setInterval(() => {
        maxConnections = Math.max(maxConnections, pool.totalCount);
        maxWaiting = Math.max(maxWaiting, pool.waitingCount);
      }, 10);
      const started = performance.now();
      try {
        await Promise.all(learners.map(async (learner, index) => {
          try {
            const bodies = await Promise.all(['/student/stats', '/progress', '/challenges'].map(async route => {
              const begin = performance.now();
              const response = await fetch(base + route, { headers: { authorization: `Bearer ${learner.token}` },
                signal: AbortSignal.timeout(30000) });
              const body = await response.json();
              latencies.push(performance.now() - begin);
              assert.equal(response.status, 200);
              return body;
            }));
            const [stats, projected, challenges] = bodies;
            assert.equal(stats.totalTime, learner.seconds, `owner ${index} time`);
            assert.equal(stats.completedObjectives, 0);
            assert.deepEqual(projected.challenges, challenges.challenges);
            assert.equal(stats.totalObjectives, projected.challenges.reduce((sum, row) => sum + row.objectiveCount, 0));
            assert.equal(projected.challenges.reduce((sum, row) => sum + row.timeSpentSeconds, 0), learner.seconds);
          } catch (error) { failures.push({ learner: index, code: error.code || error.name }); }
        }));
      } finally { clearInterval(sampler); }
      latencies.sort((a, b) => a - b);
      console.log(JSON.stringify({ qualification: 'postgres-authenticated-dashboards', learners: 200,
        requests: latencies.length, failures, totalMs: Math.round(performance.now() - started),
        p50Ms: Math.round(latencies[Math.floor(latencies.length * 0.5)] || 0),
        p95Ms: Math.round(latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * 0.95))] || 0),
        maxConnections, maxWaiting, maxInFlight, configuredPoolMax: pool.options.max,
        inference: 'not exercised', registration: 'outside measured burst' }));
      assert.deepEqual(failures, []);
      assert.equal(latencies.length, 600);
      assert.ok(maxInFlight >= 200, `Observed only ${maxInFlight} overlapping requests`);
      assert.equal(inFlight, 0);
      assert.ok(maxConnections <= pool.options.max);
    } finally {
      if (server) await new Promise(resolve => server.close(resolve));
      await Promise.allSettled([pool.end(), migration.end()]);
    }
  });
