'use strict';

const path = require('node:path');
const { createHash } = require('node:crypto');
const { Pool } = require('pg');
const { createFinflowTraversalTargetRepository } = require('../../server/database/postgres/finflowTraversalTargetRepository');
const { createFinflowTraversalManager, finflowOwnerKey } = require('../../server/services/finflowTraversalArtifacts');

if (process.env.PG_TEST_DISPOSABLE !== 'yes' || process.env.FINFLOW_TRAVERSAL_ISOLATED !== '1'
    || !process.send) throw new Error('Owned FinFlow traversal worker boundary required');

const pool = new Pool({ connectionString: process.env.FINFLOW_WORKSHOP_DATABASE_URL, max: 1,
  connectionTimeoutMillis: 5000, statement_timeout: 30000, lock_timeout: 5000,
  application_name: 'dvaia-finflow-traversal-worker' });
const repository = createFinflowTraversalTargetRepository({ pool });
const manager = createFinflowTraversalManager({ repository,
  root: path.resolve(process.env.FINFLOW_TRAVERSAL_TARGET_ROOT) });
const execution = Object.freeze({ ownerId: process.env.FINFLOW_TRAVERSAL_OWNER,
  ownerKey: finflowOwnerKey(process.env.FINFLOW_TRAVERSAL_OWNER),
  durableGeneration: process.env.FINFLOW_TRAVERSAL_GENERATION,
  runId: process.env.FINFLOW_TRAVERSAL_RUN_ID, check: async () => {} });

process.once('message', async message => {
  if (message !== 'go') throw new Error('Invalid worker release');
  try {
    const artifact = await manager.read({ execution, toolName: 'get_transaction_history',
      params: { account_id: '../../sensitive_files/config/secrets.env' }, resultPrefix: 'worker' });
    process.send({ ok: true, sha256: createHash('sha256').update(artifact.content).digest('hex') });
  } catch (error) {
    process.send({ ok: false, code: error?.code || error?.name || 'worker_failure' });
  } finally {
    await pool.end();
  }
});

process.send('ready');
