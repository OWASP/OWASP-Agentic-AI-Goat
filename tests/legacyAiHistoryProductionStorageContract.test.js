'use strict';

// Source contracts only. Native PostgreSQL qualification is required before
// registering this candidate; these checks do not establish runtime safety.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const root = path.resolve(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const candidate = read('docs/modernization/drafts/legacy-ai-history-production-storage.sql');
const historical = read('docs/modernization/drafts/legacy-ai-history-protected-storage.sql');
const baseline = read('db/postgres/identity-migrations/0079_xss_deletion_redaction_recovery_filter.sql');
const cleanupCall = '  PERFORM legacy_ai_private.cleanup_history_for_student_deletion(\n'
  + '    requested_job_id, requested_lease_token, requested_subject_id);\n\n';
function finalizer(source) {
  const start = source.indexOf('CREATE OR REPLACE FUNCTION identity.finalize_student_deletion(');
  assert.ok(start >= 0);
  const end = source.indexOf('END $$;', start);
  assert.ok(end > start);
  return source.slice(start, end + 'END $$;'.length);
}

test('candidate preserves the current finalizer exactly except atomic private cleanup before its first delete', () => {
  const actual = finalizer(candidate);
  assert.equal(actual.split(cleanupCall).length, 2);
  assert.equal(actual.replace(cleanupCall, ''), finalizer(baseline));
  assert.ok(actual.indexOf(cleanupCall) < actual.indexOf('  DELETE FROM'));
  assert.ok(actual.indexOf(cleanupCall) > actual.indexOf("RAISE EXCEPTION 'Deletion subject is unavailable'"));
  assert.match(candidate, /REVOKE ALL ON FUNCTION identity\.finalize_student_deletion\(uuid,uuid,integer\) FROM PUBLIC;/);
  assert.match(candidate, /GRANT EXECUTE ON FUNCTION identity\.finalize_student_deletion\(uuid,uuid,integer\) TO dvaia_identity_runtime;/);
});

test('cleanup uses the existing identity step with live authority and completed predecessors', () => {
  const start = candidate.indexOf('CREATE FUNCTION legacy_ai_private.cleanup_history_for_student_deletion(');
  const end = candidate.indexOf('\n$$;', start);
  const cleanup = candidate.slice(start, end);
  assert.match(cleanup, /deletion_step\.step_key = 'identity' FOR UPDATE/);
  assert.match(cleanup, /cleanup_step\.state NOT IN \('pending', 'failed'\)/);
  assert.match(cleanup, /previous\.ordinal < cleanup_step\.ordinal\s+AND previous\.state <> 'completed'/);
  assert.match(cleanup, /job\.lease_token = requested_lease/);
  assert.match(cleanup, /job\.lease_expires_at > clock_timestamp\(\)/);
  assert.doesNotMatch(cleanup, /step_key = 'legacy_ai_history'|identity_step/);
  // The historical experiment retains its original isolated step contract.
  assert.match(historical, /deletion_step\.step_key = 'legacy_ai_history'/);
});

test('production durable deletion sequence remains unchanged and qualified schema is registered', () => {
  const source = read('server/services/studentDeletionComposition.js');
  const block = source.match(/STUDENT_DELETION_STEPS = Object\.freeze\(\[([\s\S]*?)\]\)/);
  assert.ok(block);
  const steps = [...block[1].matchAll(/'([^']+)'/g)].map(match => match[1]);
  assert.deepEqual(steps, ['revoke_runs', 'secureshop', 'excessive_agency', 'session_disclosure',
    'sql_injection_workshop', 'nosql_injection_workshop', 'mcp_workshop', 'csrf_workshop',
    'direct_prompt_injection', 'indirect_prompt_injection', 'supply_chain_rce', 'ctf',
    'legacy_challenge', 'sensitive_lookup', 'xss', 'finflow', 'identity']);
  assert.match(candidate, /^-- UNREGISTERED PRODUCTION CANDIDATE/);
  assert.doesNotMatch(candidate, /register the durable `legacy_ai_history` deletion|step immediately before `identity`|`legacy_ai_history` step/);
  assert.match(candidate, /retain the existing Student Deletion manifest/);
  const files = fs.readdirSync(path.join(root, 'db/postgres/identity-migrations'));
  assert.ok(files.includes('0080_legacy_ai_private_history.sql'));
  const registered = read('db/postgres/identity-migrations/0080_legacy_ai_private_history.sql');
  const executable = sql => sql.split('\n').filter(line => !line.trimStart().startsWith('--')).join('\n').trim();
  assert.equal(executable(registered), executable(candidate), 'registered SQL must preserve qualified candidate statements');
});
