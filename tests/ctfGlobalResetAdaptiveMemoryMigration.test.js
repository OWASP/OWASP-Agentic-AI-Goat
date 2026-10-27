'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const root = path.resolve(__dirname, '..');
const migrations = path.join(root, 'db/postgres/identity-migrations');
const predecessor = fs.readFileSync(path.join(migrations, '0105_ctf_lifecycle_projection.sql'), 'utf8');
const successor = fs.readFileSync(path.join(migrations, '0154_ctf_global_reset_adaptive_memory.sql'), 'utf8');
const sha = value => createHash('sha256').update(value).digest('hex');

test('0154 accepts only the unmodified 0105 ACK and changes one ordered reset branch', () => {
  assert.equal(sha(predecessor), '98718eafed5313037de17586a7c7b88f09dd4e45721fcc40be1b11529589fd1d');
  const body = predecessor.match(/CREATE FUNCTION identity\.ack_ctf_projection\([\s\S]*? AS \$\$([\s\S]*?)\$\$;/)?.[1];
  assert(body);
  assert.equal(sha(body), 'ed13ddf23f9fe18fe7932295d97eb5f093bb485ac3cf7eeaa87d2d0662d54e1e');
  const old = successor.match(/old_branch text := \$old\$([\s\S]*?)\$old\$/)?.[1];
  const replacement = successor.match(/new_branch text := \$new\$([\s\S]*?)\$new\$/)?.[1];
  assert(old && replacement);
  assert.equal(body.split(old).length, 2, 'exactly one reset branch may match');
  assert.equal(replacement, old.replace(
    '  UPDATE identity.ctf_participant_bindings SET active=false,applied_sequence=p_sequence,applied_operation_id=p_operation;',
    '  UPDATE identity.ctf_participant_bindings SET active=false,applied_sequence=p_sequence,applied_operation_id=p_operation;\n  DELETE FROM identity.ctf_adaptive_memory;'));
  const rewritten = body.replace(old, replacement);
  assert.equal(rewritten.split('DELETE FROM identity.ctf_adaptive_memory;').length, 2);
  assert(rewritten.indexOf("IF ev.state IN ('applied','blocked') THEN") <
    rewritten.indexOf('DELETE FROM identity.ctf_adaptive_memory;'));
  assert(rewritten.indexOf('DELETE FROM identity.ctf_adaptive_memory;') <
    rewritten.indexOf("UPDATE identity.ctf_outbox AS delivered SET state='applied'"));
  assert.match(successor, /p\.prosecdef AND l\.lanname='plpgsql'/);
  assert.match(successor, /p\.proconfig=ARRAY\['search_path=pg_catalog'\]/);
  assert.match(successor, /CREATE OR REPLACE FUNCTION identity\.ack_ctf_projection\(\s*p_operation uuid,p_sequence bigint,p_command_hash text,p_result text,p_result_hash text\)/);
  assert.match(successor, /REVOKE ALL ON FUNCTION identity\.ack_ctf_projection\(uuid,bigint,text,text,text\) FROM PUBLIC/);
  assert.match(successor, /GRANT EXECUTE ON FUNCTION identity\.ack_ctf_projection\(uuid,bigint,text,text,text\) TO dvaia_identity_runtime/);
});

test('0154 is the next identity migration and does not change unrelated migration bytes', () => {
  const names = fs.readdirSync(migrations).filter(name => /^\d{4}_.*\.sql$/.test(name)).sort();
  assert.equal(names.at(-1), '0154_ctf_global_reset_adaptive_memory.sql');
  assert.equal(names.at(-2), '0153_secureshop_external_test_mail.sql');
  assert.equal(sha(fs.readFileSync(path.join(migrations, names.at(-2)))),
    '03525840db356840068220ef922ef472c4317808e8b55d7094d35875358e7e72');
});
