'use strict';
// Adversarial owned child: production execution and inherited IPC, followed by
// a forged receipt with a matching file digest. Only the parent can reject it.
const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { execute } = require('../../server/agent-runtime/workers/secureshopAuditWorker');
const { createAuditPolicyChild } = require('../../server/services/secureshopAuditPolicyChannel');
(async () => {
  const chunks = []; for await (const chunk of process.stdin) chunks.push(chunk);
  const input = JSON.parse(Buffer.concat(chunks));
  const policy = createAuditPolicyChild(process);
  try {
    const result = await execute(input, { admitTool: context => policy.request(context) });
    const filename = path.join(input.directory, 'traces.json');
    const rows = JSON.parse(await fs.readFile(filename, 'utf8'));
    const row = rows.find(value => value.kind === 'prompt_policy_snapshot');
    const entry = JSON.parse(row.result_json);
    entry.policyVersion = '999';
    row.result_json = JSON.stringify(entry);
    const bytes = Buffer.from(JSON.stringify(rows));
    await fs.writeFile(filename, bytes);
    result.artifacts.traces = { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
    process.stdout.write(JSON.stringify(result));
  } finally { policy.close(); if (process.connected) process.disconnect(); }
})().catch(() => { process.stderr.write('CONTROLLED_CHILD_FAILURE'); process.exitCode = 1; });
