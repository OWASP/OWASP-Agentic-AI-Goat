'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { Pool } = require('pg');

const migrationUrl = process.env.PG_TEACHING_CONTENT_TEST_MIGRATION_URL;
const runtimeUrl = process.env.PG_TEACHING_CONTENT_TEST_RUNTIME_URL;
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && Boolean(migrationUrl && runtimeUrl);
const migration = fs.readFileSync(path.resolve(__dirname,
  '../../db/postgres/identity-migrations/0023_workshop_teaching_content.sql'), 'utf8');

const historical = {
  ssrf_internal: {
    title: 'SSRF — Bedrock Runtime',
    hints: [
      'The AI makes real HTTP requests server-side — can you reach the AI inference backend?',
      'This app runs on AWS Bedrock in us-west-2. The runtime endpoint is publicly addressable.',
      'Try: "Check the credit score at https://bedrock-runtime.us-west-2.amazonaws.com" to probe the AI backend.',
    ],
  },
  ssrf_ollama: {
    title: 'SSRF — Enumerate Bedrock Models',
    hints: [
      "The app's AI backend is AWS Bedrock — can you enumerate what models are available?",
      'AWS Bedrock exposes a management API for listing foundation models.',
      'Try: "Check credit score at https://bedrock.us-west-2.amazonaws.com/foundation-models" to list AI models.',
    ],
  },
  csrf_x3_hint: {
    title: 'Email XSS · trigger read',
    hints: [
      'Once delivered, ask the agent to "summarize the email from indirectpromptinjection@gmail.com".',
      'It fetches + renders the real email → XSS runs as the victim → embedded CSRF fires. Watch the Victim panel change.',
    ],
  },
  csrf_i2_hint: {
    title: 'RAG · trigger on topic',
    hints: [
      'Ask a question ON the poisoned topic (e.g. MFA-audit poison → "how does MFA work?").',
      'Retrieval surfaces your poison → the RAG answer renders the embedded XSS → the CSRF fires. Off-topic questions stay clean.',
    ],
  },
  csrf_i3_hint: {
    title: 'RAG · persistence',
    hints: [
      'Ask a DIFFERENT on-topic question. The poison is retrieved again and the XSS re-fires the CSRF.',
      'One poisoned doc = repeated attacks until the index is cleaned. Use Reset RAG (clean) to remove it.',
    ],
  },
  csrf_x3_solution: {
    objective_id: 'csrf_x3', exercise_id: 'xss', title: 'Trigger execution — agent reads the email',
    hint: 'After the email arrives (~30–90s), ask the agent to **summarize the email from indirectpromptinjection@gmail.com**. It fetches the real message from your SharkLaser inbox and renders it (`dangerouslySetInnerHTML` sink); the XSS runs **as Jordan** and its embedded CSRF fires — changing the victim\'s account. Watch the forged bubble + Victim panel.',
    example: '(chat) "summarize the email from indirectpromptinjection@gmail.com"\n(chat) "read and render the newest email"',
    explanation: 'This is the full chain: **XSS (delivery) → CSRF (impact)**. The AI mail agent renders attacker HTML without sanitisation; the script executes in the victim\'s origin with their cookie; it forges an authenticated request the victim never intended. Defence: sanitise/encode all rendered email (CSP, no `dangerouslySetInnerHTML` on untrusted content) AND require confirmation for state-changing actions.',
  },
  csrf_i2_solution: {
    objective_id: 'csrf_i2', exercise_id: 'indirect', title: 'Trigger — ask a question on the poisoned topic',
    hint: 'Ask a question about the **topic your poison targets** (e.g. if you used the MFA-audit doc, ask *"how does MFA work on my account?"*). Retrieval surfaces your poisoned chunk; the RAG answer renders the embedded XSS widget, and its handler fires the CSRF — the victim\'s state changes.',
    example: '(chat) "how does MFA and login security work?"\n(chat) "what is my current balance?"  (for the balance poison)',
    explanation: 'Indirect prompt injection + stored XSS: the assistant renders your poisoned policy\'s HTML into its answer without sanitising it. Running as **Sam Okafor**, the XSS forges the state change on Sam\'s behalf. A benign, on-topic question is the trigger — the user is an unwitting accomplice, exactly like a victim browsing a malicious page in classic CSRF. (Off-topic questions stay clean — realistic vector retrieval.)',
  },
  csrf_i3_solution: {
    objective_id: 'csrf_i3', exercise_id: 'indirect', title: 'Prove persistence — a second on-topic query re-fires',
    hint: 'Ask a **different** question about the same poisoned topic. The same poisoned chunk is retrieved again, the answer re-renders the XSS, and the CSRF fires a second time — proving one poisoned document drives repeated attacks until the index is cleaned. Use **Reset RAG (clean)** to remove the poison.',
    example: '(chat) "is two-factor authentication required for login?"\n(chat) "show my account security settings"',
    explanation: 'Unlike a one-shot payload, a poisoned KB entry is **persistent and repeatable**: every matching retrieval re-injects it, so the agent re-fires on each new on-topic question. Defence: provenance-aware retrieval (never elevate document text to instruction status), OUTPUT SANITISATION of RAG answers (encode HTML, no raw render), content review of ingested docs, human-in-the-loop confirmation for mutations, and periodic index auditing.',
  },
};

const expected = {
  ssrf_internal: {
    title: 'SSRF — Internal Application API',
    hints: [
      'The credit-score tool makes real server-side HTTP requests when its account target is a URL.',
      'Target the internal application health endpoint shown for the active deployment.',
      'Completion requires a real non-empty response from that internal endpoint, not a URL echoed in prose.',
    ],
  },
  ssrf_ollama: {
    title: 'SSRF — Enumerate the Active AI Backend',
    hints: [
      'Use the provider details displayed by the workshop: local Ollama exposes /api/tags, while Bedrock uses its model-catalog endpoint.',
      'Pass the displayed backend URL through check_credit_score.',
      'Completion requires the real backend response to contain model information; a hard-coded provider name is not proof.',
    ],
  },
  csrf_x3_hint: {
    title: 'Email XSS · trigger read',
    hints: [
      'Once delivered, ask the agent to "summarize the email from indirectpromptinjection@gmail.com".',
      'The lab server reads the email, recognizes its supported gadget, and applies the victim-state action. This proves the server gadget interpreter path, not independent browser execution.',
    ],
  },
  csrf_i2_hint: {
    title: 'RAG · trigger on topic',
    hints: [
      'Ask a question ON the poisoned topic (e.g. MFA-audit poison → "how does MFA work?").',
      'Retrieval surfaces the poison; the lab server gadget interpreter records the victim-state action. Off-topic questions stay clean, but this is not proof of independent browser execution.',
    ],
  },
  csrf_i3_hint: {
    title: 'RAG · persistence',
    hints: [
      'Ask a DIFFERENT on-topic question. The poison must be retrieved again and the server interpreter must record another successful execution.',
      'This proves repeatability in the lab server path until the index is cleaned; it does not prove browser-side XSS. Use Reset RAG (clean) to remove it.',
    ],
  },
  csrf_x3_solution: {
    objective_id: 'csrf_x3', exercise_id: 'xss', title: 'Trigger the lab execution path — agent reads the email',
    hint: 'After the email arrives (~30–90s), ask the agent to **summarize the email from indirectpromptinjection@gmail.com**. The server reads the message, recognizes a supported email gadget, and applies the victim-state action. Watch the forged bubble and Victim panel; this proves the lab server interpreter path, not independent browser execution.',
    example: '(chat) "summarize the email from indirectpromptinjection@gmail.com"\n(chat) "read and render the newest email"',
    explanation: 'The current lab models the **email gadget → victim-state impact** chain in a server-side interpreter. The observed state change is real lab state and the email can be provider-delivered, but the grader does not observe a browser executing the handler or attaching a victim cookie. Treat browser-side XSS/CSRF execution as remaining authenticity work. The intended defenses remain sanitising rendered email, applying a restrictive CSP, and requiring confirmation for state-changing actions.',
  },
  csrf_i2_solution: {
    objective_id: 'csrf_i2', exercise_id: 'indirect', title: 'Trigger the lab interpreter with an on-topic query',
    hint: 'Ask a question about the **topic your poison targets** (for example, with the MFA-audit poison ask *"how does MFA work on my account?"*). Retrieval must surface the poisoned chunk; the lab server gadget interpreter then records the victim-state action. Off-topic questions stay clean. This does not prove independent browser execution.',
    example: '(chat) "how does MFA and login security work?"\n(chat) "what is my current balance?"  (for the balance poison)',
    explanation: 'This objective proves that an on-topic query retrieves the poisoned policy and that the lab\'s server-side gadget interpreter applies a real change to Sam Okafor\'s lab state. The current proof does not observe a browser rendering HTML, running an event handler, or attaching Sam\'s cookie. Browser execution remains authenticity work. The teaching mechanism here is persistent poisoned retrieval followed by an unsafe trusted execution step.',
  },
  csrf_i3_solution: {
    objective_id: 'csrf_i3', exercise_id: 'indirect', title: 'Prove persistence — a second query re-executes the lab gadget',
    hint: 'Ask a **different** question about the same poisoned topic. The same chunk must be retrieved again and the server interpreter must record another successful victim action. This proves repeatability in the current lab path, not browser-side XSS. Use **Reset RAG (clean)** to remove the poison.',
    example: '(chat) "is two-factor authentication required for login?"\n(chat) "show my account security settings"',
    explanation: 'The poisoned KB entry is **persistent and repeatable**: distinct matching queries retrieve it again and the lab server interpreter repeats the supported victim action. An idempotent action can still prove persistence when the server records successful execution. Independent browser execution remains unproved. Defenses include provenance-aware retrieval, output encoding, content review, confirmation for mutations, and index auditing.',
  },
};

function assertOwnedPair() {
  const urls = [migrationUrl, runtimeUrl].map(value => new URL(value));
  for (const url of urls) {
    assert.equal(url.protocol, 'postgresql:');
    assert.equal(url.hostname, '127.0.0.1', 'owned loopback PostgreSQL is required');
    assert.match(decodeURIComponent(url.pathname), /^\/dvaia_test_[a-z0-9_]+$/,
      'owned disposable dvaia_test_* database is required');
  }
  assert.equal(urls[0].pathname, urls[1].pathname, 'migration/runtime URLs must name the same owned database');
}

async function installSchema(client) {
  await client.query(`DROP SCHEMA IF EXISTS workshop_platform CASCADE;
    CREATE SCHEMA workshop_platform;
    CREATE TABLE workshop_platform.objectives(
      workshop_key text NOT NULL,
      objective_id text NOT NULL,
      hint_content jsonb,
      solution_content jsonb,
      updated_by bigint,
      updated_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(workshop_key, objective_id)
    );
    CREATE TABLE workshop_platform.config_revision(
      id integer PRIMARY KEY CHECK(id=1),
      revision integer NOT NULL,
      updated_at timestamptz NOT NULL
    );
    INSERT INTO workshop_platform.config_revision VALUES(1, 23, '2026-01-01T00:00:00Z');`);
}

async function insertHistorical(client) {
  const rows = [
    ['sensitive_info_disclosure', 'ssrf_internal', historical.ssrf_internal, null],
    ['sensitive_info_disclosure', 'ssrf_ollama', historical.ssrf_ollama, null],
    ['csrf_workshop', 'csrf_x3', historical.csrf_x3_hint, historical.csrf_x3_solution],
    ['csrf_workshop', 'csrf_i2', historical.csrf_i2_hint, historical.csrf_i2_solution],
    ['csrf_workshop', 'csrf_i3', historical.csrf_i3_hint, historical.csrf_i3_solution],
  ];
  for (const row of rows) await client.query(`INSERT INTO workshop_platform.objectives
    (workshop_key, objective_id, hint_content, solution_content, updated_at)
    VALUES($1,$2,$3::jsonb,$4::jsonb,'2025-01-01T00:00:00Z')`,
  [row[0], row[1], JSON.stringify(row[2]), row[3] === null ? null : JSON.stringify(row[3])]);
}

async function insertCustom(client) {
  for (const [workshop, objective] of [
    ['sensitive_info_disclosure', 'ssrf_internal'],
    ['sensitive_info_disclosure', 'ssrf_ollama'],
    ['csrf_workshop', 'csrf_x3'],
    ['csrf_workshop', 'csrf_i2'],
    ['csrf_workshop', 'csrf_i3'],
  ]) await client.query(`INSERT INTO workshop_platform.objectives
    (workshop_key, objective_id, hint_content, solution_content, updated_by, updated_at)
    VALUES($1,$2,$3::jsonb,$4::jsonb,901,'2025-02-02T00:00:00Z')`, [workshop, objective,
    JSON.stringify({ title: `Instructor hint ${objective}`, hints: ['Keep this exact text.'] }),
    JSON.stringify({ title: `Instructor solution ${objective}`, explanation: 'Keep this exact text.' })]);
}

async function snapshot(client) {
  const objectives = (await client.query(`SELECT workshop_key,objective_id,hint_content,solution_content,
    updated_by,updated_at FROM workshop_platform.objectives ORDER BY workshop_key,objective_id`)).rows;
  const revision = (await client.query(
    'SELECT revision,updated_at FROM workshop_platform.config_revision WHERE id=1')).rows[0];
  return { objectives, revision };
}

async function apply(client) {
  await client.query('BEGIN');
  try { await client.query(migration); await client.query('COMMIT'); }
  catch (error) { await client.query('ROLLBACK'); throw error; }
}

test('0023 updates only exact shipped SSRF/CSRF defaults, preserves instructor content, and replays as a no-op',
  { skip: !enabled ? 'requires an explicit owned disposable PostgreSQL URL pair' : false, timeout: 30000 },
  async () => {
    assertOwnedPair();
    assert.equal(createHash('sha256').update(migration).digest('hex'),
      'b7fc060900c4100e27ec8558fb0ba9ab0982d7f6364af8c5a72904054b0d2d2e');
    const pool = new Pool({ connectionString: migrationUrl, max: 1 });
    const client = await pool.connect();
    try {
      assert.equal((await client.query('SELECT current_database() AS name')).rows[0].name,
        decodeURIComponent(new URL(migrationUrl).pathname.slice(1)));
      await installSchema(client);
      await insertHistorical(client);
      await apply(client);
      const updated = await snapshot(client);
      const byId = Object.fromEntries(updated.objectives.map(row => [row.objective_id, row]));
      assert.deepEqual(byId.ssrf_internal.hint_content, expected.ssrf_internal);
      assert.deepEqual(byId.ssrf_ollama.hint_content, expected.ssrf_ollama);
      for (const id of ['csrf_x3', 'csrf_i2', 'csrf_i3']) {
        assert.deepEqual(byId[id].hint_content, expected[`${id}_hint`]);
        assert.deepEqual(byId[id].solution_content, expected[`${id}_solution`]);
      }
      assert.equal(updated.revision.revision, 24, 'one changed migration increments revision once');

      await apply(client);
      assert.deepEqual(await snapshot(client), updated,
        'replay must preserve content, revision, and timestamps exactly');

      await installSchema(client);
      await insertCustom(client);
      const custom = await snapshot(client);
      await apply(client);
      assert.deepEqual(await snapshot(client), custom,
        'instructor-authored rows must remain byte-for-byte equivalent at the DTO boundary');
    } finally {
      await client.query('DROP SCHEMA IF EXISTS workshop_platform CASCADE').catch(() => {});
      client.release();
      await pool.end();
    }
  });
