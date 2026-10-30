'use strict';

// Controlled presentation facet, not a model qualification. Native admission is
// deliberately absent until the shared launcher's distinct Q05 contract exists.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const BROWSER_PREFIX = 'SECURESHOP_Q05_REVIEW_MODERATION_';
const SELECTOR = 'SECURESHOP_Q05_REVIEW_MODERATION_BROWSER_NATIVE';
const BUTTON = '[data-testid="reviews-moderate-all"]';
const POST = '/api/secureshop/merchant/reviews/moderate-all';
const DISCLOSURE = 'Clicking Moderate pending lets the model approve or reject up to 100 pending reviews for your products, in batches.';
const MODEL = 'controlled-q05-review-moderation';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SCOPE = 'q05-review-moderation-rendered-controlled';
const ASSERTION = 'standalone Q05 disclosed review moderation click applies one owned controlled decision and stale authority has no effect';
const FLAGS = Object.freeze(['passed', 'isolatedStores', 'physicalDisclosure', 'noPreClickPost',
  'physicalModeration', 'durableBoundEffect', 'exactReadback', 'staleAuthorityNoEffect',
  'siblingPreserved', 'fixtureCleaned', 'zeroActualModel', 'zeroJudge']);

function selector(env) {
  if (env[SELECTOR] === undefined) return false;
  assert.equal(env[SELECTOR], '1', 'Q05 selector must be explicit');
  const others = Object.keys(env).filter(key => key !== SELECTOR
    && /^SECURESHOP_.*(?:BROWSER_NATIVE|ROLE_CHOICES_NATIVE)$/.test(key) && env[key] === '1');
  assert.deepEqual(others, [], 'Q05 must not alias another rendered cohort');
  return true;
}
function assertEvidencePath(workspace, filename) {
  assert.equal(path.resolve(workspace), workspace); assert.equal(fs.realpathSync(workspace), workspace);
  assert.equal(path.resolve(filename), filename);
  assert.equal(path.basename(filename), 'q05-review-moderation-rendered.json');
  const run = path.dirname(filename);
  assert.match(path.basename(run), /^run-[A-Za-z0-9_-]+$/);
  assert.equal(path.dirname(run), path.join(workspace, 'tasks', 'qualification'));
  for (const directory of [path.dirname(run), run]) {
    const stat = fs.lstatSync(directory);
    assert.ok(stat.isDirectory() && !stat.isSymbolicLink());
    assert.equal(stat.uid, process.getuid()); assert.equal(stat.mode & 0o777, 0o700);
    assert.equal(fs.realpathSync(directory), directory);
  }
  assert.throws(() => fs.lstatSync(filename), error => error.code === 'ENOENT');
}

function validateBrowserGrant(grant, expected) {
  assert.deepEqual(Object.keys(grant).sort(), ['version', 'cohort', 'launcherPid', 'workerPid',
    'nonce', 'workspace', 'evidencePath', 'buildSha256', 'snapshotSha256', 'outerSandbox',
    'chromium', 'chromiumSha256'].sort());
  assert.equal(grant.version, 1); assert.equal(grant.cohort, 'q05-review-moderation-browser');
  assert.equal(grant.outerSandbox, 'repository-only'); assert.match(grant.nonce, /^[a-f0-9]{64}$/);
  for (const [key, value] of Object.entries(expected)) assert.equal(grant[key], value, key);
}

async function admitBrowser(env, { workspace, evidencePath, executablePath }) {
  assert.equal(selector(env), true); assert.equal(env[`${BROWSER_PREFIX}TEST_NO_SANDBOX`], '1');
  assert.equal(env.PG_TEST_DISPOSABLE, 'yes'); assert.equal(env.NODE_ENV, 'test');
  assert.equal(env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE, workspace); assert.equal(workspace, process.cwd());
  assertEvidencePath(workspace, evidencePath);
  const run = path.dirname(evidencePath), temporary = path.join(run, 'runtime/tmp');
  assert.equal(env.TMPDIR, temporary); assert.equal(env.MAC_CHROMIUM_TMPDIR, temporary);
  const privateDirectory = directory => {
    const info = fs.lstatSync(directory);
    assert.ok(info.isDirectory() && !info.isSymbolicLink() && info.uid === process.getuid());
    assert.equal(info.mode & 0o777, 0o700); assert.equal(fs.realpathSync(directory), directory);
  };
  for (const directory of [run, path.join(run, 'runtime'), temporary]) privateDirectory(directory);
  assert.equal(fs.realpathSync(executablePath), executablePath);
  assert.equal(env.PUPPETEER_EXECUTABLE_PATH, executablePath);
  for (const key of ['BROWSER_SHA256', 'BUILD_SHA256', 'SNAPSHOT_SHA256'])
    assert.match(env[BROWSER_PREFIX + key], /^[a-f0-9]{64}$/);
  const recordPath = path.join(run, 'q05-review-moderation-browser-birth.json');
  const ackPath = path.join(run, 'q05-review-moderation-browser-ack.json');
  assert.equal(env[BROWSER_PREFIX + 'BROWSER_RECORD_PATH'], recordPath);
  assert.equal(env[BROWSER_PREFIX + 'BROWSER_ACK_PATH'], ackPath);
  for (const file of [recordPath, ackPath]) assert.throws(() => fs.lstatSync(file), error => error.code === 'ENOENT');
  assert.equal(env.SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT, path.join(workspace, 'tests/postgres/secureshop_darwin_browser_birth.py'));
  assert.ok(path.isAbsolute(env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON));
  assert.equal(fs.realpathSync(env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON), env.SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON);
  const build = await require('../postgres/adminQ05RenderedScenario').buildInventory(path.join(workspace, 'client/build'));
  assert.equal(build.sha256, env[BROWSER_PREFIX + 'BUILD_SHA256']);
  const grant = await require('./inheritedFifoGrant').readInheritedFifoGrant(env, BROWSER_PREFIX + 'ADMISSION_FD', 'Q05 review moderation');
  validateBrowserGrant(grant, { launcherPid: process.ppid, workerPid: process.pid, workspace, evidencePath,
    buildSha256: build.sha256, snapshotSha256: env[BROWSER_PREFIX + 'SNAPSHOT_SHA256'],
    chromium: executablePath, chromiumSha256: env[BROWSER_PREFIX + 'BROWSER_SHA256'] });
  return {
    browserArgs({ profile, origin }) {
      privateDirectory(profile); assert.equal(path.dirname(profile), temporary);
      assert.match(path.basename(profile), /^owasp-ai-goat-q05-review-[A-Za-z0-9_-]+$/);
      const url = new URL(origin); assert.equal(url.origin, origin); assert.equal(url.hostname, '127.0.0.1');
      assert.equal(url.protocol, 'http:'); assert.ok(Number(url.port) > 0 && Number(url.port) <= 65535);
      return ['--no-sandbox', '--disable-background-networking', '--disable-component-update',
        '--disable-domain-reliability', '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
        '--proxy-server=http://blocked.invalid:9', '--proxy-bypass-list=127.0.0.1;localhost;[::1]',
        '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost, EXCLUDE [::1]'];
    },
    async acknowledgeBrowser({ browser, profile }) {
      privateDirectory(profile); assert.equal(path.dirname(profile), temporary);
      const pid = browser.process()?.pid;
      return acknowledgeRecord({ workspace, env, pid, profile, executablePath, recordPath, ackPath });
    },
  };
}

// Dependency injection is for deterministic protocol tests only. The admitted
// browser method above always supplies the real filesystem, inspector and clock.
async function acknowledgeRecord({ workspace, env, pid, profile, executablePath, recordPath, ackPath }, {
  capture = require('./secureshopDarwinBrowserBirth').captureBrowserRecord,
  files = fs, now = Date.now, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
} = {}) {
      const record = capture({ root: workspace,
        kind: 'q05_review_moderation_browser', pid, executablePath,
        executableSha256: env[BROWSER_PREFIX + 'BROWSER_SHA256'], env });
      assert.equal(record.schemaVersion, 2);
      const bytes = `${JSON.stringify(record)}\n`;
      const staging = `${recordPath}.${process.pid}.tmp`;
      await files.promises.writeFile(staging, bytes, { flag: 'wx', mode: 0o600 });
      // Publish atomically without replacing an existing authority record.
      await files.promises.link(staging, recordPath);
      await files.promises.unlink(staging);
      const expected = { schemaVersion: 1, recordSha256: createHash('sha256').update(bytes).digest('hex'),
        parentPid: process.pid, browserPid: pid, profile };
      const deadline = now() + 15000;
      while (now() < deadline) {
        try {
          const info = files.lstatSync(ackPath);
          assert.ok(info.isFile() && !info.isSymbolicLink() && info.uid === process.getuid());
          assert.equal(info.mode & 0o777, 0o600); assert.ok(info.size <= 4096);
          assert.deepEqual(JSON.parse(files.readFileSync(ackPath, 'utf8')), expected); return;
        } catch (error) { if (error.code !== 'ENOENT') throw error; }
        await sleep(25);
      }
      throw Error('Q05 independent live browser birth ACK unavailable');
}

async function acknowledgeOrClose(admission, browser, profile) {
  try { await admission.acknowledgeBrowser({ browser, profile }); }
  catch (primary) {
    try { await browser.close(); }
    catch (cleanup) { throw new AggregateError([primary, cleanup], 'Q05 browser ACK and cleanup failed'); }
    throw primary;
  }
}

function createControlledProvider() {
  let reviewId, body;
  let calls = 0;
  const provenance = { provider: 'mock', model: MODEL, mocked: true, fallback: false };
  const final = () => ({ ...provenance, stop_reason: 'end_turn', responseMode: 'structured_final',
    text: 'Controlled moderation completed.' });
  return Object.freeze({
    config: Object.freeze({ ...provenance }),
    arm(value) {
      assert.equal(reviewId, undefined); assert.equal(calls, 0);
      assert.ok(Number.isSafeInteger(value.reviewId) && value.reviewId > 0);
      assert.equal(typeof value.body, 'string'); assert.ok(value.body.length > 0);
      ({ reviewId, body } = value);
    },
    async chat(input) {
      assert.ok(reviewId, 'provider cannot run before the real owned review is seeded');
      calls += 1;
      assert.ok(calls <= 3, 'one controlled moderation admits three provider decisions only');
      if (calls === 3) return final();
      const name = calls === 1 ? 'review-moderator.moderate_pending' : 'review-moderator.approve';
      assert.ok(input.tools.some(tool => `${tool.agent}.${tool.tool}` === name));
      if (calls === 2) {
        const observation = JSON.parse(input.messages.at(-1).content);
        assert.equal(observation.ok, true);
        assert.equal(observation.count, 1);
        assert.equal(observation.reviews.length, 1);
        assert.equal(observation.reviews[0].id, reviewId);
        assert.equal(observation.reviews[0].body, body);
        assert.equal(observation.reviews[0].status, 'pending');
      }
      return { ...provenance, stop_reason: 'tool_use', tool_uses: [{ id: `q05-${calls}`,
        name, args: calls === 1 ? { limit: 1 } : { review_id: reviewId } }] };
    },
    async finalResponse() { calls += 1; assert.equal(calls, 3); return final(); },
    counts: () => ({ controlledProviderCalls: calls, actualModelCalls: 0, judgeCalls: 0, canonicalCredit: 0 }),
  });
}

function recordControlledCounts(status, provider) {
  const counts = provider.counts();
  assert.ok(Number.isSafeInteger(counts.controlledProviderCalls)
    && counts.controlledProviderCalls >= 0 && counts.controlledProviderCalls <= 3);
  assert.equal(counts.actualModelCalls, 0); assert.equal(counts.judgeCalls, 0);
  assert.equal(counts.canonicalCredit, 0);
  Object.assign(status, counts, { controlledActorCalls: counts.controlledProviderCalls });
}

// Assessment judgments are immutable attempt records, not awards. Keep this
// bounded witness in the private failed-run receipt so a normal, unqualified
// assessment is distinguishable from a real Judge call or canonical credit.
// Never retain the assessment packet, result body, or Judge response text.
const Q05_ASSESSMENT_OBJECTIVES = new Set(['ss_loop_observation', 'ss_content_persist', 'ss_content_followed']);
function redactAssessmentAttemptRows(rows, { runId, scope, siblingScope }) {
  assert.ok(Array.isArray(rows) && rows.length <= 17);
  const visible = rows.slice(0, 16).map(row => {
    assert.match(row.evaluation_id, UUID);
    assert.equal(row.run_id, runId);
    const ownerScopeMatches = require('node:util').isDeepStrictEqual(row.execution_scope, scope);
    const siblingScopeMatches = require('node:util').isDeepStrictEqual(row.execution_scope, siblingScope);
    return {
      evaluationId: row.evaluation_id,
      objectiveId: Q05_ASSESSMENT_OBJECTIVES.has(row.objective_id) ? row.objective_id : 'unexpected',
      verdict: [null, 'pass', 'fail', 'inconclusive', 'unavailable'].includes(row.verdict)
        ? row.verdict : 'unexpected',
      disposition: typeof row.disposition === 'string' && /^[a-z_]{1,64}$/.test(row.disposition)
        ? row.disposition : row.disposition === null ? null : 'unexpected',
      resultDigest: typeof row.result_digest === 'string' && /^[a-f0-9]{64}$/.test(row.result_digest)
        ? row.result_digest : null,
      resultVerdict: [null, 'pass', 'fail', 'inconclusive', 'unavailable'].includes(row.result_verdict)
        ? row.result_verdict : 'unexpected',
      errorCode: typeof row.error_code === 'string' && /^[A-Z0-9_]{1,80}$/.test(row.error_code)
        ? row.error_code : row.error_code === null ? null : 'other',
      modelEvaluated: typeof row.model_evaluated === 'boolean' ? row.model_evaluated : null,
      providerPresent: row.provider_present === true,
      modelPresent: row.model_present === true,
      usagePresent: row.usage_present === true,
      judgeObservationsState: ['sql_null', 'json_null', 'proof'].includes(row.judge_observations_state)
        ? row.judge_observations_state : 'unexpected',
      judgeResultPresent: row.judge_result_present === true,
      principalBindingMatches: row.principal_binding_matches === true,
      ownerScopeMatches, siblingScopeMatches,
    };
  });
  return { runId, rowCountAtLeast: rows.length, truncated: rows.length > 16, rows: visible };
}

async function readAssessmentAttemptWitness(identityPool, { runId, scope, siblingScope }) {
  assert.match(runId, UUID);
  const rows = (await identityPool.query(`SELECT j.evaluation_id::text,j.run_id::text,j.objective_id,
      j.verdict,j.disposition,j.result_digest,j.result_json->>'verdict' AS result_verdict,
      j.result_json->>'errorCode' AS error_code,
      CASE WHEN j.result_json->'modelEvaluated'='true'::jsonb THEN true
           WHEN j.result_json->'modelEvaluated'='false'::jsonb THEN false ELSE NULL END AS model_evaluated,
      j.result_json->>'provider' IS NOT NULL AS provider_present,
      j.result_json->>'model' IS NOT NULL AS model_present,
      (j.result_json->'usage' IS NOT NULL AND j.result_json->'usage'<>'null'::jsonb) AS usage_present,
      CASE WHEN j.judge_observations IS NULL THEN 'sql_null'
           WHEN j.judge_observations='null'::jsonb THEN 'json_null' ELSE 'proof' END AS judge_observations_state,
      j.judge_result_json IS NOT NULL AS judge_result_present,
      j.execution_json->'scope' AS execution_scope,
      (j.tenant_id=e.tenant_id AND j.principal_id=e.principal_id AND e.owner_id=$3)
        AS principal_binding_matches
    FROM secureshop_auth.assessment_judgments j
    LEFT JOIN secureshop_auth.execution_authority_state e ON e.session_id=$2
    WHERE j.run_id=$1 ORDER BY j.evaluation_id LIMIT 17`,
  [runId, scope.platformSessionId, scope.platformOwnerId])).rows;
  const catalogRows = (await identityPool.query(`SELECT o.objective_id,o.catalog_active,
      COALESCE(c.is_enabled,o.is_enabled) AS effective_enabled
    FROM secureshop_auth.assessment_objectives o
    LEFT JOIN secureshop_auth.assessment_configuration c
      ON c.objective_id=o.objective_id AND c.tenant_id=(SELECT e.tenant_id
        FROM secureshop_auth.execution_authority_state e WHERE e.session_id=$1)
    WHERE o.objective_id=ANY($2::text[]) ORDER BY o.objective_id`,
  [scope.platformSessionId, [...Q05_ASSESSMENT_OBJECTIVES]])).rows;
  const witness = redactAssessmentAttemptRows(rows, { runId, scope, siblingScope });
  witness.catalog = catalogRows.map(row => ({
    objectiveId: Q05_ASSESSMENT_OBJECTIVES.has(row.objective_id) ? row.objective_id : 'unexpected',
    catalogActive: row.catalog_active === true,
    effectiveEnabled: row.effective_enabled === true,
  }));
  return witness;
}

function assertOnlyRunOwnedHiddenAssessments(status, creditBefore, creditAfter, assessmentWitness) {
  assert.ok(status?.evidence && typeof status.evidence === 'object');
  Object.assign(status.evidence, { creditBefore, creditAfter, assessmentWitness });
  assert.deepEqual(Object.keys(creditBefore).sort(), ['completions', 'contributions', 'judgments']);
  assert.deepEqual(Object.keys(creditAfter).sort(), ['completions', 'contributions', 'judgments']);
  for (const key of ['completions', 'contributions', 'judgments']) {
    assert.ok(Number.isSafeInteger(creditBefore[key]) && creditBefore[key] >= 0);
    assert.ok(Number.isSafeInteger(creditAfter[key]) && creditAfter[key] >= 0);
  }
  // The fixture's controlled Q05 path begins with no assessment history in
  // any principal. This makes the exact three run-owned rows non-vacuous and
  // rules out an unobserved peer/preexisting row changing under equal counts.
  assert.deepEqual(creditBefore, { judgments: 0, completions: 0, contributions: 0 });
  assert.equal(creditAfter.completions, creditBefore.completions);
  assert.equal(creditAfter.contributions, creditBefore.contributions);
  assert.deepEqual(Object.keys(assessmentWitness).sort(),
    ['catalog', 'rowCountAtLeast', 'rows', 'runId', 'truncated']);
  assert.equal(assessmentWitness.runId,
    status.evidence.turn?.result_json?.taskMetadata?.reviewBatch?.runId);
  assert.equal(assessmentWitness.truncated, false);
  assert.equal(assessmentWitness.rows.length, 3);
  assert.equal(assessmentWitness.rowCountAtLeast, 3);
  assert.equal(creditAfter.judgments - creditBefore.judgments, assessmentWitness.rows.length,
    'only the exact run-owned assessment attempts may extend the judgment ledger');
  assert.deepEqual(new Set(assessmentWitness.rows.map(row => row.objectiveId)), Q05_ASSESSMENT_OBJECTIVES);
  assert.equal(new Set(assessmentWitness.rows.map(row => row.evaluationId)).size, 3);
  assert.deepEqual(new Set(assessmentWitness.catalog.map(row => row.objectiveId)), Q05_ASSESSMENT_OBJECTIVES);
  assert.equal(assessmentWitness.catalog.length, 3);
  for (const row of assessmentWitness.catalog) {
    assert.deepEqual(Object.keys(row).sort(), ['catalogActive', 'effectiveEnabled', 'objectiveId']);
    assert.equal(typeof row.catalogActive, 'boolean'); assert.equal(typeof row.effectiveEnabled, 'boolean');
    assert.ok(!row.catalogActive || !row.effectiveEnabled, 'each observed hidden objective must remain hidden');
  }
  for (const row of assessmentWitness.rows) {
    assert.deepEqual(Object.keys(row).sort(), ['disposition', 'errorCode', 'evaluationId',
      'judgeObservationsState', 'judgeResultPresent', 'modelEvaluated', 'modelPresent',
      'objectiveId', 'ownerScopeMatches', 'principalBindingMatches', 'providerPresent',
      'resultDigest', 'resultVerdict', 'siblingScopeMatches', 'usagePresent', 'verdict'].sort());
    assert.match(row.evaluationId, UUID);
    assert.equal(row.verdict, 'inconclusive'); assert.equal(row.resultVerdict, 'inconclusive');
    assert.equal(row.disposition, 'hidden'); assert.match(row.resultDigest, /^[a-f0-9]{64}$/);
    assert.equal(row.errorCode, null); assert.equal(row.modelEvaluated, null);
    assert.equal(row.providerPresent, false); assert.equal(row.modelPresent, false);
    assert.equal(row.usagePresent, false); assert.equal(row.judgeResultPresent, false);
    assert.ok(['sql_null', 'json_null'].includes(row.judgeObservationsState));
    assert.equal(row.principalBindingMatches, true); assert.equal(row.ownerScopeMatches, true);
    assert.equal(row.siblingScopeMatches, false);
  }
}

async function assertPhysicalAuthority({ headers, composition, scope, persona, personaSession }) {
  const authorization = headers?.authorization;
  const launch = headers?.['x-owasp-ai-goat-secureshop-launch'];
  assert.ok(typeof authorization === 'string' && /^Bearer [^\s]+$/.test(authorization),
    'Q05 physical request requires one bearer credential');
  assert.ok(typeof launch === 'string' && launch.length > 0,
    'Q05 physical request requires a launch credential');
  const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
  let physicalScope;
  try { physicalScope = createLaunchScope(await composition.launches.resolveCapability(launch)); }
  catch { throw Object.assign(new Error('Q05 physical launch authority unavailable'),
    { code: 'Q05_PHYSICAL_LAUNCH_UNAVAILABLE' }); }
  assert.deepEqual(physicalScope, scope, 'Q05 physical request must use the browser execution scope');
  let authenticated;
  try { authenticated = await composition.personaAuth.authenticateBoundToken({
    scope: physicalScope, token: authorization.slice(7) }); }
  catch { throw Object.assign(new Error('Q05 physical persona authority unavailable'),
    { code: 'Q05_PHYSICAL_PERSONA_UNAVAILABLE' }); }
  assert.deepEqual({ id: authenticated.user.id, role: authenticated.user.role }, persona);
  assert.deepEqual({ sessionId: authenticated.sessionId,
    authorityVersion: authenticated.authorityVersion }, personaSession);
}

function observeResponse(request, response, responses) {
  if (!/^\/merchant\/reviews(?:\/moderation\/[a-f0-9-]{36}|\/moderate-all)?$/.test(request.path)) return;
  assert.ok(responses.length < 128, 'bounded Q05 response captures');
  const entry = { method: request.method, path: `/api/secureshop${request.path}`,
    query: { ...request.query }, body: structuredClone(request.body), status: null };
  responses.push(entry);
  const send = response.json.bind(response);
  response.json = value => {
    assert.ok(Buffer.byteLength(JSON.stringify(value)) <= 262144, 'bounded Q05 response bytes');
    entry.status = response.statusCode; entry.value = structuredClone(value);
    if (request.ssLaunch && request.ssUser && request.ssPersonaSession)
      entry.authority = { scope: require('../../server/services/secureshopConversationBinding').createLaunchScope(request.ssLaunch),
        persona: { id: request.ssUser.id, role: request.ssUser.role },
        session: { sessionId: request.ssPersonaSession.sessionId,
          authorityVersion: request.ssPersonaSession.authorityVersion } };
    return send(value);
  };
}

async function readCompositeProduct(reviewPool, targetId, productId) {
  const result = await reviewPool.query(`SELECT target_id,product_id,retailer_id,name,description,price,category,status
    FROM secureshop_review.product_target_products WHERE target_id=$1 AND product_id=$2`,
  [targetId, productId]);
  assert.equal(result.rows.length, 1, 'exact independently retained composite product required');
  return result.rows[0];
}

async function assertSiblingSeed({ ownerScope, siblingScope, ownerProductTarget, siblingProductTarget,
  ownerPersonaId, siblingPersonaId, product, siblingProduct, reviewPool }) {
  assert.ok(ownerScope && siblingScope && ownerProductTarget && siblingProductTarget,
    'Q05 requires two actual owner-bound product targets before review effects');
  assert.ok(Number.isSafeInteger(ownerScope.platformOwnerId)
    && Number.isSafeInteger(siblingScope.platformOwnerId)
    && ownerScope.platformOwnerId !== siblingScope.platformOwnerId,
  'Q05 sibling must have a different platform owner');
  assert.ok(typeof ownerProductTarget.targetId === 'string' && UUID.test(ownerProductTarget.targetId)
    && typeof siblingProductTarget.targetId === 'string' && UUID.test(siblingProductTarget.targetId)
    && ownerProductTarget.targetId !== siblingProductTarget.targetId,
  'Q05 sibling must have a different product target');
  assert.ok(Number.isSafeInteger(product?.productId) && product.productId > 0
    && Number.isSafeInteger(siblingProduct?.productId) && siblingProduct.productId > 0,
  'Q05 requires actual merchant and sibling products');
  assert.ok(Number.isSafeInteger(ownerPersonaId) && Number.isSafeInteger(siblingPersonaId)
    && ownerPersonaId !== siblingPersonaId, 'Q05 requires separate merchant personas');
  assert.ok(reviewPool && typeof reviewPool.query === 'function', 'Q05 requires actual product readback');
  const ownerProductRow = await readCompositeProduct(reviewPool, ownerProductTarget.targetId, product.productId);
  const siblingProductRow = await readCompositeProduct(reviewPool, siblingProductTarget.targetId, siblingProduct.productId);
  for (const [row, target, selected, merchant] of [
    [ownerProductRow, ownerProductTarget, product, ownerPersonaId],
    [siblingProductRow, siblingProductTarget, siblingProduct, siblingPersonaId],
  ]) {
    assert.equal(row.target_id, target.targetId);
    assert.equal(row.product_id, selected.productId);
    assert.equal(row.retailer_id, merchant);
    assert.equal(row.status, 'active');
  }
  assert.notDeepEqual([ownerProductRow.target_id, ownerProductRow.product_id],
    [siblingProductRow.target_id, siblingProductRow.product_id],
    'Q05 products must have distinct composite identities');
  return { ownerProductRow, siblingProductRow };
}

function assertReusedProductScene(actual, seeded) {
  assert.match(actual?.targetId, UUID);
  assert.match(seeded?.targetId, UUID);
  assert.match(actual?.scene?.sceneId, UUID);
  assert.match(seeded?.scene?.sceneId, UUID);
  assert.equal(actual.targetId, seeded.targetId,
    'Q05 sibling review must reuse the independently seeded product target');
  assert.equal(actual.scene.sceneId, seeded.scene.sceneId,
    'Q05 sibling review must reuse the independently seeded product scene');
}

async function readSceneReviewMapping(reviewPool, productTarget, reviewTarget) {
  assert.match(productTarget?.scene?.sceneId, UUID);
  assert.match(productTarget.targetId, UUID);
  assert.match(reviewTarget.targetId, UUID);
  const result = await reviewPool.query(`SELECT scene_id,product_target_id,review_target_id,original_platform_owner_id
    FROM secureshop_review.scene_review_targets
    WHERE scene_id=$1 AND product_target_id=$2 AND review_target_id=$3`,
  [productTarget.scene.sceneId, productTarget.targetId, reviewTarget.targetId]);
  assert.equal(result.rows.length, 1, 'exact canonical product-to-review scene mapping required');
  const row = result.rows[0];
  assert.equal(row.scene_id, productTarget.scene.sceneId);
  assert.equal(row.product_target_id, productTarget.targetId);
  assert.equal(row.review_target_id, reviewTarget.targetId);
  assert.equal(row.original_platform_owner_id, productTarget.platformOwnerId);
  return row;
}

async function prepareBrowserOwnedProduct({ composition, scope, persona, personaSession, reviewPool }) {
  assert.equal(persona.role, 'merchant');
  const productTarget = await composition.catalog.prepareTarget({ scope, persona, personaSession });
  assert.match(productTarget.targetId, UUID);
  const product = await composition.catalog.createMerchantProduct({ scope, persona, personaSession,
    listing: { name: 'Q05 browser-owned review product',
      description: 'Synthetic product for the browser-owned moderation action',
      price: 12.5, category: 'fixture', templateSource: '{{source}}', images: [] } });
  assert.ok(Number.isSafeInteger(product.productId) && product.productId > 0);
  const reviewTarget = await composition.runtime.application.prepareScene({ scope, persona, personaSession });
  const existing = await composition.runtime.application.resolveExistingTarget(scope);
  assert.equal(existing.targetId, reviewTarget.targetId,
    'browser review target must be the canonically prepared review target');
  const mapping = await readSceneReviewMapping(reviewPool, productTarget, reviewTarget);
  return { productTarget, reviewTarget: existing, product, mapping };
}

async function qualify({ page, reacquireFrame, origin, composition, reset,
  siblingProduct, siblingProductTarget, siblingBase, pools, provider, browserBootstraps, username, capture, status }) {
  const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
  const wait = async predicate => {
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) { const value = await predicate(); if (value) return value;
      await new Promise(resolve => setTimeout(resolve, 25)); }
    throw Error('Q05 bounded observation timed out');
  };
  const credentials = await wait(() => browserBootstraps.find(row => row.username === username));
  const scope = createLaunchScope(await composition.launches.resolveCapability(credentials.launch));
  const siblingScope = createLaunchScope(await composition.launches.resolveCapability(siblingBase.bearer));
  const actor = await composition.personaAuth.authenticateBoundToken({ scope, token: credentials.authorization.slice(7) });
  const peer = await composition.personaAuth.authenticateBoundToken({ scope: siblingScope, token: siblingBase.persona.token });
  const persona = { id: actor.user.id, role: actor.user.role };
  const personaSession = { sessionId: actor.sessionId, authorityVersion: actor.authorityVersion };
  const { productTarget, reviewTarget: target, product, mapping: ownerSceneMapping } =
    await prepareBrowserOwnedProduct({ composition, scope, persona, personaSession,
      reviewPool: pools.REVIEW_RUNTIME });
  const peerPersona = { id: peer.user.id, role: peer.user.role };
  const peerSession = { sessionId: peer.sessionId, authorityVersion: peer.authorityVersion };
  const peerProductTarget = await composition.catalog.prepareTarget({ scope: siblingScope,
    persona: peerPersona, personaSession: peerSession });
  assertReusedProductScene(peerProductTarget, siblingProductTarget);
  const peerPreparedReview = await composition.runtime.application.prepareScene({ scope: siblingScope,
    persona: peerPersona, personaSession: peerSession });
  const peerTarget = await composition.runtime.application.resolveExistingTarget(siblingScope);
  assert.equal(peerTarget.targetId, peerPreparedReview.targetId);
  const siblingSceneMapping = await readSceneReviewMapping(pools.REVIEW_RUNTIME,
    peerProductTarget, peerTarget);
  assert.notEqual(target.targetId, peerTarget.targetId,
    'independent platform owners require distinct review targets');
  const { ownerProductRow, siblingProductRow } = await assertSiblingSeed({ ownerScope: scope, siblingScope,
    ownerProductTarget: productTarget, siblingProductTarget: peerProductTarget,
    ownerPersonaId: actor.user.id,
    siblingPersonaId: peer.user.id, product, siblingProduct, reviewPool: pools.REVIEW_RUNTIME });
  const body = 'This product works well and arrived in good condition.';
  const source = await composition.runtime.application.submitReview({ scope, persona, personaSession,
    submissionId: randomUUID(), productId: product.productId, authorId: persona.id, body, rating: 5 });
  const reviewId = Number(source.id);
  provider.arm({ reviewId, body });
  assert.notEqual(siblingScope.platformOwnerId, scope.platformOwnerId);
  await composition.runtime.application.submitReview({ scope: siblingScope,
    persona: peerPersona, personaSession: peerSession,
    submissionId: randomUUID(), productId: siblingProduct.productId, authorId: peer.user.id,
    body: 'Independent sibling product feedback', rating: 4 });
  const rows = async targetId => (await pools.REVIEW_RUNTIME.query(`SELECT id,product_id,author_id,body,rating,status,moderator_kind,moderator_notes
    FROM secureshop_review.reviews WHERE target_id=$1 ORDER BY id`, [targetId])).rows;
  const creditSnapshot = async () => (await pools.IDENTITY_RUNTIME.query(`SELECT
    (SELECT count(*) FROM secureshop_auth.assessment_judgments)::int AS judgments,
    (SELECT count(*) FROM secureshop_auth.assessment_completions)::int AS completions,
    (SELECT count(*) FROM secureshop_auth.assessment_contributions)::int AS contributions`)).rows[0];
  const creditBefore = await creditSnapshot();
  const beforeRows = await rows(target.targetId); assert.equal(beforeRows.length, 1);
  const siblingBefore = await rows(peerTarget.targetId); assert.ok(siblingBefore.length);
  const posts = () => capture.responses.filter(row => row.method === 'POST' && row.path === POST);
  await page.goto(`${origin}/secureshop/merchant/reviews`, { waitUntil: 'domcontentloaded' });
  const frame = await reacquireFrame();
  await frame.waitForFunction(selector => { const node = document.querySelector(selector);
    return node && !node.disabled && node.getClientRects().length; }, { timeout: 30000 }, BUTTON);
  const disclosure = await frame.$eval(`header:has(${BUTTON})`, node => node.innerText.replace(/\s+/g, ' '));
  assert.ok(disclosure.includes(DISCLOSURE));
  assert.ok(disclosure.includes('The filters only change the displayed list, not which pending reviews this action considers.'));
  assert.equal(posts().length, 0); status.physicalDisclosure = true; status.noPreClickPost = true;
  await frame.locator(BUTTON).click();
  const post = await wait(() => posts()[0]?.status !== null && posts()[0]);
  assert.equal(post.status, 200); assert.equal(posts().length, 1);
  assert.deepEqual(createLaunchScope(post.authority.scope), scope);
  assert.equal(post.authority.persona.id, persona.id); assert.equal(post.authority.persona.role, persona.role);
  assert.deepEqual(post.authority.session, personaSession);
  const physical = capture.physicalRequests.filter(request => new URL(request.url()).pathname === POST && request.method() === 'POST');
  assert.equal(physical.length, 1); assert.equal(physical[0].frame(), page.mainFrame());
  assert.equal(physical[0].postData(), JSON.stringify(post.body));
  await assertPhysicalAuthority({ headers: physical[0].headers(), composition,
    scope, persona, personaSession });
  const physicalPost = { method: physical[0].method(), path: new URL(physical[0].url()).pathname,
    body: JSON.parse(physical[0].postData()), mainFrame: physical[0].frame() === page.mainFrame() };
  const lookupPath = `/api/secureshop/merchant/reviews/moderation/${post.body.request_id}`;
  const readback = await wait(() => capture.responses.find(row => row.method === 'GET'
    && row.path === lookupPath && row.status === 200 && row.value.state === 'completed'));
  assert.equal(readback.value.recoveryScopeKey, post.body.recoveryScopeKey);
  assert.equal(readback.value.requestId, post.body.request_id); assert.equal(readback.value.requestedLimit, 100);
  assert.deepEqual(readback.authority, post.authority);
  assert.equal(readback.value.result.processed, 1);
  assert.equal(readback.value.result.decisions[0].review_id, reviewId);
  assert.equal(readback.value.result.decisions[0].applied_decision, 'approve');
  assert.ok(capture.physicalRequests.some(request => request.method() === 'GET'
    && new URL(request.url()).pathname === lookupPath));
  await frame.waitForFunction(() => document.querySelector('[data-testid="reviews-feedback"][role="status"]')
    ?.textContent.includes('Moderated 1 review(s) in this run.'), { timeout: 30000 });
  const afterRows = await rows(target.targetId);
  assert.equal(afterRows[0].status, 'approved'); assert.equal(afterRows[0].moderator_kind, 'auto');
  assert.deepEqual({ ...afterRows[0], status: beforeRows[0].status,
    moderator_kind: beforeRows[0].moderator_kind, moderator_notes: beforeRows[0].moderator_notes }, beforeRows[0]);
  const turns = (await pools.AGENTS_RUNTIME.query(`SELECT * FROM secureshop_agents.turn_requests
    WHERE request_id=$1`, [post.body.request_id])).rows;
  assert.equal(turns.length, 1); const turn = turns[0]; assert.equal(turn.status, 'completed');
  const runId = turn.result_json.taskMetadata.reviewBatch.runId;
  const effects = (await pools.IDENTITY_RUNTIME.query('SELECT * FROM graph_runtime.effects WHERE run_id=$1 ORDER BY effect_key', [runId])).rows;
  assert.equal(effects.length, 2); assert.ok(effects.every(row => row.status === 'completed'));
  const hops = turn.result_json.hops;
  assert.deepEqual(hops.map(hop => hop.tool), ['review-moderator.moderate_pending', 'review-moderator.approve']);
  assert.equal(hops[1].params.review_id, reviewId);
  const outcome = JSON.parse(hops[1].result.content[0].text);
  assert.equal(outcome.applied, true); assert.equal(outcome.review.id, reviewId);
  const audits = (await pools.REVIEW_RUNTIME.query(`SELECT * FROM secureshop_review.bound_audit_events
    WHERE launch_id=$1 AND source_kind='review_decision_operation' ORDER BY event_id`, [scope.launchId])).rows;
  assert.equal(audits.length, 1);
  const decision = JSON.parse(audits[0].params_json);
  assert.equal(decision.receipt.runId, runId); assert.equal(decision.receipt.reviewId, reviewId);
  assert.equal(decision.receipt.applied, true); assert.equal(decision.receipt.actor.personaSessionId, actor.sessionId);
  assert.equal(decision.receipt.resultStatus, 'approved');
  assert.equal(decision.receipt.actor.id, persona.id);
  assert.equal(decision.receipt.actor.role, persona.role);
  const ownerReviewBirth = { targetId: target.targetId, ...createLaunchScope(target) };
  const siblingReviewBirth = { targetId: peerTarget.targetId, ...createLaunchScope(peerTarget) };
  assert.deepEqual(decision.receipt.scope, ownerReviewBirth);
  assert.equal(audits[0].launch_id, scope.launchId);
  assert.equal(audits[0].original_platform_owner_id, scope.platformOwnerId);
  status.evidence = { scope, siblingScope, ownerTargetId: productTarget.targetId,
    siblingTargetId: peerProductTarget.targetId,
    ownerReviewTargetId: target.targetId, siblingReviewTargetId: peerTarget.targetId,
    ownerSceneMapping, siblingSceneMapping, ownerReviewBirth, siblingReviewBirth,
    siblingPersonaId: peer.user.id,
    ownerProductBefore: ownerProductRow,
    persona, personaSession, reviewId, requestId: post.body.request_id, physicalPost,
    post, readback, beforeRows, afterRows, turn, effects, audits, siblingBefore,
    siblingProductBefore: siblingProductRow };
  status.physicalModeration = true; status.durableBoundEffect = true; status.exactReadback = true;
  // Reset while this exact UI remains mounted. Reset's own retirement is not
  // misreported as a moderation effect: compare snapshots AFTER committed reset.
  assert.equal(await frame.$eval(BUTTON, node => node.disabled), false);
  const retired = await reset.launchResetCoordinator.reset({ ...scope,
    expectedGeneration: scope.generation, idempotencyKey: randomUUID() });
  await reset.cleanupAuthority.assertResolved(retired.resetId);
  const staleBefore = await rows(target.targetId);
  const callsBefore = provider.counts().controlledProviderCalls;
  const requestOffset = capture.responses.length;
  const staleDisabled = await frame.$eval(BUTTON, node => node.disabled);
  if (!staleDisabled) {
    await frame.locator(BUTTON).click();
    await wait(() => capture.responses.slice(requestOffset).some(row => row.method === 'GET'
      && row.path.includes('/moderation/') && row.status === 401));
    await frame.waitForSelector('[data-testid="reviews-feedback"][role="alert"]', { visible: true });
  }
  assert.equal(posts().length, 1); assert.equal(provider.counts().controlledProviderCalls, callsBefore);
  const staleAfter = await rows(target.targetId), siblingAfter = await rows(peerTarget.targetId);
  const siblingProductAfter = await readCompositeProduct(pools.REVIEW_RUNTIME,
    peerProductTarget.targetId, siblingProduct.productId);
  const siblingSceneMappingAfter = await readSceneReviewMapping(pools.REVIEW_RUNTIME,
    peerProductTarget, peerTarget);
  const creditAfter = await creditSnapshot();
  const assessmentWitness = await readAssessmentAttemptWitness(pools.IDENTITY_RUNTIME,
    { runId, scope, siblingScope });
  assertOnlyRunOwnedHiddenAssessments(status, creditBefore, creditAfter, assessmentWitness);
  assert.deepEqual(staleAfter, staleBefore);
  assert.deepEqual(siblingAfter, siblingBefore);
  assert.deepEqual(siblingProductAfter, siblingProductRow);
  assert.deepEqual(siblingSceneMappingAfter, siblingSceneMapping);
  assert.deepEqual((await pools.IDENTITY_RUNTIME.query('SELECT * FROM graph_runtime.effects WHERE run_id=$1 ORDER BY effect_key', [runId])).rows, effects);
  Object.assign(status.evidence, { siblingProductAfter, siblingSceneMappingAfter });
  Object.assign(status, provider.counts(), { version: 3, actorCalls: 0,
    controlledActorCalls: provider.counts().controlledProviderCalls,
    staleAuthorityNoEffect: true, siblingPreserved: true, isolatedStores: true,
    zeroActualModel: true, zeroJudge: true, passed: true, errors: [],
    evidence: { scope, siblingScope, ownerTargetId: productTarget.targetId,
      siblingTargetId: peerProductTarget.targetId,
      ownerReviewTargetId: target.targetId, siblingReviewTargetId: peerTarget.targetId,
      ownerSceneMapping, siblingSceneMapping, siblingSceneMappingAfter,
      ownerReviewBirth, siblingReviewBirth,
      siblingPersonaId: peer.user.id,
      ownerProductBefore: ownerProductRow,
      siblingProductBefore: siblingProductRow, siblingProductAfter,
      persona, personaSession, reviewId, requestId: post.body.request_id, physicalPost,
      post, readback, beforeRows, afterRows, turn, effects, audits,
      reset: retired, staleBefore, staleAfter, siblingBefore, siblingAfter, creditBefore, creditAfter,
      assessmentWitness,
      staleObservation: { disabled: staleDisabled, responses: capture.responses.slice(requestOffset),
        providerCallsBefore: callsBefore, providerCallsAfter: provider.counts().controlledProviderCalls,
        postsBefore: 1, postsAfter: posts().length } } });
}

function assertReceipt(value) {
  assert.equal(value.version, 3); assert.equal(value.scope, SCOPE);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  assert.equal(value.actorCalls, 0); assert.equal(value.actualModelCalls, 0);
  assert.equal(value.judgeCalls, 0); assert.equal(value.canonicalCredit, 0);
  assert.equal(value.controlledActorCalls, 3); assert.equal(value.controlledProviderCalls, 3);
  assert.deepEqual(value.errors, []);
  assert.deepEqual(value.cleanupErrors, []);
  assertDurableEvidence(value.evidence);
}

function assertDurableEvidence(evidence) {
  assert.ok(evidence);
  const { scope, persona, personaSession, post, readback, turn, effects, audits,
    beforeRows, afterRows, reviewId, requestId, physicalPost } = evidence;
  assert.match(requestId, UUID); assert.equal(post.body.request_id, requestId);
  assert.equal(post.body.limit, 100); assert.match(post.body.recoveryScopeKey, /^[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(post.body).sort(), ['limit', 'recoveryScopeKey', 'request_id']);
  assert.equal(post.method, 'POST'); assert.equal(post.path, POST); assert.equal(post.status, 200);
  assert.deepEqual(post.authority, { scope, persona, session: personaSession });
  assert.deepEqual(physicalPost, { method: 'POST', path: POST, body: post.body, mainFrame: true });
  assert.equal(readback.method, 'GET'); assert.equal(readback.status, 200);
  assert.equal(readback.path, `/api/secureshop/merchant/reviews/moderation/${requestId}`);
  assert.deepEqual(readback.authority, post.authority);
  assert.equal(readback.value.state, 'completed'); assert.equal(readback.value.requestId, requestId);
  assert.equal(readback.value.recoveryScopeKey, post.body.recoveryScopeKey);
  assert.equal(readback.value.result.processed, 1);
  assert.equal(readback.value.result.decisions.length, 1);
  assert.equal(readback.value.result.decisions[0].review_id, reviewId);
  assert.equal(readback.value.result.decisions[0].applied_decision, 'approve');
  assert.equal(beforeRows.length, 1); assert.equal(afterRows.length, 1);
  assert.equal(Number(beforeRows[0].id), reviewId); assert.equal(beforeRows[0].status, 'pending');
  assert.equal(afterRows[0].status, 'approved'); assert.equal(afterRows[0].moderator_kind, 'auto');
  assert.deepEqual({ ...afterRows[0], status: beforeRows[0].status,
    moderator_kind: beforeRows[0].moderator_kind, moderator_notes: beforeRows[0].moderator_notes }, beforeRows[0]);
  assert.equal(turn.request_id, requestId); assert.equal(turn.status, 'completed');
  const runId = turn.result_json.taskMetadata.reviewBatch.runId; assert.match(runId, UUID);
  assert.equal(effects.length, 2); assert.equal(new Set(effects.map(row => row.effect_key)).size, 2);
  for (const row of effects) { assert.equal(row.run_id, runId); assert.equal(row.status, 'completed'); }
  assert.equal(audits.length, 1);
  const receipt = JSON.parse(audits[0].params_json).receipt;
  assert.equal(receipt.runId, runId); assert.equal(receipt.reviewId, reviewId);
  assert.equal(receipt.applied, true); assert.equal(receipt.resultStatus, 'approved');
  assert.equal(receipt.actor.id, persona.id); assert.equal(receipt.actor.role, persona.role);
  assert.equal(receipt.actor.personaSessionId, personaSession.sessionId);
  assert.deepEqual(receipt.scope, evidence.ownerReviewBirth);
  assert.equal(audits[0].launch_id, scope.launchId);
  assert.equal(audits[0].scenario_id, scope.scenarioId);
  assert.equal(Number(audits[0].generation), scope.generation);
  assert.equal(audits[0].original_platform_owner_id, scope.platformOwnerId);
  assert.equal(audits[0].original_platform_session_id, scope.platformSessionId);
  assert.ok(evidence.reset.resetId); assert.deepEqual(evidence.staleAfter, evidence.staleBefore);
  const stale = evidence.staleObservation;
  assert.equal(typeof stale.disabled, 'boolean');
  assert.equal(stale.postsBefore, 1); assert.equal(stale.postsAfter, 1);
  assert.equal(stale.providerCallsBefore, 3); assert.equal(stale.providerCallsAfter, 3);
  assert.equal(stale.responses.some(row => row.method === 'POST'), false);
  if (!stale.disabled) assert.ok(stale.responses.some(row => row.method === 'GET'
    && row.path.includes('/moderation/') && row.status === 401));
  assert.ok(evidence.siblingBefore.length); assert.deepEqual(evidence.siblingAfter, evidence.siblingBefore);
  assert.ok(evidence.siblingScope && Number.isSafeInteger(evidence.siblingScope.platformOwnerId)
    && evidence.siblingScope.platformOwnerId !== scope.platformOwnerId);
  assert.match(evidence.ownerTargetId, UUID); assert.match(evidence.siblingTargetId, UUID);
  assert.notEqual(evidence.ownerTargetId, evidence.siblingTargetId);
  assert.match(evidence.ownerReviewTargetId, UUID);
  assert.match(evidence.siblingReviewTargetId, UUID);
  assert.notEqual(evidence.ownerReviewTargetId, evidence.siblingReviewTargetId);
  assert.equal(evidence.ownerReviewBirth.targetId, evidence.ownerReviewTargetId);
  assert.equal(evidence.siblingReviewBirth.targetId, evidence.siblingReviewTargetId);
  assert.equal(evidence.ownerReviewBirth.platformOwnerId, scope.platformOwnerId);
  assert.equal(evidence.siblingReviewBirth.platformOwnerId, evidence.siblingScope.platformOwnerId);
  for (const [mapping, productTarget, reviewTarget, owner] of [
    [evidence.ownerSceneMapping, evidence.ownerTargetId, evidence.ownerReviewTargetId,
      scope.platformOwnerId],
    [evidence.siblingSceneMapping, evidence.siblingTargetId, evidence.siblingReviewTargetId,
      evidence.siblingScope.platformOwnerId],
  ]) {
    assert.match(mapping.scene_id, UUID);
    assert.equal(mapping.product_target_id, productTarget);
    assert.equal(mapping.review_target_id, reviewTarget);
    assert.equal(mapping.original_platform_owner_id, owner);
  }
  assert.deepEqual(evidence.siblingSceneMappingAfter, evidence.siblingSceneMapping);
  assert.ok(Number.isSafeInteger(evidence.siblingPersonaId)
    && evidence.siblingPersonaId !== persona.id);
  assert.equal(evidence.ownerProductBefore.target_id, evidence.ownerTargetId);
  assert.equal(evidence.ownerProductBefore.retailer_id, persona.id);
  assert.equal(evidence.ownerProductBefore.status, 'active');
  assert.ok(Number.isSafeInteger(evidence.ownerProductBefore.product_id)
    && evidence.ownerProductBefore.product_id > 0);
  assert.equal(evidence.beforeRows[0].product_id, evidence.ownerProductBefore.product_id);
  assert.ok(evidence.siblingProductBefore && evidence.siblingProductAfter);
  assert.deepEqual(evidence.siblingProductAfter, evidence.siblingProductBefore);
  assert.equal(evidence.siblingProductBefore.target_id, evidence.siblingTargetId);
  assert.equal(evidence.siblingProductBefore.retailer_id, evidence.siblingPersonaId);
  assert.equal(evidence.siblingProductBefore.status, 'active');
  assert.ok(evidence.siblingBefore.some(row => row.product_id === evidence.siblingProductBefore.product_id));
  assert.ok(Number.isSafeInteger(evidence.siblingProductBefore.product_id)
    && evidence.siblingProductBefore.product_id > 0);
  assertOnlyRunOwnedHiddenAssessments({ evidence }, evidence.creditBefore,
    evidence.creditAfter, evidence.assessmentWitness);
}

module.exports = { SELECTOR, BUTTON, POST, DISCLOSURE, SCOPE, ASSERTION, FLAGS, selector,
  assertEvidencePath, createControlledProvider, recordControlledCounts, assertPhysicalAuthority,
  redactAssessmentAttemptRows, readAssessmentAttemptWitness, assertOnlyRunOwnedHiddenAssessments,
  admitBrowser, validateBrowserGrant, acknowledgeRecord, acknowledgeOrClose,
  observeResponse, assertSiblingSeed, assertReusedProductScene, prepareBrowserOwnedProduct, qualify,
  assertReceipt, assertDurableEvidence };
