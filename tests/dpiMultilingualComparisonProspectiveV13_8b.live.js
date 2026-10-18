'use strict';
// Pure, unmounted semantic diagnostic. No application, database, actor, or credit import.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = fs.realpathSync(path.resolve(__dirname, '..'));
const SELF = fs.realpathSync(__filename);
const CORPUS = path.join(ROOT, 'tests/fixtures/dpiMultilingualSemanticProspective-v2.json');
const CONTRACT = path.join(ROOT, 'server/agent-runtime/dpiExistentialComparison.js');
const PARSER = path.join(ROOT, 'server/agent-runtime/referenceComparisonVerifier.js');
const SOURCE_VERIFIER = path.join(ROOT, 'server/agent-runtime/sourceComparisonVerifier.js');
const LEGACY_VERIFIER = path.join(ROOT, 'server/agent-runtime/sourceComparisonLegacyVerifier.js');
const ZOD = path.join(ROOT, 'node_modules/zod');
const ZOD_SCHEMA = path.join(ROOT, 'node_modules/zod-to-json-schema');
const OUTPUT = path.join(ROOT, 'backups/private-recovery');
const MODEL = 'llama3.1:8b';
const DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const PROTOCOL = 'dpi-answer-comparison-v13';
const MAX_CHATS = 32;
const PER_CHAT_MS = 60_000;
const RUN_MS = 900_000;
const MAX_OUTPUT = 900;
const CONTEXT = 32_768;
const NODE = '/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node';
const NODE_SHA256 = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861';
const SOURCE_PINS = new Map([
  [CORPUS, '336f1096b66c7993d7e5d06fdb7e2c71689a41a2f7869abdbbb35201c26ef81a'],
  [CONTRACT, '9f22d3c921dc05e4ce0d862208272e24fc71658d73b68513156880bec1c3fcda'],
  [PARSER, '477f1f4b5fbc0032cf5a6ab5650f4d2310fc04a9d27a567edda9c8f64e8a2e2b'],
  [SOURCE_VERIFIER, '9062eedf3d8f61020e8524c79e74a4b272eb0b1cd1b351c08c2e56307d7bff08'],
  [LEGACY_VERIFIER, 'c192c46a6164c97ce823acf56c03ab74c8858b80f12ce46625ed5224f1aba180'],
]);
const PACKAGE_PINS = new Map([
  [ZOD, {files: 596, sha256: '2d26c65a1f9830df75eeca4fdcaa4c0bad18be5369aec8fc3b0e45d2c1ca53cf'}],
  [ZOD_SCHEMA, {files: 130, sha256: '5ed38269271a059048890364cb73e8a8cee746f024ddf9d6acf356bf6d677f2a'}],
]);
const sha = value => crypto.createHash('sha256').update(value).digest('hex');

function regular(file) {
  const entry = fs.lstatSync(file);
  assert(entry.isFile() && !entry.isSymbolicLink(), `Regular non-symlink required: ${file}`);
}
function filesBelow(root, directory = root) {
  const rows = [];
  const byteOrder = (a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name));
  for (const entry of fs.readdirSync(directory, {withFileTypes: true}).sort(byteOrder)) {
    const file = path.join(directory, entry.name);
    assert(!entry.isSymbolicLink(), `Dependency symlink rejected: ${file}`);
    if (entry.isDirectory()) rows.push(...filesBelow(root, file));
    else if (entry.isFile()) rows.push(file);
    else assert.fail(`Unsupported dependency entry: ${file}`);
  }
  return rows;
}
function packageDigest(root) {
  const hash = crypto.createHash('sha256');
  const files = filesBelow(root);
  for (const file of files) {
    const relative = Buffer.from(path.relative(root, file).split(path.sep).join('/'));
    const content = fs.readFileSync(file);
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(relative.length));
    hash.update(length).update(relative);
    length.writeBigUInt64BE(BigInt(content.length));
    hash.update(length).update(content);
  }
  return {files: files.length, sha256: hash.digest('hex')};
}
function pinnedInputs() {
  for (const [file, expected] of SOURCE_PINS) {
    regular(file);
    assert.equal(sha(fs.readFileSync(file)), expected, `Pinned source changed: ${file}`);
  }
  for (const [directory, expected] of PACKAGE_PINS) {
    const entry = fs.lstatSync(directory);
    assert(entry.isDirectory() && !entry.isSymbolicLink(), `Pinned dependency directory required: ${directory}`);
    assert.deepEqual(packageDigest(directory), expected, `Pinned pure dependency changed: ${directory}`);
  }
}
function processIdentity() {
  const executable = fs.realpathSync(process.execPath);
  regular(executable);
  assert.equal(executable, NODE, 'Exact managed release Node runtime required');
  assert.equal(sha(fs.readFileSync(executable)), NODE_SHA256, 'Managed release Node runtime changed');
  return {
    pid: process.pid,
    ppid: process.ppid,
    uid: process.getuid?.() ?? null,
    gid: process.getgid?.() ?? null,
    executable,
    executableSha256: NODE_SHA256,
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    argv: [...process.argv],
  };
}
function runtimeSnapshot() {
  pinnedInputs();
  return {
    processIdentity: processIdentity(),
    runnerSha256: sha(fs.readFileSync(SELF)),
    sources: [...SOURCE_PINS].map(([file, sha256]) => ({path: path.relative(ROOT, file), sha256})),
    dependencies: [...PACKAGE_PINS].map(([directory, value]) => ({path: path.relative(ROOT, directory), ...value})),
  };
}
function cases() {
  const corpus = JSON.parse(fs.readFileSync(CORPUS, 'utf8'));
  assert.equal(corpus.version, 2);
  assert.equal(corpus.objective, 'multi_language');
  assert.equal(corpus.cases.length, 8);
  assert.equal(new Set(corpus.cases.map(row => row.id)).size, 8);
  for (const row of corpus.cases) {
    assert(typeof row.request === 'string' && row.request.trim());
    assert(typeof row.response === 'string' && row.response.trim());
    assert(['pass', 'fail'].includes(row.expectedVerdict));
  }
  return corpus.cases;
}
function loadComparison() {
  const before = new Set(Object.keys(require.cache));
  const loaded = require(CONTRACT);
  assert.equal(loaded.MULTILINGUAL_SUCCESSOR_VERSION, PROTOCOL);
  const allowedSources = new Set([CONTRACT, PARSER, SOURCE_VERIFIER, LEGACY_VERIFIER]);
  const allowedPackage = file => [ZOD, ZOD_SCHEMA].some(directory => file.startsWith(directory + path.sep));
  for (const file of Object.keys(require.cache).filter(file => !before.has(file))) {
    assert(allowedSources.has(file) || allowedPackage(file), `Non-pure comparison dependency loaded: ${file}`);
  }
  return loaded.createDpiExistentialComparison;
}
function comparison(create, row) {
  const value = create({primary: true, objective: 'multi_language', protocolVersion: PROTOCOL}, [
    {id: 'request', source: 'student_input', content: row.request},
    {id: 'response', source: 'assistant_response', content: row.response},
  ]);
  assert.equal(value.policy.version, PROTOCOL);
  assert.equal(value.policy.maximumCalls, 4);
  assert.equal(value.policy.maxOutput, MAX_OUTPUT);
  assert.deepEqual(value.stages.map(stage => [stage.id, stage.maximumCalls]), [['assessment', 2], ['verify', 2]]);
  return value;
}
async function readLimited(response, limit = 1_048_576) {
  const chunks = [];
  let bytes = 0;
  let complete = false;
  try {
    for await (const chunk of response.body) {
      bytes += chunk.byteLength;
      if (bytes > limit) throw Error('HTTP response too large');
      chunks.push(Buffer.from(chunk));
    }
    complete = true;
    return Buffer.concat(chunks).toString('utf8');
  } finally {
    if (!complete) await response.body?.cancel().catch(() => {});
  }
}
function record(fd, value) {
  fs.writeSync(fd, JSON.stringify(value) + '\n');
  fs.fsyncSync(fd);
}
async function main() {
  const runtimeBefore = runtimeSnapshot();
  const corpus = cases();
  const create = loadComparison();
  for (const row of corpus) comparison(create, row);
  if (process.argv.length === 2) {
    process.stdout.write(JSON.stringify({
      plan: true,
      scope: 'pure-current-v13-multilingual-comparison-diagnostic',
      cases: corpus.length,
      protocol: PROTOCOL,
      model: MODEL,
      digest: DIGEST,
      maxPhysicalChats: MAX_CHATS,
      attemptsPerStage: 2,
      perChatMs: PER_CHAT_MS,
      globalMs: RUN_MS,
      numPredict: MAX_OUTPUT,
      numCtx: CONTEXT,
      outputParent: OUTPUT,
      actorClaim: false,
      creditClaim: false,
      runtime: runtimeBefore,
    }) + '\n');
    return;
  }
  assert.deepEqual(process.argv.slice(2), ['--run']);
  const outputEntry = fs.lstatSync(OUTPUT);
  assert(outputEntry.isDirectory() && !outputEntry.isSymbolicLink());
  assert.equal(outputEntry.mode & 0o077, 0, 'Private output parent permissions required');
  assert.equal(fs.realpathSync(OUTPUT), OUTPUT);
  const deadline = Date.now() + RUN_MS;
  const pending = new Set();
  let metadataCalls = 0;
  const dispatch = async (url, options, timeoutMs) => {
    assert(Date.now() < deadline, 'Global diagnostic deadline exceeded');
    const task = (async () => {
      const response = await fetch(url, {
        ...options,
        redirect: 'error',
        signal: AbortSignal.timeout(Math.max(1, Math.min(timeoutMs, deadline - Date.now()))),
      });
      return {status: response.status, rawResponse: await readLimited(response)};
    })();
    pending.add(task);
    try { return await task; }
    finally { pending.delete(task); }
  };
  const tagsRequest = {method: 'GET', url: 'http://127.0.0.1:11434/api/tags'};
  metadataCalls += 1;
  const tags = await dispatch(tagsRequest.url, {method: tagsRequest.method}, 5_000);
  assert.equal(tags.status, 200);
  const installed = JSON.parse(tags.rawResponse).models?.filter(model => model.name === MODEL);
  assert.equal(installed?.length, 1, 'Exact installed model tag required; no implicit fallback');
  assert.equal(installed[0].digest, DIGEST, 'Installed model digest changed');
  assert.equal(pending.size, 0, 'Metadata transport remains physically pending');
  assert.deepEqual(runtimeSnapshot(), runtimeBefore, 'Runtime changed before inference');

  const output = fs.mkdtempSync(path.join(OUTPUT, 'dpi-multilingual-comparison-v13-8b-'));
  fs.chmodSync(output, 0o700);
  const fd = fs.openSync(path.join(output, 'wire.jsonl'), 'wx', 0o600);
  const summary = {
    attempted: 0,
    matches: 0,
    falsePositive: [],
    falseNegative: [],
    inconclusive: [],
    unavailable: [],
    invalid: [],
    physicalChats: 0,
    metadataCalls,
    physicalPending: 0,
    actorClaim: false,
    creditClaim: false,
  };
  try {
    record(fd, {
      kind: 'metadata',
      version: 1,
      scope: 'pure-current-v13-multilingual-comparison-diagnostic',
      protocol: PROTOCOL,
      model: MODEL,
      digest: DIGEST,
      tagsWire: {rawRequest: JSON.stringify(tagsRequest), httpStatus: tags.status, rawResponse: tags.rawResponse},
      runtimeBefore,
      limits: {maxPhysicalChats: MAX_CHATS, attemptsPerStage: 2, perChatMs: PER_CHAT_MS,
        globalMs: RUN_MS, numPredict: MAX_OUTPUT, numCtx: CONTEXT},
      claims: {actor: false, credit: false},
      startedAt: new Date().toISOString(),
    });
    for (const row of corpus) {
      pinnedInputs();
      const contract = comparison(create, row);
      const values = [];
      const stageResults = [];
      let actual = 'unavailable';
      let error = null;
      for (const stage of contract.stages) {
        if (stage.skip?.()) break;
        let accepted = false;
        let repair;
        for (let attempt = 1; attempt <= 2; attempt += 1) {
          assert(summary.physicalChats < MAX_CHATS, 'Physical chat cap exceeded');
          assert.equal(pending.size, 0, 'Prior physical chat remains pending');
          const prepared = stage.messages(repair);
          const request = {model: MODEL, stream: false, messages: prepared.messages, format: prepared.format,
            options: {temperature: 0, num_predict: MAX_OUTPUT, num_ctx: CONTEXT}};
          const rawRequest = JSON.stringify(request);
          let httpStatus = null;
          let rawResponse = null;
          let wireModel = null;
          let done = null;
          let doneReason = null;
          let usage = null;
          let validation = null;
          summary.physicalChats += 1;
          try {
            const response = await dispatch('http://127.0.0.1:11434/api/chat', {
              method: 'POST', headers: {'content-type': 'application/json'}, body: rawRequest,
            }, PER_CHAT_MS);
            httpStatus = response.status;
            rawResponse = response.rawResponse;
            assert.equal(httpStatus, 200);
            const wire = JSON.parse(rawResponse);
            wireModel = wire.model;
            done = wire.done;
            doneReason = wire.done_reason;
            usage = Object.fromEntries(['prompt_eval_count', 'eval_count', 'total_duration', 'load_duration',
              'prompt_eval_duration', 'eval_duration'].filter(key => wire[key] !== undefined).map(key => [key, wire[key]]));
            assert.equal(wireModel, MODEL, 'Model fallback or alias response rejected');
            assert.equal(done, true);
            assert.equal(doneReason, 'stop');
            assert.equal(typeof wire.message?.content, 'string');
            values.push(stage.validate(wire.message.content));
            accepted = true;
          } catch (cause) {
            validation = String(cause?.message || cause);
            repair = stage.repairMessage(cause);
          }
          assert.equal(pending.size, 0, 'Chat transport remains physically pending');
          record(fd, {kind: 'stage', caseId: row.id, stage: stage.id, attempt, rawRequest, httpStatus,
            rawResponse, wireModel, done, doneReason, usage, accepted, validation,
            physicalPending: pending.size, processIdentity: processIdentity(), finishedAt: new Date().toISOString()});
          if (accepted) break;
        }
        stageResults.push({stage: stage.id, accepted});
        if (!accepted) { error = `${stage.id} invalid or unavailable`; break; }
      }
      if (!error) {
        try { actual = contract.combine(...values).verdict; }
        catch (cause) { actual = 'invalid'; error = String(cause?.message || cause); }
      }
      summary.attempted += 1;
      if (actual === row.expectedVerdict) summary.matches += 1;
      else if (actual === 'pass' && row.expectedVerdict === 'fail') summary.falsePositive.push(row.id);
      else if (actual === 'fail' && row.expectedVerdict === 'pass') summary.falseNegative.push(row.id);
      else if (Object.hasOwn(summary, actual) && Array.isArray(summary[actual])) summary[actual].push(row.id);
      else summary.invalid.push(row.id);
      record(fd, {kind: 'case', id: row.id, expectedVerdict: row.expectedVerdict, actualVerdict: actual,
        requestSha256: sha(row.request), responseSha256: sha(row.response), stages: stageResults, error,
        actorClaim: false, creditClaim: false, finishedAt: new Date().toISOString()});
    }
    assert(summary.physicalChats <= MAX_CHATS);
    assert.equal(pending.size, 0);
    assert(Date.now() <= deadline, 'Global diagnostic deadline exceeded');
    const runtimeAfter = runtimeSnapshot();
    assert.deepEqual(runtimeAfter, runtimeBefore, 'Runtime or process identity changed during diagnostic');
    summary.physicalPending = pending.size;
    record(fd, {kind: 'summary', ...summary, runtimeAfter, finishedAt: new Date().toISOString()});
    process.stdout.write(JSON.stringify({output, summary}) + '\n');
    if (summary.matches !== 8 || summary.falsePositive.length || summary.falseNegative.length
      || summary.invalid.length || summary.unavailable.length || summary.inconclusive.length) process.exitCode = 1;
  } finally {
    fs.closeSync(fd);
  }
}
main().catch(error => {
  process.stderr.write(String(error?.stack || error) + '\n');
  process.exitCode = 1;
});
