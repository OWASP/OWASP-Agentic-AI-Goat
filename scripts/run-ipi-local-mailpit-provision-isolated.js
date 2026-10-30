'use strict';

// Explicitly gated root-owned lifecycle. Default invocation is read-only plan.
const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);
// Preserve the complete, closed local module tree that the frozen Mailpit
// entrypoints can load on both supported host platforms.  Keeping the original
// relative paths makes every local require resolve inside this immutable copy.
const SOURCE_FILES = Object.freeze([
  'scripts/local-mailpit.js',
  'scripts/local-docker-authority.js',
  'scripts/application-data-root.js',
  'scripts/lib/windows-private-state.js',
  'scripts/lib/windows-private-publication.js',
  'scripts/lib/windows-provisioning-journal.js',
  'scripts/lib/windows-owned-hyperv-observer.js',
  'scripts/lib/windows-owned-lab.js',
  'scripts/windows/windows-private-state.cs',
  'scripts/windows/windows-private-state.ps1',
  'scripts/windows/windows-private-publication.cs',
  'scripts/windows/windows-private-publication.ps1',
  'scripts/install/Windows/owned-hyperv-observer.ps1',
]);
const IMAGE = 'ghcr.io/axllent/mailpit@sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365';
const IMAGE_VERSION = 'v1.31.1';
const IMAGE_DIGEST = 'sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365';
const MAX_EVIDENCE_BYTES = 1024 * 1024;
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

async function validateExecutable(file, expected, label) {
  const stat = await fs.lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0 || sha256(await fs.readFile(file)) !== expected) throw new Error(`${label} pin mismatch`);
  return path.resolve(file);
}

async function writePrivateJson(file, value, { replace = false } = {}) {
  const bytes = Buffer.from(JSON.stringify(value, null, 2) + '\n');
  if (bytes.length > MAX_EVIDENCE_BYTES) throw new Error('Provisioning evidence exceeded its bound');
  const temporary = `${file}.${crypto.randomBytes(8).toString('hex')}.pending`;
  await fs.writeFile(temporary, bytes, { flag: 'wx', mode: 0o600 });
  try { if (replace) await fs.rename(temporary, file); else await fs.link(temporary, file); }
  finally { await fs.rm(temporary, { force: true }); }
  await fs.chmod(file, 0o600);
}

async function copyFrozenSource(root, evidence) {
  const source = path.join(evidence, 'source'); await fs.mkdir(source, { mode: 0o700 }); const snapshot = {};
  for (const relative of SOURCE_FILES) {
    const bytes = await fs.readFile(path.join(root, relative)); const target = path.resolve(source, relative);
    if (!target.startsWith(`${source}${path.sep}`)) throw new Error('Frozen source path escapes its private root');
    await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    snapshot[relative] = sha256(bytes); await fs.writeFile(target, bytes, { flag: 'wx', mode: 0o500 }); await fs.chmod(target, 0o500);
  }
  return { source, snapshot };
}

function buildProvisionPlan({ root = path.resolve(__dirname, '..'), node = process.execPath, dockerCli = 'docker', dockerHost = '<explicit-loopback-host>', nodeSha256 = '<owner-pin>', dockerCliSha256 = '<owner-pin>' } = {}) {
  return Object.freeze({ version: 2, scope: 'ipi-local-mailpit-provision', mode: 'plan', root, nodePath: node, nodeSha256, dockerCli, dockerCliSha256, dockerHost,
    sourceFiles: SOURCE_FILES, image: { ref: IMAGE, version: IMAGE_VERSION, digest: IMAGE_DIGEST }, runGate: 'MAILPIT_PROVISION_ISOLATED=1 plus --run and all executable pins', evidence: 'private retained intent/ready/cleanup receipts' });
}

async function cleanupOwnedMailpit({ docker, state, ownerId, name, assertOwned }) {
  if (!state?.containerId) return { status: 'no-recorded-container' };
  let inspected;
  try { inspected = JSON.parse((await docker(['inspect', state.containerId])).stdout)[0]; }
  catch (error) { if (error.code === 1) return { status: 'already-absent', containerId: state.containerId }; throw error; }
  assertOwned(inspected, { id: ownerId, name, state });
  if (inspected.Id !== state.containerId) throw new Error('Mailpit cleanup identity changed');
  await docker(['rm', '--force', state.containerId]);
  try { await docker(['inspect', state.containerId]); throw new Error('Mailpit cleanup did not remove the recorded container'); }
  catch (error) { if (error.code !== 1) throw error; }
  return { status: 'removed', containerId: state.containerId };
}

async function runProvision({ root = path.resolve(__dirname, '..'), evidenceRoot, execute = execFileAsync, environment = process.env,
  nodePath, nodeSha256, dockerCli, dockerCliSha256, dockerHost, request, connect, readinessAttempts = 60 } = {}) {
  if (environment.MAILPIT_PROVISION_ISOLATED !== '1') throw new Error('MAILPIT_PROVISION_ISOLATED=1 is required');
  if (!nodePath || !nodeSha256 || !dockerCli || !dockerCliSha256 || !dockerHost) throw new Error('Explicit Node, Docker CLI and Docker host pins are required');
  const node = await validateExecutable(nodePath, nodeSha256, 'Managed Node'); const cli = await validateExecutable(dockerCli, dockerCliSha256, 'Docker CLI');
  if (path.resolve(process.execPath) !== node) throw new Error('Launcher is not running under the pinned Node executable');
  const evidence = evidenceRoot || await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-ipi-mailpit-provision-')); await fs.mkdir(evidence, { recursive: true, mode: 0o700 });
  const { source, snapshot } = await copyFrozenSource(root, evidence);
  const mailpit = require(path.join(source, 'scripts/local-mailpit.js')); const authorityModule = require(path.join(source, 'scripts/local-docker-authority.js'));
  if (mailpit.MAILPIT_IMAGE !== IMAGE || mailpit.MAILPIT_IMAGE_VERSION !== IMAGE_VERSION || mailpit.MAILPIT_IMAGE_DIGEST !== IMAGE_DIGEST) throw new Error('Frozen Mailpit image constants do not match the launcher pin');
  const id = `ipi-mailpit-${crypto.randomBytes(16).toString('hex')}`; const name = `owasp-ai-goat-mailpit-${id}`; const env = { ...environment, DOCKER_HOST: dockerHost };
  const pinnedExecute = (_command, args, options = {}) => execute(cli, args, options); let resolved; let state; let primaryError = null; let cleanupResult = { status: 'not-attempted' };
  try {
    resolved = await authorityModule.resolveDockerAuthority({ directory: evidence, workspaceId: id, environment: env, execute: pinnedExecute, platform: process.platform, persist: false });
    const intent = { version: 2, ownerId: id, name, image: IMAGE, imageVersion: IMAGE_VERSION, imageDigest: IMAGE_DIGEST, dockerHost,
      dockerAuthorityDigest: authorityModule.authorityDigest(resolved.authority), nodePath: node, nodeSha256, dockerCli: cli, dockerCliSha256, sourceFiles: snapshot, createdAt: new Date().toISOString() };
    await writePrivateJson(path.join(evidence, 'intent.json'), intent);
    state = await mailpit.ensureLocalMailpit({ directory: evidence, id, execute: pinnedExecute, environment: env, pullImage: false,
      resolveAuthority: async () => resolved, readinessAttempts, ...(request ? { request } : {}), ...(connect ? { connect } : {}) });
    const docker = args => authorityModule.executeBoundDocker({ authority: resolved.authority, execute: pinnedExecute, environment: env, args });
    const repeated = await mailpit.ensureLocalMailpit({ directory: evidence, id, execute: pinnedExecute,
      environment: env, pullImage: false, existingOnly: true, resolveAuthority: async () => ({ ...resolved, persisted: true }),
      readinessAttempts, ...(request ? { request } : {}), ...(connect ? { connect } : {}) });
    if (repeated.containerId !== state.containerId || repeated.nonce !== state.nonce
        || repeated.smtpPort !== state.smtpPort || repeated.apiPort !== state.apiPort) {
      throw new Error('Mailpit repeated setup changed owned identity');
    }
    await mailpit.assertLocalMailpitReady({ statePath: path.join(evidence, 'mailpit.json'),
      execute: pinnedExecute, environment: env, resolveAuthority: async () => resolved,
      ...(request ? { request } : {}), ...(connect ? { connect } : {}) });
    await writePrivateJson(path.join(evidence, 'ready.json'), { version: 2, state,
      reuseVerified: true, startupVerified: true, authorityDigest: intent.dockerAuthorityDigest });
    return { evidence, state, authority: resolved.authority };
  } catch (error) { primaryError = error; error.evidenceRoot = evidence; throw error; }
  finally {
    try {
      if (resolved) {
        const docker = args => authorityModule.executeBoundDocker({ authority: resolved.authority, execute: pinnedExecute, environment: env, args }); let persisted = state;
        if (!persisted) { try { persisted = JSON.parse(await fs.readFile(path.join(evidence, 'mailpit.json'), 'utf8')); } catch {} }
        cleanupResult = await cleanupOwnedMailpit({ docker, state: persisted, ownerId: persisted?.id || id, name, assertOwned: mailpit.assertOwnedContainer });
      }
    } catch (cleanupError) { cleanupResult = { status: 'failed', error: `${cleanupError.name}: ${cleanupError.message}` }; if (primaryError) primaryError.cleanupError = cleanupError.message; else { cleanupError.evidenceRoot = evidence; throw cleanupError; } }
    finally {
      try { await writePrivateJson(path.join(evidence, 'cleanup.json'), { version: 2, status: cleanupResult, primaryError: primaryError?.message || null, completedAt: new Date().toISOString() }, { replace: true }); }
      catch (receiptError) { if (primaryError) primaryError.cleanupReceiptError = receiptError.message; else { receiptError.evidenceRoot = evidence; throw receiptError; } }
    }
  }
}

async function main(argv = process.argv.slice(2)) {
  const args = new Map(); for (let i = 0; i < argv.length; i += 1) if (argv[i].startsWith('--')) args.set(argv[i], argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true);
  const root = path.resolve(__dirname, '..'); if (!args.has('--run')) { process.stdout.write(`${JSON.stringify(buildProvisionPlan({ root, node: args.get('--node') || process.execPath, dockerCli: args.get('--docker-cli') || 'docker', dockerHost: args.get('--docker-host') || undefined, nodeSha256: args.get('--node-sha256') || '<owner-pin>', dockerCliSha256: args.get('--docker-cli-sha256') || '<owner-pin>' }))}\n`); return; }
  const result = await runProvision({ root, nodePath: args.get('--node'), nodeSha256: args.get('--node-sha256'), dockerCli: args.get('--docker-cli'), dockerCliSha256: args.get('--docker-cli-sha256'), dockerHost: args.get('--docker-host') });
  process.stdout.write(`${JSON.stringify({ status: 'completed-and-cleaned', evidence: result.evidence })}\n`);
}

if (require.main === module) main().catch(error => { process.stderr.write(`${error.stack || error}\nEvidence: ${error.evidenceRoot || 'unavailable'}\n`); process.exitCode = 1; });
module.exports = { SOURCE_FILES, IMAGE, IMAGE_VERSION, IMAGE_DIGEST, buildProvisionPlan, cleanupOwnedMailpit, copyFrozenSource, runProvision, validateExecutable };
