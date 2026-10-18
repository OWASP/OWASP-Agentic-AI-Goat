'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { resolveDockerAuthority, executeBoundDocker } = require('../../scripts/local-docker-authority');
const { ensureLocalMailpit, MAILPIT_IMAGE, MAILPIT_IMAGE_VERSION, MAILPIT_IMAGE_DIGEST } = require('../../scripts/local-mailpit');

const exec = promisify(execFile);
const enabled = process.env.MAILPIT_PROVISION_ISOLATED === '1';

test('owned Mailpit provisioning uses the pinned image and cleans its private container', {
  skip: !enabled,
  timeout: 120000,
}, async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-mailpit-provision-'));
  const id = `fixture-${randomBytes(8).toString('hex')}`;
  let state;
  let resolved;
  const name = `dvaia-mailpit-${id}`;
  t.diagnostic(JSON.stringify({ evidenceRoot: directory, ownerId: id, image: MAILPIT_IMAGE, imageDigest: MAILPIT_IMAGE_DIGEST }));
  try {
    resolved = await resolveDockerAuthority({ directory, workspaceId: id, environment: process.env, execute: exec, persist: false });
    await fs.writeFile(path.join(directory, 'launch-intent.json'), JSON.stringify({ version: 1, ownerId: id, name,
      image: MAILPIT_IMAGE, imageVersion: MAILPIT_IMAGE_VERSION, imageDigest: MAILPIT_IMAGE_DIGEST,
      dockerAuthorityDigest: require('../../scripts/local-docker-authority').authorityDigest(resolved.authority), pullImage: false }) + '\n', { mode: 0o600 });
    state = await ensureLocalMailpit({ directory, id, execute: exec, pullImage: false });
    assert.equal(state.image, MAILPIT_IMAGE);
    assert.equal(state.imageVersion, MAILPIT_IMAGE_VERSION);
    assert.match(state.apiUrl, /^http:\/\/127\.0\.0\.1:\d+$/);
    const docker = args => executeBoundDocker({ authority: resolved.authority, execute, environment: process.env, args });
    const inspected = JSON.parse((await docker(['inspect', state.name])).stdout)[0];
    assert.equal(inspected.Config.Labels['org.dvaia.workspace'], id);
    assert.equal(inspected.Config.Image, MAILPIT_IMAGE);
    t.diagnostic(JSON.stringify({ imageVersion: state.imageVersion, imageDigest: state.imageDigest, apiPort: state.apiPort, smtpPort: state.smtpPort }));
  } finally {
    if (resolved) {
      const docker = args => executeBoundDocker({ authority: resolved.authority, execute, environment: process.env, args });
      let candidate = null;
      try { candidate = JSON.parse((await docker(['inspect', state?.containerId || name])).stdout)[0]; } catch {}
      if (candidate?.Config?.Labels?.['org.dvaia.workspace'] === id
        && candidate.Config.Labels?.['org.dvaia.mailpit.nonce'] === state?.nonce
        && (candidate.Config.Image === MAILPIT_IMAGE || candidate.Image === MAILPIT_IMAGE_DIGEST)) {
        await docker(['rm', '--force', candidate.Id]);
        await assert.rejects(docker(['inspect', candidate.Id]));
      }
    }
    // Preserve the private evidence directory for review after a failed gated run.
    if (!state) await fs.rm(directory, { recursive: true, force: true });
  }
});
