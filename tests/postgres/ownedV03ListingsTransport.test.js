'use strict';

// Controlled V03 source contract: no guest, Docker, SSH or model execution.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const zlib = require('node:zlib');
const adapter = require('./ownedMcpOriginalBuildAdapter');
const driver = require('./ownedV03ListingsDriver');

const RUN_ID = 'a74989568eb99e07aa2974d44d6f1513';
const CURRENT_PLAN_SHA256 = 'b1bdc42ad4e3746aa254ab689a29897a03a0b0b15ba3e37ea5e23c44313af0fc';
const hash = value => createHash('sha256').update(value).digest('hex');

test('V03 derives a bounded exact system-tag transport from every admitted plan command', async () => {
  assert.equal(typeof driver._internals?.transportPlannedCommand, 'function');
  const plan = await adapter.originalBuildPlan(process.cwd(), RUN_ID,
    { target: 'listings-package', listingsMode: 'v03-manager' });
  // The retained failed admission pins the pre-fix plan; this pins the new source.
  assert.equal(adapter.planDigest(plan), CURRENT_PLAN_SHA256);
  const sourceDefault = adapter._internals.phaseTransport('printf inert');
  assert.deepEqual(adapter._internals.phaseTransport('printf inert', 'owned-original-build'), sourceDefault);
  const selected = driver._internals.transportPlannedCommand;
  for (const [name, raw] of Object.entries(plan.commands)) {
    const seconds = name === 'metadataFetch' ? 310 : 150;
    const value = selected(plan, name, seconds);
    const expected = adapter._internals.phaseTransport(raw, 'owned-system-build');
    assert.equal(value.command, expected.command, name);
    assert.equal(value.sourceSha256, hash(raw), name);
    assert.equal(value.commandSha256, hash(value.command), name);
    assert.equal(value.decodedBytes, Buffer.byteLength(raw), name);
    assert(value.encodedBytes <= 32768 && value.envelopeBytes <= 65535, name);
    const parts = / '([A-Za-z0-9+/=]+)' '[a-f0-9]{64}' "\$0" "\$@"$/.exec(value.command);
    assert(parts, name);
    assert.equal(zlib.gunzipSync(Buffer.from(parts[1], 'base64')).toString(), raw, name);
  }
  for (const tag of ['', 'owned-original', 'owned-system-build '])
    assert.throws(() => adapter._internals.phaseTransport('printf inert', tag),
      /ORIGINAL_BUILD_TRANSPORT_OWNER/);
  assert.throws(() => selected(plan, 'relayStart', 311), /V03_LISTINGS_COMMAND/);
  assert.throws(() => selected(plan, 'unknown', 150), /V03_LISTINGS_COMMAND/);
  const changed = { ...plan, commands: { ...plan.commands, relayStart: `${plan.commands.relayStart}\0` } };
  assert.throws(() => selected(changed, 'relayStart', 150),
    /ORIGINAL_BUILD_TRANSPORT_SCRIPT/);
});

test('the selected system decoder executes only intact inert bytes under the closed tag', () => {
  const oldGuard = "sys.argv[3]=='owned-original-build'";
  const original = adapter._internals.PHASE_DECODER;
  assert.equal(original.split(oldGuard).length, 2);
  const decoder = original.replace(oldGuard, "sys.argv[3]=='owned-system-build'");
  const script = 'printf v03-decoder-ok';
  const encoded = zlib.gzipSync(Buffer.from(script)).toString('base64');
  const guest = `/var/tmp/dvaia-v23-build-${RUN_ID}`;
  const invoke = (payload, digest, tag) => spawnSync('/opt/homebrew/bin/python3',
    ['-I', '-S', '-B', '-c', decoder, payload, digest, tag, guest, RUN_ID],
    { env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }, timeout: 2000, maxBuffer: 65536 });
  const valid = invoke(encoded, hash(script), 'owned-system-build');
  assert.equal(valid.error, undefined);
  assert.equal(valid.status, 0);
  assert.equal(valid.stdout.toString(), 'v03-decoder-ok');
  for (const invalid of [
    invoke(encoded, hash(script), 'owned-original-build'),
    invoke(encoded, hash('changed'), 'owned-system-build'),
    invoke(Buffer.concat([Buffer.from(encoded, 'base64'), Buffer.from('extra')]).toString('base64'),
      hash(script), 'owned-system-build'),
  ]) assert.notEqual(invalid.status, 0);
});
