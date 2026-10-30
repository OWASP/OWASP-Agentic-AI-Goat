'use strict';
// Controlled filesystem, native publication, VM observer and process providers.
// These checks establish no native Windows, SSH or Hyper-V qualification.
const test = require('node:test'), assert = require('node:assert/strict'), crypto = require('node:crypto');
const { createWindowsOwnedLab, describeOwnedLab } = require('../scripts/lib/windows-owned-lab');
const { createWindowsProvisioningJournal } = require('../scripts/lib/windows-provisioning-journal');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const options = { directory: 'C:\\Users\\Learner Space\\private', workspaceId: '0123456789ab', installationId: '11111111-1111-4111-8111-111111111111', operationId: '22222222-2222-4222-8222-222222222222',
  instanceName: 'owasp-ai-goat-lab-0123456789ab', multipassExecutable: 'C:\\Program Files\\Multipass\\bin\\multipass.exe', sshExecutable: 'C:\\Windows\\System32\\OpenSSH\\ssh.exe', image: '24.04' };
const statePath = options.directory + '\\windows-owned-lab.json';
const hostBlob = Buffer.concat([Buffer.from([0,0,0,11]),Buffer.from('ssh-ed25519'),Buffer.from([0,0,0,32]),Buffer.alloc(32,7)]);
const hostKey = 'ssh-ed25519 ' + hostBlob.toString('base64');
function fixture() {
  const files = new Map(), intents = new Map(), calls = [], remote = new Map(), executions = []; let serial = 2;
  let directoryId = '0000000000000001', vmId = '33333333-3333-4333-8333-333333333333', vmState = 'Running', owner, daemonId = 'owned-daemon', driver = 'hyperv', fault, collision = false, key = hostKey, mounted = false;
  const receipt = (value, state) => ({ state, intentSha256: hash(value.resultBytes), size: value.resultBytes.length, identity: value.identity });
  const privateState = {
    ensurePrivateDirectory() {}, inspectPrivateDirectory(p) { return { path: p, identity: { volumeSerial: 9, fileId: directoryId } }; },
    readPrivateFile(p) { if (!files.has(p)) throw Error('private denied secret'); return Buffer.from(files.get(p).bytes); },
    createPrivateFile(p, bytes) { if (files.has(p)) throw Error('create-new collision'); files.set(p, { bytes: Buffer.from(bytes), identity: { volumeSerial: 9, fileId: (++serial).toString(16).padStart(16,'0') } }); },
  };
  privateState.readAndFlushPrivateFile = privateState.readPrivateFile;
  const publication = {
    preparePrivatePublication(p) {
      calls.push(['prepare', p.targetPath]);
      const existing = files.get(p.targetPath);
      if (existing ? p.originalBytes === null || !existing.bytes.equals(p.originalBytes) : p.originalBytes !== null) throw Error('prior mismatch secret');
      const value = { ...p, identity: { volumeSerial: 9, fileId: (++serial).toString(16).padStart(16,'0') } }; intents.set(p.intentPath, value); return receipt(value, 'prepared');
    },
    publishPrivatePublication(p) { const value = intents.get(p.intentPath); files.set(p.targetPath, { bytes: Buffer.from(value.resultBytes), identity: value.identity }); return receipt(value, 'committed'); },
  };
  const journal = createWindowsProvisioningJournal({ platform: 'win32', privateState, publication });
  const execute = async (program, args, executionOptions) => {
    executions.push({ program, args, options: executionOptions });
    calls.push([program === options.multipassExecutable ? 'mp' : 'ssh', ...args]);
    if (fault && fault(program, args)) throw Object.assign(Error('password=SECRET stderr'), { code: fault.exitCode || 'EACCES', stderr: 'SECRET' });
    let stdout = '';
    if (program === options.multipassExecutable) {
      if (args[0] === 'get') stdout = driver;
      else if (args[0] === 'version') stdout = JSON.stringify({ multipass: '1.16.4+win', multipassd: '1.16.4+win' });
      else if (args[0] === 'list') stdout = JSON.stringify({ list: collision ? [{name: options.instanceName}] : [] });
      else if (args[0] === 'launch') { const config = JSON.parse(files.get(args.at(-1)).bytes.toString().replace(/^#cloud-config\n/, '')); owner = config.write_files[0].content; }
      else if (args[0] === 'start') vmState = 'Running';
      else if (args[0] === 'info') stdout = JSON.stringify({ errors: [], info: { [options.instanceName]: { state: vmState, image_hash: 'a'.repeat(64), snapshot_count: 0, mounts: mounted ? { host: {} } : {}, ipv4: ['172.20.30.40'] } } });
      else if (args[0] === 'transfer') { remote.set(args[2].slice(args[2].indexOf(':') + 1), Buffer.from(files.get(args[1]).bytes)); }
      else if (args[0] === 'exec') {
        const argv = args.slice(3);
        if (argv.at(-1).endsWith('/owner.json')) stdout = owner;
        else if (argv.at(-1) === '/etc/machine-id') stdout = 'b'.repeat(32) + '\n';
        else if (argv.at(-1) === '/etc/ssh/ssh_host_ed25519_key.pub') stdout = key + ' root@guest\n';
        else if (argv[0] === 'sha256sum') stdout = hash(remote.get(argv[1])) + '  ' + argv[1] + '\n';
      }
    } else {
      const command = args.at(-1), words = [...command.matchAll(/'([^']*)'/g)].map(match => match[1]);
      if (command.includes("'docker' 'info'")) stdout = JSON.stringify(daemonId);
      else if (command.includes("'cat'") && command.includes('/owner.json')) stdout = owner;
      else if (command.includes("'sh' '-c'") && command.includes('printf ABSENT')) {
        const target = command.match(/(?:\/var\/lib\/owasp-ai-goat|\/etc\/apparmor\.d)[A-Za-z0-9_./-]+/)[0];
        stdout = remote.has(target) ? hash(remote.get(target)) + '  ' + target : 'ABSENT';
      } else if (command.includes("'install'") && !command.includes("'-d'")) remote.set(words.at(-1), Buffer.from(remote.get(words.at(-2))));
      else if (command.includes("'sha256sum'")) stdout = hash(remote.get(words.at(-1))) + '  ' + words.at(-1) + '\n';
      else if (command.includes("'stat'")) stdout = command.includes('/bundles/') ? '0:0:644\n' : '0:0:600\n';
      else if (command.includes('/sys/kernel/security/apparmor/profiles')) stdout = 'owasp-ai-goat-mcp-sandbox (enforce)\n';
      else if (command.includes("'docker'")) stdout = 'docker-result';
    }
    return { stdout };
  };
  const factory = createWindowsOwnedLab({ filesystemPlatform: 'win32', privateState, journal,
    fileSystem: { lstatSync(p) { if (!files.has(p)) throw Object.assign(Error('absent'), {code:'ENOENT'}); return {}; } }, execute,
    keyPairFactory: () => ({ privateKey: Buffer.from('controlled PEM'), publicKey: 'ssh-rsa AAAA' }),
    observeVm: async name => ({ version: 1, operation: 'observeOwnedHyperVVm', name, vmId, state: vmState }),
  });
  return { factory, files, calls, remote, intents, executions, prepare: () => factory.prepareOwnedLab(options), setFault(v) { fault = v; }, setVm(id, state = 'Running') { vmId = id; vmState = state; }, setDriver(v) { driver = v; }, collide() { collision = true; }, replaceDirectory() { directoryId = '0000000000000099'; }, setDaemon(v) { daemonId = v; }, setHostKey(v) { key = v; }, mount() { mounted = true; } };
}
test('guest bootstrap explicitly installs and enables its required services', async () => {
  const f = fixture(); await f.prepare();
  const config = JSON.parse(f.files.get(options.directory + '\\windows-owned-lab.cloud-init.json').bytes.toString().replace(/^#cloud-config\n/, ''));
  for (const dependency of ['docker.io', 'docker-compose-v2', 'apparmor', 'openssh-server']) assert.ok(config.packages.includes(dependency));
  assert.ok(config.runcmd.some(args => args.join(' ') === 'systemctl enable --now docker.service ssh.service apparmor.service'));
});
test('real owned session composes with Docker authority for fresh provisioning verbs', async () => {
  const f = fixture(), session = await f.prepare();
  const authorityApi = require('../scripts/local-docker-authority');
  const { authority } = await authorityApi.resolveDockerAuthority({ directory: options.directory,
    workspaceId: options.workspaceId, platform: 'win32', ownedLabSession: session,
    storage: { async readLocalDockerAuthority() { return null; } } });
  await authorityApi.executeBoundDocker({ authority, args: ['volume', 'create', '--label', `org.owasp-ai-goat.workspace=${options.workspaceId}`, `owasp-ai-goat-postgres-${options.workspaceId}`] });
  assert.ok(f.calls.some(row => row[0] === 'ssh' && row.at(-1).includes("'docker' 'volume' 'create'")));
  await assert.rejects(session.executeDocker(['volume', 'create', 'not-admitted-in-inspect']));
});
test('fresh database image acquisition allows only the reviewed tag or immutable digest', async () => {
  const f = fixture(), session = await f.prepare();
  await session.executeDocker(['pull', 'postgres:18'], { scope: 'provision' });
  assert.ok(f.calls.at(-1).at(-1).includes("'docker' 'pull' 'postgres:18'"));
  await session.executeDocker(['pull', 'postgres@sha256:' + 'a'.repeat(64)], { scope: 'provision' });
  for (const args of [['pull', 'postgres:latest'], ['pull', 'postgres:17'], ['pull', 'postgres:18', '--all-tags']]) {
    await assert.rejects(session.executeDocker(args, { scope: 'provision' }));
  }
  await assert.rejects(session.executeDocker(['pull', 'postgres:18']));
});
test('reviewed builds retain the caller ten-minute bound; other operations stay bounded', async () => {
  const f = fixture(), session = await f.prepare();
  await session.executeDocker(['compose', 'up', '--build', '--wait', 'mcp-owned-sandbox'], { scope: 'provision', timeoutMs: 600000 });
  assert.equal(f.executions.at(-1).options.timeout, 600000);
  await assert.rejects(session.executeDocker(['info'], { timeoutMs: 600000 }));
  await assert.rejects(session.executeDocker(['compose', 'up'], { scope: 'provision', timeoutMs: 600001 }));
});
test('fresh creation retains prelaunch private journal and uses explicit released Hyper-V without global changes', async () => {
  const f = fixture(), session = await f.prepare();
  assert(Object.isFrozen(session)); assert.equal(describeOwnedLab(session).daemonId, null);
  assert.equal(f.calls.filter(call => call[0] === 'prepare').length, 2);
  assert(f.calls.findIndex(call => call[0] === 'prepare') < f.calls.findIndex(call => call[1] === 'launch'));
  assert(!f.calls.some(call => ['set', 'mount', 'delete', 'purge'].includes(call[1]) || call.includes('--all') || call.includes('primary')));
  const config = f.files.get(options.directory + '\\windows-owned-lab.cloud-init.json').bytes.toString();
  assert(config.startsWith('#cloud-config\n')); assert(config.includes('docker-compose-v2'));
  const binding = await session.bindDaemon(); assert.equal(binding.daemonId, 'owned-daemon'); assert.equal(binding.vmId, '33333333-3333-4333-8333-333333333333');
  assert.equal(binding.host, 'owned-hyperv:' + binding.vmId); assert.equal(f.intents.size, 3);
});
test('existing ready state reuses exact keys and verifies VMId before starting stopped owned VM', async () => {
  const f = fixture(), first = await f.prepare(); await first.bindDaemon(); const count = f.files.size;
  f.setVm(describeOwnedLab(first).vmId, 'Off'); const second = await f.prepare();
  assert.equal(f.files.size, count); assert.equal(f.calls.filter(call => call[1] === 'launch').length, 1);
  assert.equal(f.calls.filter(call => call[1] === 'start').length, 1); assert.equal((await second.bindDaemon()).daemonId, 'owned-daemon');
  f.setVm('44444444-4444-4444-8444-444444444444', 'Off'); await assert.rejects(f.prepare(), {code:'WINDOWS_OWNED_LAB_DENIED'});
  assert.equal(f.calls.filter(call => call[1] === 'start').length, 1);
});
test('collision and unsupported existing driver fail before writes or global mutation', async () => {
  for (const change of [f => f.collide(), f => f.setDriver('virtualbox'), f => f.setDriver('hcs')]) {
    const f = fixture(); change(f); await assert.rejects(f.prepare()); assert.equal(f.files.size, 0); assert(!f.calls.some(call => call[1] === 'launch' || call[1] === 'set'));
  }
});
test('runtime existingOnly refuses absent state before key/journal/launch and validates boolean', async () => {
  const f = fixture();
  await assert.rejects(f.factory.prepareOwnedLab({...options,existingOnly:true}),{code:'WINDOWS_OWNED_LAB_STATE_UNCERTAIN'});
  assert.equal(f.files.size,0); assert(!f.calls.some(call => call[0] === 'prepare' || call[1] === 'launch'));
  await assert.rejects(f.factory.prepareOwnedLab({...options,existingOnly:'true'})); assert.equal(f.files.size,0);
});
test('failed launch retains prepared journal and refuses replay/adoption on retry', async () => {
  const f = fixture(); f.setFault((program, args) => args[0] === 'launch'); await assert.rejects(f.prepare(), {code:'WINDOWS_OWNED_LAB_DENIED'});
  assert.equal(JSON.parse(f.files.get(statePath).bytes).phase, 'prepared'); const retained = Buffer.from(f.files.get(statePath).bytes);
  f.setFault(null); await assert.rejects(f.prepare(), {code:'WINDOWS_OWNED_LAB_STATE_UNCERTAIN'});
  assert(f.files.get(statePath).bytes.equals(retained)); assert.equal(f.calls.filter(call => call[1] === 'launch').length, 1);
});
test('opaque brand refuses fabricated sessions and remains fenced by directory/guest/daemon identity', async () => {
  assert.throws(() => describeOwnedLab({binding:{daemonId:'fake'}}));
  for (const change of [f => f.replaceDirectory(), f => f.setDaemon('foreign'), f => f.setHostKey('ssh-ed25519 ' + Buffer.alloc(51).toString('base64')), f => f.mount()]) {
    const f = fixture(), session = await f.prepare(); await session.bindDaemon(); change(f);
    await assert.rejects(session.executeDocker(['inspect','owned']));
  }
});
test('reviewed bundle and private env use exact file hashes and admitted guest paths, never host mounts', async () => {
  const f = fixture(), session = await f.prepare(); await session.bindDaemon();
  const bytes = Buffer.from('FROM node\n'), bundlePath = await session.stageReviewedBundle([{path:'sidecars/sandbox-runner/Dockerfile',bytes,sha256:hash(bytes)}]);
  assert.match(bundlePath,/\/bundles\/[a-f0-9]{64}$/); assert.equal(await session.executeDocker(['build','sidecars/sandbox-runner'],{scope:'provision',bundlePath}),'docker-result');
  const build = f.calls.find(call => call[0] === 'ssh' && call.at(-1).includes("'docker' 'build'"));
  assert(build.at(-1).startsWith("'sudo' '-n' 'sh' '-c' 'cd \"$1\" && shift && exec \"$@\"' 'sh' "));
  assert.equal(f.remote.get(bundlePath + '/sidecars/sandbox-runner/Dockerfile').toString(),bytes.toString());
  const env = Buffer.from('POSTGRES_PASSWORD=controlled-secret\n'), guestPath = await session.stagePrivateEnvironment({bytes:env,sha256:hash(env)});
  assert.match(guestPath,/\/private\/env-[a-f0-9]{64}$/);
  await session.executeDocker(['run','--env-file',guestPath,'postgres'],{scope:'provision'});
  assert(!JSON.stringify(f.calls).includes('controlled-secret'));
  await assert.rejects(session.executeDocker(['run','--env-file','C:\\private\\secret.env','postgres'],{scope:'provision'}));
  await assert.rejects(session.executeDocker(['run','--mount','type=bind,source=/etc,target=/host','image'],{scope:'provision'}));
  await assert.rejects(session.stageReviewedBundle([{path:'sidecars/../.env',bytes,sha256:hash(bytes)}]));
  await assert.rejects(session.stageReviewedBundle([{path:'sidecars/x',bytes,sha256:'a'.repeat(64)}]));
});
test('profile installer verifies parse, exact existing bytes, root600 and loaded enforce profile', async () => {
  const f = fixture(), session = await f.prepare(), bytes = Buffer.from('profile controlled {}\n');
  const result = await session.installAndVerifyProfile({name:'owasp-ai-goat-mcp-sandbox',bytes,sha256:hash(bytes)});
  assert.equal(result.destination,'/etc/apparmor.d/owasp-ai-goat-mcp-sandbox');
  assert(f.calls.some(call => call.at(-1).includes("'apparmor_parser' '--skip-kernel-load'")));
  f.remote.set(result.destination,Buffer.from('foreign'));
  await assert.rejects(session.installAndVerifyProfile({name:'owasp-ai-goat-mcp-sandbox',bytes,sha256:hash(bytes)}));
  assert.equal(f.remote.get(result.destination).toString(),'foreign');
});
test('startup profile verification cannot install a missing retained profile', async () => {
  const f = fixture(), session = await f.prepare(), bytes = Buffer.from('profile reviewed {}\n');
  const request = { name: 'owasp-ai-goat-mcp-sandbox', bytes, sha256: hash(bytes) };
  await assert.rejects(session.installAndVerifyProfile({ ...request, existingOnly: true }));
  assert.equal(f.remote.has('/etc/apparmor.d/owasp-ai-goat-mcp-sandbox'), false);
  await session.installAndVerifyProfile(request);
  const before = f.calls.filter(row => row[0] === 'ssh' && row.at(-1).includes("'install' '-o'")).length;
  await session.installAndVerifyProfile({ ...request, existingOnly: true });
  assert.equal(f.calls.filter(row => row[0] === 'ssh' && row.at(-1).includes("'install' '-o'")).length, before);
});
test('Docker missing-resource exit1 is scrubbed while SSH255 remains transport denial', async () => {
  const f = fixture(), session = await f.prepare(); await session.bindDaemon();
  const fault = (program,args) => program === options.sshExecutable && args.at(-1).includes("'docker' 'inspect'"); fault.exitCode = 1; f.setFault(fault);
  await assert.rejects(session.executeDocker(['inspect','absent']), error => error.code === 1 && error.exitCode === 1 && !JSON.stringify(error).includes('SECRET') && error.message === 'Owned guest Docker command failed');
  fault.exitCode = 255; await assert.rejects(session.executeDocker(['inspect','absent']),{code:'WINDOWS_OWNED_LAB_DENIED'});
});
test('bounded PostgreSQL start/readiness supports existing contract and rejects arbitrary container exec', async () => {
  const f = fixture(), session = await f.prepare(); await session.bindDaemon(); const name = 'owasp-ai-goat-postgres-' + options.workspaceId;
  await session.executeDocker(['start',name],{scope:'provision'});
  await session.executeDocker(['exec',name,'pg_isready','-h','127.0.0.1','-U','postgres'],{scope:'provision'});
  await assert.rejects(session.executeDocker(['exec',name,'sh','-c','id'],{scope:'provision'}));
  await assert.rejects(session.executeDocker(['--host','ssh://foreign','info']));
  const image = 'ghcr.io/axllent/mailpit@sha256:' + 'a'.repeat(64);
  await session.executeDocker(['pull',image],{scope:'provision'});
  await session.executeDocker(['start','owasp-ai-goat-mailpit-' + options.workspaceId],{scope:'provision'});
  await session.executeDocker(['rm','--force','b'.repeat(64)],{scope:'provision'});
  await assert.rejects(session.executeDocker(['pull','mailpit:latest'],{scope:'provision'}));
  await assert.rejects(session.executeDocker(['rm','--force','foreign-name'],{scope:'provision'}));
  await assert.rejects(session.executeDocker(['run','--privileged','image'],{scope:'provision'}));
});
test('owned SSH forwards bind only host/guest loopback and close waits owned stopAndJoin', async () => {
  const f = fixture(), session = await f.prepare(); let request, joined = false;
  await session.openLoopbackForwards([{local:8093,guest:8093}],{ownChild:async value => { request=value; return {async stopAndJoin(){joined=true;}}; }});
  assert(request.args.includes('ExitOnForwardFailure=yes')); assert(request.args.includes('127.0.0.1:8093:127.0.0.1:8093'));
  assert(request.args.includes('StrictHostKeyChecking=yes')); assert(request.args.includes('-F')); assert(request.args.includes('NUL'));
  await session.closeForwards(); assert(joined); assert.throws(()=>describeOwnedLab(session)); await assert.rejects(session.assertCurrent());
});
test('sequential PostgreSQL, Mailpit, base and protected forwards share identical ports and own disjoint jobs', async () => {
  const f = fixture(), session = await f.prepare(); let starts = 0;
  const ownChild = async () => { starts++; return { async stopAndJoin() {} }; };
  await session.openLoopbackForwards([{local:54329,guest:54329}],{ownChild});
  await session.openLoopbackForwards([{local:1025,guest:1025},{local:8025,guest:8025}],{ownChild});
  const base = [{local:1025,guest:1025},{local:8025,guest:8025},{local:8090,guest:8090},{local:8091,guest:8091},{local:9099,guest:9099}];
  const first = await session.openLoopbackForwards(base,{ownChild});
  assert.equal(await session.openLoopbackForwards(base,{ownChild}),first); assert.equal(starts,3);
  await session.openLoopbackForwards([{local:8092,guest:8092},{local:8093,guest:8093},{local:8094,guest:8094}],{ownChild}); assert.equal(starts,4);
  await session.openLoopbackForwards([{local:8093,guest:8093}],{ownChild}); assert.equal(starts,4);
  await assert.rejects(session.openLoopbackForwards([{local:8093,guest:8094}],{ownChild}));
  await assert.rejects(session.openLoopbackForwards([{local:8093,guest:8093}],{ownChild:async()=>({async stopAndJoin(){}})})); assert.equal(starts,4);
  await session.closeForwards();
});
