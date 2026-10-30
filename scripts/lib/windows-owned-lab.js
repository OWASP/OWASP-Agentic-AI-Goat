'use strict';
// Foundation only: ownership is a recorded guest identity, not an immutable
// hypervisor UUID. A privileged host/Multipass administrator can clone it.
// No caller may infer native Windows qualification from controlled providers.
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const net = require('node:net');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const privateDefaults = require('./windows-private-state');
const journalDefaults = require('./windows-provisioning-journal');
const sessions = new WeakMap();
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const uuid = value => typeof value === 'string' && value.length === 36 && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
const hash = value => typeof value === 'string' && value.length === 64 && /^[a-f0-9]{64}$/.test(value);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const denied = (code = 'WINDOWS_OWNED_LAB_DENIED') => Object.assign(Error('Owned Windows lab unavailable'), { code });
const quote = value => "'" + value.replace(/'/g, "'\\''") + "'";
const sameIdentity = (a, b) => a && b && a.volumeSerial === b.volumeSerial && a.fileId === b.fileId;
function rsaKeyPair() {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const field = bytes => { const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length); return Buffer.concat([length, bytes]); };
  const mpint = value => { let bytes = Buffer.from(value, 'base64url'); if (bytes[0] & 128) bytes = Buffer.concat([Buffer.from([0]), bytes]); return field(bytes); };
  const publicKey = 'ssh-rsa ' + Buffer.concat([field(Buffer.from('ssh-rsa')), mpint(jwk.e), mpint(jwk.n)]).toString('base64');
  return { privateKey: Buffer.from(pair.privateKey.export({ format: 'pem', type: 'pkcs1' })), publicKey };
}
function createWindowsOwnedLab({ filesystemPlatform = process.platform, privateState = privateDefaults,
  journal = journalDefaults, fileSystem = fs, execute = promisify(execFile), keyPairFactory = rsaKeyPair,
  observeVm = name => require('./windows-owned-hyperv-observer').observeOwnedHyperVVm(name) } = {}) {
  async function prepareOwnedLab(options) {
    try {
      const optionKeys = ['directory', 'workspaceId', 'installationId', 'operationId', 'instanceName', 'multipassExecutable', 'sshExecutable', 'image'];
      if (filesystemPlatform !== 'win32' || !(exact(options, optionKeys) || exact(options, [...optionKeys, 'existingOnly']))
        || (Object.hasOwn(options, 'existingOnly') && typeof options.existingOnly !== 'boolean')
        || typeof options.workspaceId !== 'string' || ![12, 64].includes(options.workspaceId.length) || !/^(?:[a-f0-9]{12}|[a-f0-9]{64})$/.test(options.workspaceId) || !uuid(options.installationId) || !uuid(options.operationId)
        || typeof options.instanceName !== 'string' || /[\r\n]/.test(options.instanceName) || !/^owasp-ai-goat-lab-[a-z0-9](?:[a-z0-9-]{0,45}[a-z0-9])?$/.test(options.instanceName) || options.image !== '24.04') throw denied();
      options = Object.freeze({ ...options });
      const directory = privateDefaults.normalizePrivatePath(options.directory);
      const multipass = privateDefaults.normalizePrivatePath(options.multipassExecutable);
      const ssh = privateDefaults.normalizePrivatePath(options.sshExecutable);
      // Executables are explicitly admitted by the installer. No PATH lookup,
      // global Docker context, driver setting or primary instance is used here.
      const statePath = privateDefaults.normalizePrivatePath(path.win32.join(directory, 'windows-owned-lab.json'));
      const keyPath = privateDefaults.normalizePrivatePath(path.win32.join(directory, 'windows-owned-lab.pem'));
      const knownHostsPath = privateDefaults.normalizePrivatePath(path.win32.join(directory, 'windows-owned-lab.hosts'));
      if (!options.existingOnly) privateState.ensurePrivateDirectory(directory);
      const directoryIdentity = Object.freeze({ ...privateState.inspectPrivateDirectory(directory).identity });
      const verifyDirectory = () => { if (!sameIdentity(directoryIdentity, privateState.inspectPrivateDirectory(directory).identity)) throw denied(); };
      const read = filename => {
        verifyDirectory();
        const bytes = (privateState.readAndFlushPrivateFile || privateState.readPrivateFile).call(privateState, filename);
        if (!Buffer.isBuffer(bytes) || bytes.length > 65536) throw denied();
        return Buffer.from(bytes);
      };
      const absent = filename => {
        try { fileSystem.lstatSync(filename); return false; }
        catch (error) { if (error.code === 'ENOENT') return true; throw denied(); }
      };
      const run = async (program, args, timeout = 30000, dockerCommand = false) => {
        verifyDirectory();
        try {
          const result = await execute(program, args, { timeout, maxBuffer: 1024 * 1024, encoding: 'utf8', windowsHide: true });
          if (typeof result.stdout !== 'string' || Buffer.byteLength(result.stdout) > 1024 * 1024) throw denied();
          verifyDirectory(); return result.stdout;
        } catch (error) {
          if (dockerCommand && Number.isInteger(error.code) && error.code > 0 && error.code < 255) {
            throw Object.assign(Error('Owned guest Docker command failed'), { code: error.code, exitCode: error.code, diagnosticCode: 'WINDOWS_OWNED_LAB_DOCKER_FAILED' });
          }
          throw denied();
        }
      };
      const mp = args => run(multipass, args);
      if ((await mp(['get', 'local.driver'])).trim() !== 'hyperv') throw denied('WINDOWS_OWNED_LAB_BACKEND_UNSUPPORTED');
      const version = (await mp(['version', '--format', 'json']));
      const versionInfo = JSON.parse(version);
      const clientVersion = versionInfo.multipass, daemonVersion = versionInfo.multipassd;
      if (typeof clientVersion !== 'string' || typeof daemonVersion !== 'string'
        || /[\r\n]/.test(clientVersion) || !/^1\.16\.[0-9]+(?:\+win)?$/.test(clientVersion) || Number(clientVersion.split('.')[2].split('+')[0]) < 4
        || daemonVersion !== clientVersion) throw denied('WINDOWS_OWNED_LAB_BACKEND_UNSUPPORTED');
      const markerFor = ownedInstanceUUID => ({ version: 1, workspaceId: options.workspaceId, installationId: options.installationId, ownedInstanceUUID });
      const observe = async () => {
        const value = await observeVm(options.instanceName);
        if (!exact(value, ['version', 'operation', 'name', 'vmId', 'state']) || value.version !== 1 || value.operation !== 'observeOwnedHyperVVm'
          || value.name !== options.instanceName || !uuid(value.vmId) || !['Running', 'Off', 'Saved'].includes(value.state)) throw denied();
        return value;
      };
      const info = async () => {
        const result = JSON.parse(await mp(['info', options.instanceName, '--format', 'json']));
        if (!exact(result, ['errors', 'info']) || !Array.isArray(result.errors) || result.errors.length || !exact(result.info, [options.instanceName])) throw denied();
        const value = result.info[options.instanceName];
        if (!value || value.state !== 'Running' || !hash(value.image_hash) || value.snapshot_count !== 0
          || (value.mounts && Object.keys(value.mounts).length) || !Array.isArray(value.ipv4)) throw denied();
        const addresses = value.ipv4.filter(address => net.isIP(address) === 4 && !/^127\.|^0\./.test(address));
        if (addresses.length !== 1) throw denied();
        return { imageHash: value.image_hash, ip: addresses[0] };
      };
      const guestMetadata = async id => {
        const base = '/var/lib/owasp-ai-goat/' + id;
        const marker = await mp(['exec', options.instanceName, '--', 'sudo', '-n', 'cat', base + '/owner.json']);
        if (marker !== encode(markerFor(id)).toString()) throw denied();
        const machineId = (await mp(['exec', options.instanceName, '--', 'cat', '/etc/machine-id'])).trim();
        const hostKey = (await mp(['exec', options.instanceName, '--', 'sudo', '-n', 'cat', '/etc/ssh/ssh_host_ed25519_key.pub'])).trim().split(/\s+/).slice(0, 2).join(' ');
        if (!/^[a-f0-9]{32}$/.test(machineId) || !/^ssh-ed25519 [A-Za-z0-9+/]{68}$/.test(hostKey)) throw denied();
        const keyBlob = Buffer.from(hostKey.split(' ')[1], 'base64');
        if (keyBlob.length !== 51 || keyBlob.readUInt32BE(0) !== 11 || keyBlob.subarray(4, 15).toString() !== 'ssh-ed25519' || keyBlob.readUInt32BE(15) !== 32) throw denied();
        return { machineId, hostKey };
      };
      let original, state;
      if (!absent(statePath)) {
        original = read(statePath); state = JSON.parse(original);
        if (!exact(state, ['version', 'phase', 'workspaceId', 'installationId', 'operationId', 'instanceName', 'ownedInstanceUUID', 'image', 'multipassVersion', 'keySha256', 'imageHash', 'machineId', 'hostKey', 'daemonId', 'vmId'])
          || state.version !== 1 || state.phase !== 'ready' || state.workspaceId !== options.workspaceId || state.installationId !== options.installationId
          || state.instanceName !== options.instanceName || state.image !== options.image || state.multipassVersion !== clientVersion
          || !uuid(state.operationId) || !uuid(state.ownedInstanceUUID) || !uuid(state.vmId) || !hash(state.keySha256) || !hash(state.imageHash)
          || typeof state.machineId !== 'string' || state.machineId.length !== 32 || !/^[a-f0-9]{32}$/.test(state.machineId) || typeof state.hostKey !== 'string' || typeof state.daemonId !== 'string'
          || !state.daemonId || state.daemonId.length > 256 || /[\x00-\x1f\x7f]/.test(state.daemonId) || !original.equals(encode(state))) throw denied('WINDOWS_OWNED_LAB_STATE_UNCERTAIN');
        const retainedVm = await observe();
        if (retainedVm.vmId !== state.vmId) throw denied();
        if (retainedVm.state !== 'Running') await run(multipass, ['start', options.instanceName], 300000);
        const started = await observe();
        if (started.vmId !== state.vmId || started.state !== 'Running') throw denied();
      } else {
        if (options.existingOnly) throw denied('WINDOWS_OWNED_LAB_STATE_UNCERTAIN');
        // A name collision is checked before recording launch authority. Never
        // adopt a same-named VM, including one with equal-looking metadata.
        const listed = JSON.parse(await mp(['list', '--format', 'json']));
        if (!Array.isArray(listed.list) || listed.list.some(item => item.name === options.instanceName)) throw denied();
        const ownedInstanceUUID = crypto.randomUUID();
        const pair = keyPairFactory();
        if (!pair || !Buffer.isBuffer(pair.privateKey) || pair.privateKey.length > 16384 || !/^ssh-rsa [A-Za-z0-9+/]+=*$/.test(pair.publicKey)) throw denied();
        privateState.createPrivateFile(keyPath, pair.privateKey);
        if (!read(keyPath).equals(pair.privateKey)) throw denied();
        state = { version: 1, phase: 'prepared', workspaceId: options.workspaceId, installationId: options.installationId,
          operationId: options.operationId, instanceName: options.instanceName, ownedInstanceUUID, image: options.image,
          multipassVersion: clientVersion, keySha256: digest(pair.privateKey) };
        original = encode(state);
        journal.createJournal({ filePath: statePath, bytes: original });
        if (!read(statePath).equals(original)) throw denied();
        const cloudInitPath = privateDefaults.normalizePrivatePath(path.win32.join(directory, 'windows-owned-lab.cloud-init.json'));
        const cloudInit = Buffer.concat([Buffer.from('#cloud-config\n'), encode({ users: ['default', { name: 'owasp-ai-goat', groups: ['sudo'], shell: '/bin/bash', sudo: 'ALL=(ALL) NOPASSWD:ALL', ssh_authorized_keys: [pair.publicKey], lock_passwd: true }],
          packages: ['docker.io', 'docker-compose-v2', 'apparmor', 'openssh-server'],
          write_files: [{ path: '/var/lib/owasp-ai-goat/' + ownedInstanceUUID + '/owner.json', owner: 'root:root', permissions: '0600', content: encode(markerFor(ownedInstanceUUID)).toString() }],
          runcmd: [['chmod', '0700', '/var/lib/owasp-ai-goat/' + ownedInstanceUUID],
            ['systemctl', 'enable', '--now', 'docker.service', 'ssh.service', 'apparmor.service']] })]);
        privateState.createPrivateFile(cloudInitPath, cloudInit);
        if (!read(cloudInitPath).equals(cloudInit)) throw denied();
        await run(multipass, ['launch', options.image, '--name', options.instanceName, '--cpus', '4', '--memory', '4G', '--disk', '30G', '--cloud-init', cloudInitPath], 600000);
        await run(multipass, ['exec', options.instanceName, '--', 'cloud-init', 'status', '--wait'], 300000);
        const vm = await observe(); if (vm.state !== 'Running') throw denied();
        const observed = await info(), metadata = await guestMetadata(ownedInstanceUUID);
        state = { ...state, imageHash: observed.imageHash, ...metadata, vmId: vm.vmId };
        privateState.createPrivateFile(knownHostsPath, Buffer.from('owasp-ai-goat-' + ownedInstanceUUID + ' ' + state.hostKey + '\n'));
      }
      const sshArgs = () => ['-F', 'NUL', '-i', keyPath, '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
        // -o values use ssh_config parsing as well as process argv parsing.
        // Quote the canonical path so a Windows user directory may contain spaces.
        '-o', 'UserKnownHostsFile="' + knownHostsPath.replace(/\\/g, '/') + '"', '-o', 'GlobalKnownHostsFile=NUL', '-o', 'HostKeyAlias=owasp-ai-goat-' + state.ownedInstanceUUID,
        '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2', '-o', 'ForwardAgent=no',
        '-o', 'PermitLocalCommand=no', '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'ControlMaster=no', '-o', 'RequestTTY=no'];
      const identityFiles = () => {
        if (digest(read(keyPath)) !== state.keySha256 || !read(knownHostsPath).equals(Buffer.from('owasp-ai-goat-' + state.ownedInstanceUUID + ' ' + state.hostKey + '\n'))) throw denied();
      };
      const guest = async (ip, argv, timeout) => run(ssh, [...sshArgs(), 'owasp-ai-goat@' + ip, argv.map(quote).join(' ')], timeout);
      const verifyGuest = async () => {
        const before = await observe(); if (before.vmId !== state.vmId || before.state !== 'Running') throw denied();
        identityFiles(); const observed = await info(), metadata = await guestMetadata(state.ownedInstanceUUID);
        if (observed.imageHash !== state.imageHash || metadata.machineId !== state.machineId || metadata.hostKey !== state.hostKey) throw denied();
        if (await guest(observed.ip, ['sudo', '-n', 'cat', '/var/lib/owasp-ai-goat/' + state.ownedInstanceUUID + '/owner.json']) !== encode(markerFor(state.ownedInstanceUUID)).toString()) throw denied();
        const after = await observe(); if (after.vmId !== before.vmId || after.state !== 'Running') throw denied();
        return observed;
      };
      await verifyGuest();
      // Docker installation is a caller phase. A newly created foundation may
      // have no daemon yet; it never installs packages as a hidden side effect.
      let daemonId = state.daemonId === 'unbound' ? null : state.daemonId || null;
      if (state.phase === 'prepared') {
        state = { ...state, phase: 'ready', daemonId: 'unbound' };
        journal.updateJournal({ filePath: statePath, originalBytes: original, resultBytes: encode(state) });
        original = encode(state);
      }
      const bindingSha256 = digest(encode({ ...markerFor(state.ownedInstanceUUID), instanceName: state.instanceName,
        vmId: state.vmId, imageHash: state.imageHash, machineId: state.machineId, hostKey: state.hostKey, multipassVersion: state.multipassVersion }));
      let closed = false, forwardOwner; const forwardGroups = new Set(), portBindings = new Map(), forwardReceipts = new Map();
      const forwards = new Set(), bundles = new Set(), environments = new Set(), secrets = new Set();
      const assertCurrent = async () => {
        if (closed || !read(statePath).equals(original) || (await mp(['get', 'local.driver'])).trim() !== 'hyperv') throw denied();
        const vm = await observe(); if (vm.vmId !== state.vmId || vm.state !== 'Running') throw denied();
        return verifyGuest();
      };
      const docker = async (args, { scope = 'inspect', bundlePath, timeoutMs = 300000 } = {}) => {
        if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000
          || timeoutMs > 300000 && !(scope === 'provision' && ['build', 'compose'].includes(args?.[0]))) throw denied();
        if (!Array.isArray(args) || !args.length || args.length > 256 || !args.every(arg => typeof arg === 'string' && arg.length <= 32768 && !/[\x00\r\n]/.test(arg))
          || args.some(arg => /^(?:--host(?:=|$)|-H$|--context(?:=|$)|--config(?:=|$))/.test(arg))
          || !(scope === 'inspect' ? ['info', 'inspect', 'ps', 'images'].includes(args[0]) || (args[0] === 'image' && args[1] === 'inspect') || (args[0] === 'volume' && args[1] === 'inspect')
            : scope === 'provision' && ['info', 'inspect', 'ps', 'image', 'images', 'volume', 'build', 'run', 'compose', 'start', 'exec', 'pull', 'rm'].includes(args[0]))
          || (args[0] === 'volume' && !['inspect', 'create'].includes(args[1])) || (args[0] === 'image' && args[1] !== 'inspect')
          || (bundlePath !== undefined && !bundles.has(bundlePath)) || args.some(arg => /^[a-z]:[\\/]/i.test(arg) || /(?:^|,)type=bind(?:,|$)/.test(arg))
          || args.some((arg, index) => arg === '--env-file' && !environments.has(args[index + 1]))
          || args.some(arg => arg.startsWith('--env-file=') && !environments.has(arg.slice(11)))
          || (args[0] === 'start' && (args.length !== 2 || !(args[1] === 'owasp-ai-goat-postgres-' + options.workspaceId.slice(0, 12) || args[1] === 'owasp-ai-goat-mailpit-' + options.workspaceId.slice(0, 12) || /^[a-f0-9]{64}$/.test(args[1]))))
          || (args[0] === 'exec' && (args.length !== 7 || args[1] !== 'owasp-ai-goat-postgres-' + options.workspaceId.slice(0, 12) || args.slice(2).join('\0') !== ['pg_isready', '-h', '127.0.0.1', '-U', 'postgres'].join('\0')))
          || args.some((arg, index) => arg === '--secret' && !secrets.has(args[index + 1]))
          || args.some(arg => arg.startsWith('--secret=') && !secrets.has(arg.slice(9)))
          // Fresh AuditSQL uses the same reviewed major as fresh local PG,
          // then retains the inspected immutable image ID before creation.
          || (args[0] === 'pull' && (args.length !== 2 || !(args[1] === 'postgres:18' || /^[A-Za-z0-9._\/-]+(?::[A-Za-z0-9._-]+)?@sha256:[a-f0-9]{64}$/.test(args[1]))))
          || (args[0] === 'rm' && (args.length !== 3 || args[1] !== '--force' || !/^[a-f0-9]{64}$/.test(args[2])))
          || args.some(arg => /^(?:--privileged(?:=|$)|--device(?:=|$)|--pid=host$|--ipc=host$|--network=host$|-v$|--volume(?:=|$))/.test(arg))
          || args.some((arg, index) => ['--pid', '--ipc', '--network'].includes(arg) && args[index + 1] === 'host')) throw denied();
        const current = await assertCurrent();
        if (state.daemonId !== 'unbound') {
          const currentDaemon = JSON.parse((await guest(current.ip, ['sudo', '-n', 'docker', 'info', '--format', '{{json .ID}}'])).trim());
          if (currentDaemon !== state.daemonId) throw denied();
        }
        const command = (bundlePath ? ['sudo', '-n', 'sh', '-c', 'cd "$1" && shift && exec "$@"', 'sh', bundlePath, 'docker', ...args]
          : ['sudo', '-n', 'docker', ...args]).map(quote).join(' ');
        return run(ssh, [...sshArgs(), 'owasp-ai-goat@' + current.ip, command], timeoutMs, true);
      };
      const bindDaemon = async () => {
        const id = JSON.parse((await docker(['info', '--format', '{{json .ID}}'])).trim());
        if (typeof id !== 'string' || !id || id.length > 256 || /[\x00-\x1f\x7f]/.test(id)) throw denied();
        if (state.daemonId !== 'unbound' && state.daemonId !== id) throw denied();
        if (state.daemonId === 'unbound') {
          const next = { ...state, daemonId: id };
          journal.updateJournal({ filePath: statePath, originalBytes: original, resultBytes: encode(next) });
          original = encode(next); state = next;
        }
        daemonId = id;
        return Object.freeze({ kind: 'owned-windows-lab', workspaceId: options.workspaceId, installationId: options.installationId,
          ownedInstanceUUID: state.ownedInstanceUUID, vmId: state.vmId, bindingSha256, daemonId, host: 'owned-hyperv:' + state.vmId });
      };
      const stageFiles = async (files, kind = 'bundle') => {
        const current = await assertCurrent();
        if (!Array.isArray(files) || !files.length || files.length > 128) throw denied();
        let total = 0; const names = new Set();
        for (const file of files) {
          if (!exact(file, ['path', 'bytes', 'sha256']) || !Buffer.isBuffer(file.bytes) || file.bytes.length > 1024 * 1024 || !hash(file.sha256) || digest(file.bytes) !== file.sha256
            || typeof file.path !== 'string' || /[\x00-\x20\x7f]/.test(file.path) || !/^[A-Za-z0-9_.\/-]+$/.test(file.path) || file.path.split('/').some(part => !part || part === '.' || part === '..')
            || !(kind === 'environment' ? /^env-[a-f0-9]{64}$/.test(file.path) : kind === 'secret' ? /^secret-npm_ca-[a-f0-9]{64}$/.test(file.path) : kind === 'profile' ? /^profile-[a-f0-9]{64}$/.test(file.path) : file.path === 'docker-compose.yml' || file.path.startsWith('sidecars/'))
            || names.has(file.path)) throw denied();
          names.add(file.path); total += file.bytes.length;
        }
        if (total > 16 * 1024 * 1024) throw denied();
        const bundleHash = digest(encode(files.map(file => ({ path: file.path, sha256: file.sha256 }))));
        const upload = '/home/ubuntu/owasp-ai-goat-' + state.ownedInstanceUUID + '-' + bundleHash;
        const destination = '/var/lib/owasp-ai-goat/' + state.ownedInstanceUUID + '/' + (['environment', 'secret'].includes(kind) ? 'private' : kind === 'profile' ? 'profiles' : 'bundles/' + bundleHash);
        await mp(['exec', options.instanceName, '--', 'install', '-d', '-m', '0700', upload]);
        await guest(current.ip, ['sudo', '-n', 'install', '-d', '-m', '0700', destination]);
        for (let index = 0; index < files.length; index++) {
          const file = files[index], local = privateDefaults.normalizePrivatePath(path.win32.join(directory, 'lab-upload-' + file.sha256));
          if (absent(local)) privateState.createPrivateFile(local, file.bytes);
          if (!readUpload(local).equals(file.bytes)) throw denied();
          await mp(['transfer', local, options.instanceName + ':' + upload + '/' + index]);
          const remote = upload + '/' + index, target = destination + '/' + file.path;
          if ((await mp(['exec', options.instanceName, '--', 'sha256sum', remote])).split(/\s+/)[0] !== file.sha256) throw denied();
          await guest(current.ip, ['sudo', '-n', 'install', '-d', '-m', '0700', path.posix.dirname(target)]);
          const prior = (await guest(current.ip, ['sudo', '-n', 'sh', '-c', `if [ -L ${quote(target)} ] || { [ -e ${quote(target)} ] && [ ! -f ${quote(target)} ]; }; then exit 1; elif [ -e ${quote(target)} ]; then sha256sum ${quote(target)}; else printf ABSENT; fi`])).trim();
          if (prior !== 'ABSENT' && prior.split(/\s+/)[0] !== file.sha256) throw denied();
          const mode = kind === 'bundle' ? '0644' : '0600';
          if (prior === 'ABSENT') await guest(current.ip, ['sudo', '-n', 'install', '-m', mode, remote, target]);
          if ((await guest(current.ip, ['sudo', '-n', 'stat', '-c', '%u:%g:%a', target])).trim() !== '0:0:' + mode.slice(1)) throw denied();
          if ((await guest(current.ip, ['sudo', '-n', 'sha256sum', target])).split(/\s+/)[0] !== file.sha256) throw denied();
        }
        if (kind === 'bundle') bundles.add(destination);
        return destination;
      };
      const readUpload = filename => { verifyDirectory(); const bytes = privateState.readPrivateFile(filename); if (!Buffer.isBuffer(bytes) || bytes.length > 1024 * 1024) throw denied(); return bytes; };
      const closeForwards = async () => {
        closed = true; let pendingFailure = false;
        const pending = await Promise.allSettled([...forwardGroups].map(group => group.promise));
        pendingFailure = pending.some(result => result.status === 'rejected');
        const owners = [...forwards], results = await Promise.allSettled(owners.map(async owner => { await owner.stopAndJoin(); forwards.delete(owner); }));
        if (pendingFailure || results.some(result => result.status === 'rejected')) throw denied();
      };
      const methods = {
        assertCurrent, executeDocker: docker, bindDaemon,
        stageReviewedBundle: files => stageFiles(files),
        stagePrivateEnvironment: async ({ bytes, sha256 }) => {
          if (!Buffer.isBuffer(bytes) || bytes.length > 32768 || /[\x00\r]/.test(bytes.toString()) || !bytes.toString().split('\n').filter(Boolean).every(line => /^[A-Z][A-Z0-9_]*=/.test(line))) throw denied();
          const name = 'env-' + sha256;
          const destination = (await stageFiles([{ path: name, bytes, sha256 }], 'environment')) + '/' + name;
          environments.add(destination); return destination;
        },
        stagePrivateBuildSecret: async ({ id = 'npm_ca', bytes, sha256 }) => {
          if (id !== 'npm_ca' || !Buffer.isBuffer(bytes) || bytes.length > 65536 || bytes.toString().includes('PRIVATE KEY')
            || !/^(?:\s*-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----\s*)+$/.test(bytes.toString())) throw denied();
          for (const certificate of bytes.toString().match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)) {
            try { new crypto.X509Certificate(certificate); } catch { throw denied(); }
          }
          const name = 'secret-npm_ca-' + sha256;
          const destination = (await stageFiles([{ path: name, bytes, sha256 }], 'secret')) + '/' + name;
          secrets.add('id=npm_ca,src=' + destination); return destination;
        },
        installAndVerifyProfile: async ({ name, bytes, sha256, existingOnly = false }) => {
          if (typeof existingOnly !== 'boolean') throw denied();
          if (!(name === 'owasp-ai-goat-mcp-sandbox' || name === 'owasp-ai-goat-owned-http-' + options.workspaceId.slice(0, 12) || name === 'owasp-ai-goat-owned-shadow-' + options.workspaceId.slice(0, 12))) throw denied();
          const staged = (await stageFiles([{ path: 'profile-' + sha256, bytes, sha256 }], 'profile')) + '/profile-' + sha256;
          const current = await assertCurrent(), destination = '/etc/apparmor.d/' + name;
          await guest(current.ip, ['sudo', '-n', 'apparmor_parser', '--skip-kernel-load', staged]);
          const prior = (await guest(current.ip, ['sudo', '-n', 'sh', '-c', `if [ -L ${quote(destination)} ] || { [ -e ${quote(destination)} ] && [ ! -f ${quote(destination)} ]; }; then exit 1; elif [ -e ${quote(destination)} ]; then sha256sum ${quote(destination)}; else printf ABSENT; fi`])).trim();
          if (existingOnly && prior === 'ABSENT') throw denied();
          if (prior !== 'ABSENT' && prior.split(/\s+/)[0] !== sha256) throw denied();
          if (prior === 'ABSENT') await guest(current.ip, ['sudo', '-n', 'install', '-o', 'root', '-g', 'root', '-m', '0600', staged, destination]);
          if ((await guest(current.ip, ['sudo', '-n', 'stat', '-c', '%u:%g:%a', destination])).trim() !== '0:0:600'
            || (await guest(current.ip, ['sudo', '-n', 'sha256sum', destination])).split(/\s+/)[0] !== sha256) throw denied();
          await guest(current.ip, ['sudo', '-n', 'apparmor_parser', '-r', destination]);
          const profiles = await guest(current.ip, ['sudo', '-n', 'cat', '/sys/kernel/security/apparmor/profiles']);
          if (!profiles.split('\n').includes(name + ' (enforce)')) throw denied();
          return Object.freeze({ name, sha256, destination, bindingSha256 });
        },
        openLoopbackForwards: async (portMap, { ownChild } = {}) => {
          const current = await assertCurrent();
          if (typeof ownChild !== 'function' || !Array.isArray(portMap) || !portMap.length || portMap.length > 32 || new Set(portMap.map(item => item.local)).size !== portMap.length
            || !portMap.every(item => exact(item, ['local', 'guest']) && [item.local, item.guest].every(port => Number.isInteger(port) && port >= 1024 && port <= 65535))) throw denied();
          const ports = portMap.map(item => Object.freeze({ ...item })).sort((a, b) => a.local - b.local), signature = JSON.stringify(ports);
          if (forwardOwner && forwardOwner !== ownChild) throw denied();
          if (forwardReceipts.has(signature)) return forwardReceipts.get(signature);
          const newPorts = ports.filter(port => !portBindings.has(port.local));
          if (portBindings.size + newPorts.length > 32 || ports.some(port => portBindings.has(port.local) && portBindings.get(port.local).guest !== port.guest)) throw denied();
          forwardOwner = ownChild;
          // Caller supplies the existing native owned-child activation/barrier.
          // It must resolve only after SSH forwarding readiness, and expose a
          // stopAndJoin that waits for job drain. No raw PID is adopted here.
          if (newPorts.length) {
            const args = [...sshArgs(), '-o', 'ExitOnForwardFailure=yes', '-N', ...newPorts.flatMap(item => ['-L', `127.0.0.1:${item.local}:127.0.0.1:${item.guest}`]), 'owasp-ai-goat@' + current.ip];
            const group = {};
            forwardGroups.add(group);
            for (const port of newPorts) portBindings.set(port.local, { guest: port.guest, group });
            group.promise = Promise.resolve().then(async () => {
              const owner = await ownChild({ executable: ssh, args });
              if (!owner || typeof owner.stopAndJoin !== 'function') throw denied();
              if (closed) { await owner.stopAndJoin(); throw denied(); }
              forwards.add(owner); return owner;
            });
          }
          const groups = [...new Set(ports.map(port => portBindings.get(port.local).group))];
          const receipt = Promise.all(groups.map(group => group.promise)).then(owners => {
            const failures = owners.map(owner => owner.failurePromise).filter(Boolean);
            return Object.freeze({ bindingSha256, ports: Object.freeze(ports), ...(failures.length ? { failurePromise: Promise.race(failures) } : {}) });
          });
          forwardReceipts.set(signature, receipt);
          return receipt;
        }, closeForwards,
      };
      const guarded = Object.fromEntries(Object.entries(methods).map(([name, method]) => [name, async (...args) => {
        try { return await method(...args); }
        catch (error) {
          if (name === 'executeDocker' && error.diagnosticCode === 'WINDOWS_OWNED_LAB_DOCKER_FAILED' && Number.isInteger(error.exitCode) && error.exitCode > 0 && error.exitCode < 255) {
            throw Object.assign(Error('Owned guest Docker command failed'), { code: error.exitCode, exitCode: error.exitCode, diagnosticCode: 'WINDOWS_OWNED_LAB_DOCKER_FAILED' });
          }
          throw denied();
        }
      }]));
      const session = Object.freeze({ ...guarded, get binding() { return describeOwnedLab(session); } });
      sessions.set(session, () => {
        if (closed) throw denied();
        return Object.freeze({ kind: 'owned-windows-lab', workspaceId: options.workspaceId, installationId: options.installationId,
          ownedInstanceUUID: state.ownedInstanceUUID, vmId: state.vmId, bindingSha256, daemonId, host: 'owned-hyperv:' + state.vmId });
      });
      return session;
    } catch (error) {
      if (['WINDOWS_OWNED_LAB_BACKEND_UNSUPPORTED', 'WINDOWS_OWNED_LAB_STATE_UNCERTAIN'].includes(error.code)) throw denied(error.code);
      throw denied();
    }
  }
  return Object.freeze({ prepareOwnedLab });
}
function describeOwnedLab(session) { const describe = sessions.get(session); if (!describe) throw denied(); return describe(); }
module.exports = { createWindowsOwnedLab, describeOwnedLab, ...createWindowsOwnedLab() };
