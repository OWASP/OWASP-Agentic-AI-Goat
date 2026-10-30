'use strict';
// Ordinary teaching services only. Their deliberate sinks/unconfined sandbox
// are retained inside the owned guest; this is not protected-runner readiness.
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { describeOwnedLab } = require('../lib/windows-owned-lab');
const { workspaceId } = require('../../server/services/mcp/ownedManagedConfiguration');
const { MAILPIT_IMAGE } = require('../local-mailpit');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const IMAGE_LABEL = 'org.owasp-ai-goat.reviewed-source';
const SERVICES = Object.freeze([
  Object.freeze({ name: 'mcp-sandbox', image: 'mcp-sandbox-runner:dev', context: 'sandbox-runner', ports: [8090] }),
  Object.freeze({ name: 'mailpit', image: MAILPIT_IMAGE, ports: [1025, 8025] }),
  Object.freeze({ name: 'ssrf-target', image: 'mcp-ssrf-target:dev', context: 'ssrf-target', ports: [9099] }),
  Object.freeze({ name: 'rogue-mcp', image: 'mcp-rogue:dev', context: 'rogue-mcp', ports: [8091] }),
]);
const denied = () => Object.assign(Error('Owned Windows base lab services unavailable'), { code: 'WINDOWS_BASE_LAB_SERVICES_DENIED' });
const ids = value => typeof value === 'string' && value.length === 71 && /^sha256:[a-f0-9]{64}$/.test(value);
function createWindowsBaseLabServices({ describeSession = describeOwnedLab, fileSystem = fs,
  collectRunnerBundle = root => require('./mcp-owned-provision')._internals.reviewedRunnerBundle(root),
  fetch = global.fetch, now = Date.now, delay = ms => new Promise(resolve => setTimeout(resolve, ms)) } = {}) {
  async function reviewedBaseBundle(root) {
    const received = await collectRunnerBundle(root);
    if (!Array.isArray(received)) throw denied();
    const files = received.map(file => ({ ...file, bytes: Buffer.isBuffer(file.bytes) ? Buffer.from(file.bytes) : file.bytes }));
    if (!Array.isArray(files) || files.some(file => !Buffer.isBuffer(file.bytes) || hash(file.bytes) !== file.sha256)) throw denied();
    for (const context of ['ssrf-target', 'rogue-mcp']) {
      for (const name of ['Dockerfile', 'index.js']) {
        const relative = 'sidecars/' + context + '/' + name, filename = path.join(root, ...relative.split('/'));
        const stat = await fileSystem.lstat(filename);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024) throw denied();
        const bytes = await fileSystem.readFile(filename);
        if (!Buffer.isBuffer(bytes) || bytes.length !== stat.size) throw denied();
        if (name === 'Dockerfile') {
          const copies = bytes.toString().split('\n').filter(line => /^(?:COPY|ADD)\b/.test(line));
          if (copies.length !== 1 || copies[0] !== 'COPY index.js ./') throw denied();
        }
        files.push({ path: relative, bytes, sha256: hash(bytes) });
      }
    }
    if (files.length > 128 || new Set(files.map(file => file.path)).size !== files.length || files.reduce((sum, file) => sum + file.bytes.length, 0) > 16 * 1024 * 1024) throw denied();
    const compose = files.find(file => file.path === 'docker-compose.yml');
    if (!compose) throw denied();
    let text = compose.bytes.toString();
    const sourceHashes = {};
    for (const service of SERVICES) {
      const marker = '  ' + service.name + ':\n', start = text.indexOf(marker);
      if (start < 0 || text.indexOf(marker, start + marker.length) !== -1) throw denied();
      const following = text.slice(start + marker.length).search(/^  [a-z][a-z0-9-]*:\n/m);
      const end = following < 0 ? text.indexOf('\nnetworks:', start) : start + marker.length + following;
      if (end < start) throw denied();
      let block = text.slice(start, end);
      if (!block.includes('    image: ' + service.image + '\n') || /^    (?:volumes|privileged|network_mode|pid|ipc|devices|cap_add):/m.test(block)) throw denied();
      if (service.context) {
        const inputs = files.filter(file => file.path.startsWith('sidecars/' + service.context + '/')).sort((a,b) => a.path.localeCompare(b.path));
        sourceHashes[service.name] = hash(Buffer.from(JSON.stringify(inputs.map(file => ({ path: file.path, sha256: file.sha256 })))));
        const build = '    build: ./sidecars/' + service.context + '\n';
        if (!block.includes(build) || block.indexOf(build) !== block.lastIndexOf(build)) throw denied();
        block = block.replace(build, '    build:\n      context: ./sidecars/' + service.context + '\n      labels:\n        ' + IMAGE_LABEL + ': "' + sourceHashes[service.name] + '"\n');
        const publication = '      - "' + service.ports[0] + ':' + service.ports[0] + '"';
        if (!block.includes(publication) || block.indexOf(publication) !== block.lastIndexOf(publication)) throw denied();
        block = block.replace(publication, '      - "127.0.0.1:' + service.ports[0] + ':' + service.ports[0] + '"');
      }
      text = text.slice(0, start) + block + text.slice(end);
    }
    compose.bytes = Buffer.from(text); compose.sha256 = hash(compose.bytes);
    return { files, sourceHashes };
  }
  async function provisionWindowsBaseLabServices({ session, root = path.resolve(__dirname, '../..'), mode = 'fresh', ownLabChild, healthTimeoutMs = 30000 } = {}) {
    try {
      const binding = describeSession(session);
      if (!binding || binding.workspaceId !== workspaceId(root) || !binding.daemonId || binding.daemonId === 'unbound'
        || !/^[a-f0-9]{64}$/.test(binding.bindingSha256) || !['fresh', 'start'].includes(mode) || typeof ownLabChild !== 'function'
        || !Number.isInteger(healthTimeoutMs) || healthTimeoutMs < 1 || healthTimeoutMs > 60000) throw denied();
      await session.assertCurrent();
      const { files, sourceHashes } = await reviewedBaseBundle(root), bundlePath = await session.stageReviewedBundle(files);
      const project = 'owasp-ai-goat-' + binding.workspaceId;
      const docker = (args, timeoutMs) => session.executeDocker(args, { scope: 'provision', bundlePath, ...(timeoutMs === undefined ? {} : { timeoutMs }) });
      const compose = (args, timeoutMs) => docker(['compose', '--project-name', project, ...args], timeoutMs);
      const parse = text => { if (typeof text !== 'string' || Buffer.byteLength(text) > 1024 * 1024) throw denied(); const value = JSON.parse(text); return Array.isArray(value) && value.length === 1 ? value[0] : value; };
      async function imageRecord(service, required) {
        let image;
        try { image = parse(await docker(['image', 'inspect', '--format', '{{json .}}', service.image])); }
        catch (error) { if (!required && error.code === 1) return null; throw denied(); }
        if (!image || !ids(image.Id) || (service.context ? image.Config?.Labels?.[IMAGE_LABEL] !== sourceHashes[service.name] : !image.RepoDigests?.includes(MAILPIT_IMAGE))) throw denied();
        return image;
      }
      async function containerRecord(service, image, required) {
        const value = (await compose(['ps', '--all', '--quiet', service.name])).trim();
        if (!value) { if (required) throw denied(); return null; }
        if (!/^[a-f0-9]{64}$/.test(value)) throw denied();
        const container = parse(await docker(['inspect', '--format', '{{json .}}', value]));
        const labels = container?.Config?.Labels, ports = container?.HostConfig?.PortBindings;
        if (!image || container.Id !== value || container.Image !== image.Id || labels?.['com.docker.compose.project'] !== project || labels?.['com.docker.compose.service'] !== service.name
          || container.Config.Image !== service.image || container.HostConfig.Privileged !== false || [container.HostConfig.NetworkMode, container.HostConfig.PidMode, container.HostConfig.IpcMode].includes('host')
          || !Array.isArray(container.Mounts) || container.Mounts.some(mount => mount.Type !== 'volume' || typeof mount.Name !== 'string' || !mount.Name.startsWith(project + '_'))
          || !ports || Object.keys(ports).sort().join(',') !== service.ports.map(port => port + '/tcp').sort().join(',')
          || service.ports.some(port => !Array.isArray(ports[port + '/tcp']) || ports[port + '/tcp'].length !== 1 || ports[port + '/tcp'][0].HostIp !== '127.0.0.1' || ports[port + '/tcp'][0].HostPort !== String(port))) throw denied();
        return container;
      }
      for (const service of SERVICES) { const image = await imageRecord(service, mode === 'start'); await containerRecord(service, image, mode === 'start'); }
      const names = SERVICES.map(service => service.name);
      if (mode === 'start') await compose(['up', '--detach', '--no-recreate', '--no-build', '--pull', 'never', '--wait', ...names]);
      else await compose(['up', '--detach', '--build', '--wait', ...names], 600000);
      const containers = {};
      for (const service of SERVICES) {
        const image = await imageRecord(service, true), container = await containerRecord(service, image, true);
        if (container.State?.Running !== true) throw denied(); containers[service.name] = container.Id;
      }
      const portMap = SERVICES.flatMap(service => service.ports.map(port => ({ local: port, guest: port })));
      const forwards = await session.openLoopbackForwards(portMap, { ownChild: ownLabChild });
      if (forwards.bindingSha256 !== binding.bindingSha256) throw denied();
      const endpoints = ['http://127.0.0.1:8090/health', 'http://127.0.0.1:8091/health', 'http://127.0.0.1:9099/health', 'http://127.0.0.1:8025/api/v1/info'];
      const deadline = now() + healthTimeoutMs;
      async function responseText(response) {
        if (!response.body?.getReader) { const text = await response.text(); if (Buffer.byteLength(text) > 65536) throw denied(); return text; }
        const reader = response.body.getReader(), chunks = []; let size = 0;
        try {
          for (;;) { const { value, done } = await reader.read(); if (done) break; size += value.byteLength; if (size > 65536) throw denied(); chunks.push(Buffer.from(value)); }
          return Buffer.concat(chunks).toString('utf8');
        } catch { try { await reader.cancel(); } catch {} throw denied(); }
        finally { reader.releaseLock(); }
      }
      for (const url of endpoints) {
        let healthy = false;
        do {
          try {
            const response = await fetch(url, { signal: AbortSignal.timeout(Math.min(2000, Math.max(1, deadline - now()))), redirect: 'error' });
            if (response.ok) { const body = JSON.parse(await responseText(response)); healthy = Boolean(body && typeof body === 'object' && !Array.isArray(body) && (url.includes('/api/v1/info') || ['ok', 'healthy'].includes(body.status))); }
          } catch { /* Only bounded loopback readiness is retried. */ }
          if (!healthy && now() < deadline) await delay(100);
        } while (!healthy && now() < deadline);
        if (!healthy) throw denied();
      }
      await session.assertCurrent();
      return Object.freeze({ project, bindingSha256: binding.bindingSha256, containers: Object.freeze(containers), ports: Object.freeze(portMap.map(port => Object.freeze(port))), ...(forwards.failurePromise ? { failurePromise: forwards.failurePromise } : {}) });
    } catch { throw denied(); }
  }
  return Object.freeze({ reviewedBaseBundle, provisionWindowsBaseLabServices });
}
module.exports = { createWindowsBaseLabServices, ...createWindowsBaseLabServices() };
