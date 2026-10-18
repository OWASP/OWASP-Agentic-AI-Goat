'use strict';

const fs = require('node:fs');
const os = require('node:os');
const MEMORY_ROOT = '/sys/fs/cgroup/';
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

// Called in the owned listener process, never in the application/agent host.
// Host-wide os.freemem(), os.totalmem() and os.loadavg() do not describe a
// constrained container, so unavailable measurements remain explicitly null.
function createOwnedSystemMetrics({ readFile = file => fs.readFileSync(file, 'utf8'),
  hostname = () => os.hostname(), uptime = () => process.uptime(),
  platform = process.platform, node = process.version, now = () => new Date() } = {}) {
  if (![readFile, hostname, uptime, now].every(value => typeof value === 'function')
      || typeof platform !== 'string' || typeof node !== 'string') throw new TypeError('System metric dependencies required');
  function memory() {
    try {
      const parse = file => {
        const raw = readFile(MEMORY_ROOT + file);
        if (typeof raw !== 'string' || raw.length > 32 || !/^\d+\n?$/.test(raw)) throw new Error('Unavailable');
        const value = BigInt(raw.trim());
        if (value > MAX_SAFE) throw new Error('Unavailable');
        return Number(value);
      };
      const limit = parse('memory.max'), used = parse('memory.current');
      if (limit <= 0) return null;
      return { limit, used, available: Math.max(0, limit - used) };
    } catch { return null; }
  }
  return Object.freeze({ snapshot() {
    const name = hostname(), seconds = uptime(), stamp = now();
    if (typeof name !== 'string' || !name || name.length > 255
        || !Number.isFinite(seconds) || seconds < 0 || !(stamp instanceof Date)
        || !Number.isFinite(stamp.getTime())) throw new Error('Owned System metrics unavailable');
    const measured = memory();
    const mb = bytes => Math.floor(bytes / (1024 * 1024));
    return Object.freeze({ version: 'secureshop-owned-system-metrics.v1', ok: true, hostname: name, platform, node,
      uptime_s: Math.floor(seconds), loadavg: null,
      freemem_mb: measured ? mb(measured.available) : null,
      totalmem_mb: measured ? mb(measured.limit) : null,
      ts: stamp.toISOString(), metricsSource: 'owned-system-listener',
      memorySource: measured ? 'cgroup-v2' : 'unavailable',
      uptimeSource: 'listener-process', loadSource: 'unavailable' });
  } });
}

module.exports = { createOwnedSystemMetrics };
