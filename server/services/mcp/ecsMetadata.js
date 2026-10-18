'use strict';

/**
 * Runtime environment detector for the MCP lab's Lab-Infrastructure panel.
 *
 * The sidecars run beside the app and are reached over 127.0.0.1:PORT in BOTH
 * local docker-compose AND AWS Fargate (on Fargate all containers share one task
 * ENI, so loopback is genuinely the real path). Showing "127.0.0.1" on AWS looks
 * identical to local and confuses students. This helper surfaces the actual
 * ENVIRONMENT — "AWS Fargate task · <region> · team <N> · task <ip> (<az>)" vs
 * "Local docker-compose" — so the panel can label where the lab is running
 * without faking a per-sidecar IP that doesn't exist.
 *
 * Detection precedence mirrors mcpSidecarSupervisor._isManagedExternally() so the
 * two never disagree. On AWS the task IP/AZ come from the ECS Task Metadata
 * Endpoint v4 (ECS_CONTAINER_METADATA_URI_V4), auto-injected on Fargate.
 */
const cfg = require('./config');

let _cached = null;

function isLocalhostUrl(url) {
  return /(^https?:\/\/)?(127\.0\.0\.1|localhost)(:|\/|$)/i.test(url || '');
}

async function fetchTaskMetadata() {
  const base = process.env.ECS_CONTAINER_METADATA_URI_V4;
  if (!base) return null;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 1500);
  try {
    const r = await fetch(`${base}/task`, { signal: ctrl.signal });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function extractTaskIp(meta) {
  // Task metadata v4: Containers[].Networks[].IPv4Addresses[] — all share the
  // task ENI, so the first IPv4 we find is the task's private IP.
  const containers = (meta && meta.Containers) || [];
  for (const c of containers) {
    for (const n of (c.Networks || [])) {
      const ips = n.IPv4Addresses || [];
      if (ips.length) return ips[0];
    }
  }
  return null;
}

/**
 * @returns {Promise<{platform, label, region?, teamId?, taskPrivateIp?, availabilityZone?, cluster?}>}
 * Memoized: task IP/AZ/region don't change over the process lifetime.
 */
async function getEnvironment() {
  if (_cached) return _cached;

  const onAws = !!process.env.TEAM_ID || !!process.env.ECS_CONTAINER_METADATA_URI_V4;
  if (onAws) {
    const meta = await fetchTaskMetadata();
    _cached = {
      platform: 'aws-fargate',
      label: 'AWS Fargate task',
      region: process.env.AWS_REGION || (meta && meta.AvailabilityZone ? meta.AvailabilityZone.replace(/[a-z]$/, '') : undefined),
      teamId: process.env.TEAM_ID || undefined,
      taskPrivateIp: meta ? extractTaskIp(meta) : undefined,
      availabilityZone: meta ? meta.AvailabilityZone : undefined,
      cluster: meta ? meta.Cluster : undefined,
    };
    return _cached;
  }

  if (!isLocalhostUrl(cfg.SANDBOX_RUNNER_URL)) {
    _cached = { platform: 'compose', label: 'Docker Compose (service DNS)' };
    return _cached;
  }

  _cached = { platform: 'local', label: 'Local docker-compose (published ports)' };
  return _cached;
}

// Test/reset hook.
function _reset() { _cached = null; }

module.exports = { getEnvironment, _reset };
