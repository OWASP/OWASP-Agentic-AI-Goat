'use strict';

const { isIP } = require('node:net');

// Forwarded identity is authoritative only when the socket peer and subsequent
// proxy hops are explicitly trusted. Direct laptop startup trusts no proxies.
function applicationProxyTrust(environment = process.env) {
  const value = environment.TRUSTED_PROXY_CIDRS;
  if (value === undefined || value === '') return false;
  const invalid = () => Object.assign(new Error(
    'TRUSTED_PROXY_CIDRS must contain comma-separated proxy IP addresses or CIDRs; unrestricted trust is unsupported.'
  ), { code: 'INVALID_PROXY_TRUST_CONFIGURATION' });
  if (typeof value !== 'string' || value.length > 2048) throw invalid();
  const entries = value.split(',').map(entry => entry.trim());
  if (entries.length > 32 || entries.some(entry => {
    const parts = entry.split('/');
    const version = isIP(parts[0]);
    if (!version || parts.length > 2 || parts[0].includes('%')) return true;
    if (parts.length === 1) return false;
    return !/^[1-9]\d*$/.test(parts[1]) || Number(parts[1]) > (version === 4 ? 32 : 128);
  })) throw invalid();
  return [...new Set(entries)];
}

module.exports = { applicationProxyTrust };
