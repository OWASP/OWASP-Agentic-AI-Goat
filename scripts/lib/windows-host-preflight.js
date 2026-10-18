'use strict';
// Read-only host admission. This does not admit a Docker daemon, VM, protected
// lab backend, or full Windows installer integration.
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const HELPER = path.resolve(__dirname, '../install/Windows/host-preflight.ps1');
const MAX_BYTES = 8192;
const SKUS = Object.freeze([4,27,48,49,70,72,84,121,122,125,126,129,130,161,162,164,165]);
const REMEDIES = Object.freeze({
  WINDOWS_HOST_CLIENT_REQUIRED: 'Use an approved Windows Pro, Education or Enterprise client; Windows Server is unsupported.',
  WINDOWS_HOST_EDITION_UNSUPPORTED: 'Use Windows Pro, Education or Enterprise with Hyper-V; Home and unknown editions are unsupported.',
  WINDOWS_HOST_BUILD_UNSUPPORTED: 'Use Windows 10 build19045 or newer, or Windows 11, with current security updates.',
  WINDOWS_HOST_X64_REQUIRED: 'Use an x64 Windows host; ARM64 and 32-bit hosts are unsupported.',
  WINDOWS_HOST_HYPERV_PERMISSION_REQUIRED: 'Ask a host administrator to grant this user Hyper-V Administrators membership, then sign out and sign in before rerunning setup from a normal terminal. Setup does not change groups or elevate the application.',
  WINDOWS_HOST_HYPERV_POWERSHELL_REQUIRED: 'Ask a host administrator to enable Hyper-V Module for Windows PowerShell through Windows Features, complete any required restart, then rerun setup. Setup does not enable Windows features.',
  WINDOWS_HOST_HYPERV_DISABLED: 'Enable the Hyper-V platform through Windows Features, then restart explicitly before setup.',
  WINDOWS_HOST_RESTART_PENDING: 'Finish pending Windows servicing and restart explicitly, then rerun the preflight.',
  WINDOWS_HOST_VIRTUALIZATION_UNAVAILABLE: 'Use hardware with SLAT and VM monitor extensions and enable virtualization in firmware.',
  WINDOWS_HOST_HYPERV_NOT_RUNNING: 'Start the Windows Hyper-V hypervisor by completing feature and firmware configuration, then restart explicitly.',
  WINDOWS_HOST_OBSERVATION_UNKNOWN: 'Obtain readable Windows CIM/servicing observations and rerun the preflight; unknown host state is unsupported.',
});
const unavailable = () => Object.assign(Error('Windows host preflight unavailable; run setup --plan to inspect supported host requirements.'), { code: 'WINDOWS_HOST_PREFLIGHT_UNAVAILABLE' });
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
function validateWindowsHostPreflight(value) {
  if (!exact(value, ['schemaVersion','component','nonMutating','hostSupported','minimumBuild','allowedSkus','capabilityEvidence','blockers'])
    || value.schemaVersion !== 1 || value.component !== 'windows-hyperv-host-preflight' || value.nonMutating !== true
    || typeof value.hostSupported !== 'boolean' || value.minimumBuild !== 19045
    || !Array.isArray(value.allowedSkus) || JSON.stringify(value.allowedSkus) !== JSON.stringify(SKUS)
    || !['unknown','running-hypervisor','processor-flags'].includes(value.capabilityEvidence)
    || !Array.isArray(value.blockers) || value.blockers.length > Object.keys(REMEDIES).length) throw unavailable();
  const codes = value.blockers.map(item => {
    if (!exact(item, ['code','remedy']) || !Object.hasOwn(REMEDIES, item.code) || item.remedy !== REMEDIES[item.code]) throw unavailable();
    return item.code;
  });
  if (JSON.stringify(codes) !== JSON.stringify([...new Set(codes)].sort())
    || value.hostSupported !== (codes.length === 0)
    || value.hostSupported && value.capabilityEvidence !== 'running-hypervisor') throw unavailable();
  return Object.freeze({ schemaVersion: 1, component: value.component, nonMutating: true,
    hostSupported: value.hostSupported, minimumBuild: 19045, allowedSkus: SKUS,
    capabilityEvidence: value.capabilityEvidence,
    blockers: Object.freeze(codes.map(code => Object.freeze({ code, remedy: REMEDIES[code] }))) });
}
function createWindowsHostPreflight({ execute = execFileSync, platform = process.platform,
  systemRoot = process.env.SystemRoot } = {}) {
  function observe() {
    try {
      if (platform !== 'win32' || typeof execute !== 'function' || typeof systemRoot !== 'string'
        || !/^[A-Za-z]:\\[^\x00-\x1f\x7f<>:"|?*/]+$/.test(systemRoot)
        || systemRoot.slice(3).split('\\').some(part => !part || part === '.' || part === '..' || /[. ]$/.test(part))) throw unavailable();
      const executable = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
      let output, status = 0;
      try {
        output = execute(executable, ['-NoLogo','-NoProfile','-NonInteractive','-File',HELPER], {
          encoding: 'utf8', timeout: 60000, maxBuffer: MAX_BYTES, windowsHide: true,
          stdio: ['ignore','pipe','pipe'],
        });
      } catch (error) {
        if (error.status !== 1 || error.signal || error.code) throw unavailable();
        status = 1; output = error.stdout;
      }
      if (typeof output !== 'string' || Buffer.byteLength(output, 'utf8') > MAX_BYTES) throw unavailable();
      const result = validateWindowsHostPreflight(JSON.parse(output));
      if (status !== (result.hostSupported ? 0 : 1)) throw unavailable();
      return result;
    } catch { throw unavailable(); }
  }
  return Object.freeze({ observe });
}
function observeWindowsHostPreflight() { return createWindowsHostPreflight().observe(); }
function assertWindowsHostSupported(observation) {
  const value = validateWindowsHostPreflight(observation);
  if (!value.hostSupported) throw Object.assign(Error('Windows Hyper-V host requirements are not met; inspect setup --plan. No features were enabled or restart requested.'), { code: 'WINDOWS_HOST_UNSUPPORTED' });
  return value;
}
module.exports = { createWindowsHostPreflight, observeWindowsHostPreflight, validateWindowsHostPreflight, assertWindowsHostSupported };
