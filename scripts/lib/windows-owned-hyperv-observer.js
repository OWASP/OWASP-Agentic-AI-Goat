'use strict';
// Read-only Hyper-V VMId/state snapshot. This neither grants restart authority
// nor establishes an immutable guest, VM configuration or disk identity.
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const HELPER = path.resolve(__dirname, '../install/Windows/owned-hyperv-observer.ps1');
const NAME = /^owasp-ai-goat-lab-[a-z0-9](?:[a-z0-9-]{0,45}[a-z0-9])?$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const ZERO = '00000000-0000-0000-0000-000000000000';
const denied = () => Object.assign(Error('Owned Hyper-V VM observation unavailable.'), { code: 'WINDOWS_OWNED_HYPERV_OBSERVATION_DENIED' });
function validName(name) { return typeof name === 'string' && name.length <= 57 && !/[\r\n]/.test(name) && NAME.test(name); }
function createWindowsOwnedHyperVObserver({ execute = execFileSync, platform = process.platform,
  systemRoot = process.env.SystemRoot } = {}) {
  function observeOwnedHyperVVm(name) {
    try {
      if (!validName(name) || platform !== 'win32' || typeof execute !== 'function' || typeof systemRoot !== 'string'
        || !/^[A-Za-z]:\\[^\x00-\x1f\x7f<>:"|?*/]+$/.test(systemRoot)
        || systemRoot.slice(3).split('\\').some(part => !part || part === '.' || part === '..' || /[. ]$/.test(part))) throw denied();
      const executable = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
      const output = execute(executable, ['-NoLogo','-NoProfile','-NonInteractive','-File',HELPER], {
        input: JSON.stringify({ version: 1, operation: 'observeOwnedHyperVVm', name }),
        encoding: 'utf8', timeout: 30000, maxBuffer: 4096, windowsHide: true,
        stdio: ['pipe','pipe','pipe'],
      });
      if (typeof output !== 'string' || Buffer.byteLength(output, 'utf8') > 4096) throw denied();
      const value = JSON.parse(output);
      if (!value || typeof value !== 'object' || Array.isArray(value)
        || Object.keys(value).sort().join(',') !== 'name,operation,state,version,vmId'
        || value.version !== 1 || value.operation !== 'observeOwnedHyperVVm' || value.name !== name
        || typeof value.vmId !== 'string' || value.vmId.length !== 36 || !UUID.test(value.vmId) || value.vmId === ZERO
        || !['Running','Off','Saved'].includes(value.state)) throw denied();
      return Object.freeze({ version: 1, operation: value.operation, name, vmId: value.vmId, state: value.state });
    } catch { throw denied(); }
  }
  return Object.freeze({ observeOwnedHyperVVm });
}
function observeOwnedHyperVVm(name) { return createWindowsOwnedHyperVObserver().observeOwnedHyperVVm(name); }
module.exports = { createWindowsOwnedHyperVObserver, observeOwnedHyperVVm };
