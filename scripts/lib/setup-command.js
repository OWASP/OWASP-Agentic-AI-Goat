'use strict';
const { spawn } = require('node:child_process');
const path = require('node:path');
const { isSupportedApplicationNodeVersion } = require('../application-node-runtime');

function hasCaOverride(env) {
  return Object.prototype.hasOwnProperty.call(env, 'NODE_USE_SYSTEM_CA')
    || Object.prototype.hasOwnProperty.call(env, 'NODE_EXTRA_CA_CERTS')
    || Object.prototype.hasOwnProperty.call(env, 'SSL_CERT_FILE')
    || Object.prototype.hasOwnProperty.call(env, 'SSL_CERT_DIR')
    || /(?:^|[\s'"])--(?:use-system-ca|use-openssl-ca|use-bundled-ca|no-use-system-ca)(?:=[^\s'"]+)?(?=$|[\s'"])/.test(String(env.NODE_OPTIONS || ''))
    || ['npm_config_cafile', 'NPM_CONFIG_CAFILE', 'npm_config_ca', 'NPM_CONFIG_CA']
      .some(key => Object.prototype.hasOwnProperty.call(env, key));
}

function isNpmInstallCommand(command, args = []) {
  const name = path.basename(String(command)).toLowerCase();
  return (name === 'npm' || name === 'npm.cmd') && ['ci', 'install', 'i'].includes(String(args[0]));
}

function prepareSetupCommandEnv(command, args, env = process.env, {
  platform = process.platform,
  nodeVersion = process.versions.node,
} = {}) {
  const childEnv = { ...env };
  if (isNpmInstallCommand(command, args) && (platform === 'darwin' || platform === 'linux')
    && isSupportedApplicationNodeVersion(nodeVersion) && !hasCaOverride(env)) {
    childEnv.NODE_USE_SYSTEM_CA = '1';
  }
  return childEnv;
}

function runSetupCommand(command, args, cwd, env, { timeoutMs, killGraceMs = 5000 } = {}, ErrorType = Error) {
  return new Promise((resolve, reject) => {
    const grouped = process.platform !== 'win32';
    const child = spawn(command, args, { cwd, env: prepareSetupCommandEnv(command, args, env), stdio: 'inherit', detached: grouped,
      shell: !grouped && command.endsWith('.cmd') });
    let timer, escalation, timedOut = false, closed = false, stopFinished = false;
    const timeoutError = new ErrorType(`${path.basename(command)} timed out`);
    const signal = name => {
      try {
        if (grouped && child.pid) process.kill(-child.pid, name);
        else child.kill(name);
      } catch (error) {
        if (error.code !== 'ESRCH') throw error;
      }
    };
    const finishTimeout = () => { if (closed && stopFinished) reject(timeoutError); };
    child.once('error', error => { clearTimeout(timer); clearTimeout(escalation); reject(error); });
    child.once('close', code => {
      closed = true;
      clearTimeout(timer);
      if (timedOut) finishTimeout();
      else code === 0 ? resolve() : reject(new ErrorType(`${path.basename(command)} failed (${code})`));
    });
    if (timeoutMs) timer = setTimeout(() => {
      timedOut = true;
      try { signal('SIGTERM'); } catch (error) { timeoutError.cause = error; }
      // A child can exit while descendants retain its process group. Always
      // finish stopping that owned group before reporting a timed-out setup.
      escalation = setTimeout(() => {
        try { signal('SIGKILL'); } catch (error) { timeoutError.cause = error; }
        stopFinished = true;
        finishTimeout();
      }, killGraceMs);
    }, timeoutMs);
  });
}

module.exports = { hasCaOverride, isNpmInstallCommand, prepareSetupCommandEnv, runSetupCommand };
