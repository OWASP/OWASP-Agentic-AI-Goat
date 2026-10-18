'use strict';
// Bounded native publication foundation only; no application caller is enabled.
// prepare retains a private immutable intent and original/result byte backups. publish
// also resolves an interrupted promotion using that exact intent. Same-user
// arbitrary mutation and privileged administrators/SYSTEM are outside the
// boundary; native invocations serialize cooperating writers with a mutex.
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { normalizePrivatePath, MAX_FILE_BYTES } = require('./windows-private-state');
const HELPER = path.resolve(__dirname, '../windows/windows-private-publication.ps1');
const MAX_REQUEST_BYTES = 3000000;
const MAX_RESPONSE_BYTES = 4096;
const denied = () => Object.assign(new Error('Windows private publication denied.'), { code: 'WINDOWS_PRIVATE_PUBLICATION_DENIED' });
const operationPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const exactKeys = (object, keys) => object && typeof object === 'object' && !Array.isArray(object) && Object.keys(object).sort().join(',') === keys.slice().sort().join(',');

function createWindowsPrivatePublication({ execute = execFileSync, platform = process.platform, systemRoot = process.env.SystemRoot } = {}) {
  function invoke(operation, options) {
    try {
      const prepare = operation === 'preparePrivatePublication';
      if (!exactKeys(options, prepare ? ['targetPath', 'intentPath', 'operationId', 'originalBytes', 'resultBytes'] : ['targetPath', 'intentPath', 'operationId'])) throw denied();
      const targetPath = normalizePrivatePath(options.targetPath);
      const intentPath = normalizePrivatePath(options.intentPath);
      const operationId = options.operationId;
      if (typeof operationId !== 'string' || !operationPattern.test(operationId)) throw denied();
      const stagePath = normalizePrivatePath(`${targetPath}.dvaia-${operationId}.stage`);
      const originalPath = normalizePrivatePath(`${intentPath}.original`);
      const resultPath = normalizePrivatePath(`${intentPath}.result`);
      const artifacts = [targetPath, intentPath, stagePath, originalPath, resultPath];
      if (artifacts.some(value => Buffer.from(value, 'utf8').toString('utf8') !== value)) throw denied();
      const paths = artifacts.map(value => value.toUpperCase());
      if (new Set(paths).size !== paths.length) throw denied();
      if (platform !== 'win32' || typeof execute !== 'function' || typeof systemRoot !== 'string') throw denied();
      const executable = path.win32.join(normalizePrivatePath(systemRoot), 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
      const request = { version: 1, operation, targetPath, intentPath, operationId };
      if (prepare) {
        if (options.originalBytes !== null && (!Buffer.isBuffer(options.originalBytes) || options.originalBytes.length > MAX_FILE_BYTES)) throw denied();
        if (!Buffer.isBuffer(options.resultBytes) || options.resultBytes.length > MAX_FILE_BYTES) throw denied();
        request.originalBytesBase64 = options.originalBytes === null ? null : options.originalBytes.toString('base64');
        request.resultBytesBase64 = options.resultBytes.toString('base64');
      }
      const input = JSON.stringify(request);
      if (Buffer.byteLength(input) > MAX_REQUEST_BYTES) throw denied();
      const output = execute(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', HELPER], {
        input, encoding: 'utf8', timeout: 30000, maxBuffer: MAX_RESPONSE_BYTES,
        windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
      });
      if (typeof output !== 'string' || Buffer.byteLength(output) > MAX_RESPONSE_BYTES) throw denied();
      const result = JSON.parse(output);
      if (!exactKeys(result, ['version', 'ok', 'operation', 'targetPath', 'intentPath', 'operationId', 'state', 'intentSha256', 'size', 'identity']) || result.version !== 1 || result.ok !== true || result.operation !== operation || result.targetPath !== targetPath || result.intentPath !== intentPath || result.operationId !== operationId || !['prepared', 'committed'].includes(result.state) || operation === 'publishPrivatePublication' && result.state !== 'committed' || !/^[a-f0-9]{64}$/.test(result.intentSha256) || !Number.isInteger(result.size) || result.size < 0 || result.size > MAX_FILE_BYTES || !exactKeys(result.identity, ['volumeSerial', 'fileId']) || !Number.isInteger(result.identity.volumeSerial) || result.identity.volumeSerial < 0 || result.identity.volumeSerial > 0xffffffff || !/^[a-f0-9]{16}$/.test(result.identity.fileId)) throw denied();
      if (prepare && result.size !== options.resultBytes.length) throw denied();
      return Object.freeze({ state: result.state, targetPath, intentPath, operationId, intentSha256: result.intentSha256, size: result.size, identity: Object.freeze({ ...result.identity }) });
    } catch {
      // Process errors can contain stdin and secret payloads. Discard them.
      throw denied();
    }
  }
  return Object.freeze({
    preparePrivatePublication: options => invoke('preparePrivatePublication', options),
    inspectPrivatePublication: options => invoke('inspectPrivatePublication', options),
    publishPrivatePublication: options => invoke('publishPrivatePublication', options),
  });
}
module.exports = { ...createWindowsPrivatePublication(), createWindowsPrivatePublication, MAX_FILE_BYTES };
