'use strict';

const path = require('node:path');
const { execFileSync } = require('node:child_process');

const MAX_FILE_BYTES = 1024 * 1024;
const MAX_DELETE_BYTES = 4096;
const MAX_WIRE_BYTES = 1500000;
const HELPER = path.resolve(__dirname, '../windows/windows-private-state.ps1');
const FAILURE_CODE = 'WINDOWS_PRIVATE_STATE_DENIED';

function denied() {
  return Object.assign(new Error('Windows private state operation denied.'), { code: FAILURE_CODE });
}

// A narrow Win32 namespace: no UNC, device paths, alternate streams, dot
// navigation, DOS aliases, or names that Win32 silently rewrites. Drive-root
// operations are excluded. No caller-controlled text is interpreted as code.
function normalizePrivatePath(value) {
  if (typeof value !== 'string' || value.length > 240 || !/^[a-zA-Z]:\\/.test(value) || /[\x00-\x1f\x7f/]/.test(value)) throw denied();
  const parts = value.slice(3).split('\\');
  if (!parts.length || parts.some(part => !part || part === '.' || part === '..' || /[<>:"|?*]/.test(part) || /[. ]$/.test(part) || /^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|CLOCK\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)/i.test(part))) throw denied();
  return value[0].toUpperCase() + value.slice(1);
}

function canonicalBase64(value) {
  if (typeof value !== 'string' || value.length > Math.ceil(MAX_FILE_BYTES / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw denied();
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > MAX_FILE_BYTES || bytes.toString('base64') !== value) throw denied();
  return bytes;
}

function exactKeys(object, expected) {
  return object && typeof object === 'object' && !Array.isArray(object) && Object.keys(object).sort().join(',') === expected.slice().sort().join(',');
}
function nativeIdentity(value) {
  return exactKeys(value, ['volumeSerial', 'fileId']) && Number.isInteger(value.volumeSerial)
    && value.volumeSerial >= 0 && value.volumeSerial <= 0xffffffff
    && typeof value.fileId === 'string' && /^[a-f0-9]{16}$/.test(value.fileId);
}

// Metadata identity is an observation for this operation, not an immutable
// cross-operation capability: NTFS may reuse identifiers after deletion.
// ensurePrivateDirectory creates only one leaf under existing admitted parents;
// createPrivateFile never replaces an existing object, and failures may retain
// a private partial file. Recovery/publication are separate integration work.
// readPrivateWorkspaceFile admits ordinarily readable parents only through the
// same trusted, non-mutating ancestor policy; its leaf remains strictly private.
// inspectWorkspaceDirectory applies that policy to the readable workspace
// itself and additionally requires the target directory's current-SID owner.
// readAndFlushPrivateFile/readAndFlushPrivateWorkspaceFile flush the exact
// held admitted file before returning bytes. They do not write bytes, create
// objects, or establish directory-entry durability; ordinary reads stay read-only.
// deleteMatchingPrivateFile requires an exact bounded prior byte/identity
// observation and deletes only the admitted handle. No pathname fallback.
// Injection is solely a controlled-test seam; using a supplied executor does
// not establish native Windows qualification. The default always uses the
// Windows installation's PowerShell 5.1 executable, never PATH or a shell.
function createWindowsPrivateState({ execute = execFileSync, platform = process.platform, systemRoot = process.env.SystemRoot } = {}) {
  function invoke(operation, inputPath, bytes, expectedIdentity, snapshot = false) {
    try {
      const normalized = normalizePrivatePath(inputPath);
      if (platform !== 'win32' || typeof execute !== 'function' || typeof systemRoot !== 'string' || !/^[a-zA-Z]:\\[^\x00-\x1f<>:"|?*]+$/.test(systemRoot)) throw denied();
      const executable = path.win32.join(normalizePrivatePath(systemRoot), 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
      const request = { version: 1, operation, path: normalized };
      const deleting = operation === 'deleteMatchingPrivateFile';
      if (operation === 'createPrivateFile' || deleting) {
        if (!Buffer.isBuffer(bytes) || bytes.length > (deleting ? MAX_DELETE_BYTES : MAX_FILE_BYTES)) throw denied();
        request.bytesBase64 = bytes.toString('base64');
      }
      if (deleting) {
        if (!nativeIdentity(expectedIdentity)) throw denied();
        request.expectedIdentity = { ...expectedIdentity };
      }
      const input = JSON.stringify(request);
      if (Buffer.byteLength(input, 'utf8') > MAX_WIRE_BYTES) throw denied();
      const output = execute(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', HELPER], {
        input, encoding: 'utf8', timeout: 30000, maxBuffer: MAX_WIRE_BYTES,
        windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
      });
      if (typeof output !== 'string' || Buffer.byteLength(output, 'utf8') > MAX_WIRE_BYTES) throw denied();
      const result = JSON.parse(output);
      const reading = operation === 'readPrivateFile' || operation === 'readPrivateWorkspaceFile'
        || operation === 'readAndFlushPrivateFile' || operation === 'readAndFlushPrivateWorkspaceFile';
      const expected = ['version', 'ok', 'operation', 'path', 'size', 'identity'];
      if (reading) expected.push('bytesBase64');
      if (deleting) expected.push('deleted');
      if (!exactKeys(result, expected) || result.version !== 1 || result.ok !== true || result.operation !== operation || result.path !== normalized || !nativeIdentity(result.identity)) throw denied();
      const directory = operation === 'ensurePrivateDirectory' || operation === 'inspectPrivateDirectory' || operation === 'inspectWorkspaceDirectory';
      if (directory ? result.size !== null : !Number.isInteger(result.size) || result.size < 0 || result.size > MAX_FILE_BYTES) throw denied();
      const metadata = Object.freeze({ path: normalized, size: result.size, identity: Object.freeze({ ...result.identity }) });
      if (reading) {
        const content = canonicalBase64(result.bytesBase64);
        if (content.length !== result.size) throw denied();
        if (snapshot) return Object.freeze({ ...metadata, get bytes() { return Buffer.from(content); } });
        return content;
      }
      if (deleting) {
        if (result.deleted !== true || result.size !== bytes.length
          || result.identity.volumeSerial !== request.expectedIdentity.volumeSerial
          || result.identity.fileId !== request.expectedIdentity.fileId) throw denied();
        return Object.freeze({ ...metadata, deleted: true });
      }
      if (operation === 'createPrivateFile' && result.size !== bytes.length) throw denied();
      return metadata;
    } catch {
      // Child exceptions may contain stdin, stdout, stderr or credentials.
      // Deliberately discard them rather than attaching a cause or logging.
      throw denied();
    }
  }
  return Object.freeze({
    ensurePrivateDirectory: directory => invoke('ensurePrivateDirectory', directory),
    inspectPrivateDirectory: directory => invoke('inspectPrivateDirectory', directory),
    inspectWorkspaceDirectory: directory => invoke('inspectWorkspaceDirectory', directory),
    readPrivateFile: file => invoke('readPrivateFile', file),
    readPrivateFileSnapshot: file => invoke('readPrivateFile', file, undefined, undefined, true),
    readPrivateWorkspaceFile: file => invoke('readPrivateWorkspaceFile', file),
    readAndFlushPrivateFile: file => invoke('readAndFlushPrivateFile', file),
    readAndFlushPrivateFileSnapshot: file => invoke('readAndFlushPrivateFile', file, undefined, undefined, true),
    readAndFlushPrivateWorkspaceFile: file => invoke('readAndFlushPrivateWorkspaceFile', file),
    createPrivateFile: (file, bytes) => invoke('createPrivateFile', file, bytes),
    deleteMatchingPrivateFile: (file, bytes, identity) => invoke('deleteMatchingPrivateFile', file, bytes, identity),
  });
}

module.exports = { ...createWindowsPrivateState(), createWindowsPrivateState, normalizePrivatePath, MAX_FILE_BYTES, MAX_DELETE_BYTES };
