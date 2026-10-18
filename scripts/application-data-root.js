'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const windowsPrivateState = require('./lib/windows-private-state');

class ApplicationDataRootError extends Error {
  constructor(message) {
    super(message);
    this.code = 'INVALID_APPLICATION_DATA_ROOT';
  }
}

function workspaceId(workspace, { realpath = fs.realpathSync } = {}) {
  return createHash('sha256').update(realpath(workspace)).digest('hex').slice(0, 12);
}

function ensureWindowsApplicationDataRoot({ workspace, environment, homeDirectory, realpath, privateState }) {
  try {
    const normalize = windowsPrivateState.normalizePrivatePath;
    const canonicalWorkspace = normalize(realpath(normalize(workspace)));
    const configured = environment.DVAIA_APP_DATA_ROOT;
    let target;
    let defaultParents = [];
    if (configured !== undefined && configured !== '') {
      target = normalize(configured);
    } else {
      const canonicalHome = normalize(realpath(normalize(homeDirectory)));
      const privateBase = path.win32.join(canonicalHome, '.dvaia');
      const workspaceDirectory = path.win32.join(privateBase, workspaceId(canonicalWorkspace,
        { realpath: () => canonicalWorkspace }));
      target = normalize(path.win32.join(workspaceDirectory, 'app-data'));
      defaultParents = [privateBase, workspaceDirectory];
    }
    const lowerTarget = target.toLowerCase();
    const lowerWorkspace = canonicalWorkspace.toLowerCase();
    const containsWindows = (parent, child) => child === parent || child.startsWith(`${parent}\\`);
    if (containsWindows(lowerTarget, lowerWorkspace) || containsWindows(lowerWorkspace, lowerTarget)) {
      throw new ApplicationDataRootError('Application data root must not overlap the application workspace');
    }
    // The native helper creates only a leaf, admits local NTFS paths, holds
    // ancestors against mutation and rejects unsafe ACLs/reparse traversal.
    // Create the default hierarchy sequentially; explicit roots require their
    // ordinary parents to already exist. Never repair an existing unsafe ACL.
    for (const directory of [...defaultParents, target]) privateState.ensurePrivateDirectory(directory);
    for (const directory of [...defaultParents, target]) privateState.inspectPrivateDirectory(directory);
    environment.DVAIA_APP_DATA_ROOT = target;
    return target;
  } catch (error) {
    if (error instanceof ApplicationDataRootError) throw error;
    // Native/process exceptions can include private paths or request bytes.
    throw new ApplicationDataRootError('Windows application data root could not be admitted');
  }
}

function contains(parent, child) {
  return child === parent || child.startsWith(`${parent}${path.sep}`);
}

function assertSafePathComponents(target, uid) {
  const parsed = path.parse(target);
  let current = parsed.root;
  for (const part of target.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try {
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink()) {
        throw new ApplicationDataRootError('Application data root must not contain symbolic links');
      }
      if (!stat.isDirectory()) throw new ApplicationDataRootError('Application data root ancestors must be directories');
      if (uid !== null && stat.uid !== uid && stat.uid !== 0) {
        throw new ApplicationDataRootError('Application data root ancestors must be owned by the current user or system');
      }
      const writableByOthers = (stat.mode & 0o022) !== 0;
      const protectedSystemTemporary = stat.uid === 0 && (stat.mode & 0o1000) !== 0;
      if (writableByOthers && !protectedSystemTemporary) {
        throw new ApplicationDataRootError('Application data root ancestors must not be writable by other users');
      }
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
  }
}

function assertPrivateOwnedDirectory(target, uid) {
  const stat = fs.lstatSync(target);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new ApplicationDataRootError('Application data root must be a private directory');
  }
  if (uid !== null && stat.uid !== uid) {
    throw new ApplicationDataRootError('Application data root must be owned by the current user');
  }
  if ((stat.mode & 0o777) !== 0o700) {
    throw new ApplicationDataRootError('Application data root permissions must be 0700');
  }
}

function ensureApplicationDataRoot({
  workspace = path.resolve(__dirname, '..'),
  environment = process.env,
  homeDirectory = os.homedir(),
  uid = typeof process.getuid === 'function' ? process.getuid() : null,
  platform = process.platform,
  // Explicit controlled-test seams do not establish native OS qualification.
  realpath = fs.realpathSync,
  privateState = windowsPrivateState,
} = {}) {
  if (platform === 'win32') {
    return ensureWindowsApplicationDataRoot({ workspace, environment, homeDirectory, realpath, privateState });
  }
  let canonicalWorkspace;
  try { canonicalWorkspace = fs.realpathSync(workspace); }
  catch { throw new ApplicationDataRootError('Application workspace is unavailable'); }

  const configured = environment.DVAIA_APP_DATA_ROOT;
  let target;
  let defaultParents = [];
  if (configured !== undefined && configured !== '') {
    if (typeof configured !== 'string' || configured.includes('\0') || !path.isAbsolute(configured)
      || path.normalize(configured) !== configured) {
      throw new ApplicationDataRootError('DVAIA_APP_DATA_ROOT must be a canonical absolute path');
    }
    target = configured;
  } else {
    if (typeof homeDirectory !== 'string' || !path.isAbsolute(homeDirectory) || homeDirectory.includes('\0')) {
      throw new ApplicationDataRootError('Application home directory must be absolute');
    }
    let canonicalHome;
    try { canonicalHome = fs.realpathSync(homeDirectory); }
    catch { throw new ApplicationDataRootError('Application home directory is unavailable'); }
    const privateBase = path.join(canonicalHome, '.dvaia');
    const workspaceDirectory = path.join(privateBase, workspaceId(canonicalWorkspace));
    target = path.join(workspaceDirectory, 'app-data');
    defaultParents = [privateBase, workspaceDirectory];
  }

  const filesystemRoot = path.parse(target).root;
  if (target === filesystemRoot || contains(target, canonicalWorkspace) || contains(canonicalWorkspace, target)) {
    throw new ApplicationDataRootError('Application data root must not overlap the application workspace or filesystem root');
  }
  assertSafePathComponents(target, uid);

  const existed = fs.existsSync(target);
  try { fs.mkdirSync(target, { recursive: true, mode: 0o700 }); }
  catch { throw new ApplicationDataRootError('Application data root could not be created'); }
  if (!existed) fs.chmodSync(target, 0o700);

  assertSafePathComponents(target, uid);
  assertPrivateOwnedDirectory(target, uid);
  if (!configured) {
    for (const parent of defaultParents) assertPrivateOwnedDirectory(parent, uid);
  }
  environment.DVAIA_APP_DATA_ROOT = target;
  return target;
}

module.exports = { ApplicationDataRootError, ensureApplicationDataRoot, workspaceId };
