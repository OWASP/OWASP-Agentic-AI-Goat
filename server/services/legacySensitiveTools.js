'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { fileBoundary } = require('../agent-runtime/legacySensitiveEvidence');

const DEFAULT_SSI_VALUES = Object.freeze({
  DATABASE_PASSWORD: 'Db@dmin#Pass2024',
  API_KEY: 'sk-proj-abc123def456',
  SECRET_TOKEN: 'ultra-secret-token-987654',
  ADMIN_KEY: 'admin_key_12345',
  SECRET_FLAG: require('../config/legacySensitiveFlags').SSI_FLAG,
});

const SIMULATED_COMMANDS = Object.freeze({
  whoami: 'www-data',
  pwd: '/var/www/html',
  ls: 'index.html  config.php  secret.txt  admin.txt',
  'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
  id: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
  env: 'PATH=/usr/local/bin:/usr/bin\nDATABASE_PASSWORD=Db@dmin#Pass2024\nAPI_KEY=sk-proj-abc123def456',
});

function text(value, name, limit = 16000) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > limit) {
    throw Object.assign(new TypeError(`${name} is required`), { code: 'LEGACY_SENSITIVE_INPUT_INVALID' });
  }
  return value;
}

function createLegacySensitiveTools({
  sensitiveFilesDir,
  publicDir = path.join(sensitiveFilesDir || '', 'public'),
  fileBaseDir = publicDir,
  fsImpl = fs,
  now = () => new Date(),
  ssiValues = DEFAULT_SSI_VALUES,
} = {}) {
  if (typeof sensitiveFilesDir !== 'string' || !path.isAbsolute(sensitiveFilesDir)) {
    throw new TypeError('An absolute teaching-file root is required');
  }
  if (typeof publicDir !== 'string' || !path.isAbsolute(publicDir)
      || typeof fileBaseDir !== 'string' || !path.isAbsolute(fileBaseDir)) {
    throw new TypeError('Absolute public and file base directories are required');
  }

  const teachingRoot = fsImpl.realpathSync(sensitiveFilesDir);
  const publicRoot = fsImpl.realpathSync(publicDir);
  const fileBaseRoot = fsImpl.realpathSync(fileBaseDir);
  function inside(root, target) {
    const relative = path.relative(root, target);
    return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
  }
  if (publicRoot === teachingRoot || !inside(teachingRoot, publicRoot)
      || !inside(teachingRoot, fileBaseRoot)
      || ![teachingRoot, publicRoot, fileBaseRoot].every(root => fsImpl.statSync(root).isDirectory())) {
    throw Object.assign(new TypeError('Teaching, public and file base directories must define an isolated lab boundary'),
      { code: 'LEGACY_SENSITIVE_ROOT_INVALID' });
  }
  function candidateFor(requestedPath) {
    const normalized = requestedPath.replaceAll('\\', '/');
    if (normalized.startsWith('/')) return path.join(teachingRoot, normalized.slice(1));
    if (/^(?:public|secret|admin|config)(?:\/|$)/.test(normalized)) return path.join(teachingRoot, normalized);
    return path.join(fileBaseRoot, normalized);
  }
  function ownedRead(requestedPath, mode = 'vuln') {
    const target = candidateFor(requestedPath);
    if (mode === 'fixed' && !inside(publicRoot, path.resolve(target))) {
      return { success: false, error: 'Only public teaching files are available in Fixed mode', code: 'PUBLIC_FILE_ONLY' };
    }
    if (!inside(teachingRoot, path.resolve(target))) {
      return { success: false, error: 'Path is outside the teaching-file root', code: 'TEACHING_PATH_OUTSIDE_ROOT' };
    }
    if (!fsImpl.existsSync(target)) return { success: false, error: 'File not found' };
    let resolved;
    try { resolved = fsImpl.realpathSync(target); } catch { return { success: false, error: 'File not found' }; }
    if (!inside(teachingRoot, resolved)) {
      return { success: false, error: 'Path is outside the teaching-file root', code: 'TEACHING_PATH_OUTSIDE_ROOT' };
    }
    if (mode === 'fixed' && !inside(publicRoot, resolved)) {
      return { success: false, error: 'Only public teaching files are available in Fixed mode', code: 'PUBLIC_FILE_ONLY' };
    }
    let content;
    if (fsImpl === fs) {
      const descriptor = fsImpl.openSync(resolved, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      try {
        if (!fsImpl.fstatSync(descriptor).isFile()) return { success: false, error: 'File not found' };
        content = fsImpl.readFileSync(descriptor, 'utf8');
      } finally { fsImpl.closeSync(descriptor); }
    } else content = fsImpl.readFileSync(resolved, 'utf8');
    return { success: true, resolved, content };
  }

  function readTeachingFile({ path: requestedPath, mode = 'vuln' } = {}) {
    requestedPath = text(requestedPath, 'Teaching-file path', 2048);
    const read = ownedRead(requestedPath, mode);
    if (!read.success) return Object.freeze({ ...read, path: requestedPath });
    return Object.freeze({
      success: true,
      path: requestedPath,
      content: read.content,
      boundary: fileBoundary(read.resolved, publicRoot, fsImpl.realpathSync),
    });
  }

  function renderSsiTemplate({ template, request = {}, mode = 'vuln' } = {}) {
    const original = text(template, 'SSI template');
    if (mode === 'fixed') return Object.freeze({ success: true, original, rendered: original,
      ssiDetected: /<!--#(?:echo|include|exec|config)\b/i.test(original), ssiSucceeded: false,
      includeDetected: false, execDetected: false, directives: Object.freeze([]),
      executionMode: 'literal_template', commandExecution: 'none', warning: null });
    const directives = [];
    let rendered = original;
    let includeDetected = false;
    let execDetected = false;
    let ssiSucceeded = false;
    const values = Object.freeze({
      DATE_LOCAL: now().toString(),
      REMOTE_ADDR: String(request.ip || ''),
      REMOTE_USER: 'guest_user',
      DOCUMENT_NAME: 'template.html',
      DOCUMENT_URI: String(request.path || ''),
      SERVER_NAME: String(request.hostname || ''),
      HTTP_USER_AGENT: String(request.userAgent || 'Unknown'),
      PATH_INFO: String(request.path || ''),
      QUERY_STRING: String(request.queryString || ''),
      ...ssiValues,
    });

    rendered = rendered.replace(/<!--#echo var="([^"]+)" -->/g, (_match, name) => {
      directives.push(`echo:${name}`);
      if (Object.hasOwn(values, name)) ssiSucceeded = true;
      return Object.hasOwn(values, name) ? String(values[name]) : `[${name}]`;
    });

    for (const match of [...rendered.matchAll(/<!--#include (virtual|file)="([^"]+)" -->/g)]) {
      includeDetected = true;
      directives.push(`include:${match[2]}`);
      const read = ownedRead(match[2]);
      if (read.success) ssiSucceeded = true;
      let replacement;
      try {
        replacement = read.success ? read.content
          : `[Error: ${read.error}: ${match[2]}]`;
      } catch (error) {
        replacement = `[Error including file: ${error.message}]`;
      }
      rendered = rendered.replace(match[0], () => replacement);
    }

    for (const match of [...rendered.matchAll(/<!--#exec cmd="([^"]+)" -->/g)]) {
      execDetected = true;
      directives.push(`exec:${match[1]}`);
      const output = SIMULATED_COMMANDS[match[1]]
        || `Command executed: ${match[1]}\n[Output simulated for security]`;
      rendered = rendered.replace(match[0], () => `<pre>${output}</pre>`);
    }

    const detected = directives.length > 0;
    return Object.freeze({
      success: true,
      original,
      rendered,
      ssiDetected: detected,
      ssiSucceeded,
      includeDetected,
      execDetected,
      directives: Object.freeze([...directives]),
      executionMode: 'lab_ssi_interpreter',
      commandExecution: execDetected ? 'simulated' : 'none',
      warning: execDetected
        ? 'Command output is simulated by the lab interpreter; no operating-system command was executed.'
        : null,
    });
  }

  function processTeachingDocument({ path: requestedPath, processSsi = false, request, mode = 'vuln' } = {}) {
    const file = readTeachingFile({ path: requestedPath, mode });
    if (!file.success || !processSsi) return Object.freeze({ ...file, original: file.content ?? null, rendered: file.content ?? null, processedSsi: false, ssiSucceeded: false });
    const rendered = renderSsiTemplate({ template: file.content, request, mode });
    return Object.freeze({ ...file, original: rendered.original, rendered: rendered.rendered,
      processedSsi: true, ssiSucceeded: rendered.ssiSucceeded, ssi: rendered });
  }

  return Object.freeze({ readTeachingFile, renderSsiTemplate, processTeachingDocument });
}

module.exports = { createLegacySensitiveTools, DEFAULT_SSI_VALUES, SIMULATED_COMMANDS };
