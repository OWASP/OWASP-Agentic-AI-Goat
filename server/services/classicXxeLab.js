'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { TextDecoder } = require('node:util');
const sax = require('sax');

const VIRTUAL_SECRET_URI = 'file:///etc/xxe-secret.txt';
const LIMITS = Object.freeze({
  maxInputBytes: 64 * 1024,
  maxSecretBytes: 4 * 1024,
  maxExpandedTextBytes: 64 * 1024,
  maxElements: 256,
  maxDepth: 32
});

class ClassicXxeError extends Error {
  constructor(code, message, unavailable = false) {
    super(message);
    this.name = 'ClassicXxeError';
    this.code = code;
    this.unavailable = unavailable;
  }
}

function fail(code, message, unavailable = false) {
  throw new ClassicXxeError(code, message, unavailable);
}

function decodeUtf8(bytes, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('XXE_INVALID_UTF8', `${label} is not valid UTF-8`);
  }
}

function sameFile(before, after, bytes) {
  return before.dev === after.dev && before.ino === after.ino
    && before.size === after.size && before.mtimeNs === after.mtimeNs
    && before.ctimeNs === after.ctimeNs && BigInt(bytes) === before.size;
}

function readRegularFile(filename) {
  let descriptor;
  try {
    descriptor = fs.openSync(filename,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile()) fail('XXE_FIXTURE_INVALID', 'The isolated training file is not a regular file', true);
    if (before.size < 1n || before.size > BigInt(LIMITS.maxSecretBytes)) {
      fail('XXE_FIXTURE_INVALID', 'The isolated training file has an invalid size', true);
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!sameFile(before, after, offset)) {
      fail('XXE_FIXTURE_CHANGED', 'The isolated training file changed while it was read', true);
    }
    return bytes;
  } catch (error) {
    if (error instanceof ClassicXxeError) throw error;
    fail('XXE_FIXTURE_UNAVAILABLE', 'The isolated training file could not be read', true);
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

function parseDeclaration(xml) {
  const starts = xml.match(/<!DOCTYPE\b/gi) || [];
  const entityTokens = xml.match(/<!ENTITY\b/gi) || [];
  if (starts.length === 0) {
    if (entityTokens.length) fail('XXE_POLICY_REJECTED', 'Entity declarations require one supported DOCTYPE');
    return null;
  }
  if (starts.length !== 1 || entityTokens.length !== 1) {
    fail('XXE_POLICY_REJECTED', 'Exactly one external entity declaration is supported');
  }
  const name = '([A-Za-z_:][A-Za-z0-9_.:-]{0,63})';
  const pattern = new RegExp(`<!DOCTYPE\\s+${name}\\s*\\[\\s*<!ENTITY\\s+${name}\\s+SYSTEM\\s+(["'])${VIRTUAL_SECRET_URI.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\3\\s*>\\s*\\]>`, 'i');
  const match = xml.match(pattern);
  if (!match) fail('XXE_POLICY_REJECTED', `Only the isolated training URI ${VIRTUAL_SECRET_URI} is available`);
  const remainder = xml.replace(match[0], '');
  if (/<!DOCTYPE\b|<!ENTITY\b|\bSYSTEM\b|\bPUBLIC\b/i.test(remainder)) {
    fail('XXE_POLICY_REJECTED', 'Additional declarations are not supported');
  }
  const referencePattern = new RegExp(`&${match[2].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')};`, 'g');
  return {
    rootName: match[1], entityName: match[2], systemId: VIRTUAL_SECRET_URI,
    referenceCount: (remainder.match(referencePattern) || []).length
  };
}

function addChild(children, name, value) {
  if (!Object.hasOwn(children, name)) Object.defineProperty(children, name,
    { value, writable: true, enumerable: true, configurable: true });
  else if (Array.isArray(children[name])) children[name].push(value);
  else children[name] = [children[name], value];
}

function parseWithSax(xml, declaration, secret) {
  const parser = sax.parser(true, { xmlns: false, position: false });
  const stack = [];
  let result;
  let elements = 0;
  let expandedTextBytes = 0;
  let sawDoctype = false;
  let sawResolvedValue = false;
  let entityResolutionReads = 0;

  parser.ondoctype = raw => {
    if (!declaration || sawDoctype) fail('XXE_POLICY_REJECTED', 'Unexpected DOCTYPE');
    const expected = new RegExp(`^\\s*${declaration.rootName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\[\\s*<!ENTITY\\s+${declaration.entityName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s+SYSTEM\\s+(["'])${VIRTUAL_SECRET_URI.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\1\\s*>\\s*\\]\\s*$`, 'i');
    if (!expected.test(raw)) fail('XXE_POLICY_REJECTED', 'The DOCTYPE does not match the isolated training declaration');
    if (secret !== null) {
      Object.defineProperty(parser.ENTITIES, declaration.entityName, {
        configurable: true,
        enumerable: true,
        get() { entityResolutionReads++; return secret; }
      });
    }
    sawDoctype = true;
  };
  parser.onopentag = node => {
    elements++;
    if (elements > LIMITS.maxElements) fail('XXE_LIMIT_EXCEEDED', 'XML element limit exceeded');
    if (stack.length >= LIMITS.maxDepth) fail('XXE_LIMIT_EXCEEDED', 'XML nesting limit exceeded');
    for (const value of Object.values(node.attributes)) {
      expandedTextBytes += Buffer.byteLength(String(value), 'utf8');
      if (secret !== null && String(value).includes(secret)) sawResolvedValue = true;
    }
    if (expandedTextBytes > LIMITS.maxExpandedTextBytes) fail('XXE_LIMIT_EXCEEDED', 'Expanded XML output limit exceeded');
    stack.push({ name: node.name, attributes: node.attributes, children: Object.create(null), text: '' });
  };
  const appendText = value => {
    expandedTextBytes += Buffer.byteLength(value, 'utf8');
    if (expandedTextBytes > LIMITS.maxExpandedTextBytes) fail('XXE_LIMIT_EXCEEDED', 'Expanded XML output limit exceeded');
    if (secret !== null && value.includes(secret)) sawResolvedValue = true;
    if (stack.length) stack[stack.length - 1].text += value;
  };
  parser.ontext = appendText;
  parser.oncdata = appendText;
  parser.onclosetag = () => {
    const node = stack.pop();
    const childNames = Object.keys(node.children);
    const attributeNames = Object.keys(node.attributes);
    let value;
    if (!childNames.length && !attributeNames.length) value = node.text;
    else {
      value = {};
      if (attributeNames.length) value.$ = node.attributes;
      if (node.text) value._ = node.text;
      if (childNames.length) value.$$ = node.children;
    }
    if (stack.length) addChild(stack[stack.length - 1].children, node.name, value);
    else result = { [node.name]: value };
  };
  try {
    parser.write(xml).close();
  } catch (error) {
    if (error instanceof ClassicXxeError) throw error;
    fail('XXE_XML_INVALID', `Invalid XML: ${String(error.message || 'parse failure').split('\n')[0]}`);
  }
  if (declaration && (!sawDoctype || !result || !Object.hasOwn(result, declaration.rootName))) {
    fail('XXE_XML_INVALID', 'The document root does not match its DOCTYPE');
  }
  return { parsed: result, expanded: Boolean(
    declaration && secret !== null && entityResolutionReads > 0 && sawResolvedValue
  ) };
}

function createClassicXxeLab({
  rootPath = path.join(os.tmpdir(), 'owasp-ai-goat-classic-xxe'),
  fixtureFactory = ({ fixturePath }) => {
    const secret = `OWASP_AI_GOAT_XXE_${crypto.randomBytes(24).toString('hex')}`;
    fs.writeFileSync(fixturePath, secret, { mode: 0o600, flag: 'wx' });
  },
  removeAttempt = attemptDir => fs.rmSync(attemptDir, { recursive: true, force: true })
} = {}) {
  if (typeof rootPath !== 'string' || !path.isAbsolute(rootPath)
      || typeof fixtureFactory !== 'function' || typeof removeAttempt !== 'function') {
    throw new TypeError('A trusted absolute lab root and fixture factory are required');
  }
  return async function execute(xmlData) {
    if (typeof xmlData !== 'string') fail('XXE_INPUT_INVALID', 'xmlData must be a string');
    const inputBytes = Buffer.byteLength(xmlData, 'utf8');
    if (inputBytes < 1 || inputBytes > LIMITS.maxInputBytes) {
      fail('XXE_LIMIT_EXCEEDED', `xmlData must be between 1 and ${LIMITS.maxInputBytes} UTF-8 bytes`);
    }
    decodeUtf8(Buffer.from(xmlData, 'utf8'), 'xmlData');
    const declaration = parseDeclaration(xmlData);
    if (!declaration) return { parsed: parseWithSax(xmlData, null, null).parsed, observation: null };
    if (declaration.referenceCount === 0) {
      return { parsed: parseWithSax(xmlData, declaration, null).parsed, observation: null };
    }

    let attemptDir;
    try {
      fs.mkdirSync(rootPath, { recursive: true, mode: 0o700 });
      const rootStat = fs.lstatSync(rootPath);
      if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
        fail('XXE_LAB_UNAVAILABLE', 'The isolated XXE training root is invalid', true);
      }
      fs.chmodSync(rootPath, 0o700);
      attemptDir = fs.mkdtempSync(path.join(rootPath, 'attempt-'));
      fs.chmodSync(attemptDir, 0o700);
      const fixturePath = path.join(attemptDir, 'xxe-secret.txt');
      await fixtureFactory({ fixturePath, attemptDir });
      const secretBytes = readRegularFile(fixturePath);
      if (inputBytes + (declaration.referenceCount * secretBytes.length) > LIMITS.maxExpandedTextBytes) {
        fail('XXE_LIMIT_EXCEEDED', 'Projected expanded XML output exceeds the size limit');
      }
      const secret = decodeUtf8(secretBytes, 'isolated training file');
      const parsedResult = parseWithSax(xmlData, declaration, secret);
      if (!parsedResult.expanded) {
        return { parsed: parsedResult.parsed, observation: null };
      }
      return {
        parsed: parsedResult.parsed,
        observation: Object.freeze({
          mechanism: 'custom-sax-external-entity-resolver',
          parser: `sax/${require('sax/package.json').version}`,
          isolated: true,
          entityName: declaration.entityName,
          systemId: declaration.systemId,
          bytesRead: secretBytes.length,
          sha256: crypto.createHash('sha256').update(secretBytes).digest('hex')
        })
      };
    } catch (error) {
      if (error instanceof ClassicXxeError) throw error;
      fail('XXE_LAB_UNAVAILABLE', 'The isolated XXE training lab is unavailable', true);
    } finally {
      if (attemptDir) {
        try { removeAttempt(attemptDir); } catch {
          fail('XXE_CLEANUP_FAILED', 'The isolated XXE attempt could not be removed', true);
        }
      }
    }
  };
}

let defaultLab;
function getClassicXxeLab() {
  if (!defaultLab) defaultLab = createClassicXxeLab();
  return defaultLab;
}

module.exports = { createClassicXxeLab, getClassicXxeLab, ClassicXxeError, LIMITS, VIRTUAL_SECRET_URI };
