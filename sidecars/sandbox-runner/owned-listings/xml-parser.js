'use strict';

// Candidate worker component. The attested executor supplies resolveEntity;
// this module has no filesystem or network authority of its own.
const sax = require('sax');
const { createHash } = require('node:crypto');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => Object.assign(new Error(code), { code });
const MAX = 1024 * 1024;
async function parseOwnedListingXml(xml, { mode, resolveEntity, signal } = {}) {
  if (typeof xml !== 'string' || !xml.isWellFormed() || Buffer.byteLength(xml) > MAX
      || !['vuln', 'fixed'].includes(mode) || typeof resolveEntity !== 'function') throw fail('LISTING_XML_INVALID');
  signal?.throwIfAborted();
  let doctype = null;
  const stop = Symbol('doctype');
  const probe = sax.parser(true);
  probe.ondoctype = value => { doctype = value; throw stop; };
  try { probe.write(xml).close(); } catch (error) { if (error !== stop) throw fail('LISTING_XML_INVALID'); }
  const entities = Object.create(null), reads = [];
  let total = Buffer.byteLength(xml);
  if (doctype !== null) {
    if (mode === 'fixed') throw fail('LISTING_XML_ENTITIES_DISABLED');
    const subset = /^\s*[A-Za-z_][\w.:-]*\s*\[([\s\S]*)\]\s*$/.exec(doctype);
    if (!subset) throw fail('LISTING_XML_DECLARATION_UNSUPPORTED');
    const declaration = /<!ENTITY\s+([A-Za-z_][\w.:-]*)\s+SYSTEM\s+(["'])([^"']+)\2\s*>/g;
    const matches = [...subset[1].matchAll(declaration)];
    if (subset[1].replace(declaration, '').trim() || matches.length > 8) throw fail('LISTING_XML_DECLARATION_UNSUPPORTED');
    for (const match of matches) {
      signal?.throwIfAborted();
      const name = match[1], uri = match[3];
      if (Object.hasOwn(entities, name) || ['amp', 'lt', 'gt', 'quot', 'apos'].includes(name)) throw fail('LISTING_XML_INVALID');
      const bytes = await resolveEntity(uri, { signal, maxBytes: MAX - total });
      signal?.throwIfAborted();
      if (!Buffer.isBuffer(bytes) || (total += bytes.length) > MAX) throw fail('LISTING_XML_LIMIT');
      let text;
      try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { throw fail('LISTING_XML_INVALID'); }
      entities[name] = text;
      reads.push(Object.freeze({ name, uri, byteCount: bytes.length, sha256: sha(bytes) }));
    }
  }
  const parser = sax.parser(true), stack = [], products = [];
  let outputBytes = 0, root;
  parser.ondoctype = () => { for (const [name, value] of Object.entries(entities)) parser.ENTITIES[name] = value; };
  parser.onopentag = node => {
    if (stack.length >= 32) throw fail('LISTING_XML_LIMIT');
    if (Object.keys(node.attributes).length || (stack.length === 1 && node.name !== 'product') || stack.length > 2) throw fail('LISTING_XML_INVALID');
    if (stack.length) stack[stack.length - 1].hasChildren = true;
    if (!stack.length) { if (root) throw fail('LISTING_XML_INVALID'); root = node.name; }
    stack.push({ name: node.name, text: '', fields: Object.create(null) });
  };
  const append = value => {
    outputBytes += Buffer.byteLength(value);
    if (outputBytes > MAX) throw fail('LISTING_XML_LIMIT');
    if (stack.length) stack[stack.length - 1].text += value;
  };
  parser.ontext = append; parser.oncdata = append;
  parser.onclosetag = () => {
    const node = stack.pop(), parent = stack[stack.length - 1];
    if (stack.length < 2 && node.text.trim()) throw fail('LISTING_XML_INVALID');
    if (node.name === 'product' && stack.length === 1) {
      if (products.length >= 100) throw fail('LISTING_XML_LIMIT');
      products.push(Object.freeze({ ...node.fields }));
    } else if (parent?.name === 'product' && stack.length === 2) {
      if (Object.hasOwn(parent.fields, node.name) || node.hasChildren) throw fail('LISTING_XML_INVALID');
      parent.fields[node.name] = node.text;
    }
  };
  try { parser.write(xml).close(); } catch (error) { if (error.code) throw error; throw fail('LISTING_XML_INVALID'); }
  if (!['products', 'catalog'].includes(root) || !products.length) throw fail('LISTING_XML_INVALID');
  return Object.freeze({ products: Object.freeze(products), entityReads: Object.freeze(reads), sourceSha256: sha(xml) });
}
module.exports = { parseOwnedListingXml };
