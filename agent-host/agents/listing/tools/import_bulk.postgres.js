const commerce=require('../../../../server/database/postgres/secureshopCommerceDb').getSecureShopCommerceDb();
/**
 * listing.import_bulk — bulk-import products from a JSON URL and/or XML URL.
 *
 * @intentional-vulnerability ssrf-listing-import
 * @teaches OWASP-Web:A10
 * @location agent-host/agents/listing/tools/import_bulk.js
 * intentional — the URL is fetched without allow-listing (SSRF).
 *
 * @intentional-vulnerability xxe-import-bulk
 * @teaches OWASP-Web:A05
 * intentional — the XML importer parses the DOCTYPE with the `sax` package
 * (used with entity resolution enabled) so `<!ENTITY xxe SYSTEM "file:...">`
 * declarations get resolved to real file contents at reference time. This is
 * a canonical XXE: the parser trusts DOCTYPE-declared external entities.
 *
 * Wave 5A F9 note: prior to this wave the sink was a hand-rolled regex
 * expander that pre-processed raw XML before xml2js parsed it. Wave 4C
 * flagged this as mislabeled (it was really a file-read primitive dressed
 * up as XXE). The path was reworked to route through `sax` and populate
 * its `ENTITIES` table on doctype detection, which mirrors how a real
 * misconfigured parser (libxml2 with `nonet: false`, xml_ext_ent enabled)
 * behaves. The hand-rolled fallback remains for JSON-only import paths
 * that never reach the XML branch — see _expandEntities export for
 * backwards compat.
 *
 * @intentional-vulnerability insecure-deser-listing-import
 * @teaches OWASP-Web:A08
 * intentional — attacker JSON reaches an unsafe recursive merge that follows
 * __proto__ into Object.prototype. The demonstrated effect is prototype
 * pollution; this lesson does not establish downstream code execution.
 */


const xml2js = require('xml2js');
const sax = require('sax');
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');

// --- SSRF: unrestricted fetcher --------------------------------------------
function _fetch(url) {
  return new Promise((resolve, reject) => {
    try {
      if (url.startsWith('file://')) {
        const p = url.replace(/^file:\/\//, '');
        return resolve(fs.readFileSync(p, 'utf8'));
      }
      const mod = url.startsWith('https://') ? https : http;
      const req = mod.get(url, (res) => {
        let buf = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { buf += c; });
        res.on('end', () => resolve(buf));
      });
      req.on('error', reject);
      req.setTimeout(3000, () => { req.destroy(new Error('timeout')); });
    } catch (e) {
      reject(e);
    }
  });
}

// --- Prototype pollution sink ----------------------------------------------
function _mergeUnsafe(target, src) {
  // Classic deep-merge pollution: recurse into nested objects without
  // filtering __proto__ / constructor. When src has a __proto__ own-property
  // (as JSON.parse gives you), the setter path pollutes Object.prototype.
  for (const key of Object.keys(src || {})) {
    const v = src[key];
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      if (!target[key] || typeof target[key] !== 'object') target[key] = {};
      _mergeUnsafe(target[key], v);
    } else {
      target[key] = v;
    }
  }
  return target;
}

async function import_bulk({ json_url = null, xml_url = null } = {}) {
  const db = null;
  const inserted = [];
  const errors = [];
  const pollutionSink = {};

  // ---- JSON path (SSRF + proto pollution) ---------------------------------
  if (json_url) {
    try {
      const raw = await _fetch(json_url);
      const parsed = JSON.parse(raw);
      const items = Array.isArray(parsed) ? parsed : (parsed.products || [parsed]);
      for (const it of items) {
        // Direct __proto__ merge — the pollution sink.
        _mergeUnsafe(pollutionSink, it);
        if (it && it.name) {
          const info = await commerce.listing_import_bulk_1(String(it.name), String(it.description || ''), Number(it.price) || 0);
          inserted.push(info.lastInsertRowid);
        }
      }
    } catch (e) {
      errors.push({ source: 'json', message: e.message });
    }
  }

  // ---- XML path (SSRF + XXE) ---------------------------------------------
  if (xml_url) {
    try {
      const rawXml = await _fetch(xml_url);
      // Wave 5A F9 — parse through a sax parser configured to RESOLVE external
      // entities declared in the DOCTYPE. This is the real XXE surface: a
      // misconfigured XML parser trusts SYSTEM entities and inlines their
      // contents when a reference like &xxe; appears in the body.
      const doc = _parseXxeSusceptibleXml(rawXml);
      const container = (doc && (doc.products || doc.catalog || doc.root)) || {};
      const list = container.product ? (Array.isArray(container.product) ? container.product : [container.product]) : [];
      for (const it of list) {
        if (it && it.name) {
          const info = await commerce.listing_import_bulk_2(String(it.name), String(it.description || ''), Number(it.price) || 0);
          inserted.push(info.lastInsertRowid);
        }
      }
      // Also return the resolved doc so tests can assert xxe content leaked.
      return { ok: true, inserted, errors, xml_doc: doc };
    } catch (e) {
      errors.push({ source: 'xml', message: e.message });
    }
  }

  return { ok: true, inserted, errors };
}

/**
 * Parse XML with sax and expose the ENTITIES table to attacker-controlled
 * DOCTYPE declarations. When the parser encounters a `<!DOCTYPE name [ ...
 * <!ENTITY xxe SYSTEM "file:///..."> ... ]>` block, we register the entity
 * name in sax's ENTITIES map with the resolved file contents. sax then
 * substitutes `&xxe;` references in the body verbatim.
 *
 * This mirrors real-world misconfigured XML parsers (libxml2 with
 * `noent: true` / `nonet: false`, Java SAXParser with external entities
 * enabled). Wave 4C called out that the previous implementation was a
 * hand-rolled regex; this version routes through an actual XML parser's
 * ENTITIES table so the vuln label ("XXE") is accurate.
 *
 * Note: sax doesn't call http:// URIs on its own — we resolve `file://`
 * synchronously here (that's the file-exfiltration attack path).
 */
function _parseXxeSusceptibleXml(rawXml) {
  const parser = sax.parser(true, { xmlns: false, position: false });

  const root = {};
  const stack = [root];
  let textBuf = '';

  // Handle DOCTYPE: extract <!ENTITY ... SYSTEM "..."> declarations and
  // populate the parser's ENTITIES table. sax fires ondoctype with the raw
  // "[ ... ]" body (or a full DOCTYPE string in some cases).
  parser.ondoctype = (doctypeStr) => {
    const entRe = /<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>/g;
    let m;
    while ((m = entRe.exec(String(doctypeStr || ''))) !== null) {
      const name = m[1];
      const uri = m[2];
      let val = '';
      try {
        if (uri.startsWith('file://')) {
          val = fs.readFileSync(uri.replace(/^file:\/\//, ''), 'utf8');
        } else if (uri.startsWith('http://') || uri.startsWith('https://')) {
          // Real XXE-over-HTTP is async; expose the URI marker for now.
          val = `[xxe:${uri}]`;
        }
      } catch (e) {
        val = `[xxe-error:${e.message}]`;
      }
      // The sink: entity resolves to real file bytes. sax will substitute
      // &name; references in the body with this string.
      parser.ENTITIES[name] = val;
    }
  };

  parser.onopentag = (node) => {
    const el = {};
    const parent = stack[stack.length - 1];
    if (parent[node.name] === undefined) {
      parent[node.name] = el;
    } else if (Array.isArray(parent[node.name])) {
      parent[node.name].push(el);
    } else {
      parent[node.name] = [parent[node.name], el];
    }
    stack.push(el);
    textBuf = '';
  };

  parser.ontext = (t) => { textBuf += t; };
  parser.oncdata = (t) => { textBuf += t; };

  parser.onclosetag = () => {
    const cur = stack.pop();
    const trimmed = textBuf.trim();
    if (trimmed && Object.keys(cur).length === 0) {
      // Leaf text node — replace parent's ref with the string. Find which key
      // holds `cur` and swap it.
      const parent = stack[stack.length - 1];
      for (const k of Object.keys(parent)) {
        if (parent[k] === cur) { parent[k] = trimmed; break; }
        if (Array.isArray(parent[k])) {
          const idx = parent[k].indexOf(cur);
          if (idx !== -1) { parent[k][idx] = trimmed; break; }
        }
      }
    }
    textBuf = '';
  };

  parser.write(String(rawXml)).close();
  return root;
}

/**
 * Legacy hand-rolled DOCTYPE entity expansion — retained for backwards
 * compatibility with mcp-registry.import_manifest, which imports this via
 * `require('.../listing/tools/import_bulk.js')._expandEntities`. The XML
 * branch of import_bulk() itself now routes through the sax-based
 * `_parseXxeSusceptibleXml` (Wave 5A F9) so the vuln id "xxe-import-bulk"
 * matches the actual attack shape (parser-level entity resolution).
 * DO NOT harden this: it's still a teaching sink.
 */
function _expandEntities(xml) {
  const doctypeMatch = xml.match(/<!DOCTYPE[\s\S]*?\[([\s\S]*?)\]>/);
  if (!doctypeMatch) return xml;
  const decls = doctypeMatch[1];
  const entRe = /<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>/g;
  let out = xml;
  let m;
  while ((m = entRe.exec(decls)) !== null) {
    const name = m[1];
    const uri = m[2];
    let val = '';
    try {
      if (uri.startsWith('file://')) {
        val = fs.readFileSync(uri.replace(/^file:\/\//, ''), 'utf8');
      } else if (uri.startsWith('http://') || uri.startsWith('https://')) {
        // SSRF via XXE
        // fire-and-forget sync HTTP not supported; leave placeholder
        val = `[xxe:${uri}]`;
      }
    } catch (e) {
      val = `[xxe-error:${e.message}]`;
    }
    // Substitute all &name; and &name refs in the doc
    const re = new RegExp(`&${name};`, 'g');
    out = out.replace(re, val);
  }
  return out;
}

module.exports = { import_bulk, _expandEntities, _mergeUnsafe, _parseXxeSusceptibleXml };
