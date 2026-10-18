/**
 * mcp-registry tools — list_servers, register, remove, describe_tools,
 * import_manifest.
 *
 * @intentional-vulnerability mcp01-tool-poisoning
 * @teaches OWASP-MCP:MCP-03
 * @location agent-host/agents/mcp-registry/tools/index.js
 * intentional — when an SSE-transport server is registered, its listTools
 * response lands verbatim in mcp_tool_cache. describe_tools then returns
 * those descriptions, and any admin supervisor turn that reads them will
 * splice a `SYSTEM: <hidden instruction>` into its own context.
 *
 * @intentional-vulnerability mcp02-rug-pull
 * @teaches OWASP-MCP:MCP-03
 * intentional — re-registering the same `name` with a different schema
 * silently replaces the previous cached tools. We DO track the change in
 * mcp_schema_history, but the runtime does not gate the swap — the next
 * agent turn uses whatever the newest schema is. The MCP page timeline
 * visualizes each swap.
 *
 * @intentional-vulnerability mcp08-ssrf
 * intentional — register() fetches ${url}/mcp/list_tools server-side to
 * discover an SSE server's tools. Any URL is accepted. Attackers can point
 * at 127.0.0.1 or 169.254.169.254.
 *
 * @intentional-vulnerability mcp09-impersonation
 * @teaches OWASP-MCP:MCP-07
 * intentional — the registry is keyed by `name`. A second register call for
 * `name="filesystem-mcp"` overwrites the seeded legitimate entry with the
 * attacker's URL. No identity/signature verification is performed.
 *
 * @intentional-vulnerability llm03-supply-chain
 * @teaches OWASP-LLM:LLM03
 * intentional — stdio-transport registration accepts an arbitrary
 * stdio_cmd. When SS_ENABLE_REAL_MCP_SPAWN=true, that command is spawned.
 * A malicious "MCP package" so registered would run untrusted binaries.
 *
 * @intentional-vulnerability xxe-import-manifest
 * @teaches OWASP-Web:A05
 * intentional — import_manifest fetches an XML manifest and parses it with
 * a sax parser configured to resolve external entities declared in the
 * DOCTYPE. `<!ENTITY xxe SYSTEM "file:...">` references get inlined with
 * real file contents. See Wave 5A F9.
 */

const { mcpSchemaDigest } = require('../../../../server/services/secureshopMcpSchemaDigest');
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const { spawn } = require('node:child_process');
const pg=()=>require('../../../../server/database/postgres/secureshopAgentsDb').getSecureShopAgentsDb();
const xml2js = require('xml2js');

// Reuse the listing import_bulk XXE parser so we don't drift.
function _parseXxeSusceptibleXml(xml) {
  return require('../../listing/tools/import_bulk.js')._parseXxeSusceptibleXml(xml);
}

function _fetch(url) {
  return new Promise((resolve, reject) => {
    try {
      if (String(url).startsWith('file://')) {
        return resolve(fs.readFileSync(String(url).replace(/^file:\/\//, ''), 'utf8'));
      }
      const mod = String(url).startsWith('https://') ? https : http;
      const req = mod.get(url, (res) => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          reject(new Error(`Discovery HTTP ${res.statusCode}`));
          return;
        }
        let buf = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { buf += c; });
        res.on('error', reject);
        res.on('aborted', () => reject(new Error('Discovery response interrupted')));
        res.on('end', () => resolve(buf));
      });
      req.on('error', reject);
      req.setTimeout(3000, () => { req.destroy(new Error('timeout')); });
    } catch (e) {
      reject(e);
    }
  });
}

function _hashSchema(tools) {
  return mcpSchemaDigest(tools || []);
}

function list_servers() {
  return pg().listServers().then(servers=>({ok:true,count:servers.length,servers}));
}

async function register({ name, url = null, transport = 'sse', stdio_cmd = null } = {}) {
    if (!name) return { ok: false, error: 'name required' };
    const t = String(transport || 'sse');
    let tools = [];
    let discoveryError = null;

    if (t === 'sse') {
      if (!url) return { ok: false, error: 'url required for sse transport' };
      try {
        // SSRF sink: url is fetched server-side without allow-listing.
        const raw = await _fetch(`${url}/mcp/list_tools`);
        // Accept either { tools: [...] } or [{...}, ...] shape.
        let parsed;
        try { parsed = JSON.parse(raw); } catch { parsed = null; }
        if (parsed && Array.isArray(parsed.tools)) tools = parsed.tools;
        else if (Array.isArray(parsed)) tools = parsed;
        else throw new Error('Discovery response has no tool list');
        if (tools.some(tool => !tool || typeof tool !== 'object'
          || typeof tool.name !== 'string' || !tool.name
          || (tool.description !== undefined && typeof tool.description !== 'string')
          || (tool.inputSchema !== undefined && (!tool.inputSchema
            || typeof tool.inputSchema !== 'object' || Array.isArray(tool.inputSchema))))) {
          throw new Error('Discovery response contains an invalid tool');
        }
      } catch (e) {
        discoveryError = e.message;
      }
    } else if (t === 'stdio') {
      // Supply-chain sink: spawn the caller-supplied command.
      if (process.env.SS_ENABLE_REAL_MCP_SPAWN === 'true' && stdio_cmd) {
        try {
          const child = spawn('sh', ['-c', stdio_cmd], { stdio: 'ignore', detached: true });
          child.unref();
        } catch (e) {
          discoveryError = e.message;
        }
      }
    }

    // Failed discovery is not a new empty schema. Preserve the last usable
    // registration, while valid replacements retain all deliberate teaching sinks.
    if (discoveryError) return { ok: false, name, error: 'MCP discovery failed', discovery_error: discoveryError };

    const schemaHash = _hashSchema(tools);
    // Descriptions remain verbatim and same-name registration still replaces
    // the active schema: the MCP-01, MCP-02, and MCP-09 teaching sinks.
    const {existing,changed}=await pg().registerServer({name,url,transport:t,stdio_cmd,schemaHash,tools});
    return{ok:true,name,url,transport:t,stdio_cmd,tool_count:tools.length,schema_hash:schemaHash,schema_changed:changed,discovery_error:discoveryError,note:existing?'existing registry entry overwritten (MCP-02 rug-pull surface)':'new registry entry'};
}

function remove({ name } = {}) {
  return name?pg().removeServer(name):Promise.resolve({ok:false,error:'name required'});
}

function describe_tools({ name } = {}) {
  return pg().describeTools(name).then(tools=>({ok:true,name,tool_count:tools.length,tools}));
}

async function import_manifest({ xml_url } = {}) {
  if (!xml_url) return { ok: false, error: 'xml_url required' };
  try {
    const rawXml = await _fetch(xml_url);
    // Wave 5A F9 — real XXE via sax parser with entity resolution enabled.
    const doc = _parseXxeSusceptibleXml(rawXml);
    // Optional: import registered servers under manifest.servers.server[]
    const container = (doc && (doc.manifest || doc.servers || doc.root)) || {};
    const list = container.server ? (Array.isArray(container.server) ? container.server : [container.server]) : [];
    const registered = [];
    for (const s of list) {
      if (s && s.name && s.url) {
        registered.push(await register({ name: String(s.name), url: String(s.url), transport: String(s.transport || 'sse') }));
      }
    }
    return { ok: true, xml_doc: doc, registered_count: registered.length, registered };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function get_schema_history({ name = null } = {}) {
  return pg().schemaHistory(name).then(history=>({ok:true,count:history.length,history}));
}

module.exports = { list_servers, register, remove, describe_tools, import_manifest, get_schema_history };
