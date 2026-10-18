#!/usr/bin/env node
/*
 * generate-vuln-map.js
 *
 * Walks the codebase and emits docs/secureshop/VULNERABILITIES.md — one section per
 * unique @intentional-vulnerability tag, with:
 *   - the vuln id
 *   - the OWASP category (from adjacent @teaches tag)
 *   - each code path that carries the annotation
 *   - each test path that carries a matching annotation
 *   - M14 additions: enforcement layer where the check is missing,
 *     attacker path (impact chain), student-visible impact, fix path.
 *
 * Regenerate any time: npm run docs:secureshop:vuln-map
 */

const fs = require('node:fs');
const path = require('node:path');

const REPO = path.resolve(__dirname, '..');
const OUT = path.join(REPO, 'docs/secureshop/VULNERABILITIES.md');

const SCAN_DIRS = [
  path.join(REPO, 'agent-host'),
  path.join(REPO, 'server/services/secureshop'),
  path.join(REPO, 'server/routes/secureshop'),
  path.join(REPO, 'client/src/pages/secureshop'),
  path.join(REPO, 'db/initialize-db/seeds'),
  path.join(REPO, 'sidecars/sandbox-runner/owned-system'),
];
const TEST_DIR = path.join(REPO, 'tests/secureshop');

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'build') continue;
      walk(p, out);
    } else if (entry.isFile() && /\.(js|jsx|ts|tsx)$/.test(entry.name)) {
      out.push(p);
    }
  }
  return out;
}

function relTo(p) { return path.relative(REPO, p); }

// Vuln ids are hyphenated slugs (e.g. `llm06-excessive-agency`, `sqli-union`,
// `xss-reflected-search`). Real annotations always appear at the start of a
// JSDoc line as ` * @intentional-vulnerability <slug>` OR at the start of a
// single-line comment as `// @intentional-vulnerability <slug>`. Inline
// references inside prose comments (`See @intentional-vulnerability above.`)
// used to trip the regex and produce false ids like `above`, `below`,
// `comment`, `header`, `in`. Two guards defeat that:
//   1. Require a hyphen inside the id (every real id has one; noise words
//      never do).
//   2. Require the annotation to start the comment body (whitespace + optional
//      `*` or `//`, then the tag). Prose sentences never match this shape.
const TAG_RE = /^\s*(?:\/\/|\*)\s*@intentional-vulnerability\s+([a-z0-9]+(?:-[a-z0-9]+)+)\s*$/i;

function extractTags(content) {
  const lines = content.split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(TAG_RE);
    if (!m) continue;
    let teaches = null;
    for (let j = i; j < Math.min(i + 4, lines.length); j++) {
      const t = lines[j].match(/@teaches\s+([\w\-:]+)/);
      if (t) { teaches = t[1]; break; }
    }
    out.push({ id: m[1], teaches });
  }
  return out;
}

/**
 * M14 — per-vuln impact-chain annotations. Every entry in the vuln coverage
 * script gets one of these blocks. Kept in code (not a separate JSON) so it
 * lives next to the generator that emits it — one thing to edit when a new
 * vuln lands. Fields:
 *
 *   layer      — where the missing check lives ('A' REST middleware,
 *                'B' supervisor ACL, 'C' agent-host tool, or 'data' when
 *                it's a data-sink vuln with no auth boundary to check).
 *   path       — the attacker's route from initial access to impact.
 *   impact     — what they gain.
 *   fix        — how the check(s) would close the chain (defense-in-depth).
 */
const IMPACT_CHAINS = {
  // ---- Authentication / access-control ----
  'auth-bypass-jwt-none': {
    layer: 'A',
    path: 'unauthenticated attacker → forges JWT with alg=none header → /admin/whoami decoder accepts it → trusted as admin identity',
    impact: 'auth bypass; attacker becomes admin without knowing JWT_SECRET',
    fix: 'jwt.verify with algorithms:["HS256"] (never accept "none")',
  },
  'broken-access-inventory': {
    layer: 'A',
    path: 'authenticated customer → /api/secureshop/merchant/inventory/set (or agent chain to inventory.set_stock) → no ownership check → any product can be reset',
    impact: 'horizontal priv-esc: customer/merchant can edit another merchant\'s stock',
    fix: 'Layer A: retailer_id check on merchant routes; Layer C: enforceRole + owner check inside set_stock',
  },
  // ---- Injection / RCE / traversal ----
  'command-injection-image-optimize': {
    layer: 'C',
    path: 'merchant supervisor → listing.optimize_images(product_id) → shell string concat of file path → attacker-supplied product name flows into ImageMagick argv',
    impact: 'RCE as agent-host process',
    fix: 'never shell-out to ImageMagick argv; use execFile with argv array + basename() the path',
  },
  'command-injection-restart': {
    layer: 'C',
    path: 'admin chat → system.restart_service(name) → systemctl name shelled → attacker injects `;`',
    impact: 'shell command injection when SS_SYSTEM_ALLOW_EXEC=true; default guarded mode and current proof construct the command without executing it',
    fix: 'allow-list of service names; execFile',
  },
  'rce-run-diagnostic': {
    layer: 'C',
    path: 'admin chat → system.run_diagnostic(cmd_template, args) → raw command concatenation; shell execution requires SS_SYSTEM_ALLOW_EXEC=true',
    impact: 'arbitrary command execution when enabled; current guarded proof verifies command construction, not an executed process effect',
    fix: 'delete the tool; if truly needed, use a fixed set of diagnostic types with parametric exec',
  },
  'email-header-injection': {
    layer: 'C',
    path: 'merchant sends email → headers object merged verbatim into raw MIME → attacker-controlled subject with `\\r\\n` injects Bcc:',
    impact: 'silent BCC exfiltration to attacker',
    fix: 'reject newlines in header values; use a proper MIME builder',
  },
  'html-injection': {
    layer: 'data',
    path: 'merchant email body_markdown → renderer outputs raw HTML → Inbox dangerouslySetInnerHTML',
    impact: 'stored XSS in merchant Inbox tab',
    fix: 'sanitize HTML on render (DOMPurify) OR escape before persistence',
  },
  // ---- IDOR family ----
  'idor-cart': {
    layer: 'A',
    path: 'customer with cart_item_id X → POST /cart/remove with someone else\'s id → no owner check',
    impact: 'horizontal priv-esc; delete another customer\'s cart lines',
    fix: 'add user_id = req.user.id predicate in cart.remove',
  },
  'idor-inbox': {
    layer: 'C',
    path: 'authenticated caller → email.read_inbox(user_id=<victim>) → tool trusts arg, no ownership check',
    impact: 'horizontal PII leak: read any inbox',
    fix: 'derive user_id from caller.id inside read_inbox instead of trusting the arg',
  },
  'idor-order-status': {
    layer: 'A',
    path: 'customer with order_id X → GET /support.order_status?order_id=<victim> → no owner check',
    impact: 'horizontal read of any order',
    fix: 'JOIN order.customer_id = req.user.id in the SELECT',
  },
  'insecure-deser-listing-import': {
    layer: 'C',
    path: 'merchant import_bulk with attacker JSON → __proto__.x=y prototype pollution',
    impact: 'prototype pollution visible on new objects; downstream code execution is not demonstrated',
    fix: 'JSON.parse with reviver that rejects __proto__; freeze Object.prototype',
  },
  // ---- LLM chain ----
  'llm01-direct-pi': {
    layer: 'B',
    path: 'customer message reaches LLM without an input filter → jailbreak / instruction override lands',
    impact: 'attacker-controlled tool calls originating from customer supervisor',
    fix: 'input safety filter before LLM call (moderation / rule-based scan) — not implemented on purpose',
  },
  'llm01-indirect-pi-audit-log': {
    layer: 'B',
    path: 'audit.summarize_anomalies reads audit_events verbatim → prior injected reason/target flows into system prompt → LLM follows the injected instructions',
    impact: 'indirect PI via log content',
    fix: 'sanitize / delimiter-fence audit content before appending to prompt',
  },
  'llm01-indirect-pi-product': {
    layer: 'B',
    path: 'summarizer.summarize_product reads products.description verbatim → injected [SYSTEM: ...] in description flows into next LLM call',
    impact: 'indirect PI via product description',
    fix: 'delimit/escape untrusted content; use tool_result quoting conventions',
  },
  'llm01-indirect-pi-review': {
    layer: 'B',
    path: 'summarizer.summarize_reviews / review-moderator concatenates review body verbatim → LLM obeys injected reviewer instructions',
    impact: 'indirect PI; poisoned classification',
    fix: 'quote review content; treat as data not instructions',
  },
  'llm01-pi-email': {
    layer: 'B',
    path: 'email.summarize_thread reads email bodies verbatim → attacker email injects instructions → merchant auto_reply follows them',
    impact: 'attacker directs auto-reply / actions via inbound email',
    fix: 'render user email into a data-only frame; do not inline into system prompt',
  },
  'llm01-pi-file-upload': {
    layer: 'B',
    path: 'summarizer.summarize_file reads uploaded PDF/MD verbatim → embedded instructions inject into supervisor',
    impact: 'PI via file upload',
    fix: 'strip metadata; only include the file body as data-only tool_result',
  },
  'llm02-analytics-pii-leak': {
    layer: 'C',
    path: 'merchant analytics.nl_query emits SELECT * FROM shop_users → returns email/api_key/pii_json in result',
    impact: 'PII leak into LLM turn (LLM02) + into UI',
    fix: 'per-column allow-list in analytics; deny SELECT on sensitive columns',
  },
  'llm02-sensitive-info': {
    layer: 'C',
    path: 'admin chat → user-management.lookup returns full row incl. bcrypt hash, api_key, session_token, pii_json',
    impact: 'credential exfiltration into any authenticated admin session',
    fix: 'per-column allow-list; never return password/api_key/session_token',
  },
  'llm02-user-lookup': {
    layer: 'C',
    path: 'admin (or jailbroken customer via LLM06) → user-management.lookup → full row exfil',
    impact: 'credential + PII exfil',
    fix: 'per-column allow-list; also close LLM06 at Layer B',
  },
  'llm03-supply-chain': {
    layer: 'C',
    path: 'admin registers untrusted MCP server → its tools land in supervisor prompt → poisoned descriptions run',
    impact: 'attacker MCP server executes as supervisor',
    fix: 'signed manifest + allow-list of registrar hosts; sandbox external tool descriptions',
  },
  'llm04-policy-poisoning': {
    layer: 'B',
    path: 'admin (or SSTI via policies/render) writes policy content with [SYSTEM: ...] → policyLoader reads and appends to system prompt',
    impact: 'persistent PI baked into every supervisor turn',
    fix: 'sanitize / structured-only policy schema; refuse markdown_source that starts new instructions',
  },
  'llm04-rag-competitor-poisoning': {
    layer: 'B',
    path: 'merchant pricing-strategy.suggest_price → RAG competitor doc corpus injects → LLM emits poisoned price',
    impact: 'attacker-controlled price recommendations',
    fix: 'per-doc trust score; quarantine untrusted corpus',
  },
  'llm04-rag-poisoning': {
    layer: 'B',
    path: 'uploads.upload_product_manual → text ingested into vector store → RAG retrieval surfaces poisoned chunk → supervisor obeys',
    impact: 'stored PI via product manual',
    fix: 'quarantine untrusted uploads; sanitize retrievals',
  },
  'llm05-improper-output': {
    layer: 'data',
    path: 'summarizer.explain_return_policy → LLM returns HTML → frontend renders with dangerouslySetInnerHTML',
    impact: 'DOM XSS via LLM output',
    fix: 'sanitize LLM HTML output on render OR require JSON-only response',
  },
  'llm05-listing-xss': {
    layer: 'data',
    path: 'Supported owned flow: Write with AI → secureshopBoundListings LangGraph model rewrite → immutable rewrite/save → ProductDescription HTML render (Listings preview is escaped). Legacy listing.create/_llmRewrite remains separate and can pass supplied markup through without a model call.',
    impact: 'stored XSS in product listing',
    fix: 'HTML-sanitize LLM output before persistence',
  },
  'llm06-excessive-agency': {
    layer: 'B (with Layer C reinforcement gap)',
    path: 'customer session → jailbreak customer supervisor → LLM emits tool_use user-management.set_role → Layer B records policy_violation=denied-by-acl but dispatches (enforce_tool_acl=false) → Layer C skips its own check → priv-esc lands',
    impact: 'vertical priv-esc; customer becomes admin',
    fix: 'defense-in-depth: (1) admin toggles SS_ENFORCE_TOOL_ACL=true at Layer B via Access Control page, (2) user-management server adds enforceRole([\'admin\']) at Layer C',
  },
  'llm07-system-prompt-leak': {
    layer: 'B',
    path: 'user message asks LLM to repeat system prompt → no output filter → system prompt (with concatenated policies) echoed',
    impact: 'system prompt + poisoned policy content leaks',
    fix: 'output filter that scrubs system-prompt-shaped strings',
  },
  'llm08-embedding-inversion': {
    layer: 'C',
    path: 'a sensitive synthetic manual is indexed → a topic-only nearest-neighbor query retrieves its stored plaintext without a document authorization check',
    impact: 'sensitive RAG document disclosure; legacy ID retained, embedding inversion is not demonstrated',
    fix: 'enforce per-document retrieval authorization and exclude secrets from shared corpora; hiding vectors alone does not prevent plaintext retrieval',
  },
  'llm08-embedding-poisoning': {
    layer: 'C',
    path: 'malicious upload with adversarial text → embedded near legitimate content → retrievals surface poisoned chunks',
    impact: 'RAG poisoning',
    fix: 'per-source trust score; anomaly detection on new embeddings',
  },
  'llm09-misinformation': {
    layer: 'B',
    path: 'price-advisor.find_deals fabricates competitor prices with Math.random and marks the result grounded=false → a supervisor may repeat the unverified tool output as authoritative',
    impact: 'customer misled into fake deals',
    fix: 'attach a real grounding source and provenance to competitor prices; require the supervisor to qualify or reject unverified tool output',
  },
  'llm09-pricing-hallucination': {
    layer: 'B',
    path: 'merchant pricing-strategy.run_pricing_experiment fabricates elasticity, lift, revenue and confidence values with Math.random and marks projections grounded=false → a supervisor may cite the unverified projections as authoritative',
    impact: 'merchant sets wrong price',
    fix: 'derive projections from real historical/competitor data with provenance; require the supervisor to qualify or reject unverified projections',
  },
  'llm10-analytics-unbounded': {
    layer: 'C',
    path: 'merchant analytics.nl_query emits SELECT without LIMIT → 10M-row response into next LLM call',
    impact: 'DoS + cost blow-up + token budget exhaustion',
    fix: 'enforce LIMIT at query build time; per-tool byte-size cap',
  },
  'llm10-audit-unbounded': {
    layer: 'C',
    path: 'admin audit.summarize_anomalies(limit=10000) → megabyte tool_result → next LLM call OOMs',
    impact: 'DoS via audit summarizer',
    fix: 'clamp limit; per-tool byte-size cap in supervisor',
  },
  'llm10-unbounded': {
    layer: 'B',
    path: 'runaway tool loop → MAX_STEPS caps outer iterations but per-hop byte size unlimited',
    impact: 'DoS via tool_result blow-up',
    fix: 'per-hop byte cap on appendToolResult',
  },
  // ---- MCP ----
  'mcp01-tool-poisoning': {
    layer: 'B',
    path: 'admin registers external MCP → its tool descriptions land verbatim in supervisor prompt → attacker instructs the LLM through description text',
    impact: 'PI via poisoned tool description',
    fix: 'quote/frame tool descriptions as data-only; signature check on registered servers',
  },
  'mcp02-rug-pull': {
    layer: 'B',
    path: 'admin registers a trusted server → attacker rotates its schema post-registration → new tools with malicious behavior appear on next refresh',
    impact: 'time-of-check vs time-of-use bypass',
    fix: 'schema-hash pinning; alert on schema change',
  },
  'mcp06-credential-leak': {
    layer: 'C',
    path: 'admin system.read_config → naive `..` strip lets caller read /etc/config with credentials',
    impact: 'credential exfil via config file read',
    fix: 'canonicalize path; refuse absolute; refuse outside allow-listed dir',
  },
  'mcp08-ssrf': {
    layer: 'C',
    path: 'admin mcp-registry.register(url=http://internal-only) → server-side fetch to internal network → response returned to caller',
    impact: 'SSRF to internal services',
    fix: 'block private-IP / metadata addresses',
  },
  'mcp09-impersonation': {
    layer: 'C',
    path: 'admin registers name=trusted-mcp with attacker URL → overwrites the trusted-name entry → supervisor picks up attacker\'s tools',
    impact: 'server impersonation',
    fix: 'immutable name registration; require signature match to overwrite',
  },
  'mcp-05-pi-via-tool-output': {
    layer: 'B',
    path: 'price-advisor.compare_competitor → attacker-controlled competitor HTML flows back into supervisor tool_result → LLM obeys',
    impact: 'PI via external tool output',
    fix: 'frame/quote tool output as data; sanitize HTML',
  },
  // ---- Path / traversal / upload ----
  'path-traversal': {
    layer: 'C',
    path: 'summarizer.summarize_file(path=../../../etc/passwd) → naive resolve → arbitrary file read',
    impact: 'arbitrary file read',
    fix: 'restrict to /uploads/; canonicalize + prefix-check',
  },
  'path-traversal-read-config': {
    layer: 'C',
    path: 'admin system.read_config with `....//server/platform_secrets.json` → single-pass `../` removal leaves `../server/platform_secrets.json` → resolves to the server secrets fixture',
    impact: 'read arbitrary file',
    fix: 'canonicalize + prefix-check; refuse absolute paths',
  },
  'path-traversal-upload': {
    layer: 'C',
    path: 'uploads with filename=../../../etc/nginx.conf → filename trusted → server writes outside upload dir',
    impact: 'file overwrite / path escape',
    fix: 'generate server-side filename; ignore client filename',
  },
  // ---- SQLi ----
  'sqli-blind-boolean': {
    layer: 'C',
    path: 'customer cart.apply_coupon(code) → string-concat WHERE → boolean-based blind extraction',
    impact: 'data exfil via blind SQLi',
    fix: 'parameterized query',
  },
  'sqli-coupon': {
    layer: 'A',
    path: 'customer POST /cart/apply-coupon with code=` OR 1=1--` → string-concat WHERE',
    impact: 'coupon lookup returns first active row',
    fix: 'parameterized query',
  },
  'sqli-error-based': {
    layer: 'C',
    path: 'customer support.order_status with error-inducing SQL → messages leak',
    impact: 'schema disclosure via error messages',
    fix: 'parameterized query + generic error message',
  },
  'sqli-nl-generated': {
    layer: 'C',
    path: 'merchant analytics.nl_query → LLM emits attacker-influenced SQL → executed unparameterized',
    impact: 'SQLi via NL-to-SQL translation',
    fix: 'AST-level allow-list; execute in a read-only sandbox',
  },
  'sqli-time-based': {
    layer: 'C',
    path: 'admin audit.search_by_user → raw username interpolation into WHERE; current fixture proves UNION injection',
    impact: 'SQL injection; legacy timing ID retained, timing-side-channel extraction requires separate native qualification',
    fix: 'parameterized query',
  },
  'sqli-union': {
    layer: 'C',
    path: 'customer product-search.search → UNION SELECT payload extracts columns',
    impact: 'data exfil across tables via UNION',
    fix: 'parameterized query',
  },
  // ---- SSRF ----
  'ssrf-competitor': {
    layer: 'C',
    path: 'merchant price-advisor.compare_competitor(url) → server-side fetch to attacker-controlled host',
    impact: 'SSRF + internal probing',
    fix: 'URL allow-list; block private IPs',
  },
  'ssrf-email-inline-image': {
    layer: 'C',
    path: 'email.summarize_thread inlines <img src=...> → server-side fetch of arbitrary URL',
    impact: 'SSRF via email content',
    fix: 'do not fetch inline images server-side',
  },
  'ssrf-listing-import': {
    layer: 'C',
    path: 'merchant listing.import_bulk(json_url, xml_url) → server fetches arbitrary URL',
    impact: 'SSRF',
    fix: 'URL allow-list; block private IPs',
  },
  'ssrf-return-policy': {
    layer: 'C',
    path: 'summarizer.explain_return_policy(policy_url) → server fetches arbitrary URL',
    impact: 'SSRF',
    fix: 'URL allow-list',
  },
  // ---- SSTI ----
  'ssti-listing-template': {
    layer: 'C',
    path: 'merchant listing.create with template_source → unsafe Nunjucks env → RCE via {{constructor.constructor(...)}} gadgets',
    impact: 'RCE',
    fix: 'sandbox Nunjucks (no globals, no proto access) or drop custom templates',
  },
  'ssti-policy-template': {
    layer: 'C',
    path: 'admin policy.update_policy → unsafe Nunjucks env → same gadget',
    impact: 'RCE',
    fix: 'sandbox Nunjucks or drop templating',
  },
  // ---- Uploads ----
  'file-upload-extension-bypass': {
    layer: 'C',
    path: 'uploads accepts .php, .html and .js filenames without an extension allowlist and preserves supplied bytes',
    impact: 'unrestricted file storage; execution requires a separately demonstrated serving/interpreter path',
    fix: 'validate allowed formats using full decoding, use generated storage names, and serve untrusted files from an isolated non-executable origin',
  },
  'file-upload-polyglot-rce': {
    layer: 'C',
    path: 'the separate legacy preview handler fully decodes an uploaded GIF, then dispatches the same original bytes to Node inside the owned sandbox in vulnerable mode; generic file serving does not execute code',
    impact: 'intended server-side execution teaching path; actual Linux execution, model/Judge and browser qualification remain pending, so crafted-file acceptance alone is not RCE proof',
    fix: 'fully decode and re-encode allowed media; isolate untrusted serving and disable executable handlers',
  },
  'file-upload-svg-xss': {
    layer: 'C',
    path: 'upload_avatar with SVG containing <script> → rendered inline',
    impact: 'stored XSS',
    fix: 'reject SVG or strip scripts before serve',
  },
  // ---- XSS ----
  'xss-reflected-search': {
    layer: 'data',
    path: 'customer search query echoed into echo_html → HopDetailSheet renders with dangerouslySetInnerHTML',
    impact: 'reflected XSS in agent lane',
    fix: 'escape echoed query; render as text',
  },
  'xss-stored-email': {
    layer: 'data',
    path: 'email.send body_markdown → stored HTML → Inbox renders raw',
    impact: 'stored XSS in Inbox',
    fix: 'sanitize HTML on render',
  },
  'xss-stored-listing': {
    layer: 'data',
    path: 'merchant listing.create → description_html stored → catalog / merchant Listings render raw',
    impact: 'stored XSS in catalog',
    fix: 'sanitize HTML on ingest',
  },
  'xss-stored-review': {
    layer: 'data',
    path: 'customer review body → stored HTML → product page renders raw',
    impact: 'stored XSS in reviews',
    fix: 'sanitize HTML on render',
  },
  'xss-stored-ticket': {
    layer: 'data',
    path: 'customer support.open_ticket body → stored HTML → admin renders raw',
    impact: 'stored XSS in admin ticket view',
    fix: 'sanitize HTML on render',
  },
  // ---- XXE ----
  'xxe-import-bulk': {
    layer: 'C',
    path: 'merchant listing.import_bulk(xml_url) → sax parser resolves DOCTYPE SYSTEM entities → file:// disclosure',
    impact: 'arbitrary local file read via XXE',
    fix: 'disable external-entity resolution',
  },
  'xxe-import-manifest': {
    layer: 'C',
    path: 'admin mcp-registry.import_manifest(xml_url) → sax parser resolves DOCTYPE SYSTEM entities',
    impact: 'arbitrary local file read via XXE',
    fix: 'disable external-entity resolution',
  },
};

function main() {
  const codeFiles = SCAN_DIRS.flatMap(d => walk(d));
  const testFiles = walk(TEST_DIR);

  const idInfo = new Map(); // id -> { teaches:Set, codePaths:Set, testPaths:Set }

  function ensure(id) {
    if (!idInfo.has(id)) {
      idInfo.set(id, { teaches: new Set(), codePaths: new Set(), testPaths: new Set() });
    }
    return idInfo.get(id);
  }

  for (const f of codeFiles) {
    let c;
    try { c = fs.readFileSync(f, 'utf8'); } catch { continue; }
    for (const tag of extractTags(c)) {
      const e = ensure(tag.id);
      if (tag.teaches) e.teaches.add(tag.teaches);
      e.codePaths.add(relTo(f));
    }
  }
  for (const f of testFiles) {
    let c;
    try { c = fs.readFileSync(f, 'utf8'); } catch { continue; }
    for (const tag of extractTags(c)) {
      const e = ensure(tag.id);
      if (tag.teaches) e.teaches.add(tag.teaches);
      e.testPaths.add(relTo(f));
    }
  }

  const ids = [...idInfo.keys()].sort();

  // Table of contents summary — every vuln, its layer, one-line impact.
  const tocRows = [];
  for (const id of ids) {
    const info = idInfo.get(id);
    const teaches = [...info.teaches].sort().join(', ') || '—';
    const chain = IMPACT_CHAINS[id] || { layer: '?', path: '(not yet annotated)', impact: '?', fix: '?' };
    tocRows.push(`| \`${id}\` | ${teaches} | ${chain.layer} | ${chain.impact} |`);
  }

  // Per-vuln detail sections with Layer / Path / Impact / Fix
  const details = [];
  for (const id of ids) {
    const info = idInfo.get(id);
    const teaches = [...info.teaches].sort().join(', ') || '—';
    const codeLinks = [...info.codePaths].sort().map(p => `\`${p}\``).join('<br>') || '—';
    const testLinks = [...info.testPaths].sort().map(p => `\`${p}\``).join('<br>') || '—';
    const chain = IMPACT_CHAINS[id] || { layer: '?', path: '(not yet annotated in generate-vuln-map.js)', impact: '?', fix: '?' };
    details.push([
      `### \`${id}\``,
      '',
      `- **OWASP:** ${teaches}`,
      `- **Enforcement layer where check is missing:** ${chain.layer}`,
      `- **Attacker path:** ${chain.path}`,
      `- **Impact:** ${chain.impact}`,
      `- **Fix path (defense-in-depth):** ${chain.fix}`,
      `- **Code:** ${codeLinks}`,
      `- **Tests:** ${testLinks}`,
      '',
    ].join('\n'));
  }

  const realityGaps = [
    '## Enforcement layers',
    '',
    'Every intentional vulnerability above names a specific enforcement layer',
    'where the check is missing. There are four:',
    '',
    '- **Layer A** — REST middleware (`requireRole()` in',
    '  `server/routes/secureshop/_ssAuthMiddleware.js`).',
    '- **Layer B** — supervisor ACL (`server/services/secureshop/toolAcl.js`).',
    '  Consults `tool_permissions`; records `agent_trace.policy_violation`.',
    '  When `system_config.enforce_tool_acl=\'true\'`, refuses out-of-role',
    '  dispatch. Default `false` = LLM06 excessive-agency sink is open.',
    '- **Layer C** — agent-host tool endpoint. Each `server.js` may call',
    '  `enforceRole()` after `extractCaller()`. `user-management.set_role`',
    '  deliberately does not — that is the LLM06 sink at Layer C.',
    '- **data** — vulnerability is a data-sink (stored HTML, XSS via',
    '  `dangerouslySetInnerHTML`). No auth layer will close it; the fix is',
    '  sanitization at render or ingest.',
    '',
  ];

  const md = [
    '# SecureShop v2 — Vulnerability Map',
    '',
    '> **AUTO-GENERATED. Do not edit by hand.**',
    '> Run `npm run docs:secureshop:vuln-map` to regenerate.',
    '',
    'Every entry below is an **intentional** teaching vulnerability. See ',
    '`docs/secureshop/README.md` for the do-not-fix policy.',
    '',
    `Generated: ${new Date().toISOString()}   ·   ${ids.length} unique vuln ids`,
    '',
    '## Summary table',
    '',
    '| ID | OWASP | Layer | Impact |',
    '|----|-------|-------|--------|',
    ...tocRows,
    '',
    '## Per-vulnerability detail',
    '',
    ...details,
    ...realityGaps,
    '## Notes',
    '',
    '- **Do not "fix" any of these.** They are deliberate teaching sinks.',
    '- If a test fails, first check whether the intentional vulnerability was',
    '  removed — the failure is telling you the teaching surface has drifted.',
    '- New vulns require both a code annotation AND a matching test annotation,',
    '  then a rerun of this generator plus `npm run verify:secureshop:vuln-coverage`.',
    '- To add a new vuln with M14 layer annotations, edit `IMPACT_CHAINS` in',
    '  `scripts/generate-vuln-map.js` — one row per vuln id.',
    '',
  ].join('\n');

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, md);
  // eslint-disable-next-line no-console
  console.log(`Wrote ${OUT}  (${ids.length} unique vuln ids)`);
}

if (require.main === module) main();
module.exports = { main, IMPACT_CHAINS, SCAN_DIRS, TEST_DIR, TAG_RE, walk, extractTags };
