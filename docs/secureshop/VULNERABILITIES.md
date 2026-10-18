# SecureShop v2 — Vulnerability Map

> **AUTO-GENERATED. Do not edit by hand.**
> Run `npm run docs:secureshop:vuln-map` to regenerate.

Every entry below is an **intentional** teaching vulnerability. See 
`docs/secureshop/README.md` for the do-not-fix policy.

Generated: 2026-10-16T19:42:48.127Z   ·   66 unique vuln ids

## Summary table

| ID | OWASP | Layer | Impact |
|----|-------|-------|--------|
| `auth-bypass-jwt-none` | OWASP-Web:A07 | A | auth bypass; attacker becomes admin without knowing JWT_SECRET |
| `broken-access-inventory` | OWASP-Web:A01 | A | horizontal priv-esc: customer/merchant can edit another merchant's stock |
| `command-injection-image-optimize` | OWASP-Web:A03 | C | RCE as agent-host process |
| `command-injection-restart` | OWASP-Web:A03 | C | shell command injection when SS_SYSTEM_ALLOW_EXEC=true; default guarded mode and current proof construct the command without executing it |
| `email-header-injection` | OWASP-Web:A03 | C | silent BCC exfiltration to attacker |
| `file-upload-extension-bypass` | OWASP-Web:A03 | C | unrestricted file storage; execution requires a separately demonstrated serving/interpreter path |
| `file-upload-polyglot-rce` | OWASP-Web:A03 | C | intended server-side execution teaching path; actual Linux execution, model/Judge and browser qualification remain pending, so crafted-file acceptance alone is not RCE proof |
| `file-upload-svg-xss` | OWASP-Web:A03 | C | stored XSS |
| `html-injection` | OWASP-Web:A03 | data | stored XSS in merchant Inbox tab |
| `idor-cart` | OWASP-Web:A01 | A | horizontal priv-esc; delete another customer's cart lines |
| `idor-inbox` | OWASP-Web:A01 | C | horizontal PII leak: read any inbox |
| `idor-order-status` | OWASP-Web:A01 | A | horizontal read of any order |
| `insecure-deser-listing-import` | OWASP-Web:A08 | C | prototype pollution visible on new objects; downstream code execution is not demonstrated |
| `llm01-direct-pi` | OWASP-LLM:LLM01 | B | attacker-controlled tool calls originating from customer supervisor |
| `llm01-indirect-pi-audit-log` | OWASP-LLM:LLM01 | B | indirect PI via log content |
| `llm01-indirect-pi-product` | OWASP-LLM:LLM01 | B | indirect PI via product description |
| `llm01-indirect-pi-review` | OWASP-LLM:LLM01 | B | indirect PI; poisoned classification |
| `llm01-pi-email` | OWASP-LLM:LLM01 | B | attacker directs auto-reply / actions via inbound email |
| `llm01-pi-file-upload` | OWASP-LLM:LLM01 | B | PI via file upload |
| `llm02-analytics-pii-leak` | OWASP-LLM:LLM02 | C | PII leak into LLM turn (LLM02) + into UI |
| `llm02-sensitive-info` | OWASP-LLM:LLM02 | C | credential exfiltration into any authenticated admin session |
| `llm02-user-lookup` | OWASP-LLM:LLM01, OWASP-LLM:LLM02 | C | credential + PII exfil |
| `llm03-supply-chain` | OWASP-LLM:LLM03 | C | attacker MCP server executes as supervisor |
| `llm04-policy-poisoning` | OWASP-LLM:LLM04 | B | persistent PI baked into every supervisor turn |
| `llm04-rag-competitor-poisoning` | OWASP-LLM:LLM04 | B | attacker-controlled price recommendations |
| `llm04-rag-poisoning` | OWASP-LLM:LLM04 | B | stored PI via product manual |
| `llm05-improper-output` | OWASP-LLM:LLM05, OWASP-Web:A03 | data | DOM XSS via LLM output |
| `llm05-listing-xss` | OWASP-LLM:LLM05 | data | stored XSS in product listing |
| `llm06-excessive-agency` | OWASP-LLM:LLM06 | B (with Layer C reinforcement gap) | vertical priv-esc; customer becomes admin |
| `llm07-system-prompt-leak` | OWASP-LLM:LLM07 | B | system prompt + poisoned policy content leaks |
| `llm08-embedding-inversion` | OWASP-LLM:LLM08 | C | sensitive RAG document disclosure; legacy ID retained, embedding inversion is not demonstrated |
| `llm08-embedding-poisoning` | OWASP-LLM:LLM08 | C | RAG poisoning |
| `llm09-misinformation` | OWASP-LLM:LLM09 | B | customer misled into fake deals |
| `llm09-pricing-hallucination` | OWASP-LLM:LLM09 | B | merchant sets wrong price |
| `llm10-analytics-unbounded` | OWASP-LLM:LLM10 | C | DoS + cost blow-up + token budget exhaustion |
| `llm10-audit-unbounded` | OWASP-LLM:LLM10 | C | DoS via audit summarizer |
| `llm10-unbounded` | OWASP-LLM:LLM10 | B | DoS via tool_result blow-up |
| `mcp-05-pi-via-tool-output` | OWASP-MCP:MCP-06 | B | PI via external tool output |
| `mcp01-tool-poisoning` | OWASP-MCP:MCP-03 | B | PI via poisoned tool description |
| `mcp02-rug-pull` | OWASP-MCP:MCP-03 | B | time-of-check vs time-of-use bypass |
| `mcp06-credential-leak` | OWASP-MCP:MCP-01 | C | credential exfil via config file read |
| `mcp08-ssrf` | — | C | SSRF to internal services |
| `mcp09-impersonation` | OWASP-MCP:MCP-07 | C | server impersonation |
| `path-traversal` | OWASP-Web:A01 | C | arbitrary file read |
| `path-traversal-read-config` | OWASP-Web:A01 | C | read arbitrary file |
| `path-traversal-upload` | OWASP-Web:A01 | C | file overwrite / path escape |
| `rce-run-diagnostic` | OWASP-Web:A03 | C | arbitrary command execution when enabled; current guarded proof verifies command construction, not an executed process effect |
| `sqli-blind-boolean` | OWASP-Web:A03 | C | data exfil via blind SQLi |
| `sqli-coupon` | OWASP-Web:A03 | A | coupon lookup returns first active row |
| `sqli-error-based` | OWASP-Web:A03 | C | schema disclosure via error messages |
| `sqli-nl-generated` | OWASP-Web:A03 | C | SQLi via NL-to-SQL translation |
| `sqli-time-based` | OWASP-Web:A03 | C | SQL injection; legacy timing ID retained, timing-side-channel extraction requires separate native qualification |
| `sqli-union` | OWASP-Web:A03 | C | data exfil across tables via UNION |
| `ssrf-competitor` | OWASP-Web:A10 | C | SSRF + internal probing |
| `ssrf-email-inline-image` | OWASP-Web:A10 | C | SSRF via email content |
| `ssrf-listing-import` | OWASP-Web:A10 | C | SSRF |
| `ssrf-return-policy` | OWASP-Web:A10 | C | SSRF |
| `ssti-listing-template` | OWASP-Web:A03 | C | RCE |
| `ssti-policy-template` | OWASP-Web:A03 | C | RCE |
| `xss-reflected-search` | OWASP-Web:A03 | data | reflected XSS in agent lane |
| `xss-stored-email` | OWASP-Web:A03 | data | stored XSS in Inbox |
| `xss-stored-listing` | OWASP-Web:A03 | data | stored XSS in catalog |
| `xss-stored-review` | OWASP-Web:A03 | data | stored XSS in reviews |
| `xss-stored-ticket` | OWASP-Web:A03 | data | stored XSS in admin ticket view |
| `xxe-import-bulk` | OWASP-Web:A05 | C | arbitrary local file read via XXE |
| `xxe-import-manifest` | OWASP-Web:A05 | C | arbitrary local file read via XXE |

## Per-vulnerability detail

### `auth-bypass-jwt-none`

- **OWASP:** OWASP-Web:A07
- **Enforcement layer where check is missing:** A
- **Attacker path:** unauthenticated attacker → forges JWT with alg=none header → /admin/whoami decoder accepts it → trusted as admin identity
- **Impact:** auth bypass; attacker becomes admin without knowing JWT_SECRET
- **Fix path (defense-in-depth):** jwt.verify with algorithms:["HS256"] (never accept "none")
- **Code:** `server/routes/secureshop/admin.js`<br>`server/routes/secureshop/postgres/admin.js`
- **Tests:** `tests/secureshop/vuln/web/auth-bypass-jwt-none.test.js`

### `broken-access-inventory`

- **OWASP:** OWASP-Web:A01
- **Enforcement layer where check is missing:** A
- **Attacker path:** authenticated customer → /api/secureshop/merchant/inventory/set (or agent chain to inventory.set_stock) → no ownership check → any product can be reset
- **Impact:** horizontal priv-esc: customer/merchant can edit another merchant's stock
- **Fix path (defense-in-depth):** Layer A: retailer_id check on merchant routes; Layer C: enforceRole + owner check inside set_stock
- **Code:** `agent-host/agents/inventory/tools/index.postgres.js`
- **Tests:** `tests/secureshop/vuln/web/broken-access-inventory.test.js`

### `command-injection-image-optimize`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** merchant supervisor → listing.optimize_images(product_id) → shell string concat of file path → attacker-supplied product name flows into ImageMagick argv
- **Impact:** RCE as agent-host process
- **Fix path (defense-in-depth):** never shell-out to ImageMagick argv; use execFile with argv array + basename() the path
- **Code:** `agent-host/agents/listing/tools/optimize_images.postgres.js`
- **Tests:** `tests/secureshop/vuln/web/command-injection-image-optimize.test.js`

### `command-injection-restart`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin chat → system.restart_service(name) → systemctl name shelled → attacker injects `;`
- **Impact:** shell command injection when SS_SYSTEM_ALLOW_EXEC=true; default guarded mode and current proof construct the command without executing it
- **Fix path (defense-in-depth):** allow-list of service names; execFile
- **Code:** `agent-host/agents/system/tools/index.js`
- **Tests:** `tests/secureshop/vuln/web/command-injection-restart.test.js`

### `email-header-injection`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** merchant sends email → headers object merged verbatim into raw MIME → attacker-controlled subject with `\r\n` injects Bcc:
- **Impact:** silent BCC exfiltration to attacker
- **Fix path (defense-in-depth):** reject newlines in header values; use a proper MIME builder
- **Code:** `agent-host/agents/email/tools/index.postgres.js`
- **Tests:** `tests/secureshop/vuln/web/email-header-injection.test.js`

### `file-upload-extension-bypass`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** uploads accepts .php, .html and .js filenames without an extension allowlist and preserves supplied bytes
- **Impact:** unrestricted file storage; execution requires a separately demonstrated serving/interpreter path
- **Fix path (defense-in-depth):** validate allowed formats using full decoding, use generated storage names, and serve untrusted files from an isolated non-executable origin
- **Code:** `agent-host/agents/uploads/tools/index.js`
- **Tests:** `tests/secureshop/vuln/web/file-upload-extension-bypass.test.js`

### `file-upload-polyglot-rce`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** the separate legacy preview handler fully decodes an uploaded GIF, then dispatches the same original bytes to Node inside the owned sandbox in vulnerable mode; generic file serving does not execute code
- **Impact:** intended server-side execution teaching path; actual Linux execution, model/Judge and browser qualification remain pending, so crafted-file acceptance alone is not RCE proof
- **Fix path (defense-in-depth):** fully decode and re-encode allowed media; isolate untrusted serving and disable executable handlers
- **Code:** `agent-host/agents/uploads/tools/index.js`<br>`sidecars/sandbox-runner/owned-system/upload-preview-worker.js`
- **Tests:** `tests/secureshop/vuln/web/file-upload-polyglot-rce.test.js`

### `file-upload-svg-xss`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** upload_avatar with SVG containing <script> → rendered inline
- **Impact:** stored XSS
- **Fix path (defense-in-depth):** reject SVG or strip scripts before serve
- **Code:** `agent-host/agents/uploads/tools/index.js`<br>`server/routes/secureshop/uploads.js`
- **Tests:** `tests/secureshop/vuln/web/file-upload-svg-xss.test.js`

### `html-injection`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** data
- **Attacker path:** merchant email body_markdown → renderer outputs raw HTML → Inbox dangerouslySetInnerHTML
- **Impact:** stored XSS in merchant Inbox tab
- **Fix path (defense-in-depth):** sanitize HTML on render (DOMPurify) OR escape before persistence
- **Code:** `agent-host/agents/email/tools/index.postgres.js`<br>`client/src/pages/secureshop/components/MailMessageBody.jsx`<br>`client/src/pages/secureshop/pages/merchant/Inbox.jsx`
- **Tests:** `tests/secureshop/vuln/web/html-injection.test.js`

### `idor-cart`

- **OWASP:** OWASP-Web:A01
- **Enforcement layer where check is missing:** A
- **Attacker path:** customer with cart_item_id X → POST /cart/remove with someone else's id → no owner check
- **Impact:** horizontal priv-esc; delete another customer's cart lines
- **Fix path (defense-in-depth):** add user_id = req.user.id predicate in cart.remove
- **Code:** `agent-host/agents/cart/tools/index.postgres.js`
- **Tests:** `tests/secureshop/vuln/web/idor-cart.test.js`

### `idor-inbox`

- **OWASP:** OWASP-Web:A01
- **Enforcement layer where check is missing:** C
- **Attacker path:** authenticated caller → email.read_inbox(user_id=<victim>) → tool trusts arg, no ownership check
- **Impact:** horizontal PII leak: read any inbox
- **Fix path (defense-in-depth):** derive user_id from caller.id inside read_inbox instead of trusting the arg
- **Code:** `agent-host/agents/email/tools/index.postgres.js`<br>`client/src/pages/secureshop/pages/merchant/Inbox.jsx`
- **Tests:** `tests/secureshop/vuln/web/idor-inbox.test.js`

### `idor-order-status`

- **OWASP:** OWASP-Web:A01
- **Enforcement layer where check is missing:** A
- **Attacker path:** customer with order_id X → GET /support.order_status?order_id=<victim> → no owner check
- **Impact:** horizontal read of any order
- **Fix path (defense-in-depth):** JOIN order.customer_id = req.user.id in the SELECT
- **Code:** `agent-host/agents/support/tools/index.postgres.js`
- **Tests:** `tests/secureshop/vuln/web/idor-order-status.test.js`

### `insecure-deser-listing-import`

- **OWASP:** OWASP-Web:A08
- **Enforcement layer where check is missing:** C
- **Attacker path:** merchant import_bulk with attacker JSON → __proto__.x=y prototype pollution
- **Impact:** prototype pollution visible on new objects; downstream code execution is not demonstrated
- **Fix path (defense-in-depth):** JSON.parse with reviver that rejects __proto__; freeze Object.prototype
- **Code:** `agent-host/agents/listing/tools/import_bulk.postgres.js`
- **Tests:** `tests/secureshop/vuln/web/insecure-deser-listing-import.test.js`

### `llm01-direct-pi`

- **OWASP:** OWASP-LLM:LLM01
- **Enforcement layer where check is missing:** B
- **Attacker path:** customer message reaches LLM without an input filter → jailbreak / instruction override lands
- **Impact:** attacker-controlled tool calls originating from customer supervisor
- **Fix path (defense-in-depth):** input safety filter before LLM call (moderation / rule-based scan) — not implemented on purpose
- **Code:** `server/services/secureshop/supervisors/customerSupervisor.js`
- **Tests:** `tests/secureshop/vuln/llm/llm01-direct-pi.test.js`

### `llm01-indirect-pi-audit-log`

- **OWASP:** OWASP-LLM:LLM01
- **Enforcement layer where check is missing:** B
- **Attacker path:** audit.summarize_anomalies reads audit_events verbatim → prior injected reason/target flows into system prompt → LLM follows the injected instructions
- **Impact:** indirect PI via log content
- **Fix path (defense-in-depth):** sanitize / delimiter-fence audit content before appending to prompt
- **Code:** `agent-host/agents/audit/tools/index.js`<br>`agent-host/agents/user-management/tools/index.js`
- **Tests:** `tests/secureshop/vuln/chains/audit-log-injection.test.js`<br>`tests/secureshop/vuln/llm/llm01-indirect-pi-audit-log.test.js`

### `llm01-indirect-pi-product`

- **OWASP:** OWASP-LLM:LLM01
- **Enforcement layer where check is missing:** B
- **Attacker path:** summarizer.summarize_product reads products.description verbatim → injected [SYSTEM: ...] in description flows into next LLM call
- **Impact:** indirect PI via product description
- **Fix path (defense-in-depth):** delimit/escape untrusted content; use tool_result quoting conventions
- **Code:** `agent-host/agents/summarizer/tools/summarize_product.postgres.js`
- **Tests:** `tests/secureshop/vuln/llm/llm01-indirect-pi-product.test.js`

### `llm01-indirect-pi-review`

- **OWASP:** OWASP-LLM:LLM01
- **Enforcement layer where check is missing:** B
- **Attacker path:** summarizer.summarize_reviews / review-moderator concatenates review body verbatim → LLM obeys injected reviewer instructions
- **Impact:** indirect PI; poisoned classification
- **Fix path (defense-in-depth):** quote review content; treat as data not instructions
- **Code:** `agent-host/agents/review-moderator/tools/index.postgres.js`<br>`agent-host/agents/summarizer/tools/summarize_reviews.postgres.js`<br>`client/src/pages/secureshop/pages/merchant/Reviews.jsx`
- **Tests:** `tests/secureshop/vuln/llm/llm01-indirect-pi-review.test.js`

### `llm01-pi-email`

- **OWASP:** OWASP-LLM:LLM01
- **Enforcement layer where check is missing:** B
- **Attacker path:** email.summarize_thread reads email bodies verbatim → attacker email injects instructions → merchant auto_reply follows them
- **Impact:** attacker directs auto-reply / actions via inbound email
- **Fix path (defense-in-depth):** render user email into a data-only frame; do not inline into system prompt
- **Code:** `agent-host/agents/email/tools/index.postgres.js`<br>`client/src/pages/secureshop/pages/merchant/Inbox.jsx`
- **Tests:** `tests/secureshop/vuln/llm/llm01-pi-email.test.js`

### `llm01-pi-file-upload`

- **OWASP:** OWASP-LLM:LLM01
- **Enforcement layer where check is missing:** B
- **Attacker path:** summarizer.summarize_file reads uploaded PDF/MD verbatim → embedded instructions inject into supervisor
- **Impact:** PI via file upload
- **Fix path (defense-in-depth):** strip metadata; only include the file body as data-only tool_result
- **Code:** `agent-host/agents/summarizer/tools/summarize_file.js`<br>`agent-host/agents/uploads/tools/index.js`
- **Tests:** `tests/secureshop/vuln/llm/llm01-pi-file-upload.test.js`

### `llm02-analytics-pii-leak`

- **OWASP:** OWASP-LLM:LLM02
- **Enforcement layer where check is missing:** C
- **Attacker path:** merchant analytics.nl_query emits SELECT * FROM shop_users → returns email/api_key/pii_json in result
- **Impact:** PII leak into LLM turn (LLM02) + into UI
- **Fix path (defense-in-depth):** per-column allow-list in analytics; deny SELECT on sensitive columns
- **Code:** `agent-host/agents/analytics/tools/index.postgres.js`
- **Tests:** `tests/secureshop/vuln/llm/llm02-analytics-pii-leak.test.js`

### `llm02-sensitive-info`

- **OWASP:** OWASP-LLM:LLM02
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin chat → user-management.lookup returns full row incl. bcrypt hash, api_key, session_token, pii_json
- **Impact:** credential exfiltration into any authenticated admin session
- **Fix path (defense-in-depth):** per-column allow-list; never return password/api_key/session_token
- **Code:** `agent-host/agents/user-management/tools/index.js`
- **Tests:** `tests/secureshop/vuln/llm/llm02-sensitive-info.test.js`

### `llm02-user-lookup`

- **OWASP:** OWASP-LLM:LLM01, OWASP-LLM:LLM02
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin (or jailbroken customer via LLM06) → user-management.lookup → full row exfil
- **Impact:** credential + PII exfil
- **Fix path (defense-in-depth):** per-column allow-list; also close LLM06 at Layer B
- **Code:** `agent-host/agents/user-management/tools/index.js`
- **Tests:** `tests/secureshop/vuln/chains/audit-log-injection.test.js`<br>`tests/secureshop/vuln/llm/llm02-user-lookup.test.js`

### `llm03-supply-chain`

- **OWASP:** OWASP-LLM:LLM03
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin registers untrusted MCP server → its tools land in supervisor prompt → poisoned descriptions run
- **Impact:** attacker MCP server executes as supervisor
- **Fix path (defense-in-depth):** signed manifest + allow-list of registrar hosts; sandbox external tool descriptions
- **Code:** `agent-host/agents/mcp-registry/tools/index.js`
- **Tests:** `tests/secureshop/vuln/mcp/llm03-supply-chain.test.js`

### `llm04-policy-poisoning`

- **OWASP:** OWASP-LLM:LLM04
- **Enforcement layer where check is missing:** B
- **Attacker path:** admin (or SSTI via policies/render) writes policy content with [SYSTEM: ...] → policyLoader reads and appends to system prompt
- **Impact:** persistent PI baked into every supervisor turn
- **Fix path (defense-in-depth):** sanitize / structured-only policy schema; refuse markdown_source that starts new instructions
- **Code:** `agent-host/agents/policy/tools/index.js`<br>`agent-host/agents/policy/tools/index.postgres.js`<br>`agent-host/agents/pricing-strategy/tools/index.postgres.js`<br>`server/services/secureshop/supervisors/policyLoader.js`
- **Tests:** `tests/secureshop/vuln/llm/llm04-policy-poisoning-merchant.test.js`<br>`tests/secureshop/vuln/llm/llm04-policy-poisoning.test.js`

### `llm04-rag-competitor-poisoning`

- **OWASP:** OWASP-LLM:LLM04
- **Enforcement layer where check is missing:** B
- **Attacker path:** merchant pricing-strategy.suggest_price → RAG competitor doc corpus injects → LLM emits poisoned price
- **Impact:** attacker-controlled price recommendations
- **Fix path (defense-in-depth):** per-doc trust score; quarantine untrusted corpus
- **Code:** `agent-host/agents/pricing-strategy/tools/index.postgres.js`<br>`client/src/pages/secureshop/pages/merchant/Pricing.jsx`
- **Tests:** `tests/secureshop/vuln/llm/llm04-rag-competitor-poisoning.test.js`

### `llm04-rag-poisoning`

- **OWASP:** OWASP-LLM:LLM04
- **Enforcement layer where check is missing:** B
- **Attacker path:** uploads.upload_product_manual → text ingested into vector store → RAG retrieval surfaces poisoned chunk → supervisor obeys
- **Impact:** stored PI via product manual
- **Fix path (defense-in-depth):** quarantine untrusted uploads; sanitize retrievals
- **Code:** `agent-host/agents/product-search/tools/similar.postgres.js`<br>`agent-host/agents/uploads/tools/index.js`<br>`server/services/secureshop/vectorStore.js`
- **Tests:** `tests/secureshop/vuln/chains/rag-summarizer-supervisor.test.js`<br>`tests/secureshop/vuln/llm/llm04-rag-poisoning.test.js`<br>`tests/secureshop/vuln/parity/llm04-rag-poisoning.parity.test.js`

### `llm05-improper-output`

- **OWASP:** OWASP-LLM:LLM05, OWASP-Web:A03
- **Enforcement layer where check is missing:** data
- **Attacker path:** summarizer.explain_return_policy → LLM returns HTML → frontend renders with dangerouslySetInnerHTML
- **Impact:** DOM XSS via LLM output
- **Fix path (defense-in-depth):** sanitize LLM HTML output on render OR require JSON-only response
- **Code:** `agent-host/agents/summarizer/tools/explain_return_policy.js`
- **Tests:** `tests/secureshop/e2e/vuln-flows/xss-stored-product-e2e.test.js`<br>`tests/secureshop/vuln/llm/llm05-improper-output.test.js`

### `llm05-listing-xss`

- **OWASP:** OWASP-LLM:LLM05
- **Enforcement layer where check is missing:** data
- **Attacker path:** Supported owned flow: Write with AI → secureshopBoundListings LangGraph model rewrite → immutable rewrite/save → ProductDescription HTML render (Listings preview is escaped). Legacy listing.create/_llmRewrite remains separate and can pass supplied markup through without a model call.
- **Impact:** stored XSS in product listing
- **Fix path (defense-in-depth):** HTML-sanitize LLM output before persistence
- **Code:** `agent-host/agents/listing/tools/_llmRewrite.js`<br>`agent-host/agents/listing/tools/create.postgres.js`<br>`client/src/pages/secureshop/components/ProductDescription.jsx`<br>`client/src/pages/secureshop/pages/merchant/Listings.jsx`
- **Tests:** `tests/secureshop/vuln/llm/llm05-listing-xss.test.js`

### `llm06-excessive-agency`

- **OWASP:** OWASP-LLM:LLM06
- **Enforcement layer where check is missing:** B (with Layer C reinforcement gap)
- **Attacker path:** customer session → jailbreak customer supervisor → LLM emits tool_use user-management.set_role → Layer B records policy_violation=denied-by-acl but dispatches (enforce_tool_acl=false) → Layer C skips its own check → priv-esc lands
- **Impact:** vertical priv-esc; customer becomes admin
- **Fix path (defense-in-depth):** defense-in-depth: (1) admin toggles SS_ENFORCE_TOOL_ACL=true at Layer B via Access Control page, (2) user-management server adds enforceRole(['admin']) at Layer C
- **Code:** `agent-host/agents/user-management/server.js`<br>`agent-host/agents/user-management/tools/index.js`<br>`agent-host/shared/callerContext.js`<br>`db/initialize-db/seeds/22_secureshop_v2_rbac.js`<br>`server/services/secureshop/supervisors/adminSupervisor.js`<br>`server/services/secureshop/supervisors/basePrompt.js`<br>`server/services/secureshop/supervisors/merchantSupervisor.js`<br>`server/services/secureshop/toolAcl.js`
- **Tests:** `tests/secureshop/e2e/vuln-flows/priv-esc-e2e.test.js`<br>`tests/secureshop/vuln/llm/llm06-excessive-agency-e2e.test.js`<br>`tests/secureshop/vuln/llm/llm06-excessive-agency.test.js`<br>`tests/secureshop/vuln/llm/llm06-real-jailbreak.test.js`<br>`tests/secureshop/vuln/parity/llm06-excessive-agency-e2e.parity.test.js`

### `llm07-system-prompt-leak`

- **OWASP:** OWASP-LLM:LLM07
- **Enforcement layer where check is missing:** B
- **Attacker path:** user message asks LLM to repeat system prompt → no output filter → system prompt (with concatenated policies) echoed
- **Impact:** system prompt + poisoned policy content leaks
- **Fix path (defense-in-depth):** output filter that scrubs system-prompt-shaped strings
- **Code:** `server/services/secureshop/supervisors/adminSupervisor.js`<br>`server/services/secureshop/supervisors/customerSupervisor.js`
- **Tests:** `tests/secureshop/vuln/llm/llm07-admin-system-prompt-leak.test.js`<br>`tests/secureshop/vuln/llm/llm07-system-prompt-leak.test.js`

### `llm08-embedding-inversion`

- **OWASP:** OWASP-LLM:LLM08
- **Enforcement layer where check is missing:** C
- **Attacker path:** a sensitive synthetic manual is indexed → a topic-only nearest-neighbor query retrieves its stored plaintext without a document authorization check
- **Impact:** sensitive RAG document disclosure; legacy ID retained, embedding inversion is not demonstrated
- **Fix path (defense-in-depth):** enforce per-document retrieval authorization and exclude secrets from shared corpora; hiding vectors alone does not prevent plaintext retrieval
- **Code:** `agent-host/agents/uploads/tools/index.js`<br>`server/services/secureshop/vectorStore.js`
- **Tests:** `tests/secureshop/vuln/llm/llm08-embedding-inversion.test.js`

### `llm08-embedding-poisoning`

- **OWASP:** OWASP-LLM:LLM08
- **Enforcement layer where check is missing:** C
- **Attacker path:** malicious upload with adversarial text → embedded near legitimate content → retrievals surface poisoned chunks
- **Impact:** RAG poisoning
- **Fix path (defense-in-depth):** per-source trust score; anomaly detection on new embeddings
- **Code:** `agent-host/agents/uploads/tools/index.js`
- **Tests:** `tests/secureshop/vuln/llm/llm08-embedding-poisoning.test.js`

### `llm09-misinformation`

- **OWASP:** OWASP-LLM:LLM09
- **Enforcement layer where check is missing:** B
- **Attacker path:** price-advisor.find_deals fabricates competitor prices with Math.random and marks the result grounded=false → a supervisor may repeat the unverified tool output as authoritative
- **Impact:** customer misled into fake deals
- **Fix path (defense-in-depth):** attach a real grounding source and provenance to competitor prices; require the supervisor to qualify or reject unverified tool output
- **Code:** `agent-host/agents/price-advisor/tools/index.postgres.js`
- **Tests:** `tests/secureshop/vuln/llm/llm09-misinformation.test.js`

### `llm09-pricing-hallucination`

- **OWASP:** OWASP-LLM:LLM09
- **Enforcement layer where check is missing:** B
- **Attacker path:** merchant pricing-strategy.run_pricing_experiment fabricates elasticity, lift, revenue and confidence values with Math.random and marks projections grounded=false → a supervisor may cite the unverified projections as authoritative
- **Impact:** merchant sets wrong price
- **Fix path (defense-in-depth):** derive projections from real historical/competitor data with provenance; require the supervisor to qualify or reject unverified projections
- **Code:** `agent-host/agents/pricing-strategy/tools/index.postgres.js`<br>`client/src/pages/secureshop/pages/merchant/Pricing.jsx`
- **Tests:** `tests/secureshop/vuln/llm/llm09-pricing-hallucination.test.js`

### `llm10-analytics-unbounded`

- **OWASP:** OWASP-LLM:LLM10
- **Enforcement layer where check is missing:** C
- **Attacker path:** merchant analytics.nl_query emits SELECT without LIMIT → 10M-row response into next LLM call
- **Impact:** DoS + cost blow-up + token budget exhaustion
- **Fix path (defense-in-depth):** enforce LIMIT at query build time; per-tool byte-size cap
- **Code:** `agent-host/agents/analytics/tools/index.postgres.js`<br>`server/services/secureshop/supervisors/merchantSupervisor.js`
- **Tests:** `tests/secureshop/vuln/llm/llm10-analytics-unbounded.test.js`

### `llm10-audit-unbounded`

- **OWASP:** OWASP-LLM:LLM10
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin audit.summarize_anomalies(limit=10000) → megabyte tool_result → next LLM call OOMs
- **Impact:** DoS via audit summarizer
- **Fix path (defense-in-depth):** clamp limit; per-tool byte-size cap in supervisor
- **Code:** `agent-host/agents/audit/tools/index.js`<br>`server/services/secureshop/supervisors/adminSupervisor.js`
- **Tests:** `tests/secureshop/vuln/llm/llm10-audit-unbounded.test.js`

### `llm10-unbounded`

- **OWASP:** OWASP-LLM:LLM10
- **Enforcement layer where check is missing:** B
- **Attacker path:** runaway tool loop → MAX_STEPS caps outer iterations but per-hop byte size unlimited
- **Impact:** DoS via tool_result blow-up
- **Fix path (defense-in-depth):** per-hop byte cap on appendToolResult
- **Code:** `server/services/secureshop/supervisors/customerSupervisor.js`
- **Tests:** `tests/secureshop/vuln/llm/llm10-unbounded.test.js`

### `mcp-05-pi-via-tool-output`

- **OWASP:** OWASP-MCP:MCP-06
- **Enforcement layer where check is missing:** B
- **Attacker path:** price-advisor.compare_competitor → attacker-controlled competitor HTML flows back into supervisor tool_result → LLM obeys
- **Impact:** PI via external tool output
- **Fix path (defense-in-depth):** frame/quote tool output as data; sanitize HTML
- **Code:** `agent-host/agents/price-advisor/tools/index.postgres.js`<br>`client/src/pages/secureshop/pages/merchant/Pricing.jsx`<br>`server/services/secureshop/supervisors/customerSupervisor.js`
- **Tests:** `tests/secureshop/vuln/chains/mcp05-external-tool-output-pi.test.js`<br>`tests/secureshop/vuln/mcp/mcp05-pi-via-tool-output.test.js`

### `mcp01-tool-poisoning`

- **OWASP:** OWASP-MCP:MCP-03
- **Enforcement layer where check is missing:** B
- **Attacker path:** admin registers external MCP → its tool descriptions land verbatim in supervisor prompt → attacker instructs the LLM through description text
- **Impact:** PI via poisoned tool description
- **Fix path (defense-in-depth):** quote/frame tool descriptions as data-only; signature check on registered servers
- **Code:** `agent-host/agents/mcp-registry/tools/index.js`
- **Tests:** `tests/secureshop/vuln/chains/mcp01-rug-pull.test.js`<br>`tests/secureshop/vuln/mcp/mcp01-tool-poisoning.test.js`

### `mcp02-rug-pull`

- **OWASP:** OWASP-MCP:MCP-03
- **Enforcement layer where check is missing:** B
- **Attacker path:** admin registers a trusted server → attacker rotates its schema post-registration → new tools with malicious behavior appear on next refresh
- **Impact:** time-of-check vs time-of-use bypass
- **Fix path (defense-in-depth):** schema-hash pinning; alert on schema change
- **Code:** `agent-host/agents/mcp-registry/tools/index.js`
- **Tests:** `tests/secureshop/e2e/vuln-flows/mcp-rug-pull-e2e.test.js`<br>`tests/secureshop/vuln/chains/mcp01-rug-pull.test.js`<br>`tests/secureshop/vuln/mcp/mcp02-rug-pull.test.js`

### `mcp06-credential-leak`

- **OWASP:** OWASP-MCP:MCP-01
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin system.read_config → naive `..` strip lets caller read /etc/config with credentials
- **Impact:** credential exfil via config file read
- **Fix path (defense-in-depth):** canonicalize path; refuse absolute; refuse outside allow-listed dir
- **Code:** `agent-host/agents/system/tools/index.js`
- **Tests:** `tests/secureshop/vuln/mcp/mcp06-credential-leak.test.js`<br>`tests/secureshop/vuln/web/path-traversal-read-config.test.js`

### `mcp08-ssrf`

- **OWASP:** —
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin mcp-registry.register(url=http://internal-only) → server-side fetch to internal network → response returned to caller
- **Impact:** SSRF to internal services
- **Fix path (defense-in-depth):** block private-IP / metadata addresses
- **Code:** `agent-host/agents/mcp-registry/tools/index.js`
- **Tests:** `tests/secureshop/vuln/mcp/mcp08-ssrf.test.js`

### `mcp09-impersonation`

- **OWASP:** OWASP-MCP:MCP-07
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin registers name=trusted-mcp with attacker URL → overwrites the trusted-name entry → supervisor picks up attacker's tools
- **Impact:** server impersonation
- **Fix path (defense-in-depth):** immutable name registration; require signature match to overwrite
- **Code:** `agent-host/agents/mcp-registry/tools/index.js`
- **Tests:** `tests/secureshop/vuln/mcp/mcp09-impersonation.test.js`

### `path-traversal`

- **OWASP:** OWASP-Web:A01
- **Enforcement layer where check is missing:** C
- **Attacker path:** summarizer.summarize_file(path=../../../etc/passwd) → naive resolve → arbitrary file read
- **Impact:** arbitrary file read
- **Fix path (defense-in-depth):** restrict to /uploads/; canonicalize + prefix-check
- **Code:** `agent-host/agents/summarizer/tools/summarize_file.js`
- **Tests:** `tests/secureshop/vuln/llm/llm01-pi-file-upload.test.js`

### `path-traversal-read-config`

- **OWASP:** OWASP-Web:A01
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin system.read_config with `....//server/platform_secrets.json` → single-pass `../` removal leaves `../server/platform_secrets.json` → resolves to the server secrets fixture
- **Impact:** read arbitrary file
- **Fix path (defense-in-depth):** canonicalize + prefix-check; refuse absolute paths
- **Code:** `agent-host/agents/system/tools/index.js`
- **Tests:** `tests/secureshop/vuln/parity/path-traversal-read-config.parity.test.js`<br>`tests/secureshop/vuln/web/path-traversal-read-config.test.js`

### `path-traversal-upload`

- **OWASP:** OWASP-Web:A01
- **Enforcement layer where check is missing:** C
- **Attacker path:** uploads with filename=../../../etc/nginx.conf → filename trusted → server writes outside upload dir
- **Impact:** file overwrite / path escape
- **Fix path (defense-in-depth):** generate server-side filename; ignore client filename
- **Code:** `agent-host/agents/uploads/tools/index.js`
- **Tests:** `tests/secureshop/vuln/web/path-traversal-upload.test.js`

### `rce-run-diagnostic`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin chat → system.run_diagnostic(cmd_template, args) → raw command concatenation; shell execution requires SS_SYSTEM_ALLOW_EXEC=true
- **Impact:** arbitrary command execution when enabled; current guarded proof verifies command construction, not an executed process effect
- **Fix path (defense-in-depth):** delete the tool; if truly needed, use a fixed set of diagnostic types with parametric exec
- **Code:** `agent-host/agents/system/tools/index.js`
- **Tests:** `tests/secureshop/vuln/web/rce-run-diagnostic.test.js`

### `sqli-blind-boolean`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** customer cart.apply_coupon(code) → string-concat WHERE → boolean-based blind extraction
- **Impact:** data exfil via blind SQLi
- **Fix path (defense-in-depth):** parameterized query
- **Code:** `agent-host/agents/cart/tools/index.postgres.js`
- **Tests:** `tests/secureshop/vuln/web/sqli-blind-boolean.test.js`

### `sqli-coupon`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** A
- **Attacker path:** customer POST /cart/apply-coupon with code=` OR 1=1--` → string-concat WHERE
- **Impact:** coupon lookup returns first active row
- **Fix path (defense-in-depth):** parameterized query
- **Code:** `server/routes/secureshop/customer.js`<br>`server/routes/secureshop/postgres/customer.js`
- **Tests:** `tests/secureshop/vuln/web/sqli-coupon.test.js`

### `sqli-error-based`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** customer support.order_status with error-inducing SQL → messages leak
- **Impact:** schema disclosure via error messages
- **Fix path (defense-in-depth):** parameterized query + generic error message
- **Code:** `agent-host/agents/support/tools/index.postgres.js`
- **Tests:** `tests/secureshop/vuln/web/sqli-error-based.test.js`

### `sqli-nl-generated`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** merchant analytics.nl_query → LLM emits attacker-influenced SQL → executed unparameterized
- **Impact:** SQLi via NL-to-SQL translation
- **Fix path (defense-in-depth):** AST-level allow-list; execute in a read-only sandbox
- **Code:** `agent-host/agents/analytics/tools/index.postgres.js`
- **Tests:** `tests/secureshop/vuln/web/sqli-nl-generated.test.js`

### `sqli-time-based`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin audit.search_by_user → raw username interpolation into WHERE; current fixture proves UNION injection
- **Impact:** SQL injection; legacy timing ID retained, timing-side-channel extraction requires separate native qualification
- **Fix path (defense-in-depth):** parameterized query
- **Code:** `agent-host/agents/audit/tools/index.js`
- **Tests:** `tests/secureshop/vuln/web/sqli-time-based.test.js`

### `sqli-union`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** customer product-search.search → UNION SELECT payload extracts columns
- **Impact:** data exfil across tables via UNION
- **Fix path (defense-in-depth):** parameterized query
- **Code:** `agent-host/agents/product-search/tools/search.postgres.js`
- **Tests:** `tests/secureshop/vuln/parity/sqli-union.parity.test.js`<br>`tests/secureshop/vuln/web/sqli-union.test.js`

### `ssrf-competitor`

- **OWASP:** OWASP-Web:A10
- **Enforcement layer where check is missing:** C
- **Attacker path:** merchant price-advisor.compare_competitor(url) → server-side fetch to attacker-controlled host
- **Impact:** SSRF + internal probing
- **Fix path (defense-in-depth):** URL allow-list; block private IPs
- **Code:** `agent-host/agents/price-advisor/tools/index.postgres.js`<br>`client/src/pages/secureshop/pages/merchant/Pricing.jsx`
- **Tests:** `tests/secureshop/vuln/web/ssrf-competitor.test.js`

### `ssrf-email-inline-image`

- **OWASP:** OWASP-Web:A10
- **Enforcement layer where check is missing:** C
- **Attacker path:** email.summarize_thread inlines <img src=...> → server-side fetch of arbitrary URL
- **Impact:** SSRF via email content
- **Fix path (defense-in-depth):** do not fetch inline images server-side
- **Code:** `agent-host/agents/email/tools/index.postgres.js`
- **Tests:** `tests/secureshop/vuln/web/ssrf-email-inline-image.test.js`

### `ssrf-listing-import`

- **OWASP:** OWASP-Web:A10
- **Enforcement layer where check is missing:** C
- **Attacker path:** merchant listing.import_bulk(json_url, xml_url) → server fetches arbitrary URL
- **Impact:** SSRF
- **Fix path (defense-in-depth):** URL allow-list; block private IPs
- **Code:** `agent-host/agents/listing/tools/import_bulk.postgres.js`<br>`client/src/pages/secureshop/pages/merchant/Listings.jsx`
- **Tests:** `tests/secureshop/vuln/web/ssrf-listing-import.test.js`

### `ssrf-return-policy`

- **OWASP:** OWASP-Web:A10
- **Enforcement layer where check is missing:** C
- **Attacker path:** summarizer.explain_return_policy(policy_url) → server fetches arbitrary URL
- **Impact:** SSRF
- **Fix path (defense-in-depth):** URL allow-list
- **Code:** `agent-host/agents/summarizer/tools/explain_return_policy.js`
- **Tests:** `tests/secureshop/vuln/parity/ssrf-return-policy.parity.test.js`<br>`tests/secureshop/vuln/web/ssrf-return-policy.test.js`

### `ssti-listing-template`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** merchant listing.create with template_source → unsafe Nunjucks env → RCE via {{constructor.constructor(...)}} gadgets
- **Impact:** RCE
- **Fix path (defense-in-depth):** sandbox Nunjucks (no globals, no proto access) or drop custom templates
- **Code:** `agent-host/agents/listing/tools/_nunjucksSink.js`<br>`agent-host/agents/listing/tools/create.postgres.js`<br>`client/src/pages/secureshop/pages/merchant/Listings.jsx`
- **Tests:** `tests/secureshop/vuln/web/ssti-listing-template.test.js`

### `ssti-policy-template`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin policy.update_policy → unsafe Nunjucks env → same gadget
- **Impact:** RCE
- **Fix path (defense-in-depth):** sandbox Nunjucks or drop templating
- **Code:** `agent-host/agents/listing/tools/_nunjucksSink.js`<br>`agent-host/agents/policy/tools/index.js`<br>`agent-host/agents/policy/tools/index.postgres.js`
- **Tests:** `tests/secureshop/vuln/web/ssti-policy-template.test.js`

### `xss-reflected-search`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** data
- **Attacker path:** customer search query echoed into echo_html → HopDetailSheet renders with dangerouslySetInnerHTML
- **Impact:** reflected XSS in agent lane
- **Fix path (defense-in-depth):** escape echoed query; render as text
- **Code:** `agent-host/agents/product-search/tools/search.postgres.js`<br>`client/src/pages/secureshop/components/AgentLane/HopDetailSheet.jsx`<br>`client/src/pages/secureshop/components/AgentLane/Turn.jsx`
- **Tests:** `tests/secureshop/vuln/web/xss-reflected-search.test.js`

### `xss-stored-email`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** data
- **Attacker path:** email.send body_markdown → stored HTML → Inbox renders raw
- **Impact:** stored XSS in Inbox
- **Fix path (defense-in-depth):** sanitize HTML on render
- **Code:** `agent-host/agents/email/tools/index.postgres.js`<br>`client/src/pages/secureshop/components/MailMessageBody.jsx`<br>`client/src/pages/secureshop/pages/merchant/Inbox.jsx`
- **Tests:** `tests/secureshop/vuln/web/xss-stored-email.test.js`

### `xss-stored-listing`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** data
- **Attacker path:** merchant listing.create → description_html stored → catalog / merchant Listings render raw
- **Impact:** stored XSS in catalog
- **Fix path (defense-in-depth):** sanitize HTML on ingest
- **Code:** `agent-host/agents/listing/tools/create.postgres.js`<br>`agent-host/agents/listing/tools/update.postgres.js`
- **Tests:** `tests/secureshop/e2e/vuln-flows/xss-stored-product-e2e.test.js`<br>`tests/secureshop/vuln/parity/xss-stored-listing.parity.test.js`<br>`tests/secureshop/vuln/web/xss-stored-listing.test.js`

### `xss-stored-review`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** data
- **Attacker path:** customer review body → stored HTML → product page renders raw
- **Impact:** stored XSS in reviews
- **Fix path (defense-in-depth):** sanitize HTML on render
- **Code:** `client/src/pages/secureshop/pages/merchant/Reviews.jsx`<br>`server/routes/secureshop/customer.js`<br>`server/routes/secureshop/postgres/customer.js`
- **Tests:** `tests/secureshop/vuln/web/xss-stored-review.test.js`

### `xss-stored-ticket`

- **OWASP:** OWASP-Web:A03
- **Enforcement layer where check is missing:** data
- **Attacker path:** customer support.open_ticket body → stored HTML → admin renders raw
- **Impact:** stored XSS in admin ticket view
- **Fix path (defense-in-depth):** sanitize HTML on render
- **Code:** `agent-host/agents/support/tools/index.postgres.js`<br>`client/src/pages/secureshop/components/AdminTicketBody.jsx`
- **Tests:** `tests/secureshop/vuln/web/xss-stored-ticket.test.js`

### `xxe-import-bulk`

- **OWASP:** OWASP-Web:A05
- **Enforcement layer where check is missing:** C
- **Attacker path:** merchant listing.import_bulk(xml_url) → sax parser resolves DOCTYPE SYSTEM entities → file:// disclosure
- **Impact:** arbitrary local file read via XXE
- **Fix path (defense-in-depth):** disable external-entity resolution
- **Code:** `agent-host/agents/listing/tools/import_bulk.postgres.js`<br>`client/src/pages/secureshop/pages/merchant/Listings.jsx`
- **Tests:** `tests/secureshop/vuln/web/xxe-import-bulk.test.js`

### `xxe-import-manifest`

- **OWASP:** OWASP-Web:A05
- **Enforcement layer where check is missing:** C
- **Attacker path:** admin mcp-registry.import_manifest(xml_url) → sax parser resolves DOCTYPE SYSTEM entities
- **Impact:** arbitrary local file read via XXE
- **Fix path (defense-in-depth):** disable external-entity resolution
- **Code:** `agent-host/agents/mcp-registry/tools/index.js`
- **Tests:** `tests/secureshop/vuln/mcp/xxe-import-manifest.test.js`

## Enforcement layers

Every intentional vulnerability above names a specific enforcement layer
where the check is missing. There are four:

- **Layer A** — REST middleware (`requireRole()` in
  `server/routes/secureshop/_ssAuthMiddleware.js`).
- **Layer B** — supervisor ACL (`server/services/secureshop/toolAcl.js`).
  Consults `tool_permissions`; records `agent_trace.policy_violation`.
  When `system_config.enforce_tool_acl='true'`, refuses out-of-role
  dispatch. Default `false` = LLM06 excessive-agency sink is open.
- **Layer C** — agent-host tool endpoint. Each `server.js` may call
  `enforceRole()` after `extractCaller()`. `user-management.set_role`
  deliberately does not — that is the LLM06 sink at Layer C.
- **data** — vulnerability is a data-sink (stored HTML, XSS via
  `dangerouslySetInnerHTML`). No auth layer will close it; the fix is
  sanitization at render or ingest.

## Notes

- **Do not "fix" any of these.** They are deliberate teaching sinks.
- If a test fails, first check whether the intentional vulnerability was
  removed — the failure is telling you the teaching surface has drifted.
- New vulns require both a code annotation AND a matching test annotation,
  then a rerun of this generator plus `npm run verify:secureshop:vuln-coverage`.
- To add a new vuln with M14 layer annotations, edit `IMPACT_CHAINS` in
  `scripts/generate-vuln-map.js` — one row per vuln id.
