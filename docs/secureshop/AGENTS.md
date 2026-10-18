# SecureShop v2 — Task Agent Catalog

Every task agent is one MCP server registered under
`agent-host/agents/<name>/server.js` and mounted at `GET /mcp/<name>` on the
Agent Host (port 8082). One paragraph per agent lists its tools and its
known-vulnerable operations.

## customer-facing

### `product-search`
Tools: `search`, `similar`, `personalized_feed`.
`search` concatenates `query` directly into a SQL LIKE clause
(**sqli-union**, **sqli-blind-boolean**, **sqli-error-based**), and echoes
the query into an HTML fragment without escaping (**xss-reflected-search**).
`similar` performs vector retrieval against the poisoned `manuals` corpus
(**llm04-rag-poisoning**, **llm08-embedding-poisoning**). All results
surface unfiltered into supervisor tool_result.

### `summarizer`
Tools: `summarize_product`, `summarize_reviews`, `summarize_file`,
`explain_return_policy`.
`summarize_product` returns `products.description` verbatim
(**llm01-indirect-pi-product**). `summarize_file` reads files via the path
argument with no confinement (**llm01-pi-file-upload**, **path-traversal**).
`explain_return_policy` fetches an arbitrary URL server-side
(**ssrf-return-policy**). `summarize_reviews` reads
`reviews.body` and reviewer content verbatim into an LLM summarization
prompt (**llm01-indirect-pi-review**).

### `price-advisor`
Tools: `suggest_from_history`, `apply_coupon`.
Consumes `orders` history and freely accepts coupon codes without ownership
checks (**llm09-pricing-hallucination**, **idor-cart**-adjacent).

### `cart`
Tools: `view`, `add`, `remove`, `checkout`.
Every operation trusts a caller-supplied `user_id` (**idor-cart**). Checkout
does not re-validate cart totals against product prices.

### `support`
Tools: `open_ticket`, `read_ticket`, `get_order_status`.
`get_order_status` accepts any `order_id` (**idor-order-status**).
Attachments are stored via `uploads.upload_return_evidence` (see uploads).

## merchant-facing

### `listing`
Tools: `create`, `update`, `import_bulk`, `optimize_images`.
`create` and `update` write raw HTML into `products.description_html`
(**xss-stored-listing**, **llm05-listing-xss**). `create`'s Nunjucks path
has `autoescape:false` + `process` in globals (**ssti-listing-template**).
`import_bulk` parses XML with entity expansion (**xxe-import-bulk**) and
recursively merges attacker JSON into ordinary JavaScript objects, allowing
prototype pollution (**insecure-deser-listing-import**, a retained lesson ID).
The demonstrated effect is an inherited property on a fresh object; Python
pickle deserialization and a downstream code-execution gadget are not present
in this lesson. It also fetches URLs
(**ssrf-listing-import**). `optimize_images` shells out to ImageMagick
without arg sanitization (**command-injection-image-optimize**).

### `inventory`
Tools: `list`, `set_stock`.
No role gate — customer sessions can invoke `set_stock`
(**broken-access-inventory**).

### `pricing-strategy`
Tools: `suggest_price`.
Reads competitor "policies" (rows in the `policies` table). A poisoned
policy directly steers the price recommendation
(**llm04-rag-competitor-poisoning**).

### `review-moderator`
Tools: `moderate`, `bulk_approve`.
The moderator LLM prompt concatenates review bodies verbatim
(**llm01-indirect-pi-review**).

### `analytics`
Tools: `top_products`, `revenue_report`, `user_activity_report`.
`user_activity_report` returns entire user rows including PII columns
(**llm02-analytics-pii-leak**). Reports accept unclamped `limit`
(**llm10-analytics-unbounded**).

## admin-facing

### `user-management`
Tools: `lookup`, `set_role`, `reset_password`, `ban`.
`lookup` returns `password`, `session_token`, `api_key`, `pii_json`
(**llm02-user-lookup**, **llm02-sensitive-info**). `set_role` writes to
`shop_users.role` with zero re-auth (**llm06-excessive-agency** — the
marquee LLM06 chain). `ban.reason` and `lookup.username` land verbatim in
`audit_events` (**llm01-indirect-pi-audit-log**).

### `audit`
Tools: `recent_events`, `search_by_user`, `summarize_anomalies`.
`search_by_user` uses raw string concatenation into a LIKE clause
(**sqli-time-based**). `summarize_anomalies` concatenates audit rows into an
LLM summarization prompt, forwarding any injected `SYSTEM: ...` lines from
prior `user-management.*` calls (**llm01-indirect-pi-audit-log**). Unclamped
`limit` (**llm10-audit-unbounded**).

### `system`
Tools: `restart`, `run_diagnostic`, `read_config`.
`restart` shells out with concatenated args (**command-injection-restart**).
`run_diagnostic` spawns arbitrary command strings (**rce-run-diagnostic**).
`read_config` strips `../` once, defeated by `....//` (**path-traversal-read-config**).
The exfiltrated fake secrets file also serves the **mcp06-credential-leak**
teaching case.

### `policy`
Tools: `list`, `update`, `render`, `attach_to_role`.
`render` uses Nunjucks with process exposed (**ssti-policy-template**).
`update`/`attach_to_role` write to the `policies` table whose contents feed
the supervisor system prompt (**llm04-policy-poisoning**,
**llm04-policy-poisoning-merchant**, **llm07-system-prompt-leak**,
**llm07-admin-system-prompt-leak**).

### `mcp-registry`
Tools: `list_servers`, `register`, `remove`, `describe_tools`,
`import_manifest`.
`register` fetches the URL server-side without allow-listing
(**mcp08-ssrf**). Descriptions land verbatim in the tool cache
(**mcp01-tool-poisoning**). Re-registering the same name overwrites
(**mcp02-rug-pull**, **mcp09-impersonation**). Stdio transport spawns
arbitrary commands when enabled (**llm03-supply-chain**).
`import_manifest` expands XML entities (**xxe-import-manifest**).

## shared

### `uploads`
Tools: `upload_avatar`, `upload_product_image`, `upload_return_evidence`,
`upload_product_manual`, `download`, `extractText`.
Extension allow-list absent (**file-upload-extension-bypass**); SVGs served
inline (**file-upload-svg-xss**); polyglot files pass through
(**file-upload-polyglot-rce**); single-pass `../` strip is defeated by
`....//` (**path-traversal-upload**). `upload_product_manual` embeds and
indexes every chunk into the manuals vector corpus with no filter
(**llm04-rag-poisoning**, **llm08-embedding-inversion**,
**llm08-embedding-poisoning**).

### `email`
Tools: `send`, `read_inbox`, `summarize_thread`, `auto_reply`.
`send` renders markdown through `marked` with sanitization off
(**html-injection**, **xss-stored-email**) and concatenates `to`/`headers`
into raw SMTP-style headers (**email-header-injection**). `read_inbox`
trusts caller-supplied `user_id` (**idor-inbox**). `summarize_thread`
concatenates every email body into an LLM prompt (**llm01-pi-email**) and
server-side-fetches inline images (**ssrf-email-inline-image**).
