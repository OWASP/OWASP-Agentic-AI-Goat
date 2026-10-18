# Legacy XSS email builder grading boundary

The mounted `/api/xss-email` builder is an API-only legacy exercise. The JSON
`/preview` response remains available, and authenticated clients can render an
owned persisted template through `POST /preview/render`. That endpoint returns
the template as an HTML document and is the published Level 1 parser sink. The
generation response advertises its method, path and server-owned template ID.
The trusted qualifier reproduces both renderer types in fresh browser contexts
with synthetic state and blocked external requests.

Levels 2 and 3 require execution from the exact stored signature or company
field. Level 4 additionally requires the handler to originate in a real,
non-fallback model response. The generation graph privately tracks unchanged
model character ranges through profile substitution; a qualifying executable
attribute must be wholly model-owned after persistence. Profile-created
attributes on the same element remain excluded. A handler elsewhere in the
combined email cannot prove another level. Direct completion is retired;
syntax verification is a hint and never awards credit.

Level 1 requires the exact stored `full_name` script to be preserved in the
generated template and execute through document parsing. The qualifier matches
browser-owned precise JavaScript coverage to the exact source coordinates of an
executable inline script in the persisted field. Page JavaScript cannot forge
that attribution, and a sibling image or event handler cannot satisfy the fact.
Invalid scripts, non-JavaScript script types and blocked external scripts do not
qualify. Levels 2–4 continue to use `innerHTML` semantics. Their version 2
evidence projection parses the complete persisted email in a detached browser
`template`, disables executable attributes and URLs outside exact occurrences
of the objective field, and attaches the result only after that pass. Browser
coverage then proves execution of a target event attribute or `javascript:`
URL. This retains inert comment, `template`, and `textarea` contexts while
preventing an unrelated handler from copying a visible instrumentation value
and impersonating the field. The API renderer applies CSP `sandbox
allow-scripts` with an opaque origin and no network. The verifier separately
uses a synthetic cookie and request interception.

Every attempted candidate verdict is stored in
`xss_email_judge_receipts`. The table contains owner, level, template, verdict,
Judge/rubric versions, evidence digest, run ID, error code, and browser result.
It excludes prompts, generated HTML, learner payloads, evidence bodies, and
private model reasoning. Passing attempts then store a bounded receipt in the
existing local progress row. PostgreSQL run-ledger events use the
`XSS_EMAIL` family; SQLite development runs remain available in the bounded
in-memory inspector.
