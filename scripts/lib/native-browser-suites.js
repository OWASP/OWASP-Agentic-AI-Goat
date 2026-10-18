'use strict';
// Closed qualification inventory; changes require explicit source review.
const defaults=Object.freeze([
  {
    "file": "tests/csrfBrowserComposition.test.js",
    "names": [
      "browser, private attempt and parser compose under one owner execution with real sandbox delta"
    ]
  },
  {
    "file": "tests/csrfBrowserDurability.test.js",
    "names": [
      "admitted effect is persisted before delayed narration, and browser shutdown cannot grade it"
    ]
  },
  {
    "file": "tests/csrfBrowserExecutor.test.js",
    "names": [
      "real Chrome executes exact form payload once and reports the outgoing ambient cookie without exposing it to the page",
      "real Chrome handles JSON preflight without consuming the one allowed action",
      "network, popup, frame, worker and duplicate action attempts cannot escape the intercepted fixture boundary",
      "abort closes the browser context immediately but retains execute until an admitted callback drains",
      "abort, deadline and invalid callback output fail closed and clean fresh contexts",
      "constructor and input bounds require an intercepted same-site cross-origin fixture"
    ]
  },
  {
    "file": "tests/csrfBrowserOriginBoundary.test.js",
    "names": [
      "real browser distinguishes same-origin, same-site cross-origin and cross-site POST with explicit Lax cookies"
    ]
  },
  {
    "file": "tests/csrfBrowserWebRtc.test.js",
    "names": [
      "learner WebRTC cannot bypass HTTP interception through non-proxied UDP"
    ]
  },
  {
    "file": "tests/csrfShippedPostTemplates.test.js",
    "names": [
      "shipped POST form templates originate from the managed attacker page"
    ]
  },
  {
    "file": "tests/opaqueFrameDevCors.test.js",
    "names": [
      "actual Vite serves public modules to opaque frames without allowing opaque API or foreign-origin reads",
      "actual Vite preview serves built assets to opaque frames without opening API paths"
    ]
  },
  {
    "file": "tests/browserProcessOwnership.test.js",
    "names": [
      "browser identity is bound to the exact parent group, session, and uid",
      "real harmless child binds the test worker to its qualification group leader",
      "process row parser rejects duplicate, extra, and unsafe identities"
    ]
  }
].map(row=>Object.freeze({...row,names:Object.freeze(row.names)})));

const adminBundle=Object.freeze([Object.freeze({file:'tests/adminProductionBundle.test.js',names:Object.freeze(['production admin bundle loads without CommonJS/ES-module runtime rejection'])})]);
const secureshop=Object.freeze([
  {
    "file": "tests/secureshopBridgeBrowser.test.js",
    "names": [
      "real opaque frame uses closed bridge for HTTP/SSE without receiving launch or platform credentials"
    ]
  },
  {
    "file": "tests/secureshopOpaqueFrame.test.js",
    "names": [
      "opaque sandbox frame contains malicious script and CORS blocks its direct platform effect"
    ]
  },
  {
    "file": "tests/secureshopStorageBrowser.test.js",
    "names": [
      "actual opaque Chromium frames keep shop state separate while Web Storage is denied"
    ]
  },
  {
    "file": "tests/secureshopStoredBrowserAssessment.test.js",
    "names": [
      "actual ReviewCard output and attributed isolated-browser effect reach protected completion",
      "optimistic Judge cannot award unattributed, forged-owner, stale or changed submissions",
      "renderer must preserve the exact stored source and configuration fails closed",
      "persona browser capture stays private and publication receives original fence",
      "persona revocation after renderer prevents browser and grading",
      "persona missing credential and foreign capture fail before conversation or effects",
      "persona revocation inside browser denies grade and completion after real callback boundary",
      "persona exact replay rechecks authority and never repeats browser or Judge",
      "persona configured capture cannot silently disable authority without grading adapter",
      "persona credential is captured before asynchronous authority work",
      "malformed persona credentials reject before authority capture",
      "valid uppercase persona UUID normalizes before capture and input mutation cannot replace it",
      "controlled cached publication denies canonical mode and roundtrip stamp"
    ]
  },
  {
    "file": "tests/secureshopUploadAuthenticity.test.js",
    "names": [
      "actual upload/download route preserves PHP source; acceptance is not server-side execution",
      "two routers use their configured roots for concurrent writes, downloads and static reads",
      "scoped tool construction validates its root but preserves the teaching traversal sink",
      "uploaded HTML executes in an opaque frame while identical text stays inert"
    ]
  }
].map(row=>Object.freeze({...row,names:Object.freeze(row.names)})));
const xss=Object.freeze([
  {
    "file": "tests/xssBrowserQualification.test.js",
    "names": [
      "fresh sandboxed browser context reproduces innerHTML event handlers and blocks external requests",
      "Chrome launches with its sandbox defaults intact",
      "externally owned browser connector is exclusive and disconnects without closing or killing",
      "popup effects are observed outside the page and leave no qualification context open",
      "module loading is lazy and a missing browser runtime fails qualification closed",
      "script tags inserted with innerHTML do not execute and plain markup remains non-executable",
      "learner element comparison allows presentation attributes but preserves source DOM semantics",
      "document renderer proves inline script parsing without attributing sibling handlers",
      "innerHTML target attribution rejects inert fields despite an executing sibling handler",
      "innerHTML target attribution supports javascript URLs in their persisted context",
      "oversized payloads and saturated queues fail closed",
      "oversized learner comparison source is rejected without changing candidate qualification"
    ]
  },
  {
    "file": "tests/xssEmailObjectiveGrader.test.js",
    "names": [
      "published level-one script execution is not silently downgraded to HTML preservation",
      "published level-one earns credit only from script-specific document execution",
      "signature and company handlers require persisted field provenance and browser execution",
      "mock or fallback model output can render but cannot earn level-four credit",
      "unavailable judgments are durably audited without raw prompt or HTML",
      "an executable sibling handler cannot be attributed to an inert level-one script source",
      "an actual model-produced executing handler persists a bounded level-four judge receipt",
      "level-two grading observes event attributes and javascript URLs in a real browser",
      "candidate mapping does not confuse profile substitution with AI-produced XSS",
      "level-four attribution survives normal graph placeholder substitution",
      "legacy direct completion is retired and syntax verification explicitly awards no credit",
      "document parser records script execution independently of a same-field image handler",
      "explicit requested level records a failed Judge decision for a model refusal without granting credit"
    ]
  },
  {
    "file": "tests/xssEmailRouteGrading.test.js",
    "names": [
      "generation binds the authenticated owner and publishes only server grader results"
    ]
  },
  {
    "file": "tests/xssObjectiveGrader.test.js",
    "names": [
      "sparse browser failure receipts remain valid JSON without inventing DOM or isolation success",
      "buildReceipt seam distinguishes explicit persisted, model-originated, email, and reflected facts",
      "all twelve objective receipts have positive and negative server-fact fixtures",
      "opaque dispatch and retrieval proofs grade; copied raw success data cannot award or invoke the browser",
      "execution objective requires isolated qualification and labels its limited provenance",
      "browser report nonce and payload pattern alone never award execution",
      "anonymous attempts remain diagnostic and cannot create unowned completion receipts",
      "mock or fallback chat output is retained for display but is not actual model provenance",
      "R2 uses isolated DOM preservation rather than opening-tag substring or element count",
      "stored-user receipt rejects altered, truncated and wrong-field artifacts even when readback matches the tool",
      "stored execution credit requires the exact profile artifact to execute, not a model sibling",
      "old g2 completion cannot authorize g3 after a manual identical-byte rewrite",
      "missing private reader reports an explicit reason and ignores caller-supplied model-origin claims"
    ]
  }
].map(row=>Object.freeze({...row,names:Object.freeze(row.names)})));
const secureshopE2e=Object.freeze([{"file": "tests/secureshop/vuln/web/xss-stored-review.test.js", "names": ["xss-stored-review: review body reaches the documented innerHTML sink and executes"]},{"file": "tests/secureshop/e2e/vuln-flows/mcp-rug-pull-e2e.test.js", "names": ["e2e/mcp-rug-pull: schema-hash timeline shows rust-highlighted change node after forced schema flip"]}, {"file": "tests/secureshop/e2e/vuln-flows/priv-esc-e2e.test.js", "names": ["e2e/priv-esc: customer \u2192 admin via set-role API \u2192 admin overview page accessible"]}, {"file": "tests/secureshop/e2e/vuln-flows/xss-stored-product-e2e.test.js", "names": ["e2e/xss-stored-product: merchant listing description_html executes on customer product page"]}].map(row=>Object.freeze({...row,names:Object.freeze(row.names)})));
module.exports=Object.freeze({defaults,adminBundle,secureshop,xss,secureshopE2e});
