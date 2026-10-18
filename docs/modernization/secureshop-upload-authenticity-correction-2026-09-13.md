# SecureShop upload teaching correction

The upload tool deliberately accepts arbitrary extensions and preserves file bytes. Its current implementation has no extension allowlist, so the prior explanation that a `.php.png` filename bypasses a last-extension check described a check that does not exist.

The historical `file-upload-polyglot-rce` proof uploads an abbreviated `GIF89a`-signature fixture with embedded JavaScript text. It checks preserved bytes and download MIME. It does not run an image decoder, browser script or server interpreter. Its generated map previously claimed a GIF/PHP polyglot was interpreted and caused RCE. Neither the payload nor that execution path was demonstrated.

## Implemented correction

The source annotation, test description and generated map now describe the measured acceptance behavior and explicitly retain both stable vulnerability IDs. No vulnerable behavior was removed, no objective was credited and no UI markup or AWS asset changed.

`tests/secureshopUploadAuthenticity.test.js` exercises the actual Express upload/download router over an ephemeral loopback HTTP server. It uploads harmless PHP source through multipart form data, checks the exact file bytes within its owned temporary root, and downloads that file. The response is the PHP source, including its delimiters, rather than the synthetic echo output. This proves acceptance and source serving on that route, not PHP execution. No shell, model, database, private file or external endpoint is used.

Verification: the actual-route test passes with no skips; the annotation verifier retains all 66 vulnerability IDs. Temporary uploaded files are removed after the test. Existing intentional upload tests remain acceptance proofs and are now labeled accordingly.

## Required complete exercise design

Keep unrestricted upload as a prerequisite, with a concrete objective such as storing an otherwise forbidden file and observing its returned content type and bytes. Do not award code-execution credit at this stage.

For browser execution, use a valid artifact served in a documented browser context, inside the owned opaque shop frame. Record a fresh marker from actual script execution and bind it to the uploaded asset, initiating request, learner and reset generation. A string found in a file is insufficient. Include a benign artifact and a wrong-context negative case. Preserve the existing HTML/SVG teaching sinks while isolating the platform.

For a true polyglot objective, independently verify that the same complete file is valid under both claimed parsers and that the actual selected serving path reaches the second parser. The abbreviated current byte fixture cannot satisfy that objective.

For server-side execution, an intentionally configured interpreter must run inside the owned lab runtime with a bounded synthetic output artifact. Do not use an interpreter on the learner's host or claim one exists because of a filename or MIME label. The current PHP source-serving route does not supply this effect. Judge credit must require the interpreter's effect receipt and provenance, with negative controls for source-only responses and failed interpretation.

These connected browser/interpreter/owner/Judge requirements remain open. They are not satisfied by the corrected documentation or the passing upload acceptance test.

## Actual uploaded-file browser qualification

The second case in `tests/secureshopUploadAuthenticity.test.js` now posts identical complete HTML bytes through the actual multipart upload router twice, with `.html` and `.txt` names. It verifies the exact stored bytes, then loads each actual download response inside a Chromium `sandbox="allow-scripts"` iframe. Chromium's process sandbox remains enabled and a fresh owned browser profile is used; intercepted requests can reach only the test's ephemeral loopback origin.

The HTML case executes its script and changes a DOM marker inside the frame. The test independently reads that DOM change through browser instrumentation and verifies the frame's message source/origin. Access to synthetic parent DOM/storage is blocked; the script's POST to a protected platform prefix reaches the production CORS middleware with `Origin: null`, receives 403, and causes zero handler effects. Identical source served as plain text includes the marker bytes but never sets the execution variable or sends an observation. This negative control prevents source-string presence from being mistaken for execution.

Both actual-router tests pass, with no skips. This qualifies real stored-file browser execution and the tested frame primitives. The parent harness is synthetic: it does not establish the live SecureShop SPA bridge, durable learner isolation, native Judge receipts, vector/polyglot validity or server-side execution. Those remain separate requirements.

Independent review confirmed that scope and identified incomplete upload-root dependency injection: `buildUploadsRouter({ uploadRoot })` uses the option only for static serving, while POST/download tools read `SECURESHOP_UPLOAD_ROOT`. The fixture therefore sets an owned temporary process-wide root and runs these cases sequentially; it proves no concurrent per-owner root isolation. Replacing this global dependency with trusted scoped tool instances is required before learner-owned upload integration. The review's test corrections are implemented: cleanup is registered before server acquisition and restores environment/files even if browser closure fails; HTML/plain-text response media types and exact response bytes are asserted directly. The frame message collector is evidence collection for this test, not a production authorization bridge.
