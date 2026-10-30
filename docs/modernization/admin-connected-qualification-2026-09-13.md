# Admin data and connected qualification

## Findings and repairs

The Activity page previously substituted fictional audit records when its API request failed. This misrepresented platform activity and obscured the reported loading failures. `ComprehensiveAdminDashboard` now clears unavailable results and displays an explicit error. Its existing layout is preserved. Refresh passes the selected numeric page, periodic refresh retains that page, and request sequencing prevents an older failure from replacing newer data.

Three component tests cover unavailable data without fabricated records, refresh failure after real data, and a late failed request after a newer page response. The subsequent frontend regression passed **312 tests across 35 suites**, and the production Vite build passed. The build still reports the large-bundle warning; this is not browser or capacity qualification.

The admin user-list repository now supplies the Activity DTO's real recent-activity and canonical progress fields. An owned native PostgreSQL HTTP test passed in `/tmp/owasp-ai-goat-admin-dto-final-DCiWRN`; it verifies visibility changes and canonical totals instead of hardcoded exercise counts.

## Connected browser failure retained

The production-browser attempt at `/tmp/owasp-ai-goat-admin-browser-cors-Sqlj2s/browser.log` failed before reaching the admin assertions. Learner login succeeded and a DPI interaction earned an actual `ollama` / `llama3.1:8b` Judge receipt. The run inspector displayed the provider/model and Judge trace, but **Decision source unavailable** failed the model-provenance assertion. This requires tracing the actor/run DTO contract; provider presence alone does not prove the decision-source field is correct.

The owned PostgreSQL container was removed. Its ownership record identifies PostgreSQL's parent data directory as tmpfs with no named mounts. The failed run must not be counted as a pass for Student Workshop View, Activity or admin Agent Runs: those steps were not reached.

## Subsequent repairs awaiting connected verification

- Student Workshop View now uses the existing authorized canonical admin response for the FinFlow panel. It no longer calls the nonexistent auxiliary endpoint or invents four levels, scores, achievements or progression locks. Labels, totals, completion and timestamps come from the same objective projection as the main cards. Empty/absent projections are explicit, and reset copy accurately describes canonical completion and time cleanup. Focused frontend verification passes19; the subsequent full frontend passes **311 tests across35 suites**, and production build passes with the existing bundle warning.
- DPI now traces the actual actor invocation separately from the Judge. It distinguishes model, mock/scripted and unavailable fallback responses. Provider failure or malformed response cannot emit a success trace or reach grading; post-inference reset invalidation is not mislabeled as provider failure. Focused graph verification passes23 with2 gated live skips. The failed browser artifact remains valid historical evidence; a new connected run is required.

## Remaining qualification

**Full default browser result:** `/tmp/owasp-ai-goat-full-browser-ipi-kYqAoP/browser.log` passes without the IPI skip flag. An owned cache supplies the actual q8 `Xenova/all-MiniLM-L6-v2` model and finite384-dimensional vectors. IPI stores a synthetic uploaded policy as a real chunk, retrieves the matching text (score0.7018), produces a model-origin response, earns actual Ollama upload/query Judge receipts and resets successfully. DPI and all admin assertions above also pass, with no browser errors. The exact tmpfs PostgreSQL container is removed and absence verified. TLS trust uses Node system CA support; certificate verification was never disabled. This closes the previously unavailable embedding prerequisite for this owned test runtime, not every IPI scenario or clean-OS installation.

**Admin/DPI connected result:** `/tmp/owasp-ai-goat-admin-dpi-current-cxh09z/browser.log` passes with the production bundle, generated bootstrap administrator and all eight canonical permissions. It verifies real Ollama actor/Judge practice completion, learner run provenance and tokens, canonical FinFlow objective rendering, no obsolete auxiliary request, Activity DTO parity and owner-filtered admin run inspection. `browserErrors` is empty. Exact owned container cleanup and absence are recorded in `cleanup.log`. The run explicitly sets `FULLSTACK_SKIP_IPI=1`; the default full test retains its IPI gate. This qualifies the listed admin/DPI interactions, not the unavailable IPI flow or all workshop objectives.

The subsequent owned browser run at `/tmp/owasp-ai-goat-admin-browser-current-V8GOYx` verifies actual DPI actor provenance: `Decision source model`, Ollama `llama3.1:8b`,345 measured actor tokens and the canonical awarded Judge receipt. It then fails at the IPI readiness gate because the isolated offline runtime lacks `Xenova/all-MiniLM-L6-v2`. Admin assertions were again not reached. The wrapper's reserved shell variable also interrupted automatic cleanup; the exact owned container was subsequently inspected, removed and verified absent, with `cleanup.log` retained. An independent admin-only path may verify admin behavior, but must not be presented as passing IPI qualification.

- Verify fresh setup prepares the same embedding prerequisite automatically, including offline reuse and failure handling; the successful owned cache alone does not prove installer behavior.
- Verify enabled objectives, hints/solutions, reset and counts across every admin and student projection. The bounded tests above do not establish all-exercise parity.
