# FinFlow backup Judge integration review

Review scope: in-progress private candidate `/tmp/finflow-integrated-agent-durable.biWDmzet`; no live activation. Source snapshot SHA-256: `3e5789f992d7a1b91ce5e777869dd4a68a5d128b4759b7c7a00520dcd5d15697`.

## Required corrections before qualification

1. The candidate establishes same-call private resource and customer-policy pairs, but its backup `toolEvidence` filter admits every call with the relevant tool name. Once one valid pair satisfies the required server facts, another failed or unpaired call can still supply content to the semantic criterion. Only paired call indices should supply eligible `tool_result` evidence. Retain other calls as explicitly ineligible diagnostic observations so the run remains inspectable.
2. The resource receipt binds the actual backup metadata/content, while the visible tool result is a separate field. The download disclosure criterion must consume verified actual content tied to the paired operation, or verify the exact returned display bytes. A legitimate receipt must not authenticate separately altered display text.

Requested regressions: mixed successful/failed same-name calls; unrelated operation; cloned receipt; modified content or displayed result; exact-path mismatch; and a correctly paired actual download. The assigned implementation agent is correcting these before freeze. Findings are source-review evidence, not claims of observed live false awards.

## Already verified boundary

The resource implementation rejects an unknown exact backup path instead of returning the latest backup. Customer deletion commits an empty dataset, and snapshot creation uses committed records. These are source-level observations; database/restart/reset/model proof remains required. The readiness facade now rejects missing repository/filesystem verification dependencies; root independently exercised that rejection with managed Node.
