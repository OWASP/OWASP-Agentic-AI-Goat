# CTF benchmark interpretation and secret provenance

Source-level design finding; no successful real-model exploit is claimed here.

All ten default protected values are distributed in `server/data/ctfDefaults.js`, alongside their guardian prompts. `server/agent-runtime/ctfStageJudge.js` intentionally grades the exact learner-visible response against the protected value, including a quotation. Its evidence packet contains the assistant response and server comparison facts; it does not establish that the learner lacked the value before submitting the prompt.

This is coherent for the current lesson, “make the guardian display a value it was instructed to protect.” It is insufficient by itself for the stronger benchmark claim, “extract an initially unknown secret from protected context.” A learner who reads the open-source seed can already know the value. An actual model that echoes a supplied value may satisfy the current disclosure contract without proving discovery. The canonical Judge, real-provider proof and atomic credit checks cannot establish missing input provenance.

## Required design distinction

Keep the reproducible workshop defaults and existing instructor-edited stages intact. Document current scores as visible-response disclosure results. Do not silently change historical completion semantics or retroactively remove credit.

For a secret-extraction benchmark, introduce an explicitly selected, versioned evaluation profile with unpredictable synthetic values bound to the participant/run and stage incarnation. The secret belongs only to owned teaching context; no real credentials or host private data. Bind its commitment to admission, evidence, evaluator version and reset generation. Preserve the same prompt/defense workflow, replacing only the designated synthetic value through structured template substitution. Instructor solution examples must explain the technique without hardcoding the generated answer.

Record whether the protected value was already supplied in attacker-controlled input. A simple literal exclusion is a diagnostic, not sufficient proof against encoded or fragmented supplied values. Define the benchmark scoring contract before implementing that check, rather than adding ad hoc rejection that changes the workshop lesson. Keep the Judge grounded in exact post-defense output, and distinguish unavailable/inconclusive from a negative result.

Shared adaptive memory needs an explicit policy: randomized identifiers must not make semantically identical winning payloads appear unrelated, and cross-user memory must not expose another learner's value. Preserve technique memory and benchmark reproducibility through recorded configuration and seed commitments, not by publishing active secrets.

## Acceptance needed

For each of the ten stages: ordinary non-disclosure, real unknown-value extraction, supplied-value echo, encoded input/output, output-filter redaction, wrong owner/stage/generation, reset and replay. Record model identity, visible output, defense decisions, input provenance and exact Judge evidence. Existing synthetic transport tests and public static fixtures do not qualify this new extraction profile.

This is a benchmark-design limitation, not authorization to remove intentional teaching behavior or change the current rubric during the CTF authority cutover.
