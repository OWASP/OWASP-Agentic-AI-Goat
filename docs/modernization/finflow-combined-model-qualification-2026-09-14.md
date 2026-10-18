# FinFlow combined model qualification

The isolated combined candidate passed on September 14, 2026 (September 15 UTC). This qualifies the tested private candidate, not live activation or the whole application.

## Scope and result

Five tests passed with no failures or skips. Actual local `llama3.1:8b` actor and Judge calls qualified the access-log and LLM-log objectives with benign, fixed-mode and reset controls, and the `traversal_secrets` objective with actual file reads, durable completion, owner isolation, canonical reset, file removal and immutable run history. Admission rechecking used an explicitly separate model stub and awarded no objective credit.

## Reproducible evidence

- Candidate: `/tmp/finflow-combined-smoke-candidate.pfksxo4w`
- Manifest SHA-256: `6ba8fd7dfaee338afca43e7e5a9f855d7c0aaa4d6a83bf2f71228d7f2b7a6e8f`
- Evidence directory: `/Users/averma5/.dvaia/native-verification/dvaia-finflow-combined-smoke-dm_n3q0y`
- Native owner handle: `50598`; terminal exit: `0`.
- Combined log SHA-256: `f38923363e173b2a518d6a5668bb578e24e02ed66236b361254e48ca8dbd0e94`
- Policy evidence SHA-256: `7bf707dce965125e5e7ab8493972a46a39902c6e7e75852e54dfae6c945637cc`
- Traversal evidence SHA-256: `464c4cc967d06a98a38c1f9f207b879af01258e8d242170ea8ba7102c56fc342`
- Ownership evidence SHA-256: `6635c9af3bea4e52563c6a75037cb2674ef8957cd6cf57153e297814ae09850b`

Root independently verified all 281 candidate and staged source files, the explicitly declared synthetic access-log fixture override, terminal cleanup and absence of the exact owned container by ID and name. Main application service and `.env` hashes remained unchanged. The access log is a real isolated file containing a synthetic teaching entry; it is not a host or provider log.

## Remaining work

Admin config/directory artifacts, durable customer/backup agent integration, their migrations and actual-model qualification remain separate pending work. This result does not establish full FinFlow, SecureShop, browser, installer or 200-concurrent-LLM readiness.
