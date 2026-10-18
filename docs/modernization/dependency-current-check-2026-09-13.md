# Current dependency verification — September 13, 2026

Read-only registry checks completed successfully: `npm outdated --json` returned `{}` in both repository root and `client`. This verifies direct dependencies against npm tags at this checkpoint, not every transitive dependency or operating-system package.

`npm run verify:learning-dependencies` passed: 0 protected entries, 0 frozen investigations and 4 current-reviewed entries. The reasons those four no longer require older versions are recorded in `learning-dependency-investigation-2026-09-13.md`; this check did not alter that curriculum policy or any package.

Current shell Node: 26.7.0. Declared engines: `^24.15.0 || >=26.0.0`. Current declared key versions: React19.3.0, Vite8.3.0, Express5.2.1, pg8.23.0, LangChain1.5.11, LangGraph1.4.15, LangChain core1.2.11 and Ollama adapter1.3.0. These are observed installed-workspace declarations, not fresh macOS/Linux installation qualification.

No dependency, lockfile, AWS or deployment modification was made by this check. Full clean-install and workshop capacity qualification remain open.
