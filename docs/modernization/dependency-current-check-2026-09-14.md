# Dependency verification — September 14, 2026

Read-only `npm outdated --json` checks returned `{}` with exit 0 in the repository root, `client`, and `agent-host`. Root and client results were collected from their existing execution handles 10116 and 16005; the agent-host check completed directly. These results cover npm's direct-dependency update report, not every transitive package, operating-system runtime, compatibility guarantee, or clean installation.

The checks used the managed Node 26.8.2 runtime. Current declarations remain React 19.3.0, Vite 8.3.0, Express 5.2.1, pg 8.23.0, LangChain 1.5.11, LangGraph 1.4.15, LangChain core 1.2.11 and Ollama adapter 1.3.0. Root engines remain `^24.15.0 || >=26.0.0`.

`scripts/verify-learning-dependencies.js` passed: 0 protected entries, 0 investigate/frozen entries and 4 current-reviewed entries. The rationale for those reviewed dependencies remains in `learning-dependency-investigation-2026-09-13.md`. This check does not establish that all intentional exploit paths still work; their vulnerability and connected exercise tests remain separate requirements.

No dependency, lockfile, runtime installation, AWS asset, or deployment setting was changed by these checks. Clean installation qualification remains open.
