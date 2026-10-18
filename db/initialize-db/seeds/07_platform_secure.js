// platform_secure.db: optional default platform users; app may sync from auth. No seed required for minimal run.
function runSeed(_dbPath) {
  return Promise.resolve();
}

module.exports = { runSeed };
