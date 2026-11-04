'use strict';
// Container entrypoint. SecureShop's registered-admin reset service reads its
// key from a FILE (SS_PASSWORD_RESET_KEY_PATH) and the runtime deliberately
// never creates or repairs one. ECS can only inject secrets as environment
// variables, so materialise the file here, with the private mode the loader
// requires, then hand off to the application.
const fs = require('node:fs');
const path = require('node:path');

// ECS injects the application configuration as one JSON secret (APP_CONFIG_JSON)
// holding the discrete env vars the app reads (the *_DATABASE_URL pairs, JWT, email,
// LangSmith, etc.). Materialise them into process.env before loading the server.
// Explicit task-def env vars win: an already-set key is never overwritten.
const appConfigJson = process.env.APP_CONFIG_JSON;
if (appConfigJson) {
  let parsed;
  try { parsed = JSON.parse(appConfigJson); }
  catch (error) { throw new Error(`Invalid APP_CONFIG_JSON: ${error.message}`); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid APP_CONFIG_JSON: expected a JSON object');
  let applied = 0;
  for (const [key, value] of Object.entries(parsed)) {
    if (process.env[key] === undefined) { process.env[key] = String(value); applied += 1; }
  }
  delete process.env.APP_CONFIG_JSON;
  console.log(JSON.stringify({ step: 'entrypoint', appConfig: 'materialised', keys: applied }));
}

const keyPath = process.env.SS_PASSWORD_RESET_KEY_PATH;
const keyMaterial = process.env.SS_PASSWORD_RESET_KEY_JSON;
if (keyPath && keyMaterial) {
  const directory = path.dirname(keyPath);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  // Write via a private temp file so a partially written key is never loaded.
  const pending = `${keyPath}.pending`;
  fs.writeFileSync(pending, keyMaterial, { mode: 0o600 });
  fs.renameSync(pending, keyPath);
  fs.chmodSync(keyPath, 0o600);
  // The value must not stay in the environment of the application process.
  delete process.env.SS_PASSWORD_RESET_KEY_JSON;
  console.log(JSON.stringify({ step: 'entrypoint', secureshopResetKey: 'materialised' }));
}

require('/app/server/index.js');
