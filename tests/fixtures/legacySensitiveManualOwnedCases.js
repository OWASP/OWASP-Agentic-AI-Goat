'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { FILE_FLAGS } = require('../../server/config/legacySensitiveFlags');
const { createLegacySensitiveTools } = require('../../server/services/legacySensitiveTools');

const within = (root, target) => {
  const relative = path.relative(root, target);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
};

// Retained Legacy Sensitive runtime only; this does not qualify the visible
// FinFlow UI or HTTP route wiring. No case requires an actor-model decision.
// The caller owns cleanup. This builder never discovers application fixture
// paths, reads environment configuration, or starts a provider/database.
function createLegacySensitiveManualOwnedCases({ ownedRoot } = {}) {
  if (typeof ownedRoot !== 'string' || !path.isAbsolute(ownedRoot)) throw new TypeError('An explicit absolute owned root is required');
  const root = fs.realpathSync(ownedRoot);
  const workspace = fs.realpathSync(path.resolve(__dirname, '../..'));
  if (root !== path.resolve(ownedRoot) || within(workspace, root) || within(root, workspace)
      || !fs.statSync(root).isDirectory() || fs.readdirSync(root).length) {
    throw new TypeError('An empty, non-symlink owned directory outside the workspace is required');
  }
  const flag = FILE_FLAGS[0];
  const apiKey = 'synthetic-manual-api-key';
  const templates = {
    genuine: `${flag}\n<!--#echo var="REMOTE_USER" -->`,
    unknown: `${flag}\n<!--#echo var="UNRECOGNIZED_MANUAL_VARIABLE" -->`,
    simulated: `${flag}\n<!--#exec cmd="whoami" -->`,
  };
  fs.mkdirSync(path.join(root, 'public'), { mode: 0o700 });
  fs.mkdirSync(path.join(root, 'secret'), { mode: 0o700 });
  for (const [name, content] of Object.entries({
    'secret/record.txt': flag, 'public/record.txt': flag,
    'secret/genuine.txt': templates.genuine, 'secret/unknown.txt': templates.unknown,
    'secret/simulated.txt': templates.simulated,
  })) fs.writeFileSync(path.join(root, name), content, { flag: 'wx', mode: 0o600 });
  const tools = createLegacySensitiveTools({ sensitiveFilesDir: root, ssiValues: { API_KEY: apiKey } });
  const cases = [];
  const add = (name, objectiveId, operation, args, expected, core = true) => cases.push(Object.freeze({
    name, objectiveId, operation, args: Object.freeze(args), core,
    request: JSON.stringify(args), expected: Object.freeze(expected),
    invoke: () => tools[operation](args),
  }));
  const read = (name, target, protectedPath, core = true) => add(name, 'path_traversal', 'readTeachingFile', { path: target },
    { completed: protectedPath, success: true, protectedPath, knownFlag: true, content: flag }, core);
  read('traversal_protected', '../secret/record.txt', true);
  read('traversal_public', 'record.txt', false);
  add('ssi_known_echo', 'ssi_injection', 'renderSsiTemplate', { template: '<!--#echo var="API_KEY" -->' },
    { completed: true, success: true, ssiSucceeded: true, knownFlag: false, rendered: apiKey });
  add('ssi_simulated_exec', 'ssi_injection', 'renderSsiTemplate', { template: '<!--#exec cmd="whoami" -->' },
    { completed: false, success: true, ssiSucceeded: false, knownFlag: false, rendered: '<pre>www-data</pre>', commandExecution: 'simulated' });
  const combined = (name, file, ssiSucceeded, rendered, core = true, processSsi = true) =>
    add(name, 'combined_traversal_ssi', 'processTeachingDocument', { path: `../secret/${file}.txt`, processSsi },
      { completed: ssiSucceeded, success: true, protectedPath: true, knownFlag: true, ssiSucceeded, rendered }, core);
  combined('combined_known_echo', 'genuine', true, `${flag}\nguest_user`);
  combined('combined_unknown_echo', 'unknown', false, `${flag}\n[UNRECOGNIZED_MANUAL_VARIABLE]`);
  add('ssi_failed_include', 'ssi_injection', 'renderSsiTemplate', { template: '<!--#include file="missing.txt" -->' },
    { completed: false, success: true, ssiSucceeded: false, knownFlag: false, rendered: '[Error: File not found: missing.txt]' }, false);
  add('ssi_unknown_echo', 'ssi_injection', 'renderSsiTemplate', { template: '<!--#echo var="UNRECOGNIZED_MANUAL_VARIABLE" -->' },
    { completed: false, success: true, ssiSucceeded: false, knownFlag: false, rendered: '[UNRECOGNIZED_MANUAL_VARIABLE]' }, false);
  combined('combined_without_processing', 'genuine', false, templates.genuine, false, false);
  combined('combined_simulated_exec', 'simulated', false, `${flag}\n<pre>www-data</pre>`, false);
  add('traversal_outside_root', 'path_traversal', 'readTeachingFile', { path: '../../outside-owned-root.txt' },
    { completed: false, success: false, protectedPath: false, knownFlag: false, code: 'TEACHING_PATH_OUTSIDE_ROOT' }, false);
  return Object.freeze(cases);
}

module.exports = { createLegacySensitiveManualOwnedCases };
