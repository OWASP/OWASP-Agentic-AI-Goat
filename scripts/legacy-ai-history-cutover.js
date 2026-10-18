#!/usr/bin/env node
'use strict';

// No dotenv/startup hooks: only explicitly provided migration environment is used.
const { createLegacyAiHistoryOperator } = require('../server/services/legacyAiHistoryOperator');
const HELP = `Usage:
  node scripts/legacy-ai-history-cutover.js plan --plan-file /private/path/plan.json
  node scripts/legacy-ai-history-cutover.js quarantine --plan-file /private/path/plan.json --receipt-file /private/path/receipt.json
  node scripts/legacy-ai-history-cutover.js cleanup --plan-file /private/path/plan.json --receipt-file /private/path/receipt.json

Required environment: LEGACY_CHALLENGE_MIGRATION_DATABASE_URL, IDENTITY_MIGRATION_DATABASE_URL.
Review the plan's source/target endpoints, databases, row count and digest before quarantine.
Quarantine preserves unknown history; it proves no ownership and restores no learner history.
Cleanup is a separate explicit exact-row removal after verified quarantine. Retry with the same files.
Files must be private, owned by the current user, under a non-symlink directory owned by that user.
No credentials or raw prompts are printed or written to the plan/receipt. Existing files are never overwritten.
`;
function parse(argv) {
  if (argv.length === 1 && argv[0] === '--help') return null;
  const [command, ...args] = argv;
  if (!['plan','quarantine','cleanup'].includes(command) || args.length % 2) throw new Error('Invalid arguments');
  const options = { command };
  for (let i = 0; i < args.length; i += 2) {
    const key = ({ '--plan-file': 'planPath', '--receipt-file': 'receiptPath' })[args[i]];
    if (!key || Object.hasOwn(options, key) || !args[i+1] || args[i+1].startsWith('--')) throw new Error('Invalid arguments');
    options[key] = args[i+1];
  }
  if (!options.planPath || (command === 'plan' ? options.receiptPath !== undefined : !options.receiptPath)) throw new Error('Invalid arguments');
  return options;
}
async function main(argv = process.argv.slice(2), { operator = createLegacyAiHistoryOperator(), output = console } = {}) {
  try {
    const options = parse(argv);
    if (!options) { output.log(HELP); return 0; }
    const result = await operator.execute(options);
    output.log(JSON.stringify(result));
    return 0;
  } catch {
    output.error('Legacy AI history action failed. Review private files, store bindings and migration readiness. Run --help for usage.');
    return 1;
  }
}
if (require.main === module) main().then(code => { process.exitCode = code; });
module.exports = { main, parse };
