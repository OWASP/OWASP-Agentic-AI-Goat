'use strict';

// Local image entry only. A mode selects one existing listener; it never enables
// the listener, creates credentials, or substitutes an executor dependency.
async function runLocalSystemListener({ argv = process.argv.slice(2), env = process.env,
  runConfig = options => require('./http-listener').runSystemConfigListener(options),
  runDiagnostic = options => require('./diagnostic-http-listener').runSystemDiagnosticListener(options),
  runRestart = options => require('./restart-http-listener').runRestartHttpListener(options),
  runUploadPreview = options => require('./upload-preview-http-listener').runUploadPreviewListener(options),
  write = text => process.stdout.write(text) } = {}) {
  if (!Array.isArray(argv) || argv.length !== 1 || !['config', 'diagnostic', 'restart', 'upload-preview'].includes(argv[0])) {
    write('SYSTEM_LOCAL_LISTENER_MODE_INVALID\n');
    return 1;
  }
  try {
    return await (argv[0] === 'config' ? runConfig : argv[0] === 'diagnostic' ? runDiagnostic : argv[0] === 'restart' ? runRestart : runUploadPreview)({ env, write });
  } catch {
    write('SYSTEM_LOCAL_LISTENER_FAILED\n');
    return 1;
  }
}

if (require.main === module) {
  runLocalSystemListener().then(code => { process.exitCode = code; }, () => { process.exitCode = 1; });
}
module.exports = { runLocalSystemListener };
