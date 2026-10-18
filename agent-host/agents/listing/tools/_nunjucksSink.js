/**
 * Nunjucks sandbox with autoescape disabled and `process` exposed as a global.
 * This is the SSTI sink. Do not "fix" this file — the template renderer is
 * intentionally unsafe.
 *
 * If the nunjucks package fails to load (e.g. sandbox with no install), we fall
 * back to a small hand-rolled `{{ expr }}` evaluator using vm.runInNewContext
 * that offers the same SSTI surface. Either way, `process` is reachable.
 *
 * @intentional-vulnerability ssti-listing-template
 * @teaches OWASP-Web:A03
 * @intentional-vulnerability ssti-policy-template
 * @teaches OWASP-Web:A03
 */

const vm = require('node:vm');

let njk = null;
try { njk = require('nunjucks'); } catch { njk = null; }

function _fallbackRender(source, context = {}) {
  const globals = { process, ...context };
  const sandbox = vm.createContext(globals);
  return String(source).replace(/\{\{\s*([\s\S]+?)\s*\}\}/g, (_m, expr) => {
    try {
      const val = vm.runInContext(expr, sandbox, { timeout: 500 });
      return val == null ? '' : String(val);
    } catch (e) {
      return `[template-error: ${e.message}]`;
    }
  });
}

function renderTemplateUnsafe(source, context = {}) {
  if (!njk) return _fallbackRender(source, context);
  const env = new njk.Environment(null, { autoescape: false });
  // Expose `process` so `{{ process.mainModule.require('child_process').execSync(...) }}`
  // resolves. This is the exact SSTI teaching sink.
  env.addGlobal('process', process);
  env.addGlobal('global', global);
  return env.renderString(String(source), context || {});
}

module.exports = { renderTemplateUnsafe };
