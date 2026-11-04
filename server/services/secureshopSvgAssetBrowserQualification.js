'use strict';

const { createHash } = require('node:crypto');
const { Parser } = require('xml2js');
const SHA = /^[a-f0-9]{64}$/;
const MAX_SVG_BYTES = 256 * 1024;
const MAX_OBSERVATIONS = 64;
const ASSET_PATH = /^\/assets\/[A-Za-z0-9_-]{1,2048}$/;
const digest = value => createHash('sha256').update(value).digest('hex');
const failed = (reason, blockedRequests = []) => Object.freeze({
  version: 1,
  executed: false,
  reason,
  blockedRequests: Object.freeze(blockedRequests.map(Object.freeze)),
});
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}
function exact(value, keys) {
  return plain(value) && Reflect.ownKeys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
}
async function scripts(bytes) {
  const source = bytes.toString('utf8');
  // The first V08 contract is deliberately narrower than general SVG. Exact
  // UTF-8 XML text is accepted; transformations through entities, CDATA,
  // doctypes, processing instructions or a BOM are unavailable rather than
  // being reinterpreted as the learner's script.
  if (!Buffer.from(source, 'utf8').equals(bytes) || source.charCodeAt(0) === 0xfeff
      || /<!|<\?|&/.test(source)) return null;
  let document;
  try {
    document = await new Parser({ strict: true, explicitArray: true, explicitRoot: true,
      xmlns: true, trim: false, normalize: false }).parseStringPromise(source);
  } catch { return null; }
  if (!plain(document) || Reflect.ownKeys(document).length !== 1) return null;
  const root = document[Reflect.ownKeys(document)[0]];
  if (!plain(root) || root.$ns?.local !== 'svg' || root.$ns?.uri !== 'http://www.w3.org/2000/svg') return null;
  const values = [];
  let invalid = false;
  let nodes = 0;
  const visit = node => {
    if (!plain(node) || invalid) return;
    if (++nodes > 2048) { invalid = true; return; }
    if (node.$ns?.local === 'script') {
      const attributes = plain(node.$) ? Reflect.ownKeys(node.$) : [];
      if (node.$ns.uri !== 'http://www.w3.org/2000/svg' || attributes.length
          || typeof node._ !== 'string' || !node._ || !source.includes(node._)) { invalid = true; return; }
      if (values.length >= MAX_OBSERVATIONS) { invalid = true; return; }
      values.push(node._);
    }
    for (const [key, value] of Object.entries(node)) {
      if (['$','$ns','_'].includes(key)) continue;
      if (!Array.isArray(value)) { invalid = true; return; }
      for (const child of value) visit(child);
    }
  };
  visit(root);
  return !invalid && values.length && new Set(values).size === values.length ? values : null;
}

function createSecureShopSvgAssetBrowserQualification({
  assetOrigin,
  puppeteer,
  connectBrowser,
  timeoutMs = 8000,
  startupTimeoutMs = 30000,
  retirementTimeoutMs = 5000,
  idleCloseMs = 30000,
  maxQueue = 8,
} = {}) {
  let trustedOrigin;
  try { trustedOrigin = new URL(assetOrigin); } catch { throw new TypeError('Exact SVG asset origin required'); }
  if (trustedOrigin.origin !== assetOrigin || trustedOrigin.pathname !== '/' || trustedOrigin.search || trustedOrigin.hash
      || !['http:', 'https:'].includes(trustedOrigin.protocol)) throw new TypeError('Exact SVG asset origin required');
  if (connectBrowser !== undefined && typeof connectBrowser !== 'function') throw new TypeError('Invalid SVG browser connector');
  if (puppeteer && connectBrowser) throw new TypeError('SVG browser connector and launcher are mutually exclusive');
  for (const [value, low, high, label] of [[timeoutMs,500,15000,'timeout'],[startupTimeoutMs,500,30000,'startup timeout'],[retirementTimeoutMs,100,10000,'retirement timeout'],[idleCloseMs,100,120000,'idle timeout'],[maxQueue,1,32,'queue size']]) {
    if (!Number.isInteger(value) || value < low || value > high) throw new RangeError(`Invalid SVG browser ${label}`);
  }
  const externalBrowser = typeof connectBrowser === 'function';
  let browserPromise;
  let tail = Promise.resolve();
  let queued = 0;
  let idleTimer;
  let closed = false;
  let retirementFailure;
  let exitCleanup;
  const controllers = new Set();
  const physicalFailure = phase => Object.assign(Error(`SVG browser did not retire (${phase})`), {
    code: 'BROWSER_RETIREMENT_INCOMPLETE', phase,
  });
  const bounded = async (promise, phase) => {
    let timer;
    try {
      return await Promise.race([promise, new Promise((_, reject) => {
        timer = setTimeout(() => reject(physicalFailure(phase)), retirementTimeoutMs);
      })]);
    } finally { clearTimeout(timer); }
  };
  async function browser() {
    if (!browserPromise) {
      // BROWSER_NO_SANDBOX=1 drops the SUID sandbox on Fargate (no SYS_ADMIN); the
      // container is the isolation boundary. Unset locally keeps the real sandbox.
      const svgLaunchArgs = process.env.BROWSER_NO_SANDBOX === '1' ? ['--no-sandbox', '--disable-setuid-sandbox'] : [];
      browserPromise = Promise.resolve().then(() => externalBrowser
        ? connectBrowser()
        : (puppeteer || require('puppeteer')).launch({ headless: true, timeout: startupTimeoutMs, ...(svgLaunchArgs.length ? { args: svgLaunchArgs } : {}) }).then(value => {
          exitCleanup = () => value.process?.()?.kill?.();
          process.once('exit', exitCleanup);
          return value;
        }));
      browserPromise.catch(() => { browserPromise = undefined; });
    }
    return browserPromise;
  }
  async function releaseBrowser() {
    clearTimeout(idleTimer);
    const current = browserPromise;
    if (!current) return;
    const value = await current.catch(() => null);
    if (externalBrowser) await value?.disconnect?.();
    else await value?.close?.();
    if (browserPromise === current) {
      browserPromise = undefined;
      if (exitCleanup) process.removeListener('exit', exitCleanup);
      exitCleanup = undefined;
    }
  }
  function terminateBrowser() {
    const current = browserPromise;
    browserPromise = undefined;
    current?.then(value => {
      if (externalBrowser) value?.disconnect?.();
      else value?.process?.()?.kill?.();
    }).catch(() => {});
    if (exitCleanup) process.removeListener('exit', exitCleanup);
    exitCleanup = undefined;
  }
  function scheduleClose() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      if (queued || closed || retirementFailure) return;
      const release = tail.then(() => bounded(releaseBrowser(), 'browser_close'));
      tail = release.catch(error => { retirementFailure = error; terminateBrowser(); });
    }, idleCloseMs);
    idleTimer.unref?.();
  }
  async function run(input, signal) {
    let context;
    let page;
    let cdp;
    let profiler = false;
    let timer;
    let retirement;
    const blockedRequests = [];
    const parsed = new Map();
    const consoleCalls = [];
    let observationOverflow = false;
    let navigationAdmitted = false;
    const retire = () => {
      if (!retirement) retirement = (async () => {
        let failure;
        try { await bounded(Promise.resolve().then(() => page?.close?.()), 'page_close'); }
        catch (error) { failure = error?.code === 'BROWSER_RETIREMENT_INCOMPLETE' ? error : physicalFailure('page_close'); }
        if (context) try { await bounded(Promise.resolve().then(() => context.close()), 'context_close'); }
        catch (error) { failure ||= error?.code === 'BROWSER_RETIREMENT_INCOMPLETE' ? error : physicalFailure('context_close'); }
        if (failure) throw failure;
      })();
      return retirement;
    };
    const abort = () => { retire().catch(() => {}); };
    try {
      signal.throwIfAborted();
      const owned = await browser();
      signal.throwIfAborted();
      context = await owned.createBrowserContext();
      signal.addEventListener('abort', abort, { once: true });
      page = await context.newPage();
      cdp = await page.createCDPSession();
      await cdp.send('Network.enable');
      await cdp.send('Debugger.enable');
      await cdp.send('Runtime.enable');
      await cdp.send('Profiler.enable');
      cdp.on('Debugger.scriptParsed', event => {
        if (event.url !== input.assetUrl || !Number.isSafeInteger(event.executionContextId)) return;
        if (parsed.size >= MAX_OBSERVATIONS) { observationOverflow = true; return; }
        parsed.set(event.scriptId, { scriptId: event.scriptId, executionContextId: event.executionContextId });
      });
      cdp.on('Runtime.consoleAPICalled', event => {
        if (consoleCalls.length >= MAX_OBSERVATIONS) { observationOverflow = true; return; }
        const values = Array.isArray(event.args) ? event.args.slice(0, 16).map(arg => {
          const value = arg?.value;
          return typeof value === 'string' && Buffer.byteLength(value) <= 512 ? value : null;
        }) : [];
        const scriptIds = (event.stackTrace?.callFrames || []).slice(0, 16).map(frame => frame.scriptId).filter(Boolean);
        consoleCalls.push({ executionContextId: event.executionContextId, scriptIds, values });
      });
      await cdp.send('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
      profiler = true;
      await page.setRequestInterception(true);
      page.on('request', request => {
        const url = request.url();
        const navigation = !navigationAdmitted && request.method() === 'GET'
          && request.isNavigationRequest() && request.frame() === page.mainFrame() && url === input.assetUrl;
        if (navigation) {
          navigationAdmitted = true;
          const headers = request.headers();
          if (headers.cookie || headers.authorization || headers.origin) {
            if (blockedRequests.length < MAX_OBSERVATIONS) blockedRequests.push({ url, resourceType: request.resourceType(), reason: 'credentialed_navigation' });
            else observationOverflow = true;
            request.abort('blockedbyclient').catch(() => {});
          } else request.continue().catch(() => {});
          return;
        }
        if (blockedRequests.length < MAX_OBSERVATIONS) blockedRequests.push({ url: url.slice(0, 500), resourceType: request.resourceType(), reason: 'subresource' });
        else observationOverflow = true;
        request.abort('blockedbyclient').catch(() => {});
      });
      const response = await page.goto(input.assetUrl, { waitUntil: 'load', timeout: timeoutMs });
      signal.throwIfAborted();
      if (observationOverflow) return failed('browser_observation_overflow', blockedRequests);
      if (!response || response.url() !== input.assetUrl || response.status() !== 200) return failed('asset_response_unavailable', blockedRequests);
      const headers = Object.fromEntries(Object.entries(response.headers()).map(([key,value]) => [key.toLowerCase(), value]));
      if (headers['content-type'] !== input.expected.contentType
          || headers['content-security-policy'] !== input.expected.contentSecurityPolicy
          || headers['content-encoding']) return failed('asset_headers_mismatch', blockedRequests);
      const bytes = Buffer.from(await response.buffer());
      const responseSha256 = digest(bytes);
      if (bytes.length !== input.expected.byteCount || responseSha256 !== input.expected.bodySha256) return failed('asset_bytes_mismatch', blockedRequests);
      const sourceScripts = await scripts(bytes);
      if (!sourceScripts?.length) return failed('svg_inline_script_unavailable', blockedRequests);
      await new Promise(resolve => { timer = setTimeout(resolve, 80); });
      signal.throwIfAborted();
      const coverage = (await cdp.send('Profiler.takePreciseCoverage')).result || [];
      if (observationOverflow || coverage.length > MAX_OBSERVATIONS
          || coverage.some(entry => !Array.isArray(entry.functions) || entry.functions.length > MAX_OBSERVATIONS
            || entry.functions.some(fn => !Array.isArray(fn.ranges) || fn.ranges.length > MAX_OBSERVATIONS)))
        return failed('browser_observation_overflow', blockedRequests);
      let executedScript;
      let executedScriptId;
      let executionContextId;
      for (const entry of coverage) {
        const event = parsed.get(entry.scriptId);
        if (!event || !entry.functions?.some(fn => fn.ranges?.some(range => range.count > 0))) continue;
        const source = (await cdp.send('Debugger.getScriptSource', { scriptId: entry.scriptId })).scriptSource;
        if (!sourceScripts.includes(source) || !source.includes(input.expected.marker)
            || sourceScripts.filter(value => value.includes(input.expected.marker)).length !== 1) continue;
        executedScript = source;
        executedScriptId = entry.scriptId;
        executionContextId = event.executionContextId;
        break;
      }
      if (!executedScript) return failed('svg_script_not_executed', blockedRequests);
      const markerObserved = consoleCalls.some(call => call.executionContextId === executionContextId
        && call.scriptIds.includes(executedScriptId)
        && call.values.some(value => value === input.expected.marker));
      if (!markerObserved) return failed('svg_effect_not_observed', blockedRequests);
      const cookies = typeof context.cookies === 'function' ? await context.cookies() : await page.cookies();
      if (!Array.isArray(cookies) || cookies.length) return failed('browser_state_not_isolated', blockedRequests);
      return Object.freeze({
        version: 1,
        executed: true,
        reason: 'svg_script_coverage_and_console_effect',
        asset: Object.freeze({
          status: 200,
          contentType: headers['content-type'],
          contentSecurityPolicy: headers['content-security-policy'],
          byteCount: bytes.length,
          bodySha256: responseSha256,
        }),
        script: Object.freeze({
          sourceSha256: digest(executedScript),
          markerSha256: digest(input.expected.marker),
          executionContextId,
          preciseCoverage: true,
          markerObserved: true,
          consoleStackJoined: true,
        }),
        isolatedContext: true,
        blockedRequests: Object.freeze(blockedRequests.map(Object.freeze)),
      });
    } catch (error) {
      if (signal.aborted) throw signal.reason;
      return failed(error?.name === 'TimeoutError' ? 'qualification_timeout' : 'qualification_error', blockedRequests);
    } finally {
      signal.removeEventListener('abort', abort);
      clearTimeout(timer);
      let teardownFailure;
      const teardown = (async () => {
        if (profiler) await cdp?.send('Profiler.stopPreciseCoverage').catch(() => {});
        await cdp?.send('Profiler.disable').catch(() => {});
        await cdp?.send('Runtime.disable').catch(() => {});
        await cdp?.send('Debugger.disable').catch(() => {});
        await cdp?.send('Network.disable').catch(() => {});
        await cdp?.detach?.().catch(() => {});
      })();
      try { await bounded(teardown, 'cdp_teardown'); } catch (error) { teardownFailure = error; }
      try { await bounded(retire(), 'context_close'); } catch (error) { teardownFailure ||= error; }
      if (teardownFailure) throw teardownFailure;
    }
  }
  function normalize(input) {
    if (!exact(input, ['assetUrl','expected']) || !exact(input.expected,
      ['byteCount','bodySha256','contentType','contentSecurityPolicy','marker'])) throw new TypeError('Exact SVG qualification input required');
    const url = new URL(input.assetUrl);
    const marker = input.expected.marker;
    if (url.origin !== trustedOrigin.origin || !ASSET_PATH.test(url.pathname) || url.search || url.hash
        || !Number.isSafeInteger(input.expected.byteCount) || input.expected.byteCount < 1 || input.expected.byteCount > MAX_SVG_BYTES
        || !SHA.test(input.expected.bodySha256) || input.expected.contentType !== 'image/svg+xml'
        || input.expected.contentSecurityPolicy !== 'sandbox allow-scripts'
        || typeof marker !== 'string' || !marker || Buffer.byteLength(marker) > 256 || /[\0\r\n]/.test(marker)) throw new TypeError('Exact SVG qualification input required');
    return Object.freeze({ assetUrl: url.href, expected: Object.freeze({...input.expected}) });
  }
  function qualify(raw, { signal } = {}) {
    const input = normalize(raw);
    if (closed || retirementFailure) return Promise.reject(retirementFailure || Error('qualification_closed'));
    if (signal?.aborted) return Promise.reject(signal.reason);
    if (queued >= maxQueue) return Promise.resolve(failed('qualification_queue_full'));
    queued++;
    clearTimeout(idleTimer);
    const controller = new AbortController();
    controllers.add(controller);
    const relay = () => controller.abort(signal.reason);
    signal?.addEventListener('abort', relay, { once: true });
    let timeout;
    const operation = tail.then(async () => {
      if (closed || retirementFailure) throw retirementFailure || Error('qualification_closed');
      let expired = false;
      const work = run(input, controller.signal);
      const expiry = new Promise(resolve => { timeout = setTimeout(() => {
        expired = true;
        controller.abort(Error('qualification_timeout'));
        resolve(failed('qualification_timeout'));
      }, startupTimeoutMs + timeoutMs); });
      const result = await Promise.race([work, expiry]);
      // A public timeout does not release the serialized queue until the owned
      // work has either retired or crossed the hard retirement deadline.
      if (expired) try { await bounded(work, 'expired_work'); }
      catch (error) {
        if (error?.code === 'BROWSER_RETIREMENT_INCOMPLETE') {
          retirementFailure = error;
          terminateBrowser();
          throw error;
        }
        // The expected abort is safe only after run() completed its bounded
        // finally path; typed retirement failures are never swallowed.
      }
      return result;
    });
    tail = operation.then(() => undefined, error => {
      if (error?.code === 'BROWSER_RETIREMENT_INCOMPLETE') { retirementFailure = error; terminateBrowser(); }
    });
    return operation.finally(() => {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', relay);
      controllers.delete(controller);
      queued--;
      scheduleClose();
    });
  }
  async function close() {
    closed = true;
    clearTimeout(idleTimer);
    for (const controller of controllers) controller.abort(Error('qualification_closed'));
    let failure;
    try { await bounded(tail, 'queue'); } catch (error) { failure = error; }
    try { await bounded(releaseBrowser(), 'browser_close'); } catch (error) { failure ||= error; terminateBrowser(); }
    if (failure) throw failure;
  }
  return Object.freeze({ qualify, close });
}

module.exports = { createSecureShopSvgAssetBrowserQualification };
