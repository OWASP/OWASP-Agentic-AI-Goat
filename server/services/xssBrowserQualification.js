'use strict';

const { randomBytes, createHash } = require('node:crypto');
const MAX_HTML_BYTES = 20000;

function exactSourceRanges(html, source) {
  if (typeof source !== 'string' || !source.length) return null;
  const ranges = [];
  for (let offset = 0; offset <= html.length - source.length;) {
    const start = html.indexOf(source, offset);
    if (start < 0) break;
    ranges.push({ start, end: start + source.length });
    offset = start + Math.max(1, source.length);
  }
  return ranges;
}

function inlineScriptLocations(html, source) {
  const locations = [];
  const sourceRanges = exactSourceRanges(html, source);
  const pattern = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  for (const match of html.matchAll(pattern)) {
    const attributes = match[1] || '';
    if (/\bsrc\s*=/i.test(attributes)) continue;
    const type = /\btype\s*=\s*["']?([^\s"'>]+)/i.exec(attributes)?.[1]?.toLowerCase();
    if (type && !['module', 'text/javascript', 'application/javascript', 'text/ecmascript', 'application/ecmascript'].includes(type)) continue;
    if (sourceRanges && !sourceRanges.some(range => match.index >= range.start
      && match.index + match[0].length <= range.end)) continue;
    const contentOffset = match.index + match[0].indexOf('>') + 1;
    const before = html.slice(0, contentOffset);
    const lines = before.split('\n');
    locations.push({ line: lines.length - 1, column: lines.at(-1).length });
  }
  return locations;
}

function instrumentEventSource(html, source, token, bindingName) {
  if (typeof source !== 'string' || !source.length || !html.includes(source)) return html;
  // Use no string literal so this prefix remains valid in either quote style.
  const proofCall = `globalThis.${bindingName}(String(0x${token}n));`;
  const instrumented = source
    .replace(/(\bon[a-z]+\s*=\s*)(["'])([\s\S]*?)\2/gi,
      (_match, prefix, quote, code) => `${prefix}${quote}${proofCall}${code}${quote}`)
    .replace(/(\bon[a-z]+\s*=\s*)([^\s"'>]+)/gi,
      (_match, prefix, code) => `${prefix}${proofCall}${code}`)
    // This also covers a field value substituted into an existing href.
    .replace(/javascript\s*:/gi, scheme => `${scheme}${proofCall}`);
  return html.split(source).join(instrumented);
}

function projectTargetHtml({ candidate, proof }) {
  if (!proof) return candidate;
  const template = document.createElement('template');
  template.innerHTML = candidate;
  const visit = root => {
    for (const node of root.querySelectorAll('*')) {
      for (const attribute of [...node.attributes]) {
        const name = attribute.name.toLowerCase();
        const normalized = attribute.value.replace(/[\u0000-\u0020]/g, '').toLowerCase();
        const executable = /^on/.test(name)
          || (['href', 'xlink:href', 'src'].includes(name) && normalized.startsWith('javascript:'));
        if ((executable && !attribute.value.includes(proof)) || name === 'srcdoc'
          || (['href', 'xlink:href', 'src'].includes(name) && normalized.startsWith('data:text/html'))) {
          node.removeAttribute(attribute.name);
        }
      }
      // Script tags inserted through innerHTML are inert already. The
      // explicit type also prevents later target code from moving an
      // unrelated script into a fresh document and executing it.
      if (node.localName === 'script') node.setAttribute('type', 'application/json');
      if (node.localName === 'template') visit(node.content);
    }
  };
  visit(template.content);
  return template.innerHTML;
}

function createXssBrowserQualification({ puppeteer, connectBrowser, clientMount, clientDomCapture,
  timeoutMs = 8000, startupTimeoutMs = 30000, maxQueue = 8, idleCloseMs = 30000,
  retirementTimeoutMs = 5000 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 500 || timeoutMs > 15000) throw new RangeError('Invalid XSS browser timeout');
  if (!Number.isInteger(startupTimeoutMs) || startupTimeoutMs < 500 || startupTimeoutMs > 30000) {
    throw new RangeError('Invalid XSS browser startup timeout');
  }
  if (!Number.isInteger(maxQueue) || maxQueue < 1 || maxQueue > 32) throw new RangeError('Invalid XSS browser queue size');
  if (connectBrowser !== undefined && typeof connectBrowser !== 'function') {
    throw new TypeError('Invalid XSS browser connector');
  }
  if (connectBrowser && puppeteer) throw new TypeError('XSS browser connector and launcher are mutually exclusive');
  if (clientMount !== undefined && typeof clientMount !== 'function') throw new TypeError('Invalid client mount');
  if (!Number.isInteger(retirementTimeoutMs) || retirementTimeoutMs < 100 || retirementTimeoutMs > 10000) throw new RangeError('Invalid browser retirement timeout');
  if (clientDomCapture !== undefined && (typeof clientDomCapture !== 'function' || !clientMount)) throw new TypeError('Invalid client DOM capture');
  const externalBrowser = typeof connectBrowser === 'function';
  let browserPromise;
  let tail = Promise.resolve();
  let queued = 0;
  let idleTimer;
  let exitCleanup;
  let closed = false;
  let retirementFailure;
  const jobs = new Set();
  const physicalFailure = phase => Object.assign(new Error(`Browser work has not retired (${phase})`),
    { code: 'BROWSER_RETIREMENT_INCOMPLETE', phase });
  async function boundedRetirement(work, phase = () => 'browser_release') {
    let timer;
    try { return await Promise.race([work, new Promise((_, reject) => { timer = setTimeout(() => reject(physicalFailure(phase())), retirementTimeoutMs); })]); }
    finally { clearTimeout(timer); }
  }

  async function getBrowser() {
    if (!browserPromise) {
      if (externalBrowser) browserPromise = Promise.resolve().then(connectBrowser);
      else {
        const api = puppeteer || require('puppeteer');
        // Do not weaken Chrome's sandbox. Each qualification also receives a new
        // BrowserContext, synthetic cookie, and a fully intercepted network.
        browserPromise = api.launch({ headless: true, timeout: startupTimeoutMs }).then(browser => {
          // Synchronous process cleanup is the last line of defence if normal
          // async close hooks cannot run during process exit.
          exitCleanup = () => browser.process()?.kill();
          process.once('exit', exitCleanup);
          return browser;
        });
      }
      browserPromise.catch(() => { browserPromise = undefined; });
    }
    return browserPromise;
  }

  async function releaseBrowser() {
    clearTimeout(idleTimer);
    const pending = browserPromise;
    if (pending) {
      const browser = await pending.catch(() => null);
      if (externalBrowser) await browser?.disconnect?.();
      else await browser?.close();
    }
    // Keep the exact pending owner reachable by hard retirement until close
    // settles. Queue serialization prevents replacement during this interval.
    if (browserPromise === pending) {
      browserPromise = undefined;
      if (exitCleanup) process.removeListener('exit', exitCleanup);
      exitCleanup = undefined;
    }
  }

  async function close() {
    closed = true;
    clearTimeout(idleTimer);
    for (const job of jobs) job.abort(new Error('qualification_closed'));
    try {
      await boundedRetirement(tail);
      if (retirementFailure) throw retirementFailure;
      await boundedRetirement(releaseBrowser());
    } catch (error) {
      retirementFailure = error;
      terminateBrowser();
      throw error;
    }
  }

  function terminateBrowser() {
    const pending = browserPromise;
    browserPromise = undefined;
    pending?.then(browser => {
      if (externalBrowser) browser?.disconnect?.();
      else browser.process()?.kill();
      // Launch may have settled only after termination was requested.
      if (exitCleanup) process.removeListener('exit', exitCleanup);
      exitCleanup = undefined;
    }).catch(() => {});
  }

  function scheduleIdleClose() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      if (queued || closed || retirementFailure) return;
      const release = tail.then(() => boundedRetirement(releaseBrowser()));
      tail = release.catch(error => { retirementFailure = error; terminateBrowser(); });
    }, idleCloseMs);
    idleTimer.unref?.();
  }

  async function run(html, signal, renderingMode = 'innerHTML', qualification = {},
    onPhase = () => {}, onBrowserReady = () => {}) {
    if (typeof html !== 'string' || Buffer.byteLength(html) > MAX_HTML_BYTES) {
      return { executed: false, reason: 'invalid_or_oversized_html', blockedRequests: [], learnerElementPreserved: false };
    }
    let context;
    let page;
    let cdp;
    let profilerStarted = false;
    const parsedScripts = new Map();
    const blockedRequests = [];
    const browserEffects = [];
    const origin = 'http://xss-qualification.invalid/';
    const eventSources = (Array.isArray(qualification.eventSources)
      ? qualification.eventSources : [qualification.eventSource])
      .filter(source => typeof source === 'string' && source.length && html.includes(source));
    const eventToken = eventSources.length ? randomBytes(16).toString('hex') : null;
    const eventPayload = eventToken ? BigInt(`0x${eventToken}`).toString() : null;
    const bindingName = eventToken ? `__owasp-ai-goatTarget_${randomBytes(12).toString('hex')}` : null;
    const proofCall = eventToken ? `globalThis.${bindingName}(String(0x${eventToken}n));` : null;
    const browserHtml = eventToken ? eventSources.reduce((document, source) =>
      instrumentEventSource(document, source, eventToken, bindingName), html) : html;
    const learnerHtml = typeof qualification.learnerHtml === 'string'
      && Buffer.byteLength(qualification.learnerHtml) <= MAX_HTML_BYTES
      ? qualification.learnerHtml : null;
    let timer;
    let targetBindingCalled = false;
    let domCapture;
    let learnerElementPreserved = false;
    let learnerElementTag = null;
    let retirement;
    const retireContext = () => {
      if (!retirement) retirement = (async () => {
        // Close in ownership order and reuse this promise on abort/finally.
        // A successful context close also confirms retirement of its pages.
        let pageError;
        try { await page?.close(); } catch (error) { pageError = error; }
        if (context) {
          try { await context.close(); } catch { throw physicalFailure('context_close'); }
        } else if (pageError) throw physicalFailure('page_close');
      })();
      return retirement;
    };
    const closeOnAbort = () => { retireContext().catch(() => {}); };
    try {
      if (signal?.aborted) throw signal.reason;
      onPhase('browser_launch');
      const browser = await getBrowser();
      if (signal?.aborted) throw signal.reason;
      onBrowserReady();
      onPhase('context_creation');
      context = await browser.createBrowserContext();
      signal?.throwIfAborted();
      // CDP setup and page creation can stall under load. Once the context is
      // owned, cancellation must close it even if one of those calls is pending.
      signal?.addEventListener('abort', closeOnAbort, { once: true });
      onPhase('page_creation');
      page = await context.newPage();
      signal?.throwIfAborted();
      page.on('dialog', dialog => {
        browserEffects.push({ kind: dialog.type(), value: dialog.message().slice(0, 200) });
        dialog.dismiss().catch(() => {});
      });
      page.on('popup', popup => {
        browserEffects.push({ kind: 'window_open', value: popup.url().slice(0, 200) });
        popup.close().catch(() => {});
      });
      if (renderingMode === 'document' || eventToken) {
        onPhase('cdp_setup');
        cdp = await page.createCDPSession();
        await cdp.send('Debugger.enable');
        cdp.on('Debugger.scriptParsed', event => parsedScripts.set(event.scriptId, event));
        await cdp.send('Runtime.enable');
        if (bindingName) {
          cdp.on('Runtime.bindingCalled', event => {
            if (event.name === bindingName && event.payload === eventPayload) targetBindingCalled = true;
          });
          await cdp.send('Runtime.addBinding', { name: bindingName });
        }
        await cdp.send('Profiler.enable');
        await cdp.send('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
        profilerStarted = true;
      }
      onPhase('page_setup');
      await page.setRequestInterception(true);
      page.on('request', request => {
        if (request.isNavigationRequest() && request.url() === origin) {
          const body = renderingMode === 'document'
            ? `<!doctype html><meta charset="utf-8">${browserHtml}`
            : '<!doctype html><meta charset="utf-8"><div id="sink"></div>';
          request.respond({ status: 200, contentType: 'text/html', body }).catch(() => {});
          return;
        }
        blockedRequests.push({ url: request.url().slice(0, 500), resourceType: request.resourceType() });
        request.abort('blockedbyclient').catch(() => {});
      });
      await page.setCookie({ name: 'qualification_session', value: 'synthetic-fixture-only', url: origin });
      onPhase('navigation');
      await page.goto(origin, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
      // The candidate is data passed to the same DOM sink used by React's
      // dangerouslySetInnerHTML. It is never evaluated in the Node process.
      if (renderingMode === 'client' || renderingMode === 'innerHTML') {
        onPhase('dom_mount');
        const mountedHtml = proofCall ? await page.evaluate(projectTargetHtml,
          { candidate: browserHtml, proof: proofCall }) : browserHtml;
        if (renderingMode === 'client') {
          const mountResult = await clientMount(page, Object.freeze({ html: mountedHtml, signal,
            ...(qualification.captureDom === true ? { captureDom: true } : {}) }));
          if (qualification.captureDom === true) {
            if (!clientDomCapture) throw new Error('Client DOM capture unavailable');
            const sha = text => createHash('sha256').update(text).digest('hex');
            domCapture = await clientDomCapture(mountResult, Object.freeze({
              originalSourceSha256: sha(html), instrumentedSourceSha256: sha(browserHtml),
              mountedSourceSha256: sha(mountedHtml) }));
            if (!domCapture) throw new Error('Complete client DOM capture unavailable');
          }
          signal?.throwIfAborted();
        } else {
          await page.$eval('#sink', (element, candidate) => { element.innerHTML = candidate; }, mountedHtml);
        }
      }
      if (learnerHtml !== null) {
        onPhase('learner_comparison');
        const comparison = await page.evaluate(source => {
          // Parsing in a detached template is inert: scripts do not execute and
          // event attributes are not dispatched. Compare against the already
          // rendered output without attaching any learner-source nodes.
          const template = document.createElement('template');
          template.innerHTML = source;
          const expected = template.content.firstElementChild;
          if (!expected) return { preserved: false, tag: null };
          const meaningfulChildren = node => [...node.childNodes].filter(child =>
            child.nodeType !== Node.TEXT_NODE || child.textContent.trim().length > 0);
          const sameNode = (left, right) => {
            if (left.nodeType !== right.nodeType) return false;
            if (left.nodeType === Node.TEXT_NODE) return left.textContent.trim() === right.textContent.trim();
            if (left.nodeType === Node.COMMENT_NODE) return left.textContent === right.textContent;
            if (left.nodeType !== Node.ELEMENT_NODE) return false;
            if (left.localName !== right.localName || left.namespaceURI !== right.namespaceURI) return false;
            const sourceAttributes = new Map([...left.attributes].map(attribute => [attribute.name, attribute.value]));
            for (const [name, value] of sourceAttributes) if (right.getAttribute(name) !== value) return false;
            for (const attribute of right.attributes) {
              if (!sourceAttributes.has(attribute.name) && !['class', 'style'].includes(attribute.name.toLowerCase())) return false;
            }
            const leftChildren = meaningfulChildren(left), rightChildren = meaningfulChildren(right);
            return leftChildren.length === rightChildren.length
              && leftChildren.every((child, index) => sameNode(child, rightChildren[index]));
          };
          const root = document.querySelector('#sink') || document.body;
          return {
            preserved: [...root.querySelectorAll('*')].some(candidate => sameNode(expected, candidate)),
            tag: expected.localName,
          };
        }, learnerHtml);
        learnerElementPreserved = comparison.preserved === true;
        learnerElementTag = typeof comparison.tag === 'string' ? comparison.tag.slice(0, 100) : null;
      }
      if (signal?.aborted) throw signal.reason;
      onPhase('browser_observation');
      await new Promise(resolve => { timer = setTimeout(resolve, 80); });

      // Reproduce the bounded interactions documented by the workshop payload
      // picker. We do not execute arbitrary automation supplied by the learner.
      for (const selector of ['[onfocus]', '[oninput]', '[ontoggle]', '[onmouseover]', '[onclick]', 'a[href]']) {
        const handles = await page.$$(selector);
        for (const handle of handles.slice(0, 4)) {
          if (selector === '[onfocus]') await handle.evaluate(element => element.focus()).catch(() => {});
          else if (selector === '[oninput]') await handle.evaluate(element => element.dispatchEvent(new Event('input', { bubbles: true }))).catch(() => {});
          else if (selector === '[ontoggle]') await handle.evaluate(element => { element.open = !element.open; }).catch(() => {});
          else if (selector === '[onmouseover]') await handle.evaluate(element => element.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }))).catch(() => {});
          else if (selector !== 'a[href]' || await handle.evaluate(element =>
            element.getAttribute('href')?.replace(/[\u0000-\u0020]/g, '').toLowerCase().startsWith('javascript:')).catch(() => false)) {
            await handle.evaluate(element => element.click()).catch(() => {});
          }
        }
      }
      await new Promise(resolve => { timer = setTimeout(resolve, 80); });
      let scriptExecuted = false;
      let targetEventExecuted = targetBindingCalled;
      if (profilerStarted) {
        const servedHtml = `<!doctype html><meta charset="utf-8">${browserHtml}`;
        const locations = inlineScriptLocations(servedHtml, qualification.scriptSource);
        const coverage = (await cdp.send('Profiler.takePreciseCoverage')).result;
        scriptExecuted = coverage.some(entry => {
          const parsed = parsedScripts.get(entry.scriptId);
          if (!parsed || parsed.url !== origin || !locations.some(location =>
            location.line === parsed.startLine && location.column === parsed.startColumn)) return false;
          return entry.functions.some(fn => fn.ranges.some(range => range.count > 0));
        });
        if (renderingMode !== 'client' && eventToken && !targetEventExecuted) {
          for (const entry of coverage) {
            const parsed = parsedScripts.get(entry.scriptId);
            const ranTargetCode = entry.functions.some(fn => fn.ranges.some(range => range.count > 0));
            // javascript: URL executions are reported without the document URL
            // by Chromium. The random token exists only in target source after
            // the inert-template projection has disabled every non-target
            // executable node, so matching its covered script is sufficient.
            if (!parsed || !ranTargetCode) continue;
            const source = await cdp.send('Debugger.getScriptSource', { scriptId: entry.scriptId });
            if (source.scriptSource.includes(eventToken)) { targetEventExecuted = true; break; }
          }
        }
      }
      const observed = await page.evaluate(() => ({
        cookie: document.cookie,
        elementCount: document.querySelectorAll((document.querySelector('#sink') ? '#sink ' : 'body ') + '*').length,
        eventAttributes: [...document.querySelectorAll((document.querySelector('#sink') ? '#sink ' : 'body ') + '*')]
          .flatMap(element => [...element.attributes].map(attribute => attribute.name))
          .filter(name => /^on/i.test(name)).slice(0, 20),
      }));
      return {
        ...(domCapture === undefined ? {} : { domCapture }),
        executed: browserEffects.length > 0 || scriptExecuted || targetEventExecuted,
        // Document scripts use exact CDP source coordinates. Event attributes
        // and javascript: URLs use a browser binding retained only on target
        // attributes by the detached-template projection.
        scriptExecuted,
        targetEventExecuted,
        targetEffectObserved: targetEventExecuted && browserEffects.length > 0,
        markers: browserEffects,
        eventAttributes: observed.eventAttributes,
        elementCount: observed.elementCount,
        // This fresh context is seeded with no platform state; the payload may
        // mutate document.cookie, so report that separately from provenance.
        syntheticCookieOnly: true,
        finalCookieIsSyntheticOnly: observed.cookie === 'qualification_session=synthetic-fixture-only',
        blockedRequests,
        renderingMode,
        learnerElementPreserved,
        learnerElementTag,
        reason: scriptExecuted ? 'browser_coverage_script_execution'
          : targetEventExecuted ? 'browser_binding_target_execution'
          : browserEffects.length > 0 ? 'browser_observed_effect' : 'no_instrumented_execution',
      };
    } catch (error) {
      if (signal?.aborted && signal.reason?.name === 'AbortError') throw signal.reason;
      return { executed: false, reason: error?.name === 'TimeoutError' ? 'qualification_timeout' : 'qualification_error', blockedRequests, learnerElementPreserved: false };
    } finally {
      signal?.removeEventListener('abort', closeOnAbort);
      clearTimeout(timer);
      onPhase('cdp_teardown');
      if (profilerStarted) await cdp?.send('Profiler.stopPreciseCoverage').catch(() => {});
      await cdp?.send('Profiler.disable').catch(() => {});
      await cdp?.send('Runtime.disable').catch(() => {});
      await cdp?.send('Debugger.disable').catch(() => {});
      await cdp?.detach().catch(() => {});
      onPhase('context_retirement');
      await retireContext();
    }
  }

  function qualifyWithMode(html, options = {}, renderingMode) {
    const { signal } = options;
    if (closed || retirementFailure) return Promise.reject(retirementFailure || new Error('qualification_closed'));
    if (signal?.aborted) return Promise.reject(signal.reason);
    if (queued >= maxQueue) return Promise.resolve({ executed: false, reason: 'qualification_queue_full', blockedRequests: [], learnerElementPreserved: false });
    queued++;
    clearTimeout(idleTimer);
    const controller = new AbortController();
    jobs.add(controller);
    const relayAbort = () => controller.abort(signal.reason);
    signal?.addEventListener('abort', relayAbort, { once: true });
      let timeout;
      let phase = 'starting';
    // The serialization tail includes physical retirement, not just the public
    // cancellation race. An unretired operation permanently poisons this runner.
    const work = tail.then(async () => {
      if (retirementFailure) throw retirementFailure;
      controller.signal.throwIfAborted();
      let rejectCancellation;
      const cancelled = new Promise((_, reject) => { rejectCancellation = reject; });
      const rejectOnAbort = () => rejectCancellation(controller.signal.reason);
      controller.signal.addEventListener('abort', rejectOnAbort, { once: true });
      let resolveTimeout;
      const timedOut = new Promise(resolve => { resolveTimeout = resolve; });
      const expire = reason => {
        resolveTimeout({ executed: false, reason, blockedRequests: [], learnerElementPreserved: false });
        controller.abort(new Error(reason));
      };
      // Cold Chrome startup can compete with the model for local resources.
      // Give it a separate bounded budget; page work keeps its existing limit.
      timeout = setTimeout(() => expire('browser_startup_timeout'), startupTimeoutMs);
      const runWork = run(html, controller.signal, renderingMode, options,
        value => { phase = value; }, () => {
          clearTimeout(timeout);
          timeout = setTimeout(() => expire('qualification_timeout'), timeoutMs);
        });
      let value, primary;
      try { value = await Promise.race([runWork, timedOut, cancelled]); }
      catch (error) { primary = error; }
      finally {
        clearTimeout(timeout);
        controller.signal.removeEventListener('abort', rejectOnAbort);
        try { await boundedRetirement(runWork.catch(error => { if (error?.code === 'BROWSER_RETIREMENT_INCOMPLETE') throw error; }), () => phase); }
        catch (error) { retirementFailure = error; terminateBrowser(); }
      }
      if (retirementFailure) {
        if (primary && typeof primary === 'object') { try { Object.defineProperty(primary, 'cleanupErrorCode', { value: 'BROWSER_RETIREMENT_INCOMPLETE', configurable: true }); } catch {} }
        throw primary || retirementFailure;
      }
      if (primary) throw primary;
      return value;
    }).finally(() => {
      signal?.removeEventListener('abort', relayAbort);
      jobs.delete(controller);
      queued--;
      if (!closed && !retirementFailure) scheduleIdleClose();
    });
    tail = work.catch(() => {});
    return work;
  }

  const qualify = (html, options) => qualifyWithMode(html, options, 'innerHTML');
  const qualifyDocument = (html, options) => qualifyWithMode(html, options, 'document');

  const qualifyClient = (html, options = {}) => {
    if (!clientMount || Object.keys(options).some(key => !['signal', 'eventSource', 'captureDom', 'learnerHtml'].includes(key))
        || (Object.hasOwn(options, 'captureDom') && (options.captureDom !== true || !clientDomCapture))
        || (Object.hasOwn(options, 'learnerHtml')
          && (typeof options.learnerHtml !== 'string' || Buffer.byteLength(options.learnerHtml) > MAX_HTML_BYTES))) {
      return Promise.reject(new TypeError('Client qualification requires trusted factory mount'));
    }
    return qualifyWithMode(html, options, 'client');
  };
  return { qualify, qualifyDocument, qualifyClient, close };
}

let singleton;
function getXssBrowserQualification() {
  if (!singleton) singleton = createXssBrowserQualification();
  return singleton;
}

module.exports = { projectTargetHtml, createXssBrowserQualification, getXssBrowserQualification, MAX_HTML_BYTES };
