'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const Module = require('node:module');

test('generation binds the authenticated owner and publishes only server grader results', { timeout: 60000 }, async () => {
  const profile = { id: 5, user_id: 42, full_name: 'Owner', email_address: 'owner@example.test',
    company_name: '', job_title: '', signature_html: '' };
  const mutations = [];
  let holdPreview = false;
  let previewEnteredResolve;
  let releasePreview;
  const previewEntered = new Promise(resolve => { previewEnteredResolve = resolve; });
  const db = {
    get(sql, params, callback) {
      if (/FROM email_templates/i.test(sql)) return callback(null,
        Number(params[0]) === 77 && String(params[1]) === '42'
          ? { id: 77, user_id: 42, html_content: '<script>alert(1)</script>' } : null);
      callback(null, String(params[0]) === '42' ? profile : null);
    },
    run(sql, _params, callback) {
      mutations.push(sql);
      if (holdPreview && /INSERT INTO template_previews/i.test(sql)) {
        previewEnteredResolve();
        return new Promise(resolve => {
          releasePreview = () => { callback?.call({ lastID: 77, changes: 1 }, null); resolve(); };
        });
      }
      if (callback) callback.call({ lastID: 77, changes: 1 }, null);
    },
    all(_sql, _params, callback) { callback(null, []); },
  };
  let gradeInput;
  const grader = { evaluate: async input => {
    gradeInput = input;
    return { completedLevels: [2], judgments: [{ level: 2, verdict: 'pass', explanation: 'Observed.' }] };
  } };
  const originalLoad = Module._load;
  let releaseSlow;
  let slowEnteredResolve;
  const slowEntered = new Promise(resolve => { slowEnteredResolve = resolve; });
  const routePath = require.resolve('../server/routes/xssEmail');
  delete require.cache[routePath];
  Module._load = function(specifier, parent, isMain) {
    if (parent?.filename === routePath && specifier === '../database/xssEmailDb') return db;
    if (parent?.filename === routePath && specifier === '../services/multiProviderAIService') return {
      generateResponse: async prompt => {
        if (prompt.includes('slow generation')) {
          slowEnteredResolve();
          await new Promise(resolve => { releaseSlow = resolve; });
        }
        return { response: '<p>Hello {{name}}</p>', provider: 'ollama', model: 'llama3.1:8b' };
      },
    };
    if (parent?.filename === routePath && specifier === '../middleware/adminAuth') return {
      authenticateToken(req, res, next) {
        if (req.headers.authorization !== 'Bearer owner') return res.status(401).json({ error: 'Authentication required' });
        req.user = { id: 42 }; next();
      },
    };
    if (parent?.filename === routePath && specifier === '../services/xssEmailObjectiveGrader') return {
      createXssEmailObjectiveGrader: () => grader,
    };
    return originalLoad.call(this, specifier, parent, isMain);
  };
  let router;
  try { router = require(routePath); } finally { Module._load = originalLoad; }
  const app = express(); app.use(express.json()); app.use(express.urlencoded({ extended: false })); app.use('/api/xss-email', router);
  const server = app.listen(0, '127.0.0.1');
  const ready = bounded(new Promise((resolve,reject) => { server.once('listening', resolve);server.once('error',reject); }),10000);
  let base;
  const post = (pathname, body, authenticated = false) => fixtureFetch(`${base}${pathname}`, { method: 'POST',
    headers: { 'content-type': 'application/json', ...(authenticated ? { authorization: 'Bearer owner' } : {}) },
    body: JSON.stringify(body) });
  try {
    await ready;
    base = `http://127.0.0.1:${server.address().port}/api/xss-email`;
    assert.equal((await post('/generate', { userId: 999, prompt: 'welcome' })).status, 401);
    const ownerProfile = await fixtureFetch(`${base}/profile/999`, { headers: { authorization: 'Bearer owner' } });
    assert.equal(ownerProfile.status, 200);
    assert.equal((await ownerProfile.json()).profile.user_id, 42);
    for (const body of [{ prompt: {} }, { prompt: '  ' }, { prompt: 'hello', includeSignature: 'false' },
      { prompt: 'hello', templateType: {} }, { prompt: '界'.repeat(22000) }]) {
      assert.equal((await post('/generate', body, true)).status, 400);
      assert.equal(gradeInput, undefined, 'invalid metadata never reaches model/grader');
    }
    for (const challengeLevel of ['constructor', '__proto__', {}, 5]) {
      assert.equal((await post('/challenge/verify', { challengeLevel, testPayload: '<script>alert(1)</script>', profileField: 'full_name' }, true)).status, 400);
    }
    const invalidProfile = await fixtureFetch(`${base}/profile/42`, { method: 'PUT', headers: {
      'content-type': 'application/json', authorization: 'Bearer owner' }, body: JSON.stringify({ full_name: {} }) });
    assert.equal(invalidProfile.status, 400);
    const generatedResponse = await post('/generate', { userId: 999, prompt: 'welcome' }, true);
    assert.equal(generatedResponse.status, 200);
    const generated = await generatedResponse.json();
    assert.equal(gradeInput.userId, 42);
    assert.equal(gradeInput.templateId, 77);
    assert.equal(gradeInput.profile.user_id, 42);
    assert.equal(generated.completedLevels[0], 2);
    assert.equal(generated.judgments[0].verdict, 'pass');
    assert.deepEqual(generated.render, {
      method: 'POST', path: '/api/xss-email/preview/render', templateId: 77,
    });

    const renderedResponse = await post('/preview/render', { templateId: 77 }, true);
    assert.equal(renderedResponse.status, 200);
    assert.match(renderedResponse.headers.get('content-type'), /^text\/html/);
    assert.match(renderedResponse.headers.get('content-security-policy'), /sandbox allow-scripts/);
    assert.match(renderedResponse.headers.get('content-security-policy'), /default-src 'none'/);
    assert.equal(await renderedResponse.text(), '<script>alert(1)</script>');

    // Preview is a persisted mutation too. Reset must invalidate and wait for
    // its callback before clearing the owner's state, while preserving the
    // intentionally unsanitized response contract.
    holdPreview = true;
    const previewDuringReset = post('/preview', { templateId: 77 }, true);
    previewDuringReset.catch(()=>{}); // Observed immediately; original await still asserts the result.
    await bounded(previewEntered,10000);
    const previewReset = post('/challenge/reset', {}, true);
    previewReset.catch(()=>{}); // Observed immediately; original await still asserts the result.
    await new Promise(resolve => setTimeout(resolve, 20));
    releasePreview();
    assert.equal((await previewDuringReset).status, 409);
    assert.equal((await previewReset).status, 200);
    holdPreview = false;

    // Exercise the actual HTTP renderer and CSP in a fresh browser with only a
    // synthetic fixture token. Scripts execute, while the sandbox denies origin
    // storage access and the response policy denies network destinations.
    const browser = await require('puppeteer').launch({ headless: true, timeout: 15000, protocolTimeout: 15000 });
    try {
      const context = await browser.createBrowserContext();
      const page = await context.newPage();
      page.setDefaultTimeout(10000);page.setDefaultNavigationTimeout(10000);
      const dialogs = [];
      page.on('dialog', async dialog => { dialogs.push(dialog.message()); await dialog.dismiss(); });
      await page.setExtraHTTPHeaders({ authorization: 'Bearer owner' });
      await page.setContent(`<form method="post" action="${base}/preview/render"><input name="templateId" value="77"></form>`);
      await Promise.all([
        page.waitForNavigation({ waitUntil: 'domcontentloaded' }),
        page.$eval('form', form => form.submit()),
      ]);
      await new Promise(resolve => setTimeout(resolve, 50));
      assert.deepEqual(dialogs, ['1']);
      assert.equal(await page.evaluate(() => {
        try { return document.cookie, 'accessible'; } catch (error) { return error.name; }
      }), 'SecurityError');
      await bounded(context.close());
    } finally { await bounded(browser.close()); }

    const retiredResponse = await post('/challenge/complete', { userId: 999, challengeLevel: 4 }, true);
    assert.equal(retiredResponse.status, 409);
    assert.equal((await retiredResponse.json()).code, 'JUDGED_ATTEMPT_REQUIRED');

    const gradesBeforeResetRace = gradeInput;
    const slowGeneration = post('/generate', { prompt: 'slow generation' }, true);
    slowGeneration.catch(()=>{}); // Observed immediately; original await still asserts the result.
    await bounded(slowEntered,10000);
    const reset = post('/challenge/reset', {}, true);
    reset.catch(()=>{}); // Observed immediately; original await still asserts the result.
    await new Promise(resolve => setTimeout(resolve, 20));
    releaseSlow();
    assert.equal((await slowGeneration).status, 409);
    assert.equal((await reset).status, 200);
    assert.equal(gradeInput, gradesBeforeResetRace, 'invalidated generation must not reach grading');
    assert.equal(mutations.filter(sql => /^DELETE FROM/i.test(sql)).length, 6,
      'both reset operations completed their three-table cleanup after fencing mutations');
  } finally {
    releasePreview?.();releaseSlow?.();
    try { server.closeAllConnections();await bounded(new Promise((resolve,reject) => server.close(error=>error?reject(error):resolve()))); }
    finally { delete require.cache[routePath]; }
  }
});

function fixtureFetch(url,options={}) { return fetch(url,{...options,signal:AbortSignal.timeout(10000)}); }
async function bounded(work,ms=5000){let timer;try{return await Promise.race([work,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned XSS fixture deadline')),ms);})]);}finally{clearTimeout(timer);}}
