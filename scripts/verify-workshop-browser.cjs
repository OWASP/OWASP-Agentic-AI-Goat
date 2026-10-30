const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const puppeteer = require('puppeteer');

const root = path.resolve(__dirname, '..');
const buildDirectory = path.join(root, 'client/build');
const outputDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-workshop-browser-'));
const widths = [375, 768, 1024, 1440];
const ids = {
  direct_prompt_injection: ['interact', 'system_prompt', 'jailbreak', 'multi_language', 'virtualization', 'role_playing', 'side_stepping', 'obfuscation'],
  indirect_prompt_injection: ['rag_upload', 'rag_clean_doc', 'rag_query', 'rag_injected_doc', 'rag_query_injection', 'email_create_inbox', 'email_send_attack', 'email_retrieve', 'email_trigger_injection', 'email_understand_defense'],
};
const snapshot = {
  revision: 1,
  exercises: Object.fromEntries(Object.entries(ids).map(([workshopKey, objectiveIds]) => [workshopKey, {
    isVisible: true,
    objectives: Object.fromEntries(objectiveIds.map((objectiveId) => [objectiveId, {
      isVisible: true,
      hintVisible: true,
      solutionVisible: true,
    }])),
  }])),
};
const challenges = Object.keys(ids).map((id) => ({
  id,
  title: id === 'direct_prompt_injection' ? 'Direct Prompt Injection' : 'Indirect Prompt Injection',
  showHints: true,
  showSolutions: true,
  objectives: [],
}));

assert.ok(fs.existsSync(path.join(buildDirectory, 'index.html')), 'Run npm run build first');

function json(res, body, status = 200) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function apiResponse(req, res) {
  const url = new URL(req.url, 'http://fixture.local');
  if (url.pathname === '/api/auth/status') return json(res, {
    authenticated: true,
    user: { id: 17, username: 'browser-fixture', role: 'student' },
  });
  if (url.pathname === '/api/workshop/config/snapshot') return json(res, snapshot);
  if (url.pathname === '/api/workshop/config/revision') return json(res, { revision: 1 });
  if (url.pathname === '/api/changes/revisions') return json(res, { revisions: { global: {}, workshops: {}, user: {} } });
  if (url.pathname === '/api/workshop/challenges') return json(res, { success: true, challenges });
  if (url.pathname === '/api/solutions/indirect-pi/status') {
    return json(res, { objectives: Object.fromEntries(ids.indirect_prompt_injection.filter((id) => id.startsWith('rag_')).map((id) => [id, true])) });
  }
  if (url.pathname === '/api/workshop/rag-injection/current-session') {
    return json(res, { session_id: 'browser-rag-session', filename: 'fixture.txt', chunks_stored: 1 });
  }
  if (url.pathname === '/api/workshop/rag-injection/query' && req.method === 'POST') {
    await delay(250);
    return json(res, {
      retrieved_chunks: [{ content: 'Browser-owned document result', score: 0.95 }],
      answer: 'Document scenario response stayed with its owner.',
      completedObjectiveIds: [],
      judgments: [],
    });
  }
  if (url.pathname === '/api/workshop/prompt-injection/chat' && req.method === 'POST') {
    await delay(250);
    return json(res, { response: 'Direct scenario response stayed with its objective.', progress: { objectives: {} } });
  }
  if (url.pathname === '/api/workshop/rag-injection/progress/reset' && req.method === 'POST') {
    await delay(100);
    return json(res, { success: true, progress: { objectives: {} } });
  }
  if (url.pathname === '/api/email-agent/progress/reset' && req.method === 'POST') {
    await delay(100);
    return json(res, { success: true, progress: {} });
  }
  if (url.pathname === '/api/workshop/prompt-injection/progress') return json(res, { success: true, objectives: {} });
  if (url.pathname === '/api/workshop/rag-injection/progress') return json(res, { success: true, objectives: {} });
  if (url.pathname === '/api/email-agent/progress') return json(res, { success: true, progress: {} });
  if (url.pathname === '/api/email-agent/scenarios') return json(res, { scenarios: [] });
  if (url.pathname === '/api/email-agent/health') return json(res, {
    gmail: { initialized: true, canSend: true }, llm: { available: true }, allowedDomains: [],
  });
  if (url.pathname.endsWith('/health') || url.pathname.endsWith('/llm-status')) return json(res, {
    available: true,
    embeddingReady: true,
    llmReady: true,
    modelReady: true,
    ollamaAvailable: true,
    provider: 'ollama',
    providerName: 'Ollama',
    model: 'llama3.1:8b',
    status: 'healthy',
  });
  if (url.pathname.startsWith('/api/hints/')) return json(res, { hint: { title: 'Fixture hint', hints: ['Browser fixture hint'] } });
  if (url.pathname.startsWith('/api/solutions/')) return json(res, { solution: { title: 'Fixture solution', examples: [] } });
  return json(res, { success: true });
}

const server = http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) {
    void apiResponse(req, res).catch((error) => json(res, { error: error.message }, 500));
    return;
  }
  const requestedPath = new URL(req.url, 'http://fixture.local').pathname;
  const requestedFile = path.join(buildDirectory, requestedPath);
  const file = requestedFile.startsWith(`${buildDirectory}${path.sep}`)
    && fs.existsSync(requestedFile)
    && fs.statSync(requestedFile).isFile()
    ? requestedFile
    : path.join(buildDirectory, 'index.html');
  res.setHeader('content-type', file.endsWith('.js') ? 'text/javascript'
    : file.endsWith('.css') ? 'text/css'
      : file.endsWith('.html') ? 'text/html' : 'application/octet-stream');
  fs.createReadStream(file).pipe(res);
});

function luminance(channels) {
  const values = channels.map((channel) => {
    const normalized = channel / 255;
    return normalized <= 0.03928 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
  });
  return (0.2126 * values[0]) + (0.7152 * values[1]) + (0.0722 * values[2]);
}

function contrastRatio(foreground, background) {
  const foregroundLuminance = luminance(foreground);
  const backgroundLuminance = luminance(background);
  return (Math.max(foregroundLuminance, backgroundLuminance) + 0.05)
    / (Math.min(foregroundLuminance, backgroundLuminance) + 0.05);
}

async function waitForWorkshop(page, template) {
  await page.waitForSelector(`[data-workshop-template="${template}"]`, { visible: true });
}

async function settleFiniteAnimations(page) {
  await page.evaluate(async () => {
    const finite = document.getAnimations().filter((animation) => {
      const iterations = animation.effect?.getTiming?.().iterations;
      return iterations !== Infinity;
    });
    await Promise.race([
      Promise.all(finite.map((animation) => animation.finished.catch(() => undefined))),
      new Promise((resolve) => setTimeout(resolve, 2000)),
    ]);
  });
  await delay(100);
}

async function verifyResponsivePages(page, origin, pageErrors) {
  for (const slug of ['direct-prompt-injection', 'indirect-prompt-injection']) {
    for (const width of widths) {
      pageErrors.length = 0;
      await page.setViewport({ width, height: 1000, deviceScaleFactor: 1 });
      await page.goto(`${origin}/vulnerabilities/${slug}`, { waitUntil: 'networkidle0' });
      const expectedTemplate = slug === 'direct-prompt-injection' ? 'single-scenario' : 'multi-scenario';
      await waitForWorkshop(page, expectedTemplate);
      await settleFiniteAnimations(page);
      const layout = await page.evaluate(() => ({
        viewport: document.documentElement.clientWidth,
        documentWidth: document.documentElement.scrollWidth,
        bodyWidth: document.body.scrollWidth,
        overflowers: [...document.querySelectorAll('*')].flatMap((element) => {
          const rect = element.getBoundingClientRect();
          const clippedByScroller = [...function* ancestors() {
            for (let current = element.parentElement; current; current = current.parentElement) yield current;
          }()].some((ancestor) => /auto|scroll|hidden|clip/.test(getComputedStyle(ancestor).overflowX));
          return (rect.right > document.documentElement.clientWidth + 0.5 || rect.left < -0.5) && !clippedByScroller
            ? [{ tag: element.tagName, text: String(element.textContent || '').trim().slice(0, 80), className: String(element.className || '').slice(0, 120), left: rect.left, right: rect.right, width: rect.width }]
            : [];
        }).slice(0, 12),
      }));
      assert.ok(layout.documentWidth <= layout.viewport, `${slug} document overflows at ${width}px: ${JSON.stringify(layout)}`);
      assert.ok(layout.bodyWidth <= layout.viewport, `${slug} body overflows at ${width}px: ${JSON.stringify(layout)}`);
      assert.deepEqual(pageErrors, [], `${slug} emitted browser errors at ${width}px`);
      await page.screenshot({ path: path.join(outputDirectory, `${slug}-${width}.png`), fullPage: true });
      if (width === 375) {
        await page.screenshot({ path: path.join(outputDirectory, `${slug}-${width}-viewport.png`) });
      }
      console.log(JSON.stringify({ check: 'responsive', slug, width, ...layout, browserErrors: pageErrors.length }));
    }
  }
}

async function verifyIndirectInteractions(page, origin) {
  await page.setViewport({ width: 1024, height: 1000, deviceScaleFactor: 1 });
  await page.goto(`${origin}/vulnerabilities/indirect-prompt-injection`, { waitUntil: 'networkidle0' });
  await waitForWorkshop(page, 'multi-scenario');

  const activeTab = await page.$('[data-scenario-tab="document"]');
  await activeTab.focus();
  await page.keyboard.press('ArrowRight');
  await page.waitForFunction(() => document.querySelector('[data-scenario-tab="email"]')?.getAttribute('aria-selected') === 'true');
  assert.equal(await page.evaluate(() => document.activeElement?.dataset.scenarioTab), 'email');
  await page.type('input[placeholder="youremail@sharklasers.com"]', 'learner@sharklasers.com');

  await page.click('[data-scenario-tab="document"]');
  await page.type('input[placeholder="What is the remote work policy?"]', 'Who owns this response?');
  await page.click('form button[type="submit"]');
  await page.click('[data-scenario-tab="email"]');
  assert.equal(await page.$eval('input[placeholder="youremail@sharklasers.com"]', (input) => input.value), 'learner@sharklasers.com');
  await page.waitForFunction(() => document.querySelector('[data-scenario-workspace="document"]')
    ?.textContent.includes('Document scenario response stayed with its owner.'));
  assert.equal(await page.$eval('[data-scenario-tab="email"]', (tab) => tab.getAttribute('aria-selected')), 'true');
  assert.equal(await page.$eval('[data-scenario-workspace="document"]', (panel) => panel.hidden), true);

  await page.click('[data-scenario-tab="document"]');
  assert.ok((await page.content()).includes('Document scenario response stayed with its owner.'));
  await page.click('[data-scenario-tab="email"]');
  const emailReset = await page.evaluateHandle(() => [...document.querySelectorAll('button')]
    .filter((button) => button.innerText.trim() === 'Reset Progress').at(-1));
  await emailReset.asElement().click();
  await page.waitForSelector('[role="alertdialog"]');
  assert.equal(await page.evaluate(() => document.activeElement?.innerText), 'Confirm reset');
  await page.keyboard.press('Escape');
  await page.waitForSelector('[role="alertdialog"]', { hidden: true });
  assert.equal(await page.evaluate(() => document.activeElement?.innerText), 'Reset Progress');
  await emailReset.asElement().click();
  await page.click('[role="alertdialog"] button:last-of-type');
  await page.waitForSelector('[role="alertdialog"]', { hidden: true });
  assert.equal(await page.$eval('input[placeholder="youremail@sharklasers.com"]', (input) => input.value), 'learner@sharklasers.com');
  await page.click('[data-scenario-tab="document"]');
  assert.ok((await page.content()).includes('Document scenario response stayed with its owner.'));
  await settleFiniteAnimations(page);

  const colors = await page.$eval('[data-scenario-tab="document"]', (element) => {
    const parse = (value) => {
      const values = value.match(/[\d.]+/g)?.map(Number) || [];
      return { channels: values.slice(0, 3), alpha: values.length > 3 ? values[3] : 1 };
    };
    const blend = (foreground, background) => foreground.channels.map((channel, index) => (
      (channel * foreground.alpha) + (background[index] * (1 - foreground.alpha))
    ));
    const ancestry = [];
    for (let current = element; current; current = current.parentElement) {
      const style = getComputedStyle(current);
      ancestry.push({ tag: current.tagName, backgroundColor: style.backgroundColor, opacity: Number(style.opacity) });
    }
    let resolvedBackground = [255, 255, 255];
    for (const entry of [...ancestry].reverse()) {
      resolvedBackground = blend(parse(entry.backgroundColor), resolvedBackground);
    }
    const foreground = blend(parse(getComputedStyle(element).color), resolvedBackground);
    return { foreground, background: resolvedBackground, ancestry };
  });
  assert.ok(colors.ancestry.every(({ opacity }) => opacity === 1), `Scenario tab has translucent ancestor opacity: ${JSON.stringify(colors.ancestry)}`);
  assert.equal(colors.ancestry[0].backgroundColor, 'rgb(255, 255, 255)', 'Active scenario tab must provide an opaque surface for deterministic text contrast');
  const ratio = contrastRatio(colors.foreground, colors.background);
  assert.ok(ratio >= 4.5, `Active scenario tab contrast ${ratio.toFixed(2)}:1 is below 4.5:1`);
  console.log(JSON.stringify({
    check: 'ipi-interactions', keyboardTabs: true, focusRestored: true,
    siblingStatePreserved: true, pendingRunOwnerPreserved: true,
    activeTabForeground: colors.foreground.map(Math.round),
    activeTabBackground: colors.background.map(Math.round),
    activeTabContrast: Number(ratio.toFixed(2)),
  }));
}

async function verifyDirectObjectiveOwnership(page, origin) {
  await page.setViewport({ width: 768, height: 1000, deviceScaleFactor: 1 });
  await page.goto(`${origin}/vulnerabilities/direct-prompt-injection`, { waitUntil: 'networkidle0' });
  await waitForWorkshop(page, 'single-scenario');
  await page.type('textarea', 'Keep this response with practice');
  await page.click('button[aria-label="Send message"]');
  await page.click('[data-testid="objective-card-system_prompt"]');
  await page.waitForFunction(() => document.querySelector('[data-testid="objective-card-system_prompt"]')?.innerText.includes('ACTIVE'));
  await delay(350);
  assert.ok(!(await page.$eval('body', (body) => body.innerText)).includes('Direct scenario response stayed with its objective.'));
  await page.click('[data-testid="objective-card-interact"]');
  await page.waitForFunction(() => document.body.innerText.includes('Direct scenario response stayed with its objective.'));
  console.log(JSON.stringify({ check: 'dpi-interactions', pendingRunOwnerPreserved: true, objectiveTranscriptPreserved: true }));
}

(async () => {
  console.log('Qualification mode: production frontend with injected local API responses; no backend, database, email, or model calls.');
  console.log(`Browser artifacts: ${outputDirectory}`);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const browser = await puppeteer.launch({ headless: true });
  try {
    const page = await browser.newPage();
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    await page.evaluateOnNewDocument(() => localStorage.setItem('token', `fixture.${btoa(JSON.stringify({ exp: 9999999999 }))}.signature`));
    const origin = `http://127.0.0.1:${server.address().port}`;
    await verifyResponsivePages(page, origin, pageErrors);
    pageErrors.length = 0;
    await verifyIndirectInteractions(page, origin);
    await verifyDirectObjectiveOwnership(page, origin);
    assert.deepEqual(pageErrors, [], 'Interactive checks emitted browser errors');
  } finally {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  server.close();
  process.exitCode = 1;
});
