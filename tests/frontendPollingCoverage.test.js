const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

const scopedLabs = {
  'client/src/pages/challenges/IndirectPromptInjectionChallenge.js': ['indirect_prompt_injection', '/api/solutions/indirect-pi/status'],
  'client/src/pages/challenges/XSSWorkshop.js': ['xss_workshop', '/api/solutions/xss-workshop/status', '/api/hints/reflected_xss_llm/status'],
  'client/src/pages/challenges/CSRFWorkshop.js': ['csrf_workshop', '/api/solutions/csrf-workshop/status'],
  'client/src/pages/challenges/MCPWorkshop.js': ['mcp_workshop', '/api/solutions/mcp-workshop/status', '/api/hints/mcp_workshop/status'],
  'client/src/pages/challenges/ExcessiveAgencyBolaLab.js': ['excessive_agency', '/api/solutions/excessive-agency/status'],
  'client/src/pages/workshops/SQLWorkshop.js': ['sql_injection_workshop', '/api/solutions/sql-injection/status'],
  'client/src/pages/workshops/NoSQLWorkshop.js': ['nosql_injection_workshop', '/api/solutions/nosql-injection/status'],
  'client/src/pages/workshops/SensitiveInfoWorkshop.js': ['sensitive_info_disclosure', '/api/workshop/sensitive-info/progress/'],
  'client/src/pages/workshops/SupplyChainWorkshop.js': ['supply_chain_rce', '/api/solutions/supply-chain/status', '/api/hints/supply_chain_rce/status'],
};

function pollingBody(file, scope) {
  const source = read(file);
  const start = source.indexOf('\n  useChangePolling(');
  const endMarker = `}, ['${scope}']);`;
  const end = source.indexOf(endMarker, start);
  assert.ok(start >= 0 && end > start, `${file} missing polling callback for ${scope}`);
  return source.slice(start, end + endMarker.length);
}

function assertGuardedProgressCommit(file, source, phase) {
  if (file.endsWith('/SensitiveInfoWorkshop.js')) {
    assert.match(source, /commitFinflowPresentation\(progressGuard, progressGeneration,/, `${phase} must commit the canonical response atomically`);
    const helper = read('client/src/utils/finflowWorkshopPresentation.mjs');
    assert.match(helper, /guard\.commit\('progress', generation, \(\) => \{/);
    for (const setter of ['setProgress', 'setCanonicalObjectives', 'setSsrfExamples', 'setSolutionStatus']) {
      assert.ok(helper.includes(`setters.${setter}(`), `${setter} belongs to the guarded presentation`);
    }
    assert.doesNotMatch(read(file), /begin\(['"]solutionVisibility['"]\)/,
      'a separate gate response must not overwrite canonical presentation visibility');
  } else {
    assert.match(source, /commit\(['"]progress['"]/, `${file} ${phase} must guard progress commit`);
  }
}

test('every scoped open lab polls its canonical status endpoints', () => {
  for (const [file, markers] of Object.entries(scopedLabs)) {
    const source = read(file);
    assert.match(source, /useChangePolling/, `${file} must use shared polling`);
    for (const marker of markers) assert.ok(source.includes(marker), `${file} missing ${marker}`);
  }
});

test('DPI keeps provider-owned configuration and per-objective transcripts', () => {
  const source = read('client/src/pages/challenges/DirectPromptInjectionChallenge.js');
  assert.match(source, /useWorkshopConfig\(\)/);
  assert.match(source, /\[transcripts, setTranscripts\]/);
  assert.match(source, /const transcriptKey = \(mode, objectiveId\) => `\$\{mode\}:\$\{objectiveId\}`/);
  assert.match(source, /transcripts\[transcriptKey\(labMode, activeObjectiveId\)\]/);
  assert.match(source, /useChangePolling[\s\S]*direct_prompt_injection/);
  assert.ok(source.includes('/api/workshop/prompt-injection/progress'));
});

test('poll refresh handlers do not reset interaction state or surface failures', () => {
  for (const [file, [scope]] of Object.entries(scopedLabs)) {
    assert.doesNotMatch(pollingBody(file, scope), /toast\.|setMessages|setInput|reset/i, file);
  }
});

test('all open-lab poll callbacks sequence at request start instead of overwriting newer state', () => {
  const files = {
    'client/src/pages/challenges/DirectPromptInjectionChallenge.js': 'direct_prompt_injection',
    ...Object.fromEntries(Object.entries(scopedLabs).map(([file, [scope]]) => [file, scope])),
  };
  for (const [file, scope] of Object.entries(files)) {
    const source = read(file);
    const body = pollingBody(file, scope);
    assert.match(source, /useReconciliationGuard/, `${file} missing shared reconciliation guard`);
    assert.match(body, /begin\(['"]progress['"]\)/, `${file} must own a progress sequence before polling`);
    assertGuardedProgressCommit(file, body, 'poll');
  }
});

test('all open labs sequence canonical mount progress through the shared guard', () => {
  const files = {
    'client/src/pages/challenges/DirectPromptInjectionChallenge.js': 'direct_prompt_injection',
    ...Object.fromEntries(Object.entries(scopedLabs).map(([file, [scope]]) => [file, scope])),
  };
  for (const [file, scope] of Object.entries(files)) {
    const source = read(file);
    const outsidePoll = source.replace(pollingBody(file, scope), '');
    assert.match(outsidePoll, /begin\(['"]progress['"]\)/, `${file} mount must begin guarded progress`);
    assertGuardedProgressCommit(file, outsidePoll, 'mount');
  }
});

test('mount gates and foreground disclosure requests use independent request-start domains', () => {
  const expectedDomains = {
    'client/src/pages/challenges/DirectPromptInjectionChallenge.js': ['help'],
    'client/src/pages/challenges/IndirectPromptInjectionChallenge.js': ['solutionVisibility', 'emailProgress', 'solutionModal'],
    'client/src/pages/challenges/XSSWorkshop.js': ['gates', 'solutionModal'],
    'client/src/pages/challenges/CSRFWorkshop.js': ['gates', 'solutionModal'],
    'client/src/pages/challenges/MCPWorkshop.js': ['solutionVisibility', 'hintVisibility', 'solutionModal', 'hintModal'],
    'client/src/pages/challenges/ExcessiveAgencyBolaLab.js': ['solutionVisibility', 'solutionModal'],
    'client/src/pages/workshops/SQLWorkshop.js': ['solutionVisibility', 'solutionModal'],
    'client/src/pages/workshops/NoSQLWorkshop.js': ['solutionVisibility', 'solutionModal'],
    'client/src/pages/workshops/SensitiveInfoWorkshop.js': ['solutionModal'],
    'client/src/pages/workshops/SupplyChainWorkshop.js': ['solutionVisibility', 'hintVisibility', 'solutionModal'],
  };
  for (const [file, domains] of Object.entries(expectedDomains)) {
    const source = read(file);
    for (const domain of domains) {
      assert.match(source, new RegExp(`begin\\(['"]${domain}['"]\\)`), `${file} missing ${domain} request ownership`);
      assert.match(source, new RegExp(`(?:commit|mark)\\(['"]${domain}['"]`), `${file} missing ${domain} guarded state change`);
    }
  }
});

test('polling refreshes rendered or pending disclosure content across every applicable lab', () => {
  const solutionPages = {
    'client/src/pages/challenges/IndirectPromptInjectionChallenge.js': ['indirect_prompt_injection', 'ipiSolutionOwnerRef'],
    'client/src/pages/challenges/XSSWorkshop.js': ['xss_workshop', 'pendingObjectiveSolutionRef'],
    'client/src/pages/challenges/CSRFWorkshop.js': ['csrf_workshop', 'pendingSolutionRef'],
    'client/src/pages/challenges/ExcessiveAgencyBolaLab.js': ['excessive_agency', 'pendingEaSolutionRef'],
    'client/src/pages/workshops/SQLWorkshop.js': ['sql_injection_workshop', 'pendingSolutionRef'],
    'client/src/pages/workshops/NoSQLWorkshop.js': ['nosql_injection_workshop', 'pendingSolutionRef'],
    'client/src/pages/workshops/SensitiveInfoWorkshop.js': ['sensitive_info_disclosure', 'pendingSolutionRef'],
    'client/src/pages/workshops/SupplyChainWorkshop.js': ['supply_chain_rce', 'pendingSolutionRef'],
  };
  for (const [file, [scope, pendingRef]] of Object.entries(solutionPages)) {
    const body = pollingBody(file, scope);
    const targetPattern = pendingRef === 'ipiSolutionOwnerRef'
      ? /const\s+\w*[Dd]isclosureId\s*=\s*ipiSolutionOwnerRef\.current/
      : new RegExp(`const\\s+\\w*[Dd]isclosureId\\s*=.*\\|\\|\\s*${pendingRef}\\.current`);
    assert.match(body, targetPattern, `${file} must select rendered or pending disclosure before refresh`);
    assert.match(body, /const\s+modalGeneration\s*=\s*\w*[Dd]isclosureId\s*\?\s*progressGuard\.begin\(['"]solutionModal['"]\)/,
      `${file} must own the pending/open disclosure request`);
    assert.match(body, /refreshedSolution[\s\S]*\w*[Dd]isclosureId/,
      `${file} must fetch canonical content for the selected disclosure`);
  }

  const dpiBody = pollingBody('client/src/pages/challenges/DirectPromptInjectionChallenge.js', 'direct_prompt_injection');
  assert.match(dpiBody, /const helpDisclosure = help\.open \? help : pendingHelpRef\.current/);
  assert.match(dpiBody, /helpDisclosure\s*\?\s*progressGuard\.begin\(['"]help['"]\)/);
  assert.match(dpiBody, /helpDisclosure[\s\S]*axios\.get\(helpEndpoint/);
});

test('MCP polling refreshes both solution and hint content for rendered or pending disclosures', () => {
  const body = pollingBody('client/src/pages/challenges/MCPWorkshop.js', 'mcp_workshop');
  assert.match(body, /const solutionDisclosureId = viewingSolution\?\.objectiveId \|\| pendingSolutionRef\.current/);
  assert.match(body, /const hintDisclosureId = viewingHint\?\.objectiveId \|\| pendingHintRef\.current/);
  assert.match(body, /begin\(['"]solutionModal['"]\)/);
  assert.match(body, /begin\(['"]hintModal['"]\)/);
  assert.match(body, /\/api\/solutions\/mcp-workshop\/\$\{solutionDisclosureId\}/);
  assert.match(body, /\/api\/hints\/mcp_workshop\/\$\{hintDisclosureId\}/);
  assert.match(body, /commit\(['"]solutionModal['"]/);
  assert.match(body, /commit\(['"]hintModal['"]/);
});

test('gate disable clears pending disclosure loading without waiting for stale request finally', () => {
  const expectations = {
    'client/src/pages/challenges/IndirectPromptInjectionChallenge.js': ['indirect_prompt_injection', 'nextVisibility', 'setIpiSolutionLoading'],
    'client/src/pages/challenges/ExcessiveAgencyBolaLab.js': ['excessive_agency', 'nextSolutions', 'setEaSolutionLoading'],
    'client/src/pages/workshops/SensitiveInfoWorkshop.js': ['sensitive_info_disclosure', 'nextSolutions', 'setSolutionLoadingId'],
  };
  for (const [file, [scope, gates, setter]] of Object.entries(expectations)) {
    const body = pollingBody(file, scope);
    assert.match(body, new RegExp(`!${gates}\\[\\w*[Dd]isclosureId\\][\\s\\S]*${setter}\\(null\\)`),
      `${file} must clear pending loading when the gate closes`);
  }
});

test('XSS and Supply Chain invalidate HintPanel content on scoped revisions', () => {
  for (const [file, scope] of [
    ['client/src/pages/challenges/XSSWorkshop.js', 'xss_workshop'],
    ['client/src/pages/workshops/SupplyChainWorkshop.js', 'supply_chain_rce'],
  ]) {
    const source = read(file);
    const body = pollingBody(file, scope);
    assert.match(source, /\[hintRefreshRevision, setHintRefreshRevision\]/, `${file} missing hint refresh ownership`);
    assert.match(body, /setHintRefreshRevision\(current => current \+ 1\)/, `${file} must invalidate open/pending hints`);
    assert.match(source, /<HintPanel[\s\S]{0,240}revision=\{hintRefreshRevision\}/,
      `${file} must deliver revision invalidation to HintPanel`);
  }
});

test('CSRF polling refreshes or revokes every rendered and pending inline hint', () => {
  const source = read('client/src/pages/challenges/CSRFWorkshop.js');
  const body = pollingBody('client/src/pages/challenges/CSRFWorkshop.js', 'csrf_workshop');
  assert.match(source, /pendingHintRef\s*=\s*useRef\(null\)/);
  assert.match(body, /const hintDisclosureIds = \[\.\.\.new Set\(\[/);
  assert.match(body, /Object\.keys\(hints\)/);
  assert.match(body, /pendingHintRef\.current/);
  assert.match(body, /begin\(['"]hintContent['"]\)/);
  assert.match(body, /\/api\/hints\/csrf_workshop\/\$\{objectiveId\}/);
  assert.match(body, /commit\(['"]hintContent['"]/);
  assert.match(body, /nextSolutions\[objectiveId\]\?\.hint === true/);
  assert.match(body, /nextSolutions\[objectiveId\]\?\.hint !== true/);
  assert.match(body, /nextSolutions\[pendingHintRef\.current\]\?\.hint !== true/);
  assert.doesNotMatch(body, /\.hint !== false/);
  assert.match(body, /delete next\[objectiveId\]/);
  assert.match(source, /toggleHint[\s\S]*mark\(['"]hintContent['"]\)/);
  assert.match(source, /toggleHint[\s\S]*\/api\/hints\/csrf_workshop\/\$\{oid\}/);
});

test('SQL and NoSQL polling use master-aware solution APIs and close hidden open modals', () => {
  for (const [file, scope, canonical, legacy] of [
    ['client/src/pages/workshops/SQLWorkshop.js', 'sql_injection_workshop', '/api/solutions/sql-injection', '/api/workshop/sql/solutions'],
    ['client/src/pages/workshops/NoSQLWorkshop.js', 'nosql_injection_workshop', '/api/solutions/nosql-injection', '/api/workshop/nosql/solutions'],
  ]) {
    const body = pollingBody(file, scope);
    assert.ok(body.includes(`${canonical}/status`), `${file} missing master-aware status`);
    assert.ok(body.includes(`${canonical}/\${solutionDisclosureId}`), `${file} missing master-aware content`);
    assert.ok(!body.includes(legacy), `${file} still polls a master-blind endpoint`);
    assert.match(body, /!nextSolutions\[solutionDisclosureId\][\s\S]*setViewingSolution\(null\)/);
  }
});

test('SQL and NoSQL authoritative empty progress clears stale local fallback state', () => {
  for (const file of [
    'client/src/pages/workshops/SQLWorkshop.js',
    'client/src/pages/workshops/NoSQLWorkshop.js',
  ]) {
    const source = read(file);
    const start = source.indexOf("axios.get('/api/workshop/", source.indexOf('// Fetch server-side progress'));
    const end = source.indexOf('\n  }, []);', start);
    const loader = source.slice(start, end);
    assert.doesNotMatch(loader, /if \(ids\.size > 0\)/, `${file} must trust an empty server result`);
    assert.match(loader, /commit\(['"]progress['"][\s\S]*setCompletedFromPoll\(ids\)/);
    assert.match(loader, /writeCompletedCache\(completedCacheKey, ids\)/);
    assert.match(source, /const writeCompletedCache[\s\S]*try\s*{[\s\S]*localStorage\.setItem\(cacheKey[\s\S]*catch \(_\) {}/);
  }
});

test('no open lab reintroduces WebSocket transport', () => {
  const files = [
    'client/src/pages/challenges/DirectPromptInjectionChallenge.js',
    ...Object.keys(scopedLabs),
  ];
  for (const file of files) assert.doesNotMatch(read(file), /new\s+WebSocket\s*\(/, file);
});
