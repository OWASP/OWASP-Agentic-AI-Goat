'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

const listConsumers = [
  'client/src/pages/challenges/MCPWorkshop.js',
  'client/src/pages/challenges/ExcessiveAgencyBolaLab.js',
  'client/src/pages/workshops/SensitiveInfoWorkshop.js',
  'client/src/pages/workshops/SupplyChainWorkshop.js',
];

for (const file of listConsumers) {
  test(`${path.basename(file)} derives rendered objectives from canonical visibility`, () => {
    const source = read(file);
    assert.match(source, /useWorkshopConfig/);
    assert.match(source, /visibleObjectives/);
    assert.match(source, /visibleObjectiveIds/);
    assert.match(source, /visibleObjectives(?:\.map|\.filter)\(/);
    assert.match(source, /visibleObjectives\.length/);
    assert.doesNotMatch(source, /animate=\{\{ width: `\$\{\(completedCount \/ OBJECTIVES\.length\)/);
    if (file.endsWith('SupplyChainWorkshop.js')) {
      assert.match(source, /hintsEnabled\[obj\.id\] === true/);
      assert.match(source, /solutionVisibility\[viewingSolution\.id\] === true/);
      assert.match(source, /<ObjectiveHelpModal kind="solution"/);
      // Shared solution dialogs do not render hint content; hints retain their independent gate.
      const modal = read('client/src/components/workshop/ObjectiveHelpModal.js');
      const solutionBody = modal.split('{showReadySolution && (')[1].split("{displayStatus !== 'ready'")[0];
      assert.doesNotMatch(solutionBody, /hints\.|HintList|HintStep/);
    }
  });
}

test('CSRF derives each tab and both progress denominators from canonical visibility', () => {
  const source = read('client/src/pages/challenges/CSRFWorkshop.js');
  assert.match(source, /useWorkshopConfig/);
  assert.match(source, /visibleTabs/);
  assert.match(source, /visibleObjectiveIds/);
  assert.match(source, /const currentTab = visibleTabs\[activeTab\]/);
  assert.doesNotMatch(source, /This tab: \{tabDone\}\/3/);
  assert.doesNotMatch(source, /Total: \{totalDone\}\/\{TOTAL_OBJECTIVES\}/);
  // Reset recovery refreshes canonical progress instead of optimistically clearing a tab.
  assert.match(source, /await Promise\.all\(\[fetchProgress\(\), fetchVictim\(targetTab\)\]\)/);
  assert.doesNotMatch(source, /TABS\[activeTab\]\.objectives\.forEach/);
  assert.match(source, /if \(!visibleObjectiveIds\.has\(objId\)\) return/);
  assert.match(source, /visibleObjectiveIds\.has\(curPayloadObj\)/);
  const routeSource = read('server/routes/csrfWorkshop.js');
  assert.match(routeSource, /getVisibleObjectivePrerequisite/);
  assert.match(routeSource, /isObjectiveVisible\(objectiveId\)/);
  assert.match(routeSource, /workshopConfig\.isSolutionVisible\(WORKSHOP_KEY, objectiveId\)/);
  assert.match(routeSource, /await resetWorkshopProgress\(getUserId\(req\),\s*WORKSHOP_KEY\)/);
  assert.match(routeSource, /await resetWorkshopProgress\(userId,\s*WORKSHOP_KEY,\s*\{objectiveIds:ids\}\)/);
});

test('user activity excludes completed objectives disabled by objective or exercise visibility', () => {
  const composition = read('server/routes/workshop.js');
  assert.match(composition, /createPostgresWorkshopRouter/);
  const route = read('server/routes/postgresWorkshop.js');
  assert.match(route, /stores\.progress\.getVisibleUserProgress\(req\.user\.id\)/);
  assert.match(route, /challenge\.objectives\.filter\(o => o\.completed\)/);
  const repository = read('server/database/postgres/workshopProgressRepository.js');
  assert.match(repository, /o\.catalog_active=true AND o\.is_enabled=true/);
  assert.match(repository, /WHERE w\.catalog_active=true/);
  assert.match(repository, /!visible\|\|row\.is_visible/);
  assert.match(repository, /c\.user_id=u\.user_id/);
});

test('Excessive Agency progress response filters objective metadata through canonical visibility', () => {
  const source = read('server/routes/excessiveAgencyLab.js');
  assert.match(source, /createWorkshopConfigService/);
  assert.match(source, /exercise\.objectives\?\.\[`objective_\$\{objective\.id\}`\]\?\.isVisible/);
  assert.doesNotMatch(source, /totalObjectives:\s*9/);
  assert.match(source, /completedAt:\s*visibleCompletedAt/);
});

test('Sensitive objective-specific OOB guidance follows the objective visibility gate', () => {
  const source = read('client/src/pages/workshops/SensitiveInfoWorkshop.js');
  assert.match(source, /visibleObjectiveIds\.has\('ssrf_oob'\)/);
  assert.match(source, /placeholder\.objectiveId/);
  assert.match(source, /visibleObjectiveIds\.has\(placeholder\.objectiveId\)/);
  assert.doesNotMatch(source, /What tools do you have\? What AI model are you\?/);
  assert.match(source, /HintPanel/);
  assert.match(source, /hintVisible/);
  assert.match(source, /exerciseConfig\.objectives\?\.\[activeSolution\.id\]\?\.hintVisible/);
});

test('dashboard and navbar do not navigate into canonically locked exercises', () => {
  const dashboard = read('client/src/pages/WorkshopDashboard.js');
  const navbar = read('client/src/components/WorkshopNavbar.js');
  assert.match(
    dashboard,
    /exercises\.find\(\(exercise\) => exercise\.status === 'in_progress'\)[\s\S]{0,180}exercises\.find\(\(exercise\) => exercise\.status === 'unlocked'\)/,
    'the Overview must prefer an actionable exercise before its locked fallback',
  );
  assert.match(dashboard, /recommendedExercise\.status === 'locked'/);
  assert.match(dashboard, /LockedExerciseAction/);
  assert.match(navbar, /filterVisibleExercises/);
  assert.equal((navbar.match(/filterVisibleExercises\(/g) || []).length, 2);
  assert.match(navbar, /exercise\.status === 'locked' \? \([\s\S]*?<DropdownItem key=\{exercise\.id\} disabled/);
  assert.doesNotMatch(navbar, /challenge\.status !== 'locked'/);
});

test('MCP scoring and progress responses exclude admin-hidden objectives', () => {
  const source = read('server/routes/mcpWorkshop.js');
  assert.match(source, /createWorkshopConfigService/);
  assert.match(source, /visibleObjectiveIds/);
  assert.match(source, /qualifiedObjectiveCandidates\(result\.objectivesHit, visibleObjectiveIds\)/);
  assert.match(source, /function qualifiedObjectiveCandidates[\s\S]*?filter\(id => visibleObjectiveIds\.has\(id\) && qualification\.canGrade\(id\)\)/);
  assert.match(source, /for \(const objectiveId of objectiveCandidates\)/);
  assert.match(source, /objective disabled by instructor/);
});

test('non-PI Solutions master uses the canonical mutation once without changing objective availability', () => {
  const source = read('client/src/pages/ComprehensiveAdminDashboard.js');
  const handlerStart = source.indexOf('const handleToggleChallengeSolution');
  const handlerEnd = source.indexOf('const handleToggleChallengeHints', handlerStart);
  assert.notEqual(handlerStart, -1, 'solution handler must exist');
  assert.notEqual(handlerEnd, -1, 'hint handler boundary must exist');

  const handler = source.slice(handlerStart, handlerEnd);
  assert.match(handler, /runMasterMutation\(challengeKey, 'solutions', showSolutions, async post =>/);
  const nonPromptInjectionStart = handler.indexOf("await post('/api/admin/challenges/solutions/toggle'");
  assert.notEqual(nonPromptInjectionStart, -1, 'non-PI master solution mutation must remain');
  const nonPromptInjectionPath = handler.slice(nonPromptInjectionStart);

  assert.doesNotMatch(nonPromptInjectionPath, /objectives\/bulk-toggle/,
    'Solutions must not call the curriculum objective bulk-toggle endpoint');
  assert.doesNotMatch(nonPromptInjectionPath, /setWorkshopObjectives/,
    'Solutions must not optimistically rewrite Manage Objectives state');
  assert.doesNotMatch(nonPromptInjectionPath, /post\(`\/api\/admin\/.*?\/solutions\/(?:bulk|toggle)/,
    'a second family write can fail after the canonical master mutation commits');
  assert.doesNotMatch(nonPromptInjectionPath, /Promise\.all\(allObjIds/,
    'XSS objective writes must not follow its atomic canonical and legacy master mutation');
  const hintsPath = source.slice(handlerEnd, source.indexOf('const handleLogout', handlerEnd));
  assert.doesNotMatch(hintsPath, /hints\/bulk-toggle/,
    'the canonical hint master route already cascades objective gates');
});
