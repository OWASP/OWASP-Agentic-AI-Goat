'use strict';
const { FAMILY_CONFIG, XSS_TABS, CSRF_TABS } = require('../../db/postgres/map-platform-additional-solutions');
const DIGEST = 'd'.repeat(64);

function distinctRows(tabs, prefix) {
  return Object.entries(tabs).flatMap(([exercise, ids]) => ids.map((objectiveId, index) => ({
    id: Number(objectiveId.replace(/\D/g, '') || index + 1) + Object.values(tabs).flat().indexOf(objectiveId) * 10 + (prefix === 'xss' ? 100 : 300),
    objective_id: objectiveId,
    exercise_id: exercise,
    title: `Title ${objectiveId}`,
    hint: `Hint ${objectiveId}`,
    example: `Example ${objectiveId}`,
    explanation: `Explanation ${objectiveId}`,
    solutions_enabled: index % 2,
    updated_at: '2026-03-04 05:06:07.123456',
  })));
}

function genericRows(config) {
  return config.objectiveIds.map((objectiveId, index) => ({
    id: index + 1,
    objective_id: objectiveId,
    title: `Title ${objectiveId}`,
    difficulty: 'Intermediate',
    hints: JSON.stringify([`Hint ${objectiveId}`]),
    examples: JSON.stringify([{ prompt: `Prompt ${objectiveId}`, explanation: `Explanation ${objectiveId}` }]),
    approach: `Approach ${objectiveId}`,
    tips: JSON.stringify([`Tip ${objectiveId}`]),
    updated_at: '2026-04-05 06:07:08.654321',
  }));
}

function visibilityRows(config) {
  return config.objectiveIds.map((objectiveId, index) => ({
    id: index + 101,
    objective_id: objectiveId,
    solutions_enabled: index % 2,
    enabled_by: config.source === 'supply_chain_workshop.db' ? (index % 2 ? 'teacher' : null) : (index % 2 ? 42 : null),
    enabled_at: '2026-05-06 07:08:09',
    ...(config.visibilityColumns.includes('updated_at') ? { updated_at: '2026-05-06 07:08:09.111222' } : {}),
  }));
}

function fixture() {
  const sources = {
    'users_auth.db': { tables: {
      xss_workshop_objective_solutions: distinctRows(XSS_TABS, 'xss'),
      csrf_workshop_objective_solutions: distinctRows(CSRF_TABS, 'csrf'),
    } },
  };
  for (const config of Object.values(FAMILY_CONFIG)) {
    sources[config.source] = { tables: {
      [config.contentTable]: genericRows(config),
      [config.visibilityTable]: visibilityRows(config),
    } };
  }
  return { sources, archiveDigest: DIGEST };
}

function legacyXssContent(tab = 'reflected') {
  return {
    id: 900, challenge_id: tab, title: 'Legacy tab content', difficulty: 'Easy',
    hints: '["legacy hint"]', examples: '[{"payload":"legacy payload","explanation":"legacy why"}]',
    approach: 'Legacy approach', tips: '["legacy tip"]', updated_at: '2025-01-02 03:04:05',
  };
}
function legacyXssVisibility(tab = 'reflected') {
  return { id: 901, challenge_id: tab, solutions_enabled: 0, enabled_by: 42, enabled_at: '2025-01-02 03:04:05', updated_at: '2025-01-02 03:04:06' };
}

module.exports = { fixture, legacyXssContent, legacyXssVisibility, DIGEST };
