/* eslint-disable testing-library/no-unnecessary-act -- React DOM createRoot is used directly. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import CTFAdminPanel from './CTFAdminPanel';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

function level(levelNumber, configurationApplicability, instructorSolution = '') {
  return {
    level: levelNumber,
    stageName: `Stage ${levelNumber}`,
    guardian: `Guardian ${levelNumber}`,
    defenses: 'Controlled defenses',
    secret: `ADMIN_ONLY_${levelNumber}`,
    payloads: [],
    instructorSolution,
    configurationApplicability,
  };
}

test('solutions tab distinguishes current default matches, instructor drift, and missing stages', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear();
  localStorage.setItem('token', 'admin-token');
  axios.get.mockImplementation((url) => {
    if (url === '/api/ctf/admin/analytics') return Promise.resolve({ data: { analytics: {} } });
    if (url === '/api/ctf/admin/solutions') {
      return Promise.resolve({
        data: {
          comparisonPolicy: {
            description: 'Compares the exact guardian prompt and stage secret, ordered defenses, and adaptive mode. This reports configuration compatibility, not a guaranteed model outcome.',
          },
          howWinningWorks: [],
          payloadFamilies: [],
          instructorNotes: [],
          levels: [
            level(1, {
              candidateBasis: 'canonical_default', appliesToDefault: true,
              currentConfiguration: 'matches_default', differingFields: [],
            }, 'Instructor-authored Level 1 solution'),
            level(2, {
              candidateBasis: 'canonical_default', appliesToDefault: true,
              currentConfiguration: 'differs_from_default',
              differingFields: ['system_prompt', 'defense_style'],
            }),
            level(3, {
              candidateBasis: 'canonical_default', appliesToDefault: true,
              currentConfiguration: 'stage_missing', differingFields: [],
            }),
            level(4, {
              candidateBasis: 'canonical_default', appliesToDefault: false,
              currentConfiguration: 'canonical_default_invalid', differingFields: [],
              invalidDefaultFields: ['defense_style'],
            }),
          ],
        },
      });
    }
    return Promise.reject(new Error(`Unexpected request ${url}`));
  });

  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<CTFAdminPanel />));
  await flush();

  const solutionsButton = [...node.querySelectorAll('button')]
    .find(button => button.textContent.includes('Solutions'));
  act(() => solutionsButton.click());
  await flush();

  expect(axios.get).toHaveBeenCalledWith(
    '/api/ctf/admin/solutions',
    { headers: { Authorization: 'Bearer admin-token' } },
  );
  expect(node.textContent).toContain('Candidate applies to default; current configuration matches');
  expect(node.textContent).toContain('Candidate applies to default; current configuration differs');
  expect(node.textContent).toContain('Changed: guardian prompt, defense stack');
  expect(node.textContent).toContain('Candidate applies to default; current stage missing');
  expect(node.textContent).toContain('Canonical default configuration invalid');
  expect(node.textContent).toContain('This reports configuration compatibility, not a guaranteed model outcome.');
  expect(node.textContent).toContain('Instructor-authored Level 1 solution');

  act(() => root.unmount());
  node.remove();
});

test('teaching editor uses the narrow content endpoint and excludes guardian and scoring policy', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  jest.clearAllMocks();
  const stage = {
    id: 12, stage_number: 2, stage_name: 'Teaching level', stage_description: 'Learner description',
    hints: '["First hint"]', teaching_objective: 'Learner objective', solution_content: 'Instructor solution',
    system_prompt: 'immutable guardian', success_criteria: 'IMMUTABLE_SECRET', defense_style: '[]',
    adaptive_mode: 'none', level_score: 100, feedback_mode: 'reason',
  };
  axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/stages') ? { stages: [stage] } : { analytics: {} } }));
  axios.put.mockResolvedValue({ data: { message: 'Teaching content updated' } });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    const button = text => [...container.querySelectorAll('button')].find(node => node.textContent.trim() === text);
    await act(async () => button('Levels').click()); await flush();
    const row = [...container.querySelectorAll('tr')].find(node => node.textContent.includes('Teaching level'));
    await act(async () => row.click());
    await act(async () => button('Save teaching content').click()); await flush();
    expect(axios.put).not.toHaveBeenCalled();
    const dialog = container.querySelector('[role="dialog"]');
    expect(dialog.textContent).toContain('Teaching level');
    await act(async () => [...dialog.querySelectorAll('button')].find(node => node.textContent.trim() === 'Confirm Teaching Save').click()); await flush();
    expect(axios.put).toHaveBeenCalledTimes(1);
    const [url, body] = axios.put.mock.calls[0];
    expect(url).toBe('/api/ctf/admin/stages/12/content');
    expect(body).toEqual({
      stage_name: 'Teaching level', stage_description: 'Learner description', hints: '["First hint"]',
      teaching_objective: 'Learner objective', solution_content: 'Instructor solution',
    });
    for (const policy of ['system_prompt', 'success_criteria', 'defense_style', 'adaptive_mode', 'level_score', 'feedback_mode']) {
      expect(body).not.toHaveProperty(policy);
    }
  } finally { await act(async () => root.unmount()); container.remove(); }
});

test('level editor retains disabled legacy bonus but excludes it from actual save request', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  jest.clearAllMocks();
  const stage = { id: 9, stage_number: 1, stage_name: 'Owned level', hints: '[]', defense_style: '[]', time_bonus_seconds: 777, level_score: 100, success_criteria: 'OWNED_SECRET' };
  axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/stages') ? { stages: [stage] } : { analytics: {} } }));
  axios.put.mockResolvedValue({ status: 200, data: { message: 'Stage updated' } });
  const container = document.createElement('div'); document.body.appendChild(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<CTFAdminPanel />)); await flush();
    const button = text => [...container.querySelectorAll('button')].find(node => node.textContent.trim() === text);
    await act(async () => button('Levels').click()); await flush();
    const row = [...container.querySelectorAll('tr')].find(node => node.textContent.includes('Owned level'));
    await act(async () => row.click());
    const inactive = container.querySelector('[aria-label="Legacy inactive time bonus"]');
    expect(inactive.disabled).toBe(true); expect(inactive.readOnly).toBe(true); expect(inactive.value).toBe('777');
    expect(container.textContent).toContain('This legacy value does not affect scoring.');
    await act(async () => button('Save').click()); await flush();
    expect(axios.put).not.toHaveBeenCalled();
    await act(async () => [...container.querySelector('[role="dialog"]').querySelectorAll('button')]
      .find(node => node.textContent.trim() === 'Cancel').click()); await flush();
    expect(axios.put).not.toHaveBeenCalled();
    await act(async () => button('Save').click()); await flush();
    await act(async () => [...container.querySelector('[role="dialog"]').querySelectorAll('button')]
      .find(node => node.textContent.trim() === 'Confirm Advanced Save').click()); await flush();
    expect(axios.put).toHaveBeenCalledTimes(1);
    const [url, body] = axios.put.mock.calls[0]; expect(url).toBe('/api/ctf/admin/stages/9');
    expect(body.stage_name).toBe('Owned level'); expect(body).not.toHaveProperty('time_bonus_seconds');
    expect(stage.time_bonus_seconds).toBe(777);
  } finally { await act(async () => root.unmount()); container.remove(); }
});
