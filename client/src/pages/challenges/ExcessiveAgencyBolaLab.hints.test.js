import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import ExcessiveAgencyBolaLab from './ExcessiveAgencyBolaLab';

let mockConfig;
jest.mock('../../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => mockConfig }));
jest.mock('../../hooks/useChangePolling', () => () => {});
jest.mock('../../hooks/useWorkshopHeartbeat', () => () => {});
jest.mock('../../components/VulnerabilityTemplate', () => ({ children }) => <div>{children}</div>);
jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: { success: jest.fn(), error: jest.fn(), info: jest.fn() } }));

test('EA fixed and vulnerable hints follow canonical visibility independently of solutions', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const objectives = Object.fromEntries(Array.from({ length: 9 }, (_, index) => [`objective_${index + 1}`,
    { isVisible: true, hintVisible: index === 0 || index === 4, solutionVisible: false }]));
  objectives.objective_1.label = 'Instructor-defined owner boundary';
  objectives.objective_1.description = 'Instructor-owned objective detail';
  mockConfig = { revision: '1', snapshot: { exercises: { excessive_agency: { isVisible: true, objectives } } } };
  axios.get.mockResolvedValue({ data: { mode: 'fixed', objectives: {}, progress: { objectives: {} }, message: 'Welcome', hint: { title: 'Owner boundary', hints: ['Check the requested owner before calling the tool.'] } } });
  axios.post.mockResolvedValue({ data: { user: { username: 'alice' }, sessionToken: 'owned-fixture' } });
  const container = document.createElement('div'); document.body.append(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<ExcessiveAgencyBolaLab />));
    await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent.includes('Login as Alice')).click());
    const hints = () => [...container.querySelectorAll('button')].filter(button => button.textContent.trim() === 'Hint');
    expect(hints()).toHaveLength(2);
    expect([...container.querySelectorAll('.section-desc')].map(node => node.textContent)).toEqual(['4 enabled objectives', '5 enabled objectives']);
    expect(container.textContent).toContain('Instructor-defined owner boundary');
    expect(container.textContent).toContain('Instructor-owned objective detail');
    await act(async () => hints()[0].click());
    expect(axios.get).toHaveBeenCalledWith('/api/hints/excessive_agency/objective_1');
    expect(document.body.textContent).toContain('Check the requested owner before calling the tool.');
    expect([...container.querySelectorAll('button')].some(button => button.textContent.trim() === 'Solution')).toBe(false);
    objectives.objective_1.hintVisible = false;
    objectives.objective_1.description = '  ';
    objectives.objective_5.isVisible = false;
    mockConfig = { ...mockConfig, revision: '2', snapshot: { exercises: { excessive_agency: { isVisible: true, objectives: { ...objectives } } } } };
    await act(async () => root.render(<ExcessiveAgencyBolaLab />));
    expect(hints()).toHaveLength(0);
    expect([...container.querySelectorAll('.section-desc')].map(node => node.textContent)).toEqual(['4 enabled objectives', '4 enabled objectives']);
    expect(container.textContent).toContain('View your notes or orders in secure mode');
    expect(container.textContent).not.toContain('Instructor-owned objective detail');
    expect(document.querySelector('[role=dialog]')).toBeNull();
    expect(document.body.textContent).not.toContain('Check the requested owner before calling the tool.');
  } finally {
    act(() => root.unmount()); container.remove();
  }
});

test.each([false, true])('EA shared solution preserves all examples and gated hint copy (%s)', async hintVisible => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const objectives = Object.fromEntries(Array.from({ length: 9 }, (_, index) => [`objective_${index + 1}`,
    { isVisible: true, hintVisible: index === 0 && hintVisible, solutionVisible: index === 0 }]));
  mockConfig = { revision: '1', snapshot: { exercises: { excessive_agency: { isVisible: true, objectives } } } };
  axios.get.mockImplementation(url => {
    if (url === '/api/solutions/excessive-agency/status') {
      return Promise.resolve({ data: { objectives: { objective_1: true } } });
    }
    if (url === '/api/solutions/excessive-agency/objective_1') {
      return Promise.resolve({ data: { solution: {
        title: 'Owned data solution', difficulty: 'Easy', hints: ['Check the owner'],
        examples: [{ prompt: 'first owned prompt', explanation: 'First reason' },
          { prompt: 'second owned prompt', explanation: 'Second reason' }],
        approach: 'Use an owner-bound request', tips: ['Keep the session scoped'],
      } } });
    }
    return Promise.resolve({ data: { mode: 'fixed', objectives: {}, progress: { objectives: {} }, message: 'Welcome' } });
  });
  axios.post.mockResolvedValue({ data: { user: { username: 'alice' }, sessionToken: 'owned-fixture' } });
  const container = document.createElement('div'); document.body.append(container);
  const root = createRoot(container);
  try {
    await act(async () => { root.render(<ExcessiveAgencyBolaLab />); });
    await act(async () => {
      [...container.querySelectorAll('button')].find(button => button.textContent.includes('Login as Alice')).click();
    });
    await act(async () => { container.querySelector('[data-testid="solution-button-objective_1"]').click(); });
    const modal = document.querySelector('[data-testid="objective-help-modal"]');
    expect(modal?.dataset.helpKind).toBe('solution');
    expect(modal.textContent).toContain('Owned data solution');
    expect(modal.textContent).toContain('Difficulty: Easy');
    expect(modal.textContent).toContain('Use an owner-bound request');
    expect(modal.textContent).toContain('Keep the session scoped');
    expect(modal.textContent.includes('Check the owner')).toBe(hintVisible);
    expect(modal.querySelectorAll('[data-testid="solution-example"]')).toHaveLength(2);
    await act(async () => { modal.querySelectorAll('[data-testid="solution-example"] button')[1].click(); });
    expect(container.querySelector('textarea').value).toBe('second owned prompt');
    expect(document.querySelector('[data-testid="objective-help-modal"]')).toBeNull();
  } finally {
    act(() => root.unmount()); container.remove();
  }
});
