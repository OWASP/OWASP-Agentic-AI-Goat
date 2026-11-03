import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import LegacyFileSsiWorkshop from '../LegacyFileSsiWorkshop';

const fileObjective = {
  id: 'path_traversal', label: 'Read protected file', description: 'Admin-authored description',
  enabled: true, completed: false, showHints: false, hint: { hints: ['private hint'] },
  showSolutions: true, solution: { title: 'Visible solution', approach: 'Use the owned path.',
    examples: [{ title: 'Example', payload: '../secret/owned.txt', explanation: 'Owned teaching artifact.' }],
    tips: ['Do not use host paths.'] },
};
const combinedObjective = {
  id: 'combined_traversal_ssi', label: 'Combined owned workflow', description: 'Second canonical description',
  enabled: true, completed: true, showHints: true, hint: { hints: ['Second hint'] }, showSolutions: false,
};
const templateObjective = { id: 'ssi_injection', label: 'Expand template', description: 'Inspect template interpretation.', enabled: true, completed: false };
const agentObjective = { id: 'ai_assisted_path_traversal', label: 'Ask the owned file agent', description: 'Observe the real actor response.', enabled: true, completed: false };
const snapshot = {
  workshopKey: 'legacy_sensitive_file_ssi', mode: { effectiveMode: 'vuln', allowedModes: ['vuln', 'fixed'] },
  objectives: [fileObjective, { ...templateObjective, enabled: false }],
};
let container, root;
const click = element => act(() => element.click());
const activePanel = () => container.querySelector('[data-scenario-workspace]:not([hidden])');
const card = id => container.querySelector(`[data-testid="objective-card-${id}"]`);
const buttonWithText = (text, scope = container) => [...scope.querySelectorAll('button')].find(button => button.textContent.trim() === text);
const render = props => act(() => root.render(<LegacyFileSsiWorkshop snapshot={snapshot} {...props} />));
const fill = (value, input = activePanel().querySelector('textarea')) => act(() => {
  Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, value);
  input.dispatchEvent(new Event('input', { bubbles: true }));
});
const submit = async () => act(async () => {
  activePanel().querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  await Promise.resolve();
});
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
};
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container);
});
afterEach(() => { act(() => root.unmount()); container.remove(); });

test('canonical totals and independent help gates retain the light objective dialog', () => {
  render();
  expect(container.querySelector('[data-workshop="legacy_sensitive_file_ssi"]')).not.toBeNull();
  expect(activePanel().textContent).toContain('0 of 1 objectives completed');
  expect(activePanel().textContent).toContain('Admin-authored description');
  expect(container.querySelector('[data-testid="hint-button-path_traversal"]')).toBeNull();
  expect(container.textContent).not.toContain('private hint');
  click(container.querySelector('[data-testid="solution-button-path_traversal"]'));
  const dialog = document.querySelector('[data-testid="objective-help-modal"]');
  expect(dialog.querySelector('h2').textContent).toBe('Solution · Read protected file');
  expect(dialog.textContent).toContain('Use the owned path.');
  expect(dialog.textContent).toContain('Do not use host paths.');
  expect(getComputedStyle(dialog).backgroundColor).toBe('rgb(255, 255, 255)');
  click(container.querySelector('[data-scenario-tab="templates"]'));
  expect(document.querySelector('[data-testid="objective-help-modal"]')).toBeNull();
  expect(activePanel().textContent).toContain('No enabled objectives in this scenario.');
  expect(activePanel().textContent).not.toContain('All objectives completed!');
});

test('disabled objectives are absent and selection has no duplicate dropdown', () => {
  render();
  expect(card('path_traversal')).not.toBeNull(); expect(card('ssi_injection')).toBeNull();
  expect(container.querySelector('select')).toBeNull();
  expect(container.querySelectorAll('[data-testid^="objective-card-"]')).toHaveLength(1);
});

test('missing canonical family remains unavailable and initial loading is distinct', () => {
  render({ snapshot: { ...snapshot, workshopKey: 'sensitive_info' } });
  expect(container.querySelector('form')).toBeNull(); expect(container.textContent).toContain('unavailable');
  render({ snapshot: null, loading: true });
  expect(container.textContent).toContain('Loading exercise'); expect(container.textContent).not.toContain('unavailable');
});

test('baseline shell contains the workflow and objective rail with accessible progress', () => {
  render();
  const experience = container.querySelector('[data-workshop]'), surface = experience.parentElement;
  expect(getComputedStyle(surface).maxWidth).toBe('1800px');
  expect(getComputedStyle(surface).borderRadius).toBe('24px');
  const workspace = activePanel().querySelector('[aria-label="File traversal workspace"]');
  const objectives = activePanel().querySelector('aside[aria-label="Exercise objectives"]');
  expect(workspace.parentElement).toBe(objectives.parentElement);
  expect(getComputedStyle(workspace.parentElement).display).toBe('grid');
  expect(activePanel().querySelector('[role="progressbar"]').getAttribute('aria-valuenow')).toBe('0');
  expect(activePanel().querySelector('button[type="submit"]').disabled).toBe(true);
  expect(activePanel().querySelector('label').htmlFor).toBe(activePanel().querySelector('textarea').id);
});

test('each objective has its own canonical card, completion and independently gated help', () => {
  render({ snapshot: { ...snapshot, objectives: [...snapshot.objectives, combinedObjective] } });
  const choice = card(combinedObjective.id).querySelector('button.select');
  expect(card(combinedObjective.id).textContent).toContain('COMPLETED');
  expect(choice.getAttribute('aria-pressed')).toBe('false');
  click(choice); expect(choice.getAttribute('aria-pressed')).toBe('true');
  expect(activePanel().textContent).toContain('Second canonical description');
  expect(activePanel().textContent).toContain('1 of 2 objectives completed');
  expect(activePanel().querySelector('[role="progressbar"]').getAttribute('aria-valuenow')).toBe('50');
  expect(container.querySelector('[data-testid="hint-button-combined_traversal_ssi"]')).not.toBeNull();
  expect(container.querySelector('[data-testid="solution-button-combined_traversal_ssi"]')).toBeNull();
  expect(container.querySelector('[data-testid="solution-button-path_traversal"]')).not.toBeNull();
});

test('opening a sibling solution does not select it; using its payload selects and fills without sending', () => {
  const onAttempt = jest.fn();
  render({ snapshot: { ...snapshot, objectives: [fileObjective, combinedObjective] }, onAttempt });
  click(card(combinedObjective.id).querySelector('button.select'));
  click(container.querySelector('[data-testid="solution-button-path_traversal"]'));
  expect(card(combinedObjective.id).querySelector('button.select').getAttribute('aria-pressed')).toBe('true');
  click(buttonWithText('Use this payload', document.querySelector('[role="dialog"]')));
  expect(document.querySelector('[role="dialog"]')).toBeNull();
  expect(card(fileObjective.id).querySelector('button.select').getAttribute('aria-pressed')).toBe('true');
  expect(activePanel().querySelector('textarea').value).toBe('../secret/owned.txt');
  expect(onAttempt).not.toHaveBeenCalled();
});

test('revoking solution permission closes already disclosed content without exposing stale payload', () => {
  render(); click(container.querySelector('[data-testid="solution-button-path_traversal"]'));
  expect(document.querySelector('[role="dialog"]')).not.toBeNull();
  render({ snapshot: { ...snapshot, objectives: [{ ...fileObjective, showSolutions: false }] } });
  expect(document.querySelector('[role="dialog"]')).toBeNull();
  expect(document.body.textContent).not.toContain('../secret/owned.txt');
  expect(container.querySelector('[data-testid="solution-button-path_traversal"]')).toBeNull();
});

test('owned attempts render output as inert text and retain results and drafts across tabs', async () => {
  const onAttempt = jest.fn().mockResolvedValue({ rendered: '<img src=x onerror=alert(1)> Owned SSI observation' });
  const onRefresh = jest.fn().mockResolvedValue();
  render({ snapshot: { ...snapshot, objectives: [fileObjective, templateObjective] }, onAttempt, onRefresh });
  fill('../secret/owned.txt'); await submit();
  expect(onAttempt).toHaveBeenCalledWith({ objectiveId: 'path_traversal', input: '../secret/owned.txt' });
  expect(onRefresh).toHaveBeenCalledTimes(1);
  expect(activePanel().querySelector('[aria-label="Observed result"]').textContent).toContain('<img src=x onerror=alert(1)>');
  expect(activePanel().querySelector('[aria-label="Observed result"] img')).toBeNull();
  fill('next file draft'); click(container.querySelector('[data-scenario-tab="templates"]'));
  expect(activePanel().querySelector('[aria-label="Observed result"]')).toBeNull();
  fill('template draft'); click(container.querySelector('[data-scenario-tab="files"]'));
  expect(activePanel().querySelector('textarea').value).toBe('next file draft');
  expect(activePanel().querySelector('[aria-label="Observed result"]').textContent).toContain('Owned SSI observation');
  click(container.querySelector('[data-scenario-tab="templates"]'));
  expect(activePanel().querySelector('textarea').value).toBe('template draft');
});

test('a delayed response remains in its originating scenario after tab navigation', async () => {
  const pending = deferred();
  render({ snapshot: { ...snapshot, objectives: [fileObjective, templateObjective] }, onAttempt: jest.fn(() => pending.promise), onRefresh: jest.fn().mockResolvedValue() });
  fill('owned path'); await submit();
  click(container.querySelector('[data-scenario-tab="templates"]'));
  expect(activePanel().textContent).not.toContain('Running attempt');
  expect(container.querySelector('[data-scenario-workspace="files"]').textContent).toContain('Running attempt');
  await act(async () => { pending.resolve({ content: 'Owned file response' }); await Promise.resolve(); });
  expect(activePanel().querySelector('[aria-label="Observed result"]')).toBeNull();
  click(container.querySelector('[data-scenario-tab="files"]'));
  expect(activePanel().querySelector('[aria-label="Observed result"]').textContent).toBe('Owned file response');
});

test('Enter submits agent messages while Shift+Enter and IME remain composition input', async () => {
  const onAttempt = jest.fn().mockResolvedValue({ response: 'Actor output' });
  render({ snapshot: { ...snapshot, objectives: [fileObjective, agentObjective] }, onAttempt, onRefresh: jest.fn().mockResolvedValue() });
  click(container.querySelector('[data-scenario-tab="agent"]')); fill('Inspect my owned file');
  const input = activePanel().querySelector('textarea');
  act(() => input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, shiftKey: true, cancelable: true })));
  act(() => input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, isComposing: true, cancelable: true })));
  expect(onAttempt).not.toHaveBeenCalled();
  await act(async () => { input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true })); await Promise.resolve(); });
  expect(onAttempt).toHaveBeenCalledWith({ objectiveId: agentObjective.id, input: 'Inspect my owned file' });
  expect(activePanel().querySelector('[aria-label="Observed result"]').textContent).toBe('Actor output');
  click(container.querySelector('[data-scenario-tab="files"]')); fill('owned path');
  act(() => activePanel().querySelector('textarea').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true })));
  expect(onAttempt).toHaveBeenCalledTimes(1);
});

test('conversation reset clears only that local objective and preserves canonical completion', async () => {
  const onReset = jest.fn();
  render({ snapshot: { ...snapshot, objectives: [fileObjective, { ...agentObjective, completed: true }] }, onAttempt: jest.fn().mockResolvedValue({ response: 'Actor output' }), onRefresh: jest.fn().mockResolvedValue(), onReset });
  fill('retained file draft'); click(container.querySelector('[data-scenario-tab="agent"]'));
  fill('Agent request'); await submit(); fill('discarded local agent draft');
  click(buttonWithText('Reset conversation', activePanel()));
  expect(activePanel().querySelector('textarea').value).toBe('');
  expect(activePanel().querySelector('[aria-label="Observed result"]')).toBeNull();
  expect(card(agentObjective.id).textContent).toContain('COMPLETED'); expect(onReset).not.toHaveBeenCalled();
  click(container.querySelector('[data-scenario-tab="files"]'));
  expect(activePanel().querySelector('textarea').value).toBe('retained file draft');
});

test('unknown mode blocks submission and confirmed mode namespaces retain separate drafts', () => {
  render({ snapshot: { ...snapshot, mode: null } });
  expect(activePanel().querySelector('textarea').disabled).toBe(true);
  render(); fill('vulnerable draft');
  render({ snapshot: { ...snapshot, mode: { ...snapshot.mode, effectiveMode: 'fixed' } } });
  expect(activePanel().querySelector('textarea').value).toBe(''); fill('fixed draft');
  render(); expect(activePanel().querySelector('textarea').value).toBe('vulnerable draft');
});

test('progress reset is explicit about all scenarios and cancellation preserves drafts', () => {
  const onReset = jest.fn(); render({ onReset }); fill('retained draft');
  click(buttonWithText('Reset Progress', activePanel()));
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog.textContent).toContain('all three File and SSI scenarios');
  click(buttonWithText('Cancel', dialog));
  expect(onReset).not.toHaveBeenCalled(); expect(activePanel().querySelector('textarea').value).toBe('retained draft');
});

test('outer hero uses canonical metadata without inventing difficulty', () => {
  render();
  expect(container.querySelector('a[href="/workshop/challenges"]').textContent).toContain('Back to Dashboard');
  expect(container.querySelectorAll('h1')).toHaveLength(1);
  expect(container.querySelector('h1').textContent).toBe('File and SSI Security');
  const hero = container.querySelector('header[aria-labelledby="file-ssi-title"]');
  const surface = container.querySelector('[data-workshop]').parentElement;
  expect(hero.nextElementSibling).toBe(surface);
  expect(container.textContent).not.toMatch(/Intermediate|Advanced|Beginner/);
  render({ snapshot: { ...snapshot, title: 'Instructor file lab', description: 'Instructor-authored introduction', difficulty: 'Advanced' } });
  expect(container.querySelector('h1').textContent).toBe('Instructor file lab');
  expect(hero.textContent).toContain('Instructor-authored introduction');
  expect(hero.textContent).toContain('Advanced');
});


test('an uncertain mode change blocks execution until a successful progress refresh', async () => {
  const onModeChange = jest.fn().mockRejectedValue(new Error('Connection lost'));
  const onRefresh = jest.fn().mockResolvedValue(true);
  const onAttempt = jest.fn();
  render({ onModeChange, onRefresh, onAttempt }); fill('owned path');
  await act(async () => { buttonWithText('Fixed').click(); await Promise.resolve(); });
  expect(onModeChange).toHaveBeenCalledWith('fixed');
  expect(activePanel().querySelector('textarea').disabled).toBe(true);
  expect(container.textContent).toContain('Mode could not be confirmed');
  await submit(); expect(onAttempt).not.toHaveBeenCalled();
  await act(async () => { buttonWithText('Refresh progress', activePanel()).click(); await Promise.resolve(); });
  expect(onRefresh).toHaveBeenCalledTimes(1);
  expect(activePanel().querySelector('textarea').disabled).toBe(false);
});
