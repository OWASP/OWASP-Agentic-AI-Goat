import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import SecureShopObjectives from './SecureShopObjectives';
let mockSnapshot; let mockPoll;
jest.mock('axios');
jest.mock('../../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ snapshot: mockSnapshot, revision: mockSnapshot.revision }) }));
jest.mock('../../hooks/useChangePolling', () => callback => { mockPoll = callback; });
jest.mock('../../components/workshop/ObjectiveHelpModal', () => props => <div role="dialog">{props.objective.title}:{props.content?.hints?.join(' ')}</div>);
jest.mock('../../components/workshop/WorkshopExperience', () => ({
  EmptyState: ({ children }) => <div>{children}</div>,
  ExerciseProgress: ({ completed, total }) => <div>{completed} of {total} objectives completed</div>,
  ObjectiveCard: ({ children }) => <div>{children}</div>, ObjectiveList: ({ children }) => <div>{children}</div>,
  ObjectiveHelpActions: ({ objectiveId, hintVisible, solutionVisible, activeKind, onOpen }) => <div data-objective-help-actions={objectiveId} data-active-kind={activeKind || ''}>
    {hintVisible && <button onClick={() => onOpen('hint', objectiveId)}>Hint</button>}
    {solutionVisible && <button onClick={() => onOpen('solution', objectiveId)}>Solution</button>}
  </div>,
  StatusNotice: ({ children }) => <div>{children}</div>, WorkshopButton: ({ children, ...props }) => <button {...props}>{children}</button>,
}));
const KEY = 'secureshop_agent_security';
let node; let root;
const data = { challenges: [{ workshopKey: KEY, exerciseGroups: [{ id: 'intro', title: 'Observe the loop', objectives: [
  { id: 'one', label: 'Instructor label', completed: true, hintVisible: true, solutionVisible: false }, { id: 'two', label: 'Disabled objective', completed: true },
] }] }] };
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  mockSnapshot = { revision: 1, exercises: { [KEY]: { isVisible: true, objectives: {
    one: { isVisible: true, hintVisible: true, solutionVisible: false, label: 'Edited catalog title', description: 'Edited catalog description' }, two: { isVisible: false },
  } } } };
  axios.get.mockReset(); axios.get.mockResolvedValue({ data });
  node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); });
test('renders canonical labels, live enabled totals and decoupled help controls', async () => {
  await act(async () => root.render(<SecureShopObjectives />));
  expect(axios.get).toHaveBeenCalledWith('/api/workshop/applications/secureshop', expect.any(Object));
  expect(node.textContent).toContain('1 of 1 objectives completed');
  expect(node.textContent).toContain('Edited catalog title');
  expect(node.textContent).toContain('Edited catalog description');
  expect(node.textContent).not.toContain('Disabled objective');
  expect([...node.querySelectorAll('button')].map(button => button.textContent)).toEqual(['Hint']);
  expect(node.querySelector('[data-objective-help-actions="one"]')).not.toBeNull();
  axios.get.mockResolvedValue({ data: { hint: { hints: ['Read the real receipt'] } } });
  await act(async () => node.querySelector('button').click());
  expect(axios.get).toHaveBeenLastCalledWith(`/api/hints/${KEY}/one`, expect.any(Object));
  expect(node.querySelector('[role="dialog"]').textContent).toContain('Read the real receipt');
  mockSnapshot = { ...mockSnapshot, revision: 2, exercises: { [KEY]: { isVisible: true, objectives: { one: { isVisible: false } } } } };
  axios.get.mockResolvedValue({ data });
  await act(async () => root.render(<SecureShopObjectives />));
  expect(node.querySelector('[role="dialog"]')).toBeNull();
  expect(node.textContent).toContain('0 of 0');
});
test('newer progress wins when an older poll resolves late', async () => {
  await act(async () => root.render(<SecureShopObjectives />));
  let finishOld;
  axios.get.mockImplementationOnce(() => new Promise(resolve => { finishOld = resolve; }));
  const old = mockPoll();
  axios.get.mockResolvedValueOnce({ data: { challenges: [] } });
  await act(async () => mockPoll());
  await act(async () => { finishOld({ data }); await old; });
  expect(node.textContent).toContain('No objectives are currently enabled');
  expect(node.textContent).not.toContain('Edited catalog title');
});
test('a failed refresh clears stale completion claims and offers retry', async () => {
  await act(async () => root.render(<SecureShopObjectives />));
  axios.get.mockRejectedValueOnce(new Error('unavailable'));
  await act(async () => mockPoll());
  expect(node.textContent).toContain('Unable to load objective progress');
  expect(node.textContent).not.toContain('Completed:');
  axios.get.mockResolvedValueOnce({ data });
  await act(async () => node.querySelector('button').click());
  expect(node.textContent).toContain('1 of 1');
});


test('removing canonical objectives closes disclosed help even before config catches up', async () => {
  await act(async () => root.render(<SecureShopObjectives />));
  axios.get.mockResolvedValueOnce({ data: { hint: { hints: ['Previously visible hint'] } } });
  await act(async () => node.querySelector('button').click());
  expect(node.querySelector('[role="dialog"]')).not.toBeNull();
  axios.get.mockResolvedValueOnce({ data: { challenges: [] } });
  await act(async () => mockPoll());
  expect(mockSnapshot.exercises[KEY].objectives.one.hintVisible).toBe(true);
  expect(node.querySelector('[role="dialog"]')).toBeNull();
});

test('canonical disclosure revocation wins over an older visible config snapshot', async () => {
  const hidden = JSON.parse(JSON.stringify(data));
  hidden.challenges[0].exerciseGroups[0].objectives[0].hintVisible = false;
  axios.get.mockResolvedValueOnce({ data: hidden });
  await act(async () => root.render(<SecureShopObjectives />));
  expect(node.textContent).toContain('Edited catalog title');
  expect(node.querySelector('button')).toBeNull();
});
