import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import ComprehensiveAdminDashboard from './ComprehensiveAdminDashboard';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), patch: jest.fn(), delete: jest.fn() }));
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({
  user: { id: 1, username: 'admin', isAdmin: true, adminLevel: 2,
    permissions: ['manage_progress', 'challenge_management', 'user_management'] },
  logout: jest.fn(),
}) }));
let mockSnapshot;
jest.mock('../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ snapshot: mockSnapshot, registerReconciler: () => () => {} }) }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));
jest.mock('./admin/CTFAdminPanel', () => () => null);
jest.mock('../components/admin/AIProviderManagement', () => () => null);
jest.mock('../components/admin/StudentWorkshopView', () => () => null);
jest.mock('../components/admin/ServerLogs', () => () => null);
jest.mock('./admin/ProgressAnalyticsPanel', () => () => null);
jest.mock('../components/admin/PromptInjectionHintEditorModal', () => () => null);
jest.mock('../components/observability/AgentRunInspector', () => () => null);

const challenge = {
  id: 'secureshop_agent_security', key: 'secureshop_agent_security', workshopKey: 'secureshop_agent_security',
  name: 'OWASP AI SecureShop Agent Security', description: 'OWASP AI SecureShop', category: 'ai', difficulty: 'advanced',
  enabled: false, showHints: false, showSolutions: false, completions: 0,
};
const objective = {
  objective_id: 'ss_audit_instruction_followed',
  label: 'Cause an audit summary to follow an instruction embedded in an owned event log',
  is_enabled: false, hint_enabled: false, has_hint_content: true,
};
const solution = {
  id: 'secureshop_agent_security:ss_audit_instruction_followed',
  challengeKey: 'secureshop_agent_security', challenge_key: 'secureshop_agent_security',
  objective_id: 'ss_audit_instruction_followed',
  title: objective.label, description: 'Pending bound audit summary proof.',
  steps: ['Use the owned event source.'], explanation: 'Pending qualification.', code: '',
  references: ['docs/modernization/secureshop-audit-agent-design.md'], prerequisites: ['Owned launch'],
  examples: [{ action: 'Use the owned event source.', explanation: 'Keep the summary bound to the launch.' }, '<b>quoted example</b>'],
  tags: ['audit', 'pending'], difficultyLevel: 'advanced', estimatedTime: '15 minutes',
  isPublic: false, is_public: false,
};

const flush = async () => act(async () => {
  await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
});

test('OWASP AI SecureShop Manage Objectives exposes the pending audit solution controls through the generic ledger', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.setItem('token', 'fixture');
  axios.get.mockImplementation(url => {
    if (url === '/api/admin/challenges') return Promise.resolve({ data: { success: true, challenges: [challenge] } });
    if (url === '/api/admin/solutions') return Promise.resolve({ data: { success: true, solutions: [solution] } });
    if (url === '/api/admin/workshops/secureshop_agent_security/objectives') {
      return Promise.resolve({ data: { success: true, objectives: [objective] } });
    }
    if (url === '/api/admin/workshops/secureshop_agent_security/hints') {
      return Promise.resolve({ data: { success: true, hints: { ss_audit_instruction_followed: false } } });
    }
    return Promise.resolve({ data: {} });
  });
  axios.post.mockResolvedValue({ data: { success: true } });
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  await act(async () => root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard /></MemoryRouter>));
  await flush();
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)); });
  const manage = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Manage Objectives'));
  expect(manage).toBeDefined();
  await act(async () => manage.click());
  await flush();
  expect(node.textContent).toContain('ss_audit_instruction_followed');
  expect(node.textContent).toContain(objective.label);
  const preview = node.querySelector('button[title="Preview Solution"]');
  const edit = node.querySelector('button[title="Edit Solution"]');
  expect(preview).toBeTruthy();
  expect(edit).toBeTruthy();
  await act(async () => preview.click());
  expect(node.textContent).toContain('Solution Details');
  expect(node.textContent).toContain('Pending bound audit summary proof.');
  expect(node.textContent).toContain('Use the owned event source.');
  expect(node.textContent).toContain('Keep the summary bound to the launch.');
  expect(node.textContent).toContain('<b>quoted example</b>');
  expect(node.querySelector('script')).toBeNull();
  const detailHeading = [...node.querySelectorAll('h2')].find(heading => heading.textContent === 'Solution Details');
  await act(async () => detailHeading.parentElement.querySelector('button').click());
  await act(async () => edit.click());
  expect(node.textContent).toContain('Edit Solution');
  await act(async () => [...node.querySelectorAll('form')].at(-1).dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await flush();
  expect(axios.put).toHaveBeenCalledWith(
    '/api/admin/solutions/secureshop_agent_security:ss_audit_instruction_followed',
    expect.objectContaining({
      solution_title: objective.label,
      solution_steps: ['Use the owned event source.'],
      difficulty_level: 'advanced',
      tags: ['audit', 'pending'],
      solution_description: solution.description, solution_code: solution.code,
      reference_links: solution.references, estimated_time: solution.estimatedTime,
      prerequisites: solution.prerequisites, is_public: false,
    }),
  );
  act(() => root.unmount());
  document.body.replaceChildren(); localStorage.clear(); jest.clearAllMocks();
});


test('visible OWASP AI SecureShop with disabled objectives explains student availability without enabling anything', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.setItem('token', 'fixture');
  mockSnapshot = { exercises: { secureshop_agent_security: { isVisible: true, showHints: false, showSolutions: false, objectives: { ss_audit_instruction_followed: { isVisible: false } } } } };
  axios.get.mockImplementation(url => Promise.resolve({ data: url === '/api/admin/challenges' ? { success: true, challenges: [], applications: [{ ...challenge, enabled: true }] } : {} }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<MemoryRouter initialEntries={['/admin/exercises']}><ComprehensiveAdminDashboard /></MemoryRouter>));
    await flush();
    const card = node.querySelector('[data-application-key="secureshop_agent_security"]');
    expect(card.textContent).toContain('VISIBLE');
    expect(card.textContent).toContain('0 of 1 objectives available to students.');
    expect(card.textContent).toContain('Locked for students: no enabled objectives.');
    expect(axios.post).not.toHaveBeenCalled(); expect(axios.patch).not.toHaveBeenCalled();
  } finally { act(() => root.unmount()); node.remove(); localStorage.clear(); mockSnapshot = undefined; jest.clearAllMocks(); }
});
