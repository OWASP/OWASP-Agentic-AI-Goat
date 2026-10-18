import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import UserProfile from './UserProfile';
import { toast } from 'react-toastify';

let mockUser;
const mockUpdateUser = jest.fn();
jest.mock('axios', () => ({ get: jest.fn(), put: jest.fn() }));
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: mockUser, updateUser: mockUpdateUser }) }));
jest.mock('react-toastify', () => ({ toast: { success: jest.fn(), error: jest.fn() } }));

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

function renderProfile({ strict = false } = {}) {
  const node = document.createElement('div');
  const root = createRoot(node);
  act(() => root.render(strict ? <React.StrictMode><UserProfile /></React.StrictMode> : <UserProfile />));
  return { node, root };
}

function rerenderProfile(view) {
  act(() => view.root.render(<UserProfile />));
}

function deferred() {
  let resolve;
  const promise = new Promise(resolvePromise => { resolve = resolvePromise; });
  return { promise, resolve };
}

function clickActivity(node) {
  const button = [...node.querySelectorAll('button')].find(item => item.textContent.includes('User Activity'));
  act(() => button.dispatchEvent(new MouseEvent('click', { bubbles: true })));
}

function clickEdit(node) {
  const button = [...node.querySelectorAll('button')].find(item => item.textContent.includes('Edit Profile'));
  act(() => button.dispatchEvent(new MouseEvent('click', { bubbles: true })));
}

function changeInput(input, value) {
  act(() => {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  mockUser = { id: 71, username: 'learner-71', email: 'learner@example.test', fullName: 'Owner Seventy One', phone: '555-0071', created_at: '2026-09-01T00:00:00Z' };
  axios.get.mockReset();
  axios.put.mockReset();
  mockUpdateUser.mockReset();
  toast.success.mockReset();
  toast.error.mockReset();
});

test('profile renders only owner-derived activity and last-login projections', async () => {
  axios.get.mockResolvedValue({ data: {
    lastLogin: '2026-09-14T12:00:00Z',
    activity: [{ id: 'obj_1', type: 'challenge', title: 'Completed: Real objective', timestamp: '2026-09-14T11:00:00Z' }],
  } });
  const view = renderProfile();
  await flush();
  clickActivity(view.node);

  expect(axios.get).toHaveBeenCalledWith('/api/workshop/user-activity', expect.objectContaining({ signal: expect.any(AbortSignal) }));
  expect(view.node.textContent).toContain('Completed: Real objective');
  expect(view.node.textContent).not.toContain('Completed SQL Injection challenge');
  expect(view.node.textContent).not.toContain('Started XSS challenge');
  expect(view.node.textContent).not.toContain('Sep 05, 2025');
  expect(view.node.textContent).toContain('Sep 14, 2026');
  act(() => view.root.unmount());
});

test('profile distinguishes an empty activity projection from an unavailable one', async () => {
  axios.get.mockResolvedValueOnce({ data: { activity: [], lastLogin: null } });
  const empty = renderProfile();
  await flush();
  clickActivity(empty.node);
  expect(empty.node.textContent).toContain('No account activity recorded.');
  expect(empty.node.textContent).toContain('Never');
  act(() => empty.root.unmount());

  axios.get.mockRejectedValueOnce(new Error('activity offline'));
  const unavailable = renderProfile();
  await flush();
  clickActivity(unavailable.node);
  expect(unavailable.node.textContent).toContain('Account activity is temporarily unavailable.');
  expect(unavailable.node.textContent).toContain('Unavailable');
  expect(unavailable.node.textContent).not.toContain('No account activity recorded.');
  act(() => unavailable.root.unmount());
});

test('profile resets owner state and ignores an old owner response that arrives late', async () => {
  const oldOwner = deferred();
  axios.get.mockImplementationOnce(() => oldOwner.promise).mockResolvedValueOnce({ data: {
    activity: [{ id: 'owner_72', title: 'Owner 72 activity', timestamp: '2026-09-15T12:00:00Z' }],
    lastLogin: null,
  } });
  const view = renderProfile();
  expect(view.node.textContent).toContain('learner-71');
  clickEdit(view.node);
  const oldFullName = view.node.querySelectorAll('input[type="text"]')[1];
  changeInput(oldFullName, 'OWNER_71_PRIVATE_DRAFT');

  mockUser = { id: 72, username: 'learner-72', email: 'owner72@example.test', fullName: 'Owner Seventy Two', created_at: null };
  rerenderProfile(view);
  expect(view.node.textContent).toContain('learner-72');
  expect(view.node.textContent).not.toContain('learner-71');
  clickEdit(view.node);
  expect(view.node.querySelectorAll('input[type="text"]')[1].value).toBe('Owner Seventy Two');
  expect(view.node.querySelectorAll('input[type="text"]')[1].value).not.toBe('OWNER_71_PRIVATE_DRAFT');
  await flush();
  clickActivity(view.node);
  expect(view.node.textContent).toContain('Owner 72 activity');

  await act(async () => oldOwner.resolve({ data: {
    activity: [{ id: 'owner_71', title: 'Old owner activity', timestamp: '2026-09-14T12:00:00Z' }],
    lastLogin: '2026-09-14T12:00:00Z',
  } }));
  await flush();
  expect(view.node.textContent).not.toContain('Old owner activity');
  expect(view.node.textContent).toContain('Owner 72 activity');
  act(() => view.root.unmount());
});

test('profile does not fetch without an authenticated owner and treats malformed activity as unavailable', async () => {
  mockUser = null;
  const absent = renderProfile();
  await flush();
  expect(axios.get).not.toHaveBeenCalled();
  clickActivity(absent.node);
  expect(absent.node.textContent).toContain('Account activity is temporarily unavailable.');
  act(() => absent.root.unmount());

  mockUser = { id: 73, username: 'learner-73' };
  axios.get.mockResolvedValueOnce({ data: { lastLogin: null } });
  const malformed = renderProfile();
  await flush();
  clickActivity(malformed.node);
  expect(malformed.node.textContent).toContain('Account activity is temporarily unavailable.');
  expect(malformed.node.textContent).not.toContain('No account activity recorded.');
  act(() => malformed.root.unmount());
});

test('profile saves only accepted fields and applies sanitized returned PostgreSQL values once', async () => {
  axios.get.mockResolvedValue({ data: { activity: [], lastLogin: null } });
  const save = deferred();
  axios.put.mockImplementationOnce(() => save.promise);
  const view = renderProfile();
  await flush();
  clickEdit(view.node);

  const textInputs = view.node.querySelectorAll('input[type="text"]');
  const username = textInputs[0];
  const fullName = textInputs[1];
  const email = view.node.querySelector('input[type="email"]');
  const phone = view.node.querySelector('input[type="tel"]');
  expect(username.readOnly).toBe(true);
  expect(username.value).toBe('learner-71');
  expect(phone.readOnly).toBe(true);
  expect(phone.value).toBe('555-0071');
  expect(view.node.textContent).toContain('Usernames are fixed when the account is created.');
  expect(view.node.textContent).toContain('Phone numbers cannot be changed from this profile form.');
  changeInput(fullName, '  Submitted Name  ');
  changeInput(email, 'submitted@example.test');

  const button = [...view.node.querySelectorAll('button')].find(item => item.textContent.includes('Update Profile'));
  act(() => {
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
  expect(axios.put).toHaveBeenCalledTimes(1);
  expect(axios.put).toHaveBeenCalledWith('/api/auth/profile', {
    email: 'submitted@example.test',
    fullName: '  Submitted Name  '
  }, expect.objectContaining({ signal: expect.any(AbortSignal) }));

  await act(async () => save.resolve({ data: { success: true, user: {
    id: 71,
    username: 'learner-71',
    email: 'sanitized@example.test',
    full_name: 'Sanitized Name'
  } } }));
  await flush();
  expect(mockUpdateUser).toHaveBeenCalledTimes(1);
  expect(mockUpdateUser).toHaveBeenCalledWith(expect.objectContaining({
    id: 71,
    email: 'sanitized@example.test',
    full_name: 'Sanitized Name',
    fullName: 'Sanitized Name'
  }));
  expect(view.node.querySelectorAll('input[type="text"]')[1].value).toBe('Sanitized Name');
  expect(view.node.querySelector('input[type="email"]').value).toBe('sanitized@example.test');
  expect(toast.success).toHaveBeenCalledTimes(1);
  act(() => view.root.unmount());
});

test('late profile-save responses cannot update a replacement owner', async () => {
  axios.get.mockResolvedValue({ data: { activity: [], lastLogin: null } });
  const oldSave = deferred();
  axios.put.mockImplementationOnce(() => oldSave.promise);
  const view = renderProfile();
  await flush();
  clickEdit(view.node);
  changeInput(view.node.querySelectorAll('input[type="text"]')[1], 'OWNER_71_SAVE_DRAFT');
  const saveButton = [...view.node.querySelectorAll('button')].find(item => item.textContent.includes('Update Profile'));
  act(() => saveButton.dispatchEvent(new MouseEvent('click', { bubbles: true })));

  mockUser = { id: 72, username: 'learner-72', email: 'owner72@example.test', fullName: 'Owner Seventy Two' };
  rerenderProfile(view);
  await act(async () => oldSave.resolve({ data: { success: true, user: {
    id: 71,
    username: 'learner-71',
    email: 'late@example.test',
    full_name: 'Late Owner Name'
  } } }));
  await flush();
  expect(mockUpdateUser).not.toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();
  expect(view.node.textContent).toContain('learner-72');
  expect(view.node.textContent).not.toContain('Late Owner Name');
  act(() => view.root.unmount());
});

test('profile reports a bounded server update error without claiming success', async () => {
  axios.get.mockResolvedValue({ data: { activity: [], lastLogin: null } });
  axios.put.mockRejectedValue({ response: { data: { error: `Email already exists${'x'.repeat(300)}` } } });
  const view = renderProfile();
  await flush();
  clickEdit(view.node);
  const saveButton = [...view.node.querySelectorAll('button')].find(item => item.textContent.includes('Update Profile'));
  act(() => saveButton.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  await flush();
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).toHaveBeenCalledTimes(1);
  expect(toast.error.mock.calls[0][0]).toHaveLength(160);
  expect(toast.error.mock.calls[0][0]).toMatch(/^Email already exists/);
  act(() => view.root.unmount());
});

test('StrictMode effect replay retains a live owner authority for saving', async () => {
  axios.get.mockResolvedValue({ data: { activity: [], lastLogin: null } });
  axios.put.mockResolvedValue({ data: { success: true, user: {
    id: 71,
    username: 'learner-71',
    email: 'strict@example.test',
    full_name: 'Strict Owner'
  } } });
  const view = renderProfile({ strict: true });
  await flush();
  clickEdit(view.node);
  changeInput(view.node.querySelector('input[type="email"]'), 'strict@example.test');
  const saveButton = [...view.node.querySelectorAll('button')].find(item => item.textContent.includes('Update Profile'));
  act(() => saveButton.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  await flush();
  expect(axios.put).toHaveBeenCalledTimes(1);
  expect(mockUpdateUser).toHaveBeenCalledTimes(1);
  expect(mockUpdateUser).toHaveBeenCalledWith(expect.objectContaining({ id: 71, fullName: 'Strict Owner' }));
  expect(toast.success).toHaveBeenCalledTimes(1);
  act(() => view.root.unmount());
});

test('malformed successful update payload cannot clear local fields or claim success', async () => {
  axios.get.mockResolvedValue({ data: { activity: [], lastLogin: null } });
  axios.put.mockResolvedValue({ data: { success: true, user: { id: 71, username: 'learner-71' } } });
  const view = renderProfile();
  await flush();
  clickEdit(view.node);
  const originalEmail = view.node.querySelector('input[type="email"]').value;
  const originalFullName = view.node.querySelectorAll('input[type="text"]')[1].value;
  const saveButton = [...view.node.querySelectorAll('button')].find(item => item.textContent.includes('Update Profile'));
  act(() => saveButton.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  await flush();
  expect(mockUpdateUser).not.toHaveBeenCalled();
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).toHaveBeenCalledWith('Failed to update profile');
  expect(view.node.querySelector('input[type="email"]').value).toBe(originalEmail);
  expect(view.node.querySelectorAll('input[type="text"]')[1].value).toBe(originalFullName);
  act(() => view.root.unmount());
});
