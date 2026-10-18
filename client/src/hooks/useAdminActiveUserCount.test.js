import React, {act} from 'react';
import {createRoot} from 'react-dom/client';
import axios from 'axios';
import useAdminActiveUserCount from './useAdminActiveUserCount';
jest.mock('axios', () => ({get: jest.fn()}));
let root, node;
function View(props) {const count = useAdminActiveUserCount(props); return <span>{count ?? '—'}</span>;}
const render = async props => {await act(async () => {root.render(<View {...props}/>);});};
beforeEach(() => {
 global.IS_REACT_ACT_ENVIRONMENT = true;
 node = document.createElement('div'); document.body.append(node); root = createRoot(node);
 localStorage.setItem('token', 'current'); axios.get.mockReset();
});
afterEach(() => {act(() => root.unmount()); node.remove(); localStorage.clear();});
test('uses recorded activity including genuine zero', async () => {
 axios.get.mockResolvedValue({data: {success: true, stats: {active_users: 0}}});
 await render({ownerId: 1, enabled: true}); expect(node.textContent).toBe('0');
 expect(axios.get.mock.calls[0][0]).toBe('/api/admin/activity-stats');
});
test('does not fetch without permission', async () => {
 await render({ownerId: 1, enabled: false});
 expect(axios.get).not.toHaveBeenCalled(); expect(node.textContent).toBe('—');
});
test('late previous-owner response cannot overwrite current owner', async () => {
 let resolve; axios.get.mockImplementationOnce(() => new Promise(r => {resolve = r;}));
 await render({ownerId: 1, enabled: true});
 axios.get.mockResolvedValue({data: {success: true, stats: {active_users: 2}}});
 await render({ownerId: 2, enabled: true});
 await act(async () => {resolve({data: {success: true, stats: {active_users: 99}}});});
 expect(node.textContent).toBe('2');
});
test('permission loss hides existing count', async () => {
 axios.get.mockResolvedValue({data: {success: true, stats: {active_users: 2}}});
 await render({ownerId: 1, enabled: true}); await render({ownerId: 1, enabled: false});
 expect(node.textContent).toBe('—');
});
test('malformed activity does not masquerade as zero', async () => {
 axios.get.mockResolvedValue({data: {success: true, stats: {active_users: '12'}}});
 await render({ownerId: 1, enabled: true}); expect(node.textContent).toBe('—');
});
