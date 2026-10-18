import { loadAdminActivityUsers } from './loadAdminActivityUsers';

const response = (users, pages) => ({ data: { success: true, users, pagination: { pages } } });

test('loads a 200-student workshop plus instructor beyond the first page and sorts globally', async () => {
  const all = Array.from({ length: 201 }, (_, index) => ({ id: index + 1, recent_activity_count: index }));
  const get = jest.fn(async (_url, { params }) => response(all.slice((params.page - 1) * 100, params.page * 100), 3));
  const users = await loadAdminActivityUsers(get, () => true);
  expect(users).toHaveLength(201);
  expect(users[0].id).toBe(201);
  expect(get.mock.calls.map(([, config]) => config.params.page)).toEqual([1, 2, 3]);
});

test('superseded refresh stops pagination and cannot replace newer results', async () => {
  let current = true;
  const get = jest.fn(async () => { current = false; return response([{ id: 1 }], 3); });
  expect(await loadAdminActivityUsers(get, () => current)).toBeNull();
  expect(get).toHaveBeenCalledTimes(1);
});

test('a later-page failure rejects instead of presenting partial success', async () => {
  const get = jest.fn().mockResolvedValueOnce(response([{ id: 1 }], 2)).mockRejectedValueOnce(new Error('unavailable'));
  await expect(loadAdminActivityUsers(get, () => true)).rejects.toThrow('unavailable');
});

test('deduplicates overlapping pages and rejects invalid pagination', async () => {
  const get = jest.fn().mockResolvedValueOnce(response([{ id: 1 }], 2)).mockResolvedValueOnce(response([{ id: 1 }, { id: 2 }], 2));
  expect(await loadAdminActivityUsers(get, () => true)).toHaveLength(2);
  await expect(loadAdminActivityUsers(async () => response([], Infinity), () => true)).rejects.toThrow('pagination');
});
