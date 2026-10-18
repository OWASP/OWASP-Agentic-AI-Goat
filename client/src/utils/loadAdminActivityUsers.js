// Keep the existing activity view complete for workshops larger than one API page.
export async function loadAdminActivityUsers(get, isCurrent) {
  const users = new Map();
  let page = 1;
  while (isCurrent()) {
    const response = await get('/api/admin/users', { params: { page, limit: 100, role: '' } });
    if (!isCurrent()) return null;
    if (!response.data?.success || !Array.isArray(response.data.users)) {
      throw new Error('Invalid admin users response');
    }
    for (const user of response.data.users) users.set(user.id, user);
    const pages = response.data.pagination?.pages;
    if (pages !== undefined && (!Number.isSafeInteger(pages) || pages < 0)) {
      throw new Error('Invalid admin users pagination');
    }
    if (page >= (pages || 1) || response.data.users.length === 0) break;
    page += 1;
  }
  if (!isCurrent()) return null;
  return [...users.values()].sort((a, b) => (b.recent_activity_count || 0) - (a.recent_activity_count || 0));
}
