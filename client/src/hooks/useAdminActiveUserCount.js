import {useEffect, useState} from 'react';
import axios from 'axios';

export default function useAdminActiveUserCount({ownerId, enabled}) {
  const token = localStorage.getItem('token');
  const [snapshot, setSnapshot] = useState(null);
  useEffect(() => {
    if (!enabled || !ownerId || !token) return undefined;
    let current = true, timer;
    const controller = new AbortController();
    const valid = () => current && localStorage.getItem('token') === token;
    async function refresh() {
      try {
        const response = await axios.get('/api/admin/activity-stats', {
          headers: {Authorization: `Bearer ${token}`}, signal: controller.signal,
        });
        const count = response.data?.stats?.active_users;
        if (!response.data?.success || !Number.isSafeInteger(count) || count < 0) throw new Error('Invalid activity count');
        if (valid()) setSnapshot({ownerId, token, count});
      } catch {
        if (valid()) setSnapshot({ownerId, token, count: null});
      } finally {
        if (valid()) timer = setTimeout(refresh, 30000);
      }
    }
    refresh();
    return () => { current = false; clearTimeout(timer); controller.abort(); };
  }, [ownerId, token, enabled]);
  return enabled && snapshot?.ownerId === ownerId && snapshot?.token === token ? snapshot.count : null;
}
