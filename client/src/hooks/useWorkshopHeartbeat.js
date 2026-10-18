import { useEffect, useRef } from 'react';
import axios from 'axios';

const HEARTBEAT_INTERVAL_MS = 30000;
const IDLE_THRESHOLD_MS = 120_000; // 2 minutes — matches server's gap threshold
const ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart'];

export default function useWorkshopHeartbeat(workshopKey) {
  const keyRef = useRef(workshopKey);
  keyRef.current = workshopKey;

  const lastActivityRef = useRef(Date.now());

  useEffect(() => {
    if (!keyRef.current) return;

    const markActive = () => { lastActivityRef.current = Date.now(); };

    const isUserActive = () =>
      document.visibilityState === 'visible' &&
      Date.now() - lastActivityRef.current < IDLE_THRESHOLD_MS;

    const send = () => {
      if (!isUserActive()) return;
      axios.post('/api/workshop/time/heartbeat', { workshopKey: keyRef.current }).catch(() => {});
    };

    ACTIVITY_EVENTS.forEach(e => window.addEventListener(e, markActive, { passive: true }));
    document.addEventListener('visibilitychange', markActive);

    send();
    const id = setInterval(send, HEARTBEAT_INTERVAL_MS);

    return () => {
      clearInterval(id);
      ACTIVITY_EVENTS.forEach(e => window.removeEventListener(e, markActive));
      document.removeEventListener('visibilitychange', markActive);
    };
  }, [workshopKey]);
}
