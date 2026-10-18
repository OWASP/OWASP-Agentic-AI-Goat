import { useCallback, useRef } from 'react';
import { createReconciliationGuard } from '../services/revisionPoller';

export function useGuardedSetter(setter, guard, domain = 'progress') {
  return useCallback((value) => {
    guard.mark(domain);
    setter(value);
  }, [domain, guard, setter]);
}

export default function useReconciliationGuard() {
  const guardRef = useRef(null);
  if (!guardRef.current) guardRef.current = createReconciliationGuard();
  return guardRef.current;
}
