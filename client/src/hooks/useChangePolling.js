import { useEffect, useRef } from 'react';
import axios from 'axios';
import { createRevisionPoller } from '../services/revisionPoller';

const useChangePolling = (onChange, workshopKeys = ['*'], options = {}) => {
  const onChangeRef = useRef(onChange);
  const optionsRef = useRef(options);
  onChangeRef.current = onChange;
  optionsRef.current = options;
  const scopeKey = [...new Set(workshopKeys || [])].sort().join(',');

  useEffect(() => {
    const poller = createRevisionPoller({
      ...optionsRef.current.pollerOptions,
      async fetchSnapshot({ signal } = {}) {
        const currentOptions = optionsRef.current;
        const requestOptions = currentOptions.requestOptions || {};
        const response = await (currentOptions.axiosInstance || axios).get(
          currentOptions.endpoint || '/api/changes/revisions',
          {
            ...requestOptions,
            params: {
              ...requestOptions.params,
              workshops: scopeKey || undefined,
            },
            signal,
            timeout: requestOptions.timeout ?? 10000,
          },
        );
        return response.data.revisions;
      },
      async onChange(next, previous, context) {
        await onChangeRef.current?.(next, previous, context);
      },
      // Reconcile once after the first snapshot so initial page data cannot absorb a missed change.
      notifyOnBaseline: true,
    });

    void poller.start();
    return () => poller.stop();
  }, [scopeKey]);
};

export default useChangePolling;
