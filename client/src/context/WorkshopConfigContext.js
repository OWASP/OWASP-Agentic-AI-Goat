import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import axios from 'axios';
import { createRevisionPoller, fingerprint } from '../services/revisionPoller';

const WorkshopConfigContext = createContext(null);

function trimTrailingSlashes(value) {
  return value.replace(/\/+$/, '');
}

export function buildWorkshopConfigUrls({ apiBaseUrl = '', locationOrigin } = {}) {
  const configuredBase = trimTrailingSlashes(String(apiBaseUrl || '').trim());

  if (!configuredBase) {
    return {
      snapshotUrl: '/api/workshop/config/snapshot',
      revisionUrl: '/api/workshop/config/revision',
      appChangesRevisionUrl: '/api/changes/revisions',
    };
  }

  const origin = locationOrigin || window.location.origin;
  const configuredUrl = new URL(`${configuredBase}/`, origin);
  const configuredPath = trimTrailingSlashes(configuredUrl.pathname);
  const apiPath = configuredPath.endsWith('/api') ? configuredPath : `${configuredPath}/api`;
  const makeHttpUrl = (suffix) => {
    const url = new URL(configuredUrl.toString());
    url.pathname = `${apiPath}${suffix}`.replace(/\/{2,}/g, '/');
    return url.toString();
  };

  return {
    snapshotUrl: makeHttpUrl('/workshop/config/snapshot'),
    revisionUrl: makeHttpUrl('/workshop/config/revision'),
    appChangesRevisionUrl: makeHttpUrl('/changes/revisions'),
  };
}

function numericRevision(value) {
  const revision = Number(value);
  return Number.isFinite(revision) && revision >= 0 ? revision : null;
}

function configRelevantRevisions(changes) {
  return {
    global: changes?.global,
    workshops: changes?.workshops,
    user: Object.fromEntries(Object.entries(changes?.user || {})
      .filter(([category]) => category !== 'workshop_progress' && category !== 'workshop_time')),
  };
}

function createSyncError(prefix, cause) {
  const detail = cause instanceof Error ? cause.message : String(cause || 'Unknown error');
  return new Error(`${prefix}: ${detail}`);
}

export function WorkshopConfigProvider({
  children,
  token,
  apiBaseUrl,
  pollerOptions = {},
}) {
  const configuredApiBase = apiBaseUrl ?? process.env.REACT_APP_API_URL ?? axios.defaults.baseURL ?? '';
  const urls = useMemo(
    () => buildWorkshopConfigUrls({ apiBaseUrl: configuredApiBase }),
    [configuredApiBase]
  );
  const [snapshot, setSnapshot] = useState(null);
  const [revision, setRevision] = useState(0);
  const [snapshotReadSequence, setSnapshotReadSequence] = useState(0);
  const readSequenceRef = useRef(0);
  const [loading, setLoading] = useState(Boolean(token));
  const [stale, setStale] = useState(false);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState(null);

  const mountedRef = useRef(false);
  const generationRef = useRef(0);
  const committedRevisionRef = useRef(0);
  const snapshotRef = useRef(null);
  const inFlightRef = useRef(null);
  const requiredRevisionRef = useRef(null);
  const refreshRef = useRef(null);
  const reconcilersRef = useRef(new Set());
  const pollerOptionsRef = useRef(pollerOptions);
  pollerOptionsRef.current = pollerOptions;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      generationRef.current += 1;
      inFlightRef.current?.controller?.abort();
      inFlightRef.current = null;
    };
  }, []);

  const requestConfig = useMemo(() => ({
    headers: { Authorization: `Bearer ${token}` },
  }), [token]);

  const runRefresh = useCallback((minimumRevision = null, { background = false, signal } = {}) => {
    if (!token) return Promise.resolve(null);

    const requestedRevision = numericRevision(minimumRevision);
    if (requestedRevision !== null) {
      requiredRevisionRef.current = Math.max(
        requiredRevisionRef.current ?? 0,
        requestedRevision
      );
    }

    const generation = generationRef.current;
    if (inFlightRef.current?.generation === generation) {
      return inFlightRef.current.promise;
    }

    const readSequence = ++readSequenceRef.current;
    const targetRevision = requiredRevisionRef.current;
    const controller = typeof AbortController === 'undefined' ? null : new AbortController();
    const abortFromReconciliation = () => controller?.abort();
    if (signal?.aborted) abortFromReconciliation();
    else signal?.addEventListener?.('abort', abortFromReconciliation, { once: true });
    let followUpForHigherRevision = false;
    if (!background && !snapshotRef.current) setLoading(true);

    const request = axios.get(urls.snapshotUrl, {
      ...requestConfig,
      signal: controller?.signal || signal,
      ...(background ? { timeout: requestConfig.timeout ?? 10000 } : {}),
    })
      .then(({ data }) => {
        if (!mountedRef.current || generation !== generationRef.current || controller?.signal.aborted || signal?.aborted) {
          return null;
        }
        const responseRevision = numericRevision(data?.revision);
        if (responseRevision === null || !data?.exercises || typeof data.exercises !== 'object') {
          throw new Error('Invalid workshop configuration snapshot');
        }

        const requiredRevision = requiredRevisionRef.current;
        if (requiredRevision !== null && responseRevision < requiredRevision) {
          followUpForHigherRevision = targetRevision === null || requiredRevision > targetRevision;
          throw new Error(
            `Workshop configuration snapshot revision ${responseRevision} is behind announced revision ${requiredRevision}`
          );
        }
        if (responseRevision < committedRevisionRef.current) return snapshotRef.current;

        committedRevisionRef.current = responseRevision;
        snapshotRef.current = data;
        if (requiredRevision !== null && responseRevision >= requiredRevision) {
          requiredRevisionRef.current = null;
        }
        setSnapshot(data);
        setSnapshotReadSequence(readSequence);
        setRevision(responseRevision);
        setConnected(true);
        setStale(false);
        setError(null);
        return data;
      })
      .catch((cause) => {
        if (!mountedRef.current || generation !== generationRef.current || controller?.signal.aborted || signal?.aborted) {
          return null;
        }
        if (!background) {
          setStale(true);
          setError(createSyncError('Workshop configuration snapshot refresh failed', cause));
        }
        throw cause;
      })
      .finally(() => {
        signal?.removeEventListener?.('abort', abortFromReconciliation);
        if (!mountedRef.current || generation !== generationRef.current) return;
        if (inFlightRef.current?.promise === request) inFlightRef.current = null;
        if (!background) setLoading(false);

        const requiredRevision = requiredRevisionRef.current;
        if (followUpForHigherRevision
          && requiredRevision !== null
          && requiredRevision > committedRevisionRef.current) {
          void refreshRef.current?.(requiredRevision, { background: true }).catch(() => {});
        }
      });

    inFlightRef.current = { generation, promise: request, controller };
    return request;
  }, [requestConfig, token, urls.snapshotUrl]);

  refreshRef.current = runRefresh;

  const refresh = useCallback((minimumRevision = null) => (
    runRefresh(minimumRevision, { background: false }).catch(() => null)
  ), [runRefresh]);

  // A committed mutation needs a new read, even while background polling is paused.
  const retireSnapshotReads = useCallback(() => {
    inFlightRef.current?.controller?.abort();
    inFlightRef.current = null;
    return readSequenceRef.current;
  }, []);

  const refreshAfterMutation = useCallback(({ signal } = {}) => {
    if (signal?.aborted) return Promise.resolve(null);
    // Retire the older read before starting the new one; its late response cannot publish.
    retireSnapshotReads();
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener('abort', abort, { once: true });
    let onAbort;
    const cancelled = new Promise(resolve => {
      onAbort = () => resolve(null);
      controller.signal.addEventListener('abort', onAbort, { once: true });
    });
    const timer = setTimeout(abort, 10000);
    return Promise.race([
      runRefresh(null, { background: true, signal: controller.signal }).catch(() => null),
      cancelled,
    ]).finally(() => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      controller.signal.removeEventListener('abort', onAbort);
    });
  }, [runRefresh, retireSnapshotReads]);

  const registerReconciler = useCallback((reconciler) => {
    if (typeof reconciler !== 'function') {
      throw new TypeError('Workshop configuration reconciler must be a function');
    }
    reconcilersRef.current.add(reconciler);
    return () => reconcilersRef.current.delete(reconciler);
  }, []);

  const reconcileConsumers = useCallback(async (nextRevision, context = {}) => {
    const mountedReconcilers = [...reconcilersRef.current];
    await Promise.all(mountedReconcilers.map((reconciler) => reconciler(nextRevision, context)));
  }, []);

  useEffect(() => {
    generationRef.current += 1;
    inFlightRef.current?.controller?.abort();
    inFlightRef.current = null;
    requiredRevisionRef.current = null;
    committedRevisionRef.current = 0;
    snapshotRef.current = null;
    setSnapshot(null);
    setRevision(0);
    setConnected(false);
    setStale(false);
    setError(null);
    setLoading(Boolean(token));
    if (token) void refresh();
  }, [refresh, token]);

  useEffect(() => {
    if (!token) return undefined;
    const generation = generationRef.current;
    const poller = createRevisionPoller({
      ...pollerOptionsRef.current,
      async fetchSnapshot({ signal } = {}) {
        const [{ data: configRevisionData }, { data: appChangesData }] = await Promise.all([
          axios.get(urls.revisionUrl, {
            ...requestConfig,
            signal,
            timeout: requestConfig.timeout ?? 10000,
          }),
          axios.get(urls.appChangesRevisionUrl, {
            ...requestConfig,
            params: { workshops: '*' },
            signal,
            timeout: requestConfig.timeout ?? 10000,
          }),
        ]);
        if (!mountedRef.current || generation !== generationRef.current) {
          throw new Error('Workshop configuration polling generation replaced');
        }
        const serverRevision = numericRevision(configRevisionData?.revision);
        if (serverRevision === null) throw new Error('Invalid workshop configuration revision');
        const appChanges = appChangesData?.revisions;
        if (!appChanges || typeof appChanges !== 'object' || Array.isArray(appChanges)) {
          throw new Error('Invalid application change revision snapshot');
        }
        setConnected(true);
        return { revision: serverRevision, appChanges };
      },
      async onChange(next, previous, context = {}) {
        if (!mountedRef.current || generation !== generationRef.current) return;
        const serverRevision = numericRevision(next?.revision);
        if (serverRevision === null) throw new Error('Invalid workshop configuration revision');
        const requiredRevision = Math.max(serverRevision, requiredRevisionRef.current ?? 0);
        const configChangesChanged = previous !== undefined
          && fingerprint(configRelevantRevisions(previous?.appChanges))
            !== fingerprint(configRelevantRevisions(next?.appChanges));
        // Progress and time revisions are user-scoped. Their consumers read the
        // canonical challenge projection, so an unrelated config read must not
        // hold up a newly awarded completion or reset. A config change still
        // forces a read if its revision request raced the mutation.
        const requiresForcedRefresh = previous === undefined || configChangesChanged;

        if (requiresForcedRefresh) {
          const olderRefresh = inFlightRef.current?.promise;
          if (olderRefresh) await olderRefresh;
          if (!mountedRef.current || generation !== generationRef.current || context.signal?.aborted) return;
          await refreshRef.current?.(requiredRevision, { background: true, signal: context.signal });
        } else if (!snapshotRef.current || requiredRevision > committedRevisionRef.current) {
          await refreshRef.current?.(requiredRevision, { background: true, signal: context.signal });
        }
        if (context.signal?.aborted) return;
        await reconcileConsumers(requiredRevision, context);
      },
      notifyOnBaseline: true,
    });

    void poller.start();
    return () => poller.stop();
  }, [reconcileConsumers, requestConfig, token, urls.appChangesRevisionUrl, urls.revisionUrl]);

  const value = useMemo(() => ({
    snapshot,
    revision,
    loading,
    stale,
    connected,
    error,
    refresh,
    refreshAfterMutation,
    retireSnapshotReads,
    snapshotReadSequence,
    registerReconciler,
  }), [connected, error, loading, refresh, refreshAfterMutation, retireSnapshotReads, snapshotReadSequence, registerReconciler, revision, snapshot, stale]);

  return (
    <WorkshopConfigContext.Provider value={value}>
      {children}
    </WorkshopConfigContext.Provider>
  );
}

export function useWorkshopConfig() {
  const context = useContext(WorkshopConfigContext);
  if (!context) throw new Error('useWorkshopConfig must be used within a WorkshopConfigProvider');
  return context;
}
