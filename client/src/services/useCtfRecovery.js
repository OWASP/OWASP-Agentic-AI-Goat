import { useEffect, useRef, useState } from 'react';
import axios from 'axios';
import { canCheckCtfRecovery, createCtfRecoveryState, isCtfRecoveryCancelled, recoveryCancelled, recoveryNeeded, resolveCtfRecovery } from './ctfRecovery';

// References live only in this mounted page; bearer credentials are never persisted.
export default function useCtfRecovery(scope, isScopeCurrent) {
  const scopeRef = useRef(null);
  if (!scopeRef.current || !Object.is(scopeRef.current.value, scope)) {
    scopeRef.current = { value: scope };
  }
  const owner = scopeRef.current;
  const active = useRef(new Set());
  const actions = useRef(new Map());
  const mounted = useRef(true);
  const [notices, setNotices] = useState([]);
  const update = () => { if (mounted.current) setNotices([...active.current].filter(job => job.parked)); };
  useEffect(() => {
    mounted.current = true;
    setNotices([]);
    return () => {
      mounted.current = false;
      for (const job of active.current) { job.controller.abort(); job.finish(recoveryCancelled()); }
      active.current.clear();
    };
  }, [scope]);
  function request(method, url, data, config = {}) {
    const headers = Object.freeze({ ...(config.headers || {}) });
    // A retained callback belongs to the scope that rendered it, even when a
    // later scope uses the same bearer token. Reject before dedup or reset.
    const controller = new AbortController();
    const current = () => mounted.current && scopeRef.current === owner && !controller.signal.aborted
      && (!isScopeCurrent || isScopeCurrent())
      && headers.Authorization === (localStorage.getItem('token') ? `Bearer ${localStorage.getItem('token')}` : undefined);
    if (!current()) return Promise.reject(recoveryCancelled());
    const actionKey = JSON.stringify([method, url, data]);
    const existing = actions.current.get(actionKey);
    if (existing && existing.headers.Authorization === headers.Authorization) return existing.promise;
    if (url === '/api/ctf/admin/reset') {
      for (const job of [...active.current]) job.finish(recoveryCancelled());
    }

    let job;
    const promise = new Promise((resolve, reject) => {
      job = { headers, controller, settled: false, state: null, parked: false, checking: false, message: '', check: null,
        finish(error, value) {
          if (job.settled) return;
          job.settled = true;
          if (actions.current.get(actionKey) === job) actions.current.delete(actionKey);
          clearInterval(watch); active.current.delete(job); controller.abort(); update();
          if (error) reject(error); else resolve(value);
        } };
      const watch = setInterval(() => { if (!current()) job.finish(recoveryCancelled()); }, 200);
      active.current.add(job);
      actions.current.set(actionKey, job);
      const park = error => { job.state = error.recovery; job.message = error.message; job.parked = true; job.checking = false; update(); };
      const fail = error => {
        if (!current() || isCtfRecoveryCancelled(error)) return job.finish(recoveryCancelled());
        if (error.code === 'CTF_RECOVERY_NEEDED') return park(error);
        job.finish(error);
      };
      const check = async (explicit) => {
        if (job.checking || !current()) return;
        job.checking = true; update();
        try {
          const response = await resolveCtfRecovery({ client: axios, state: job.state, headers, signal: controller.signal, isCurrent: current, explicitResume: explicit === true });
          job.finish(null, response);
        } catch (error) { fail(error); }
      };
      job.check = () => check(true);
      job.dismiss = () => job.finish(recoveryCancelled());
      (async () => {
        try {
          const initial = new AbortController();
          let rejectInitial;
          const abortInitial = () => { initial.abort(); rejectInitial?.(recoveryCancelled()); };
          controller.signal.addEventListener('abort', abortInitial, { once: true });
          let timer;
          let response;
          try {
            const options = { ...config, headers, signal: initial.signal };
            response = await Promise.race([
              method === 'delete' ? axios.delete(url, options) : axios[method](url, data, options),
              new Promise((_, reject) => {
                rejectInitial = reject;
                timer = setTimeout(() => {
                  reject(recoveryNeeded(null, 'Outcome unknown: the original request timed out. Do not resubmit automatically.'));
                  initial.abort();
                }, 180000);
              }),
            ]);
          } finally {
            clearTimeout(timer); controller.signal.removeEventListener('abort', abortInitial); initial.abort();
          }
          if (!current()) throw recoveryCancelled();
          if (response?.status !== 202 && response?.data?.pending !== true) return job.finish(null, response);
          job.state = createCtfRecoveryState(/\/attempt$/.test(url) ? 'attempt' : 'operation', response);
          await check(false);
        } catch (error) {
          if (!error?.response && !isCtfRecoveryCancelled(error)) return fail(recoveryNeeded(null, 'Outcome unknown because the response was lost. Do not resubmit automatically.'));
          fail(error);
        }
      })();
    });
    job.promise = promise;
    return promise;
  }
  return { request, notices, canCheck: canCheckCtfRecovery };
}
