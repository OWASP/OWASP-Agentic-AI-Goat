import BoundSystemRestart from './BoundSystemRestart.jsx';
import React, { useCallback, useContext, useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import PageTransition from '../../components/PageTransition.jsx';
import { AuthCtx } from '../../context/AuthContext.jsx';
import { getBridgeFetchMetadata } from '../../bridge/fetchAdapter.mjs';
import { useToast } from '../../context/ToastContext.jsx';
import { readSystemConfigReferences, saveSystemConfigReference, forgetSystemConfigReference } from './systemConfigRecovery.js';
import { rebuildRequest, validateCompletedRebuild, validateFailedRebuild } from './systemRebuildOperation.mjs';
import { readSystemRebuildReferences, saveSystemRebuildReference, forgetSystemRebuildReference } from './systemRebuildRecovery.js';
import { readSystemDiagnosticReferences, saveSystemDiagnosticReference, forgetSystemDiagnosticReference } from './systemDiagnosticRecovery.js';

/**
 * Admin — System.jsx (Wave 2C).
 *
 * Platform system control panel. Preserves four intentional surfaces:
 *   - path traversal + credential leak via /admin/system/read-config
 *   - RCE via /admin/system/diagnostic (cmd_template + args exec)
 *   - command injection via /admin/system/restart-service
 *   - config-viewer XSS when config content contains HTML (dangerouslySetInnerHTML)
 *
 * The exec surfaces are guarded by SS_SYSTEM_ALLOW_EXEC=true — but the
 * constructed cmd is always displayed so students can inspect the sink.
 */

const COMMAND_TEMPLATES = [
  { label: 'ping',     value: 'ping -c 2' },
  { label: 'nslookup', value: 'nslookup' },
  { label: 'curl',     value: 'curl -s' },
  { label: 'echo',     value: 'echo' },
  { label: 'custom',   value: '' },
];

const CORPORA = ['products', 'reviews', 'manuals', 'policies'];
const BOUND_CONFIG_CAPABILITY = 'secureshop-owned-system-config-read.v1';
const BOUND_DIAGNOSTIC_CAPABILITY = 'secureshop-owned-system-diagnostic.v1';
const DIAGNOSTIC_VERSION = 'secureshop-owned-system-diagnostic.v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
async function sha256Json(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}
async function diagnosticDigest(request) {
  return sha256Json({ version: DIAGNOSTIC_VERSION, request });
}

export default function AdminSystem() {
  const authToken = useContext(AuthCtx)?.token;
  const transport = globalThis.fetch;
  const bridgeMetadata = getBridgeFetchMetadata(transport);
  const attachedBridge = !!bridgeMetadata;
  const [configBoundReady, setConfigBoundReady] = useState(false);
  const boundSystem = attachedBridge && configBoundReady;
  const epoch = useRef(0);
  const live = useRef({ authToken, transport });
  const mounted = useRef(true);
  const controllers = useRef(new Set());
  const operations = useRef(new Map());
  live.current = { authToken, transport };
  const current = (generation, controller) => mounted.current
    && !controller.signal.aborted
    && epoch.current === generation
    && live.current.authToken === authToken
    && live.current.transport === transport
    && globalThis.fetch === transport;
  const beginOperation = operation => {
    if (operations.current.has(operation)) return null;
    const controller = new AbortController();
    operations.current.set(operation, controller);
    controllers.current.add(controller);
    return { controller, generation: epoch.current };
  };
  const endOperation = (operation, controller) => {
    controllers.current.delete(controller);
    if (operations.current.get(operation) !== controller) return false;
    operations.current.delete(operation);
    return true;
  };

  const [health, setHealth] = useState(null);
  const [hostStatus, setHostStatus] = useState(null);
  const [healthErrors, setHealthErrors] = useState({});

  // Config viewer
  const [configPath, setConfigPath] = useState(attachedBridge ? 'application.json' : '.env');
  const [configResult, setConfigResult] = useState(null);
  const [configBusy, setConfigBusy] = useState(false);
  const [configAdministration, setConfigAdministration] = useState(null);
  const [configReferences, setConfigReferences] = useState([]);
  const [configNotice, setConfigNotice] = useState(null);

  // Diagnostic
  const [diagTemplate, setDiagTemplate] = useState('ping -c 2');
  const [diagArgs, setDiagArgs] = useState('127.0.0.1');
  const [diagCustom, setDiagCustom] = useState('');
  const [diagResult, setDiagResult] = useState(null);
  const [diagBusy, setDiagBusy] = useState(false);
  const [diagAdministration, setDiagAdministration] = useState(null);
  const [diagBoundReady, setDiagBoundReady] = useState(false);
  const [diagReferences, setDiagReferences] = useState([]);
  const [diagNotice, setDiagNotice] = useState(null);
  const boundDiagnostic = attachedBridge && diagBoundReady;

  // Restart
  const [restartName, setRestartName] = useState('nginx');
  const [restartResult, setRestartResult] = useState(null);
  const [restartBusy, setRestartBusy] = useState(false);

  // Vector index
  const [rebuildResult, setRebuildResult] = useState(null);
  const [rebuildAdministration, setRebuildAdministration] = useState(null);
  const [rebuildReferences, setRebuildReferences] = useState([]);
  const [rebuildNotice, setRebuildNotice] = useState(null);
  const [rebuildBusy, setRebuildBusy] = useState(null); // corpus name while active

  const toastApi = useToast();
  const showToast = useCallback((msg, kind = 'info') => {
    if (kind === 'success') toastApi.success(msg);
    else if (kind === 'error') toastApi.error(msg);
    else if (kind === 'warn') toastApi.warn(msg);
    else toastApi.info(msg);
  }, [toastApi]);

  useEffect(() => {
    const generation = ++epoch.current;
    for (const controller of controllers.current) controller.abort();
    controllers.current.clear();
    operations.current.clear();
    setHealth(null);
    setHostStatus(null);
    setHealthErrors({});
    setConfigResult(null);
    setConfigAdministration(null);
    setConfigBoundReady(false);
    setConfigReferences([]);
    setConfigNotice(null);
    setDiagResult(null);
    setDiagAdministration(null);
    setDiagBoundReady(false);
    setDiagReferences([]);
    setDiagNotice(null);
    setRestartResult(null);
    setRebuildResult(null);
    setRebuildAdministration(null);
    setRebuildReferences([]);
    setRebuildNotice(null);
    setConfigBusy(false);
    setDiagBusy(false);
    setRestartBusy(false);
    setRebuildBusy(null);

    const controller = new AbortController();
    operations.current.set('health', controller);
    controllers.current.add(controller);
    for (const [key, url, setter, field] of [
      ['system', '/api/secureshop/admin/system/health', setHealth, 'hostname'],
      ['runtime', '/api/secureshop/admin/agent-host/health', setHostStatus, 'status'],
    ]) {
      (async () => {
        try {
          const response = await transport(url, { signal: controller.signal });
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          const value = await response.json();
          if (typeof value?.[field] !== 'string' || !value[field]) throw new Error('Invalid health response');
          if (current(generation, controller)) setter(value);
        } catch (error) {
          if (current(generation, controller)) setHealthErrors(prev => ({ ...prev, [key]: error.message }));
        }
      })();
    }
    return () => {
      controller.abort();
      controllers.current.delete(controller);
      if (operations.current.get('health') === controller) operations.current.delete('health');
    };
  }, [authToken, transport]);

  useEffect(() => {
    if (!attachedBridge) {
      return undefined;
    }
    const request = beginOperation('system-config-administration');
    if (!request) return undefined;
    const { controller, generation } = request;
    (async () => {
      try {
        const response = await transport('/api/secureshop/admin/system/config-read', { signal: controller.signal });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const value = await response.json();
        if (value?.ok !== true || value.administration?.configReadCapability !== BOUND_CONFIG_CAPABILITY || typeof value.administration?.scopeKey !== 'string' || !/^[a-f0-9]{64}$/.test(value.administration.scopeKey)) throw new Error('Invalid config-read capability');
        if (!current(generation, controller)) return;
        setConfigAdministration(value.administration);
        setConfigBoundReady(true);
        setConfigReferences(readSystemConfigReferences());
      } catch (error) {
        if (current(generation, controller)) { setConfigAdministration(null); setConfigBoundReady(false); setConfigNotice(`bound config read unavailable: ${error.message}`); }
      } finally {
        endOperation('system-config-administration', controller);
      }
    })();
    return () => controller.abort();
  }, [authToken, transport, attachedBridge]);

  useEffect(() => {
    if (!attachedBridge) return undefined;
    const request = beginOperation('system-diagnostic-administration');
    if (!request) return undefined;
    const { controller, generation } = request;
    (async () => {
      try {
        const response = await transport('/api/secureshop/admin/system/diagnostic', { signal: controller.signal });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const value = await response.json();
        const administration = value?.administration;
        if (value?.ok !== true || administration?.diagnosticCapability !== BOUND_DIAGNOSTIC_CAPABILITY
          || typeof administration?.scopeKey !== 'string' || !HASH.test(administration.scopeKey)) throw new Error('Invalid diagnostic capability');
        if (!current(generation, controller)) return;
        setDiagAdministration(administration);
        setDiagBoundReady(true);
        try { setDiagReferences(readSystemDiagnosticReferences()); }
        catch (error) { setDiagNotice(`diagnostic operation references unavailable: ${error.message}`); }
      } catch (error) {
        if (current(generation, controller)) { setDiagAdministration(null); setDiagBoundReady(false); setDiagNotice(`bound diagnostic unavailable: ${error.message}`); }
      } finally { endOperation('system-diagnostic-administration', controller); }
    })();
    return () => controller.abort();
  }, [authToken, transport, attachedBridge]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      ++epoch.current;
      for (const controller of controllers.current) controller.abort();
      controllers.current.clear();
      operations.current.clear();
    };
  }, []);

  const validateBoundConfig = (value, operationId, expectedPath) => {
    const read = value;
    if (read?.ok !== true || read.operationId !== operationId || read.state !== 'completed'
      || typeof read.input !== 'string' || typeof read.sanitized !== 'string' || typeof read.abs !== 'string'
      || !read.abs.startsWith('/app/') || typeof read.content !== 'string'
      || (expectedPath !== undefined && read.input !== expectedPath) || !Number.isSafeInteger(read.size) || read.size < 0
      || read.size > 512 * 1024 || new TextEncoder().encode(read.content).byteLength !== read.size || typeof read.contentSha256 !== 'string'
      || !/^[a-f0-9]{64}$/.test(read.contentSha256)) throw new Error('Invalid config-read receipt');
    return { ...read, ok: true };
  };

  const saveReference = async (reference, generation, controller) => {
    const next = await saveSystemConfigReference(reference);
    if (!current(generation, controller)) return false;
    setConfigReferences(next);
    return true;
  };

  const recoverConfig = async reference => {
    if (!boundSystem || !configAdministration) return;
    if (reference.scopeKey !== configAdministration.scopeKey) { setConfigNotice('This config operation belongs to another launch or session.'); return; }
    const request = beginOperation(`config-recovery:${reference.operationId}`);
    if (!request) return;
    const { controller, generation } = request;
    setConfigBusy(true);
    try {
      const response = await transport(`/api/secureshop/admin/system/config-operations/${encodeURIComponent(reference.operationId)}`, { signal: controller.signal });
      const value = await response.json();
      if (value?.operationId !== reference.operationId) throw new Error('Invalid config operation');
      if (response.status === 202 || value?.state === 'pending') { if (current(generation, controller)) setConfigNotice('Config read remains pending. No read was repeated.'); return; }
      if (value?.state === 'unknown' || value?.code === 'SYSTEM_CONFIG_OUTCOME_UNCERTAIN') {
        if (current(generation, controller)) {
          const saved = await saveReference({ ...reference, state: 'unknown' }, generation, controller);
          if (!saved || !current(generation, controller)) return;
          setConfigNotice('Config read outcome is unknown; no read was repeated.');
        }
        return;
      }
      if (value?.state === 'not_executed') {
        if (!current(generation, controller)) return;
        const next = await forgetSystemConfigReference(reference);
        if (current(generation, controller)) { setConfigReferences(next); setConfigNotice('Config read was not executed.'); }
        return;
      }
      if (value?.state === 'completed' && value?.ok === false) {
        if (!current(generation, controller)) return;
        const next = await forgetSystemConfigReference(reference);
        if (!current(generation, controller)) return;
        setConfigReferences(next); setConfigNotice(value.error || 'Config read completed without a read result.');
        return;
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = validateBoundConfig(value, reference.operationId);
      if (!current(generation, controller)) return;
      setConfigResult(result); setConfigNotice(null);
      const next = await forgetSystemConfigReference(reference);
      if (!current(generation, controller)) return;
      setConfigReferences(next);
      showToast(`read ${result.size} bytes`, 'success');
    } catch (error) {
      if (current(generation, controller)) setConfigNotice(`config read recovery failed: ${error.message}`);
    } finally {
      if (endOperation(`config-recovery:${reference.operationId}`, controller) && current(generation, controller)) setConfigBusy(false);
    }
  };

  const dismissConfigReference = async reference => {
    const request = beginOperation(`config-dismiss:${reference.operationId}`);
    if (!request) return;
    const { controller, generation } = request;
    try {
      const next = await forgetSystemConfigReference(reference);
      if (current(generation, controller)) setConfigReferences(next);
    } catch (error) { if (current(generation, controller)) setConfigNotice(`config operation reference unavailable: ${error.message}`); }
    finally { endOperation(`config-dismiss:${reference.operationId}`, controller); }
  };

  const readBoundCfg = async e => {
    e && e.preventDefault();
    if (!configAdministration) { setConfigNotice('Bound config read unavailable'); return; }
    const request = beginOperation('read-config');
    if (!request) return;
    const { controller, generation } = request;
    setConfigBusy(true);
    let operationId;
    let reference;
    let dispatched = false;
    try {
      operationId = crypto.randomUUID().toLowerCase();
      reference = { scopeKey: configAdministration.scopeKey, operationId, state: 'pending' };
      if (!await saveReference(reference, generation, controller)) return;
      if (!current(generation, controller)) return;
      dispatched = true;
      const response = await transport('/api/secureshop/admin/system/config-read', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ operationId, path: configPath }), signal: controller.signal,
      });
      const value = await response.json();
      if ((response.ok || value?.state !== undefined) && value?.operationId !== operationId) throw new Error('Invalid config-read operation');
      if (response.status === 202 || value?.state === 'pending') {
        if (current(generation, controller)) setConfigNotice('Config read remains pending. No read was repeated.');
        return;
      }
      if (value?.state === 'not_executed') {
        if (!current(generation, controller)) return;
        const next = await forgetSystemConfigReference(reference);
        if (current(generation, controller)) { setConfigReferences(next); setConfigNotice('Config read was not executed.'); }
        return;
      }
      if (value?.state === 'completed' && value?.ok === false) {
        if (!current(generation, controller)) return;
        const next = await forgetSystemConfigReference(reference);
        if (!current(generation, controller)) return;
        setConfigReferences(next); setConfigNotice(value.error || 'Config read completed without a read result.');
        return;
      }
      if (!response.ok) {
        if (dispatched && current(generation, controller)) {
          try { await saveReference({ ...reference, state: 'unknown' }, generation, controller); }
          catch (storageError) { if (current(generation, controller)) setConfigNotice(`config operation reference unavailable: ${storageError.message}`); }
        }
        throw new Error(value?.code || `HTTP ${response.status}`);
      }
      const result = validateBoundConfig(value, operationId, configPath);
      if (!current(generation, controller)) return;
      setConfigResult(result); setConfigNotice(null);
      // Retain only the opaque operation reference so a reload can recover
      // the durable receipt. File paths and contents remain out of storage.
      const saved = await saveReference({ ...reference, state: 'completed' }, generation, controller);
      if (!saved || !current(generation, controller)) return;
      showToast(`read ${result.size} bytes`, 'success');
    } catch (error) {
      if (current(generation, controller)) {
        setConfigNotice(`config read failed: ${error.message}`);
        if (dispatched) { try { setConfigReferences(readSystemConfigReferences()); } catch (storageError) { setConfigNotice(`config operation reference unavailable: ${storageError.message}`); } }
      }
    } finally {
      if (endOperation('read-config', controller) && current(generation, controller)) setConfigBusy(false);
    }
  };

  const readCfg = async (e) => {
    if (attachedBridge && !boundSystem) { e && e.preventDefault(); setConfigNotice('Bound config read capability unavailable'); return; }
    if (boundSystem) return readBoundCfg(e);
    e && e.preventDefault();
    const request = beginOperation('read-config');
    if (!request) return;
    const { controller, generation } = request;
    setConfigBusy(true);
    try {
      const r = await transport('/api/secureshop/admin/system/read-config', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ path: configPath }),
        signal: controller.signal,
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      if (j?.ok !== true) throw new Error(j?.error || 'Operation failed');
      if (typeof j.content !== 'string' || !Number.isFinite(j.size) || j.size < 0) throw new Error('Invalid config response');
      if (!current(generation, controller)) return;
      setConfigResult(j);
      showToast(`read ${j.size} bytes`, 'success');
    } catch (error) {
      if (!current(generation, controller)) return;
      setConfigResult({ok:false,error:error.message});
      showToast(`read failed: ${error.message}`, 'error');
    } finally {
      if (endOperation('read-config', controller) && current(generation, controller)) setConfigBusy(false);
    }
  };

  const validateBoundDiagnostic = async (value, operationId, requestSha256) => {
    if (value?.ok !== true || value.operationId !== operationId || value.state !== 'completed'
      || typeof value.requestSha256 !== 'string' || !HASH.test(value.requestSha256)
      || (requestSha256 !== undefined && value.requestSha256 !== requestSha256)
      || typeof value.targetId !== 'string' || !UUID.test(value.targetId)
      || value.hostname !== `system-diag-${value.targetId.replaceAll('-', '')}`
      || typeof value.bindingSha256 !== 'string' || !HASH.test(value.bindingSha256)
      || typeof value.cmd !== 'string' || value.executed !== true || value.timedOut !== false
      || value.truncated !== false || value.drained !== true
      || (!Number.isInteger(value.exitCode) && value.exitCode !== null)
      || (value.signal !== null && (!Number.isInteger(value.signal) || value.signal < 1 || value.signal > 64))
      || typeof value.stdout !== 'string' || typeof value.stderr !== 'string') throw new Error('Invalid diagnostic receipt');
    const exited = Number.isInteger(value.exitCode) && value.exitCode >= 0 && value.exitCode <= 255 && value.signal === null;
    const signaled = value.exitCode === null && Number.isInteger(value.signal) && value.signal >= 1 && value.signal <= 64;
    if (!exited && !signaled) throw new Error('Invalid diagnostic receipt');
    const receipt = value.receipt;
    if (!receipt || receipt.version !== 'secureshop-owned-system-diagnostic-http.v1'
      || receipt.targetId !== value.targetId || receipt.hostname !== value.hostname
      || receipt.bindingSha256 !== value.bindingSha256 || !receipt.result
      || receipt.result.operationId !== operationId || receipt.result.requestSha256 !== value.requestSha256
      || receipt.result.command !== value.cmd || receipt.result.executed !== true || receipt.result.exitCode !== value.exitCode
      || receipt.result.signal !== value.signal || receipt.result.timedOut !== false
      || receipt.result.truncated !== false || receipt.result.drained !== true
      || typeof receipt.result.stdout !== 'string' || typeof receipt.result.stderr !== 'string'
      || typeof receipt.result.encoding !== 'string' || !Number.isSafeInteger(receipt.result.stdoutBytes)
      || !Number.isSafeInteger(receipt.result.stderrBytes) || !HASH.test(receipt.result.stdoutSha256)
      || !HASH.test(receipt.result.stderrSha256)) throw new Error('Invalid diagnostic receipt');
    const binding = await sha256Json({ version: 'secureshop-owned-system-diagnostic-http.v1', targetId: value.targetId, requestSha256: value.requestSha256 });
    if (binding !== value.bindingSha256) throw new Error('Invalid diagnostic target binding');
    return value;
  };

  const saveDiagnosticReference = async (reference, generation, controller) => {
    const next = await saveSystemDiagnosticReference(reference);
    if (!current(generation, controller)) return false;
    setDiagReferences(next);
    return true;
  };

  const recoverDiagnostic = async reference => {
    if (!boundDiagnostic || !diagAdministration) return;
    if (reference.scopeKey !== diagAdministration.scopeKey) { setDiagNotice('This diagnostic operation belongs to another launch or session.'); return; }
    const request = beginOperation(`diagnostic-recovery:${reference.operationId}`);
    if (!request) return;
    const { controller, generation } = request;
    setDiagBusy(true);
    try {
      const response = await transport(`/api/secureshop/admin/system/diagnostic-operations/${encodeURIComponent(reference.operationId)}`, { signal: controller.signal });
      const value = await response.json();
      if (value?.operationId !== reference.operationId) throw new Error('Invalid diagnostic operation');
      if (response.status === 202 || value?.state === 'pending') { if (current(generation, controller)) setDiagNotice('Diagnostic remains pending. No command was repeated.'); return; }
      if (value?.state === 'unknown') { if (current(generation, controller)) { const saved = await saveDiagnosticReference({ ...reference, state: 'unknown' }, generation, controller); if (saved && current(generation, controller)) setDiagNotice('Diagnostic outcome is unknown; no command was repeated.'); } return; }
      if (value?.state === 'not_executed' || (value?.state === 'completed' && value?.ok === false)) {
        if (!current(generation, controller)) return;
        const next = await forgetSystemDiagnosticReference(reference);
        if (current(generation, controller)) { setDiagReferences(next); setDiagNotice(value.error || 'Diagnostic was not executed.'); }
        return;
      }
      const result = await validateBoundDiagnostic(value, reference.operationId);
      if (!current(generation, controller)) return;
      setDiagResult(result); setDiagNotice(null);
      const next = await forgetSystemDiagnosticReference(reference);
      if (!current(generation, controller)) return;
      setDiagReferences(next);
      showToast(result.exitCode === 0 ? 'diagnostic executed' : (result.signal !== null ? `diagnostic stopped by signal ${result.signal}` : `diagnostic exited ${result.exitCode}`), result.exitCode === 0 ? 'success' : 'warn');
    } catch (error) { if (current(generation, controller)) setDiagNotice(`diagnostic recovery failed: ${error.message}`); }
    finally { if (endOperation(`diagnostic-recovery:${reference.operationId}`, controller) && current(generation, controller)) setDiagBusy(false); }
  };

  const dismissDiagnostic = async reference => {
    const request = beginOperation(`diagnostic-dismiss:${reference.operationId}`);
    if (!request) return;
    const { controller, generation } = request;
    try { const next = await forgetSystemDiagnosticReference(reference); if (current(generation, controller)) setDiagReferences(next); }
    catch (error) { if (current(generation, controller)) setDiagNotice(`diagnostic operation reference unavailable: ${error.message}`); }
    finally { endOperation(`diagnostic-dismiss:${reference.operationId}`, controller); }
  };

  const doDiag = async (e) => {
    e.preventDefault();
    if (attachedBridge && !boundDiagnostic) { setDiagNotice('Bound diagnostic capability unavailable'); return; }
    const request = beginOperation('diagnostic');
    if (!request) return;
    const { controller, generation } = request;
    setDiagBusy(true);
    let operationId;
    let reference;
    let dispatched = false;
    try {
      const tpl = diagTemplate === '' ? diagCustom : diagTemplate;
      if (boundDiagnostic) {
        operationId = globalThis.crypto.randomUUID().toLowerCase();
        const body = { operationId, cmd_template: tpl, args: diagArgs };
        const requestSha256 = await diagnosticDigest(body);
        reference = { scopeKey: diagAdministration.scopeKey, operationId, state: 'pending' };
        if (!await saveDiagnosticReference(reference, generation, controller)) return;
        if (!current(generation, controller)) return;
        dispatched = true;
        const response = await transport('/api/secureshop/admin/system/diagnostic', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: controller.signal });
        const value = await response.json();
        if (value?.operationId !== operationId) throw new Error('Invalid diagnostic operation');
        if (response.status === 202 || value?.state === 'pending') { if (current(generation, controller)) setDiagNotice('Diagnostic remains pending. No command was repeated.'); return; }
        if (value?.state === 'unknown') { if (current(generation, controller)) { await saveDiagnosticReference({ ...reference, state: 'unknown' }, generation, controller); if (current(generation, controller)) setDiagNotice('Diagnostic outcome is unknown; no command was repeated.'); } return; }
        if (value?.state === 'not_executed' || (value?.state === 'completed' && value?.ok === false)) {
          const next = await forgetSystemDiagnosticReference(reference); if (current(generation, controller)) { setDiagReferences(next); setDiagNotice(value.error || 'Diagnostic was not executed.'); } return;
        }
        if (!response.ok) throw new Error(value?.code || `HTTP ${response.status}`);
        const result = await validateBoundDiagnostic(value, operationId, requestSha256);
        if (!current(generation, controller)) return;
        setDiagResult(result); setDiagNotice(null);
        // Keep only the opaque reference so a reload can read the durable
        // receipt. The command and output remain in the rendered session only.
        const next = await saveDiagnosticReference({ ...reference, state: 'completed' }, generation, controller);
        if (!next || !current(generation, controller)) return;
        showToast(result.exitCode === 0 ? 'diagnostic executed' : (result.signal !== null ? `diagnostic stopped by signal ${result.signal}` : `diagnostic exited ${result.exitCode}`), result.exitCode === 0 ? 'success' : 'warn');
        return;
      }
      const r = await transport('/api/secureshop/admin/system/diagnostic', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ cmd_template: tpl, args: diagArgs }),
        signal: controller.signal,
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      if (j?.ok !== true) throw new Error(j?.error || 'Operation failed');
      if (typeof j.executed !== 'boolean' || typeof j.cmd !== 'string') throw new Error('Invalid execution response');
      if (!current(generation, controller)) return;
      setDiagResult(j);
      showToast(j.executed ? 'command executed' : 'command constructed (exec disabled)', j.executed ? 'success' : 'info');
    } catch (error) {
      if (!current(generation, controller)) return;
      if (boundDiagnostic && dispatched) { try { await saveDiagnosticReference({ ...reference, state: 'unknown' }, generation, controller); } catch {} if (!current(generation, controller)) return; }
      setDiagResult({ok:false,error:error.message});
      setDiagNotice(`diagnostic failed: ${error.message}`);
      showToast(`diagnostic failed: ${error.message}`, 'error');
    } finally {
      if (endOperation('diagnostic', controller) && current(generation, controller)) setDiagBusy(false);
    }
  };

  const doRestart = async (e) => {
    e.preventDefault();
    const request = beginOperation('restart-service');
    if (!request) return;
    const { controller, generation } = request;
    setRestartBusy(true);
    try {
      const r = await transport('/api/secureshop/admin/system/restart-service', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: restartName }),
        signal: controller.signal,
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      if (j?.ok !== true) throw new Error(j?.error || 'Operation failed');
      if (typeof j.executed !== 'boolean' || typeof j.cmd !== 'string') throw new Error('Invalid execution response');
      if (!current(generation, controller)) return;
      setRestartResult(j);
      showToast(j.executed ? 'restart executed' : 'cmd constructed (exec disabled)', j.executed ? 'success' : 'info');
    } catch (error) {
      if (!current(generation, controller)) return;
      setRestartResult({ok:false,error:error.message});
      showToast(`restart failed: ${error.message}`, 'error');
    } finally {
      if (endOperation('restart-service', controller) && current(generation, controller)) setRestartBusy(false);
    }
  };

  const readRebuildResult = async (response, reference, generation, controller, corpus) => {
    const value = await response.json();
    if (value?.operationId !== reference.operationId) throw new Error('Invalid rebuild operation');
    if (response.status === 202 && value.state === 'pending') {
      if (current(generation, controller)) setRebuildNotice('Rebuild outcome remains pending. No rebuild was repeated.');
      return;
    }
    if (!response.ok || !['completed','failed'].includes(value.state)) throw new Error('Rebuild outcome unavailable; use readback to verify.');
    const result = await (value.state === 'failed' ? validateFailedRebuild : validateCompletedRebuild)(value, reference.operationId, corpus);
    if (!current(generation, controller)) return;
    const references = await forgetSystemRebuildReference(reference);
    if (!current(generation, controller)) return;
    setRebuildReferences(references); setRebuildResult(result);
    setRebuildNotice(result.state === 'failed' ? 'Rebuild failed without publishing a revision. No rebuild was repeated.' : null);
  };
  const forgetRebuild = async (reference) => {
    const request=beginOperation('rebuild-index'); if(!request)return;
    const {controller,generation}=request;setRebuildBusy('forget');
    try {const references=await forgetSystemRebuildReference(reference);if(current(generation,controller))setRebuildReferences(references);}
    catch(error){if(current(generation,controller))setRebuildNotice(error.message);}
    finally{if(endOperation('rebuild-index',controller)&&current(generation,controller))setRebuildBusy(null);}
  };
  const recoverRebuild = async (reference) => {
    if (!rebuildAdministration || reference.scopeKey !== rebuildAdministration.scopeKey) {
      setRebuildNotice('This rebuild belongs to another launch or session.'); return;
    }
    const request = beginOperation('rebuild-index'); if (!request) return;
    const {controller,generation}=request; setRebuildBusy('recovery');
    try {
      const response=await transport(`/api/secureshop/admin/system/rebuild-index/operations/${reference.operationId}`,{signal:controller.signal});
      await readRebuildResult(response,reference,generation,controller);
    } catch(error) { if(current(generation,controller))setRebuildNotice(error.message); }
    finally {if(endOperation('rebuild-index',controller)&&current(generation,controller))setRebuildBusy(null);}
  };
  useEffect(() => {
    if (!attachedBridge) return undefined;
    const request=beginOperation('rebuild-administration'); if(!request)return undefined;
    const {controller,generation}=request;
    (async()=>{try{
      const response=await transport('/api/secureshop/admin/system/rebuild-index',{signal:controller.signal});
      if(!response.ok)throw new Error(`HTTP ${response.status}`);
      const value=await response.json(), administration=value?.administration;
      if(value?.ok!==true||administration?.rebuildCapability!=='secureshop-owned-system-rebuild.v1'||!HASH.test(administration.scopeKey)
       ||!Array.isArray(administration.corpora)||![3,4].includes(administration.corpora.length)
       ||new Set(administration.corpora).size!==administration.corpora.length
       ||!['products','reviews','manuals'].every(c=>administration.corpora.includes(c))
       ||administration.corpora.some(c=>!CORPORA.includes(c)))throw new Error('Invalid rebuild capability');
      if(!current(generation,controller))return;
      setRebuildAdministration(administration);
      const references=readSystemRebuildReferences();setRebuildReferences(references);
      // Restore by GET only; never repeat a mutating POST after reload.
      for(const reference of references.filter(r=>r.scopeKey===administration.scopeKey)){
        const recovery=await transport(`/api/secureshop/admin/system/rebuild-index/operations/${reference.operationId}`,{signal:controller.signal});
        await readRebuildResult(recovery,reference,generation,controller);
      }
    }catch(error){if(current(generation,controller))setRebuildNotice(`Rebuild unavailable: ${error.message}`);}
    finally{endOperation('rebuild-administration',controller);}})();
    return()=>controller.abort();
  },[authToken,transport,attachedBridge]);

  const doRebuild = async (corpus) => {
    if(attachedBridge && (!rebuildAdministration?.corpora.includes(corpus)||rebuildReferences.length)){setRebuildNotice('Verify or forget earlier operations before rebuilding.');return;}
    const request = beginOperation('rebuild-index');
    if (!request) return;
    const { controller, generation } = request;
    setRebuildBusy(corpus);
    let boundReference=null, dispatched=false;
    try {
      if(attachedBridge){
        const body=rebuildRequest(globalThis.crypto.randomUUID(),corpus);
        const reference={scopeKey:rebuildAdministration.scopeKey,operationId:body.operationId,state:'pending'};
        boundReference=reference;
        const references=await saveSystemRebuildReference(reference);
        if(!current(generation,controller))return;
        setRebuildReferences(references);
        dispatched=true;
        const response=await transport('/api/secureshop/admin/system/rebuild-index',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),signal:controller.signal});
        await readRebuildResult(response,reference,generation,controller,corpus);return;
      }

      const r = await transport(`/api/secureshop/admin/system/rebuild-index?corpus=${encodeURIComponent(corpus)}`, {
        method: 'POST',
        signal: controller.signal,
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      if (j?.ok !== true) throw new Error(j?.error || 'Operation failed');
      if (typeof j.job_id !== 'string' || j.status !== 'enqueued') throw new Error('Invalid rebuild response');
      if (!current(generation, controller)) return;
      setRebuildResult(j);
      showToast(`enqueued rebuild for ${corpus} (${j.current_vector_count} vectors)`, 'success');
    } catch (error) {
      if (!current(generation, controller)) return;
      if(attachedBridge && dispatched){
        setRebuildResult(null);
        setRebuildNotice(`Rebuild outcome unverified: ${error.message} Verify the saved operation before starting another rebuild.`);
        try {
          const references=await saveSystemRebuildReference({...boundReference,state:'unknown'});
          if(current(generation,controller))setRebuildReferences(references);
        }catch(storageError){if(current(generation,controller))setRebuildNotice(`Rebuild outcome unverified; recovery storage unavailable: ${storageError.message}`);}
        return;
      }
      setRebuildResult({ok:false,error:error.message});
      showToast(`rebuild failed: ${error.message}`, 'error');
    } finally {
      if (endOperation('rebuild-index', controller) && current(generation, controller)) setRebuildBusy(null);
    }
  };

  // Config XSS surface — if the file contains HTML, render it verbatim.
  const looksLikeHtml = configResult
    && configResult.ok
    && /<[a-z][\s\S]*>/i.test(String(configResult.content || ''));

  const execAllowed = diagResult?.executed || restartResult?.executed;

  return (
    <PageTransition className="ss-admin-system">
      <header style={{ marginBottom: 24 }}>
        <div className="ss-card__meta">ADMIN LENS</div>
        <h1 className="ss-display" style={{ fontSize: 36, margin: '4px 0 6px 0' }}>System</h1>
        <p className="ss-mono" style={{ opacity: 0.7, fontSize: 12, maxWidth: '80ch' }}>
          {attachedBridge ? <>
            Health · configuration reads · diagnostics · service restart · vector index.
            Practice actions run only when their section is available; check each result for what executed.
          </> : <>
            health · read_config (path traversal + credential leak sink) · run_diagnostic (RCE) · restart_service (command injection).
            Exec is guarded by <code>SS_SYSTEM_ALLOW_EXEC=true</code> — but the constructed cmd is always shown, so the sink is visible even when disabled.
          </>}
        </p>
      </header>

      {/* Health + Agent Host status */}
      <section className="ss-admin-system__health-grid">
        <StaggerCard delay={0.00}>
          <div className="ss-card__meta">HOSTNAME</div>
          <div style={{ fontSize: 15, marginTop: 4 }} className="ss-mono">{health?.hostname || (healthErrors.system ? 'unavailable' : 'loading…')}</div>
        </StaggerCard>
        <StaggerCard delay={0.04}>
          <div className="ss-card__meta">PLATFORM</div>
          <div style={{ fontSize: 15, marginTop: 4 }} className="ss-mono">{health?.platform || '—'}</div>
        </StaggerCard>
        <StaggerCard delay={0.08}>
          <div className="ss-card__meta">NODE</div>
          <div style={{ fontSize: 15, marginTop: 4 }} className="ss-mono">{health?.node || '—'}</div>
        </StaggerCard>
        <StaggerCard delay={0.12}>
          <div className="ss-card__meta">UPTIME</div>
          <div style={{ fontSize: 15, marginTop: 4 }} className="ss-mono">{health?.uptime_s != null ? _fmtUptime(health.uptime_s) : '—'}</div>
        </StaggerCard>
        <StaggerCard delay={0.16}>
          <div className="ss-card__meta">LOAD [1m]</div>
          <div style={{ fontSize: 15, marginTop: 4 }} className="ss-mono">{health?.loadavg?.[0] != null ? String(health.loadavg[0]).slice(0, 6) : '—'}</div>
        </StaggerCard>
        <StaggerCard delay={0.20}>
          <div className="ss-card__meta">FREE MEM</div>
          <div style={{ fontSize: 15, marginTop: 4 }} className="ss-mono">{health?.freemem_mb != null ? `${health.freemem_mb} MB` : '—'}</div>
        </StaggerCard>
        <StaggerCard delay={0.24}>
          <div className="ss-card__meta">AGENT HOST</div>
          <div style={{ fontSize: 15, marginTop: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{
              display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
              background: ['ONLINE','SERVICE_READY'].includes(hostStatus?.status) ? 'var(--signal)' : 'var(--rust)',
            }} />
            <span className="ss-mono" style={{ color: ['ONLINE','SERVICE_READY'].includes(hostStatus?.status) ? 'var(--ink)' : 'var(--rust)' }}>
              {hostStatus?.status || (healthErrors.runtime ? 'unavailable' : 'checking…')}
            </span>
          </div>
        </StaggerCard>
      </section>

      {Object.entries(healthErrors).map(([key,error])=><div role="alert" key={key} className="ss-mono" style={{color:'var(--rust)',fontSize:12,marginBottom:12}}>{key} health unavailable · {error}</div>)}
      {hostStatus?.model_execution === 'not_tested' && <div className="ss-mono" style={{fontSize:12,marginBottom:12}}>Scoped service checks only; model execution not tested.</div>}
      {/* Config viewer */}
      <section className="ss-admin-system__config" style={{ marginBottom: 32 }}>
        <h2 className="ss-shelf__title">Config viewer <span style={{ opacity: 0.55, fontFamily: 'var(--mono)', fontSize: 11 }}>· path traversal sink</span></h2>
        <form className="ss-admin-system__action-form" onSubmit={readCfg}>
          <input
            className="ss-lane__input"
            value={configPath}
            onChange={(e) => setConfigPath(e.target.value)}
            style={{ flex: 1 }}
            placeholder={attachedBridge
              ? 'path (try application.json, or ....//.env for traversal)'
              : 'path (try .env, or ....//server/platform_secrets.json for traversal)'}
            aria-label="Config path"
          />
          <button className="ss-btn" type="submit" disabled={configBusy || (attachedBridge && (!boundSystem || !configAdministration))}>{configBusy ? 'reading…' : 'read'}</button>
        </form>
        {configNotice && <div role="alert" className="ss-mono" style={{ color: 'var(--rust)', fontSize: 12, marginBottom: 10 }}>{configNotice}</div>}
        {boundSystem && configReferences.length > 0 && <div className="ss-mono" style={{ fontSize: 11, marginBottom: 10 }}>
          {configReferences.map(reference => <div key={`${reference.scopeKey}:${reference.operationId}`} style={{ marginBottom: 6 }}>
            Config read {reference.operationId} · outcome {reference.state}
            <button className="ss-btn ss-btn--ghost" onClick={() => recoverConfig(reference)} disabled={configBusy} style={{ marginLeft: 8, padding: '3px 8px', fontSize: 11 }}>Refresh operation status</button>
            <button className="ss-btn ss-btn--ghost" onClick={() => dismissConfigReference(reference)} disabled={configBusy} style={{ marginLeft: 6, padding: '3px 8px', fontSize: 11 }}>Dismiss</button>
          </div>)}
        </div>}
        <AnimatePresence>
          {configResult && (
            <motion.div
              className="ss-admin-system__result"
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <div className="ss-mono" style={{ fontSize: 11, opacity: 0.6, marginBottom: 6 }}>
                input=<code>{configResult.input}</code> · sanitized=<code>{configResult.sanitized}</code>
                {configResult.abs && <> · abs=<code style={{ opacity: 0.65 }}>{configResult.abs}</code></>}
                {configResult.size != null && <> · {configResult.size} bytes</>}
              </div>
              {looksLikeHtml ? (
                <>
                  <div className="ss-mono" style={{ fontSize: 11, color: 'var(--rust)', marginBottom: 6 }}>
                    ⚠ content contains HTML — rendered via dangerouslySetInnerHTML (config-viewer XSS surface)
                  </div>
                  {/*
                    Intentional XSS surface preserved: some config files carry HTML
                    fragments (e.g. an installer README fragment) that render verbatim.
                    Reachable only for authenticated admins with a path that pierces
                    the traversal filter.
                  */}
                  <div
                    style={{ border: '1px solid var(--rule)', padding: 12, background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))' }}
                    dangerouslySetInnerHTML={{ __html: configResult.content }}
                  />
                </>
              ) : (
                <pre className="ss-mono ss-admin-system__output" style={{
                  background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))', padding: 12,
                  border: '1px solid var(--rule)', fontSize: 11, overflowX: 'auto', whiteSpace: 'pre-wrap',
                  margin: 0, maxHeight: 420, overflowY: 'auto',
                }}>
                  {configResult.content || configResult.error || '(empty)'}
                </pre>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      {/* Diagnostic — RCE */}
      <section style={{ marginBottom: 32 }}>
        <h2 className="ss-shelf__title">Diagnostic runner <span style={{ opacity: 0.55, fontFamily: 'var(--mono)', fontSize: 11 }}>· RCE sink</span></h2>
        <div className="ss-mono" style={{ padding: 10, marginBottom: 10, border: '1px solid var(--rust)', color: 'var(--rust)', background: 'color-mix(in srgb, var(--rust) 5%, transparent)', fontSize: 11 }}>
          {attachedBridge
            ? '⚠ Command template and arguments form a shell command in the isolated diagnostic service. A verified result below shows whether it ran.'
            : <>⚠ cmd_template + args are concatenated and exec'd. Guarded by <code>SS_SYSTEM_ALLOW_EXEC=true</code> — the sink surface is the constructed shell string, always visible below.</>}
        </div>
        {diagNotice && <div role="alert" className="ss-mono" style={{ color: 'var(--rust)', fontSize: 12, marginBottom: 10 }}>{diagNotice}</div>}
        {boundDiagnostic && diagReferences.length > 0 && <div className="ss-mono" style={{ fontSize: 11, marginBottom: 10 }}>
          {diagReferences.map(reference => <div key={`${reference.scopeKey}:${reference.operationId}`} style={{ marginBottom: 6 }}>
            Diagnostic {reference.operationId} · outcome {reference.state}
            <button className="ss-btn ss-btn--ghost" onClick={() => recoverDiagnostic(reference)} disabled={diagBusy} style={{ marginLeft: 8, padding: '3px 8px', fontSize: 11 }}>Refresh operation status</button>
            <button className="ss-btn ss-btn--ghost" onClick={() => dismissDiagnostic(reference)} disabled={diagBusy} style={{ marginLeft: 6, padding: '3px 8px', fontSize: 11 }}>Dismiss</button>
          </div>)}
        </div>}
        <form className="ss-admin-system__diagnostic-form" onSubmit={doDiag}>
          <select
            value={diagTemplate}
            onChange={(e) => setDiagTemplate(e.target.value)}
            style={{ padding: 8, border: '1px solid var(--rule)', background: 'var(--paper)', fontFamily: 'var(--mono)', fontSize: 12 }}
            aria-label="Command template"
          >
            {COMMAND_TEMPLATES.map(t => <option key={t.label} value={t.value}>{t.label}</option>)}
          </select>
          {diagTemplate === '' ? (
            <input
              className="ss-lane__input"
              value={diagCustom}
              onChange={(e) => setDiagCustom(e.target.value)}
              placeholder="custom cmd_template (e.g. `sh -c 'curl ...'`)"
              aria-label="Custom cmd_template"
            />
          ) : (
            <input
              className="ss-lane__input"
              value={diagArgs}
              onChange={(e) => setDiagArgs(e.target.value)}
              placeholder="args (concatenated as-is — try ; whoami)"
              aria-label="Command args"
            />
          )}
          <button className="ss-btn" type="submit" disabled={diagBusy || (attachedBridge && !boundDiagnostic)}>{diagBusy ? 'running…' : 'run'}</button>
        </form>
        {diagTemplate === '' && (
          <input
            className="ss-lane__input"
            value={diagArgs}
            onChange={(e) => setDiagArgs(e.target.value)}
            placeholder="args (concatenated as-is)"
            aria-label="Custom command args"
            style={{ width: '100%', marginBottom: 10 }}
          />
        )}
        <AnimatePresence>
          {diagResult && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <div className="ss-mono" style={{ fontSize: 11, opacity: 0.75, marginBottom: 6 }}>
                constructed shell: <code style={{ background: 'color-mix(in srgb, var(--paper) 88%, var(--carbon))', padding: '2px 6px', color: 'var(--rust)' }}>{diagResult.cmd}</code>
                {' · '}
                <span style={{ color: diagResult.executed ? 'var(--signal)' : 'var(--copper)' }}>
                  {!diagResult.ok ? 'REQUEST FAILED' : diagResult.executed ? 'EXECUTED' : 'not executed (guard on)'}
                </span>
              </div>
              <pre className="ss-mono ss-admin-system__output" style={{
                background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))', padding: 12,
                border: '1px solid var(--rule)', fontSize: 11, overflowX: 'auto', margin: 0,
              }}>{JSON.stringify(diagResult, null, 2)}</pre>
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      {/* Restart service — command injection */}
      {attachedBridge ? <BoundSystemRestart key={authToken} authToken={authToken} transport={transport} /> : <section style={{ marginBottom: 32 }}>
        <h2 className="ss-shelf__title">Restart service <span style={{ opacity: 0.55, fontFamily: 'var(--mono)', fontSize: 11 }}>· command injection sink</span></h2>
        <div className="ss-mono" style={{ padding: 10, marginBottom: 10, border: '1px solid var(--rust)', color: 'var(--rust)', background: 'color-mix(in srgb, var(--rust) 5%, transparent)', fontSize: 11 }}>
          ⚠ Service name is interpolated directly into <code>systemctl restart ${'$'}{'{'}{'name}'}</code>. Guarded by <code>SS_SYSTEM_ALLOW_EXEC=true</code>.
        </div>
        <form className="ss-admin-system__action-form" onSubmit={doRestart}>
          <input
            className="ss-lane__input"
            value={restartName}
            onChange={(e) => setRestartName(e.target.value)}
            placeholder="service name (try `nginx; whoami`)"
            style={{ flex: 1 }}
            aria-label="Service name"
          />
          <button className="ss-btn" type="submit" disabled={restartBusy}>{restartBusy ? 'restarting…' : 'restart'}</button>
        </form>
        <AnimatePresence>
          {restartResult && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <div className="ss-mono" style={{ fontSize: 11, opacity: 0.75, marginBottom: 6 }}>
                constructed shell: <code style={{ background: 'color-mix(in srgb, var(--paper) 88%, var(--carbon))', padding: '2px 6px', color: 'var(--rust)' }}>{restartResult.cmd}</code>
              </div>
              <pre className="ss-mono ss-admin-system__output" style={{
                background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))', padding: 12,
                border: '1px solid var(--rule)', fontSize: 11, margin: 0,
              }}>{JSON.stringify(restartResult, null, 2)}</pre>
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      }

      {/* Vector index rebuild */}
      <section data-testid="system-rebuild-panel" style={{ marginBottom: 32 }}>
        <h2 className="ss-shelf__title">Vector index management</h2>
        <p className="ss-mono" style={{ opacity: 0.65, fontSize: 11, marginBottom: 10 }}>
          {attachedBridge ? 'Publish an owned embedding revision for the selected corpus. Source content is preserved; this manual operation does not award objective credit.' : 'Rebuild the HNSW index per corpus. Source content is preserved.'}
        </p>
        {rebuildNotice && <div role="status" className="ss-mono" style={{marginBottom:10}}>{rebuildNotice}</div>}
        {rebuildReferences.map(reference=><div key={`${reference.scopeKey}:${reference.operationId}`} className="ss-mono" style={{marginBottom:8}}>
          <span>Rebuild {reference.operationId} </span>
          <button className="ss-btn" disabled={rebuildBusy!==null} onClick={()=>recoverRebuild(reference)}>verify outcome</button>
          <button className="ss-btn ss-btn--ghost" disabled={rebuildBusy!==null} onClick={()=>forgetRebuild(reference)}>forget reference</button>
        </div>)}
        <div className="ss-admin-system__corpora-grid">
          {CORPORA.map(c => (
            <div key={c} style={{ border: '1px solid var(--rule)', padding: 14 }}>
              <div className="ss-card__meta">{c.toUpperCase()}</div>
              <button
                className="ss-btn"
                onClick={() => doRebuild(c)}
                disabled={rebuildBusy !== null || (attachedBridge && (!rebuildAdministration?.corpora.includes(c) || rebuildReferences.length > 0))}
                style={{ marginTop: 8, width: '100%', padding: '6px 10px', fontSize: 12 }}
              >
                {rebuildBusy === c ? (attachedBridge ? 'rebuilding…' : 'enqueuing…') : `rebuild ${c}`}
              </button>
            </div>
          ))}
        </div>
        <AnimatePresence>
          {rebuildResult && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              style={{ marginTop: 12 }}
            >
              <pre className="ss-mono ss-admin-system__output" style={{
                background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))', padding: 10,
                border: '1px solid var(--rule)', fontSize: 11, margin: 0,
              }}>{JSON.stringify(rebuildResult, null, 2)}</pre>
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      {/* Toasts now render via <ToastProvider> at the Shell level (Wave 3A). */}

      {execAllowed && (
        <motion.div
          initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          style={{ marginTop: 24, padding: 12, border: '1px solid var(--signal)', color: 'var(--signal)', fontFamily: 'var(--mono)', fontSize: 11 }}
        >
          {attachedBridge
            ? 'Diagnostic ran in the isolated SecureShop practice; inspect its verified receipt.'
            : 'exec surface is LIVE (SS_SYSTEM_ALLOW_EXEC=true) — you are running real shell commands.'}
        </motion.div>
      )}
    </PageTransition>
  );
}

function StaggerCard({ children, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28, delay, ease: [0.16, 1, 0.3, 1] }}
      style={{ border: '1px solid var(--rule)', padding: 14 }}
    >
      {children}
    </motion.div>
  );
}

function _fmtUptime(s) {
  if (!Number.isFinite(s) || s < 0) return '—';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${h}h ${m}m`;
}
