import { decodeMerchantListingsSetup } from '../utils/merchantListingsSetup.mjs';
import { useCallback, useEffect, useRef, useState } from 'react';
import { parseAgentFrame, requireAgentContentType, takeAgentFrame } from '../utils/agentStreamProtocol.mjs';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';
import { clearRoleAssistantReference, readRoleAssistantReference,
  saveRoleAssistantReference } from '../utils/roleAssistantReferences.mjs';
import { clearRoleAssistantCompletedReference, readRoleAssistantCompletedReference,
  sameRoleAssistantReference, saveRoleAssistantCompletedReference } from '../utils/roleAssistantCompletedReferences.mjs';
import { decodeInventoryProposal } from '../pages/merchant/inventoryReference.mjs';
import { decodePricingProposal, validateCompetitorUrl } from '../pages/merchant/pricingOperation.mjs';
import { decodeListingEditProposal } from '../pages/merchant/listingEditOperation.mjs';
import { decodeListingCreateProposal } from '../pages/merchant/listingCreateOperation.mjs';
import { decodeMerchantReviewDetail, decodeMerchantReviewPage, decodeMerchantReviewProposal,
  merchantReviewSelection } from '../utils/merchantReviewChat.mjs';
import { decodeUserAdministrationProposal } from '../utils/userAdministrationProposal.mjs';
import { decodeRolePolicyDetail, decodeRolePolicyProposal, sameRolePolicyMode } from '../utils/rolePolicyProposal.mjs';
import { decodeRoleMcpDetail, decodeRoleMcpRegistryProposal,
  decodeRegisteredMcpSetup } from '../utils/roleMcpRegistry.mjs';
import { decodeAdminAuditRead } from '../utils/adminAuditRead.mjs';
import { decodeAuditSearchDescriptor, decodeAuditSearchOperation, decodeSystemHealth,
  decodeSystemConfigDescriptor, decodeSystemConfigOperation, decodeUserLookup } from '../utils/adminSavedOperationReads.mjs';
import { decodeRoleSystemRestartProposal } from '../utils/roleSystemRestartProposal.mjs';
import { decodeRoleSystemDiagnosticProposal } from '../utils/roleSystemDiagnosticProposal.mjs';
import { decodeRoleAuditJobProposal } from '../utils/roleAuditJob.mjs';
import { decodeRoleAclProposal } from '../utils/roleAclProposal.mjs';
import { decodeMerchantOrdersPage } from '../utils/merchantOrdersPage.mjs';
import { decodeCatalogPage } from '../utils/catalogPage.mjs';
import { decodeMerchantManualSearch } from '../utils/merchantManualSearch.mjs';
import { decodeMerchantMailRead } from '../utils/merchantMailRead.mjs';
import { decodeMerchantMailProposal } from '../utils/merchantMailAction.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_MESSAGE_BYTES = 8192;
const MAX_STREAM_BYTES = 131072;
const MAX_EVENTS = 80;
const encoder = new TextEncoder();
const CARD_KINDS = Object.freeze({ merchant: ['merchant_product', 'merchant_order', 'merchant_review',
  'merchant_mail_recipient', 'merchant_mail_message'], admin: ['tenant_user', 'admin_policy', 'admin_mcp_server', 'admin_acl_permission'] });
const newId = () => {
  if (typeof globalThis.crypto?.randomUUID !== 'function') throw new Error('Secure request identity unavailable');
  return globalThis.crypto.randomUUID().toLowerCase();
};
const validMessage = value => typeof value === 'string' && value.trim()
  && value.isWellFormed() && encoder.encode(value).byteLength <= MAX_MESSAGE_BYTES
  && !value.includes('\0');
const path = (role, leaf) => `/api/secureshop/agents/${role}/assistant/${leaf}`;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const savedSystemAssessmentResult = (value, label = 'System') => {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`Saved ${label} assessment invalid`);
  if (exact(value, ['completed', 'status', 'modelEvaluated'])
    && value.completed === false && typeof value.status === 'string' && value.status.length > 0
    && value.status.length <= 128 && !/[\u0000-\u001f\u007f]/.test(value.status)
    && value.modelEvaluated === false) return Object.freeze({ kind: 'ineligible', status: value.status });
  const judgment = value.judgment;
  if (!exact(value, ['completed', 'judgment', 'replayed']) || typeof value.completed !== 'boolean'
    || typeof value.replayed !== 'boolean' || !judgment || Object.getPrototypeOf(judgment) !== Object.prototype
    || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(judgment.verdict)
    || !UUID.test(judgment.evaluationId || '') || typeof judgment.canRetry !== 'boolean') {
    throw new Error(`Saved ${label} assessment invalid`);
  }
  return Object.freeze({ kind: 'judgment', completed: value.completed, replayed: value.replayed,
    judgment: Object.freeze({ verdict: judgment.verdict, evaluationId: judgment.evaluationId.toLowerCase(),
      canRetry: judgment.canRetry }) });
};
const cardText = (value, limit) => typeof value === 'string' && value.trim()
  && value.isWellFormed() && !value.includes('\0') && encoder.encode(value).byteLength <= limit;
function decodePasswordResetSetup(value, sessionId, requestId) {
  if (value == null) return null;
  if (!exact(value, ['version', 'kind', 'sessionId', 'requestId', 'choiceId', 'userId',
    'username', 'identityKind', 'channel', 'scopeKey'])
    || value.version !== 1 || value.kind !== 'password_reset_setup'
    || value.sessionId !== sessionId || value.requestId !== requestId
    || !UUID.test(value.choiceId) || value.choiceId !== value.choiceId.toLowerCase()
    || !Number.isSafeInteger(value.userId) || value.userId < 1 || value.userId > 2147483647
    || !cardText(value.username, 100) || !cardText(value.scopeKey, 1024)
    || !['registered_account', 'teaching_persona'].includes(value.identityKind)
    || value.channel !== (value.identityKind === 'registered_account'
      ? 'protected_account' : 'bound_persona')) throw new Error('Saved password reset handoff invalid');
  return Object.freeze({ ...value });
}
function decodeRoleCards(value, role) {
  if (!Array.isArray(value) || value.length > 5) throw new Error('Saved role assistant choices invalid');
  const seen = new Set();
  return value.map(card => {
    if ((!exact(card, ['version', 'kind', 'choiceId', 'title', 'detail'])
      && !(card.kind === 'merchant_product' && role === 'merchant'
        && exact(card, ['version', 'kind', 'choiceId', 'title', 'detail', 'readOnly'])
        && card.readOnly === true))
      || (card.readOnly !== undefined && card.readOnly !== true)
      || card.version !== 1 || !CARD_KINDS[role]?.includes(card.kind)
      || !UUID.test(card.choiceId) || card.choiceId !== card.choiceId.toLowerCase()
      || seen.has(card.choiceId) || !cardText(card.title, 256) || !cardText(card.detail, 512)) {
      throw new Error('Saved role assistant choices invalid');
    }
    seen.add(card.choiceId);
    return Object.freeze({ ...card });
  });
}
function decodeMerchantOrderDetail(hops, role) {
  if (role !== 'merchant') return null;
  const hop = [...hops].reverse().find(item => item?.tool === 'merchant.orders_detail'
    && !item.error && item.result?.isError !== true);
  if (!hop) return null;
  const content = hop.result?.content;
  if (!exact(hop.result, ['content']) || !Array.isArray(content) || content.length !== 1
    || !exact(content[0], ['type', 'text']) || content[0].type !== 'text'
    || typeof content[0].text !== 'string' || encoder.encode(content[0].text).byteLength > 16384) {
    throw new Error('Saved merchant order detail invalid');
  }
  let value;
  try { value = JSON.parse(content[0].text); }
  catch { throw new Error('Saved merchant order detail invalid'); }
  const order = value?.order;
  if (!exact(value, ['order'])
    || !exact(order, ['orderId', 'status', 'orderDate', 'merchantSubtotal', 'items'])
    || !Number.isSafeInteger(order.orderId) || order.orderId < 1
    || !cardText(order.status, 128) || !cardText(order.orderDate, 128)
    || !Number.isFinite(Date.parse(order.orderDate))
    || !Number.isFinite(order.merchantSubtotal) || order.merchantSubtotal < 0
    || !Array.isArray(order.items) || !order.items.length || order.items.length > 256) {
    throw new Error('Saved merchant order detail invalid');
  }
  const items = order.items.map(item => {
    if (!exact(item, ['productId', 'name', 'quantity', 'price', 'discountAmount', 'lineTotal'])
      || !Number.isSafeInteger(item.productId) || item.productId < 1
      || !cardText(item.name, 4096)
      || !Number.isSafeInteger(item.quantity) || item.quantity < 1
      || ['price', 'discountAmount', 'lineTotal'].some(key => !Number.isFinite(item[key]) || item[key] < 0)) {
      throw new Error('Saved merchant order detail invalid');
    }
    return Object.freeze({ name: item.name, quantity: item.quantity, price: item.price,
      discountAmount: item.discountAmount, lineTotal: item.lineTotal });
  });
  return Object.freeze({ orderId: order.orderId, status: order.status,
    orderDate: order.orderDate.slice(0, 10), merchantSubtotal: order.merchantSubtotal,
    items: Object.freeze(items) });
}

export function useBoundRoleAssistant({ role, shopUserId, authorityKey, transport = globalThis.fetch }) {
  const [turns, setTurns] = useState([]);
  const [pending, setPending] = useState(null);
  const [completedPage, setCompletedPage] = useState(null);
  const [status, setStatus] = useState('idle');
  const [error, setError] = useState(null);
  const [canStopWatching, setCanStopWatching] = useState(false);
  const sessionRef = useRef(null);
  const epochRef = useRef(0);
  const activeRef = useRef(null);
  const watchingRef = useRef(null);
  const readerRef = useRef(null);
  const storageFaultRef = useRef(false);
  const attemptedCompletedRecoveryRef = useRef(null);

  useEffect(() => {
    const epoch = ++epochRef.current;
    activeRef.current?.abort(); activeRef.current = null;
    watchingRef.current = null; readerRef.current = null;
    sessionRef.current = null; storageFaultRef.current = false;
    attemptedCompletedRecoveryRef.current = null;
    setTurns([]); setPending(null); setCompletedPage(null); setStatus('idle'); setError(null);
    setCanStopWatching(false);
    try {
      const saved = readRoleAssistantReference(role, shopUserId);
      if (saved) {
        sessionRef.current = saved.sessionId;
        setPending(saved); setStatus('unresolved');
        setTurns([{ sessionId: saved.sessionId, requestId: saved.requestId,
          user: 'Saved role assistant request',
          reply: '', hops: [], status: 'error', startedAt: saved.startedAt }]);
      } else {
        const completed = readRoleAssistantCompletedReference(role, shopUserId);
        if (completed) { setCompletedPage(completed); setStatus('recovering'); }
      }
    } catch {
      storageFaultRef.current = true;
      setStatus('error'); setError('Saved role assistant reference is unavailable');
    }
    return () => { if (epochRef.current === epoch) ++epochRef.current;
      activeRef.current?.abort(); activeRef.current = null;
      watchingRef.current = null; readerRef.current = null; };
  }, [role, shopUserId, authorityKey, transport]);

  const stopWatching = useCallback(() => {
    const watching = watchingRef.current;
    if (!watching || !pending || pending.requestId !== watching.reference.requestId
      || activeRef.current !== watching.controller) return false;
    watchingRef.current = null;
    setCanStopWatching(false);
    activeRef.current = null;
    const reader = readerRef.current?.controller === watching.controller
      ? readerRef.current.reader : null;
    readerRef.current = null;
    watching.controller.abort();
    if (reader) void Promise.resolve().then(() => reader.cancel()).catch(() => {});
    setTurns(previous => previous.map(turn => turn.requestId === watching.reference.requestId
      ? { ...turn, status: 'unresolved' } : turn));
    setStatus('unresolved');
    setError('Stopped watching this response. The saved request may still complete. Check its saved outcome.');
    return true;
  }, [pending]);

  const readExact = useCallback(async (reference, signal) => {
    const response = await transport(path(role,
      `operations/${reference.sessionId}/${reference.requestId}`), { signal });
    if (!response.ok) {
      const failure = new Error(response.status === 401
        ? 'Return to the original shop scene and sign in with its authority to check this saved request.'
        : `Saved role assistant request unavailable (${response.status})`);
      failure.status = response.status;
      throw failure;
    }
    requireAgentContentType(response, 'application/json', 'Saved role assistant request');
    const value = await response.json();
    if (value.sessionId !== reference.sessionId || value.requestId !== reference.requestId
      || !['completed', 'unconfirmed'].includes(value.status)) {
      throw new Error('Saved role assistant identity mismatch');
    }
    if (value.status === 'unconfirmed') return { status: 'unconfirmed' };
    if (value.replayed !== true || !trustedTurnMode(value.modeCapability)
      || typeof value.text !== 'string' || typeof value.stopReason !== 'string'
      || !Array.isArray(value.hops) || value.hops.length > 10) {
      throw new Error('Saved role assistant receipt invalid');
    }
    if (role !== 'merchant' && (value.inventoryProposal != null || value.pricingProposal != null
      || value.listingProposal != null || value.listingCreateProposal != null
      || value.reviewDetail != null || value.reviewPage != null || value.reviewProposal != null
      || value.ordersPage != null || value.catalogPage != null || value.manualSearch != null || value.mailRead != null
      || value.mailProposal != null || value.listingsSetup != null)) {
      throw new Error('Saved role assistant receipt invalid');
    }
    if (value.ordersPage != null && value.stopReason !== 'end_turn') {
      throw new Error('Saved merchant order page is invalid');
    }
    const catalogPage = role === 'merchant' ? decodeCatalogPage(value.catalogPage ?? null, 5) : null;
    if (catalogPage && value.stopReason !== 'end_turn') throw new Error('Saved catalog page invalid');
    if (role !== 'admin' && (value.userAdministrationProposal != null
      || value.passwordResetSetup != null || value.policyDetail != null
      || value.policyProposal != null || value.mcpDetail != null
      || value.mcpRegistryProposal != null || value.registeredMcpSetup != null
      || value.auditSearch != null || value.systemHealth != null || value.userLookup != null
      || value.systemConfigRead != null || value.systemRestartProposal != null
      || value.systemDiagnosticProposal != null
      || value.auditJobProposal != null || value.aclPage != null || value.aclProposal != null)) {
      throw new Error('Saved role assistant receipt invalid');
    }
    if (value.passwordResetSetup != null && value.stopReason !== 'end_turn') {
      throw new Error('Saved password reset handoff invalid');
    }
    if ((value.policyDetail != null || value.policyProposal != null)
      && value.stopReason !== 'end_turn') throw new Error('Saved policy review invalid');
    if ((value.mcpDetail != null || value.mcpRegistryProposal != null
      || value.registeredMcpSetup != null) && value.stopReason !== 'end_turn') {
      throw new Error('Saved MCP review invalid');
    }
    if ((value.systemRestartProposal != null || value.auditJobProposal != null
      || value.systemDiagnosticProposal != null
      || value.aclPage != null || value.aclProposal != null) && value.stopReason !== 'end_turn') {
      throw new Error('Saved System restart review invalid');
    }
    const auditSearch = role === 'admin'
      ? decodeAuditSearchDescriptor(value.auditSearch ?? null, value.modeCapability, value.stopReason) : null;
    const systemHealth = role === 'admin'
      ? decodeSystemHealth(value.systemHealth ?? null, value.modeCapability, value.stopReason) : null;
    const systemConfigRead = role === 'admin'
      ? decodeSystemConfigDescriptor(value.systemConfigRead ?? null, value.modeCapability, value.stopReason) : null;
    const userLookup = role === 'admin'
      ? decodeUserLookup(value.userLookup ?? null, value.modeCapability, value.stopReason) : null;
    let auditSearchResult = null, systemConfigResult = null;
    if (auditSearch?.status === 'completed') {
      const detail = await transport(path(role, `audit/operations/${reference.sessionId}/${reference.requestId}/${auditSearch.operationId}`), { signal });
      if (detail.status === 202) return { status: 'unconfirmed', reason: 'Audit SQL result is not confirmed. Check the saved request.' };
      if (!detail.ok) throw new Error(detail.status === 401
        ? 'Return to the original shop scene and sign in with its authority to check this audit result.'
        : `Saved audit SQL result unavailable (${detail.status})`);
      requireAgentContentType(detail, 'application/json', 'Saved audit SQL result');
      auditSearchResult = await decodeAuditSearchOperation(auditSearch, await detail.json());
    } else if (auditSearch && auditSearch.status !== 'blocked') {
      return { status: 'unconfirmed', reason: 'Audit SQL result is not confirmed. Check the saved request.' };
    }
    if (systemConfigRead?.state === 'completed') {
      const detail = await transport(path(role, `system/config/operations/${reference.sessionId}/${reference.requestId}/${systemConfigRead.operationId}`), { signal });
      if (detail.status === 202) return { status: 'unconfirmed', reason: 'System config result is not confirmed. Check the saved request.' };
      if (!detail.ok) throw new Error(detail.status === 401
        ? 'Return to the original shop scene and sign in with its authority to check this System result.'
        : `Saved System config result unavailable (${detail.status})`);
      requireAgentContentType(detail, 'application/json', 'Saved System config result');
      const full = await decodeSystemConfigOperation(systemConfigRead, await detail.json());
      if (full.state !== 'completed') return { status: 'unconfirmed', reason: 'System config result is not confirmed. Check the saved request.' };
      systemConfigResult = full;
    } else if (systemConfigRead) {
      return { status: 'unconfirmed', reason: 'System config result is not confirmed. Check the saved request.' };
    }
    const policyDetail = role === 'admin' ? decodeRolePolicyDetail(value.policyDetail ?? null) : null;
    const policyProposal = role === 'admin' ? await decodeRolePolicyProposal(value.policyProposal ?? null) : null;
    if (policyProposal && !sameRolePolicyMode(policyProposal.modeCapability, value.modeCapability)) {
      throw new Error('Saved policy review invalid');
    }
    if (policyDetail && policyProposal && (policyDetail.scopeKey !== policyProposal.scopeKey
      || policyDetail.choiceId !== policyProposal.choiceId)) throw new Error('Saved policy review invalid');
    const mcpDetail = role === 'admin' ? await decodeRoleMcpDetail(value.mcpDetail ?? null) : null;
    const mcpRegistryProposal = role === 'admin'
      ? await decodeRoleMcpRegistryProposal(value.mcpRegistryProposal ?? null) : null;
    const registeredMcpSetup = role === 'admin'
      ? decodeRegisteredMcpSetup(value.registeredMcpSetup ?? null,
        reference.sessionId, reference.requestId) : null;
    if (mcpRegistryProposal && !sameRolePolicyMode(mcpRegistryProposal.modeCapability,
      value.modeCapability)) throw new Error('Saved MCP review invalid');
    if (mcpDetail && mcpRegistryProposal && (mcpDetail.scopeKey !== mcpRegistryProposal.scopeKey
      || mcpDetail.choiceId !== mcpRegistryProposal.choiceId)) throw new Error('Saved MCP review invalid');
    const systemRestartProposal = role === 'admin'
      ? await decodeRoleSystemRestartProposal(value.systemRestartProposal ?? null) : null;
    if (systemRestartProposal && !sameRolePolicyMode(systemRestartProposal.modeCapability,
      value.modeCapability)) throw new Error('Saved System restart review invalid');
    const systemDiagnosticProposal = role === 'admin'
      ? await decodeRoleSystemDiagnosticProposal(value.systemDiagnosticProposal ?? null) : null;
    const auditJobProposal = role === 'admin'
      ? await decodeRoleAuditJobProposal(value.auditJobProposal ?? null,
        reference.sessionId, reference.requestId) : null;
    const aclProposal = role === 'admin'
      ? await decodeRoleAclProposal(value.aclProposal ?? null) : null;
    const manualSearch = role === 'merchant'
      ? await decodeMerchantManualSearch(value.manualSearch ?? null, value.modeCapability,
        value.hops, value.stopReason) : null;
    const mailRead = role === 'merchant'
      ? decodeMerchantMailRead(value.mailRead ?? null, value.modeCapability,
        value.stopReason) : null;
    const listingsSetup = role === 'merchant' ? decodeMerchantListingsSetup(value.listingsSetup ?? null, reference.sessionId, reference.requestId) : null;
    if (listingsSetup && value.stopReason !== 'end_turn') throw new Error('Saved listing setup invalid');
    const mailProposal = role === 'merchant'
      ? decodeMerchantMailProposal(value.mailProposal ?? null) : null;
    if (mailProposal && value.stopReason !== 'end_turn') {
      throw new Error('Saved merchant mail proposal invalid');
    }
    if (aclProposal && !sameRolePolicyMode(aclProposal.modeCapability,
      value.modeCapability)) throw new Error('Saved ACL review invalid');
    let aclPage = null;
    if (role === 'admin' && value.aclPage != null) {
      const page = value.aclPage;
      if (!exact(page, ['page', 'total', 'nextPage', 'search'])
        || !Number.isSafeInteger(page.page) || page.page < 1 || page.page > 100000
        || !Number.isSafeInteger(page.total) || page.total < 0
        || (page.nextPage !== null && page.nextPage !== page.page + 1)
        || typeof page.search !== 'string' || encoder.encode(page.search).byteLength > 256) {
        throw new Error('Saved ACL page invalid');
      }
      aclPage = Object.freeze({ ...page });
    }
    return { status: 'completed', text: value.text, stopReason: value.stopReason,
      hops: value.hops, modeCapability: value.modeCapability,
      cards: decodeRoleCards(value.cards, role),
      catalogPage,
      ordersPage: role === 'merchant' ? decodeMerchantOrdersPage(value.ordersPage ?? null) : null,
      orderDetail: decodeMerchantOrderDetail(value.hops, role),
      manualSearch, mailRead, mailProposal, listingsSetup,
      auditRead: role === 'admin'
        ? decodeAdminAuditRead(value.hops, value.modeCapability, value.stopReason) : null,
      auditSearch: auditSearchResult || (auditSearch?.status === 'blocked'
        ? { blocked: true, reason: auditSearch.reason } : null),
      systemHealth, systemConfigRead: systemConfigResult, userLookup,
      reviewDetail: role === 'merchant' ? decodeMerchantReviewDetail(value.reviewDetail ?? null) : null,
      reviewPage: role === 'merchant' ? decodeMerchantReviewPage(value.reviewPage ?? null) : null,
      reviewProposal: role === 'merchant' ? decodeMerchantReviewProposal(value.reviewProposal ?? null) : null,
      userAdministrationProposal: role === 'admin'
        ? await decodeUserAdministrationProposal(value.userAdministrationProposal ?? null) : null,
      passwordResetSetup: role === 'admin'
        ? decodePasswordResetSetup(value.passwordResetSetup ?? null, reference.sessionId,
          reference.requestId) : null,
      policyDetail, policyProposal, mcpDetail, mcpRegistryProposal, registeredMcpSetup,
      systemRestartProposal, systemDiagnosticProposal, auditJobProposal, aclProposal, aclPage,
      inventoryProposal: role === 'merchant' ? decodeInventoryProposal(value.inventoryProposal ?? null) : null,
      pricingProposal: role === 'merchant' ? decodePricingProposal(value.pricingProposal ?? null) : null,
      listingProposal: role === 'merchant' ? await decodeListingEditProposal(value.listingProposal ?? null) : null,
      listingCreateProposal: role === 'merchant' ? await decodeListingCreateProposal(value.listingCreateProposal ?? null) : null };
  }, [role, transport]);

  const recover = useCallback(async () => {
    if (activeRef.current || storageFaultRef.current) return false;
    let reference, completedOnly = false;
    try {
      reference = pending || readRoleAssistantReference(role, shopUserId);
      if (!reference && completedPage) {
        reference = readRoleAssistantCompletedReference(role, shopUserId);
        if (!sameRoleAssistantReference(reference, completedPage)) {
          setCompletedPage(reference);
          setStatus(reference ? 'unresolved' : 'idle');
          return false;
        }
        completedOnly = true;
      }
    } catch (caught) {
      storageFaultRef.current = true;
      setStatus('unresolved'); setError(caught.message || 'Saved role assistant reference is unavailable');
      return false;
    }
    if (!reference) return false;
    const epoch = epochRef.current, controller = new AbortController();
    const current = () => epochRef.current === epoch && !controller.signal.aborted;
    activeRef.current = controller; setStatus('recovering'); setError(null);
    try {
      const value = await readExact(reference, controller.signal);
      if (!current()) return false;
      if (completedOnly) {
        const newerPending = readRoleAssistantReference(role, shopUserId);
        const currentPage = readRoleAssistantCompletedReference(role, shopUserId);
        if (newerPending) {
          sessionRef.current = newerPending.sessionId;
          setPending(newerPending); setCompletedPage(null);
          setTurns([{ sessionId: newerPending.sessionId, requestId: newerPending.requestId,
            user: 'Saved role assistant request', reply: '', hops: [],
            status: 'error', startedAt: newerPending.startedAt }]);
          setStatus('unresolved'); setError('A newer saved assistant request needs checking.');
          return false;
        }
        if (!sameRoleAssistantReference(currentPage, reference)) {
          setCompletedPage(currentPage);
          setStatus(currentPage ? 'unresolved' : 'idle');
          setError(currentPage ? 'Saved assistant page changed. Check the current page.' : null);
          return false;
        }
      }
      if (value.status === 'unconfirmed') {
        if (completedOnly) {
          await clearRoleAssistantCompletedReference(reference, current);
          if (!current()) return false;
          const newerPending = readRoleAssistantReference(role, shopUserId);
          const currentPage = readRoleAssistantCompletedReference(role, shopUserId);
          setPending(newerPending); setCompletedPage(newerPending ? null : currentPage);
          if (newerPending) {
            sessionRef.current = newerPending.sessionId;
            setTurns([{ sessionId: newerPending.sessionId, requestId: newerPending.requestId,
              user: 'Saved role assistant request', reply: '', hops: [],
              status: 'error', startedAt: newerPending.startedAt }]);
          }
          setStatus(newerPending || currentPage ? 'unresolved' : 'idle');
          setError(newerPending ? 'A newer saved assistant request needs checking.'
            : currentPage ? 'Saved assistant page changed. Check the current page.'
              : 'Saved assistant page is no longer available. Start a new chat.');
          return false;
        }
        setStatus('unresolved'); setError(value.reason || 'This request may still be running. Check it again.');
        return false;
      }
      if (!completedOnly) {
        await saveRoleAssistantCompletedReference(reference, current);
        if (!current()) return false;
      }
      const failed = value.stopReason === 'error' || value.stopReason === 'cancelled';
      setTurns(previous => {
        const index = previous.findIndex(turn => turn.requestId === reference.requestId);
        const prior = index < 0 ? null : previous[index];
        const turn = { ...(prior || {}), sessionId: reference.sessionId, requestId: reference.requestId,
          user: prior?.user || 'Saved role assistant request', reply: value.text,
          hops: value.hops, modeCapability: value.modeCapability, status: failed ? 'error' : 'done',
          startedAt: reference.startedAt, finishedAt: Date.now() };
        for (const key of ['cards', 'ordersPage', 'catalogPage', 'orderDetail', 'manualSearch', 'mailRead', 'mailProposal', 'listingsSetup', 'auditRead', 'auditSearch',
          'systemHealth', 'systemConfigRead', 'userLookup', 'systemRestartProposal', 'systemDiagnosticProposal', 'auditJobProposal',
          'aclProposal', 'aclPage', 'reviewDetail', 'reviewPage', 'reviewProposal',
          'userAdministrationProposal', 'passwordResetSetup', 'policyDetail', 'policyProposal',
          'mcpDetail', 'mcpRegistryProposal', 'registeredMcpSetup', 'inventoryProposal',
          'pricingProposal', 'listingProposal', 'listingCreateProposal']) {
          turn[key] = failed ? (key === 'cards' ? [] : null) : value[key];
        }
        if (index < 0) return [...previous, turn];
        const next = [...previous]; next[index] = turn; return next;
      });
      sessionRef.current = reference.sessionId;
      if (!completedOnly) await clearRoleAssistantReference(reference);
      if (!current()) return false;
      if (completedOnly) setCompletedPage(null);
      else setPending(null);
      setStatus(failed ? 'error' : 'idle');
      if (failed) setError('Role assistant did not complete');
      return !failed;
    } catch (caught) {
      if (current()) {
        if (completedOnly && [401, 403, 404, 409].includes(caught?.status)) {
          try {
            let newerPending = readRoleAssistantReference(role, shopUserId);
            let currentPage = readRoleAssistantCompletedReference(role, shopUserId);
            if (!newerPending && sameRoleAssistantReference(currentPage, reference)) {
              await clearRoleAssistantCompletedReference(reference, current);
            }
            newerPending = readRoleAssistantReference(role, shopUserId);
            currentPage = readRoleAssistantCompletedReference(role, shopUserId);
            if (!current()) return false;
            setPending(newerPending); setCompletedPage(newerPending ? null : currentPage);
            if (newerPending) {
              sessionRef.current = newerPending.sessionId;
              setTurns([{ sessionId: newerPending.sessionId, requestId: newerPending.requestId,
                user: 'Saved role assistant request', reply: '', hops: [],
                status: 'error', startedAt: newerPending.startedAt }]);
            }
            setStatus(newerPending || currentPage ? 'unresolved' : 'idle');
            setError(newerPending ? 'A newer saved assistant request needs checking.'
              : currentPage ? 'Saved assistant page changed. Check the current page.'
                : 'Saved assistant page is no longer available. Start a new chat.');
          } catch (storageError) {
            if (current()) { setStatus('unresolved'); setError(storageError.message); }
          }
        } else {
          setStatus('unresolved'); setError(caught.message || 'Saved role assistant request unavailable');
        }
      }
      return false;
    } finally { if (activeRef.current === controller) activeRef.current = null; }
  }, [completedPage, pending, readExact, role, shopUserId]);

  useEffect(() => {
    if (pending || !completedPage || activeRef.current
      || attemptedCompletedRecoveryRef.current === completedPage.requestId) return;
    attemptedCompletedRecoveryRef.current = completedPage.requestId;
    void recover();
  }, [completedPage, pending, recover]);

  const send = useCallback(async (message, selection = null, orderContinuation = null,
    mailContinuation = null, catalogContinuation = null) => {
    if (activeRef.current || pending || completedPage || storageFaultRef.current || !validMessage(message)
      || !['merchant', 'admin'].includes(role) || !Number.isSafeInteger(shopUserId)
      || shopUserId < 1) return false;
    if ([orderContinuation, mailContinuation, catalogContinuation].filter(Boolean).length > 1) return false;
    if (catalogContinuation !== null) {
      const latest = turns.at(-1);
      if (role !== 'merchant' || selection !== null || message !== 'Show more products'
        || !exact(catalogContinuation, ['intent', 'sourceRequestId'])
        || catalogContinuation.intent !== 'catalog_next'
        || typeof catalogContinuation.sourceRequestId !== 'string'
        || !UUID.test(catalogContinuation.sourceRequestId)
        || catalogContinuation.sourceRequestId !== catalogContinuation.sourceRequestId.toLowerCase()
        || latest?.status !== 'done' || !trustedTurnMode(latest.modeCapability)
        || latest.sessionId !== sessionRef.current
        || latest.requestId !== catalogContinuation.sourceRequestId
        || latest.catalogPage?.hasMore !== true) return false;
    }
    if (orderContinuation !== null) {
      const latest = turns.at(-1);
      if (role !== 'merchant' || selection !== null || message !== 'Show older orders'
        || !exact(orderContinuation, ['intent', 'sourceRequestId'])
        || orderContinuation.intent !== 'orders_next'
        || typeof orderContinuation.sourceRequestId !== 'string'
        || !UUID.test(orderContinuation.sourceRequestId)
        || orderContinuation.sourceRequestId !== orderContinuation.sourceRequestId.toLowerCase()
        || latest?.status !== 'done' || !trustedTurnMode(latest.modeCapability)
        || latest.sessionId !== sessionRef.current
        || latest.requestId !== orderContinuation.sourceRequestId
        || !latest.ordersPage?.nextCursor) return false;
    }
    if (mailContinuation !== null) {
      const latest = turns.at(-1);
      if (role !== 'merchant' || selection !== null || message !== 'Show older mail'
        || !exact(mailContinuation, ['intent', 'sourceRequestId'])
        || mailContinuation.intent !== 'mail_next'
        || typeof mailContinuation.sourceRequestId !== 'string'
        || !UUID.test(mailContinuation.sourceRequestId)
        || mailContinuation.sourceRequestId !== mailContinuation.sourceRequestId.toLowerCase()
        || latest?.status !== 'done' || !trustedTurnMode(latest.modeCapability)
        || latest.sessionId !== sessionRef.current
        || latest.requestId !== mailContinuation.sourceRequestId
        || latest.mailRead?.result?.kind !== 'list' || latest.mailRead.result.hasMore !== true) return false;
    }
    let selectedCard = null;
    if (selection !== null) {
      const latest = turns.at(-1);
      const typedSelection = selection && Object.hasOwn(selection, 'intent');
      const adminRole = typedSelection && role === 'admin' && selection.intent === 'user_role';
      if ((!typedSelection && !exact(selection, ['choiceId']))
        || (typedSelection && !exact(selection, adminRole
          ? ['choiceId', 'intent', 'newRole'] : selection.intent === 'pricing_compare'
            ? ['choiceId', 'intent', 'competitorUrl'] : ['choiceId', 'intent']))
        || typeof selection.choiceId !== 'string'
        || !UUID.test(selection.choiceId) || selection.choiceId !== selection.choiceId.toLowerCase()
        || latest?.status !== 'done' || !trustedTurnMode(latest.modeCapability)) return false;
      selectedCard = latest.cards?.find(card => card.choiceId === selection.choiceId
        && CARD_KINDS[role]?.includes(card.kind)) || null;
      if (!selectedCard || (typedSelection && role === 'merchant'
        && selectedCard.kind !== (['product_details', 'pricing_compare', 'manual_search', 'listing_rewrite', 'listing_optimize'].includes(selection.intent)
          ? 'merchant_product' : ['mail_list', 'mail_send'].includes(selection.intent)
            ? 'merchant_mail_recipient' : ['mail_detail', 'mail_reply'].includes(selection.intent)
              ? 'merchant_mail_message' : 'merchant_review'))
        || (typedSelection && role === 'admin' && selectedCard.kind !== (
          selection.intent?.startsWith('policy_') ? 'admin_policy'
            : selection.intent?.startsWith('mcp_') ? 'admin_mcp_server'
              : selection.intent?.startsWith('acl_') ? 'admin_acl_permission' : 'tenant_user'))) return false;
      if (typedSelection && role === 'merchant') {
        if (selection.intent === 'pricing_compare') {
          try { validateCompetitorUrl(selection.competitorUrl); }
          catch { return false; }
        } else if (selection.intent === 'manual_search') {
          if (encoder.encode(message).byteLength > 4096) return false;
        } else if (!['product_details', 'listing_rewrite', 'listing_optimize', 'manual_search', 'mail_list', 'mail_detail',
          'mail_send', 'mail_reply'].includes(selection.intent)) {
          try { merchantReviewSelection(selection.choiceId, selection.intent); }
          catch { return false; }
        }
      }
      if (typedSelection && role === 'admin') {
        if (selection.intent === 'user_password_reset' || selection.intent === 'user_ban') {
          if (encoder.encode(message).byteLength > 1024) return false;
        } else if (selection.intent === 'user_role') {
          if (!['customer', 'merchant', 'admin'].includes(selection.newRole)) return false;
        } else if (!['policy_detail', 'policy_edit', 'policy_preview', 'policy_delete',
          'mcp_detail', 'mcp_retire', 'acl_allow', 'acl_deny'].includes(selection.intent)) {
          return false;
        }
      }
    }
    const epoch = epochRef.current, controller = new AbortController();
    activeRef.current = controller; setStatus('thinking'); setError(null);
    let reference = null;
    try {
      if (readRoleAssistantReference(role, shopUserId)) {
        throw new Error('Check the saved role assistant request before sending another');
      }
      if (completedPage) throw new Error('Check the saved assistant page before sending another');
      let sessionId = sessionRef.current;
      if (!sessionId) {
        const opened = await transport(path(role, 'session'), {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}', signal: controller.signal,
        });
        if (!opened.ok) throw new Error(`Role assistant session unavailable (${opened.status})`);
        requireAgentContentType(opened, 'application/json', 'Role assistant session');
        const value = await opened.json();
        if (!UUID.test(value?.sessionId || '')) throw new Error('Role assistant session identity invalid');
        sessionId = value.sessionId.toLowerCase();
        if (epochRef.current !== epoch || controller.signal.aborted) return false;
        sessionRef.current = sessionId;
      }
      reference = { role, shopUserId, sessionId, requestId: newId(), startedAt: Date.now() };
      await saveRoleAssistantReference(reference);
      if (epochRef.current !== epoch || controller.signal.aborted) return false;
      setPending(reference);
      watchingRef.current = { controller, reference };
      setCanStopWatching(true);
      setTurns(previous => [...previous, { sessionId: reference.sessionId,
        requestId: reference.requestId,
        user: selectedCard ? `Selected ${selectedCard.kind === 'merchant_order' ? 'order'
          : selectedCard.kind === 'merchant_review' ? 'review'
          : selectedCard.kind === 'merchant_mail_recipient' ? 'mail recipient'
            : selectedCard.kind === 'merchant_mail_message' ? 'mail message'
          : role === 'merchant' ? 'product' : selectedCard.kind === 'admin_policy' ? 'policy'
            : selectedCard.kind === 'admin_mcp_server' ? 'MCP server'
              : selectedCard.kind === 'admin_acl_permission' ? 'permission' : 'user'}: ${selectedCard.title}${message === 'Use my selected option.' ? '' : ` · ${message}`}` : message,
        reply: '', hops: [], status: 'in-flight', startedAt: reference.startedAt }]);
      const response = await transport(path(role, 'chat'), {
        method: 'POST', headers: { 'content-type': 'application/json', accept: 'text/event-stream' },
        body: JSON.stringify({ sessionId, requestId: reference.requestId, message,
          ...(orderContinuation ? { orderContinuation } : {}),
          ...(mailContinuation ? { mailContinuation } : {}),
          ...(catalogContinuation ? { catalogContinuation } : {}),
          ...(selectedCard ? { selection: { choiceId: selectedCard.choiceId,
            ...(selection?.intent ? { intent: selection.intent } : {}),
            ...(selection?.intent === 'user_role' ? { newRole: selection.newRole } : {}),
            ...(selection?.intent === 'pricing_compare' ? { competitorUrl: selection.competitorUrl } : {}) } } : {}) }),
        signal: controller.signal,
      });
      if (epochRef.current !== epoch || controller.signal.aborted) return false;
      if (!response.ok) throw new Error(`Role assistant request unavailable (${response.status})`);
      requireAgentContentType(response, 'text/event-stream', 'Role assistant stream');
      if (!response.body?.getReader) throw new Error('Role assistant stream unavailable');
      const reader = response.body.getReader(), decoder = new TextDecoder();
      readerRef.current = { controller, reader };
      if (epochRef.current !== epoch || controller.signal.aborted) {
        try { await reader.cancel(); } catch {}
        return false;
      }
      let buffer = '', bytes = 0, events = 0;
      while (true) {
        const part = await reader.read();
        if (epochRef.current !== epoch || controller.signal.aborted) { await reader.cancel(); return false; }
        if (part.done) { buffer += decoder.decode(); break; }
        bytes += part.value.byteLength;
        if (bytes > MAX_STREAM_BYTES) throw new Error('Role assistant stream limit exceeded');
        buffer += decoder.decode(part.value, { stream: true });
        while (true) {
          const next = takeAgentFrame(buffer);
          if (!next) break;
          buffer = next.rest;
          if (++events > MAX_EVENTS) throw new Error('Role assistant stream limit exceeded');
          const event = parseAgentFrame(next.frame);
          if (!event) continue;
          if (event.payload.sessionId !== sessionId
            || event.payload.requestId !== reference.requestId) throw new Error('Role assistant stream identity mismatch');
          if (event.name === 'tool_call') {
            setTurns(previous => previous.map(turn => turn.requestId === reference.requestId
              ? { ...turn, hops: [...turn.hops, { id: event.payload.id, tool: event.payload.tool,
                params: event.payload.params, status: 'in-flight' }] } : turn));
          } else if (event.name === 'tool_result') {
            setTurns(previous => previous.map(turn => turn.requestId === reference.requestId
              ? { ...turn, hops: turn.hops.map(hop => hop.id === event.payload.id
                ? { ...hop, result: event.payload.result, status: 'done' } : hop) } : turn));
          } else if (event.name === 'assistant_message' && typeof event.payload.text === 'string') {
            setTurns(previous => previous.map(turn => turn.requestId === reference.requestId
              ? { ...turn, reply: event.payload.text } : turn));
          } else if (event.name === 'done') {
            if (watchingRef.current?.controller === controller) {
              watchingRef.current = null; setCanStopWatching(false);
            }
            if (readerRef.current?.controller === controller) readerRef.current = null;
            if (!trustedTurnMode(event.payload.modeCapability)) throw new Error('Role assistant mode unavailable');
            if (event.payload.stopReason === 'error' || event.payload.stopReason === 'cancelled') {
              throw new Error('Role assistant did not complete');
            }
            const saved = await readExact(reference, controller.signal);
            if (epochRef.current !== epoch || controller.signal.aborted) return false;
            if (saved.status === 'unconfirmed') {
              setStatus('unresolved');
              setError(saved.reason || 'This request may still be running. Check the saved request.');
              // Retain the unresolved reference, but let its exact GET recovery
              // proceed even when local stream cancellation does not settle.
              try { Promise.resolve(reader.cancel()).catch(() => {}); } catch {}
              return false;
            }
            const failed = saved.stopReason === 'error' || saved.stopReason === 'cancelled';
            await saveRoleAssistantCompletedReference(reference,
              () => epochRef.current === epoch && !controller.signal.aborted);
            if (epochRef.current !== epoch || controller.signal.aborted) return false;
            setTurns(previous => previous.map(turn => turn.requestId === reference.requestId
              ? { ...turn, reply: saved.text, hops: saved.hops, cards: failed ? [] : saved.cards,
                ordersPage: failed ? null : saved.ordersPage,
                catalogPage: failed ? null : saved.catalogPage,
                orderDetail: failed ? null : saved.orderDetail,
                manualSearch: failed ? null : saved.manualSearch,
                mailRead: failed ? null : saved.mailRead,
                mailProposal: failed ? null : saved.mailProposal,
                listingsSetup: failed ? null : saved.listingsSetup,
                auditRead: failed ? null : saved.auditRead,
                auditSearch: failed ? null : saved.auditSearch,
                systemHealth: failed ? null : saved.systemHealth,
                systemConfigRead: failed ? null : saved.systemConfigRead,
                userLookup: failed ? null : saved.userLookup,
                systemRestartProposal: failed ? null : saved.systemRestartProposal,
                systemDiagnosticProposal: failed ? null : saved.systemDiagnosticProposal,
                auditJobProposal: failed ? null : saved.auditJobProposal,
                aclProposal: failed ? null : saved.aclProposal,
                aclPage: failed ? null : saved.aclPage,
                reviewDetail: failed ? null : saved.reviewDetail,
                reviewPage: failed ? null : saved.reviewPage,
                reviewProposal: failed ? null : saved.reviewProposal,
                userAdministrationProposal: failed ? null : saved.userAdministrationProposal,
                passwordResetSetup: failed ? null : saved.passwordResetSetup,
                policyDetail: failed ? null : saved.policyDetail,
                policyProposal: failed ? null : saved.policyProposal,
                mcpDetail: failed ? null : saved.mcpDetail,
                mcpRegistryProposal: failed ? null : saved.mcpRegistryProposal,
                registeredMcpSetup: failed ? null : saved.registeredMcpSetup,
                inventoryProposal: failed ? null : saved.inventoryProposal,
                pricingProposal: failed ? null : saved.pricingProposal,
                listingProposal: failed ? null : saved.listingProposal,
                listingCreateProposal: failed ? null : saved.listingCreateProposal,
                status: failed ? 'error' : 'done', modeCapability: saved.modeCapability,
                finishedAt: Date.now() } : turn));
            await clearRoleAssistantReference(reference);
            if (epochRef.current !== epoch || controller.signal.aborted) return false;
            setPending(null); setStatus(failed ? 'error' : 'idle');
            if (failed) setError('Role assistant did not complete');
            // The exact saved result and parent clear are already acknowledged.
            // Cancellation only releases local stream resources; it must not
            // hold the active guard after the UI becomes ready for another turn.
            try { Promise.resolve(reader.cancel()).catch(() => {}); } catch {}
            return !failed;
          } else if (event.name === 'error') {
            throw new Error('Role assistant outcome is uncertain. Check the saved request.');
          }
        }
      }
      throw new Error('Role assistant stream ended before a terminal event');
    } catch (caught) {
      if (epochRef.current === epoch && !controller.signal.aborted) {
        setStatus(reference ? 'unresolved' : 'error');
        setError(caught.message || 'Role assistant unavailable');
      }
      return false;
    } finally {
      if (activeRef.current === controller) activeRef.current = null;
      if (readerRef.current?.controller === controller) readerRef.current = null;
      if (watchingRef.current?.controller === controller) {
        watchingRef.current = null;
        if (epochRef.current === epoch) setCanStopWatching(false);
      }
    }
  }, [completedPage, pending, readExact, role, shopUserId, transport, turns]);

  const checkSavedAssessment = useCallback(async (reference, policyInstruction = false) => {
    const label = policyInstruction ? 'policy instruction' : 'System';
    if (role !== 'admin' || activeRef.current || !exact(reference, ['sessionId', 'requestId'])
      || ![reference.sessionId, reference.requestId].every(value => typeof value === 'string'
        && UUID.test(value) && value === value.toLowerCase())) {
      return Object.freeze({ kind: 'error', message: `Saved ${label} assessment is unavailable.` });
    }
    const source = turns.find(turn => turn.sessionId === reference.sessionId
      && turn.requestId === reference.requestId);
    if (!source || source.status !== 'done' || source.systemConfigRead?.kind !== 'content') {
      return Object.freeze({ kind: 'error', message: 'Return to the verified saved System read before checking its assessment.' });
    }
    const epoch = epochRef.current, controller = new AbortController();
    const current = () => epochRef.current === epoch && !controller.signal.aborted;
    activeRef.current = controller; setStatus('recovering'); setError(null);
    try {
      const response = await transport(path(role, policyInstruction
        ? 'policy/instruction/assessment-retry' : 'system/config/assessment-retry'), {
        method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ sessionId: reference.sessionId, requestId: reference.requestId }), signal: controller.signal,
      });
      if (!current()) return Object.freeze({ kind: 'stale' });
      if (!response.ok) {
        let message = `Saved ${label} assessment unavailable (${response.status})`;
        try {
          const body = await response.json();
          if (!current()) return Object.freeze({ kind: 'stale' });
          if (typeof body?.error === 'string') message = body.error;
        } catch { /* Public status is enough. */ }
        if (!current()) return Object.freeze({ kind: 'stale' });
        return Object.freeze({ kind: 'error', message });
      }
      requireAgentContentType(response, 'application/json', `Saved ${label} assessment`);
      const body = await response.json();
      if (!current()) return Object.freeze({ kind: 'stale' });
      const result = savedSystemAssessmentResult(body, label);
      if (policyInstruction && result.kind === 'ineligible' && result.status !== 'ineligible') {
        throw new Error('Saved policy instruction assessment invalid');
      }
      return result;
    } catch (caught) {
      if (!current()) return Object.freeze({ kind: 'stale' });
      return Object.freeze({ kind: 'error', message: caught?.message || `Saved ${label} assessment unavailable.` });
    } finally {
      if (activeRef.current === controller) activeRef.current = null;
      if (current()) setStatus('idle');
    }
  }, [role, transport, turns]);
  const checkSavedSystemConfigAssessment = useCallback(reference =>
    checkSavedAssessment(reference, false), [checkSavedAssessment]);
  const checkSavedPolicyInstructionAssessment = useCallback(reference =>
    checkSavedAssessment(reference, true), [checkSavedAssessment]);

  return Object.freeze({ turns, pending, completedPagePending: !!completedPage,
    status, error, send, recover, canStopWatching, stopWatching,
    checkSavedSystemConfigAssessment, checkSavedPolicyInstructionAssessment });
}
