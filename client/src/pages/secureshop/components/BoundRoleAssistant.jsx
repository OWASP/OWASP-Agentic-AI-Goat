import { MerchantListingsSetupCard } from './MerchantListingsSetup.jsx';
import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { SafeChatBody } from '../../../components/workshop/WorkshopExperience.js';
import { useBoundRoleAssistant } from '../hooks/useBoundRoleAssistant.js';
import MerchantInventoryConfirmation from './MerchantInventoryConfirmation.jsx';
import MerchantPricingConfirmation from './MerchantPricingConfirmation.jsx';
import MerchantListingEditConfirmation from './MerchantListingEditConfirmation.jsx';
import MerchantListingCreateConfirmation from './MerchantListingCreateConfirmation.jsx';
import MerchantReviewChat from './MerchantReviewChat.jsx';
import AdminUserConfirmation from './AdminUserConfirmation.jsx';
import AdminPolicyConfirmation from './AdminPolicyConfirmation.jsx';
import AdminMcpRegistryConfirmation from './AdminMcpRegistryConfirmation.jsx';
import AdminSystemRestartConfirmation from './AdminSystemRestartConfirmation.jsx';
import AdminSystemDiagnosticConfirmation from './AdminSystemDiagnosticConfirmation.jsx';
import AdminAuditJobConfirmation from './AdminAuditJobConfirmation.jsx';
import AdminAclConfirmation from './AdminAclConfirmation.jsx';
import RegisteredAdminConversation from './RegisteredAdminConversation.jsx';
import AdminAuditRead from './AdminAuditRead.jsx';
import { AdminAuditSearch, AdminSystemHealth, AdminSystemConfigRead, AdminUserLookup } from './AdminSavedReads.jsx';
import MerchantManualSearchCard from './MerchantManualSearchCard.jsx';
import MerchantMailReadCard from './MerchantMailReadCard.jsx';
import MerchantMailConfirmation from './MerchantMailConfirmation.jsx';
import { openStandaloneChatPasswordReset } from '../bridge/passwordResetIntent.mjs';
import { requireAgentContentType } from '../utils/agentStreamProtocol.mjs';
import { validateCompetitorUrl } from '../pages/merchant/pricingOperation.mjs';

function MerchantCompareChoice({ card, disabled, onPrepare }) {
  const [competitorUrl, setCompetitorUrl] = useState('');
  let valid = false;
  try { validateCompetitorUrl(competitorUrl); valid = true; } catch { /* Keep the typed URL unchanged. */ }
  return <div className="ss-input-wrap" style={{ marginTop: 8 }}>
    <label className="ss-input-label" htmlFor={`compare-url-${card.choiceId}`}>
      Competitor URL for {card.title}
    </label>
    <input className="ss-input" id={`compare-url-${card.choiceId}`} type="url" inputMode="url"
      aria-label={`Competitor URL for ${card.title}`} placeholder="http://competitor.example/product"
      value={competitorUrl} disabled={disabled} onChange={event => setCompetitorUrl(event.target.value)} />
    <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      aria-label={`Review competitor comparison for ${card.title}`}
      disabled={disabled || !valid}
      onClick={() => onPrepare({ choiceId: card.choiceId, intent: 'pricing_compare', competitorUrl })}>
      Review comparison
    </button>
  </div>;
}

const ROLE_HELP = Object.freeze({
  merchant: 'Ask about your catalog, orders, mail, storefront overview, top products, or pricing. Mail sends and replies need a saved proposal and your confirmation. Stock changes and Pricing analysis require saved proposals and your explicit confirmation.',
  admin: 'Search users, policies, registered MCP servers, and permissions. Review available audit jobs, System diagnostics, restarts, and changes before confirming them.',
});
const TOOLS = Object.freeze({
  merchant: ['Catalog search', 'Owned order summaries and details', 'Named mail recipients, messages, sends and replies', 'Storefront overview', 'Top products', 'Stock change proposal', 'Pricing analysis proposal'],
  admin: ['User search', 'Policy and MCP server search', 'Permission search', 'Recent audit activity', 'Audit SQL search', 'Audit job review when available', 'System reads', 'System diagnostic review', 'Restart review when available', 'Change review', 'Password reset handoff'],
});

export default function BoundRoleAssistant({ role, shopUserId, authorityKey, instance = 'role',
  transport = globalThis.fetch, composerTarget = null, scrollContainerRef = null }) {
  const [message, setMessage] = useState('');
  const messageRevisionRef = useRef(0);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [selectedMailSend, setSelectedMailSend] = useState(null);
  const [selectedReviewAction, setSelectedReviewAction] = useState(null);
  const [selectedAdminBan, setSelectedAdminBan] = useState(null);
  const [selectedAdminRole, setSelectedAdminRole] = useState(null);
  const [selectedPolicyAction, setSelectedPolicyAction] = useState(null);
  const [resetHandoffError, setResetHandoffError] = useState(null);
  const [policyOutcomeRevision, setPolicyOutcomeRevision] = useState(0);
  const [mailOutcomeRevision, setMailOutcomeRevision] = useState(0);
  const [channel, setChannel] = useState('assistant');
  const [registeredPending, setRegisteredPending] = useState(false);
  const registeredRef = useRef(null);
  const followLatestRef = useRef(true);
  const assistant = useBoundRoleAssistant({ role, shopUserId, authorityKey, transport });
  const confirmSystemRestart = useCallback((body, signal) => transport(
    '/api/secureshop/agents/admin/assistant/system/restart/confirm', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body), signal,
    }), [transport]);
  const readSystemRestart = useCallback(async (operationId, signal) => {
    const response = await transport(`/api/secureshop/admin/system/restart-operations/${operationId}`,
      { signal });
    if (response.status === 404) return { state: 'not_found' };
    if (!response.ok && response.status !== 202) {
      throw Error(`Saved restart lookup failed (${response.status})`);
    }
    requireAgentContentType(response, 'application/json', 'Saved restart operation');
    return response.json();
  }, [transport]);
  useEffect(() => { setSelectedProduct(null); }, [role, shopUserId, authorityKey, transport]);
  useEffect(() => { setSelectedMailSend(null); }, [role, shopUserId, authorityKey, transport]);
  useEffect(() => { setSelectedReviewAction(null); }, [role, shopUserId, authorityKey, transport]);
  useEffect(() => { setSelectedAdminBan(null); setSelectedAdminRole(null); }, [role, shopUserId, authorityKey, transport]);
  useEffect(() => { setSelectedPolicyAction(null); }, [role, shopUserId, authorityKey, transport]);
  useEffect(() => { setChannel('assistant'); },
    [role, shopUserId, authorityKey, transport]);
  useEffect(() => {
    if (selectedProduct && (assistant.turns.at(-1)?.requestId !== selectedProduct.turnRequestId
      || assistant.turns.at(-1)?.status !== 'done')) setSelectedProduct(null);
  }, [assistant.turns, selectedProduct]);
  useEffect(() => {
    const latest = assistant.turns.at(-1);
    if (selectedMailSend && (latest?.requestId !== selectedMailSend.turnRequestId
      || latest?.status !== 'done')) setSelectedMailSend(null);
    if (selectedAdminBan && (latest?.requestId !== selectedAdminBan.turnRequestId
      || latest?.status !== 'done')) setSelectedAdminBan(null);
    if (selectedAdminRole && (latest?.requestId !== selectedAdminRole.turnRequestId
      || latest?.status !== 'done')) setSelectedAdminRole(null);
    if (selectedPolicyAction && (latest?.requestId !== selectedPolicyAction.turnRequestId
      || latest?.status !== 'done')) setSelectedPolicyAction(null);
  }, [assistant.turns, selectedMailSend, selectedAdminBan, selectedAdminRole, selectedPolicyAction]);
  useEffect(() => {
    const body = scrollContainerRef?.current;
    if (!composerTarget || !body) return undefined;
    followLatestRef.current = body.scrollHeight - body.clientHeight - body.scrollTop <= 80;
    const trackScroll = () => {
      followLatestRef.current = body.scrollHeight - body.clientHeight - body.scrollTop <= 80;
    };
    body.addEventListener('scroll', trackScroll, { passive: true });
    return () => body.removeEventListener('scroll', trackScroll);
  }, [composerTarget, scrollContainerRef]);
  useLayoutEffect(() => {
    const body = scrollContainerRef?.current;
    if (composerTarget && body && followLatestRef.current) body.scrollTop = body.scrollHeight;
  }, [composerTarget, scrollContainerRef, assistant.turns, assistant.pending, assistant.status,
    policyOutcomeRevision, mailOutcomeRevision]);
  if (!Object.hasOwn(ROLE_HELP, role)) return null;
  const busy = assistant.status === 'thinking' || assistant.status === 'recovering';
  const assistantLocked = busy || !!assistant.pending || !!assistant.completedPagePending;
  const locked = assistantLocked || registeredPending;
  const latest = assistant.turns.at(-1);
  const inventoryProposal = role === 'merchant' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done' ? latest.inventoryProposal || null : null;
  const pricingProposal = role === 'merchant' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done' ? latest.pricingProposal || null : null;
  const mailProposal = role === 'merchant' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done' ? latest.mailProposal || null : null;
  const listingProposal = role === 'merchant' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done' ? latest.listingProposal || null : null;
  const listingCreateProposal = role === 'merchant' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done' ? latest.listingCreateProposal || null : null;
  const userAdministrationProposal = role === 'admin' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done'
    ? latest.userAdministrationProposal || null : null;
  const passwordResetSetup = role === 'admin' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done'
    ? latest.passwordResetSetup || null : null;
  const policyProposal = role === 'admin' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done' ? latest.policyProposal || null : null;
  const mcpRegistryProposal = role === 'admin' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done' ? latest.mcpRegistryProposal || null : null;
  const systemRestartProposal = role === 'admin' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done' ? latest.systemRestartProposal || null : null;
  const systemDiagnosticProposal = role === 'admin' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done' ? latest.systemDiagnosticProposal || null : null;
  const auditJobProposal = role === 'admin' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done' ? latest.auditJobProposal || null : null;
  const aclProposal = role === 'admin' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done' ? latest.aclProposal || null : null;
  const registeredMcpSetup = role === 'admin' && assistant.status === 'idle'
    && !assistant.pending && latest?.status === 'done' ? latest.registeredMcpSetup || null : null;
  const latestCompleted = [...assistant.turns].reverse().find(turn => turn.status === 'done') || null;
  const latestCompletedIsCurrent = latestCompleted === latest;
  const submit = event => {
    event.preventDefault();
    if (!message.trim() || locked || (selectedProduct?.intent === 'manual_search'
      && (!message.isWellFormed() || message.includes('\0')
        || new TextEncoder().encode(message).byteLength > 4096)) || (selectedAdminBan
      && (!message.isWellFormed() || new TextEncoder().encode(message).byteLength > 1024))) return;
    const submittedRevision = messageRevisionRef.current;
    const selection = role === 'merchant' && selectedProduct
      ? selectedProduct.intent === 'manual_search'
        ? { choiceId: selectedProduct.choiceId, intent: 'manual_search' }
        : { choiceId: selectedProduct.choiceId } : null;
    const mailSendSelection = role === 'merchant' && selectedMailSend
      ? { choiceId: selectedMailSend.choiceId, intent: 'mail_send' } : null;
    const reviewSelection = role === 'merchant' && selectedReviewAction
      ? { choiceId: selectedReviewAction.choiceId, intent: selectedReviewAction.intent } : null;
    const adminSelection = role === 'admin' && selectedAdminBan
      ? { choiceId: selectedAdminBan.choiceId, intent: 'user_ban' } : null;
    const policySelection = role === 'admin' && selectedPolicyAction
      ? { choiceId: selectedPolicyAction.choiceId, intent: selectedPolicyAction.intent } : null;
    setSelectedProduct(null);
    setSelectedMailSend(null);
    setSelectedReviewAction(null);
    void (adminSelection ? assistant.send(message, adminSelection)
      : policySelection ? assistant.send(message, policySelection)
      : reviewSelection ? assistant.send(message, reviewSelection)
      : mailSendSelection ? assistant.send(message, mailSendSelection)
      : selection ? assistant.send(message, selection) : assistant.send(message))
      .then(sent => {
        if (sent && adminSelection) setSelectedAdminBan(null);
        if (sent && policySelection) setSelectedPolicyAction(null);
        if (sent && messageRevisionRef.current === submittedRevision) setMessage('');
      });
  };
  const composer = <form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={submit}>
    <label htmlFor={`lane-${role}-assistant-${instance}`}>Message</label>
    {selectedProduct && <p role="status">
      {selectedProduct.intent === 'manual_search' ? 'Search manual for: ' : 'Selected product for this message: '}
      {selectedProduct.title}{' '}
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        onClick={() => setSelectedProduct(null)}>Clear selection</button>
    </p>}
    {selectedMailSend && <p role="status">Draft a message to {selectedMailSend.title}{' '}
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        onClick={() => setSelectedMailSend(null)}>Cancel</button>
    </p>}
    {selectedReviewAction && <p role="status">Rejecting review: {selectedReviewAction.title}{' '}
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        onClick={() => setSelectedReviewAction(null)}>Cancel</button>
    </p>}
    {selectedAdminBan && <p role="status">Ban reason for {selectedAdminBan.title}{' '}
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        onClick={() => setSelectedAdminBan(null)}>Cancel</button>
    </p>}
    {selectedPolicyAction && <p role="status">
      {selectedPolicyAction.intent === 'policy_preview' ? 'Preview' : 'Edit'} policy {selectedPolicyAction.title} from this message{' '}
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        onClick={() => setSelectedPolicyAction(null)}>Cancel</button>
    </p>}
    <textarea id={`lane-${role}-assistant-${instance}`} className="ss-lane__input"
      value={message} onChange={event => { messageRevisionRef.current += 1; setMessage(event.target.value); }}
      maxLength={selectedAdminBan ? 1024 : selectedProduct?.intent === 'manual_search' ? 4096 : 8192}
      rows={3} placeholder={role === 'merchant'
        ? selectedProduct?.intent === 'manual_search'
          ? 'What would you like to find in this product manual?'
          : selectedMailSend ? 'Describe the subject and message you want to send'
          : 'Which products are selling best?' : selectedAdminBan
          ? 'Write the reason for this ban' : selectedPolicyAction
            ? 'Describe the policy source and targets you want to review' : 'Find a shop user or policy by name'}
      style={{ width: '100%', boxSizing: 'border-box', marginTop: 5 }}
      onKeyDown={event => {
        if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
          event.preventDefault(); submit(event);
        }
      }} />
    <span className="ss-mono" style={{ fontSize: 11, opacity: 0.7 }}>Enter to send · Shift+Enter for a new line</span>
    <button className="ss-btn" type="submit" disabled={!message.trim() || locked
      || (selectedProduct?.intent === 'manual_search'
        && (!message.isWellFormed() || message.includes('\0')
          || new TextEncoder().encode(message).byteLength > 4096))
      || (selectedAdminBan && (!message.isWellFormed()
        || new TextEncoder().encode(message).byteLength > 1024))}>
      {busy ? 'Working…' : `Send to ${role} assistant`}
    </button>
  </form>;
  return <>
    {role === 'admin' && <div role="group" aria-label="Admin chat channels" style={{ marginBottom: 10 }}>
      <button className="ss-btn ss-btn--ghost" type="button" aria-label="Open Admin assistant"
        disabled={channel === 'assistant' || locked || registeredPending}
        onClick={() => setChannel('assistant')}>Admin assistant</button>
      <button className="ss-btn ss-btn--ghost" type="button" aria-label="Open registered tools"
        disabled={channel === 'registered' || assistantLocked}
        onClick={() => setChannel('registered')}>Registered tools · complete manifest</button>
    </div>}
    <div className="ss-role-assistant" hidden={role === 'admin' && channel !== 'assistant'}
      data-testid={`${role}-role-assistant`}>
    <p>{ROLE_HELP[role]}</p>
    <div className="ss-mono" style={{ fontSize: 11, marginBottom: 10 }}>
      Available reads: {TOOLS[role].join(' · ')}
    </div>
    <div role="log" aria-label={`${role === 'merchant' ? 'Merchant' : 'Admin'} assistant conversation`}
      aria-live="polite" aria-relevant="additions text">
      {assistant.turns.length === 0 && <p className="ss-mono">Ask a question to start the conversation.</p>}
      {assistant.turns.map((turn, index) => <article className="ss-turn" key={turn.requestId || index}
        data-testid="role-assistant-turn">
        <div className="ss-turn__you">YOU</div>
        <div className="ss-turn__msg">{turn.user}</div>
        <div className="ss-turn__supervisor">{role.toUpperCase()} ASSISTANT · {turn.status}</div>
        {turn.hops?.length > 0 && <div role="list">{turn.hops.map((hop, hopIndex) =>
          <div className="ss-card ss-mono" role="listitem" key={hop.id || hopIndex}
            style={{ padding: 10, marginTop: 8, fontSize: 11 }}>
            {hop.tool || 'Shop read'} · {hop.status || (hop.error ? 'error' : 'done')}
          </div>)}</div>}
        {turn.reply && <div className="ss-turn__reply">
          <div className="ss-turn__you">{role.toUpperCase()} ASSISTANT · reply</div>
          <div data-testid="role-assistant-reply"><SafeChatBody content={turn.reply} /></div>
        </div>}
        {role === 'merchant' && turn.status === 'done' && turn.orderDetail &&
          <section className="ss-card" aria-label="Merchant order details"
            data-testid="merchant-order-detail" style={{ padding: 12, marginTop: 10 }}>
            <strong>Your items in Order #{turn.orderDetail.orderId}</strong>
            <p className="ss-mono">{turn.orderDetail.status} · {turn.orderDetail.orderDate}</p>
            <ul>{turn.orderDetail.items.map((item, itemIndex) =>
              <li key={itemIndex}>{item.name} · {item.quantity} × USD {item.price.toFixed(2)}
                {' · '}Line USD {item.lineTotal.toFixed(2)}
                {item.discountAmount > 0 && <> · Discount USD {item.discountAmount.toFixed(2)}</>}
              </li>)}</ul>
            <strong>Your items subtotal: USD {turn.orderDetail.merchantSubtotal.toFixed(2)}</strong>
          </section>}
        {role === 'merchant' && turn.status === 'done' && index === assistant.turns.length - 1 && !locked && turn.listingsSetup && <MerchantListingsSetupCard setup={turn.listingsSetup} />}
        {role === 'merchant' && turn.status === 'done' && turn.manualSearch &&
          <MerchantManualSearchCard read={turn.manualSearch} />}
        {role === 'merchant' && turn.status === 'done' && turn.mailRead &&
          <MerchantMailReadCard key={`mail-read:${authorityKey}:${turn.requestId || index}`} read={turn.mailRead}
            active={index === assistant.turns.length - 1 && !assistant.pending} shopUserId={shopUserId}
            source={{ sessionId: turn.sessionId, requestId: turn.requestId }}
            locked={locked} transport={transport} />}
        {role === 'admin' && turn.status === 'done' && turn.auditRead &&
          <AdminAuditRead read={turn.auditRead} />}
        {role === 'admin' && turn.status === 'done' && turn.auditSearch &&
          <AdminAuditSearch read={turn.auditSearch} />}
        {role === 'admin' && turn.status === 'done' && turn.systemHealth &&
          <AdminSystemHealth read={turn.systemHealth} />}
        {role === 'admin' && turn.status === 'done' && turn.userLookup &&
          <AdminUserLookup key={`user-lookup:${authorityKey}:${turn.requestId}`} read={turn.userLookup}
            reference={{ sessionId: turn.sessionId, requestId: turn.requestId }}
            authorityKey={authorityKey} transport={transport} locked={locked} />}
        {role === 'admin' && turn.status === 'done' && turn.systemConfigRead &&
          <AdminSystemConfigRead read={turn.systemConfigRead}
            reference={{ sessionId: turn.sessionId, requestId: turn.requestId }}
            onCheck={assistant.checkSavedSystemConfigAssessment}
            onCheckPolicy={assistant.checkSavedPolicyInstructionAssessment} />}
        {role === 'admin' && turn.status === 'done' && turn.policyDetail &&
          <section className="ss-card" aria-label="Admin policy details"
            style={{ padding: 12, marginTop: 10 }}>
            <strong>{turn.policyDetail.name}</strong>
            <p>Version {turn.policyDetail.policyVersion} · Shown to: {turn.policyDetail.targets.join(', ')}</p>
            <pre style={{ maxHeight: 300, overflow: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere',
              border: '1px solid var(--rule)', borderRadius: 8, padding: 12 }}>{turn.policyDetail.markdown}</pre>
          </section>}
        {role === 'admin' && turn.status === 'done' && turn.mcpDetail &&
          <section className="ss-card" aria-label="Admin MCP server details"
            style={{ padding: 12, marginTop: 10 }}>
            <strong>{turn.mcpDetail.server.name}</strong>
            <p>{turn.mcpDetail.server.provenance === 'owned_registry' ? 'Registered server' : 'Discovered scenario'}
              {' · '}Schema version {turn.mcpDetail.schemaVersion}</p>
            <p>{turn.mcpDetail.server.transport || 'Scenario'} · {turn.mcpDetail.server.url
              || turn.mcpDetail.server.stdio_cmd || turn.mcpDetail.server.scenario}</p>
            <p className="ss-mono" style={{ overflowWrap: 'anywhere' }}>
              Current schema fingerprint: {turn.mcpDetail.server.schemaSha256 || 'Unavailable before discovery'}
            </p>
            <strong>Available tools</strong>
            {turn.mcpDetail.tools.length === 0 ? <p>No tools in the saved schema.</p>
              : <ul>{turn.mcpDetail.tools.map(tool => <li key={tool.name}>
                <strong>{tool.name}</strong><p style={{ overflowWrap: 'anywhere' }}>{tool.description}</p>
                <details><summary>Input schema</summary><pre style={{ maxHeight: 250, overflow: 'auto',
                  whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                  {JSON.stringify(tool.inputSchema, null, 2)}</pre></details>
              </li>)}</ul>}
            <details><summary>Schema history ({turn.mcpDetail.history.length})</summary>
              <ul>{turn.mcpDetail.history.map((item, itemIndex) =>
                <li key={`${item.version}-${itemIndex}`} style={{ overflowWrap: 'anywhere' }}>
                  Version {item.version} · {item.observedAt} · {item.schemaSha256}</li>)}</ul>
            </details>
          </section>}
        {turn.cards?.filter(card => card.kind !== 'merchant_review').length > 0 && <div role="group" aria-label={role === 'merchant'
          ? turn.cards.filter(card => card.kind !== 'merchant_review').every(card =>
            ['merchant_mail_recipient', 'merchant_mail_message'].includes(card.kind))
            ? 'Merchant mail choices'
            : turn.cards.filter(card => card.kind !== 'merchant_review').some(card => card.kind === 'merchant_order')
            ? turn.cards.filter(card => card.kind !== 'merchant_review').some(card => card.kind === 'merchant_product')
              ? 'Merchant product and order choices' : 'Merchant order choices'
            : 'Merchant product choices' : turn.cards.some(card => card.kind === 'admin_acl_permission')
              ? 'Admin permission choices' : turn.cards.some(card => card.kind === 'admin_mcp_server')
                ? 'Admin MCP server choices' : turn.cards.some(card => card.kind === 'admin_policy')
                  ? 'Admin policy and user choices' : 'Admin user choices'} style={{ marginTop: 10 }}>
          {turn.cards.filter(card => card.kind !== 'merchant_review').map(card => <div className="ss-card" key={card.choiceId}
            style={{ padding: 12, marginTop: 8 }}>
            {card.kind !== 'admin_policy' && card.kind !== 'admin_mcp_server'
              && card.kind !== 'merchant_mail_recipient' && card.kind !== 'merchant_mail_message'
              && card.kind !== 'admin_acl_permission' && <button className="ss-btn ss-btn--ghost" type="button"
              aria-label={card.kind === 'merchant_product'
                ? `View details for ${card.title}` : `Choose ${card.title}`}
              disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
              onClick={() => { setSelectedProduct(null);
                void assistant.send(card.kind === 'merchant_product'
                  ? 'Show my selected product details.' : 'Use my selected option.',
                card.kind === 'merchant_product'
                  ? { choiceId: card.choiceId, intent: 'product_details' } : { choiceId: card.choiceId }); }}
              style={{ display: 'block', width: '100%', padding: 10, textAlign: 'left' }}>
              <strong>{card.title}</strong>
              <span className="ss-mono" style={{ display: 'block', fontSize: 12 }}>{card.detail}</span>
              <span className="ss-mono" style={{ display: 'block', fontSize: 11, marginTop: 6 }}>
                {card.kind === 'merchant_product' ? 'View details'
                  : `Ask about this ${card.kind === 'merchant_order' ? 'order'
                    : role === 'merchant' ? 'product' : 'user'}`}
              </span>
            </button>}
            {role === 'merchant' && card.kind === 'merchant_product' && card.readOnly !== true && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
              onClick={() => { setSelectedProduct(null); setSelectedMailSend(null); setSelectedReviewAction(null); void assistant.send('Prepare to rewrite this listing.', {choiceId:card.choiceId,intent:'listing_rewrite'}); }}>Rewrite listing</button>}
            {role === 'merchant' && card.kind === 'merchant_product' && card.readOnly !== true && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
              onClick={() => { setSelectedProduct(null); setSelectedMailSend(null); setSelectedReviewAction(null); void assistant.send('Prepare image optimization for this listing.', {choiceId:card.choiceId,intent:'listing_optimize'}); }}>Prepare image optimization</button>}
            {role === 'merchant' && card.kind === 'merchant_mail_recipient' && <div>
              <strong>{card.title}</strong><p className="ss-mono" style={{ overflowWrap: 'anywhere' }}>{card.detail}</p>
              <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
                aria-label={`View mailbox for ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => { setSelectedProduct(null); setSelectedMailSend(null); setSelectedReviewAction(null);
                  void assistant.send('Show this recipient’s mailbox.',
                    { choiceId: card.choiceId, intent: 'mail_list' }); }}>View mailbox</button>
              <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
                aria-label={`Compose message to ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => { setSelectedProduct(null); setSelectedReviewAction(null);
                  setSelectedMailSend({ choiceId: card.choiceId, title: card.title,
                    turnRequestId: turn.requestId }); }}>Compose message</button>
            </div>}
            {role === 'merchant' && card.kind === 'merchant_mail_message' && <div>
              <strong>{card.title}</strong><p className="ss-mono" style={{ overflowWrap: 'anywhere' }}>{card.detail}</p>
              <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
                aria-label={`View message: ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => { setSelectedProduct(null); setSelectedMailSend(null); setSelectedReviewAction(null);
                  void assistant.send('Show this message.',
                    { choiceId: card.choiceId, intent: 'mail_detail' }); }}>View message</button>
              <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
                aria-label={`Prepare reply to ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => { setSelectedProduct(null); setSelectedMailSend(null); setSelectedReviewAction(null);
                  void assistant.send('Prepare a reply to this message.',
                    { choiceId: card.choiceId, intent: 'mail_reply' }); }}>Prepare reply</button>
            </div>}
            {role === 'merchant' && card.kind === 'merchant_product' && card.readOnly !== true &&
              <MerchantCompareChoice card={card}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onPrepare={selection => { setSelectedProduct(null);
                  void assistant.send('Compare my selected product with this competitor URL.', selection); }} />}
            {role === 'admin' && card.kind === 'admin_policy' && <div>
              <strong>{card.title}</strong>
              <p className="ss-mono">{card.detail}</p>
              <button className="ss-btn ss-btn--ghost" type="button" aria-label={`View policy ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => { setSelectedPolicyAction(null);
                  void assistant.send('Show this policy in full.', { choiceId: card.choiceId, intent: 'policy_detail' }); }}>
                View full policy</button>
              <button className="ss-btn ss-btn--ghost" type="button" aria-label={`Describe policy edit for ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => setSelectedPolicyAction({ choiceId: card.choiceId, title: card.title,
                  intent: 'policy_edit', turnRequestId: turn.requestId })}>Describe edit</button>
              <button className="ss-btn ss-btn--ghost" type="button" aria-label={`Describe policy preview for ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => setSelectedPolicyAction({ choiceId: card.choiceId, title: card.title,
                  intent: 'policy_preview', turnRequestId: turn.requestId })}>Describe preview</button>
              <button className="ss-btn ss-btn--ghost" type="button" aria-label={`Review policy deletion for ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => { setSelectedPolicyAction(null);
                  void assistant.send('Prepare to delete this policy.', { choiceId: card.choiceId, intent: 'policy_delete' }); }}>
                Review deletion</button>
            </div>}
            {role === 'admin' && card.kind === 'admin_mcp_server' && <div>
              <strong>{card.title}</strong><p className="ss-mono">{card.detail}</p>
              <button className="ss-btn ss-btn--ghost" type="button"
                aria-label={`View MCP server ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => void assistant.send('Show this registered server and its schema history.',
                  { choiceId: card.choiceId, intent: 'mcp_detail' })}>View server details</button>
              <button className="ss-btn ss-btn--ghost" type="button"
                aria-label={`Review MCP retirement for ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => void assistant.send('Prepare to retire this registered server.',
                  { choiceId: card.choiceId, intent: 'mcp_retire' })}>Review retirement</button>
            </div>}
            {role === 'admin' && card.kind === 'admin_acl_permission' && <div>
              <strong>{card.title}</strong><p className="ss-mono">{card.detail}</p>
              <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
                aria-label={`Review allow permission for ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => void assistant.send('Review allowing this permission.',
                  { choiceId: card.choiceId, intent: 'acl_allow' })}>Review Allow</button>
              <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
                aria-label={`Review deny permission for ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => void assistant.send('Review denying this permission.',
                  { choiceId: card.choiceId, intent: 'acl_deny' })}>Review Deny</button>
            </div>}
            {role === 'merchant' && card.kind === 'merchant_product' && card.readOnly !== true && <button className="ss-btn ss-btn--ghost" type="button"
              aria-label={`Use ${card.title} in next message`}
              disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
              onClick={() => setSelectedProduct({ choiceId: card.choiceId, title: card.title,
                turnRequestId: turn.requestId })}>
              Use in next message
            </button>}
            {role === 'merchant' && card.kind === 'merchant_product' && card.readOnly !== true && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
              aria-label={`Search manual for ${card.title}`}
              disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
              onClick={() => setSelectedProduct({ choiceId: card.choiceId, title: card.title,
                intent: 'manual_search', turnRequestId: turn.requestId })}>
              Search manual
            </button>}
            {role === 'merchant' && card.kind === 'merchant_product' && card.readOnly !== true && <button className="ss-btn ss-btn--ghost" type="button"
              aria-label={`View reviews for ${card.title}`}
              disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
              onClick={() => {
                setSelectedProduct(null);
                void assistant.send('Show reviews for this product', { choiceId: card.choiceId });
              }}>
              View reviews
            </button>}
            {role === 'admin' && card.kind === 'tenant_user' && <div style={{ marginTop: 8 }}>
              <label className="ss-mono" htmlFor={`admin-role-${card.choiceId}`}>New role</label>
              <select id={`admin-role-${card.choiceId}`}
                aria-label={`New role for ${card.title}`}
                value={selectedAdminRole?.choiceId === card.choiceId ? selectedAdminRole.newRole : ''}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onChange={event => setSelectedAdminRole(event.target.value
                  ? { choiceId: card.choiceId, newRole: event.target.value,
                    turnRequestId: turn.requestId } : null)}>
                <option value="">Choose role</option>
                {['customer', 'merchant', 'admin'].map(nextRole =>
                  <option value={nextRole} key={nextRole}>{nextRole}</option>)}
              </select>
              <button className="ss-btn ss-btn--ghost" type="button"
                aria-label={`Review role change for ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1
                  || selectedAdminRole?.choiceId !== card.choiceId || !selectedAdminRole.newRole}
                onClick={() => {
                  const nextRole = selectedAdminRole.newRole;
                  setSelectedAdminRole(null); setSelectedAdminBan(null);
                  void assistant.send(`Review changing this user's role to ${nextRole}.`,
                    { choiceId: card.choiceId, intent: 'user_role', newRole: nextRole });
                }}>Review role change</button>
              <button className="ss-btn ss-btn--ghost" type="button"
                aria-label={`Write ban reason for ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => { setSelectedAdminRole(null);
                  setSelectedAdminBan({ choiceId: card.choiceId, title: card.title,
                    turnRequestId: turn.requestId }); }}>
                Write ban reason
              </button>
              <button className="ss-btn ss-btn--ghost" type="button"
                aria-label={`Review password reset for ${card.title}`}
                disabled={locked || turn.status !== 'done' || index !== assistant.turns.length - 1}
                onClick={() => {
                  setSelectedAdminRole(null); setSelectedAdminBan(null); setResetHandoffError(null);
                  void assistant.send('Review a password reset for this user.',
                    { choiceId: card.choiceId, intent: 'user_password_reset' });
                }}>Review password reset</button>
            </div>}
          </div>)}
        </div>}
        {role === 'admin' && turn.status === 'done' && turn.aclPage && <div className="ss-mono"
          style={{ fontSize: 12, marginTop: 8 }}>Permission page {turn.aclPage.page} · {turn.aclPage.total} matches
          {turn.aclPage.nextPage && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
            disabled={locked || index !== assistant.turns.length - 1}
            onClick={() => void assistant.send(`Show permission page ${turn.aclPage.nextPage}.`)}>
            Next permission page</button>}</div>}
        {role === 'merchant' && turn.status === 'done' && (turn.ordersPage?.nextCursor || turn.ordersPage?.productName)
          && index === assistant.turns.length - 1 && !assistant.pending && <div style={{ marginTop: 8 }}>
            {turn.ordersPage.productName && <p className="ss-mono" style={{ fontSize: 12,
              overflowWrap: 'anywhere' }}>Orders containing {turn.ordersPage.productName}</p>}
            {turn.ordersPage.nextCursor && index === assistant.turns.length - 1
              && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
              aria-label="Older merchant orders" disabled={locked}
              onClick={() => void assistant.send('Show older orders', null,
                { intent: 'orders_next', sourceRequestId: turn.requestId })}>Older orders</button>}
          </div>}
        {role === 'merchant' && turn.status === 'done' && turn.mailRead?.result?.kind === 'list'
          && turn.mailRead.result.hasMore && index === assistant.turns.length - 1
          && !assistant.pending && <button className="ss-btn ss-btn--ghost ss-btn--sm"
            type="button" aria-label="Older mail" disabled={locked}
            onClick={() => void assistant.send('Show older mail', null, null,
              { intent: 'mail_next', sourceRequestId: turn.requestId })}>Older mail</button>}
        {role === 'merchant' && turn.status === 'done' && turn.catalogPage?.hasMore === true
          && index === assistant.turns.length - 1 && !assistant.pending
          && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
            aria-label="Next merchant products" disabled={locked}
            onClick={() => void assistant.send('Show more products', null, null, null,
              { intent: 'catalog_next', sourceRequestId: turn.requestId })}>Next products</button>}
      </article>)}
    </div>
    {role === 'merchant' && <MerchantReviewChat
      cards={latestCompletedIsCurrent ? latestCompleted.cards : []}
      detail={latestCompletedIsCurrent ? latestCompleted.reviewDetail : null}
      page={latestCompletedIsCurrent ? latestCompleted.reviewPage : null}
      proposal={latestCompletedIsCurrent ? latestCompleted.reviewProposal : null}
      sessionId={latestCompletedIsCurrent ? latestCompleted.sessionId : null}
      requestId={latestCompletedIsCurrent ? latestCompleted.requestId : null}
      authorityKey={authorityKey}
      locked={locked || !latestCompletedIsCurrent}
      onSelect={selection => {
        if (!latestCompletedIsCurrent) return;
        setSelectedProduct(null);
        if (selection.intent === 'review_reject') {
          const card = latestCompleted.cards?.find(candidate => candidate.choiceId === selection.choiceId);
          setSelectedReviewAction({ ...selection, title: card?.title || 'selected review' });
          return;
        }
        setSelectedReviewAction(null);
        void assistant.send('Use my selected review action.', selection);
      }} transport={transport} />}
    {assistant.pending && <div className="ss-card" role="status" style={{ padding: 12, marginTop: 12 }}>
      <p>This assistant request may have completed. Check its saved outcome before sending another.</p>
      {assistant.canStopWatching && <>
        <p className="ss-mono">Stop watching closes this response stream here. The saved request may still finish.</p>
        <button className="ss-btn ss-btn--ghost" type="button"
          onClick={() => assistant.stopWatching()}>Stop watching response</button>
      </>}
      <button className="ss-btn ss-btn--ghost" type="button" disabled={busy}
        onClick={() => void assistant.recover()}>Check saved assistant request</button>
    </div>}
    {assistant.completedPagePending && !assistant.pending && <div className="ss-card" role="status"
      style={{ padding: 12, marginTop: 12 }}>
      <p>Checking the last saved assistant page.</p>
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy}
        onClick={() => void assistant.recover()}>Check saved assistant page</button>
    </div>}
    {assistant.error && <p role="alert" style={{ color: 'var(--rust)' }}>{assistant.error}</p>}
    {role === 'merchant' && <MerchantInventoryConfirmation proposal={inventoryProposal}
      sessionId={inventoryProposal ? latest.sessionId : null}
      requestId={inventoryProposal ? latest.requestId : null}
      authorityKey={authorityKey} transport={transport} />}
    {role === 'merchant' && <MerchantPricingConfirmation proposal={pricingProposal}
      sessionId={pricingProposal ? latest.sessionId : null}
      requestId={pricingProposal ? latest.requestId : null}
      authorityKey={authorityKey} transport={transport} />}
    {role === 'merchant' && <MerchantMailConfirmation proposal={mailProposal}
      sessionId={mailProposal ? latest.sessionId : null}
      requestId={mailProposal ? latest.requestId : null}
      authorityKey={authorityKey} transport={transport} locked={locked}
      onOutcomeChange={() => setMailOutcomeRevision(value => value + 1)} />}
    {role === 'merchant' && <MerchantListingEditConfirmation proposal={listingProposal}
      sessionId={listingProposal ? latest.sessionId : null}
      requestId={listingProposal ? latest.requestId : null}
      authorityKey={authorityKey} transport={transport} />}
    {role === 'merchant' && <MerchantListingCreateConfirmation proposal={listingCreateProposal}
      sessionId={listingCreateProposal ? latest.sessionId : null}
      requestId={listingCreateProposal ? latest.requestId : null}
      authorityKey={authorityKey} transport={transport} />}
    {role === 'admin' && <AdminUserConfirmation proposal={userAdministrationProposal}
      sessionId={userAdministrationProposal ? latest.sessionId : null}
      requestId={userAdministrationProposal ? latest.requestId : null}
      shopUserId={shopUserId} authorityKey={authorityKey} transport={transport} locked={locked} />}
    {role === 'admin' && <AdminPolicyConfirmation proposal={policyProposal}
      sessionId={policyProposal ? latest.sessionId : null}
      requestId={policyProposal ? latest.requestId : null}
      authorityKey={authorityKey} transport={transport} locked={locked}
      onOutcomeChange={setPolicyOutcomeRevision} />}
    {role === 'admin' && <AdminMcpRegistryConfirmation proposal={mcpRegistryProposal}
      sessionId={mcpRegistryProposal ? latest.sessionId : null}
      requestId={mcpRegistryProposal ? latest.requestId : null}
      shopUserId={shopUserId} authorityKey={authorityKey} transport={transport} locked={locked}
      onOutcomeChange={setPolicyOutcomeRevision} />}
    {role === 'admin' && <AdminSystemRestartConfirmation proposal={systemRestartProposal} shopUserId={shopUserId}
      sessionId={systemRestartProposal ? latest.sessionId : null}
      requestId={systemRestartProposal ? latest.requestId : null}
      authorityKey={authorityKey} transport={transport} locked={locked}
      confirmOperation={confirmSystemRestart}
      readOperation={readSystemRestart} />}
    {role === 'admin' && <AdminSystemDiagnosticConfirmation proposal={systemDiagnosticProposal}
      sessionId={systemDiagnosticProposal ? latest.sessionId : null}
      requestId={systemDiagnosticProposal ? latest.requestId : null}
      shopUserId={shopUserId} authorityKey={authorityKey} transport={transport} locked={locked} />}
    {role === 'admin' && <AdminAuditJobConfirmation proposal={auditJobProposal}
      sessionId={auditJobProposal ? latest.sessionId : null}
      requestId={auditJobProposal ? latest.requestId : null}
      authorityKey={authorityKey} transport={transport} locked={locked}
      onOutcomeChange={setPolicyOutcomeRevision} />}
    {role === 'admin' && <AdminAclConfirmation proposal={aclProposal}
      sessionId={aclProposal ? latest.sessionId : null}
      requestId={aclProposal ? latest.requestId : null}
      authorityKey={authorityKey} transport={transport} locked={locked}
      onOutcomeChange={setPolicyOutcomeRevision} />}
    {registeredMcpSetup && <section className="ss-card" aria-label="Registered tools handoff"
      style={{ padding: 14, marginTop: 12 }}>
      <strong>Ask registered tools</strong>
      <p>This uses the complete registered-tool manifest in a separate conversation.</p>
      <p>Your prompt: {registeredMcpSetup.message}</p>
      <button className="ss-btn" type="button" disabled={locked || registeredPending}
        onClick={() => {
          if (!registeredRef.current) return;
          setChannel('registered'); setRegisteredPending(true);
          void registeredRef.current.ask(registeredMcpSetup.message, registeredMcpSetup);
        }}>Ask registered tools</button>
    </section>}
    {passwordResetSetup && <section className="ss-card" aria-label="Password reset handoff"
      style={{ padding: 14, marginTop: 12 }}>
      <strong>Review password reset</strong>
      <p>{passwordResetSetup.username} · {passwordResetSetup.identityKind === 'teaching_persona'
        ? 'Teaching persona' : 'Registered account'}</p>
      <p>The reset opens in the protected shop panel. No password appears in this conversation.</p>
      <button className="ss-btn" type="button" disabled={locked}
        onClick={() => {
          setResetHandoffError(null);
          if (!openStandaloneChatPasswordReset({ sessionId: passwordResetSetup.sessionId,
            requestId: passwordResetSetup.requestId, choiceId: passwordResetSetup.choiceId })) {
            setResetHandoffError('Open the standalone shop to review this password reset.');
          }
        }}>Open protected password reset</button>
      {resetHandoffError && <p role="alert">{resetHandoffError}</p>}
    </section>}
    {channel === 'assistant' && (composerTarget ? createPortal(composer, composerTarget) : composer)}
    </div>
    {role === 'admin' && <RegisteredAdminConversation ref={registeredRef}
      shopUserId={shopUserId} authorityKey={authorityKey} transport={transport}
      visible={channel === 'registered'} composerTarget={composerTarget}
      onPendingChange={setRegisteredPending} />}
  </>;
}
