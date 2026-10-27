import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router-dom';
import Turn from './AgentLane/Turn.jsx';
import HopDetailSheet from './AgentLane/HopDetailSheet.jsx';
import CustomerChoiceCards from './CustomerChoiceCards.jsx';
import CustomerIdorLessonCard from './CustomerIdorLessonCard.jsx';
import CustomerCheckoutCard from './CustomerCheckoutCard.jsx';
import CustomerCouponProposalCard from './CustomerCouponProposalCard.jsx';
import CustomerTicketConfirmationCard from './CustomerTicketConfirmationCard.jsx';
import CustomerCheckoutAuditLesson from './CustomerCheckoutAuditLesson.jsx';
import CustomerAvatarUploadLesson from './CustomerAvatarUploadLesson.jsx';
import CustomerAvatarTraversalLesson from './CustomerAvatarTraversalLesson.jsx';
import CustomerFileSummaryLesson from './CustomerFileSummaryLesson.jsx';
import CustomerFilePathSummaryLesson from './CustomerFilePathSummaryLesson.jsx';
import CustomerCartConfirmation from './CustomerCartConfirmation.jsx';
import PracticePaymentSetup from './PracticePaymentSetup.jsx';
import PracticeAddressSetup from './PracticeAddressSetup.jsx';
import PracticeProfileUpdate from './PracticeProfileUpdate.jsx';
import BoundProductPicker from './BoundProductPicker.jsx';
import BoundRoleAssistant from './BoundRoleAssistant.jsx';
import { useAgentStream } from '../hooks/useAgentStream.js';
import { useCustomerIdorLesson } from '../hooks/useCustomerIdorLesson.js';
import { useCustomerProductSearchLesson } from '../hooks/useCustomerProductSearchLesson.js';
import { useCustomerOrderStatusLesson } from '../hooks/useCustomerOrderStatusLesson.js';
import { useCustomerCouponConfirmation } from '../hooks/useCustomerCouponConfirmation.js';
import { useCustomerTicketConfirmation } from '../hooks/useCustomerTicketConfirmation.js';
import { useSearchEchoAssessment } from '../hooks/useSearchEchoAssessment.js';
import { useProductQuestion } from '../hooks/useProductQuestion.js';
import { useAuth } from '../context/AuthContext.jsx';
import { useCart } from '../context/CartContext.jsx';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';
import { decodeCustomerCards } from '../utils/customerCards.mjs';
import { decodeSelectedOrderDetails } from '../utils/customerOrderDetails.mjs';
import { decodePracticePaymentMethods } from '../utils/practicePaymentOperation.mjs';
import { decodeAddressCards } from '../utils/addressSetupOperation.mjs';
import { createCustomerIdorLessonReferenceStore } from '../utils/customerIdorLessonReference.mjs';
import { createCustomerCouponConfirmationStore } from '../utils/customerCouponConfirmationReference.mjs';
import { createCustomerTicketConfirmationStore } from '../utils/customerTicketConfirmationReference.mjs';
import { shopStorage, flushShopStorage } from '../utils/shopStorage.mjs';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../bridge/assessmentPanelIntent.mjs';
import InventoryPanel from '../pages/merchant/InventoryPanel.jsx';
import useBoundAnalytics from '../pages/merchant/useBoundAnalytics.js';
import { useBoundPricing } from '../pages/merchant/useBoundPricing.js';
import { useBoundListings } from '../pages/merchant/useBoundListings.js';

const CUSTOMER_TASKS = [
  ['product', 'Product question'], ['chat', 'General help'], ['refund', 'Refund request'],
  ['idor', 'Access control lesson'], ['product-search-lesson', 'Product search lesson'],
  ['order-status-lesson', 'Order status lesson'], ['checkout-audit-lesson', 'Checkout audit token lesson'],
  ['avatar-upload-lesson', 'Avatar upload lesson'], ['file-summary-lesson', 'File summary lesson'],
  ['avatar-traversal-lesson', 'Avatar path traversal lesson'],
  ['file-path-summary-lesson', 'File path summary lesson'],
];
const idorReferenceStore = createCustomerIdorLessonReferenceStore({
  storage: shopStorage, flush: flushShopStorage,
});
const couponConfirmationStore = createCustomerCouponConfirmationStore({
  storage: shopStorage, flush: flushShopStorage,
});
const ticketConfirmationStore = createCustomerTicketConfirmationStore({
  storage: shopStorage, flush: flushShopStorage,
});
const MERCHANT_TASKS = [
  ['inventory', 'Inventory'], ['assistant', 'Shop assistant'], ['analytics', 'Analytics'], ['pricing', 'Pricing'],
  ['listing', 'Listing rewrite'], ['reviews', 'Review moderation'],
];
const FIELD_STYLE = { width: '100%', boxSizing: 'border-box', marginTop: 5 };
const validResourceId = value => Number.isSafeInteger(Number(value))
  && Number(value) > 0 && Number(value) <= 2147483647;
const money = value => value !== null && value !== undefined && value !== ''
  && Number.isFinite(Number(value)) ? `$${Number(value).toFixed(2)}` : '';

function selectedProductDetails(turn) {
  if (!turn || turn.status !== 'done' || turn.stopReason !== 'end_turn'
    || !trustedTurnMode(turn.modeCapability)) return null;
  const hop = [...(turn.hops || [])].reverse().find(candidate => candidate.tool === 'catalog.details'
    && candidate.status === 'ok' && !candidate.error && trustedTurnMode(candidate.modeCapability));
  const choiceId = hop?.params?.choiceId?.toLowerCase();
  if (!choiceId || !turn.cards?.some(card => card.kind === 'product' && card.choiceId === choiceId)) return null;
  const envelope = hop.result;
  if (!envelope || typeof envelope !== 'object' || envelope.isError === true
    || Object.keys(envelope).sort().join(',') !== 'content'
    || !Array.isArray(envelope.content) || envelope.content.length !== 1) return null;
  const part = envelope.content[0];
  if (!part || typeof part !== 'object' || Object.keys(part).sort().join(',') !== 'text,type'
    || part.type !== 'text' || typeof part.text !== 'string' || new TextEncoder().encode(part.text).byteLength > 128 * 1024) return null;
  let result;
  try { result = JSON.parse(part.text); } catch { return null; }
  if (!result || typeof result !== 'object' || Object.keys(result).sort().join(',') !== 'cards,product'
    || !Array.isArray(result.cards) || result.cards.length !== 1) return null;
  let returnedCards;
  try { returnedCards = decodeCustomerCards(result.cards); } catch { return null; }
  if (!returnedCards?.some(card => card.kind === 'product' && card.choiceId === choiceId)) return null;
  const product = result?.product;
  if (!product || typeof product !== 'object' || typeof product.name !== 'string' || !product.name.trim()
    || new TextEncoder().encode(product.name).byteLength > 4096) return null;
  const description = typeof product.description === 'string' && product.description.trim()
    && new TextEncoder().encode(product.description).byteLength <= 65536 ? product.description : 'Unavailable';
  const rawPrice = product.price;
  const price = rawPrice !== null && rawPrice !== undefined && rawPrice !== ''
    && (typeof rawPrice === 'number' || typeof rawPrice === 'string')
    && String(rawPrice).length <= 64 && Number.isFinite(Number(rawPrice)) && Number(rawPrice) >= 0
    ? `$${Number(rawPrice).toFixed(2)}` : 'Unavailable';
  const stock = Number.isInteger(product.stock_quantity) && product.stock_quantity >= 0
    ? `${product.stock_quantity} available` : 'Unavailable';
  return { name: product.name, description, price, stock };
}

function Policy({ capability }) {
  const trusted = trustedTurnMode(capability);
  return trusted && <div className="ss-mono" style={{ fontSize: 11, marginTop: 6 }}>
    {trusted.featureId} effect policy · {trusted.effectiveMode}
  </div>;
}

function TaskStatus({ error, status }) {
  return <>
    {status && <p role="status" style={{ whiteSpace: 'pre-wrap' }}>{status}</p>}
    {error && <p role="alert" style={{ color: 'var(--rust)' }}>{error}</p>}
  </>;
}

function ProductQuestionTask({ productId: routeProductId, ownerKey, token, instance }) {
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [message, setMessage] = useState('');
  const question = useProductQuestion({ productId: selectedProduct?.id ?? '', ownerKey });
  const submit = event => {
    event.preventDefault();
    if (!selectedProduct || !question.validProduct || !message.trim() || question.status === 'thinking') return;
    void question.send(message);
  };
  return <>
    <p>Choose a product from this shop, then ask a question about it.</p>
    <BoundProductPicker instance={instance} source="customer" initialProductId={routeProductId}
      selectedProduct={selectedProduct} onSelect={setSelectedProduct}
      authorityKey={ownerKey} transport={globalThis.fetch} />
    <form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={submit}>
      <label htmlFor={`lane-product-question-${instance}`}>Question</label>
      <input id={`lane-product-question-${instance}`} className="ss-lane__input" value={message}
        onChange={event => setMessage(event.target.value)} maxLength={8192} style={FIELD_STYLE}
        placeholder="Will this work with my setup?" required />
      <button className="ss-btn" type="submit" disabled={!selectedProduct || !question.validProduct || !message.trim() || question.status === 'thinking'}>
        {question.status === 'thinking' ? 'Asking…' : 'Ask about product'}
      </button>
    </form>
    {question.turns.map((turn, index) => <article className="ss-turn" key={index} data-testid="product-question-turn">
      <div className="ss-turn__you">YOU · PRODUCT QUESTION</div>
      <div className="ss-turn__msg">{turn.user}</div>
      <div className="ss-turn__supervisor">PRODUCT ASSIST · {turn.status}</div>
      {turn.reply && <div className="ss-turn__reply" style={{ whiteSpace: 'pre-wrap' }}>
        <Policy capability={turn.modeCapability} />{turn.reply}
      </div>}
    </article>)}
    <TaskStatus error={question.error} />
  </>;
}

function RefundTask({ userId, token, instance }) {
  const transport = globalThis.fetch;
  const [orders, setOrders] = useState([]);
  const [ordersStatus, setOrdersStatus] = useState('loading');
  const [selectedOrder, setSelectedOrder] = useState(null);
  const [orderItems, setOrderItems] = useState({});
  const [loadingOrderId, setLoadingOrderId] = useState(null);
  const detailControllerRef = useRef(null);
  const detailEpochRef = useRef(0);
  const [reason, setReason] = useState('');
  const [selectedHop, setSelectedHop] = useState(null);
  const stream = useAgentStream({ role: 'customer/refund', defaultUserId: userId, authorityKey: token });
  useEffect(() => {
    const controller = new AbortController();
    detailEpochRef.current += 1;
    detailControllerRef.current?.abort();
    detailControllerRef.current = null;
    setOrderItems({}); setLoadingOrderId(null);
    setOrders([]); setSelectedOrder(null); setOrdersStatus('loading');
    transport('/api/secureshop/orders', { signal: controller.signal })
      .then(async response => {
        if (!response.ok) throw new Error('Orders unavailable');
        const body = await response.json();
        if (!Array.isArray(body?.orders) || body.orders.some(order => !validResourceId(order?.id)))
          throw new Error('Orders response invalid');
        if (!controller.signal.aborted) { setOrders(body.orders); setOrdersStatus('ready'); }
      })
      .catch(() => { if (!controller.signal.aborted) setOrdersStatus('error'); });
    return () => { controller.abort(); detailEpochRef.current += 1; detailControllerRef.current?.abort(); };
  }, [userId, token, transport]);
  const viewProducts = async orderId => {
    if (!validResourceId(orderId) || detailControllerRef.current
      || orderItems[orderId]?.status === 'ready') return;
    const controller = new AbortController();
    const epoch = detailEpochRef.current;
    detailControllerRef.current = controller;
    setLoadingOrderId(orderId);
    try {
      const response = await transport(`/api/secureshop/orders/${orderId}`, { signal: controller.signal });
      if (!response.ok) throw new Error('Order products unavailable');
      const body = await response.json();
      if (Number(body?.order?.id) !== Number(orderId) || !Array.isArray(body.items)
        || body.items.some(item => typeof item?.name !== 'string' || !item.name.trim()
          || !Number.isSafeInteger(item.quantity) || item.quantity < 1)) {
        throw new Error('Order products invalid');
      }
      if (!controller.signal.aborted && detailEpochRef.current === epoch) {
        setOrderItems(previous => ({ ...previous, [orderId]: { status: 'ready', items: body.items.map(item => ({
          name: item.name, quantity: item.quantity,
        })) } }));
      }
    } catch {
      if (!controller.signal.aborted && detailEpochRef.current === epoch) {
        setOrderItems(previous => ({ ...previous, [orderId]: { status: 'error' } }));
      }
    } finally {
      if (detailControllerRef.current === controller) detailControllerRef.current = null;
      if (!controller.signal.aborted && detailEpochRef.current === epoch) setLoadingOrderId(null);
    }
  };
  const submit = event => {
    event.preventDefault();
    if (!selectedOrder || stream.status === 'thinking') return;
    const message = `refund order ${selectedOrder.id}${reason.trim() ? `: ${reason.trim()}` : ''}`;
    void stream.send(message);
  };
  return <>
    <p>Choose an order you own. An agent reply alone does not confirm a refund ticket; check your Orders page.</p>
    {ordersStatus === 'loading' && <p role="status">Loading your orders…</p>}
    {ordersStatus === 'error' && <p role="alert">Your orders are unavailable.</p>}
    {ordersStatus === 'ready' && !orders.length && <p>No orders in this shop yet.</p>}
    {ordersStatus === 'ready' && orders.length > 0 && <div aria-label="Owned order choices">
      {orders.map(order => <article className="ss-card" key={order.id}
        style={{ padding: 12, marginBottom: 8 }}>
        <button className="ss-btn ss-btn--ghost" type="button" onClick={() => setSelectedOrder(order)}
          style={{ width: '100%', textAlign: 'left' }}>
          <strong>Order #{order.id} · {new Date(order.order_date).toLocaleDateString()}</strong>
          <span className="ss-mono" style={{ display: 'block', fontSize: 12 }}>
            {String(order.status || 'Order')}{money(order.total_amount) ? ` · ${money(order.total_amount)}` : ''}
          </span>
        </button>
        <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
          aria-label={`View products in Order #${order.id}`}
          disabled={loadingOrderId !== null || orderItems[order.id]?.status === 'ready'}
          onClick={() => void viewProducts(order.id)}>View products</button>
        {loadingOrderId === order.id && <p role="status">Loading products for Order #{order.id}…</p>}
        {orderItems[order.id]?.status === 'error' && <p role="alert">Products for Order #{order.id} are unavailable. Try again.</p>}
        {orderItems[order.id]?.status === 'ready' && (orderItems[order.id].items.length
          ? <ul aria-label={`Products in Order #${order.id}`}>
              {orderItems[order.id].items.map((item, index) => <li key={index}>{item.name} × {item.quantity}</li>)}
            </ul>
          : <p>No product names are recorded for this order.</p>)}
      </article>)}
    </div>}
    {selectedOrder && <p role="status">Selected Order #{selectedOrder.id} from {new Date(selectedOrder.order_date).toLocaleDateString()}</p>}
    <form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={submit}>
      <label htmlFor={`lane-refund-reason-${instance}`}>Reason</label>
      <input id={`lane-refund-reason-${instance}`} className="ss-lane__input" value={reason}
        onChange={event => setReason(event.target.value)} maxLength={2000} style={FIELD_STYLE}
        placeholder="Why are you requesting a refund?" />
      <button className="ss-btn" type="submit" disabled={!selectedOrder || stream.status === 'thinking'}>
        {stream.status === 'thinking' ? 'Working…' : 'Ask refund agent'}
      </button>
    </form>
    {stream.turns.map((turn, index) => <Turn key={index} turn={turn} role="customer" onOpenHop={setSelectedHop} />)}
    <TaskStatus error={stream.error} />
    <HopDetailSheet hop={selectedHop} onClose={() => setSelectedHop(null)} />
    <Link to="/secureshop/orders">View orders</Link>
  </>;
}

function CustomerIdorTask({ userId, token }) {
  const lesson = useCustomerIdorLesson({ shopUserId: userId, authorityKey: token,
    transport: globalThis.fetch, referenceStore: idorReferenceStore });
  useEffect(() => { void lesson.loadCards(); }, []); // A read never provisions lesson targets.
  const judgment = lesson.assessment?.judgment;
  return <>
    <p>Try the reserved practice cart item or order through a customer agent. The current mode decides whether the request is allowed.</p>
    {!lesson.cards && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={lesson.loading || lesson.busy || !!lesson.reference}
      onClick={() => void lesson.prepare()}>Prepare lesson targets</button>}
    {lesson.reference && !lesson.cards && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={lesson.loading || lesson.busy} onClick={() => void lesson.loadCards()}>
      Load lesson targets
    </button>}
    <CustomerIdorLessonCard cards={lesson.cards} mode={lesson.mode}
      loading={lesson.loading} busy={lesson.busy} error={lesson.error}
      savedResult={lesson.savedResult} onSelect={lesson.reference ? null : lesson.select} />
    {lesson.reference && <section className="ss-card" aria-label="Saved access-control lesson request"
      style={{ padding: 12, marginTop: 10 }}>
      <p className="ss-mono">Saved customer request · {lesson.status}</p>
      {lesson.savedText !== null && <p role="status" style={{ whiteSpace: 'pre-wrap' }}>{lesson.savedText}</p>}
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy}
        onClick={() => void lesson.recover()}>Check saved request</button>
      {lesson.status === 'completed' && <button className="ss-btn ss-btn--ghost ss-btn--sm"
        type="button" disabled={lesson.busy} onClick={() => void lesson.readAssessment()}>
        Check saved assessment
      </button>}
      {lesson.assessment?.status === 'unconfirmed' && <>
        <p role="status">Assessment has not been confirmed.</p>
        <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy}
          onClick={() => void lesson.retryAssessment()}>Retry pending assessment</button>
      </>}
      {lesson.assessment?.status === 'ineligible' && <p role="status">This saved request is not eligible for objective credit.</p>}
      {judgment && <p role="status">{judgment.verdict === 'unavailable'
        ? 'Grading unavailable. The saved request remains available.'
        : lesson.assessment.completed === true && judgment.verdict === 'pass'
          ? 'Objective completed.' : 'Assessment recorded without objective credit.'}</p>}
      {judgment?.verdict === 'unavailable' && <button className="ss-btn ss-btn--ghost ss-btn--sm"
        type="button" onClick={() => openStandaloneAssessments(judgment.evaluationId)}>
        {isStandaloneShopFrame() ? 'Open saved assessments' : 'Saved assessment available'}
      </button>}
      {lesson.status === 'completed' && <button className="ss-btn ss-btn--ghost ss-btn--sm"
        type="button" disabled={lesson.busy} onClick={() => void lesson.clearCompleted()}>
        Start another lesson request
      </button>}
    </section>}
  </>;
}

function CustomerProductSearchTask({ userId, token, instance }) {
  const [message, setMessage] = useState('');
  const lesson = useCustomerProductSearchLesson({ shopUserId: userId, authorityKey: token,
    transport: globalThis.fetch });
  const submit = event => {
    event.preventDefault();
    if (message.trim() && lesson.ready && !lesson.busy && !lesson.reference) void lesson.run(message);
  };
  return <section aria-label="Product search lesson">
    <p>Ask the product-search agent to search this owned practice catalog. Search results are read-only observations.</p>
    <form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={submit}>
      <label htmlFor={`product-search-lesson-${instance}`}>Search request</label>
      <textarea id={`product-search-lesson-${instance}`} className="ss-lane__input"
        value={message} onChange={event => setMessage(event.target.value)} maxLength={8192}
        disabled={!lesson.ready || lesson.busy || !!lesson.reference} rows={3} style={FIELD_STYLE} />
      <button className="ss-btn" type="submit" disabled={!lesson.ready || lesson.busy
        || !!lesson.reference || !message.trim()}>{lesson.busy ? 'Working…' : 'Ask product-search agent'}</button>
    </form>
    {lesson.reference && <div className="ss-card" style={{ padding: 12, marginTop: 10 }}>
      <p className="ss-mono">Saved product-search request · {lesson.status}</p>
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy}
        onClick={() => void lesson.recover()}>Check saved search</button>
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy}
        onClick={() => void lesson.recoverAssessment()}>Check saved assessment</button>
      {lesson.status === 'completed' && <button className="ss-btn ss-btn--ghost ss-btn--sm"
        type="button" disabled={lesson.busy} onClick={() => void lesson.startNew()}>Start another search</button>}
    </div>}
    {lesson.result && <div role="log" aria-label="Product-search lesson result" className="ss-card"
      style={{ padding: 12, marginTop: 10 }}>
      <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{lesson.result.text}</p>
      {lesson.result.searches.map((search, index) => <section key={index}>
        <p className="ss-mono">Search observation {index + 1} · {search.count} rows</p>
        <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{search.query}</p>
        {search.results.map((row, rowIndex) => <pre key={rowIndex}
          style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(row)}</pre>)}
      </section>)}
    </div>}
    {lesson.result && (!lesson.assessment || (lesson.assessment.completed === false
      && lesson.assessment.status === 'unconfirmed' && lesson.assessment.modelEvaluated === false))
      && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={lesson.busy} onClick={() => void lesson.assess()}>Assess saved search</button>}
    {lesson.assessment && <p role="status">Assessment: {lesson.assessment.judgment?.verdict
      || lesson.assessment.status}</p>}
    <TaskStatus error={lesson.error} />
  </section>;
}

function CustomerOrderStatusTask({ userId, token, instance }) {
  const [message, setMessage] = useState('');
  const lesson = useCustomerOrderStatusLesson({ shopUserId: userId, authorityKey: token,
    transport: globalThis.fetch });
  const submit = event => {
    event.preventDefault();
    if (message.trim() && lesson.ready && !lesson.busy && !lesson.reference) void lesson.run(message);
  };
  return <section aria-label="Order status lesson">
    <p>Ask the order-status agent about an owned practice order. Lookup results and query errors are read-only observations.</p>
    <form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={submit}>
      <label htmlFor={`order-status-lesson-${instance}`}>Order request</label>
      <textarea id={`order-status-lesson-${instance}`} className="ss-lane__input"
        value={message} onChange={event => setMessage(event.target.value)} maxLength={8192}
        disabled={!lesson.ready || lesson.busy || !!lesson.reference} rows={3} style={FIELD_STYLE} />
      <button className="ss-btn" type="submit" disabled={!lesson.ready || lesson.busy
        || !!lesson.reference || !message.trim()}>{lesson.busy ? 'Working…' : 'Ask order-status agent'}</button>
    </form>
    {lesson.reference && <div className="ss-card" style={{ padding: 12, marginTop: 10 }}>
      <p className="ss-mono">Saved order-status request · {lesson.status}</p>
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy}
        onClick={() => void lesson.recover()}>Check saved request</button>
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={lesson.busy}
        onClick={() => void lesson.recoverAssessment()}>Check saved assessment</button>
      {lesson.status === 'completed' && <button className="ss-btn ss-btn--ghost ss-btn--sm"
        type="button" disabled={lesson.busy} onClick={() => void lesson.startNew()}>Start another request</button>}
    </div>}
    {lesson.result && <div role="log" aria-label="Order-status lesson result" className="ss-card"
      style={{ padding: 12, marginTop: 10 }}>
      <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{lesson.result.text}</p>
      {lesson.result.lookups.map((lookup, index) => <section key={index}>
        <p className="ss-mono">Order lookup {index + 1}</p>
        <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>Requested ID: {String(lookup.order_id)}</p>
        <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{lookup.sql}</pre>
        {lookup.error !== null && <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{lookup.error}</p>}
        {lookup.order !== null && <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
          {JSON.stringify(lookup.order)}
        </pre>}
      </section>)}
    </div>}
    {lesson.result && (!lesson.assessment || (lesson.assessment.completed === false
      && lesson.assessment.status === 'unconfirmed' && lesson.assessment.modelEvaluated === false))
      && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={lesson.busy} onClick={() => void lesson.assess()}>Assess saved request</button>}
    {lesson.assessment && <p role="status">Assessment: {lesson.assessment.judgment?.verdict
      || lesson.assessment.status}</p>}
    <TaskStatus error={lesson.error} />
  </section>;
}

function GeneralHelpTask({ userId, token, instance, composerTarget, scrollContainerRef }) {
  const { reload: reloadCart } = useCart();
  const { refreshProfile } = useAuth();
  const [message, setMessage] = useState('');
  const [ticketDraft, setTicketDraft] = useState({ subject: '', body: '' });
  const ticketRevisionRef = useRef(0);
  const messageRevisionRef = useRef(0);
  const [paymentRefresh, setPaymentRefresh] = useState(null);
  const [addressRefresh, setAddressRefresh] = useState(null);
  const [selectedHop, setSelectedHop] = useState(null);
  const historyEndRef = useRef(null);
  const followLatestRef = useRef(true);
  const paymentRefreshEpoch = useRef(0);
  const addressRefreshEpoch = useRef(0);
  const transport = globalThis.fetch;
  useEffect(() => setSelectedHop(null), [token]);
  const stream = useAgentStream({ role: 'customer', defaultUserId: userId, boundCustomerChat: true,
    authorityKey: token, transport });
  const busy = stream.status === 'thinking' || stream.status === 'recovering';
  const activeHop = stream.turns.at(-1)?.hops?.at(-1);
  const workingLabel = stream.status === 'recovering' ? 'Checking the saved chat…'
    : activeHop?.status === 'in-flight' && activeHop.tool === 'catalog.search' ? 'Searching this shop’s products…'
    : activeHop?.status === 'in-flight' && activeHop.tool === 'cart.view' ? 'Reading your cart…'
    : 'Customer agent is working…';
  const latestTurn = stream.turns.at(-1);
  const latestTurnId = latestTurn?.requestId || null;
  const couponProposal = !busy && !stream.pending && latestTurn?.status === 'done'
    && latestTurn?.stopReason === 'end_turn' && trustedTurnMode(latestTurn.modeCapability)
    ? latestTurn.couponProposal || null : null;
  const coupon = useCustomerCouponConfirmation({ shopUserId: userId, authorityKey: token,
    transport, referenceStore: couponConfirmationStore, sourceSessionId: latestTurn?.sessionId,
    sourceRequestId: latestTurnId, proposal: couponProposal });
  const ticketProposal = !busy && !stream.pending && latestTurn?.status === 'done'
    && latestTurn?.stopReason === 'end_turn' && trustedTurnMode(latestTurn.modeCapability)
    ? latestTurn.ticketProposal || null : null;
  const ticket = useCustomerTicketConfirmation({ shopUserId: userId, authorityKey: token,
    transport, referenceStore: ticketConfirmationStore, sourceSessionId: latestTurn?.sessionId,
    sourceRequestId: latestTurnId, proposal: ticketProposal });
  const searchAssessment = useSearchEchoAssessment({ shopUserId: userId, authorityKey: token,
    transport });
  const selectedSearchSource = selectedHop?.searchSource || null;
  const searchAssessmentSaved = !!selectedSearchSource && !!searchAssessment.reference
    && selectedSearchSource.sessionId === searchAssessment.reference.sessionId
    && selectedSearchSource.requestId === searchAssessment.reference.requestId
    && selectedSearchSource.step === searchAssessment.reference.step;
  const ticketDraftValid = [ticketDraft.subject, ticketDraft.body].every((value, index) =>
    typeof value === 'string' && !!value.trim() && value.isWellFormed() && !value.includes('\0')
    && new TextEncoder().encode(value).byteLength <= (index === 0 ? 256 : 4096));
  const currentOrderPage = !busy && !stream.pending && latestTurn?.status === 'done'
    && latestTurn?.stopReason === 'end_turn' && trustedTurnMode(latestTurn.modeCapability)
    ? latestTurn.orderPage : null;
  const olderOrdersAvailable = !!currentOrderPage?.nextCursor;
  const productDetails = !busy && !stream.pending ? selectedProductDetails(latestTurn) : null;
  const orderDetails = !busy && !stream.pending ? decodeSelectedOrderDetails(latestTurn) : null;
  const paymentSetup = !busy && !stream.pending && latestTurn?.status === 'done'
    && latestTurn?.stopReason === 'end_turn'
    && trustedTurnMode(latestTurn.modeCapability) ? latestTurn.paymentSetup || null : null;
  const addressSetup = !busy && !stream.pending && latestTurn?.status === 'done'
    && latestTurn?.stopReason === 'end_turn'
    && trustedTurnMode(latestTurn.modeCapability) ? latestTurn.addressSetup || null : null;
  const refundSetup = !busy && !stream.pending && latestTurn?.status === 'done'
    && latestTurn?.stopReason === 'end_turn'
    && trustedTurnMode(latestTurn.modeCapability) ? latestTurn.refundSetup || null : null;
  const profileProposal = !busy && !stream.pending && latestTurn?.status === 'done'
    && latestTurn?.stopReason === 'end_turn'
    && trustedTurnMode(latestTurn.modeCapability) ? latestTurn.profileProposal || null : null;
  const currentOperations = !busy && !stream.pending && latestTurn?.status === 'done'
    && latestTurn?.stopReason === 'end_turn'
    && trustedTurnMode(latestTurn.modeCapability) ? (latestTurn.operations || [])
    .filter(operation => ['prepared', 'completed'].includes(operation.status) && operation.proposal) : [];
  const checkoutProposal = currentOperations.find(operation => !operation.proposal.kind)?.proposal || null;
  const cartProposal = currentOperations.find(operation => operation.status === 'prepared'
    && operation.proposal.kind?.startsWith('cart.'))?.proposal || null;
  const cartRejection = !busy && !stream.pending && latestTurn?.status === 'done'
    && latestTurn?.stopReason === 'end_turn' && trustedTurnMode(latestTurn.modeCapability)
    ? (latestTurn.operations || []).find(operation => operation.status === 'completed'
      && operation.rejection?.code === 'INSUFFICIENT_STOCK')?.rejection || null : null;
  const sendMessage = () => {
    if (!message.trim() || busy || stream.pending || stream.completedPagePending) return;
    const submittedRevision = messageRevisionRef.current;
    void stream.send(message).then(sent => {
      if (sent && messageRevisionRef.current === submittedRevision) setMessage('');
    });
  };
  const prepareTicket = () => {
    if (!ticketDraftValid || busy || stream.pending || stream.completedPagePending) return;
    const revision = ticketRevisionRef.current;
    const submitted = JSON.stringify({ subject: ticketDraft.subject, body: ticketDraft.body });
    void stream.send(submitted).then(sent => {
      if (sent && ticketRevisionRef.current === revision) setTicketDraft({ subject: '', body: '' });
    });
  };
  useEffect(() => {
    paymentRefreshEpoch.current += 1;
    addressRefreshEpoch.current += 1;
    setPaymentRefresh(null);
    setAddressRefresh(null);
    return () => { paymentRefreshEpoch.current += 1; addressRefreshEpoch.current += 1; };
  }, [token, transport, latestTurnId]);
  const refreshAddressChoices = async () => {
    const epoch = addressRefreshEpoch.current;
    setAddressRefresh({ status: 'loading' });
    try {
      const response = await transport('/api/secureshop/customer/commerce/addresses',
        { method: 'GET', headers: { accept: 'application/json' } });
      if (!response.ok) throw Error('Current addresses unavailable');
      const current = decodeAddressCards(await response.json());
      if (addressRefreshEpoch.current === epoch) setAddressRefresh({ status: 'ready', cards: current.cards });
    } catch {
      if (addressRefreshEpoch.current === epoch) setAddressRefresh({ status: 'error' });
    }
  };
  const refreshPaymentChoices = async () => {
    const epoch = paymentRefreshEpoch.current;
    setPaymentRefresh({ status: 'loading' });
    try {
      const response = await transport('/api/secureshop/customer/commerce/payment-methods',
        { method: 'GET', headers: { accept: 'application/json' } });
      if (!response.ok) throw Error('Current practice payment choices are unavailable');
      const current = decodePracticePaymentMethods(await response.json());
      if (paymentRefreshEpoch.current === epoch) setPaymentRefresh({ status: 'ready', cards: current.cards });
    } catch {
      if (paymentRefreshEpoch.current === epoch) setPaymentRefresh({ status: 'error' });
    }
  };
  useEffect(() => {
    const body = scrollContainerRef?.current;
    if (!composerTarget || !body) return undefined;
    followLatestRef.current = true;
    const trackScroll = () => {
      followLatestRef.current = body.scrollHeight - body.clientHeight - body.scrollTop <= 80;
    };
    body.addEventListener('scroll', trackScroll, { passive: true });
    return () => body.removeEventListener('scroll', trackScroll);
  }, [composerTarget, scrollContainerRef]);
  useLayoutEffect(() => {
    const body = scrollContainerRef?.current;
    if (composerTarget && body && historyEndRef.current && followLatestRef.current) {
      body.scrollTop = body.scrollHeight;
    }
  }, [composerTarget, scrollContainerRef, stream.turns, stream.pending, stream.status,
    addressRefresh, paymentRefresh, profileProposal]);
  return <>
    <p>Ask about products, your cart or orders, delivery addresses, checkout, and synthetic practice payments. Agent actions and their results appear below.</p>
    <div role="log" aria-label="Customer conversation" aria-live="polite" aria-relevant="additions text">
      {stream.turns.length === 0 && <p className="ss-mono" style={{ fontSize: 12, opacity: 0.7 }}>
        Your customer conversation will appear here.
      </p>}
      {stream.turns.map((turn, index) => trustedTurnMode(turn.modeCapability)
        ? <React.Fragment key={turn.requestId || index}>
            <Turn turn={turn} role="customer" onOpenHop={hop => setSelectedHop({ ...hop,
              modeCapability: hop.modeCapability ?? turn.modeCapability,
              searchSource: hop.tool === 'catalog.search' && ['ok', 'done'].includes(hop.status)
                && !hop.error && turn.status === 'done' && turn.stopReason === 'end_turn'
                && trustedTurnMode(turn.modeCapability)?.featureId === 'customer_chat'
                && Number.isInteger(hop.step) && hop.step >= 1 && hop.step <= 4
                ? { sessionId: turn.sessionId, requestId: turn.requestId, step: hop.step } : null,
            })} compactHops />
            {turn.agencyRole && <div aria-label="Teaching role assessment">
              <p role="status">{turn.agencyAssessment?.completed === true
                && turn.agencyAssessment?.judgment?.verdict === 'pass'
                ? 'Teaching role objective completed in canonical progress.'
                : turn.agencyAssessment?.judgment
                  ? `Teaching role assessment: ${turn.agencyAssessment.judgment.verdict}. No objective completion confirmed.`
                  : turn.agencyAssessment?.status === 'ineligible'
                    ? 'This teaching role action is not eligible for objective completion.'
                    : turn.agencyAssessment?.status === 'unavailable'
                      ? 'Saved role assessment unavailable. No objective completion confirmed.'
                      : turn.agencyAssessment?.status === 'checking'
                        ? 'Checking saved role assessment…'
                        : 'Role assessment pending. No objective completion confirmed.'}</p>
              <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
                disabled={busy || !!stream.pending || stream.completedPagePending}
                onClick={() => void stream.refreshAgencyAssessment(turn.sessionId, turn.requestId)}>
                Check saved role assessment
              </button>
              {turn.agencyAssessment?.judgment?.canRetry && <button className="ss-btn ss-btn--ghost ss-btn--sm"
                type="button" onClick={() => openStandaloneAssessments(turn.agencyAssessment.judgment.evaluationId)}>
                Open saved assessments
              </button>}
            </div>}
            <CustomerChoiceCards cards={turn.cards}
              disabled={busy || !!stream.pending || turn.status !== 'done' || turn.stopReason !== 'end_turn'
                || index !== stream.turns.length - 1}
              onChoose={choiceId => void stream.send('Use my selected option.', { choiceId })}
              onProductAction={selection => void stream.send(selection.intent === 'details'
                ? 'Show this product’s details.'
                : `Add ${selection.quantity} of this product to my cart.`, selection)}
              onCartAction={selection => void stream.send(selection.intent === 'cart_update'
                ? `Update this cart item to ${selection.quantity}.`
                : 'Remove this item from my cart.', selection)}
              onOrderAction={selection => void stream.send('Show this order’s details.', selection)}
              onAddressAction={selection => void stream.send(selection.intent === 'address_checkout'
                ? 'Use this address for checkout.' : 'Prepare to edit this address.', selection)} />
            {index === stream.turns.length - 1 && turn.status === 'done'
              && turn.stopReason === 'end_turn' && turn.catalogPage?.hasMore === true
              && !stream.pending && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
                aria-label="Next customer products" disabled={busy}
                onClick={() => void stream.send('Show more products', null,
                  { intent: 'catalog_next', sourceRequestId: turn.requestId })}>Next products</button>}
            {index === stream.turns.length - 1 && (olderOrdersAvailable || currentOrderPage?.productName)
              && <div>
              {currentOrderPage.productName && <p className="ss-mono" style={{ fontSize: 12,
                overflowWrap: 'anywhere' }}>Orders containing {currentOrderPage.productName}</p>}
              {olderOrdersAvailable && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
                onClick={() => void stream.send('Show older orders')}>Older orders</button>}
            </div>}
            {turn.status === 'unresolved' && turn.operations?.length > 0 &&
              <p role="status">A saved customer action exists. Its chat result is not confirmed, so no action can be repeated or confirmed yet.</p>}
          </React.Fragment>
        : <article className="ss-turn" key={turn.requestId || index} data-testid="agent-turn">
            <div className="ss-turn__you">YOU</div><div className="ss-turn__msg">{turn.user}</div>
            <div className="ss-turn__supervisor">CUSTOMER-SUPERVISOR · {turn.status}</div>
            {turn.operations?.length > 0 && <p role="status">A saved action exists. Check this chat’s exact result before continuing.</p>}
          </article>)}
    {productDetails && <section aria-label="Selected product details" className="ss-card" style={{ padding: 14, marginTop: 12 }}>
      <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>SELECTED PRODUCT</div>
      <h3 style={{ margin: '6px 0' }}>{productDetails.name}</h3>
      <p style={{ margin: '6px 0', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{productDetails.description}</p>
      <div className="ss-mono" style={{ fontSize: 12 }}>Price: {productDetails.price} · Stock: {productDetails.stock}</div>
    </section>}
    {orderDetails && <section aria-label="Selected order details" className="ss-card"
      style={{ padding: 14, marginTop: 12, overflowWrap: 'anywhere' }}>
      <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>YOUR ORDER</div>
      <h3 style={{ margin: '6px 0' }}>Order #{orderDetails.orderNumber}</h3>
      <p style={{ margin: '6px 0' }}>Placed {orderDetails.date} · {orderDetails.status}</p>
      <p style={{ margin: '6px 0' }}>Payment: {orderDetails.paymentStatus} · Total: {orderDetails.total}</p>
      <h4 style={{ margin: '12px 0 4px' }}>Items</h4>
      <ul style={{ margin: '4px 0 12px', paddingLeft: 20 }}>
        {orderDetails.items.map((item, index) => <li key={index}>
          {item.name} · {item.quantity} × {item.unitPrice} each
        </li>)}
      </ul>
      <h4 style={{ margin: '8px 0 4px' }}>Shipping address</h4>
      <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{orderDetails.shippingAddress}</p>
    </section>}
    {busy && <p role="status">{workingLabel}</p>}
    {stream.canStopWatching && <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      onClick={() => stream.stopWatching()}>Stop watching response</button>}
    {stream.pending && <>
      <p role="status">This chat may have completed. Check its saved result before sending another message.</p>
      <button className="ss-btn ss-btn--ghost" type="button" disabled={busy}
        onClick={() => void stream.recover()}>Check saved chat</button>
    </>}
    {!stream.pending && stream.completedPagePending && <>
      <p role="status">Checking your last saved chat page before continuing.</p>
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy}
        onClick={() => void stream.recover()}>Check saved chat page</button>
    </>}
    {composerTarget && createPortal(<form className="ss-lane__composer ss-lane__composer--stacked"
      onSubmit={event => { event.preventDefault(); sendMessage(); }}>
      <label htmlFor={`lane-general-help-${instance}`}>Message</label>
      <textarea id={`lane-general-help-${instance}`} className="ss-lane__input" value={message}
        onChange={event => { messageRevisionRef.current += 1; setMessage(event.target.value); }} maxLength={8192} style={FIELD_STYLE}
        onKeyDown={event => {
          if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
            event.preventDefault(); sendMessage();
          }
        }}
        rows={3} placeholder="Find a laptop for coding" required />
      <span className="ss-mono" style={{ fontSize: 11, opacity: 0.7 }}>Enter to send · Shift+Enter for a new line</span>
      <button className="ss-btn" type="submit" disabled={!message.trim() || busy || !!stream.pending
        || !!stream.completedPagePending}>
        {busy ? 'Working…' : 'Send to customer agent'}
      </button>
    </form>, composerTarget)}
    <TaskStatus error={stream.error} />
    {searchAssessment.reference && <section className="ss-card" aria-label="Saved search echo assessment"
      style={{ padding: 14, marginTop: 12 }}>
      <strong>Search echo assessment · step {searchAssessment.reference.step}</strong>
      {searchAssessment.outcome?.judgment && <p role="status">
        Saved assessment: {searchAssessment.outcome.judgment.verdict}</p>}
      {searchAssessment.outcome?.status && <p role="status">
        Saved assessment: {searchAssessment.outcome.status}</p>}
      {searchAssessment.error && <p role="alert">{searchAssessment.error}</p>}
      <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
        disabled={searchAssessment.busy || searchAssessment.accessLost}
        onClick={() => void searchAssessment.check()}>Check saved search echo assessment</button>
      {searchAssessment.outcome?.status === 'unconfirmed' && <button type="button"
        className="ss-btn ss-btn--ghost ss-btn--sm"
        disabled={searchAssessment.busy || searchAssessment.accessLost}
        onClick={() => void searchAssessment.retryUnconfirmed()}>Retry search assessment</button>}
      {selectedSearchSource && !searchAssessmentSaved
        && searchAssessment.outcome && searchAssessment.outcome.status !== 'unconfirmed'
        && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
          disabled={searchAssessment.busy || searchAssessment.accessLost}
          onClick={() => void searchAssessment.clearCompleted(selectedSearchSource)}>
          Start another search assessment</button>}
    </section>}
    <section className="ss-card" aria-label="Prepare support ticket"
      style={{ padding: 14, marginTop: 12, display: 'grid', gap: 8 }}>
      <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)' }}>SUPPORT TICKET</div>
      <p style={{ margin: 0 }}>Describe the issue. The agent prepares a proposal; you review it before opening a ticket.</p>
      <label htmlFor={`lane-ticket-subject-${instance}`}>Subject</label>
      <input id={`lane-ticket-subject-${instance}`} className="ss-lane__input"
        value={ticketDraft.subject} maxLength={256} required style={FIELD_STYLE}
        onChange={event => { ticketRevisionRef.current += 1;
          setTicketDraft(previous => ({ ...previous, subject: event.target.value })); }} />
      <label htmlFor={`lane-ticket-body-${instance}`}>Details</label>
      <textarea id={`lane-ticket-body-${instance}`} className="ss-lane__input"
        value={ticketDraft.body} maxLength={4096} required rows={4} style={FIELD_STYLE}
        onChange={event => { ticketRevisionRef.current += 1;
          setTicketDraft(previous => ({ ...previous, body: event.target.value })); }} />
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" onClick={prepareTicket}
        disabled={!ticketDraftValid || busy || !!stream.pending || !!stream.completedPagePending}>
        Prepare support ticket
      </button>
    </section>
    <CustomerCartConfirmation proposal={cartProposal} authorityKey={token}
      onCartApplied={reloadCart} transport={globalThis.fetch} />
    <CustomerCouponProposalCard proposal={coupon.reference
      && (coupon.reference.sessionId !== latestTurn?.sessionId
        || coupon.reference.requestId !== latestTurnId
        || coupon.reference.proposalId !== couponProposal?.proposalId) ? null : couponProposal}
      nextProposalAvailable={!!coupon.reference && !!couponProposal
        && (coupon.reference.sessionId !== latestTurn?.sessionId
          || coupon.reference.requestId !== latestTurnId
          || coupon.reference.proposalId !== couponProposal.proposalId)}
      reference={coupon.reference} status={coupon.status} result={coupon.result}
      assessment={coupon.assessment}
      busy={coupon.busy || busy || !!stream.pending || !!stream.completedPagePending}
      error={coupon.error} onConfirm={() => void coupon.confirm()}
      onCheck={() => void coupon.check()} onClear={() => void coupon.clearCompleted()}
      onReadAssessment={() => void coupon.readAssessment()}
      onRetryAssessment={() => void coupon.retryAssessment()} />
    <CustomerTicketConfirmationCard proposal={ticket.reference
      && (ticket.reference.sessionId !== latestTurn?.sessionId
        || ticket.reference.requestId !== latestTurnId
        || ticket.reference.proposalId !== ticketProposal?.proposalId) ? null : ticketProposal}
      nextProposalAvailable={!!ticket.reference && !!ticketProposal
        && (ticket.reference.sessionId !== latestTurn?.sessionId
          || ticket.reference.requestId !== latestTurnId
          || ticket.reference.proposalId !== ticketProposal.proposalId)}
      reference={ticket.reference} status={ticket.status} result={ticket.result}
      busy={ticket.busy || busy || !!stream.pending || !!stream.completedPagePending}
      error={ticket.error} onConfirm={() => void ticket.confirm()}
      onCheck={() => void ticket.check()} onClear={() => void ticket.clearCompleted()} />
    {cartRejection && <section className="ss-card" aria-label="Customer cart rejection" role="status"
      style={{ padding: 14, marginTop: 12 }}>
      <strong>Not added to cart</strong>
      <p>Requested quantity {cartRejection.quantity} is unavailable. Your cart was not changed.</p>
    </section>}
    <CustomerCheckoutCard proposal={checkoutProposal} authorityKey={token} transport={globalThis.fetch}
      onChooseAnotherPayment={!busy && !stream.pending && !stream.completedPagePending
        && latestTurn?.status === 'done' && latestTurn?.stopReason === 'end_turn' && checkoutProposal
        ? () => void stream.send('Show my current payment methods so I can choose another one.') : null} />
    <PracticePaymentSetup key={latestTurnId || 'no-turn'} setup={paymentSetup} entryPoint="chat"
      authorityKey={JSON.stringify([token, latestTurnId])} transport={transport}
      onConfirmed={refreshPaymentChoices} />
    <PracticeAddressSetup key={`address-${latestTurnId || 'no-turn'}`} setup={addressSetup} entryPoint="chat"
      interactionBlocked={busy || !!stream.pending || !!stream.completedPagePending}
      authorityKey={JSON.stringify([token, latestTurnId])} transport={transport}
      onConfirmed={refreshAddressChoices} />
    <PracticeProfileUpdate proposal={profileProposal} entryPoint="chat"
      sourceSessionId={latestTurn?.sessionId} sourceRequestId={latestTurn?.requestId}
      authorityKey={JSON.stringify([token, latestTurnId])} transport={transport}
      onConfirmed={refreshProfile} />
    {refundSetup && <section className="ss-card" aria-label="Refund review handoff"
      style={{ padding: 14, marginTop: 12 }}>
      <p>Review your selected order and enter a reason before sending a refund request.</p>
      <Link className="ss-btn" to="/secureshop/orders" state={{ refundSetup }}
        onClick={event => {
          const current = stream.turns.at(-1);
          if (busy || stream.pending || current?.requestId !== latestTurnId
            || current?.status !== 'done' || current?.stopReason !== 'end_turn'
            || current?.refundSetup?.choiceId !== refundSetup.choiceId) event.preventDefault();
        }}>
        Review refund request in Orders
      </Link>
    </section>}
    {addressRefresh && <section aria-label="Current delivery addresses">
      {addressRefresh.status === 'loading' && <p role="status">Refreshing delivery addresses…</p>}
      {addressRefresh.status === 'error' && <p role="status">The address was saved, but current addresses could not be refreshed. Ask the agent to show them again.</p>}
      {addressRefresh.status === 'ready' && <><p role="status">Address saved. Current named addresses:</p>
        <ul>{addressRefresh.cards.map(card => <li key={card.choiceId}>{card.title} — {card.detail}</li>)}</ul></>}
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy || !!stream.pending}
        onClick={() => void stream.send('Show my delivery addresses')}>Show addresses in chat</button>
    </section>}
    {paymentRefresh && <section aria-label="Current practice payment choices">
      {paymentRefresh.status === 'loading' && <p role="status">Refreshing practice payment choices…</p>}
      {paymentRefresh.status === 'error' && <p role="status">The payment was saved, but current choices could not be refreshed. Ask the agent to show them again.</p>}
      {paymentRefresh.status === 'ready' && <>
        <p role="status">Practice payment saved. Current named choices:</p>
        <ul>{paymentRefresh.cards.map(card => <li key={card.choiceId}>{card.title} — {card.detail}</li>)}</ul>
      </>}
      <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={busy || !!stream.pending}
        onClick={() => void stream.send('Show my payment methods')}>Use payment in chat</button>
    </section>}
      <div ref={historyEndRef} data-testid="customer-chat-end" />
    </div>
    <HopDetailSheet hop={selectedHop} onClose={() => setSelectedHop(null)}
      searchAssessment={selectedSearchSource ? {
        busy: searchAssessment.busy || searchAssessment.accessLost, saved: searchAssessmentSaved,
        blocked: !!searchAssessment.reference && !searchAssessmentSaved,
        onCheck: () => void (searchAssessmentSaved
          ? searchAssessment.check() : searchAssessment.start(selectedSearchSource)),
      } : null} />
  </>;
}

function AnalyticsTask({ token, instance }) {
  const recovery = useBoundAnalytics({ bound: true, token, transport: globalThis.fetch });
  const [question, setQuestion] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const submit = async event => {
    event.preventDefault();
    if (!question.trim() || busy || !recovery.ready || recovery.references.some(row => row.scopeKey === recovery.scopeKey)) return;
    setBusy(true); setError(null); setResult(null);
    try { setResult(await recovery.submit(question)); }
    catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  return <>
    <p>Ask a bounded merchant analytics question. The full table and chart remain on Analytics.</p>
    <form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={submit}>
      <label htmlFor={`lane-analytics-question-${instance}`}>Analytics question</label>
      <input id={`lane-analytics-question-${instance}`} className="ss-lane__input" value={question}
        onChange={event => setQuestion(event.target.value)} maxLength={8192} style={FIELD_STYLE}
        placeholder="Top products by revenue" required />
      <button className="ss-btn" type="submit" disabled={!question.trim() || busy || !recovery.ready || recovery.references.some(row => row.scopeKey === recovery.scopeKey)}>
        {busy ? 'Querying…' : 'Run analytics'}
      </button>
    </form>
    {result?.status === 'completed' && <div role="status" style={{ whiteSpace: 'pre-wrap' }}>
      <Policy capability={result.modeCapability} />{result.answer}
    </div>}
    {result?.status === 'denied' && <TaskStatus status={result.error || 'Database permission denied.'} />}
    {recovery.recovered?.status === 'completed' && <div role="status" style={{ whiteSpace: 'pre-wrap' }}>
      <Policy capability={recovery.recovered.modeCapability} />{recovery.recovered.answer}
    </div>}
    {recovery.references.filter(row => row.scopeKey === recovery.scopeKey).map(row =>
      <button className="ss-btn ss-btn--ghost" key={row.operationId} type="button" disabled={busy}
        onClick={() => void recovery.check(row)}>Check saved query</button>)}
    <TaskStatus error={error} status={recovery.notice} />
    <Link to="/secureshop/merchant/analytics">Open analytics table</Link>
  </>;
}

function PricingTask({ token, instance }) {
  const pricing = useBoundPricing(token, globalThis.fetch);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [message, setMessage] = useState('');
  const valid = validResourceId(selectedProduct?.id);
  const submit = event => {
    event.preventDefault();
    if (valid && message.trim() && !pricing.locked) void pricing.run('suggest', Number(selectedProduct.id), message);
  };
  return <>
    <p>Choose one of your products and ask for a pricing suggestion. Saved operations must be checked before another request.</p>
    <BoundProductPicker instance={`pricing-${instance}`} source="merchant" selectedProduct={selectedProduct}
      onSelect={setSelectedProduct} authorityKey={token} disabled={pricing.locked} transport={globalThis.fetch} />
    <form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={submit}>
      <label htmlFor={`lane-pricing-message-${instance}`}>Pricing question</label>
      <input id={`lane-pricing-message-${instance}`} className="ss-lane__input" value={message}
        onChange={event => setMessage(event.target.value)} maxLength={8192} style={FIELD_STYLE}
        placeholder="Suggest a price for this product" required />
      <button className="ss-btn" type="submit" disabled={!valid || !message.trim() || pricing.locked}>Run pricing</button>
    </form>
    {pricing.result?.state === 'completed' && <p role="status" style={{ whiteSpace: 'pre-wrap' }}>
      <Policy capability={pricing.result.modeCapability} />{pricing.result.response}
    </p>}
    {pricing.references.map(row => <button className="ss-btn ss-btn--ghost" key={row.operationId} type="button"
      disabled={pricing.busy} onClick={() => void pricing.recover(row)}>Check saved pricing operation</button>)}
    <TaskStatus status={pricing.notice} />
    <Link to="/secureshop/merchant/pricing">Open pricing details</Link>
  </>;
}

function ListingTask({ token, instance }) {
  const listings = useBoundListings(token, globalThis.fetch);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const source = { title, description };
  const act = async work => {
    setBusy(true); setError(null);
    try { setResult(await work()); } catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  return <>
    <p>Rewrite a listing draft. Review and save the result on Listings; generating text does not publish it.</p>
    <form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={event => { event.preventDefault(); if (title.trim() && listings.ready && !listings.busy) void act(() => listings.run('rewrite', source)); }}>
      <label htmlFor={`lane-listing-title-${instance}`}>Listing title</label>
      <input id={`lane-listing-title-${instance}`} className="ss-lane__input" value={title} onChange={event => { setTitle(event.target.value); setResult(null); }}
        maxLength={1024} style={FIELD_STYLE} required />
      <label htmlFor={`lane-listing-description-${instance}`}>Source description</label>
      <textarea id={`lane-listing-description-${instance}`} className="ss-lane__input" value={description}
        onChange={event => { setDescription(event.target.value); setResult(null); }} rows={3} maxLength={32768} style={FIELD_STYLE} />
      <button className="ss-btn" type="submit" disabled={!title.trim() || !listings.ready || listings.busy || busy}>Rewrite draft</button>
    </form>
    {result?.state === 'completed' && <div role="status">
      <Policy capability={result.modeCapability} />
      <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{result.html}</pre>
    </div>}
    {result && result.state !== 'completed' && <TaskStatus status={`Rewrite ${result.state}. Check the saved operation.`} />}
    {listings.references.rewrite && <button className="ss-btn ss-btn--ghost" type="button" disabled={listings.busy || busy}
      onClick={() => void act(() => listings.recover('rewrite', source))}>Check saved rewrite</button>}
    <TaskStatus error={error} />
    <Link to="/secureshop/merchant/listings">Open listings to review and save</Link>
  </>;
}

export default function BoundAgentLane({ role, productId, instance = 'default' }) {
  const { user, token } = useAuth();
  const tasks = role === 'merchant' ? MERCHANT_TASKS : CUSTOMER_TASKS;
  const [task, setTask] = useState(tasks[0][0]);
  const [chatComposerSlot, setChatComposerSlot] = useState(null);
  const [roleComposerSlot, setRoleComposerSlot] = useState(null);
  const bodyRef = useRef(null);
  useEffect(() => { setTask(role === 'merchant' ? 'inventory' : 'product'); }, [role, token]);
  useEffect(() => { if (bodyRef.current) bodyRef.current.scrollTop = 0; }, [task]);
  return <aside className="ss-lane" data-testid="agent-lane" aria-label="Agent activity lane">
    <div className="ss-lane__header">
      <div><div className="ss-lane__title">Agent lane</div>
        <div className="ss-mono" style={{ marginTop: 4, opacity: 0.7 }}>{role} · choose a task</div></div>
      <span className="ss-dot ss-dot--kelp" aria-label="task available" />
    </div>
    <div className="ss-lane__body" ref={bodyRef}>
      <label htmlFor={`agent-lane-task-${role}-${instance}`}>Task</label>
      <select id={`agent-lane-task-${role}-${instance}`} value={task} onChange={event => setTask(event.target.value)}
        className="ss-lane__input" style={{ ...FIELD_STYLE, marginBottom: 14 }}>
        {tasks.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select>
      {role === 'customer' && task === 'product' && <ProductQuestionTask productId={productId} token={token} instance={instance}
        ownerKey={`${user?.id || ''}:${user?.role || ''}:${token || ''}`} />}
      {role === 'customer' && <div hidden={task !== 'chat'}>
        <GeneralHelpTask userId={user?.id} token={token} instance={instance}
          composerTarget={task === 'chat' ? chatComposerSlot : null} scrollContainerRef={bodyRef} />
      </div>}
      {role === 'customer' && task === 'refund' && <RefundTask userId={user?.id} token={token} instance={instance} />}
      {role === 'customer' && task === 'idor' && <CustomerIdorTask userId={user?.id} token={token} />}
      {role === 'customer' && task === 'product-search-lesson' && <CustomerProductSearchTask
        userId={user?.id} token={token} instance={instance} />}
      {role === 'customer' && task === 'order-status-lesson' && <CustomerOrderStatusTask
        userId={user?.id} token={token} instance={instance} />}
      {role === 'customer' && task === 'checkout-audit-lesson' && <CustomerCheckoutAuditLesson
        shopUserId={user?.id} authorityKey={token} transport={globalThis.fetch} />}
      {role === 'customer' && task === 'avatar-upload-lesson' && <CustomerAvatarUploadLesson
        shopUserId={user?.id} authorityKey={token} transport={globalThis.fetch} />}
      {role === 'customer' && task === 'avatar-traversal-lesson' && <CustomerAvatarTraversalLesson
        shopUserId={user?.id} authorityKey={token} transport={globalThis.fetch} />}
      {role === 'customer' && task === 'file-summary-lesson' && <CustomerFileSummaryLesson
        shopUserId={user?.id} authorityKey={token} transport={globalThis.fetch} />}
      {role === 'customer' && task === 'file-path-summary-lesson' && <CustomerFilePathSummaryLesson
        shopUserId={user?.id} authorityKey={token} transport={globalThis.fetch} />}
      {role === 'merchant' && task === 'inventory' && <InventoryPanel token={token} transport={globalThis.fetch} />}
      {role === 'merchant' && task === 'assistant' && <BoundRoleAssistant role="merchant" shopUserId={user?.id}
        authorityKey={token} instance={instance} transport={globalThis.fetch}
        composerTarget={roleComposerSlot} scrollContainerRef={bodyRef} />}
      {role === 'merchant' && task === 'analytics' && <AnalyticsTask token={token} instance={instance} />}
      {role === 'merchant' && task === 'pricing' && <PricingTask token={token} instance={instance} />}
      {role === 'merchant' && task === 'listing' && <ListingTask token={token} instance={instance} />}
      {role === 'merchant' && task === 'reviews' && <>
        <p>Choose a pending review card on the Reviews page, then approve it or enter a reason to reject it.</p>
        <Link to="/secureshop/merchant/reviews">Open review moderation</Link>
      </>}
    </div>
    {role === 'customer' && task === 'chat' &&
      <div ref={setChatComposerSlot} data-testid="customer-chat-composer-slot" style={{ flexShrink: 0 }} />}
    {role === 'merchant' && task === 'assistant' &&
      <div ref={setRoleComposerSlot} data-testid="merchant-assistant-composer-slot" style={{ flexShrink: 0 }} />}
  </aside>;
}
