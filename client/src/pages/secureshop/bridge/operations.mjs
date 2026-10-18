/**
 * Closed request registry for the future SecureShop opaque-frame bridge.
 *
 * This module is deliberately transport-free. It accepts only named operations
 * and JSON input, and never accepts URLs, headers, credentials, or platform
 * ownership data. The parent transport supplies the shop bearer separately and
 * binds trusted launch authority outside this compiler.
 */
import { validateCompetitorUrl } from '../pages/merchant/pricingOperation.mjs';

const MAX_JSON_BYTES = 128 * 1024;
const MAX_JSON_DEPTH = 24;
const MAX_JSON_NODES = 4096;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const ANY = Symbol('any-json-value');

function body(...keys) { return Object.freeze({ keys: Object.freeze(keys), emitEmpty: false }); }
function emptyBody() { return Object.freeze({ keys: Object.freeze([]), emitEmpty: true }); }
function shape(fields) { return Object.freeze({ fields: Object.freeze({ ...fields }) }); }

function operation(path, method = 'GET', options = {}) {
  return Object.freeze({
    path,
    method,
    params: Object.freeze(options.params || []),
    query: Object.freeze(options.query || []),
    body: options.body || null,
    requiredBody: options.requiredBody === true,
    responseKind: options.responseKind || 'json',
  });
}

const ADDRESS_FIELDS = ['label', 'line1', 'line2', 'city', 'state', 'zip', 'phone', 'is_default'];
const PRODUCT_PATCH = shape({
  name: ANY,
  description: ANY,
  price: ANY,
  category: ANY,
  template_source: ANY,
  image_url: ANY,
});
const LISTINGS_CHAT_SOURCE = shape({ sessionId: ANY, requestId: ANY, proposalId: ANY });
const listingsBody = (...keys) => Object.freeze({ keys: Object.freeze([...keys, 'chatSource']), nested: Object.freeze({ chatSource: LISTINGS_CHAT_SOURCE }), emitEmpty: false });
const CUSTOMER_CHAT_BODY = Object.freeze({
  keys: Object.freeze(['sessionId', 'message', 'requestId', 'selection', 'catalogContinuation']),
  emitEmpty: false,
  nested: Object.freeze({ selection: shape({ choiceId: ANY, intent: ANY, quantity: ANY }),
    catalogContinuation: shape({ intent: ANY, sourceRequestId: ANY }) }),
});
const CUSTOMER_IDOR_CHAT_BODY = Object.freeze({
  keys: Object.freeze(['sessionId', 'requestId', 'message', 'selection']),
  nested: Object.freeze({ selection: shape({ action: ANY, numericId: ANY }) }),
  emitEmpty: false,
});
const ROLE_ASSISTANT_CHAT_BODY = Object.freeze({
  keys: Object.freeze(['sessionId', 'requestId', 'message', 'selection', 'orderContinuation', 'mailContinuation', 'catalogContinuation']),
  emitEmpty: false,
  nested: Object.freeze({ selection: ANY,
    orderContinuation: shape({ intent: ANY, sourceRequestId: ANY }),
    mailContinuation: shape({ intent: ANY, sourceRequestId: ANY }),
    catalogContinuation: shape({ intent: ANY, sourceRequestId: ANY }) }),
});

const OPERATIONS = Object.freeze({
  'auth.login': operation('/api/secureshop/v2/auth/login', 'POST', { body: body('username', 'password') }),
  'auth.register': operation('/api/secureshop/v2/auth/register', 'POST', { body: body('username', 'email', 'password', 'role', 'full_name') }),
  'auth.whoami': operation('/api/secureshop/v2/auth/whoami'),
  'auth.logout': operation('/api/secureshop/v2/auth/logout', 'POST'),

  'lab.policyHtml.readiness': operation('/api/secureshop/v2/controlled-ssrf/html/readiness'),
  'lab.policyHtml.run': operation('/api/secureshop/v2/controlled-ssrf/html/run', 'POST', { body: body('request_id', 'policy_html'), requiredBody: true }),
  'lab.policyHtml.request': operation('/api/secureshop/v2/controlled-ssrf/html/run/:requestId', 'GET', { params: ['requestId'] }),
  'lab.policyHtml.assess': operation('/api/secureshop/v2/controlled-ssrf/html/assess', 'POST', { body: body('session_id', 'request_id'), requiredBody: true }),
  'lab.policyHtml.assessment': operation('/api/secureshop/v2/controlled-ssrf/html/assessment/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'lab.ssrf.readiness': operation('/api/secureshop/v2/controlled-ssrf/readiness'),
  'lab.ssrf.run': operation('/api/secureshop/v2/controlled-ssrf/run', 'POST', { body: body('resource', 'request_id') }),
  'lab.personaInbox.readiness': operation('/api/secureshop/v2/persona-inbox/readiness'),
  'lab.personaInbox.read': operation('/api/secureshop/v2/persona-inbox/read', 'POST', { body: body('message_id', 'request_id') }),
  'lab.personaInbox.enforce': operation('/api/secureshop/v2/persona-inbox/enforce', 'POST', { body: emptyBody() }),
  'lab.mcpTrust.readiness': operation('/api/secureshop/v2/mcp-trust/readiness'),
  'lab.mcpTrust.discover': operation('/api/secureshop/v2/mcp-trust/discover', 'POST', { body: body('scenario') }),
  'lab.mcpTrust.rotate': operation('/api/secureshop/v2/mcp-trust/rotate', 'POST', { body: emptyBody() }),
  'lab.mcpTrust.run': operation('/api/secureshop/v2/mcp-trust/run', 'POST', { body: body('scenario', 'request_id') }),

  'account.profile.update': operation('/api/secureshop/v2/auth/users/me', 'PUT', { body: body('full_name', 'email', 'phone') }),
  'account.password.change': operation('/api/secureshop/v2/auth/users/me/password', 'POST', { body: body('current_password', 'new_password') }),
  'account.addresses.list': operation('/api/secureshop/v2/auth/users/me/addresses'),
  'account.addresses.create': operation('/api/secureshop/v2/auth/users/me/addresses', 'POST', { body: body(...ADDRESS_FIELDS) }),
  'account.addresses.update': operation('/api/secureshop/v2/auth/users/me/addresses/:id', 'PUT', { params: ['id'], body: body(...ADDRESS_FIELDS) }),
  'account.addresses.delete': operation('/api/secureshop/v2/auth/users/me/addresses/:id', 'DELETE', { params: ['id'] }),
  'account.apiKeys.get': operation('/api/secureshop/v2/auth/users/me/api-keys'),
  'account.apiKeys.rotate': operation('/api/secureshop/v2/auth/users/me/api-keys/rotate', 'POST'),
  'account.sessions.list': operation('/api/secureshop/v2/auth/users/me/sessions'),
  'account.sessions.revoke': operation('/api/secureshop/v2/auth/users/me/sessions/:id/revoke', 'POST', { params: ['id'] }),

  'catalog.list': operation('/api/secureshop/products', 'GET', { query: ['search', 'category', 'sort', 'page', 'limit', 'offset', 'minRating', 'maxPrice'] }),
  'catalog.categories': operation('/api/secureshop/categories'),
  'catalog.recommended': operation('/api/secureshop/recommended', 'GET', { query: ['user_id'] }),
  'catalog.product.get': operation('/api/secureshop/products/:id', 'GET', { params: ['id'] }),
  'catalog.product.summary': operation('/api/secureshop/products/:id/summary', 'POST',
    { params: ['id'], body: body('sessionId', 'requestId'), requiredBody: true }),
  'catalog.product.summarySession': operation('/api/secureshop/products/:id/summary/session', 'POST',
    { params: ['id'], body: emptyBody(), requiredBody: true }),
  'catalog.product.summarySaved': operation('/api/secureshop/products/:id/summary/sessions/:sessionId/requests/:requestId', 'GET',
    { params: ['id', 'sessionId', 'requestId'] }),
  'agent.customer.productSummary.assess': operation('/api/secureshop/agents/customer/product-summary/assess', 'POST',
    { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.productSummary.assessment': operation('/api/secureshop/agents/customer/sessions/:sessionId/requests/:requestId/product-summary/assessment', 'GET',
    { params: ['sessionId', 'requestId'] }),
  'catalog.product.question': operation('/api/secureshop/products/:id/question', 'POST', { params: ['id'], body: body('message', 'sessionId', 'requestId') }),
  'catalog.product.reviews.list': operation('/api/secureshop/products/:id/reviews', 'GET', { params: ['id'], query: ['limit', 'offset'] }),
  'catalog.product.reviews.create': operation('/api/secureshop/products/:id/reviews', 'POST', { params: ['id'], body: body('submission_id', 'author_id', 'body', 'rating') }),
  'catalog.product.reviews.browserAttempt': operation('/api/secureshop/products/:productId/reviews/:reviewId/browser-attempt', 'POST', { params: ['productId', 'reviewId'], body: body('request_id') }),
  'catalog.product.similar': operation('/api/secureshop/products/:id/similar', 'GET', { params: ['id'] }),
  'catalog.product.similarSession': operation('/api/secureshop/products/:id/similar/session', 'POST',
    { params: ['id'], body: emptyBody(), requiredBody: true }),
  'catalog.product.similarRun': operation('/api/secureshop/products/:id/similar', 'POST',
    { params: ['id'], body: body('sessionId', 'requestId'), requiredBody: true }),
  'catalog.product.similarSaved': operation('/api/secureshop/products/:id/similar/sessions/:sessionId/requests/:requestId', 'GET',
    { params: ['id', 'sessionId', 'requestId'] }),

  'cart.get': operation('/api/secureshop/cart', 'GET', { query: ['user_id'] }),
  'cart.add': operation('/api/secureshop/cart', 'POST', { body: body('product_id', 'quantity') }),
  'cart.update': operation('/api/secureshop/cart/:itemId', 'PATCH', { params: ['itemId'], body: body('quantity') }),
  'cart.remove': operation('/api/secureshop/cart/:itemId', 'DELETE', { params: ['itemId'] }),
  'cart.applyCoupon': operation('/api/secureshop/cart/apply-coupon', 'POST', { body: body('code', 'operationId') }),

  'orders.summary': operation('/api/secureshop/orders/summary', 'POST', { body: emptyBody() }),
  'orders.create': operation('/api/secureshop/orders', 'POST', { body: body('shipping_address', 'payment_method', 'operationId') }),
  'orders.list': operation('/api/secureshop/orders', 'GET', { query: ['user_id'] }),
  'orders.operations': operation('/api/secureshop/orders/operations'),
  'orders.operation': operation('/api/secureshop/orders/operations/:operationId', 'GET', { params: ['operationId'] }),
  'orders.get': operation('/api/secureshop/orders/:id', 'GET', { params: ['id'] }),

  'email.readiness': operation('/api/secureshop/email/readiness', 'GET'),
  'email.operation': operation('/api/secureshop/email/operations/:action/:requestId', 'GET', { params: ['action', 'requestId'] }),
  'email.keepUnresolved': operation('/api/secureshop/email/operations/autoReply/:requestId/keep-unresolved', 'POST', { params: ['requestId'], body: body('threadId') }),
  'email.inbox': operation('/api/secureshop/email/inbox/:userId', 'GET', { params: ['userId'], query: ['requestId'] }),
  'email.disclosure': operation('/api/secureshop/email/disclosure', 'POST', { body: body('requestId', 'userId') }),
  'email.disclosureAssessment': operation('/api/secureshop/email/disclosure-assessment', 'POST', { body: body('requestId', 'readOperationId', 'evaluationId') }),
  'email.browserAssessment': operation('/api/secureshop/email/browser-assessment', 'POST', { body: body('requestId', 'sendOperationId', 'messageId', 'evaluationId') }),
  'email.htmlInjectionAssessment': operation('/api/secureshop/email/html-injection-assessment', 'POST', { body: body('requestId', 'sourceSessionId', 'sourceRequestId', 'sendOperationId', 'messageId'), requiredBody: true }),
  'email.htmlInjectionAssessmentOperation': operation('/api/secureshop/email/html-injection-assessment/:requestId/:sourceSessionId/:sourceRequestId/:sendOperationId/:messageId', 'GET', { params: ['requestId', 'sourceSessionId', 'sourceRequestId', 'sendOperationId', 'messageId'] }),
  'email.headerAssessment': operation('/api/secureshop/email/header-assessment', 'POST', { body: body('requestId', 'sendOperationId', 'evaluationId') }),
  'email.replyAssessment': operation('/api/secureshop/email/reply-assessment', 'POST', { body: body('requestId', 'replyOperationId', 'threadId', 'evaluationId') }),
  'email.send': operation('/api/secureshop/email/send', 'POST', { body: body('requestId', 'from', 'to', 'subject', 'body_markdown') }),
  'email.autoReply': operation('/api/secureshop/email/auto-reply/:threadId', 'POST', { params: ['threadId'], body: body('requestId') }),
  'email.inlineTeaching.save': operation('/api/secureshop/email/inline/teaching-message', 'POST', { body: body('requestId'), requiredBody: true }),
  'email.inlineTeaching.operation': operation('/api/secureshop/email/inline/teaching-message/:requestId', 'GET', { params: ['requestId'] }),
  'email.inlineSummary.run': operation('/api/secureshop/email/inline/summary', 'POST', { body: body('requestId', 'readOperationId', 'messageId'), requiredBody: true }),
  'email.inlineSummary.operation': operation('/api/secureshop/email/inline/summary/:requestId', 'GET', { params: ['requestId'] }),
  'email.inlineSummary.assessment': operation('/api/secureshop/email/inline/assessment', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'email.inlineSummary.assessmentOperation': operation('/api/secureshop/email/inline/assessment/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),

  'agent.customer.session': operation('/api/secureshop/agents/customer/session', 'POST', {
    body: Object.freeze({ keys: Object.freeze(['userId']), emitEmpty: true }),
  }),
  'agent.customer.chat': operation('/api/secureshop/agents/customer/chat', 'POST', { body: CUSTOMER_CHAT_BODY, responseKind: 'sse' }),
  'agent.customer.operation': operation('/api/secureshop/agents/customer/operations/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.agencyRoleAssessment': operation('/api/secureshop/agents/customer/sessions/:sessionId/requests/:requestId/agency-role/assessment', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.searchEchoAssess': operation('/api/secureshop/agents/customer/search-echo/assess', 'POST', {
    body: body('sessionId', 'requestId', 'step'), requiredBody: true }),
  'agent.customer.searchEchoAssessment': operation('/api/secureshop/agents/customer/sessions/:sessionId/requests/:requestId/search-echo/:step/assessment', 'GET', {
    params: ['sessionId', 'requestId', 'step'] }),
  'agent.customer.coupon.confirm': operation('/api/secureshop/agents/customer/coupons/confirm', 'POST', {
    body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.customer.coupon.saved': operation('/api/secureshop/agents/customer/coupons/confirm/:sessionId/:requestId/:proposalId', 'GET', {
    params: ['sessionId', 'requestId', 'proposalId'] }),
  'agent.customer.coupon.assessment': operation('/api/secureshop/agents/customer/coupons/assessment/:sessionId/:requestId/:proposalId', 'GET', {
    params: ['sessionId', 'requestId', 'proposalId'] }),
  'agent.customer.coupon.assessmentRetry': operation('/api/secureshop/agents/customer/coupons/assessment-retry', 'POST', {
    body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.customer.couponProbe.capabilities': operation('/api/secureshop/customer/coupon-probe/capabilities', 'GET'),
  'agent.customer.couponProbe.session': operation('/api/secureshop/customer/coupon-probe/session', 'POST', {
    body: emptyBody(), requiredBody: true }),
  'agent.customer.couponProbe.run': operation('/api/secureshop/customer/coupon-probe/run', 'POST', {
    body: body('sessionId', 'requestId', 'message', 'protocol') }),
  'agent.customer.couponProbe.operation': operation('/api/secureshop/customer/coupon-probe/operations/:sessionId/:requestId', 'GET', {
    params: ['sessionId', 'requestId'] }),
  'agent.customer.couponProbe.assess': operation('/api/secureshop/customer/coupon-probe/assess', 'POST', {
    body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.couponProbe.assessment': operation('/api/secureshop/customer/coupon-probe/assess/:sessionId/:requestId', 'GET', {
    params: ['sessionId', 'requestId'] }),
  'agent.customer.productSearch.capabilities': operation('/api/secureshop/customer/product-search/capabilities'),
  'agent.customer.productSearch.session': operation('/api/secureshop/customer/product-search/session', 'POST', {
    body: emptyBody(), requiredBody: true }),
  'agent.customer.productSearch.run': operation('/api/secureshop/customer/product-search/run', 'POST', {
    body: body('sessionId', 'requestId', 'message'), requiredBody: true }),
  'agent.customer.productSearch.operation': operation('/api/secureshop/customer/product-search/operations/:sessionId/:requestId', 'GET', {
    params: ['sessionId', 'requestId'] }),
  'agent.customer.productSearch.assess': operation('/api/secureshop/customer/product-search/assess', 'POST', {
    body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.productSearch.assessment': operation('/api/secureshop/customer/product-search/assess/:sessionId/:requestId', 'GET', {
    params: ['sessionId', 'requestId'] }),
  'agent.customer.orderStatus.capabilities': operation('/api/secureshop/customer/order-status/capabilities'),
  'agent.customer.orderStatus.session': operation('/api/secureshop/customer/order-status/session', 'POST', {
    body: emptyBody(), requiredBody: true }),
  'agent.customer.orderStatus.run': operation('/api/secureshop/customer/order-status/run', 'POST', {
    body: body('sessionId', 'requestId', 'message'), requiredBody: true }),
  'agent.customer.orderStatus.operation': operation('/api/secureshop/customer/order-status/operations/:sessionId/:requestId', 'GET', {
    params: ['sessionId', 'requestId'] }),
  'agent.customer.orderStatus.assess': operation('/api/secureshop/customer/order-status/assess', 'POST', {
    body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.orderStatus.assessment': operation('/api/secureshop/customer/order-status/assess/:sessionId/:requestId', 'GET', {
    params: ['sessionId', 'requestId'] }),
  'agent.customer.ticket.confirm': operation('/api/secureshop/agents/customer/tickets/confirm', 'POST', {
    body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.customer.ticket.saved': operation('/api/secureshop/agents/customer/tickets/confirm/:sessionId/:requestId/:proposalId', 'GET', {
    params: ['sessionId', 'requestId', 'proposalId'] }),
  'agent.customer.idor.prepare': operation('/api/secureshop/agents/customer/idor/prepare', 'POST', { body: emptyBody() }),
  'agent.customer.idor.cards': operation('/api/secureshop/agents/customer/idor/cards'),
  'agent.customer.idor.session': operation('/api/secureshop/agents/customer/idor/session', 'POST', { body: emptyBody() }),
  'agent.customer.idor.chat': operation('/api/secureshop/agents/customer/idor/chat', 'POST', { body: CUSTOMER_IDOR_CHAT_BODY, requiredBody: true, responseKind: 'sse' }),
  'agent.customer.idor.operation': operation('/api/secureshop/agents/customer/idor/operations/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.idor.assessment': operation('/api/secureshop/agents/customer/idor/assessments/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.idor.assessmentRetry': operation('/api/secureshop/agents/customer/idor/assessment-retry', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.checkoutAudit.session': operation('/api/secureshop/agents/customer/checkout-audit/session', 'POST', {
    body: emptyBody(), requiredBody: true }),
  'agent.customer.checkoutAudit.practiceToken': operation('/api/secureshop/agents/customer/checkout-audit/practice-token', 'POST', {
    body: body('checkoutOperationId'), requiredBody: true }),
  'agent.customer.checkoutAudit.chat': operation('/api/secureshop/agents/customer/checkout-audit/chat', 'POST', {
    body: body('sessionId', 'requestId', 'checkoutOperationId', 'teachingToken', 'message'),
    requiredBody: true, responseKind: 'sse' }),
  'agent.customer.checkoutAudit.operation': operation('/api/secureshop/agents/customer/checkout-audit/operations/:sessionId/:requestId', 'GET', {
    params: ['sessionId', 'requestId'] }),
  'agent.customer.checkoutAudit.assess': operation('/api/secureshop/agents/customer/checkout-audit/assess', 'POST', {
    body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.checkoutAudit.assessment': operation('/api/secureshop/agents/customer/checkout-audit/assess/:sessionId/:requestId', 'GET', {
    params: ['sessionId', 'requestId'] }),
  'agent.customer.avatarTraversal.session': operation('/api/secureshop/agents/customer/avatar-upload/path-traversal/session', 'POST', { body: emptyBody(), requiredBody: true }),
  'agent.customer.avatarTraversal.request': operation('/api/secureshop/agents/customer/avatar-upload/path-traversal/requests/:requestId', 'GET', { params: ['requestId'] }),
  'agent.customer.avatarTraversal.assess': operation('/api/secureshop/agents/customer/avatar-upload/path-traversal/assess', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.avatarTraversal.assessment': operation('/api/secureshop/agents/customer/avatar-upload/path-traversal/assessment/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.avatarUpload.session': operation('/api/secureshop/agents/customer/avatar-upload/session', 'POST'),
  'agent.customer.avatarUpload.request': operation('/api/secureshop/agents/customer/avatar-upload/requests/:requestId', 'GET', { params: ['requestId'] }),
  'agent.customer.avatarUpload.operation': operation('/api/secureshop/agents/customer/avatar-upload/operations/:operationId', 'GET', { params: ['operationId'] }),
  'agent.customer.avatarUpload.asset': operation('/api/secureshop/agents/customer/avatar-upload/operations/:operationId/asset', 'POST', { params: ['operationId'] }),
  'agent.customer.avatarUpload.assess': operation('/api/secureshop/agents/customer/avatar-upload/assess', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.avatarUpload.assessment': operation('/api/secureshop/agents/customer/avatar-upload/assess/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.avatarUpload.svgAssess': operation('/api/secureshop/agents/customer/avatar-upload/svg-assess', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.avatarUpload.svgAssessment': operation('/api/secureshop/agents/customer/avatar-upload/svg-assess/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.avatarUpload.polyglotReadiness': operation('/api/secureshop/agents/customer/avatar-upload/polyglot-readiness', 'GET'),
  'agent.customer.avatarUpload.polyglotPreview': operation('/api/secureshop/agents/customer/avatar-upload/polyglot-preview', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.avatarUpload.polyglotPreviewSaved': operation('/api/secureshop/agents/customer/avatar-upload/polyglot-preview/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.avatarUpload.polyglotAssess': operation('/api/secureshop/agents/customer/avatar-upload/polyglot-assess', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.avatarUpload.polyglotAssessment': operation('/api/secureshop/agents/customer/avatar-upload/polyglot-assess/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.filePathSummary.capability': operation('/api/secureshop/agents/customer/file-path-summary/capability'),
  'agent.customer.filePathSummary.session': operation('/api/secureshop/agents/customer/file-path-summary/session', 'POST', { body: emptyBody(), requiredBody: true }),
  'agent.customer.filePathSummary.run': operation('/api/secureshop/agents/customer/file-path-summary/run', 'POST', { body: body('sessionId', 'requestId', 'message', 'path'), requiredBody: true }),
  'agent.customer.filePathSummary.request': operation('/api/secureshop/agents/customer/file-path-summary/requests/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.filePathSummary.assess': operation('/api/secureshop/agents/customer/file-path-summary/assess', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.filePathSummary.assessment': operation('/api/secureshop/agents/customer/file-path-summary/assess/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.fileSummary.capability': operation('/api/secureshop/agents/customer/file-summary/capability'),
  'agent.customer.fileSummary.session': operation('/api/secureshop/agents/customer/file-summary/session', 'POST', { body: emptyBody(), requiredBody: true }),
  'agent.customer.fileSummary.request': operation('/api/secureshop/agents/customer/file-summary/requests/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.fileSummary.assess': operation('/api/secureshop/agents/customer/file-summary/assess', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.customer.fileSummary.assessment': operation('/api/secureshop/agents/customer/file-summary/assess/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.profile.confirm': operation('/api/secureshop/agents/customer/profile/confirm', 'POST', {
    requiredBody: true, body: body('sessionId', 'requestId', 'proposalId') }),
  'customer.commerce.profileForm': operation('/api/secureshop/customer/commerce/profile-form'),
  'customer.commerce.profile.save': operation('/api/secureshop/customer/commerce/profile', 'POST', { requiredBody: true,
    body: Object.freeze({ keys: Object.freeze(['operationId', 'expectedSnapshotSha256', 'fields']),
      nested: Object.freeze({ fields: shape({ fullName: ANY, email: ANY, phone: ANY }) }), emitEmpty: false }) }),
  'customer.commerce.addresses': operation('/api/secureshop/customer/commerce/addresses'),
  'customer.commerce.addressForm': operation('/api/secureshop/customer/commerce/address-form', 'GET', { query: ['action', 'choiceId'] }),
  'customer.commerce.addresses.save': operation('/api/secureshop/customer/commerce/addresses', 'POST', { requiredBody: true,
    body: Object.freeze({ keys: Object.freeze(['operationId', 'action', 'choiceId', 'expectedSnapshotSha256', 'defaultSetSha256', 'fields']),
      nested: Object.freeze({ fields: shape({ label: ANY, line1: ANY, line2: ANY, city: ANY, state: ANY, zip: ANY, phone: ANY, isDefault: ANY }) }), emitEmpty: false }) }),
  'customer.commerce.paymentMethods.list': operation('/api/secureshop/customer/commerce/payment-methods'),
  'customer.commerce.paymentMethods.create': operation('/api/secureshop/customer/commerce/payment-methods', 'POST', { body: body('operationId', 'scenario') }),
  'customer.commerce.checkout.prepare': operation('/api/secureshop/customer/commerce/checkout/prepare', 'POST', { body: body('operationId', 'addressChoiceId', 'paymentChoiceId') }),
  'customer.commerce.checkout.confirm': operation('/api/secureshop/customer/commerce/checkout/confirm', 'POST', { body: body('proposalId') }),
  'customer.commerce.cart.confirm': operation('/api/secureshop/customer/commerce/cart/confirm', 'POST', { body: body('proposalId'), requiredBody: true }),
  'customer.commerce.operation': operation('/api/secureshop/customer/commerce/operations/:operationId', 'GET', { params: ['operationId'] }),
  'agent.customer.refund.session': operation('/api/secureshop/agents/customer/refund/session', 'POST', { body: body('userId') }),
  'agent.customer.refund.chat': operation('/api/secureshop/agents/customer/refund/chat', 'POST', { body: body('sessionId', 'message', 'requestId'), responseKind: 'sse' }),
  'agent.customer.refund.operation': operation('/api/secureshop/agents/customer/refund/operations/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.customer.trace.latest': operation('/api/secureshop/agents/customer/trace/latest', 'GET', { query: ['limit'] }),
  'agent.merchant.session': operation('/api/secureshop/agents/merchant/session', 'POST', { body: body('userId') }),
  'agent.merchant.chat': operation('/api/secureshop/agents/merchant/chat', 'POST', { body: body('sessionId', 'message'), responseKind: 'sse' }),
  'agent.merchant.trace.latest': operation('/api/secureshop/agents/merchant/trace/latest', 'GET', { query: ['limit'] }),
  'agent.merchant.assistant.session': operation('/api/secureshop/agents/merchant/assistant/session', 'POST', { body: emptyBody() }),
  'agent.merchant.assistant.chat': operation('/api/secureshop/agents/merchant/assistant/chat', 'POST', { body: ROLE_ASSISTANT_CHAT_BODY, responseKind: 'sse' }),
  'agent.merchant.assistant.operation': operation('/api/secureshop/agents/merchant/assistant/operations/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.merchant.assistant.inventoryConfirm': operation('/api/secureshop/agents/merchant/assistant/inventory/confirm', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.merchant.assistant.pricingConfirm': operation('/api/secureshop/agents/merchant/assistant/pricing/confirm', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.merchant.assistant.listingConfirm': operation('/api/secureshop/agents/merchant/assistant/listing/confirm', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.merchant.assistant.reviewConfirm': operation('/api/secureshop/agents/merchant/assistant/review/confirm', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.merchant.assistant.mailConfirm': operation('/api/secureshop/agents/merchant/assistant/mail/confirm', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.merchant.assistant.mailOperation': operation('/api/secureshop/agents/merchant/assistant/mail/operations/:sessionId/:requestId/:operationId', 'GET', { params: ['sessionId', 'requestId', 'operationId'] }),
  'agent.merchant.assistant.mailReadAssess': operation('/api/secureshop/agents/merchant/assistant/mail-read/assess', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.merchant.assistant.mailReadAssessment': operation('/api/secureshop/agents/merchant/assistant/mail-read/assessment/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.merchant.assistant.listingOperation': operation('/api/secureshop/agents/merchant/assistant/listing/operations/:operationId', 'GET', { params: ['operationId'] }),
  'agent.admin.session': operation('/api/secureshop/agents/admin/session', 'POST', {
    body: Object.freeze({ keys: Object.freeze(['userId']), emitEmpty: true }),
  }),
  'agent.admin.chat': operation('/api/secureshop/agents/admin/chat', 'POST', { body: body('sessionId', 'message', 'requestId'), responseKind: 'sse' }),
  'agent.admin.chat.request': operation('/api/secureshop/agents/admin/chat/requests/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.admin.chat.assessment': operation('/api/secureshop/agents/admin/chat/assessment/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.admin.chat.assessmentRetry': operation('/api/secureshop/agents/admin/chat/assessment-retry', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.admin.chat.descriptionAssessment': operation('/api/secureshop/agents/admin/chat/description-assessment/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.admin.chat.descriptionAssess': operation('/api/secureshop/agents/admin/chat/description-assessment', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.admin.trace.latest': operation('/api/secureshop/agents/admin/trace/latest', 'GET', { query: ['limit'] }),
  'agent.admin.assistant.session': operation('/api/secureshop/agents/admin/assistant/session', 'POST', { body: emptyBody() }),
  'agent.admin.assistant.chat': operation('/api/secureshop/agents/admin/assistant/chat', 'POST', { body: ROLE_ASSISTANT_CHAT_BODY, responseKind: 'sse' }),
  'agent.admin.assistant.operation': operation('/api/secureshop/agents/admin/assistant/operations/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.admin.assistant.auditOperation': operation('/api/secureshop/agents/admin/assistant/audit/operations/:sessionId/:requestId/:operationId', 'GET', { params: ['sessionId', 'requestId', 'operationId'] }),
  'agent.admin.assistant.systemConfigOperation': operation('/api/secureshop/agents/admin/assistant/system/config/operations/:sessionId/:requestId/:operationId', 'GET', { params: ['sessionId', 'requestId', 'operationId'] }),
  'agent.admin.assistant.systemConfigAssessmentRetry': operation('/api/secureshop/agents/admin/assistant/system/config/assessment-retry', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.admin.assistant.policyInstructionAssessmentRetry': operation('/api/secureshop/agents/admin/assistant/policy/instruction/assessment-retry', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.admin.assistant.userLookupAssess': operation('/api/secureshop/agents/admin/assistant/user-lookup/assess', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.admin.assistant.userLookupAssessment': operation('/api/secureshop/agents/admin/assistant/sessions/:sessionId/requests/:requestId/user-lookup/assessment', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.admin.assistant.userConfirm': operation('/api/secureshop/agents/admin/assistant/user/confirm', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.admin.assistant.policyConfirm': operation('/api/secureshop/agents/admin/assistant/policies/confirm', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.admin.assistant.mcpConfirm': operation('/api/secureshop/agents/admin/assistant/mcp/confirm', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.admin.assistant.mcpManifestAssess': operation('/api/secureshop/agents/admin/assistant/mcp-manifest/assess', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.admin.assistant.mcpManifestAssessment': operation('/api/secureshop/agents/admin/assistant/sessions/:sessionId/requests/:requestId/mcp-manifest/:proposalId/assessment', 'GET', { params: ['sessionId', 'requestId', 'proposalId'] }),
  'agent.admin.assistant.mcpDiscoveryAssess': operation('/api/secureshop/agents/admin/assistant/mcp-discovery/assess', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.admin.assistant.mcpDiscoveryAssessment': operation('/api/secureshop/agents/admin/assistant/sessions/:sessionId/requests/:requestId/mcp-discovery/:proposalId/assessment', 'GET', { params: ['sessionId', 'requestId', 'proposalId'] }),
  'agent.admin.assistant.systemRestartConfirm': operation('/api/secureshop/agents/admin/assistant/system/restart/confirm', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.admin.assistant.systemRestartAssess': operation('/api/secureshop/agents/admin/assistant/system/restart/assess', 'POST', { body: body('sessionId', 'requestId'), requiredBody: true }),
  'agent.admin.assistant.systemRestartAssessment': operation('/api/secureshop/agents/admin/assistant/system/restart/assessment/:sessionId/:requestId', 'GET', { params: ['sessionId', 'requestId'] }),
  'agent.admin.assistant.systemDiagnosticConfirm': operation('/api/secureshop/agents/admin/assistant/system/diagnostic/confirm', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.admin.assistant.systemDiagnosticOperation': operation('/api/secureshop/agents/admin/assistant/system/diagnostic/confirm/:sessionId/:requestId/:proposalId', 'GET', { params: ['sessionId', 'requestId', 'proposalId'] }),
  'agent.admin.assistant.systemDiagnosticAssess': operation('/api/secureshop/agents/admin/assistant/system/diagnostic/assess', 'POST', {
    body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.admin.assistant.systemDiagnosticAssessment': operation('/api/secureshop/agents/admin/assistant/system/diagnostic/assess/:sessionId/:requestId/:proposalId', 'GET', {
    params: ['sessionId', 'requestId', 'proposalId'] }),
  'agent.admin.assistant.auditJobRun': operation('/api/secureshop/agents/admin/assistant/audit/job/run', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.admin.assistant.auditJobOperation': operation('/api/secureshop/agents/admin/assistant/audit/job/operations/:sessionId/:requestId/:proposalId', 'GET', { params: ['sessionId', 'requestId', 'proposalId'] }),
  'agent.admin.assistant.aclConfirm': operation('/api/secureshop/agents/admin/assistant/acl/confirm', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),

  'merchant.overview.kpis': operation('/api/secureshop/merchant/overview/kpis', 'GET', { query: ['retailer_id'] }),
  'merchant.overview.salesChart': operation('/api/secureshop/merchant/overview/sales-chart', 'GET', { query: ['retailer_id', 'days'] }),
  'merchant.overview.topProducts': operation('/api/secureshop/merchant/overview/top-products', 'GET', { query: ['limit', 'days'] }),
  'merchant.products.list': operation('/api/secureshop/merchant/products', 'GET', { query: ['retailer_id', 'page', 'per_page', 'sort', 'search', 'status', 'category'] }),
  'merchant.products.create': operation('/api/secureshop/merchant/products', 'POST', { body: body('title', 'description', 'price', 'images', 'category', 'template_source', 'retailer_id') }),
  'merchant.products.update': operation('/api/secureshop/merchant/products/:id', 'PUT', { params: ['id'], body: Object.freeze({ keys: Object.freeze(['patch']), nested: Object.freeze({ patch: PRODUCT_PATCH }), emitEmpty: false }) }),
  'merchant.products.delete': operation('/api/secureshop/merchant/products/:id', 'DELETE', { params: ['id'] }),
  'merchant.inventory.readiness': operation('/api/secureshop/merchant/inventory/readiness'),
  'merchant.inventory.run': operation('/api/secureshop/merchant/inventory/run', 'POST', { body: body('requestId', 'message', 'access', 'stockChange'), requiredBody: true }),
  'merchant.inventory.judge-retry': operation('/api/secureshop/merchant/inventory/judge-retry', 'POST', { body: body('requestId', 'originalRequestId', 'evaluationId') }),
  'merchant.inventory.operation': operation('/api/secureshop/merchant/inventory/operations/:requestId', 'GET', { params: ['requestId'] }),
  'merchant.inventory.history': operation('/api/secureshop/merchant/inventory/history'),
  'merchant.inventory.historyRead': operation('/api/secureshop/merchant/inventory/history/:requestId', 'GET', { params: ['requestId'] }),
  'merchant.listings.assistWrite': operation('/api/secureshop/merchant/listings/assist-write', 'POST', { body: listingsBody('title', 'description', 'operationId') }),
  'merchant.listings.importBulk': operation('/api/secureshop/merchant/listings/import-bulk', 'POST', { body: listingsBody('json_url', 'xml_url', 'operationId') }),
  'merchant.listings.optimizeImages': operation('/api/secureshop/merchant/listings/optimize-images', 'POST', { body: listingsBody('operationId') }),
  'merchant.listings.browserRetry': operation('/api/secureshop/merchant/listings/browser-retry', 'POST', { body: body('requestId', 'rewriteOperationId', 'saveOperationId', 'evaluationId') }),
  'merchant.listings.browserAttempt': operation('/api/secureshop/merchant/listings/browser-attempt', 'POST', { body: body('requestId', 'rewriteOperationId', 'saveOperationId') }),
  'merchant.listings.readiness': operation('/api/secureshop/merchant/listings/readiness'),
  'merchant.listings.templateReadiness': operation('/api/secureshop/merchant/listings/template-readiness'),
  'merchant.listings.templateRender': operation('/api/secureshop/merchant/listings/template-render', 'POST', { body: body('operationId', 'productId') }),
  'merchant.listings.templateOperation': operation('/api/secureshop/merchant/listings/template-operations/:operationId', 'GET', { params: ['operationId'] }),
  'merchant.listings.operation': operation('/api/secureshop/merchant/listings/operations/:operationId', 'GET', { params: ['operationId'] }),
  'merchant.listings.resume': operation('/api/secureshop/merchant/listings/operations/:operationId/resume', 'POST', { params: ['operationId'], body: emptyBody() }),
  'merchant.listings.rewriteSaved': operation('/api/secureshop/merchant/listings/rewrite-saves/:saveOperationId', 'GET', { params: ['saveOperationId'], query: ['sessionId','requestId','proposalId','rewriteOperationId'] }),
  'merchant.listings.rewriteSave': operation('/api/secureshop/merchant/listings/rewrite-save', 'POST', { body: Object.freeze({ keys: Object.freeze(['rewriteOperationId', 'saveOperationId', 'productId', 'item', 'chatSource']), nested: Object.freeze({ chatSource: LISTINGS_CHAT_SOURCE, item: shape({ name: ANY, description: ANY, price: ANY, category: ANY, images: ANY, templateSource: ANY }) }), emitEmpty: false }) }),
  'merchant.reviews.list': operation('/api/secureshop/merchant/reviews', 'GET', { query: ['status', 'per_page', 'product_id', 'min_rating', 'max_rating'] }),
  'merchant.reviews.moderateAll': operation('/api/secureshop/merchant/reviews/moderate-all', 'POST', { body: body('request_id', 'limit') }),
  'merchant.reviews.operation': operation('/api/secureshop/merchant/reviews/operations/:operationId', 'GET', {params:['operationId']}),
  'merchant.reviews.approve': operation('/api/secureshop/merchant/reviews/:id/approve', 'POST', { params: ['id'], body:body('operationId') }),
  'merchant.reviews.reject': operation('/api/secureshop/merchant/reviews/:id/reject', 'POST', { params: ['id'], body: body('reason','operationId') }),
  'agent.merchant.assistant.listingCreateConfirm': operation('/api/secureshop/agents/merchant/assistant/listing-create/confirm', 'POST', { body: body('sessionId', 'requestId', 'proposalId'), requiredBody: true }),
  'agent.merchant.assistant.listingCreateOperation': operation('/api/secureshop/agents/merchant/assistant/listing-create/operations/:operationId', 'GET', { params: ['operationId'] }),
  'agent.merchant.assistant.listingCreateAssess': operation('/api/secureshop/agents/merchant/assistant/listing-create/assess', 'POST', { body: body('operationId'), requiredBody: true }),
  'agent.merchant.assistant.listingCreateAssessment': operation('/api/secureshop/agents/merchant/assistant/listing-create/assessment/:operationId', 'GET', { params: ['operationId'] }),
  'merchant.pricing.capability': operation('/api/secureshop/merchant/pricing/run', 'GET'),
  'merchant.pricing.run': operation('/api/secureshop/merchant/pricing/run', 'POST', { body: Object.freeze({ keys: Object.freeze(['operationId', 'productId', 'message', 'experiment', 'competitorUrl']), nested: Object.freeze({ experiment: shape({ strategy: ANY, durationDays: ANY }) }), emitEmpty: false }) }),
  'merchant.pricing.operation': operation('/api/secureshop/merchant/pricing/operations/:operationId', 'GET', { params: ['operationId'] }),
  'merchant.pricing.history': operation('/api/secureshop/merchant/pricing/history', 'GET', { query: ['product_id'] }),
  'merchant.pricing.suggest': operation('/api/secureshop/merchant/pricing/suggest', 'POST', { body: body('product_id') }),
  'merchant.pricing.compare': operation('/api/secureshop/merchant/pricing/compare', 'POST', { query: ['product_id', 'url'] }),
  'merchant.pricing.experiment': operation('/api/secureshop/merchant/pricing/experiment', 'POST', { body: body('product_id', 'strategy', 'duration_days') }),
  'merchant.analytics.describe': operation('/api/secureshop/merchant/analytics'),
  'merchant.analytics.request': operation('/api/secureshop/merchant/analytics/requests/:requestId', 'GET', { params: ['requestId'] }),
  'merchant.analytics.history': operation('/api/secureshop/merchant/analytics/history', 'GET', { query: ['limit', 'cursor'] }),
  'merchant.analytics.topProducts': operation('/api/secureshop/merchant/analytics/top-products', 'GET', { query: ['limit'] }),
  'merchant.analytics.query': operation('/api/secureshop/merchant/analytics/query', 'POST', { body: body('question', 'requestId') }),

  'admin.overview.kpis': operation('/api/secureshop/admin/overview/kpis'),
  'admin.agentHost.health': operation('/api/secureshop/admin/agent-host/health'),
  'admin.providerState': operation('/api/secureshop/admin/provider-state'),
  'admin.dbSizes': operation('/api/secureshop/admin/db-sizes'),
  'admin.users.list': operation('/api/secureshop/admin/users', 'GET', { query: ['page', 'pageSize', 'search', 'role', 'banned'] }),
  'admin.users.lookup': operation('/api/secureshop/admin/users/lookup', 'POST', { body: body('username') }),
  'admin.users.operation': operation('/api/secureshop/admin/users/operations/:operationId', 'GET', { params: ['operationId'] }),
  'admin.users.setRole': operation('/api/secureshop/admin/users/:id/role', 'POST', { params: ['id'], body: body('role', 'operationId', 'expectedVersion') }),
  'admin.users.ban': operation('/api/secureshop/admin/users/:id/ban', 'POST', { params: ['id'], body: body('reason', 'operationId', 'expectedVersion') }),
  'admin.users.resetPassword': operation('/api/secureshop/admin/users/:id/reset-password', 'POST', { params: ['id'], body: body('operationId','expectedCredentialVersion','expectedAuthorityVersion') }),
  'admin.users.resetRead': operation('/api/secureshop/admin/users/:id/password-resets/:operationId', 'GET', {params:['id','operationId']}),
  'admin.users.resetReveal': operation('/api/secureshop/admin/users/:id/password-resets/:operationId/reveal', 'POST', {params:['id','operationId'],body:emptyBody()}),
  'admin.users.resetAcknowledge': operation('/api/secureshop/admin/users/:id/password-resets/:operationId/acknowledge', 'POST', {params:['id','operationId'],body:emptyBody()}),
  'admin.tickets.list': operation('/api/secureshop/admin/tickets', 'GET', { query: ['cursor'] }),
  'admin.tickets.detail': operation('/api/secureshop/admin/tickets/:ticketId', 'GET', { params: ['ticketId'] }),
  'admin.tickets.assess': operation('/api/secureshop/admin/tickets/:ticketId/assessment', 'POST', {
    params: ['ticketId'], body: body('requestId'), requiredBody: true }),
  'admin.tickets.assessment': operation('/api/secureshop/admin/tickets/:ticketId/assessment/:requestId', 'GET', {
    params: ['ticketId', 'requestId'] }),
  'admin.audit.list': operation('/api/secureshop/admin/audit', 'GET', { query: ['actor', 'action', 'target', 'q', 'from', 'to', 'limit', 'cursor'] }),
  'admin.audit.capabilities': operation('/api/secureshop/admin/audit/capabilities'),
  'admin.audit.searchByUser': operation('/api/secureshop/admin/audit/search-by-user', 'POST', { body: body('username', 'operationId') }),
  'admin.audit.summarizeAnomalies': operation('/api/secureshop/admin/audit/summarize-anomalies', 'POST', { body: body('limit') }),
  'admin.audit.agentSession': operation('/api/secureshop/admin/audit/agent-session', 'POST', { body: emptyBody() }),
  'admin.audit.agentSearch': operation('/api/secureshop/admin/audit/agent-search', 'POST', { body: body('sessionId', 'requestId', 'message') }),
  'admin.audit.boundSession': operation('/api/secureshop/admin/audit/bound-session', 'POST', { body: emptyBody() }),
  'admin.audit.boundSummary': operation('/api/secureshop/admin/audit/bound-summary', 'POST', { body: body('session_id', 'request_id', 'limit') }),
  'admin.audit.unboundedSession': operation('/api/secureshop/admin/audit/unbounded-session', 'POST', { body: emptyBody() }),
  'admin.audit.unboundedSummary': operation('/api/secureshop/admin/audit/unbounded-summary', 'POST', { body: body('session_id', 'request_id', 'limit') }),
  'admin.audit.timingSession': operation('/api/secureshop/admin/audit/timing-session', 'POST', { body: emptyBody() }),
  'admin.audit.timingRun': operation('/api/secureshop/admin/audit/timing-run', 'POST', { body: body('sessionId', 'requestId', 'message') }),
  'admin.policies.list': operation('/api/secureshop/admin/policies'),
  'admin.policies.readiness': operation('/api/secureshop/admin/policies/readiness'),
  'admin.policies.upsert': operation('/api/secureshop/admin/policies', 'POST', { body: body('name', 'markdown', 'injected_into', 'operationId', 'expectedVersion') }),
  'admin.policies.saveMarkdown': operation('/api/secureshop/admin/policies/:name', 'POST', { params: ['name'], body: body('markdown', 'injected_into', 'operationId', 'expectedVersion') }),
  'admin.policies.render': operation('/api/secureshop/admin/policies/:name/render', 'POST', { params: ['name'], body: body('markdown', 'injected_into', 'operationId', 'expectedVersion') }),
  'admin.policies.delete': operation('/api/secureshop/admin/policies/:name', 'DELETE', { params: ['name'], body: body('operationId', 'expectedVersion') }),
  'admin.policies.operation': operation('/api/secureshop/admin/policies/operations/:operationId', 'GET', { params: ['operationId'] }),
  'admin.mcp.servers': operation('/api/secureshop/admin/mcp/servers'),
  'admin.mcp.schemaHistory': operation('/api/secureshop/admin/mcp/schema-history'),
  'admin.mcp.tools': operation('/api/secureshop/admin/mcp/servers/:name/tools', 'GET', { params: ['name'] }),
  'admin.mcp.register': operation('/api/secureshop/admin/mcp/register', 'POST', { body: body('version', 'action', 'operationId', 'expectedVersion', 'name', 'url', 'transport', 'stdio_cmd') }),
  'admin.mcp.importManifest': operation('/api/secureshop/admin/mcp/import-manifest', 'POST', { body: body('version', 'action', 'operationId', 'expectedVersion', 'xml_url') }),
  'admin.mcp.delete': operation('/api/secureshop/admin/mcp/:name', 'DELETE', { params: ['name'], body: body('version', 'action', 'operationId', 'expectedVersion', 'name') }),
  'admin.mcp.operation': operation('/api/secureshop/admin/mcp/operations/:operationId', 'GET', { params: ['operationId'] }),
  'admin.system.health': operation('/api/secureshop/admin/system/health'),
  'admin.system.readConfig': operation('/api/secureshop/admin/system/read-config', 'POST', { body: body('path') }),
  'admin.system.configRead': operation('/api/secureshop/admin/system/config-read', 'POST', { body: body('operationId', 'path') }),
  'admin.system.configReadAdministration': operation('/api/secureshop/admin/system/config-read'),
  'admin.system.configReadOperation': operation('/api/secureshop/admin/system/config-operations/:operationId', 'GET', { params: ['operationId'] }),
  'admin.system.diagnosticAdministration': operation('/api/secureshop/admin/system/diagnostic'),
  'admin.system.diagnosticOperation': operation('/api/secureshop/admin/system/diagnostic-operations/:operationId', 'GET', { params: ['operationId'] }),
  'admin.system.diagnostic': operation('/api/secureshop/admin/system/diagnostic', 'POST', { body: body('operationId', 'cmd_template', 'args') }),
  'admin.system.restartService': operation('/api/secureshop/admin/system/restart-service', 'POST', { body: body('name') }),
  'admin.system.restartAdministration': operation('/api/secureshop/admin/system/restart'),
  'admin.system.restart': operation('/api/secureshop/admin/system/restart', 'POST', { body: body('version', 'operationId', 'name') }),
  'admin.system.restartOperation': operation('/api/secureshop/admin/system/restart-operations/:operationId', 'GET', { params: ['operationId'] }),
  'admin.system.rebuildAdministration': operation('/api/secureshop/admin/system/rebuild-index'),
  'admin.system.rebuildIndex': operation('/api/secureshop/admin/system/rebuild-index', 'POST', { body: body('version', 'operationId', 'corpus') }),
  'admin.system.rebuildOperation': operation('/api/secureshop/admin/system/rebuild-index/operations/:operationId', 'GET', { params: ['operationId'] }),
  'admin.accessControl.get': operation('/api/secureshop/admin/access-control'),
  'admin.accessControl.operation': operation('/api/secureshop/admin/access-control/operations/:operationId', 'GET', { params: ['operationId'] }),
  'admin.accessControl.setPermission': operation('/api/secureshop/admin/access-control/permission', 'POST', { body: body('tool_name', 'role', 'allowed', 'operationId', 'expectedVersion') }),
  'admin.accessControl.setEnforcement': operation('/api/secureshop/admin/access-control/enforcement', 'POST', { body: body('enabled', 'operationId', 'expectedVersion') }),
});

const SEPARATE = Object.freeze([
  Object.freeze({ name: 'agent.customer.avatarTraversal.run', method: 'POST', path: '/api/secureshop/agents/customer/avatar-upload/path-traversal/run', responseKind: 'json', bodyKind: 'multipart', compiler: 'compileBridgeOperation' }),
  Object.freeze({ name: 'agent.customer.avatarUpload.run', method: 'POST', path: '/api/secureshop/agents/customer/avatar-upload/run', responseKind: 'json', bodyKind: 'multipart', compiler: 'compileBridgeOperation' }),
  Object.freeze({ name: 'agent.customer.fileSummary.run', method: 'POST', path: '/api/secureshop/agents/customer/file-summary/run', responseKind: 'json', bodyKind: 'multipart', compiler: 'compileBridgeOperation' }),
  Object.freeze({ name: 'uploads.create', method: 'POST', path: '/api/secureshop/uploads', responseKind: 'json', bodyKind: 'multipart', compiler: 'compileBridgeOperation' }),
]);

function fail(message) {
  throw new TypeError(`SecureShop operation rejected: ${message}`);
}

function cloneBoundedJson(value) {
  let nodes = 0;
  let approximateBytes = 0;
  const seen = new Set();

  function visit(current, depth) {
    nodes += 1;
    if (nodes > MAX_JSON_NODES) fail('input is too complex');
    if (depth > MAX_JSON_DEPTH) fail('input is too deep');

    if (current === null || typeof current === 'boolean') return current;
    if (typeof current === 'number') {
      if (!Number.isFinite(current)) fail('numbers must be finite');
      return current;
    }
    if (typeof current === 'string') {
      if (current.length > MAX_JSON_BYTES) fail('input is too large');
      approximateBytes += new TextEncoder().encode(current).byteLength;
      if (approximateBytes > MAX_JSON_BYTES) fail('input is too large');
      return current;
    }
    if (typeof current !== 'object') fail('input must contain JSON values only');
    if (seen.has(current)) fail('cyclic input is not allowed');
    seen.add(current);

    const symbols = Object.getOwnPropertySymbols(current);
    if (symbols.length) fail('symbol keys are not allowed');
    const descriptors = Object.getOwnPropertyDescriptors(current);

    let clone;
    if (Array.isArray(current)) {
      const keys = Object.keys(descriptors);
      if (!Number.isSafeInteger(current.length) || current.length > MAX_JSON_NODES) fail('array is too large');
      if (keys.length !== current.length + 1 || !Object.hasOwn(descriptors, 'length')) fail('arrays must be dense and ordinary');
      clone = [];
      for (let index = 0; index < current.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail('array accessors are not allowed');
        clone.push(visit(descriptor.value, depth + 1));
      }
    } else {
      const proto = Object.getPrototypeOf(current);
      if (proto !== Object.prototype && proto !== null) fail('objects must be plain');
      clone = {};
      for (const [key, descriptor] of Object.entries(descriptors)) {
        if (!Object.hasOwn(descriptor, 'value')) fail('object accessors are not allowed');
        if (!descriptor.enumerable) fail('non-enumerable JSON properties are not allowed');
        if (key.length > MAX_JSON_BYTES) fail('input is too large');
        approximateBytes += new TextEncoder().encode(key).byteLength;
        if (approximateBytes > MAX_JSON_BYTES) fail('input is too large');
        Object.defineProperty(clone, key, {
          value: visit(descriptor.value, depth + 1), enumerable: true, writable: true, configurable: true,
        });
      }
    }
    seen.delete(current);
    return clone;
  }

  const cloned = visit(value, 0);
  const encoded = JSON.stringify(cloned);
  if (new TextEncoder().encode(encoded).byteLength > MAX_JSON_BYTES) fail('input is too large');
  return cloned;
}

function assertExactKeys(value, allowed, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const keys = Object.keys(value);
  const allowedSet = new Set(allowed);
  for (const key of keys) {
    if (!allowedSet.has(key)) fail(`${label} contains unknown key ${key}`);
  }
}

function compileSegment(value, name) {
  if (!['string', 'number'].includes(typeof value) || (typeof value === 'number' && !Number.isFinite(value))) {
    fail(`path parameter ${name} must be a string or finite number`);
  }
  const raw = String(value);
  if (!raw || raw.includes('/') || raw.includes('\\') || raw.includes('\0')) fail(`path parameter ${name} is unsafe`);
  let decoded = raw;
  for (let pass = 0; pass < 3; pass += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      // A literal percent-bearing name (for example "50% off") is safe once
      // encodeURIComponent below quotes it. Continue rejecting valid encodings
      // that recursively reveal a slash or dot segment.
      break;
    }
  }
  if (decoded === '.' || decoded === '..' || decoded.includes('/') || decoded.includes('\\') || decoded.includes('\0')) {
    fail(`path parameter ${name} is unsafe`);
  }
  return encodeURIComponent(raw);
}

function validateNestedBody(bodyValue, schema, label) {
  if (!schema || schema === ANY) return;
  assertExactKeys(bodyValue, Object.keys(schema.fields), label);
  for (const [key, value] of Object.entries(bodyValue)) {
    const child = schema.fields[key];
    if (child !== ANY) validateNestedBody(value, child, `${label}.${key}`);
  }
}

function validateCustomerChatSelection(value) {
  const keys = Object.keys(value).sort().join(',');
  if (typeof value.choiceId !== 'string' || !UUID.test(value.choiceId)) fail('customer choice identity invalid');
  if (keys === 'choiceId') return;
  if (keys === 'choiceId,intent' && value.intent === 'details') return;
  if (keys === 'choiceId,intent' && value.intent === 'order_details') return;
  if (keys === 'choiceId,intent' && ['address_checkout', 'address_edit'].includes(value.intent)) return;
  if (keys === 'choiceId,intent' && value.intent === 'cart_remove') return;
  if (keys === 'choiceId,intent,quantity' && ['cart_add', 'cart_update'].includes(value.intent)
    && Number.isInteger(value.quantity) && value.quantity >= 1 && value.quantity <= 99) return;
  fail('customer choice intent invalid');
}

function validateRoleAssistantSelection(value, role) {
  const keys = Object.keys(value).sort().join(',');
  if (typeof value.choiceId !== 'string' || !UUID.test(value.choiceId)) fail('role choice identity invalid');
  if (keys === 'choiceId') return;
  if (role === 'merchant' && keys === 'choiceId,intent'
    && ['product_details', 'listing_rewrite', 'listing_optimize', 'manual_search', 'mail_list', 'mail_detail', 'mail_send', 'mail_reply'].includes(value.intent)) return;
  if (role === 'merchant' && keys === 'choiceId,competitorUrl,intent'
    && value.intent === 'pricing_compare') {
    try { validateCompetitorUrl(value.competitorUrl); return; }
    catch { fail('role pricing comparison URL invalid'); }
  }
  if (role === 'merchant' && keys === 'choiceId,intent'
    && ['review_details', 'review_approve', 'review_reject'].includes(value.intent)) return;
  if (role === 'admin' && value.choiceId === value.choiceId.toLowerCase()
    && keys === 'choiceId,intent' && ['user_ban', 'user_password_reset'].includes(value.intent)) return;
  if (role === 'admin' && value.choiceId === value.choiceId.toLowerCase()
    && keys === 'choiceId,intent' && ['policy_detail', 'policy_edit', 'policy_preview', 'policy_delete'].includes(value.intent)) return;
  if (role === 'admin' && value.choiceId === value.choiceId.toLowerCase()
    && keys === 'choiceId,intent' && ['mcp_detail', 'mcp_retire'].includes(value.intent)) return;
  if (role === 'admin' && value.choiceId === value.choiceId.toLowerCase()
    && keys === 'choiceId,intent' && ['acl_allow', 'acl_deny'].includes(value.intent)) return;
  if (role === 'admin' && value.choiceId === value.choiceId.toLowerCase()
    && keys === 'choiceId,intent,newRole' && value.intent === 'user_role'
    && ['customer', 'merchant', 'admin'].includes(value.newRole)) return;
  fail('role choice intent invalid');
}

function freezeDeep(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

export function compileOperation(name, input = {}) {
  if (typeof name !== 'string' || !Object.hasOwn(OPERATIONS, name)) fail('unknown operation');
  const clean = cloneBoundedJson(input);
  assertExactKeys(clean, ['params', 'query', 'body'], 'input envelope');
  if (['agent.customer.filePathSummary.capability','agent.customer.filePathSummary.request','agent.customer.filePathSummary.assessment','agent.customer.fileSummary.capability','agent.customer.fileSummary.request','agent.customer.fileSummary.assessment','agent.customer.filePathSummary.request','agent.customer.filePathSummary.assessment'].includes(name)
    && clean.body !== undefined) fail('File-summary GET body forbidden');
  if(name==='agent.merchant.assistant.mailReadAssessment'&&clean.body!==undefined)fail('Mail-read assessment GET body forbidden');

  const spec = OPERATIONS[name];
  const params = clean.params === undefined ? Object.create(null) : clean.params;
  const query = clean.query === undefined ? Object.create(null) : clean.query;
  assertExactKeys(params, spec.params, 'params');
  assertExactKeys(query, spec.query, 'query');

  if(name==='merchant.listings.rewriteSaved') {
    const keys=Object.keys(query).sort().join(',');
    if(!['rewriteOperationId','proposalId,requestId,sessionId'].includes(keys)||Object.values(query).some(value=>typeof value!=='string'||!UUID.test(value))) fail('Saved listing source invalid');
  }
  let path = spec.path;
  for (const param of spec.params) {
    if (!Object.hasOwn(params, param)) fail(`missing path parameter ${param}`);
    path = path.replace(`:${param}`, compileSegment(params[param], param));
  }
  if (['agent.admin.assistant.mcpManifestAssessment', 'agent.admin.assistant.mcpDiscoveryAssessment',
    'agent.admin.assistant.systemDiagnosticAssessment'].includes(name)
    && spec.params.some(param => typeof params[param] !== 'string' || !UUID.test(params[param])))
    fail('Saved assessment source invalid');
  if (name === 'agent.admin.chat.descriptionAssessment'
    && (!UUID.test(params.sessionId || '') || !UUID.test(params.requestId || '')
      || params.sessionId !== params.sessionId.toLowerCase()
      || params.requestId !== params.requestId.toLowerCase())) fail('Saved description assessment source invalid');
  if (name === 'agent.admin.assistant.systemRestartAssessment'
    && (!UUID.test(params.sessionId || '') || !UUID.test(params.requestId || '')
      || params.sessionId !== params.sessionId.toLowerCase()
      || params.requestId !== params.requestId.toLowerCase())) fail('Saved restart assessment source invalid');
  if (name === 'agent.customer.agencyRoleAssessment'
    && [params.sessionId, params.requestId].some(value => typeof value !== 'string' || !UUID.test(value)))
    fail('Saved role assessment source invalid');
  if (name === 'agent.customer.searchEchoAssessment'
    && (!UUID.test(params.sessionId || '') || !UUID.test(params.requestId || '')
      || typeof params.step !== 'string' || !/^[1-4]$/.test(params.step)))
    fail('Search echo assessment source invalid');
  if (['agent.customer.couponProbe.operation', 'agent.customer.couponProbe.assessment'].includes(name)
    && (!UUID.test(params.sessionId || '') || !UUID.test(params.requestId || '')
      || params.sessionId !== params.sessionId.toLowerCase()
      || params.requestId !== params.requestId.toLowerCase())) fail('Coupon probe source invalid');
  if (['agent.customer.productSearch.operation', 'agent.customer.productSearch.assessment',
    'agent.customer.orderStatus.operation', 'agent.customer.orderStatus.assessment',
    'agent.customer.checkoutAudit.operation', 'agent.customer.checkoutAudit.assessment'].includes(name)
    && (!UUID.test(params.sessionId || '') || !UUID.test(params.requestId || '')
      || params.sessionId !== params.sessionId.toLowerCase()
      || params.requestId !== params.requestId.toLowerCase())) fail('Product-search lesson source invalid');
  if (['agent.customer.avatarTraversal.request','agent.customer.avatarTraversal.assessment','agent.customer.avatarUpload.request','agent.customer.avatarUpload.operation','agent.customer.avatarUpload.asset','agent.customer.avatarUpload.assessment','agent.customer.avatarUpload.svgAssessment','agent.customer.avatarUpload.polyglotPreviewSaved','agent.customer.avatarUpload.polyglotAssessment','agent.customer.fileSummary.request','agent.customer.fileSummary.assessment','agent.customer.filePathSummary.request','agent.customer.filePathSummary.assessment'].includes(name)
    && Object.values(params).some(value=>typeof value!=='string'||!UUID.test(value)||value!==value.toLowerCase()))
    fail('Avatar upload source invalid');
  if(name==='agent.merchant.assistant.mailReadAssessment'
    &&(!UUID.test(params.sessionId||'')||!UUID.test(params.requestId||'')
      ||params.sessionId!==params.sessionId.toLowerCase()||params.requestId!==params.requestId.toLowerCase()))fail('Mail-read assessment source invalid');
  if (['catalog.product.summarySaved', 'agent.customer.productSummary.assessment'].includes(name)
    && [params.sessionId, params.requestId].some(value => typeof value !== 'string' || !UUID.test(value) || value !== value.toLowerCase()))
    fail('Product summary source invalid');
  if (name === 'catalog.product.similarSaved'
    && (!UUID.test(params.sessionId || '') || !UUID.test(params.requestId || '')))
    fail('Saved similar-products source invalid');

  if (['lab.policyHtml.request', 'lab.policyHtml.assessment'].includes(name)
    && spec.params.some(key => !UUID.test(params[key] || ''))) fail('Policy output source invalid');
  const queryParts = [];
  for (const key of spec.query) {
    if (!Object.hasOwn(query, key) || query[key] === undefined) continue;
    const value = query[key];
    if (!['string', 'number', 'boolean'].includes(typeof value) || (typeof value === 'number' && !Number.isFinite(value))) {
      fail(`query value ${key} must be a string, boolean, or finite number`);
    }
    queryParts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
  }
  if (queryParts.length) path += `?${queryParts.join('&')}`;

  const result = { path, method: spec.method, responseKind: spec.responseKind };
  if (spec.body) {
    if (name === 'agent.customer.checkoutAudit.session' && clean.body === undefined)
      fail('Checkout audit session body required');
    const bodyValue = clean.body === undefined ? Object.create(null) : clean.body;
    assertExactKeys(bodyValue, spec.body.keys, 'body');
    if (spec.requiredBody && spec.body.keys.some(key => !Object.hasOwn(bodyValue, key))) fail('body is missing a required key');
    if (name === 'lab.policyHtml.run' && (!UUID.test(bodyValue.request_id || '')
      || typeof bodyValue.policy_html !== 'string' || !bodyValue.policy_html.trim()
      || !bodyValue.policy_html.isWellFormed() || bodyValue.policy_html.includes('\0')
      || new TextEncoder().encode(bodyValue.policy_html).byteLength > 8192)) fail('Policy HTML request invalid');
    if (name === 'lab.policyHtml.assess'
      && [bodyValue.session_id, bodyValue.request_id].some(value => !UUID.test(value || '')))
      fail('Policy output assessment source invalid');
    if (['agent.admin.assistant.mcpManifestAssess', 'agent.admin.assistant.mcpDiscoveryAssess',
      'agent.admin.assistant.systemDiagnosticAssess'].includes(name)
      && spec.body.keys.some(key => typeof bodyValue[key] !== 'string' || !UUID.test(bodyValue[key])))
      fail('Assessment source invalid');
    if (name === 'agent.admin.chat.descriptionAssess'
      && (!UUID.test(bodyValue.sessionId || '') || !UUID.test(bodyValue.requestId || '')
        || bodyValue.sessionId !== bodyValue.sessionId.toLowerCase()
        || bodyValue.requestId !== bodyValue.requestId.toLowerCase())) fail('Description assessment source invalid');
    if (name === 'agent.admin.assistant.systemRestartAssess'
      && (!UUID.test(bodyValue.sessionId || '') || !UUID.test(bodyValue.requestId || '')
        || bodyValue.sessionId !== bodyValue.sessionId.toLowerCase()
        || bodyValue.requestId !== bodyValue.requestId.toLowerCase())) fail('Restart assessment source invalid');
    if (name === 'agent.customer.searchEchoAssess'
      && (!UUID.test(bodyValue.sessionId || '') || !UUID.test(bodyValue.requestId || '')
        || !Number.isInteger(bodyValue.step) || bodyValue.step < 1 || bodyValue.step > 4))
      fail('Search echo assessment source invalid');
    if (['agent.customer.couponProbe.run', 'agent.customer.couponProbe.assess'].includes(name)
      && (!UUID.test(bodyValue.sessionId || '') || !UUID.test(bodyValue.requestId || '')
        || bodyValue.sessionId !== bodyValue.sessionId.toLowerCase()
        || bodyValue.requestId !== bodyValue.requestId.toLowerCase())) fail('Coupon probe source invalid');
    if (['agent.customer.productSearch.run', 'agent.customer.productSearch.assess',
      'agent.customer.orderStatus.run', 'agent.customer.orderStatus.assess',
      'agent.customer.checkoutAudit.assess','agent.customer.avatarTraversal.assess','agent.customer.avatarUpload.assess','agent.customer.avatarUpload.svgAssess','agent.customer.avatarUpload.polyglotPreview','agent.customer.avatarUpload.polyglotAssess','agent.customer.fileSummary.assess','agent.customer.filePathSummary.run','agent.customer.filePathSummary.assess'].includes(name)
      && (!UUID.test(bodyValue.sessionId || '') || !UUID.test(bodyValue.requestId || '')
        || bodyValue.sessionId !== bodyValue.sessionId.toLowerCase()
        || bodyValue.requestId !== bodyValue.requestId.toLowerCase())) fail('Product-search lesson source invalid');
    if (name === 'agent.customer.filePathSummary.run'
      && (typeof bodyValue.message !== 'string' || !bodyValue.message.trim()
        || !bodyValue.message.isWellFormed() || bodyValue.message.includes('\0')
        || new TextEncoder().encode(bodyValue.message).byteLength > 8192
        || typeof bodyValue.path !== 'string' || !bodyValue.path.trim()
        || !bodyValue.path.isWellFormed() || bodyValue.path.startsWith('/')
        || /^[A-Za-z]:/.test(bodyValue.path) || /[\\\0\r\n]/.test(bodyValue.path)
        || new TextEncoder().encode(bodyValue.path).byteLength > 4096)) fail('File-path summary input invalid');
    if (name === 'agent.customer.couponProbe.run'
      && (bodyValue.protocol !== undefined
        && !['guided-boolean-v1', 'guided-boolean-v2'].includes(bodyValue.protocol)
        || typeof bodyValue.message !== 'string' || !bodyValue.message.trim()
        || !bodyValue.message.isWellFormed() || bodyValue.message.includes('\0')
        || new TextEncoder().encode(bodyValue.message).byteLength > 8192)) fail('Coupon probe message invalid');
    if (name === 'agent.customer.productSearch.run'
      && (typeof bodyValue.message !== 'string' || !bodyValue.message.trim()
        || !bodyValue.message.isWellFormed() || bodyValue.message.includes('\0')
        || new TextEncoder().encode(bodyValue.message).byteLength > 8192)) fail('Product-search lesson message invalid');
    if (name === 'agent.customer.orderStatus.run'
      && (typeof bodyValue.message !== 'string' || !bodyValue.message.trim()
        || !bodyValue.message.isWellFormed() || bodyValue.message.includes('\0')
        || new TextEncoder().encode(bodyValue.message).byteLength > 8192)) fail('Order-status lesson message invalid');
    if (name === 'agent.customer.checkoutAudit.practiceToken'
      && (!UUID.test(bodyValue.checkoutOperationId || '')
        || bodyValue.checkoutOperationId !== bodyValue.checkoutOperationId.toLowerCase()))
      fail('Checkout audit operation invalid');
    if (name === 'agent.customer.checkoutAudit.chat'
      && (![bodyValue.sessionId,bodyValue.requestId,bodyValue.checkoutOperationId]
        .every(value => typeof value === 'string' && UUID.test(value)
          && value === value.toLowerCase())
        || typeof bodyValue.teachingToken !== 'string' || !bodyValue.teachingToken
        || !bodyValue.teachingToken.isWellFormed()
        || new TextEncoder().encode(bodyValue.teachingToken).byteLength > 4096
        || typeof bodyValue.message !== 'string' || !bodyValue.message.trim()
        || !bodyValue.message.isWellFormed() || bodyValue.message.includes('\0')
        || new TextEncoder().encode(bodyValue.message).byteLength > 8192))
      fail('Checkout audit chat invalid');
    if(name==='agent.merchant.assistant.mailReadAssess'
      &&(!UUID.test(bodyValue.sessionId||'')||!UUID.test(bodyValue.requestId||'')
        ||bodyValue.sessionId!==bodyValue.sessionId.toLowerCase()||bodyValue.requestId!==bodyValue.requestId.toLowerCase()))fail('Mail-read assessment source invalid');
    if (['catalog.product.summary', 'agent.customer.productSummary.assess'].includes(name)
      && [bodyValue.sessionId, bodyValue.requestId].some(value => typeof value !== 'string' || !UUID.test(value) || value !== value.toLowerCase()))
      fail('Product summary source invalid');
    if (name === 'catalog.product.similarRun'
      && (!UUID.test(bodyValue.sessionId || '') || !UUID.test(bodyValue.requestId || '')))
      fail('Similar-products source invalid');
    for (const [key, nestedSchema] of Object.entries(spec.body.nested || {})) {
      if (Object.hasOwn(bodyValue, key)) validateNestedBody(bodyValue[key], nestedSchema, `body.${key}`);
    }
    if (name.startsWith('merchant.listings.') && Object.hasOwn(bodyValue, 'chatSource')) {
      const source=bodyValue.chatSource;
      if (Object.keys(source).sort().join(',') !== 'proposalId,requestId,sessionId'
        || Object.values(source).some(value=>typeof value!=='string'||!UUID.test(value))) fail('Listings setup source invalid');
      if (['merchant.listings.assistWrite','merchant.listings.importBulk','merchant.listings.optimizeImages'].includes(name) && Object.keys(bodyValue).sort().join(',')!=='chatSource,operationId') fail('Listings setup cannot mix manual input fields');
      if (name==='merchant.listings.rewriteSave' && (Object.keys(bodyValue).sort().join(',')!=='chatSource,rewriteOperationId,saveOperationId'||![bodyValue.rewriteOperationId,bodyValue.saveOperationId].every(value=>typeof value==='string'&&UUID.test(value)))) fail('Listings setup save invalid');
    }
    if (name === 'agent.customer.chat' && Object.hasOwn(bodyValue, 'selection')) {
      validateCustomerChatSelection(bodyValue.selection);
    }
    if (Object.hasOwn(bodyValue, 'catalogContinuation')) {
      const continuation = bodyValue.catalogContinuation;
      if (!['agent.customer.chat', 'agent.merchant.assistant.chat'].includes(name)
        || Object.hasOwn(bodyValue, 'selection')
        || Object.hasOwn(bodyValue, 'orderContinuation')
        || Object.hasOwn(bodyValue, 'mailContinuation')
        || bodyValue.message !== 'Show more products'
        || Object.keys(continuation).sort().join(',') !== 'intent,sourceRequestId'
        || continuation.intent !== 'catalog_next'
        || typeof continuation.sourceRequestId !== 'string'
        || !UUID.test(continuation.sourceRequestId)
        || continuation.sourceRequestId !== continuation.sourceRequestId.toLowerCase()) {
        fail('catalog continuation invalid');
      }
    }
    if ((name === 'agent.merchant.assistant.chat' || name === 'agent.admin.assistant.chat')
      && Object.hasOwn(bodyValue, 'selection')) {
      validateRoleAssistantSelection(bodyValue.selection, name === 'agent.merchant.assistant.chat' ? 'merchant' : 'admin');
      if (name === 'agent.merchant.assistant.chat' && bodyValue.selection.intent === 'manual_search'
        && (typeof bodyValue.message !== 'string' || !bodyValue.message.trim()
          || !bodyValue.message.isWellFormed() || bodyValue.message.includes('\0')
          || new TextEncoder().encode(bodyValue.message).byteLength > 4096)) {
        fail('merchant manual query invalid');
      }
      if (name === 'agent.admin.assistant.chat' && bodyValue.selection.intent === 'user_ban'
        && (typeof bodyValue.message !== 'string' || !bodyValue.message.trim()
          || !bodyValue.message.isWellFormed()
          || new TextEncoder().encode(bodyValue.message).byteLength > 1024)) fail('admin ban reason invalid');
    }
    if (name === 'merchant.pricing.run' && Object.hasOwn(bodyValue, 'competitorUrl')) {
      if (Object.hasOwn(bodyValue, 'experiment')) fail('Pricing request variants conflict');
      try { validateCompetitorUrl(bodyValue.competitorUrl); }
      catch { fail('Pricing competitor URL invalid'); }
    }
    if ((name === 'agent.merchant.assistant.chat' || name === 'agent.admin.assistant.chat')
      && Object.hasOwn(bodyValue, 'orderContinuation')) {
      const continuation = bodyValue.orderContinuation;
      if (name !== 'agent.merchant.assistant.chat' || Object.hasOwn(bodyValue, 'selection')
        || bodyValue.message !== 'Show older orders'
        || Object.keys(continuation).sort().join(',') !== 'intent,sourceRequestId'
        || continuation.intent !== 'orders_next'
        || typeof continuation.sourceRequestId !== 'string'
        || !UUID.test(continuation.sourceRequestId)
        || continuation.sourceRequestId !== continuation.sourceRequestId.toLowerCase()) {
        fail('merchant order continuation invalid');
      }
    }
    if ((name === 'agent.merchant.assistant.chat' || name === 'agent.admin.assistant.chat')
      && Object.hasOwn(bodyValue, 'mailContinuation')) {
      const continuation = bodyValue.mailContinuation;
      if (name !== 'agent.merchant.assistant.chat' || Object.hasOwn(bodyValue, 'selection')
        || Object.hasOwn(bodyValue, 'orderContinuation')
        || bodyValue.message !== 'Show older mail'
        || Object.keys(continuation).sort().join(',') !== 'intent,sourceRequestId'
        || continuation.intent !== 'mail_next'
        || typeof continuation.sourceRequestId !== 'string'
        || !UUID.test(continuation.sourceRequestId)
        || continuation.sourceRequestId !== continuation.sourceRequestId.toLowerCase()) {
        fail('merchant mail continuation invalid');
      }
    }
    if (spec.body.emitEmpty || Object.keys(bodyValue).length) result.body = bodyValue;
  } else if (clean.body !== undefined) {
    assertExactKeys(clean.body, [], 'body');
  }
  return freezeDeep(result);
}

export function describeOperations() {
  const operations = Object.entries(OPERATIONS).map(([name, spec]) => Object.freeze({
    name,
    method: spec.method,
    pathTemplate: spec.path,
    params: spec.params,
    query: spec.query,
    body: spec.body ? spec.body.keys : Object.freeze([]),
    responseKind: spec.responseKind,
  }));
  return freezeDeep({ operations, separate: SEPARATE.slice() });
}

const routes = describeOperations().operations.map(spec => ({
  ...spec,
  segments: spec.pathTemplate.split('/'),
  literalCount: spec.pathTemplate.split('/').filter(part => !part.startsWith(':')).length,
})).sort((a, b) => b.literalCount - a.literalCount);

function matchOperation(pathname, method) {
  const segments = pathname.split('/');
  for (const route of routes) {
    if (route.method !== method || route.segments.length !== segments.length) continue;
    const params = Object.create(null);let matches = true;
    for (let index = 0; index < segments.length; index++) {
      const expected = route.segments[index];
      if (expected.startsWith(':')) {
        try { params[expected.slice(1)] = decodeURIComponent(segments[index]); } catch { fail(); }
      } else if (expected !== segments[index]) { matches = false;break; }
    }
    if (matches) return { route, params };
  }
  fail();
}

export function matchOperationRequest({ pathname, method, query = {}, body }) {
  const { route, params } = matchOperation(pathname, method);
  const input = { params, query, ...(body === undefined ? {} : { body }) };
  const compiled = compileOperation(route.name, input);
  if (compiled.path.split('?')[0] !== pathname) fail('noncanonical operation path');
  return { name: route.name, input };
}
