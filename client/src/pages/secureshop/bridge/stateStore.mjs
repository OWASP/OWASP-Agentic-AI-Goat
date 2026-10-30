import { decodePolicyFinalHtmlReference } from '../utils/policyFinalHtmlReference.mjs';
import { decodeCustomerFilePathSummaryReference } from '../utils/customerFilePathSummaryReference.mjs';
import { decodeCustomerAvatarTraversalReference, decodeCustomerAvatarTraversalAssessmentReference } from '../utils/customerAvatarTraversalReference.mjs';
import { decodeProductSummaryReferences } from '../utils/productSummaryReference.mjs';
import { decodeCustomerAvatarUploadReference } from '../utils/customerAvatarUploadReference.mjs';
import { decodeAccountAvatarPending } from '../utils/accountAvatarPendingReference.mjs';
import { decodeCustomerAvatarUploadAssessmentReference, decodeCustomerAvatarSvgAssessmentReference } from '../utils/customerAvatarUploadAssessmentReference.mjs';
import { decodeCustomerFileSummaryReference } from '../utils/customerFileSummaryReference.mjs';
import { decodeSearchEchoAssessmentReference } from '../utils/customerSearchEchoAssessmentReference.mjs';
import { decodeCouponReference } from '../utils/couponReference.mjs';
import { decodeCheckoutReference } from '../utils/checkoutReference.mjs';
import { decodeRefundReferences } from '../utils/refundReferences.mjs';
import { decodeCustomerChatReferences } from '../utils/customerChatReferences.mjs';
import { decodeProductSimilarReference } from '../utils/productSimilarReference.mjs';
import { decodeProductManualPendingReference } from '../utils/productManualPendingReference.mjs';
import { decodeReviewModerationReference } from '../utils/reviewModerationReference.mjs';
import { decodeCustomerIdorLessonReference } from '../utils/customerIdorLessonReference.mjs';
import { decodeCustomerCheckoutAuditReference } from '../utils/customerCheckoutAuditReference.mjs';
import { decodeCustomerCouponConfirmationReference } from '../utils/customerCouponConfirmationReference.mjs';
import { decodeCustomerCouponProbeReferences } from '../utils/customerCouponProbeReference.mjs';
import { decodeProductSearchReferences } from '../utils/customerProductSearchReference.mjs';
import { decodeOrderStatusReferences } from '../utils/customerOrderStatusReference.mjs';
import { decodeCustomerTicketConfirmationReference } from '../utils/customerTicketConfirmationReference.mjs';
import { decodeAdminTicketAssessmentReference } from '../utils/adminTicketAssessmentReference.mjs';
import { decodeAdminMcpManifestAssessmentReference } from '../utils/adminMcpManifestAssessmentReference.mjs';
import { decodeRoleAssistantReferences } from '../utils/roleAssistantReferences.mjs';
import { decodeAuditJobReference } from '../utils/auditJobReference.mjs';
import { decodeRegisteredAdminChatReference } from '../utils/registeredAdminChatReference.mjs';
import { decodeChatCartReference } from '../utils/chatCartReference.mjs';
import {decodeInventoryReference} from '../pages/merchant/inventoryReference.mjs';
import { decodeListingEditReference } from '../pages/merchant/listingEditOperation.mjs';
import { decodeListingCreateReference } from '../pages/merchant/listingCreateOperation.mjs';
import { decodePracticePaymentReference } from '../utils/practicePaymentOperation.mjs';
import { decodeAddressReference } from '../utils/addressSetupOperation.mjs';
import { decodeProfileReference } from '../utils/profileOperation.mjs';
import {decodeMailReferences} from './mailReferences.mjs';
import { decodeListingsReferences } from '../pages/merchant/listingsReferences.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_MCP_REGISTRY_KEY, SHOP_USER_ADMIN_KEY, SHOP_REVIEW_DECISION_KEY, SHOP_ACL_KEY, SHOP_PASSWORD_RESET_KEY, SHOP_PROMPT_POLICY_KEY, SHOP_SYSTEM_CONFIG_KEY, SHOP_SYSTEM_DIAGNOSTIC_KEY, SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY, SHOP_SYSTEM_RESTART_KEY, SHOP_SYSTEM_REBUILD_KEY, SHOP_ANALYTICS_KEY, SHOP_PRICING_KEY, SHOP_LISTINGS_KEY, SHOP_MAIL_KEY, SHOP_INVENTORY_KEY, SHOP_LISTING_EDIT_KEY, SHOP_LISTING_CREATE_KEY, SHOP_PRACTICE_PAYMENT_KEY, SHOP_ADDRESS_SETUP_KEY, SHOP_PROFILE_KEY, SHOP_COUPON_KEY, SHOP_CHECKOUT_KEY, SHOP_REFUND_KEY, SHOP_CUSTOMER_CHAT_KEY, SHOP_CUSTOMER_CHAT_COMPLETED_KEY, SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY, SHOP_CUSTOMER_COUPON_PROBE_KEY, SHOP_CUSTOMER_PRODUCT_SEARCH_KEY, SHOP_CUSTOMER_ORDER_STATUS_KEY, SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY, SHOP_ADMIN_TICKET_ASSESSMENT_KEY, SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY, SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY, SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY, SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_UPLOAD_KEY, SHOP_ACCOUNT_AVATAR_PENDING_KEY, SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY, SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY, SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY, SHOP_CUSTOMER_FILE_SUMMARY_KEY, SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY, SHOP_POLICY_FINAL_HTML_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY, SHOP_CUSTOMER_IDOR_KEY, SHOP_PRODUCT_SIMILAR_KEY, SHOP_PRODUCT_MANUAL_KEY, SHOP_PRODUCT_SUMMARY_KEY, SHOP_CHAT_CART_KEY, SHOP_AUDIT_JOB_KEY, SHOP_ROLE_ASSISTANT_KEY, SHOP_ROLE_ASSISTANT_COMPLETED_KEY, SHOP_REGISTERED_ADMIN_CHAT_KEY, SHOP_REGISTERED_ADMIN_COMPLETED_KEY } from '../utils/shopStorage.mjs';
import { decodePricingReferences } from '../pages/merchant/pricingOperation.mjs';
import { decodeAdminSystemDiagnosticReference } from '../utils/adminSystemDiagnosticReference.mjs';
import { decodeSystemConfigReferences } from '../pages/admin/systemConfigOperation.mjs';
import { SHOP_REVIEW_MODERATION_KEY } from '../utils/shopStorage.mjs';

const keys = [SHOP_TOKEN_KEY, SHOP_CART_KEY];
const encoder = new TextEncoder();
export function validateShopSnapshot(value) {
  if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new TypeError('Invalid shop state');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some(key => ![...keys, SHOP_REVIEW_MODERATION_KEY, SHOP_MCP_REGISTRY_KEY, SHOP_USER_ADMIN_KEY, SHOP_REVIEW_DECISION_KEY, SHOP_ACL_KEY, SHOP_PASSWORD_RESET_KEY, SHOP_PROMPT_POLICY_KEY, SHOP_SYSTEM_CONFIG_KEY, SHOP_SYSTEM_DIAGNOSTIC_KEY, SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY, SHOP_SYSTEM_RESTART_KEY, SHOP_SYSTEM_REBUILD_KEY, SHOP_ANALYTICS_KEY, SHOP_PRICING_KEY, SHOP_LISTINGS_KEY, SHOP_MAIL_KEY, SHOP_INVENTORY_KEY, SHOP_LISTING_EDIT_KEY, SHOP_LISTING_CREATE_KEY, SHOP_PRACTICE_PAYMENT_KEY, SHOP_ADDRESS_SETUP_KEY, SHOP_PROFILE_KEY, SHOP_COUPON_KEY, SHOP_CHECKOUT_KEY, SHOP_REFUND_KEY, SHOP_CUSTOMER_CHAT_KEY, SHOP_CUSTOMER_CHAT_COMPLETED_KEY, SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY, SHOP_CUSTOMER_COUPON_PROBE_KEY, SHOP_CUSTOMER_PRODUCT_SEARCH_KEY, SHOP_CUSTOMER_ORDER_STATUS_KEY, SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY, SHOP_ADMIN_TICKET_ASSESSMENT_KEY, SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY, SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY, SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY, SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_UPLOAD_KEY, SHOP_ACCOUNT_AVATAR_PENDING_KEY, SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY, SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY, SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY, SHOP_CUSTOMER_FILE_SUMMARY_KEY, SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY, SHOP_POLICY_FINAL_HTML_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY, SHOP_CUSTOMER_IDOR_KEY, SHOP_PRODUCT_SIMILAR_KEY, SHOP_PRODUCT_MANUAL_KEY, SHOP_PRODUCT_SUMMARY_KEY, SHOP_CHAT_CART_KEY, SHOP_AUDIT_JOB_KEY, SHOP_ROLE_ASSISTANT_KEY, SHOP_ROLE_ASSISTANT_COMPLETED_KEY, SHOP_REGISTERED_ADMIN_CHAT_KEY, SHOP_REGISTERED_ADMIN_COMPLETED_KEY].includes(key))) throw new TypeError('Invalid shop state');
  const copy = Object.create(null);
  for (const key of [...keys, ...[SHOP_REVIEW_MODERATION_KEY, SHOP_MCP_REGISTRY_KEY, SHOP_USER_ADMIN_KEY,SHOP_REVIEW_DECISION_KEY,SHOP_ACL_KEY, SHOP_PASSWORD_RESET_KEY, SHOP_PROMPT_POLICY_KEY, SHOP_SYSTEM_CONFIG_KEY, SHOP_SYSTEM_DIAGNOSTIC_KEY, SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY, SHOP_SYSTEM_RESTART_KEY, SHOP_SYSTEM_REBUILD_KEY, SHOP_ANALYTICS_KEY, SHOP_PRICING_KEY, SHOP_LISTINGS_KEY, SHOP_MAIL_KEY, SHOP_INVENTORY_KEY, SHOP_LISTING_EDIT_KEY, SHOP_LISTING_CREATE_KEY, SHOP_PRACTICE_PAYMENT_KEY, SHOP_ADDRESS_SETUP_KEY, SHOP_PROFILE_KEY, SHOP_COUPON_KEY, SHOP_CHECKOUT_KEY, SHOP_REFUND_KEY, SHOP_CUSTOMER_CHAT_KEY, SHOP_CUSTOMER_CHAT_COMPLETED_KEY, SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY, SHOP_CUSTOMER_COUPON_PROBE_KEY, SHOP_CUSTOMER_PRODUCT_SEARCH_KEY, SHOP_CUSTOMER_ORDER_STATUS_KEY, SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY, SHOP_ADMIN_TICKET_ASSESSMENT_KEY, SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY, SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY, SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY, SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_UPLOAD_KEY, SHOP_ACCOUNT_AVATAR_PENDING_KEY, SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY, SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY, SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY, SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY, SHOP_CUSTOMER_FILE_SUMMARY_KEY, SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY, SHOP_POLICY_FINAL_HTML_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY, SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY, SHOP_CUSTOMER_IDOR_KEY, SHOP_PRODUCT_SIMILAR_KEY, SHOP_PRODUCT_MANUAL_KEY, SHOP_PRODUCT_SUMMARY_KEY, SHOP_CHAT_CART_KEY, SHOP_AUDIT_JOB_KEY, SHOP_ROLE_ASSISTANT_KEY, SHOP_ROLE_ASSISTANT_COMPLETED_KEY, SHOP_REGISTERED_ADMIN_CHAT_KEY, SHOP_REGISTERED_ADMIN_COMPLETED_KEY].filter(key=>Object.hasOwn(descriptors,key))]) {
    const field = descriptors[key];
    if (!field || !Object.hasOwn(field, 'value') || (field.value !== null && typeof field.value !== 'string')) throw new TypeError('Invalid shop state');
    const limit = [SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY, SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY].includes(key) ? 640 : key === SHOP_PRODUCT_SUMMARY_KEY ? 16384 : key === SHOP_AUDIT_JOB_KEY ? 1024 : key === SHOP_TOKEN_KEY ? 8192 : (key === SHOP_MCP_REGISTRY_KEY || key === SHOP_USER_ADMIN_KEY || key === SHOP_ACL_KEY || key === SHOP_PASSWORD_RESET_KEY || key === SHOP_PROMPT_POLICY_KEY || key === SHOP_PRICING_KEY || key === SHOP_LISTINGS_KEY || key === SHOP_MAIL_KEY || key === SHOP_INVENTORY_KEY || key === SHOP_LISTING_EDIT_KEY || key === SHOP_LISTING_CREATE_KEY || key === SHOP_PRACTICE_PAYMENT_KEY || key === SHOP_ADDRESS_SETUP_KEY || key === SHOP_PROFILE_KEY || key === SHOP_COUPON_KEY || key === SHOP_CHECKOUT_KEY || key === SHOP_REFUND_KEY || key === SHOP_CUSTOMER_CHAT_KEY || key === SHOP_CUSTOMER_CHAT_COMPLETED_KEY || key === SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY || key === SHOP_CUSTOMER_COUPON_PROBE_KEY || key === SHOP_CUSTOMER_PRODUCT_SEARCH_KEY || key === SHOP_CUSTOMER_ORDER_STATUS_KEY || key === SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY || key === SHOP_ADMIN_TICKET_ASSESSMENT_KEY || key === SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY || key === SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY || key === SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY || key === SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY || key === SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY || key === SHOP_CUSTOMER_AVATAR_UPLOAD_KEY || key === SHOP_ACCOUNT_AVATAR_PENDING_KEY || key === SHOP_CUSTOMER_IDOR_KEY || key === SHOP_PRODUCT_SIMILAR_KEY || key === SHOP_PRODUCT_MANUAL_KEY || key ===SHOP_CHAT_CART_KEY || key === SHOP_ROLE_ASSISTANT_KEY || key === SHOP_ROLE_ASSISTANT_COMPLETED_KEY || key === SHOP_REGISTERED_ADMIN_CHAT_KEY || key === SHOP_REGISTERED_ADMIN_COMPLETED_KEY) ? 8192 : ((key === SHOP_SYSTEM_CONFIG_KEY || key === SHOP_SYSTEM_DIAGNOSTIC_KEY || key === SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY || key === SHOP_SYSTEM_RESTART_KEY || key === SHOP_SYSTEM_REBUILD_KEY || key === SHOP_ANALYTICS_KEY) ? 4096 : 128 * 1024);
    if (field.value !== null && (field.value.length > limit || encoder.encode(field.value).byteLength > limit
      || (key === SHOP_REVIEW_MODERATION_KEY && encoder.encode(field.value).byteLength > 8192))) throw new TypeError('Shop state exceeds limit');
    if (key === SHOP_SYSTEM_CONFIG_KEY || key === SHOP_SYSTEM_DIAGNOSTIC_KEY || key === SHOP_SYSTEM_RESTART_KEY || key === SHOP_SYSTEM_REBUILD_KEY || key === SHOP_ANALYTICS_KEY) decodeSystemConfigReferences(field.value);
    if (key === SHOP_PRICING_KEY) decodePricingReferences(field.value);
    if (key === SHOP_LISTINGS_KEY) decodeListingsReferences(field.value);
    if (key === SHOP_MAIL_KEY) decodeMailReferences(field.value);
    if (key === SHOP_INVENTORY_KEY) decodeInventoryReference(field.value);
    if (key === SHOP_LISTING_EDIT_KEY) decodeListingEditReference(field.value);
    if (key === SHOP_LISTING_CREATE_KEY) decodeListingCreateReference(field.value);
    if (key === SHOP_PRACTICE_PAYMENT_KEY) decodePracticePaymentReference(field.value);
    if (key === SHOP_ADDRESS_SETUP_KEY) decodeAddressReference(field.value);
    if (key === SHOP_PROFILE_KEY) decodeProfileReference(field.value);
    if (key === SHOP_COUPON_KEY) decodeCouponReference(field.value);
    if (key === SHOP_CHECKOUT_KEY) decodeCheckoutReference(field.value);
    if (key === SHOP_REFUND_KEY) decodeRefundReferences(field.value);
    if (key === SHOP_CUSTOMER_CHAT_KEY) decodeCustomerChatReferences(field.value);
    if (key === SHOP_CUSTOMER_CHAT_COMPLETED_KEY) decodeCustomerChatReferences(field.value);
    if (key === SHOP_CUSTOMER_COUPON_CONFIRMATION_KEY) decodeCustomerCouponConfirmationReference(field.value);
    if (key === SHOP_CUSTOMER_COUPON_PROBE_KEY) decodeCustomerCouponProbeReferences(field.value);
    if (key === SHOP_CUSTOMER_PRODUCT_SEARCH_KEY) decodeProductSearchReferences(field.value);
    if (key === SHOP_CUSTOMER_ORDER_STATUS_KEY) decodeOrderStatusReferences(field.value);
    if (key === SHOP_CUSTOMER_TICKET_CONFIRMATION_KEY) decodeCustomerTicketConfirmationReference(field.value);
    if (key === SHOP_ADMIN_TICKET_ASSESSMENT_KEY) decodeAdminTicketAssessmentReference(field.value);
    if (key === SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY) decodeAdminMcpManifestAssessmentReference(field.value);
    if (key === SHOP_ADMIN_DIAGNOSTIC_CONFIRMATION_KEY) decodeAdminSystemDiagnosticReference(field.value);
    if (key === SHOP_CUSTOMER_SEARCH_ECHO_ASSESSMENT_KEY) decodeSearchEchoAssessmentReference(field.value);
    if (key === SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY || key === SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY) decodeCustomerCheckoutAuditReference(field.value);
    if (key === SHOP_CUSTOMER_AVATAR_UPLOAD_KEY) decodeCustomerAvatarUploadReference(field.value);
    if (key === SHOP_ACCOUNT_AVATAR_PENDING_KEY) decodeAccountAvatarPending(field.value);
    if (key === SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY) decodeCustomerAvatarUploadAssessmentReference(field.value);
    if (key === SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY) decodeCustomerAvatarSvgAssessmentReference(field.value);
    if (key === SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY || key === SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY) decodeCustomerAvatarUploadAssessmentReference(field.value);
    if (key === SHOP_POLICY_FINAL_HTML_KEY) decodePolicyFinalHtmlReference(field.value);
    if (key === SHOP_CUSTOMER_FILE_PATH_SUMMARY_KEY || key === SHOP_CUSTOMER_FILE_PATH_SUMMARY_ASSESSMENT_KEY) decodeCustomerFilePathSummaryReference(field.value);
    if (key === SHOP_CUSTOMER_FILE_SUMMARY_KEY || key === SHOP_CUSTOMER_FILE_SUMMARY_ASSESSMENT_KEY) decodeCustomerFileSummaryReference(field.value);
    if (key === SHOP_CUSTOMER_IDOR_KEY) decodeCustomerIdorLessonReference(field.value);
    if (key === SHOP_PRODUCT_SIMILAR_KEY) decodeProductSimilarReference(field.value);
    if (key === SHOP_PRODUCT_MANUAL_KEY) decodeProductManualPendingReference(field.value);
    if (key === SHOP_REVIEW_MODERATION_KEY) decodeReviewModerationReference(field.value);
    if (key === SHOP_PRODUCT_SUMMARY_KEY) decodeProductSummaryReferences(field.value);
    if (key === SHOP_CUSTOMER_AVATAR_TRAVERSAL_KEY) decodeCustomerAvatarTraversalReference(field.value);
    if (key === SHOP_CUSTOMER_AVATAR_TRAVERSAL_ASSESSMENT_KEY) decodeCustomerAvatarTraversalAssessmentReference(field.value);
    if (key === SHOP_CHAT_CART_KEY) decodeChatCartReference(field.value);
    if (key === SHOP_ROLE_ASSISTANT_KEY || key === SHOP_ROLE_ASSISTANT_COMPLETED_KEY) decodeRoleAssistantReferences(field.value);
    if (key === SHOP_AUDIT_JOB_KEY) decodeAuditJobReference(field.value);
    if (key === SHOP_REGISTERED_ADMIN_CHAT_KEY || key === SHOP_REGISTERED_ADMIN_COMPLETED_KEY) decodeRegisteredAdminChatReference(field.value);
    copy[key] = field.value;
  }
  return copy;
}

// Scope and generation come from verified parent launch authority, never child
// messages. This adapter is synchronous: a successful replace means the backing
// storage completed its write. Failure is not silently converted into memory.
export function createScopedShopStateStore({ storage, scenarioId, generation, isCurrent, canRetire = () => false }) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(scenarioId)
    || !Number.isSafeInteger(generation) || generation < 1 || typeof isCurrent !== 'function'
    || typeof canRetire !== 'function' || typeof storage?.getItem !== 'function' || typeof storage?.setItem !== 'function') throw new TypeError('Trusted shop state dependencies required');
  const storageKey = `owasp-ai-goat:secureshop:${scenarioId.toLowerCase()}:${generation}`;
  let closed = false;
  const assertCurrent = () => { if (closed || isCurrent() !== true) throw new DOMException('Shop state is stale', 'AbortError'); };
  return Object.freeze({
    read() {
      assertCurrent();
      const raw = storage.getItem(storageKey);
      if (raw !== null && (typeof raw !== 'string' || raw.length > 6 * (16384 + 256 * 1024) + 128)) throw new TypeError('Invalid persisted shop state');
      const state = raw === null ? validateShopSnapshot({[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null}) : validateShopSnapshot(JSON.parse(raw));
      assertCurrent();return state;
    },
    replace(snapshot) {
      assertCurrent();const state = validateShopSnapshot(snapshot);assertCurrent();
      storage.setItem(storageKey, JSON.stringify(state));
      // A callback-backed adapter may revoke authority during a write. Never
      // acknowledge that write as current after the authority has changed.
      assertCurrent();
    },
    // Parent lifecycle only; never a frame operation. The callback must verify
    // durable reset/revocation cleanup for this exact scenario and generation.
    retire() {
      if (canRetire() !== true || typeof storage.removeItem !== 'function') throw new Error('Shop state cleanup is not confirmed');
      storage.removeItem(storageKey);closed = true;
    },
    close() { closed = true; },
  });
}
