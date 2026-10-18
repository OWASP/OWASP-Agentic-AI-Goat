'use strict';
const {captureFeatureMode,guardFeatureFence,POLICIES}=require('./secureshopFeatureModeAuthority');
const { CART_QUANTITY_LIMIT_REJECTED, EMPTY_CART_REJECTED, CART_STOCK_REJECTED, normalizeOrderProductName } = require('../database/postgres/secureshopBoundCommerceRepository');
const { createConversationBinding, createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function failure(code, message) {
  return Object.assign(new Error(message), { code });
}

function createSecureShopBoundCommerce({ repository, catalog, personaAuthority, personaRepository, resolveExistingTarget, couponWorkflow, withSelectedSceneEffect, mode = 'vuln', modeAuthority } = {}) {
  const methods = ['listCart', 'addCart', 'updateCart', 'removeCart', 'checkout', 'listOrders', 'getOrder'];
  if (methods.some(name => typeof repository?.[name] !== 'function')
      || typeof catalog?.hasProduct !== 'function'
      || typeof catalog?.prepareTarget !== 'function') {
    throw new TypeError('Bound commerce dependencies required');
  }

  if (personaAuthority !== undefined && typeof personaAuthority?.capture !== 'function') {
    throw new TypeError('Bound commerce persona authority required');
  }
  async function execute(input, operation, requireProduct = false, apiEmpty, mutation = false, role = 'customer', validate, existingOnly = false, beforeEffect, confirmed) {
    if (input?.persona?.role !== role || !Number.isSafeInteger(input.persona.id)) {
      throw failure('OWNER_MISMATCH', `${role} persona required`);
    }
    const binding = createConversationBinding(input.scope, input.persona);
    const originalToken=(token,featureId)=>{
      if(typeof modeAuthority?.assertToken!=='function')throw failure('COMMERCE_MODE_CHANGED','Coupon mode unavailable');
      const owned=modeAuthority.assertToken(token),s=owned.snapshot;
      if(s?.featureId!==featureId||s.policyVersion!==POLICIES[featureId]
        ||!['vuln','fixed'].includes(s.mode)||JSON.stringify(s.scope)!==JSON.stringify(createLaunchScope(binding))
        ||typeof owned.assertCurrent!=='function'||typeof owned.assertCurrentAtEffect!=='function')
        throw failure('COMMERCE_MODE_CHANGED','Coupon mode unavailable');
      return owned;
    };
    const modeToken = confirmed?originalToken(confirmed.couponMode,'coupons')
      :await captureFeatureMode(modeAuthority,binding,'coupons',mode);
    const customerToken=confirmed?originalToken(confirmed.customerMode,'customer_chat'):null;
    if(confirmed){
      if(typeof confirmed.checkCurrent!=='function'||!confirmed.expectedTarget
        ||['targetId','sceneId','grantId'].some(key=>!UUID.test(confirmed.expectedTarget[key]||''))
        ||!Number.isSafeInteger(confirmed.expectedTarget.sceneGeneration)
        ||confirmed.expectedTarget.sceneGeneration<1)throw failure('SHOP_SCENE_STALE','Coupon scene unavailable');
      await confirmed.checkCurrent();
    }
    const request = Object.freeze({ ...input, scope: binding, mode: modeToken.snapshot.mode,
      persona: Object.freeze({ id: binding.shopUserId, role: binding.role }) });
    let fence;
    if (personaAuthority) {
      if (request.apiAuthority !== undefined) {
        fence = require('./secureshopBoundPersonaAuth').resolveBoundApiKeyAuthority(
          request.apiAuthority, { scope: binding, persona: request.persona });
      } else {
        const session = input.personaSession;
        if (typeof session?.sessionId !== 'string' || !UUID.test(session.sessionId)
            || typeof session.authorityVersion !== 'string' || !/^[1-9]\d*$/.test(session.authorityVersion)) {
          throw failure('SHOP_AUTH_INVALID', 'Commerce authority unavailable');
        }
        const credential = Object.freeze({ sessionId: session.sessionId.toLowerCase(),
          authorityVersion: session.authorityVersion });
        fence = await personaAuthority.capture({ scope: binding, personaId: binding.shopUserId,
          role: binding.role, ...credential });
        const actual = fence?.binding;
        if (typeof fence?.assertRemoteAdmission !== 'function' || typeof fence?.withCrossStoreEffect !== 'function' || !actual
            || ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']
              .some(key => actual[key] !== binding[key])
            || actual.personaId !== binding.shopUserId || actual.role !== binding.role
            || actual.sessionId !== credential.sessionId || actual.authorityVersion !== credential.authorityVersion) {
          throw failure('SHOP_AUTH_INVALID', 'Commerce authority unavailable');
        }
      }
      // The confirmed path retains the unwrapped persona fence. Its mode checks
      // run outside the selected-scene owner lease and at the review effect
      // boundary; the guarded wrapper may reacquire the identity owner lock.
      if(!confirmed)fence = guardFeatureFence(fence,modeToken);
      await fence.assertRemoteAdmission();
    }
    let target;
    if (existingOnly || (personaAuthority && request.apiAuthority !== undefined)) {
      // API order reads never provision a product target or initialize commerce.
      if ((!existingOnly && apiEmpty === undefined) || typeof resolveExistingTarget !== 'function') {
        throw failure('SHOP_API_KEY_INVALID', 'API read authority required');
      }
      const existing = await resolveExistingTarget(binding);
      await fence?.assertRemoteAdmission();
      if (!existing) {
        if (existingOnly) throw failure('PRODUCT_TARGET_UNAVAILABLE', 'Existing product target unavailable');
        return apiEmpty;
      }
      if (typeof existing.targetId !== 'string' || !UUID.test(existing.targetId)) {
        throw failure('PRODUCT_TARGET_UNAVAILABLE', 'Existing product target unavailable');
      }
      if (existing.scene !== undefined) {
        const execution = executionScope(existing);
        if (['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']
          .some(key => execution[key] !== binding[key])) {
          throw failure('PRODUCT_TARGET_UNAVAILABLE', 'Existing product target unavailable');
        }
        // Keep the resolver's private scene capability intact for the storage transaction.
        target = existing;
      } else {
        if (existing.kind !== 'products'
            || ['launchId', 'scenarioId', 'generation'].some(key => existing[key] !== binding[key])) {
          throw failure('PRODUCT_TARGET_UNAVAILABLE', 'Existing product target unavailable');
        }
        target = Object.freeze({ ...binding, targetId: existing.targetId.toLowerCase() });
      }
    } else {
      validate?.(request);
      target = await catalog.prepareTarget(fence ? { ...request, personaEffect:
        require('./secureshopPersonaProductEffect').createPersonaProductEffect(fence) } : request);
    }
    if (requireProduct && !await catalog.hasProduct(request)) {
      throw failure('INVALID_ARGUMENT', 'product unavailable');
    }
    if(confirmed){
      const expected=confirmed.expectedTarget;
      if(target?.targetId!==expected.targetId||target.scene?.sceneId!==expected.sceneId
        ||target.scene?.sceneGeneration!==expected.sceneGeneration
        ||target.scene?.grantId!==expected.grantId)throw failure('SHOP_SCENE_STALE','Coupon scene unavailable');
      await confirmed.checkCurrent();await customerToken.assertCurrent();
    }
    await fence?.assertRemoteAdmission();
    await modeToken.assertCurrent();
    const prepared = beforeEffect ? await beforeEffect(target, request, fence) : undefined;
    if (beforeEffect) { await fence?.assertRemoteAdmission(); await modeToken.assertCurrent(); }
    const result = fence && mutation
      ? await fence.withCrossStoreEffect(() => operation(target, request, fence, prepared))
      : await operation(target, request, fence, prepared);
    try { await modeToken.assertCurrent(); await customerToken?.assertCurrent(); await confirmed?.checkCurrent(); await fence?.assertRemoteAdmission(); }
    catch (cause) {
      if (!mutation && !confirmed) throw cause;
      const error = Object.assign(new Error('Commerce effect requires authoritative readback'),
        { code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', executionBoundary: true });
      Object.defineProperty(error, 'cause', { value: cause }); throw error;
    }
    return result;
  }

  return Object.freeze({
    async conversational(input) {
      const method=input?.method;
      const names=['search','details','resolveChoice','cartView','prepareCart','confirmCart','ordersList','orderDetails','addresses','addressChoices','addressForm','saveAddress','profileForm','saveProfile','paymentMethods','createPaymentMethod','prepareCheckout','confirmCheckout','readOperation','readTurnOperations'];
      if(!personaAuthority||!names.includes(method)||typeof repository.conversation?.[method]!=='function'||input.apiAuthority!==undefined)throw failure('SERVICE_UNAVAILABLE','Conversational commerce unavailable');
      const args=input.args;
      if(!args||Object.getPrototypeOf(args)!==Object.prototype)throw failure('INVALID_ARGUMENT','Conversational commerce request invalid');
      // Capture exact JSON arguments before target resolution or authority awaits.
      const captured=structuredClone(args);
      const expectedTarget=['profileForm','saveProfile'].includes(method)?input.expectedTarget:null;
      const expectedScopeKey=method==='saveProfile'?input.expectedScopeKey:null;
      if(expectedScopeKey!==undefined&&expectedScopeKey!==null
        &&(typeof expectedScopeKey!=='string'||!/^[a-f0-9]{64}$/.test(expectedScopeKey)))
        throw failure('INVALID_ARGUMENT','Profile scope unavailable');
      const credential=input?.personaSession;
      if(typeof credential?.sessionId!=='string'||!UUID.test(credential.sessionId)
        ||typeof credential.authorityVersion!=='string'||!/^[1-9]\d{0,18}$/.test(credential.authorityVersion))throw failure('SHOP_AUTH_INVALID','Commerce authority unavailable');
      const safeInput={...input,scope:createConversationBinding(input.scope,input.persona),
        persona:Object.freeze({id:input.persona.id,role:input.persona.role}),
        personaSession:Object.freeze({sessionId:credential.sessionId.toLowerCase(),authorityVersion:credential.authorityVersion})};
      const profileMethod=['profileForm','saveProfile'].includes(method);
      const assertExpectedTarget=target=>{
        if(expectedTarget&&(target.targetId!==expectedTarget.targetId
          ||target.scene?.sceneId!==expectedTarget.sceneId
          ||target.scene?.sceneGeneration!==expectedTarget.sceneGeneration
          ||target.scene?.grantId!==expectedTarget.grantId))
          throw failure('SHOP_SCENE_STALE','Profile scene unavailable');
      };
      const readCanonicalProfile=profileMethod?async(target,request,fence)=>{
          assertExpectedTarget(target);
          if(typeof personaRepository?.readPersona!=='function')throw failure('SERVICE_UNAVAILABLE','Profile authority unavailable');
          await fence.assertRemoteAdmission();
          const canonical=await personaRepository.readPersona(request.persona.id,request.scope);
          await fence.assertRemoteAdmission();
          if(!canonical||Number(canonical.id)!==request.persona.id)throw failure('SHOP_AUTH_INVALID','Profile authority unavailable');
          return require('./secureshopProfileUpdateContract').normalizeProfileView({
            fullName:canonical.full_name??null,email:canonical.email,phone:canonical.phone??null});
        }:undefined;
      return execute(safeInput,async(target,request,_fence,canonicalProfile)=>{
        assertExpectedTarget(target);
        return repository.conversation[method](target,{
          ...captured,...(canonicalProfile?{canonicalProfile}:{}),
          ...(expectedScopeKey?{expectedScopeKey}:{}),shopUserId:request.persona.id,
          personaSession:request.personaSession,mode:request.mode,
        });
      },false,undefined,!['readOperation','readTurnOperations','addressForm','profileForm'].includes(method),'customer',undefined,true,readCanonicalProfile);
    },
    couponAvailable: typeof couponWorkflow?.apply === 'function',
    async importGuestCart(input) {
      if (typeof repository.importGuestCart !== 'function') {
        throw failure('SERVICE_UNAVAILABLE', 'Guest cart import unavailable');
      }
      return execute(input, (target, request) => repository.importGuestCart(target, {
        shopUserId: request.persona.id, requestId: request.requestId,
        items: request.items, personaSession: request.personaSession,
      }), false, undefined, true, 'customer', request => {
        if (typeof request.requestId !== 'string' || !UUID.test(request.requestId)
            || !Array.isArray(request.items) || request.items.length < 1 || request.items.length > 50) {
          throw failure('INVALID_ARGUMENT', 'Guest cart import request invalid');
        }
      });
    },
    async merchantOrders(input) {
      if (typeof repository.listMerchantOrders !== 'function') throw failure('SERVICE_UNAVAILABLE', 'Merchant orders unavailable');
      const productName = normalizeOrderProductName(input.productName);
      return execute({ ...input, ...(productName === undefined ? {} : { productName }) }, (target, request) => repository.listMerchantOrders(target, request.persona.id, request.cursor,
        ...(productName === undefined ? [] : [request.productName])),
        false, undefined, false, 'merchant', undefined, true);
    },
    async merchantOrder(input) {
      if (typeof repository.getMerchantOrder !== 'function') throw failure('SERVICE_UNAVAILABLE', 'Merchant orders unavailable');
      return execute(input, (target, request) => repository.getMerchantOrder(target,
        { merchantId: request.persona.id, orderId: request.orderId }),
        false, undefined, false, 'merchant', undefined, true);
    },
    async merchantOverview(input) {
      if (typeof repository.merchantOverview !== 'function') throw failure('SERVICE_UNAVAILABLE', 'Merchant reporting unavailable');
      const { reportingWindow, projectMerchantMetrics } = require('./secureshopMerchantMetrics');
      const merchantId = input.persona.id;
      const window = reportingWindow(input.days ?? 30);
      const data = await execute(input, (target, request) => repository.merchantOverview(target, request.persona.id, window),
        false, undefined, false, 'merchant');
      return projectMerchantMetrics(data, window, merchantId);
    },
    async merchantTopProducts(input) {
      if (typeof repository.merchantOverview !== 'function') throw failure('SERVICE_UNAVAILABLE', 'Merchant reporting unavailable');
      const limit = input.limit ?? 8;
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50) throw failure('INVALID_ARGUMENT', 'Invalid merchant reporting limit');
      const window = require('./secureshopMerchantMetrics').reportingWindow(input.days ?? 30);
      const data = await execute(input, (target, request) => repository.merchantOverview(target, request.persona.id, window, limit),
        false, undefined, false, 'merchant');
      if (!Array.isArray(data.products) || data.products.length > limit) throw new Error('Invalid stored top products');
      const rows = data.products.map(row => {
        const id = Number(row.id), revenue = Number(row.revenue);
        if (!Number.isSafeInteger(id) || id < 1 || typeof row.name !== 'string'
            || row.revenue === null || !['string','number'].includes(typeof row.revenue)
            || (typeof row.revenue === 'string' && !row.revenue.trim())
            || !Number.isFinite(revenue) || revenue < 0) throw new Error('Invalid stored top product');
        return { id, name: row.name, revenue };
      });
      return { rows, periodDays: window.days, source: 'owned-commerce' };
    },
    async recommendations(input) {
      if (typeof repository.recommendations !== 'function') throw failure('SERVICE_UNAVAILABLE', 'Recommendations unavailable');
      return execute(input, (target, request) => repository.recommendations(target, request.persona.id));
    },
    async applyCoupon(input) {
      if(typeof couponWorkflow?.apply!=='function')throw failure('SERVICE_UNAVAILABLE','Bound coupon unavailable');
      return execute(input,(target,request,fence)=>couponWorkflow.apply({...request,target},{fence,signal:request.signal}));
    },
    async applyConfirmedCoupon(input) {
      if(typeof couponWorkflow?.applyConfirmed!=='function'||!personaAuthority
        ||typeof withSelectedSceneEffect!=='function'||input?.apiAuthority!==undefined)
        throw failure('SERVICE_UNAVAILABLE','Confirmed coupon unavailable');
      return execute(input,(target,request,fence)=>couponWorkflow.applyConfirmed({...request,target},
        {fence,signal:request.signal,customerMode:input.customerMode,couponMode:input.couponMode,
          checkCurrent:input.checkCurrent,
          withSelectedSceneEffect:work=>withSelectedSceneEffect({scope:request.scope,
            expectedTarget:input.expectedTarget},work)}),false,undefined,false,'customer',undefined,true,undefined,input);
    },
    async readConfirmedCoupon(input) {
      if(typeof couponWorkflow?.readConfirmed!=='function'||!personaAuthority
        ||typeof withSelectedSceneEffect!=='function'||input?.apiAuthority!==undefined)
        throw failure('SERVICE_UNAVAILABLE','Confirmed coupon unavailable');
      return execute(input,(target,request,fence)=>couponWorkflow.readConfirmed({...request,target},
        {fence,signal:request.signal,customerMode:input.customerMode,couponMode:input.couponMode,
          checkCurrent:input.checkCurrent,
          withSelectedSceneEffect:work=>withSelectedSceneEffect({scope:request.scope,
            expectedTarget:input.expectedTarget},work)}),false,undefined,false,'customer',undefined,true,undefined,input);
    },
    async cart(input) {
      return execute(input, async (target, request, fence) => {
        const result = await repository.listCart(target, request.persona.id, request.mode);
        // Opaque recovery identity derives only from verified server authority.
        if (!fence || request.apiAuthority !== undefined) return result;
        const couponScopeKey = require('node:crypto').createHash('sha256')
          .update(JSON.stringify({ authority: fence.binding, targetId: target.targetId, mode: request.mode })).digest('hex');
        return { ...result, couponScopeKey };
      });
    },
    async add(input) {
      const result = await execute(input, (target, request) => repository.addCart(target, {
        shopUserId: request.persona.id, productId: request.productId, quantity: request.quantity,
      }), true, undefined, true);
      // Reject only after the read-only transaction and authority post-checks succeed.
      // Exceptions still retain the shared cross-store uncertainty contract.
      if (result === CART_QUANTITY_LIMIT_REJECTED) throw failure('INVALID_ARGUMENT', 'quantity is invalid');
      return result;
    },
    async update(input) {
      return execute(input, (target, request) => repository.updateCart(target, {
        shopUserId: request.persona.id, cartItemId: request.cartItemId, quantity: request.quantity,
      }), false, undefined, true);
    },
    async remove(input) {
      return execute(input, (target, request) => repository.removeCart(target, {
        shopUserId: request.persona.id, cartItemId: request.cartItemId,
      }), false, undefined, true);
    },
    async summary(input) {
      return execute(input, async (target, request, fence) => {
        const result = await repository.listCart(target, request.persona.id, request.mode);
        // Opaque recovery identity derives only from verified server authority.
        if (!fence || request.apiAuthority !== undefined) return result;
        const couponScopeKey = require('node:crypto').createHash('sha256')
          .update(JSON.stringify({ authority: fence.binding, targetId: target.targetId, mode: request.mode })).digest('hex');
        return { ...result, couponScopeKey };
      });
    },
    async checkout(input) {
      const result = await execute(input, (target, request) => repository.checkout(target, {
        shopUserId: request.persona.id,
        shippingAddress: request.shippingAddress,
        paymentMethod: request.paymentMethod,
        operationId:request.operationId,persona:request.persona,personaSession:request.personaSession,mode:request.mode,
      }), false, undefined, true, 'customer', request => {
        for (const [key, maximum] of [['shippingAddress', 4096], ['paymentMethod', 256]]) {
          const value = request[key];
          if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value, 'utf8') > maximum) {
            throw failure('INVALID_ARGUMENT', `${key} is invalid`);
          }
        }
      });
      if (result === EMPTY_CART_REJECTED) throw failure('INVALID_ARGUMENT', 'cart is empty');
      if (result === CART_STOCK_REJECTED) throw failure('INVALID_ARGUMENT', 'cart contains unavailable stock');
      return result;
    },
    async checkoutHistory(input) {
      if (!personaAuthority || input.apiAuthority !== undefined || typeof repository.checkoutHistory !== 'function') {
        throw failure('SERVICE_UNAVAILABLE', 'Checkout history unavailable');
      }
      return execute(input, (target, request) => repository.checkoutHistory(target, request.persona.id),
        false, undefined, false, 'customer', undefined, true);
    },
    async checkoutReceipt(input) {
      if (!UUID.test(input.operationId || '')) throw failure('INVALID_ARGUMENT', 'Invalid checkout reference');
      if (!personaAuthority || input.apiAuthority !== undefined || typeof repository.checkoutReceipt !== 'function') {
        throw failure('SERVICE_UNAVAILABLE', 'Checkout history unavailable');
      }
      return execute(input, (target, request) => repository.checkoutReceipt(target, request.persona.id, request.operationId),
        false, undefined, false, 'customer', undefined, true);
    },
    async orders(input) {
      const productName = normalizeOrderProductName(input.productName);
      return execute({ ...input, ...(productName === undefined ? {} : { productName }) }, (target, request) => repository.listOrders(target, request.persona.id,
        ...(productName === undefined ? [] : [request.productName])), false, []);
    },
    async order(input) {
      return execute(input, (target, request) => repository.getOrder(target, {
        shopUserId: request.persona.id, orderId: request.orderId,
      }), false, null);
    },
  });
}

module.exports = { createSecureShopBoundCommerce };
