'use strict';

const { createLaunchScope } = require('./secureshopConversationBinding');
const { copySceneBinding, executionScope } = require('./secureshopSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ROLES = new Set(['customer', 'merchant', 'admin']);
const PRODUCT_SORT = new Set(['', 'newest', 'price_asc', 'price_desc', 'deals']);
const MERCHANT_SORT = new Set(['updated_desc', 'updated_asc', 'price_asc', 'price_desc',
  'name_asc', 'stock_desc', 'stock_asc']);
const MAX_SOURCE_PRODUCTS = 256;

function invalid(code = 'INVALID_ARGUMENT') {
  return Object.assign(new Error('Bound catalog request is invalid'), { code });
}
function persona(value, role) {
  if (!value || !Number.isSafeInteger(value.id) || value.id < 1 || !ROLES.has(value.role)
      || (role && value.role !== role)) throw invalid();
  return Object.freeze({ id: value.id, role: value.role });
}
function text(value, max = 1024) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > max) throw invalid();
  return value;
}
function count(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw invalid();
  return value;
}
function price(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 100000
      || Math.abs(value * 100 - Math.round(value * 100)) > 1e-8) throw invalid();
  return value;
}
function target(value, scope) {
  if (value?.scene !== undefined) {
    const execution = executionScope(value);
    if (Object.keys(scope).some(key => scope[key] !== execution[key])) throw invalid('PRODUCT_TARGET_UNAVAILABLE');
    return copySceneBinding(value, { ...createLaunchScope(value), targetId: value.targetId });
  }
  if (!value || value.kind !== 'products' || !UUID.test(value.targetId)
      || value.launchId !== scope.launchId || value.scenarioId !== scope.scenarioId
      || value.generation !== scope.generation) throw invalid('PRODUCT_TARGET_UNAVAILABLE');
  return Object.freeze({ targetId: value.targetId.toLowerCase(), ...scope });
}
function sourceProduct(row, ownMerchantId, sourceOwner) {
  const sourceRetailerId = Number(row.retailer_id);
  return Object.freeze({ id: Number(row.id), sourceRetailerId,
    retailerId: sourceRetailerId === sourceOwner ? ownMerchantId : sourceRetailerId,
    name: row.name, description: row.description, descriptionHtml: row.description_html,
    price: Number(row.price), category: row.category, imageUrl: row.image_url,
    images: Array.isArray(row.images) ? row.images : [], stockQuantity: Number(row.stock_quantity),
    status: row.status, templateSource: row.template_source,
    createdAt: row.created_at, updatedAt: row.updated_at });
}

// @intentional-vulnerability broken-access-inventory
// An explicit retailer_id may select a decoy merchant inside this launch's
// product target. Target scope remains server-owned, so the teaching IDOR
// never crosses platform learners or reaches shared mutable commerce rows.
function createSecureShopBoundCatalog({ sourcePool, repository, resolveTarget, checkCurrent,
  ownMerchantId = 12, personaAuthority, scenes, modeAuthority } = {}) {
  if (typeof sourcePool?.query !== 'function'
      || ['open', 'provision', 'list', 'get', 'categories', 'createListing', 'updateListing',
        'archiveListing'].some(name => typeof repository?.[name] !== 'function')
      || typeof resolveTarget !== 'function' || typeof checkCurrent !== 'function') {
    throw new TypeError('Bound catalog source, target, and launch authority required');
  }
  count(ownMerchantId, 1, 2147483647);
  if (scenes !== undefined && ['resolve','finalize'].some(key => typeof scenes?.[key] !== 'function')) throw TypeError('Scene resolver required');
  if(personaAuthority!==undefined&&typeof personaAuthority?.capture!=='function')throw TypeError('Catalog persona authority required');
  async function readSource(selectedMerchantId = ownMerchantId) {
    const rows = (await sourcePool.query(`SELECT p.id,p.name,p.description,p.description_html,p.price,
        p.category,p.image_url,p.stock_quantity,p.retailer_id,p.status,p.template_source,
        p.created_at,p.updated_at,u.role AS retailer_role,
        COALESCE(jsonb_agg(i.path ORDER BY i.id) FILTER (WHERE i.path IS NOT NULL),'[]'::jsonb) AS images
      FROM secureshop.products p
      JOIN secureshop.shop_users u ON u.id=p.retailer_id
      LEFT JOIN secureshop.product_images i ON i.product_id=p.id
      GROUP BY p.id,u.role ORDER BY p.id LIMIT $1`, [MAX_SOURCE_PRODUCTS + 1])).rows;
    if (!rows.length || rows.length > MAX_SOURCE_PRODUCTS) throw invalid('PRODUCT_SOURCE_UNAVAILABLE');
    const owners = [...new Set(rows.filter(row => ['merchant', 'retailer'].includes(row.retailer_role))
      .map(row => Number(row.retailer_id)).filter(id => Number.isSafeInteger(id) && id > 0 && id !== selectedMerchantId))]
      .sort((a, b) => a - b);
    if (owners.length < 2) throw invalid('PRODUCT_SOURCE_UNAVAILABLE');
    return Object.freeze(rows.map(row => sourceProduct(row, selectedMerchantId, owners[0])));
  }
  async function prepared(input) {
    if (scenes?.withProvisionLease) return scenes.withProvisionLease(input.scope, () => prepareLocked(input));
    return prepareLocked(input);
  }
  async function prepareLocked(input) {
    const scope = createLaunchScope(input.scope);
    const personaEffect=require('./secureshopPersonaProductEffect').assertPersonaProductEffect(input.personaEffect);await personaEffect?.check(scope);
    await checkCurrent(scope);
    let binding = target((scenes && await scenes.resolve(scope)) || await resolveTarget(scope), scope);await personaEffect?.check(scope);
    if(input.expectedScene){const expected=input.expectedScene.scene||input.expectedScene,actual=binding.scene;
      if(!actual||binding.targetId!==input.expectedScene.targetId||actual.sceneId!==expected.sceneId
        ||actual.sceneGeneration!==expected.sceneGeneration)throw invalid('SHOP_SCENE_STALE');}
    let opened = await repository.open(binding);
    const store = scenes?.store ? await scenes.store(scope) : null;
    const registeredMerchant = input.persona?.role === 'merchant' && input.persona.id >= 1000000000;
    const selectedMerchantId = store ? count(store.seedMerchantId, 1000000000, 2147483647)
      : registeredMerchant ? input.persona.id : ownMerchantId;
    if (!opened) {const source={ownMerchantId:selectedMerchantId,products:await readSource(selectedMerchantId)};opened=personaEffect?await personaEffect.provision(repository,binding,source):await repository.provision(binding,source);}
    if (!binding.scene && opened.ownMerchantId !== selectedMerchantId) throw invalid('PRODUCT_TARGET_MISMATCH');
    if (scenes && !binding.scene) binding = await scenes.finalize(scope, binding);
    if (store && registeredMerchant) binding = await scenes.merchant(binding, input.persona.id);
    await checkCurrent(scope);
    await personaEffect?.check(scope);
    return Object.freeze({ scope, binding, opened });
  }
  async function existingMerchantAction(input, keyFor = require('./secureshopListingEditContract').listingEditScopeKey) {
    const actor = persona(input.persona, 'merchant');
    const scope = createLaunchScope(input.scope);
    const effect = require('./secureshopPersonaProductEffect').assertPersonaProductEffect(input.personaEffect);
    await effect?.check(scope); await checkCurrent(scope);
    let binding = target((scenes && await scenes.resolve(scope)) || await resolveTarget(scope), scope);
    const opened = await repository.open(binding);
    if (!opened) throw invalid('PRODUCT_TARGET_UNAVAILABLE');
    if (scenes && actor.id >= 1000000000 && scenes.merchant) binding = await scenes.merchant(binding, actor.id);
    if (actor.id !== opened.ownMerchantId
        && !require('./secureshopSceneBinding').isSceneMerchant(binding, actor.id)) throw invalid('OWNER_MISMATCH');
    const key = keyFor(binding, actor.id, input.personaSession);
    await effect?.check(scope); await checkCurrent(scope);
    return Object.freeze({ actor, scope, binding, effect, key });
  }
  const service = {
    async provisionPracticeTarget(admission) {
      const { binding, ownMerchantId: merchantId } = require('../database/postgres/secureshopPracticeAdmissionRepository')
        .assertPracticeAdmission(admission);
      await checkCurrent(binding);
      let opened = await repository.open(binding);
      if (!opened) opened = await repository.provision(binding, {
        ownMerchantId: merchantId, products: await readSource(merchantId),
      });
      const verified = await repository.open(binding);
      await checkCurrent(binding);
      if (!verified || verified.ownMerchantId !== merchantId || verified.sourceSha256 !== opened.sourceSha256) {
        throw invalid('PRODUCT_TARGET_MISMATCH');
      }
      return Object.freeze({ targetId: binding.targetId, sourceSha256: verified.sourceSha256 });
    },
    async prepareTarget(input = {}) {
      persona(input.persona);
      return (await prepared(input)).binding;
    },
    async readRetainedTarget(input = {}) {
      const actor=persona(input.persona,'merchant'),scope=createLaunchScope(input.scope);
      await checkCurrent(scope);
      if(typeof scenes?.readRetained!=='function')throw invalid('PRODUCT_TARGET_UNAVAILABLE');
      let binding=await scenes.readRetained(scope);
      if(!binding)throw invalid('PRODUCT_TARGET_UNAVAILABLE');
      const opened=await repository.open(binding);
      if(!opened)throw invalid('PRODUCT_TARGET_UNAVAILABLE');
      if(actor.id>=1000000000){
        if(typeof scenes.merchant!=='function')throw invalid('OWNER_MISMATCH');
        binding=await scenes.merchant(binding,actor.id); // Existing membership SELECT only.
      }else if(opened.ownMerchantId!==actor.id)throw invalid('OWNER_MISMATCH');
      await checkCurrent(scope);return binding;
    },
    async listProducts(input = {}) {
      persona(input.persona);
      const query = input.query || {};
      const category = text(query.category, 256); const search = text(query.search, 1024);
      const minRating = query.minRating == null ? null : count(query.minRating, 1, 5);
      const maxPrice = price(query.maxPrice);
      const limit = count(query.limit, 1, 100); const page = count(query.page, 1, 2147483647);
      const offset = count(query.offset, 0, 2147483647);
      if (!PRODUCT_SORT.has(query.sort) || offset !== (page - 1) * limit) throw invalid();
      const { binding, scope } = await prepared(input);
      const result = await repository.list(binding, { category, search, minRating, maxPrice, status: 'active',
        retailerId: null, sort: query.sort, limit, offset });
      await checkCurrent(scope);
      return Object.freeze({ products: result.rows, count: result.rows.length, total: result.total });
    },
    async getProduct(input = {}) {
      persona(input.persona); const productId = count(input.productId, 1, 2147483647);
      const { binding, scope } = await prepared(input);
      const product = await repository.get(binding, productId); await checkCurrent(scope);
      return product ? Object.freeze({ product }) : null;
    },
    async categories(input = {}) {
      persona(input.persona);
      const { binding, scope } = await prepared(input);
      const names = await repository.categories(binding);
      await checkCurrent(scope);
      if (!Array.isArray(names) || names.length > MAX_SOURCE_PRODUCTS
          || names.some(name => typeof name !== 'string')) throw invalid('PRODUCT_SOURCE_UNAVAILABLE');
      // Category metadata is in the commerce store; the eligible names come
      // from this launch's product snapshot in the separate review store.
      const { rows } = await sourcePool.query(
        'SELECT id,name,description FROM secureshop.categories WHERE name = ANY($1::text[]) ORDER BY name,id',
        [names]);
      await checkCurrent(scope);
      const metadata = new Map();
      for (const row of rows) {
        const id = Number(row.id);
        if (!Number.isSafeInteger(id) || id < 1 || !names.includes(row.name)
            || metadata.has(row.name)
            || (row.description !== null && typeof row.description !== 'string')) {
          throw invalid('PRODUCT_SOURCE_UNAVAILABLE');
        }
        metadata.set(row.name, Object.freeze({ id, name: row.name, description: row.description }));
      }
      // A merchant may have retained a custom category absent from the static
      // metadata table. Its exact name still belongs to this owned snapshot.
      const categories = names.map(name => metadata.get(name)
        || Object.freeze({ id: name, name, description: null }));
      return Object.freeze({ categories: Object.freeze(categories) });
    },
    async listMerchantProducts(input = {}) {
      const actor = persona(input.persona, 'merchant'); const query = input.query || {};
      const page = count(query.page, 1, 2147483647); const perPage = count(query.perPage, 1, 100);
      const retailerId = query.retailerId == null ? actor.id : count(query.retailerId, 1, 2147483647);
      const search = text(query.search, 1024); const status = text(query.status, 64);
      const category = text(query.category, 256);
      if (!MERCHANT_SORT.has(query.sort)) throw invalid();
      const { binding, opened, scope } = await prepared(input);
      if (actor.id !== opened.ownMerchantId && !require('./secureshopSceneBinding').isSceneMerchant(binding, actor.id)) throw invalid('OWNER_MISMATCH');
      const result = await repository.list(binding, { retailerId, search, status, category,
        sort: query.sort, limit: perPage, offset: (page - 1) * perPage });
      await checkCurrent(scope);
      return Object.freeze({ products: result.rows, count: result.rows.length, total: result.total,
        categories: result.categories });
    },
    async createMerchantProduct(input = {}) {
      const actor = persona(input.persona, 'merchant');
      const { binding, opened, scope } = await prepared(input);
      if (actor.id !== opened.ownMerchantId && !require('./secureshopSceneBinding').isSceneMerchant(binding, actor.id)) throw invalid('OWNER_MISMATCH');
      const effect=require('./secureshopPersonaProductEffect').assertPersonaProductEffect(input.personaEffect);
      const productId = effect?await effect.listing(repository,binding,'createListing',actor.id,[input.listing]):await repository.createListing(binding, actor.id, input.listing);
      await checkCurrent(scope);
      return Object.freeze({ productId });
    },
    async updateMerchantProduct(input = {}) {
      const actor = persona(input.persona, 'merchant');
      const productId = count(input.productId, 1, 2147483647);
      const { binding, opened, scope } = await prepared(input);
      if (actor.id !== opened.ownMerchantId && !require('./secureshopSceneBinding').isSceneMerchant(binding, actor.id)) throw invalid('OWNER_MISMATCH');
      const effect=require('./secureshopPersonaProductEffect').assertPersonaProductEffect(input.personaEffect);
      const updated = effect?await effect.listing(repository,binding,'updateListing',actor.id,[productId,input.patch]):await repository.updateListing(binding, actor.id, productId, input.patch);
      await checkCurrent(scope);
      return updated === null ? null : Object.freeze({ productId: updated });
    },
    async previewMerchantListingEdit(input = {}) {
      const { actor, binding, scope, effect, key } = await existingMerchantAction(input);
      const productId = count(input.productId, 1, 2147483647);
      const preview = await repository.previewListingEdit(binding, actor.id, productId, input.patch, key);
      await effect?.check(scope); await checkCurrent(scope);
      return preview;
    },
    async confirmMerchantListingEdit(input = {}) {
      const { actor, binding, scope, effect, key } = await existingMerchantAction(input);
      const preview = require('./secureshopListingEditContract').validateListingEditPreview(input.preview);
      if (preview.scopeKey !== key) throw invalid('SHOP_AUTH_INVALID');
      const operationId = typeof input.operationId === 'string' ? input.operationId.toLowerCase() : input.operationId;
      const args = [{ operationId, preview, personaSession: input.personaSession }];
      const receipt = effect
        ? await effect.listing(repository, binding, 'confirmListingEdit', actor.id, args)
        : await repository.confirmListingEdit(binding, actor.id, ...args);
      await checkCurrent(scope);
      return receipt;
    },
    async readMerchantListingEdit(input = {}) {
      const { actor, binding, scope, effect, key } = await existingMerchantAction(input);
      const receipt = await repository.readListingEdit(binding, actor.id,
        { operationId: input.operationId, personaSession: input.personaSession });
      if (receipt.scopeKey !== key) throw invalid('LISTING_EDIT_RECEIPT_INVALID');
      await effect?.check(scope); await checkCurrent(scope);
      return receipt;
    },
    async previewMerchantListingCreate(input = {}) {
      const contract = require('./secureshopListingCreateContract');
      const { actor, binding, scope, effect, key } = await existingMerchantAction(input,
        contract.listingCreateScopeKey);
      const raw = input.listing?.presentation === 'html';
      if (raw && (typeof modeAuthority?.capture !== 'function' || typeof modeAuthority?.assertToken !== 'function'))
        throw invalid('LISTING_CREATE_MODE_INVALID');
      const modeToken = raw ? modeAuthority.assertToken(await modeAuthority.capture(scope, 'listings')) : null;
      const preview = await repository.previewListingCreate(binding, actor.id, input.listing, key,
        ...(raw ? [{ preparation: input.preparation, modeToken }] : []));
      await modeToken?.assertCurrent();
      await effect?.check(scope); await checkCurrent(scope);
      return preview;
    },
    async confirmMerchantListingCreate(input = {}) {
      const contract = require('./secureshopListingCreateContract');
      const { actor, binding, scope, effect, key } = await existingMerchantAction(input,
        contract.listingCreateScopeKey);
      const preview = contract.validateListingCreatePreview(input.preview);
      if (preview.scopeKey !== key) throw invalid('SHOP_AUTH_INVALID');
      const operationId = typeof input.operationId === 'string'
        ? input.operationId.toLowerCase() : input.operationId;
      let modeToken;
      if (preview.version === 2) {
        // A protected completed receipt is a historical read, not a new HTML
        // publication. Read it before capturing a fresh mode epoch.
        const prior = await repository.readListingCreate(binding, actor.id,
          { operationId, personaSession: input.personaSession });
        if (prior.status === 'completed') {
          contract.validateListingCreateReceipt(prior, operationId);
          if (prior.scopeKey !== key || prior.requestSha256 !== preview.requestSha256)
            throw invalid('LISTING_CREATE_RECEIPT_INVALID');
          await effect?.check(scope); await checkCurrent(scope);
          return prior;
        }
        if (typeof modeAuthority?.capture !== 'function' || typeof modeAuthority?.assertToken !== 'function')
          throw invalid('LISTING_CREATE_MODE_INVALID');
        modeToken = modeAuthority.assertToken(await modeAuthority.capture(scope, 'listings'));
        await modeToken.assertCurrent();
      }
      const args = [{ operationId, preview, personaSession: input.personaSession,
        ...(modeToken ? { modeToken } : {}) }];
      const receipt = effect
        ? await effect.listing(repository, binding, 'confirmListingCreate', actor.id, args)
        : await repository.confirmListingCreate(binding, actor.id, ...args);
      await modeToken?.assertCurrent();
      await checkCurrent(scope);
      return receipt;
    },
    async readMerchantListingCreate(input = {}) {
      const contract = require('./secureshopListingCreateContract');
      const { actor, binding, scope, effect, key } = await existingMerchantAction(input,
        contract.listingCreateScopeKey);
      const receipt = await repository.readListingCreate(binding, actor.id,
        { operationId: input.operationId, personaSession: input.personaSession });
      if (receipt.scopeKey !== key) throw invalid('LISTING_CREATE_RECEIPT_INVALID');
      await effect?.check(scope); await checkCurrent(scope);
      return receipt;
    },
    async readMerchantListingCreateSource(input = {}) {
      const contract = require('./secureshopListingCreateContract');
      const { actor, binding, scope, effect, key } = await existingMerchantAction(input,
        contract.listingCreateScopeKey);
      const source = await repository.readListingCreateSource(binding, actor.id,
        { operationId: input.operationId, personaSession: input.personaSession });
      if (source.receipt.scopeKey !== key) throw invalid('LISTING_CREATE_RECEIPT_INVALID');
      await effect?.check(scope); await checkCurrent(scope);
      return source;
    },
    async archiveMerchantProduct(input = {}) {
      const actor = persona(input.persona, 'merchant');
      const productId = count(input.productId, 1, 2147483647);
      const { binding, opened, scope } = await prepared(input);
      if (actor.id !== opened.ownMerchantId && !require('./secureshopSceneBinding').isSceneMerchant(binding, actor.id)) throw invalid('OWNER_MISMATCH');
      const effect=require('./secureshopPersonaProductEffect').assertPersonaProductEffect(input.personaEffect);
      const archived = effect?await effect.listing(repository,binding,'archiveListing',actor.id,[productId]):await repository.archiveListing(binding, actor.id, productId);
      await checkCurrent(scope);
      return archived === 1;
    },
    async searchMerchantProducts(input = {}) {
      const actor=persona(input.persona,'merchant'),query=input.query;
      if(!query||Object.getPrototypeOf(query)!==Object.prototype
        ||Object.keys(query).some(key=>!['search','status','afterProductId'].includes(key))
        ||typeof query.search!=='string'||Buffer.byteLength(query.search)>128
        ||!['active','inactive','all'].includes(query.status)
        ||typeof repository.listMerchantChoices!=='function')throw invalid();
      const afterProductId=query.afterProductId===undefined?undefined:count(query.afterProductId,1,2147483647);
      const {binding,opened,scope}=await prepared(input);
      if(actor.id!==opened.ownMerchantId&&!require('./secureshopSceneBinding').isSceneMerchant(binding,actor.id))throw invalid('OWNER_MISMATCH');
      const result=await repository.listMerchantChoices(binding,{retailerId:actor.id,
        search:query.search,status:query.status,...(afterProductId===undefined?{}:{afterProductId})});
      await checkCurrent(scope);
      return Object.freeze({products:result.rows,total:result.total,nextProductId:result.nextProductId});
    },
    // Read-only discovery includes inactive listings. Mutation callers retain
    // getOwnedMerchantProduct's separate active-product eligibility gate.
    async getOwnedMerchantCatalogProduct(input = {}) {
      const actor=persona(input.persona,'merchant'),productId=count(input.productId,1,2147483647);
      const {binding,opened,scope}=await prepared(input);
      if(actor.id!==opened.ownMerchantId&&!require('./secureshopSceneBinding').isSceneMerchant(binding,actor.id))throw invalid('OWNER_MISMATCH');
      const product=await repository.get(binding,productId);
      await checkCurrent(scope);
      if(!product||!['active','inactive'].includes(product.status)||product.retailer_id!==actor.id)throw invalid('OWNER_MISMATCH');
      return Object.freeze({binding,product});
    },
    async getOwnedMerchantProduct(input = {}) {
      const actor = persona(input.persona, 'merchant');
      const productId = count(input.productId, 1, 2147483647);
      const { binding, opened, scope } = await prepared(input);
      if (actor.id !== opened.ownMerchantId && !require('./secureshopSceneBinding').isSceneMerchant(binding, actor.id)) throw invalid('OWNER_MISMATCH');
      const product = await repository.get(binding, productId);
      await checkCurrent(scope);
      if (!product || product.status !== 'active' || product.retailer_id !== actor.id) {
        throw invalid('OWNER_MISMATCH');
      }
      return Object.freeze({ binding, product });
    },
    async hasProduct(input = {}) {
      persona(input.persona); const productId = count(input.productId, 1, 2147483647);
      const { binding, scope } = await prepared(input);
      const exists = Boolean(await repository.get(binding, productId)); await checkCurrent(scope);
      return exists;
    },
  };
  for(const method of ['searchMerchantProducts','getOwnedMerchantCatalogProduct','listMerchantProducts','createMerchantProduct','updateMerchantProduct','archiveMerchantProduct',
    'getOwnedMerchantProduct','previewMerchantListingEdit','confirmMerchantListingEdit','readMerchantListingEdit',
    'previewMerchantListingCreate','confirmMerchantListingCreate','readMerchantListingCreate','readMerchantListingCreateSource']) {
    const original=service[method],mutation=['createMerchantProduct','updateMerchantProduct','archiveMerchantProduct',
      'confirmMerchantListingEdit','confirmMerchantListingCreate'].includes(method);
    service[method]=async function(raw={}) {
      const existing=require('./secureshopPersonaProductEffect').assertPersonaProductEffect(raw.personaEffect);
      if(!personaAuthority&&!existing)return original(raw);
      const input={...structuredClone({...raw,personaEffect:undefined}),...(existing?{personaEffect:existing}:{})};
      const scope=createLaunchScope(input.scope);let effect=existing;
      if(!effect){
        const actor=persona(input.persona,'merchant'),session=input.personaSession;
        if(typeof session?.sessionId!=='string'||!UUID.test(session.sessionId)||typeof session.authorityVersion!=='string'||!/^[1-9]\d*$/.test(session.authorityVersion))throw invalid('SHOP_AUTH_INVALID');
        const credential={sessionId:session.sessionId.toLowerCase(),authorityVersion:session.authorityVersion};
        const fence=await personaAuthority.capture({scope,personaId:actor.id,role:actor.role,...credential});
        if(typeof fence?.assertRemoteAdmission!=='function'||typeof fence?.withCrossStoreEffect!=='function'||!fence.binding
          ||Object.keys(scope).some(k=>fence.binding[k]!==scope[k])||fence.binding.personaId!==actor.id||fence.binding.role!==actor.role
          ||fence.binding.sessionId!==credential.sessionId||fence.binding.authorityVersion!==credential.authorityVersion)throw invalid('SHOP_AUTH_INVALID');
        effect=require('./secureshopPersonaProductEffect').createPersonaProductEffect(fence);input.personaEffect=effect;
      }
      await effect.check(scope);const result=await original(input);
      try{await effect.check(scope);}catch(cause){if(!mutation)throw cause;const error=Object.assign(Error('Listing effect requires authoritative readback'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',executionBoundary:true});Object.defineProperty(error,'cause',{value:cause});throw error;}
      return result;
    };
  }
  return Object.freeze(service);
}

module.exports = { createSecureShopBoundCatalog, MAX_SOURCE_PRODUCTS };
