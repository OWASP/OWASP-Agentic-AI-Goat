'use strict';
const { createLaunchScope } = require('./secureshopConversationBinding');

function invalid() { return Object.assign(new Error('Invalid product tool arguments'), { code: 'INVALID_ARGUMENT' }); }
function wrap(value) { return { content: [{ type: 'text', text: JSON.stringify(value) }] }; }
function productDto(product) {
  return { product_id: product.id, name: product.name, price: product.price,
    category: product.category, stock_quantity: product.stock_quantity,
    description: product.description, description_html: product.description_html,
    image_url: product.image_url };
}

function fixedText(value,max){
 if(value==null)return null;if(typeof value!=='string'||!value.isWellFormed())throw invalid();
 return value.slice(0,max).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g,'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&#39;');
}
function fixedProductDto(product){
 if(!Number.isSafeInteger(product?.id)||product.id<1||product.id>2147483647||!Number.isFinite(Number(product.price))||Number(product.price)<0||!Number.isSafeInteger(product.stock_quantity)||product.stock_quantity<0)throw invalid();
 const name=fixedText(product.name,256);if(!name)throw invalid();
 return {product_id:product.id,name,price:Number(product.price),stock_quantity:product.stock_quantity,category:fixedText(product.category,128),description:fixedText(product.description??product.description_html,4096),description_html:null,image_url:null,data_policy:'untrusted_catalog_text'};
}
// Fixed Summarize deliberately has a smaller capability than product questions:
// merchant-controlled text never reaches the graph, including names/categories.
function fixedSummaryFacts(product) {
  const price = product?.price;
  if (!Number.isSafeInteger(product?.id) || product.id < 1 || product.id > 2147483647
      || !['number', 'string'].includes(typeof price) || (typeof price === 'string' && !/^\d+(?:\.\d+)?$/.test(price))
      || !Number.isFinite(Number(price)) || Number(price) < 0
      || !Number.isSafeInteger(product.stock_quantity) || product.stock_quantity < 0) throw invalid();
  return { product_id: product.id, name: `Product ${product.id}`, price: Number(price),
    stock_quantity: product.stock_quantity, category: null, description: null,
    description_html: null, image_url: null, data_policy: 'fixed_summary_numeric_facts_v1',
    summary_scope: 'catalog_price_and_stock_only' };
}

function createSecureShopBoundProductTools({ catalog, retrieval, scope, persona,
  productId, operation, signal, checkCurrent, personaEffect, mode='vuln', answerQuestion=false, captureManualRagSource } = {}) {
  scope = createLaunchScope(scope);
  if(!['vuln','fixed'].includes(mode)||captureManualRagSource!==undefined&&typeof captureManualRagSource!=='function')throw invalid();
  if(typeof answerQuestion!=='boolean'||answerQuestion&&operation!=='summary')throw invalid();
  if (persona?.role !== 'customer' || !Number.isSafeInteger(persona.id) || persona.id < 1
      || !Number.isSafeInteger(productId) || productId < 1 || productId > 2147483647
      || !['summary', 'similar'].includes(operation) || typeof checkCurrent !== 'function'
      || typeof catalog?.getProduct !== 'function'
      || (operation === 'similar' && (mode==='fixed'?typeof catalog?.listProducts!=='function':typeof retrieval?.similar!=='function'))) throw invalid();
  persona = Object.freeze({ id: persona.id, role: 'customer' });
  const check = async () => { signal?.throwIfAborted(); await checkCurrent(scope); signal?.throwIfAborted(); };
  const execute = async args => {
    if (!args || typeof args !== 'object' || Array.isArray(args)
        || Object.keys(args).length !== 1 || args.product_id !== productId) throw invalid();
    await check();
    let output;
    if (operation === 'summary') {
      const value = await catalog.getProduct({ scope, persona, productId, personaEffect });
      await check();
      if (!value?.product || value.product.id !== productId) throw invalid();
      // @intentional-vulnerability llm01-indirect-pi-product
      // Product text reaches the next model turn verbatim inside this launch.
      output = mode==='fixed'?(answerQuestion?fixedProductDto(value.product):fixedSummaryFacts(value.product)):productDto(value.product);
    } else if(mode==='fixed') {
      const value=await catalog.getProduct({scope,persona,productId,personaEffect});await check();
      if(value?.product?.id!==productId)throw invalid();
      const seed=fixedProductDto(value.product),all=[];let total=null;
      for(let page=1;all.length<256;page++){
        const result=await catalog.listProducts({scope,persona,personaEffect,query:{category:null,search:null,sort:'',page,limit:100,offset:(page-1)*100}});await check();
        if(!Array.isArray(result?.products)||!Number.isSafeInteger(result.total)||result.total<1||result.total>256||result.products.length>100||(total!==null&&result.total!==total))throw invalid();
        total=result.total;all.push(...result.products);if(all.length===total)break;if(!result.products.length||all.length>total)throw invalid();
      }
      if(all.length!==total||new Set(all.map(row=>row.id)).size!==all.length)throw invalid();
      const neighbors=all.filter(row=>row.id!==productId&&row.category===value.product.category).map(row=>fixedProductDto(row)).sort((a,b)=>Math.abs(a.price-seed.price)-Math.abs(b.price-seed.price)||a.product_id-b.product_id).slice(0,5);
      output={seed:{id:productId,name:seed.name},results:neighbors.map(({product_id,...row})=>({id:product_id,...row})),count:neighbors.length,mode:'catalog',retrieved_context:[],data_policy:'untrusted_catalog_text',selection_basis:'same_category_nearest_price'};
    } else {
      // @intentional-vulnerability llm04-rag-poisoning
      // Target-owned retrieved manual chunks remain unfiltered tool context.
      output = await retrieval.similar({ scope, persona, productId, signal, personaEffect, ...(captureManualRagSource ? { captureManualRagSource } : {}) });
      await check();
      if (!output || output.seed?.id !== productId || !Array.isArray(output.results)
          || !Array.isArray(output.retrieved_context)) throw invalid();
    }
    return wrap(output);
  };
  return new Map([[operation === 'summary' ? 'summarizer.summarize_product' : 'product-search.similar', execute]]);
}
module.exports = { createSecureShopBoundProductTools, productDto };
