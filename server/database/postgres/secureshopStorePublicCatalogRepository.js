'use strict';
const { consistentRead } = require('./workshopPlatformSupport');
const { EFFECTIVE_PRODUCTS, EFFECTIVE_REVIEW_TARGET_JOIN } = require('./secureshopBoundProductRepository');
const { createSecureShopPublicCatalogRepository } = require('./secureshopPublicCatalogRepository');
const fields = ['id','name','description','description_html','price','category','image_url','stock_quantity','status','avg_rating','review_count','images'];
const columns = `product_id AS id,left(name,512) AS name,left(description,16384) AS description,
 left(description_html,16384) AS description_html,price,left(category,100) AS category,
 left(image_url,2048) AS image_url,stock_quantity,status,avg_rating,review_count,
 ARRAY(SELECT left(value,2048) FROM jsonb_array_elements_text(to_jsonb(images)) WITH ORDINALITY a(value,n) WHERE n<=12) AS images`;
const orders = { default:'product_id',price_asc:'price,product_id',price_desc:'price DESC,product_id',newest:'source_created_at DESC,product_id DESC',deals:'price,product_id' };
function project(row) {
 const value=Object.fromEntries(fields.map(key=>[key,row[key]??null]));
 for(const key of ['price','avg_rating','review_count']) value[key]=Number(value[key]||0);
 value.images=Array.isArray(value.images)?value.images:[];
 if(!value.images.length&&value.image_url)value.images=[value.image_url];
 return value;
}
// Public reads select only the installation's explicitly designated storefront.
// Never accept an owner, tenant, target, credential or execution grant from HTTP.
function createSecureShopStorePublicCatalogRepository({identityPool,reviewPool,commercePool}) {
 for(const pool of [identityPool,reviewPool,commercePool])if(!pool?.query||!pool?.connect)throw new TypeError('Store catalog pools required');
 const seed=createSecureShopPublicCatalogRepository(commercePool);
 async function current() {
  const rows=(await identityPool.query(`SELECT t.tenant_id,t.owner_id,t.is_active,s.scene_id,s.product_target_id,s.scene_generation
   FROM secureshop_auth.tenants t LEFT JOIN identity.secureshop_scenes s
   ON s.original_platform_owner_id=t.owner_id AND s.status='active' AND s.is_default
   WHERE t.slug='default'`)).rows;
  if(rows.length!==1||!rows[0].is_active)throw new Error('Default storefront unavailable');
  return rows[0];
 }
 async function read(method,args,work) {
  const scene=await current();
  const result=scene.scene_id?await consistentRead(reviewPool,async client=>{
   const target=(await client.query("SELECT target_id FROM secureshop_review.product_targets WHERE target_id=$1 AND original_platform_owner_id=$2 AND lifecycle='active'",[scene.product_target_id,scene.owner_id])).rows;
   if(target.length!==1)throw new Error('Store catalog unavailable');
   return work(client,scene.product_target_id);
  }):await seed[method](...args);
  const after=await current();
  if(JSON.stringify(after)!==JSON.stringify(scene))throw new Error('Store catalog changed during read');
  return result;
 }
 const cte=`WITH effective AS (${EFFECTIVE_PRODUCTS})`;
 const available="target_id=$1 AND status='active' AND archived_at IS NULL";
 return Object.freeze({
  browse(options={}) {
   const {category=null,search=null,minRating=null,maxPrice=null,sort='default',limit=24,offset=0}=options;
   if(!Object.hasOwn(orders,sort))throw new TypeError('Unknown catalog sort');
   return read('browse',[options],async(c,target)=>{
    const where=`${available} AND ($2::text IS NULL OR category=$2)
     AND ($3::text IS NULL OR name ILIKE $3 ESCAPE '\\' OR description ILIKE $3 ESCAPE '\\')
     AND ($4::integer IS NULL OR avg_rating_raw >= $4) AND ($5::numeric IS NULL OR price <= $5)`;
    const params=[target,category,search?`%${search.replace(/[\\%_]/g,'\\$&')}%`:null,minRating,maxPrice];
    const total=Number((await c.query(`${cte} SELECT count(*) AS total FROM effective WHERE ${where}`,params)).rows[0].total);
    const products=(await c.query(`${cte} SELECT ${columns} FROM effective WHERE ${where} ORDER BY ${orders[sort]} LIMIT $6 OFFSET $7`,[...params,limit,offset])).rows.map(project);
    return {products,count:products.length,total};
   });
  },
  product(id){return read('product',[id],async(c,target)=>{
   const row=(await c.query(`${cte} SELECT ${columns} FROM effective WHERE ${available} AND product_id=$2`,[target,id])).rows[0];
   return row?{product:project(row)}:null;
  });},
  related(id,options={}){return read('related',[id,options],async(c,target)=>{
   const row=(await c.query(`${cte} SELECT category FROM effective WHERE ${available} AND product_id=$2`,[target,id])).rows[0];
   if(!row)return null;
   const results=(await c.query(`${cte} SELECT ${columns} FROM effective WHERE ${available} AND product_id<>$2 AND category=$3 ORDER BY product_id LIMIT $4`,[target,id,row.category,options.limit??4])).rows.map(project);
   return {results,recommendation:''};
  });},
  categories(){return read('categories',[],async(c,target)=>({categories:(await c.query(`${cte} SELECT DISTINCT left(category,100) AS name FROM effective WHERE ${available} AND category IS NOT NULL ORDER BY name LIMIT 100`,[target])).rows.map(row=>({id:row.name,name:row.name,description:null}))}));},
  reviews(id,options={}){return read('reviews',[id,options],async(c,target)=>{
   const found=(await c.query(`${cte} SELECT product_id FROM effective WHERE ${available} AND product_id=$2`,[target,id])).rows;
   if(!found.length)return null;
   const source=`FROM secureshop_review.product_targets t
    ${EFFECTIVE_REVIEW_TARGET_JOIN}
    JOIN secureshop_review.reviews r ON r.target_id=rt.target_id AND r.status='approved'
    WHERE t.target_id=$1 AND t.lifecycle='active' AND r.product_id=$2`;
   const total=Number((await c.query(`SELECT count(*) AS total ${source}`,[target,id])).rows[0].total);
   const reviews=(await c.query(`SELECT r.id,left(r.body,16384) AS body,r.rating,r.status,r.created_at,
    'Customer'::text AS author_name ${source} ORDER BY r.created_at DESC,r.id DESC LIMIT $3 OFFSET $4`,
    [target,id,options.limit??10,options.offset??0])).rows.map(row=>Object.fromEntries(
     ['id','body','rating','status','created_at','author_name'].map(key=>[key,row[key]??null])));
   return {reviews,total};
  });},
 });
}
module.exports={createSecureShopStorePublicCatalogRepository};
