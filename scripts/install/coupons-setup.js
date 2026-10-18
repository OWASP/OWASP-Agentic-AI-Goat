'use strict';
const {Pool}=require('pg');
const managed=require('../../server/services/secureshopCouponManagedConfiguration');
const {assertCouponSchema}=require('../../server/services/secureshopCouponProduction');
const fail=code=>Object.assign(Error('Owned coupon setup unavailable; existing data preserved'),{code});
function assertPrerequisites(environment){require('./analytics-setup').assertPrerequisites(environment);if(!environment.SECURESHOP_REVIEW_DATABASE_URL||!environment.SECURESHOP_REVIEW_MIGRATION_DATABASE_URL)throw fail('COUPON_SETUP_PREREQUISITES');}
async function setupOwnedCoupons({requested=false,root,homeDirectory,environment=process.env,applicationEnvironment=environment,loadRuntime=require('../../server/services/secureshopOwnedAnalyticsProduction').getOwnedAnalyticsProduction,checkSchema=assertCouponSchema,migrateSchema,makePool=options=>new Pool(options)}={}){
 if(!requested)return{requested:false,activationEnabled:false};assertPrerequisites(applicationEnvironment);
 const options={root,home:homeDirectory},before=managed.load(options),runtime=await loadRuntime({root,homeDirectory,environment});let pool;
 try{if(runtime?.admissions!==true||typeof runtime.service?.lookupCoupon!=='function')throw fail('COUPON_ANALYTICS_DISABLED');await runtime.assertReady();if(migrateSchema)await migrateSchema(applicationEnvironment);else{const migrationPool=makePool({connectionString:applicationEnvironment.SECURESHOP_REVIEW_MIGRATION_DATABASE_URL,max:1,connectionTimeoutMillis:5000});try{await require('../../db/postgres/migrate').migrate(migrationPool,require('node:path').join(root,'db/postgres/workshop-migrations/secureshop_review'));}finally{await migrationPool.end();}}pool=makePool({connectionString:applicationEnvironment.SECURESHOP_REVIEW_DATABASE_URL,max:1,connectionTimeoutMillis:5000});await checkSchema(pool);
 if(managed.load(options)?.sha256!==before?.sha256)throw fail('COUPON_ACTIVATION_CONFLICT');return{requested:true,...managed.activateNew(options)};
 }finally{try{await pool?.end();}finally{await runtime?.close();}}
}
module.exports={setupOwnedCoupons,assertPrerequisites};
