'use strict';
const {createPool,verifyServer}=require('./index');
const {initialize}=require('./workshopSupport');
const {getCommercePool,getAgentsPool}=require('./secureshopPools');
async function initializeSecureShopCommerceDb({runtimePool=getCommercePool(),migrationPool}={}) {
  const owned=!migrationPool;
  migrationPool ||= createPool(process.env,'SECURESHOP_MIGRATION_DATABASE_URL');
  try {await initialize(runtimePool,migrationPool,'secureshop',require('./secureshopSeed').seedSecureShop);}
  finally {if(owned)await migrationPool.end();}
}
async function initializeSecureShopAgentsDb({runtimePool=getAgentsPool(),migrationPool}={}) {
  const owned=!migrationPool;
  migrationPool ||= createPool(process.env,'SECURESHOP_AGENTS_MIGRATION_DATABASE_URL');
  try {await require('./secureshopAgentsDb').initializeSecureShopAgentsDb({runtimePool,migrationPool});}
  finally {if(owned)await migrationPool.end();}
}
async function initializeSecureShopDatabases(){
  await initializeSecureShopCommerceDb();
  await initializeSecureShopAgentsDb();
}
async function verifySecureShopRuntime(){
  const commerce=getCommercePool(),agents=getAgentsPool();
  await Promise.all([verifyServer(commerce),verifyServer(agents)]);
  await commerce.query('SELECT id FROM secureshop.shop_users LIMIT 0');
  await agents.query('SELECT id FROM secureshop_agents.agent_sessions LIMIT 0');
}
module.exports={initializeSecureShopCommerceDb,initializeSecureShopAgentsDb,initializeSecureShopDatabases,verifySecureShopRuntime};
