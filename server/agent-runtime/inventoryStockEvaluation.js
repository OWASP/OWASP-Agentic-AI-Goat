'use strict';
const {createBoundedSourceClassificationEvaluation}=require('./boundedSourceClassificationEvaluation');
function createInventoryStockEvaluation(options){return createBoundedSourceClassificationEvaluation({...options,auditField:'inventoryStockComparison',eventPrefix:'judge_inventory',label:'inventory request'});}
module.exports={createInventoryStockEvaluation};
