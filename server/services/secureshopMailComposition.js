'use strict';
// Keep dependency preparation lazy: a disabled or unqualified release must not
// open mail state or require agent policy/Judge dependencies.
async function createOptionalMailComposition({flag,loadDependencies},production=require('./secureshopMailProduction')){
 if(!production.mailServingEnabled(flag,production.PRODUCTION_QUALIFIED))return undefined;
 if(typeof loadDependencies!=='function')throw TypeError('Mail dependency preparation required');
 return production.createMailProduction({...await loadDependencies(),enabled:true});
}
module.exports={createOptionalMailComposition};
