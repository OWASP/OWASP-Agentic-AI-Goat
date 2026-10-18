'use strict';
const path=require('node:path');
async function prepareCtfDelivery({directory,adminUrl,environment,existing={},provision=require('../../db/postgres/provision-ctf-delivery').provisionCtfDelivery}){
 const result=await provision({adminUrl,manifestPath:path.join(directory,'provisioning.json'),outputPath:path.join(directory,'ctf-delivery.json'),env:environment});
 const value=result?.configuration?.CTF_DELIVERY_DATABASE_URL;
 let url;try{url=new URL(value);}catch{throw Error('CTF_DELIVERY_CONFIGURATION_INVALID');}
 if(!['postgres:','postgresql:'].includes(url.protocol)||decodeURIComponent(url.username)!=='dvaia_ctf_delivery'||!url.password||url.search||url.hash)throw Error('CTF_DELIVERY_CONFIGURATION_INVALID');
 if(existing.CTF_DELIVERY_DATABASE_URL!==undefined&&existing.CTF_DELIVERY_DATABASE_URL!==value)throw Error('CTF_DELIVERY_CONFIGURATION_CONFLICT');
 return {configuration:{CTF_DELIVERY_DATABASE_URL:value},additions:existing.CTF_DELIVERY_DATABASE_URL===undefined?{CTF_DELIVERY_DATABASE_URL:value}:{}};
}
module.exports={prepareCtfDelivery};
