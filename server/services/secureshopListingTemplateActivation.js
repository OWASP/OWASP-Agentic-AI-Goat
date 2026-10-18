'use strict';

const path = require('node:path');
const os = require('node:os');
const managed = require('./secureshopListingTemplateManagedConfiguration');
const { createListingTemplateClient } = require('./secureshopListingTemplateClient');

const fail = () => Object.assign(new Error('Owned listing template startup unavailable'),
  { code:'LISTING_TEMPLATE_START_UNAVAILABLE' });

async function prepareListingTemplateClient({root=path.resolve(__dirname,'../..'),home=os.homedir(),
  environment=process.env,capture=managed.capture,
  startExisting=options=>require('../../scripts/install/secureshop-owned-listing-template').startExisting(options),
  createClient=createListingTemplateClient,assertCaptured=managed.assertCaptured}={}) {
  const record=capture({root,home});
  if(!record||record.value.enabled===false)return undefined;
  if(record.value.enabled!==true)throw fail();
  const ready=await startExisting({root,home,environment});
  if(ready?.ready!==true||ready.enabled!==true
      ||ready.containerId!==record.value.containerId||ready.imageId!==record.value.imageId
      ||ready.baseUrl!==`http://127.0.0.1:${record.value.port}`)throw fail();
  assertCaptured(record,{root,home});
  const client=createClient({baseUrl:ready.baseUrl});
  if(typeof client?.health!=='function'||typeof client?.execute!=='function'
      ||await client.health()!==true)throw fail();
  assertCaptured(record,{root,home});
  return client;
}

module.exports={prepareListingTemplateClient};
