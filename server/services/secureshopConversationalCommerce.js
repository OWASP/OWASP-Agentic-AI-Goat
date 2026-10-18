'use strict';
const C=require('./secureshopConversationalCommerceContract');
const Address=require('./secureshopAddressSetupContract');
const Profile=require('./secureshopProfileUpdateContract');
function createConversationalCommerce({commerce}){
 if(typeof commerce?.conversational!=='function')throw new TypeError('Bound conversational commerce required');
 const methods={addresses:[],addressChoices:[],addressForm:['action','choiceId'],saveAddress:['operationId','action','choiceId','expectedSnapshotSha256','defaultSetSha256','fields'],profileForm:[],saveProfile:['operationId','expectedSnapshotSha256','fields'],paymentMethods:[],createPaymentMethod:['operationId','scenario'],prepareCheckout:['operationId','addressChoiceId','paymentChoiceId'],confirmCheckout:['proposalId'],confirmCart:['proposalId'],readOperation:['operationId']};
 const api={};
 for(const [method,keys]of Object.entries(methods))api[method]=async input=>{
  if(!C.exact(input.args,keys))throw C.fail();
  const args=method==='addressForm'?Address.addressFormRequest(input.args)
   :method==='saveAddress'?Address.addressSaveRequest(input.args)
   :method==='saveProfile'?Profile.profileSaveRequest(input.args)
   :method==='createPaymentMethod'?C.practice(input.args):method==='prepareCheckout'?C.prepare(input.args)
   :['confirmCheckout','confirmCart'].includes(method)?C.confirm(input.args)
   :method==='readOperation'?{operationId:C.uuid(input.args.operationId)}:{};
  return commerce.conversational({...input,method,args});
 };
 return Object.freeze(api);
}
module.exports={createConversationalCommerce};
