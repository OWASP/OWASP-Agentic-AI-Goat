'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const parser=require('../client/node_modules/@babel/parser');

const ROOT=path.resolve(__dirname,'..');
const MANIFEST='docs/secureshop/supported-action-manifest.json';
const SOURCE='server/services/secureshopBoundRoleChat.js';
const COMPOSITION='server/services/secureshopBoundReviewComposition.js';
const APPLICATION='server/services/secureshopBoundApplication.js';
const GATEWAY='server/routes/secureshop/boundGateway.js';
const ROUTER='server/routes/secureshop/boundRoleChat.js';
const MAIL='server/services/secureshopRoleMailActions.js';
const AUDIT='server/services/secureshopBoundAuditChat.js';
const SYSTEM='server/services/secureshopRoleSystemReads.js';
const USER_ADMIN='server/services/secureshopBoundUserAdministration.js';
const USER_DIRECTORY='server/database/postgres/secureshopSyntheticUserDirectoryRepository.js';
const USER_ASSESSMENT='server/services/secureshopUserLookupAssessment.js';
const AUDIT_JOBS='server/services/secureshopBoundAuditJobs.js';
const AUDIT_PROPOSAL='server/services/secureshopRoleAuditJobProposal.js';
const AUDIT_LIFECYCLE='server/services/secureshopAuditRuntimeLifecycle.js';
const AUDIT_RUNTIME='server/services/secureshopAuditRuntime.js';
const AUDIT_RUNNER='server/services/secureshopAuditRunner.js';
const AUDIT_JOB='server/services/secureshopAuditJob.js';
const AUDIT_HOST='server/services/secureshopAuditWorkerHost.js';
const AUDIT_WORKER='server/agent-runtime/workers/secureshopAuditWorker.js';
const AUDIT_GRAPH='server/agent-runtime/secureshopAuditSummaryGraph.js';
const AUDIT_PROVIDER='server/services/secureshop/providers/ollamaProvider.js';
const AUDIT_MODEL_CHAIN='server/services/secureshopAuditModelChain.js';
const AUDIT_VERIFIED='server/services/secureshopAuditVerifiedEvidence.js';
const AUDIT_ARTIFACTS='server/services/secureshopAuditArtifactVerification.js';
const MAIL_READ='server/services/secureshopRoleMailRead.js';
const MAIL_APP='server/services/secureshopMailApplication.js';
const MAIL_PRODUCTION='server/services/secureshopMailProduction.js';
const MAIL_COMPOSITION='server/services/secureshopMailComposition.js';
const MAIL_REPOSITORY='server/database/postgres/secureshopBoundMailRepository.js';
const MAIL_SQL='db/postgres/workshop-migrations/secureshop_agents/0051_mail_scene_execution.sql';
const MAIL_PROJECTION_SQL='db/postgres/workshop-migrations/secureshop_agents/0083_bound_lab_mail_read_projection.sql';
const MAIL_ASSESSMENT='server/services/secureshopMailAgentReadAssessment.js';
const MAIL_ORIGINAL='server/services/secureshopMailAgentReadOriginalReader.js';
const LISTING_SETUP='server/services/secureshopRoleListingActionSetup.js';
const LISTING_OPTIMIZE_SETUP='server/services/secureshopRoleListingOptimizeSetup.js';
const LISTINGS_APP='server/services/secureshopListingsApplication.js';
const LISTINGS_PRODUCTION='server/services/secureshopListingsProduction.js';
const COMMERCE='server/services/secureshopBoundCommerce.js';
const COMMERCE_REPOSITORY='server/database/postgres/secureshopBoundCommerceRepository.js';
const MERCHANT_METRICS='server/services/secureshopMerchantMetrics.js';
const ROLE_REVIEW='server/services/secureshopRoleReviewService.js';
const REVIEW_REPOSITORY='server/database/postgres/secureshopBoundReviewRepository.js';
const CATALOG='server/services/secureshopBoundCatalog.js';
const PRODUCT_RETRIEVAL='server/services/secureshopBoundProductRetrieval.js';
const PRODUCT_REPOSITORY='server/database/postgres/secureshopBoundProductRepository.js';
const EMBEDDING_REPOSITORY='server/database/postgres/secureshopEmbeddingRevisionRepository.js';
const ROLE_USER_PROPOSAL='server/services/secureshopRoleUserAdministrationProposal.js';
const ACL_CHAT='server/services/secureshopBoundAclChat.js';
const ACL_PROPOSAL='server/services/secureshopRoleAclProposal.js';
const ACCESS_CONTROL='server/services/secureshopBoundAccessControl.js';
const SYSTEM_READS='server/services/secureshopRoleSystemReads.js';
const SYSTEM_HEALTH='server/services/secureshopBoundSystemHealthService.js';
const SYSTEM_COMPOSITION='server/services/secureshopSystemConfigComposition.js';
const SYSTEM_RESTART_CHAT='server/services/secureshopBoundSystemRestartChat.js';
const SYSTEM_RESTART_PROPOSAL='server/services/secureshopRoleSystemRestartProposal.js';
const SYSTEM_DIAGNOSTIC_CHAT='server/services/secureshopBoundSystemDiagnosticChat.js';
const SYSTEM_DIAGNOSTIC_PROPOSAL='server/services/secureshopRoleSystemDiagnosticProposal.js';
const PRICING_PROPOSAL='server/services/secureshopRolePricingProposal.js';
const POLICY_CHAT='server/services/secureshopBoundPolicyChat.js';
const POLICY_PROPOSAL='server/services/secureshopRolePolicyProposal.js';
const MCP_CHAT='server/services/secureshopBoundMcpRegistryChat.js';
const MCP_PROPOSAL='server/services/secureshopRoleMcpRegistryProposal.js';
const INVENTORY_PROPOSAL='server/services/secureshopRoleInventoryProposal.js';
const LISTING_CREATE_PROPOSAL='server/services/secureshopRoleListingCreateProposal.js';
const LISTING_EDIT_PROPOSAL='server/services/secureshopRoleListingProposal.js';
const REVIEW_PROPOSAL='server/services/secureshopRoleReviewProposal.js';
const ADMIN_SERVICE='server/services/secureshopBoundAdmin.js';
const BRIDGE='client/src/pages/secureshop/bridge/operations.mjs';
const selected={
 'admin.audit_search':{handler:'auditChat.search',operation:'readAuditOperation',verb:'get',route:'/audit/operations/:sessionId/:requestId/:operationId'},
 'admin.system_config_read':{handler:'systemReads.configRead',operation:'readSystemConfigOperation',verb:'get',route:'/system/config/operations/:sessionId/:requestId/:operationId'},
 'merchant.mail_send_prepare':{handler:'mailActions.prepare',operation:'confirmMail',verb:'post',route:'/mail/confirm'},
 'admin.user_lookup':{handler:'userAdministration.lookupForAgent',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.audit_summary_prepare':{handler:'auditJobs.prepare',operation:'runAuditJob',verb:'post',route:'/audit/job/run'},
 'merchant.mail_recipients':{handler:'mailChat.recipients',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.mail_list':{handler:'mailChat.list',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.mail_detail':{handler:'mailChat.detail',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.listing_import_setup':{handler:'listingsSetup.prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.listing_rewrite_setup':{handler:'listingsSetup.prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.listing_optimize_setup':{handler:'listingsSetup.prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.orders_list':{handler:'commerce.merchantOrders',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.orders_detail':{handler:'commerce.merchantOrder',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.overview':{handler:'commerce.merchantOverview',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.top_products':{handler:'commerce.merchantTopProducts',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.reviews_list':{handler:'reviewService().list',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.reviews_detail':{handler:'selectedReview',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.catalog_search':{handler:'catalog.searchMerchantProducts',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.manual_search':{handler:'productRetrieval.searchManuals',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.users_search':{handler:'admin.users',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.role_change_prepare':{handler:'prepareUserAdministration',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.ban_prepare':{handler:'prepareUserAdministration',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.password_reset_setup':{handler:'preparePasswordReset',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.acl_list':{handler:'aclChat.snapshot',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.acl_permission_prepare':{handler:'aclChat.prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.acl_enforcement_prepare':{handler:'aclChat.prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.system_health':{handler:'systemReads.health',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.system_diagnostic_prepare':{handler:'systemDiagnosticChat.prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.system_restart_prepare':{handler:'systemRestartChat.prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.pricing_suggest_prepare':{handler:'preparePricing',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.pricing_compare_prepare':{handler:'preparePricing',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.pricing_experiment_prepare':{handler:'preparePricing',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.policies_search':{handler:'policySnapshot',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.policy_detail':{handler:'selectedPolicy',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.policy_create_prepare':{handler:'policyService().prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.policy_edit_prepare':{handler:'policyService().prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.policy_preview_prepare':{handler:'policyService().prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.policy_delete_prepare':{handler:'policyService().prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.mcp_servers':{handler:'mcpSnapshot',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.mcp_detail':{handler:'mcpService().detail',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.mcp_register_prepare':{handler:'mcpService().prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.mcp_import_prepare':{handler:'mcpService().prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.mcp_retire_prepare':{handler:'mcpService().prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.mcp_invocation_setup':{handler:'registeredMcpSetup',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.listing_create_prepare':{handler:'catalog.previewMerchantListingCreate',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.listing_edit_prepare':{handler:'catalog.previewMerchantListingEdit',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.inventory_prepare':{handler:'createRoleInventoryProposal',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.mail_reply_prepare':{handler:'mailActions.prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'merchant.review_decision_prepare':{handler:'createRoleReviewProposal',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.audit_recent':{handler:'admin.audit',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
 'admin.audit_agent_prepare':{handler:'auditJobs.prepare',operation:'readRequest',verb:'get',route:'/operations/:sessionId/:requestId'},
};
function walk(node,visit){
 if(!node||typeof node!=='object')return;
 if(typeof node.type==='string')visit(node);
 for(const [key,value] of Object.entries(node)){
  if(key==='loc'||key==='start'||key==='end'||key==='extra'||key==='comments')continue;
  if(Array.isArray(value))value.forEach(child=>walk(child,visit));
  else if(value&&typeof value==='object')walk(value,visit);
 }
}
const nodes=(root,predicate)=>{const found=[];walk(root,node=>{if(predicate(node))found.push(node)});return found};
const name=node=>node?.type==='Identifier'?node.name:null;
const literal=node=>node?.type==='StringLiteral'?node.value:null;
const prop=(node,key)=>node?.type==='ObjectExpression'?node.properties.find(p=>p.type==='ObjectProperty'&&(name(p.key)===key||literal(p.key)===key))?.value:null;
const member=node=>node?.type==='MemberExpression'&&!node.computed&&name(node.object)&&name(node.property)?`${name(node.object)}.${name(node.property)}`:null;
const memberPath=node=>node?.type==='Identifier'?node.name:['MemberExpression','OptionalMemberExpression'].includes(node?.type)&&!node.computed?`${memberPath(node.object)}.${name(node.property)}`:null;
const calleePath=node=>node?.type==='CallExpression'?`${calleePath(node.callee)}()`:['MemberExpression','OptionalMemberExpression'].includes(node?.type)&&!node.computed?`${calleePath(node.object)}.${name(node.property)}`:name(node);
const call=(node,callee)=>node?.type==='CallExpression'&&member(node.callee)===callee;
function handlerAnchor(body,anchor){
 if(anchor==='selectedReview')return nodes(body,n=>n.type==='CallExpression'&&calleePath(n.callee)==='readInScene'&&n.arguments.some(x=>name(x)==='selectedReview')).length===1;
 if(anchor==='registeredMcpSetup')return nodes(body,n=>n.type==='AssignmentExpression'&&name(n.left)==='registeredMcpSetup'&&n.right?.type==='ObjectExpression').length===1;
 return nodes(body,n=>n.type==='CallExpression'&&calleePath(n.callee)===anchor).length>0;
}
function generatedHandler(src,id){
 const tool=id.split('.')[1];let pair,template;
 if(tool==='mail_reply_prepare'){pair='reply';template='merchant.mail_|_prepare'}
 else if(tool.startsWith('listing_')&&tool.endsWith('_setup')){pair=tool;template='merchant.|'}
 else if(tool.startsWith('policy_')&&tool.endsWith('_prepare')){pair=tool;template='admin.|'}
 else if(tool.startsWith('mcp_')&&tool.endsWith('_prepare')){pair=tool;template='admin.|'}
 else return null;
 const matches=nodes(src,n=>n.type==='CallExpression'&&name(n.callee?.property)==='map'&&n.callee.object?.type==='ArrayExpression'
  &&n.callee.object.elements.some(e=>literal(e)===pair||e.type==='ArrayExpression'&&literal(e.elements[1])===pair)
  &&nodes(n.arguments[0],x=>x.type==='TemplateLiteral'&&x.quasis.map(q=>q.value.cooked).join('|')===template).length);
 assert.equal(matches.length,1,`generated handler family ${id}`);
 return matches[0].arguments[0];
}
function parse(file,overrides){return parser.parse(overrides?.[file]??fs.readFileSync(path.join(ROOT,file),'utf8'),{sourceType:'unambiguous'}).program}
function exactSourceNode(file,overrides,label,predicate,expected){
 const source=overrides?.[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
 const matches=nodes(parse(file,overrides),predicate);
 assert.equal(matches.length,1,`${label}: one selected node`);
 assert.equal(crypto.createHash('sha256').update(source.slice(matches[0].start,matches[0].end)).digest('hex'),expected,
  `${label}: selected source drift requires renewed review`);
 return matches[0];
}
const userLookupSourcePins=Object.freeze({
 descriptor:'9c4bf9bb3c97e93fc6311110a9e86c0a1c64a48f65261e638392301abf5779f7',
 availability:'ad65c49d89d47122ac69f38b8432fc1abf1c41368a74030dc3719b8388dacfaa',
 handler:'fc5e785d19dcf747b81123b9f99fddd08660357ab2fff256964daeb1020c59a9',
 savedReread:'c0dd89678821fa47355965c948203ee418c6c12553ccf5d5ec39c6098bc0b46b',
 composition:'e5aeff2d8ae9a6175affedcd64a1c82f9b72e0af5cdaeb56727e8f8d6c80d53e',
 assessmentComposition:'783eac9c273f349b5be56414001cb727f16894e59ae368ab39224974ff3e97cd',
 administration:'4e18f2b256e2b88fe51121b08b25a89e79fad63353ab3588fa5f18e724c37548',
 repository:'3639066e1b84f021b5926cc89181b65e1d51ca44f2bae646c8d87e5934e7f76f',
 directoryFields:'2a4fda99fecec1061421d9ae85a80199536eb3ab0dc3e4d5d0288c14ca3ec9e1',
 safeFields:'ea5ae39ed88adf2e20e1b7def2b13761793b67ed6c00082221cc8380abab2aa5',
 directoryDigest:'695badc04c04ce7f5d860566db901483cfea0991b3e8daf77846f55dd70880ca',
 rowDigest:'7beb848b3ca4a7716acf82dc54003b7be8db4c4b25be34144c71961def59be73',
 agentContext:'3145a230e2c5ab91998b2c681fada2bdf5ca22dc68a7ba6845f79aa10ea26605',
 reference:'e104a8f2ae200f52ac2f47da6ada60521412f084c0ea46bf0aa40e52af8854b4',
 syntheticDirectory:'4da000b5647757b1b4ef1825c6cd6e0c5ffd4fe2382999f2c6386bb9a077ad05',
 assessment:'b70fb442c668b3ab7d1c2bb6d781a883859856a03459601b4c5d3b353f966b36',
 assessmentRoute:'002b786bb5d189d7b8969a27ec0102c824b3dfa0866bf001d947291b73eb32ed',
 assessmentRouteMount:'6ec6e068fa86a2a3082f1465e13450ea957f050a9075344b41a0658d0f5b56f5',
 cryptoImport:'e3a2e3a2fded99a1b75f3deab69a492021a4fdd8b6ff03dca3f7a16053f2aa29',
 bcryptImport:'7dfe134911f64657da2d641ef5722c9079e1207822f825b97f0e4891d40c26d1',
 utilImport:'f30f87219c45a398766f3f295b65d7128bdbd20f39aec47a478cba3de19b8359',
 scopeImport:'d324e8aa08bc47b28affaa624ab2e8f14725cae5bec82fc112252922155b8f77',
});
const auditSummarySourcePins=Object.freeze({
 roleChat:'b91f7068045eb98cfe51774ecdc0a7f4c4474f6fc1e92f9cb75b253998400735',
 selectedHandler:'dfedd46c94199880d0e1fc29ac0e085e3bc3c2a078bcf00a88fdc9ba5494ff50',
 composition:'74f1ad43ce989827ee62a9fc01897b057180f0a7b2f3541931013203e017377a',
 auditJobsComposition:'4218bd653f590801d0eefda38c3da8f2bffeb29e7256c446e90b66fcc8f99e82',
 ordinaryProvider:'d8e6d01f5756d796108b529d86687550b9d8771c19156f67b1185db4d80f6618',
 runtimeComposition:'96a83b3d11e6adeddd60599e6af72d28fa564be052736bcdccaa8835ff3f3198',
 featureGate:'b90c781f5a2902fc3370c53f3bed6ea041672020e923f023b8ba684c8e05120c',
 jobs:'b4e4dfebb865dde74b0d1ec9035857350668da24f04d5e3d51cd62714a12547c',
 proposalInput:'0bf11c3f974c9c19aa561cf90ef47bb49287239cad7284415b726914f0266936',
 proposalCreate:'dcc24b01fbb057131b77562599bfab795039b45d560836adc7c68260b45ca522',
 proposalValidate:'c26827ccbe9fee57bf8a7adf0891da4abbbe5cc38c57423e8051bfd35c59d71c',
 proposalResult:'d7ae2e5d85506c396850b965ea71eff285c165c4fde5feaa8977125ae040e534',
 lifecycle:'aa16cabeb6f9ac6137f6df42288aa67b546b197af8f88e882a8bf87e03de4235',
 runtime:'20b07c9cb56c1ce05d9bd36416f667901dcb31b04cd144da669142b16edba91a',
 runner:'4af047901645de9921cb90838e242c2758c9a86fb4c9b46c6dfbd253802d93d7',
 job:'a39630ddef81137571add010e900cfe46397862d432557d0a7cb4fa4b31ba3ea',
 runRoute:'65348bfc9e0472f4f51be6d0bdb0564824a3c9494f70c40c049ce69a0e1b8a3f',
 readRoute:'72475321aa66dbd0b4f3d9057c23040b18ad5fabaa59a4727d6cac5ad2cb2617',
});
const auditSummaryFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [AUDIT_JOBS]:'a2794d32418b2489b9a3f07b895099a9b7c2c5015abf5923a62c07c25bd9a785',
 [AUDIT_PROPOSAL]:'633eba76c081d49fbe4e43c756c124e50668818c052b7c9bc258b1765313d7c4',
 [AUDIT_LIFECYCLE]:'efa6e6955b69093bd5c353a362844e1fc60b634b790d5a7636e90a263f67afeb',
 [AUDIT_RUNTIME]:'b5b820ff41e8a8584210155f427560a9f662a186f5191dd485750e273bf8f5bb',
 [AUDIT_RUNNER]:'29e8090884b0d1f201f84fffbf1eebec9dcf38902c5e82c16abc7f41e9abab87',
 [AUDIT_JOB]:'2d982dde9c87ed0e997640d6483441af938e7c2ebc2ba271e0c6dfb01263ba90',
 [AUDIT_HOST]:'953e57e3a5ba3764fbc72eea7a6de3a22a2ed82ca040ef93b2f148153afb36b1',
 [AUDIT_WORKER]:'43113d93d46a958a95ade742e27746f040a3a5476d008f8b5312e7bd129c009b',
 [AUDIT_GRAPH]:'00db79a31ebf2bdd32ac06fccf8f44316d0df5069cee802e56f413f9ca647f86',
 [AUDIT_PROVIDER]:'571f271f4341eeddf199e3351d7b9d0fa005695b923c10cdcee242aec3b72801',
 [AUDIT_MODEL_CHAIN]:'dc0e537f9719ce91f0a04e9361c66516c25dfbc64b9c4bd42f681d4ba7000560',
 [AUDIT_VERIFIED]:'7b9ce55c20f4ab7f2d06eecd4d6f956381fd836cad7841a923ebb5b66d46567c',
 [AUDIT_ARTIFACTS]:'b9403e53ddb08c144a6936656e58f3c42a2f325d0d7ff8e61c05f85f7943dc01',
 [ROUTER]:'6c08d6d93bf6b6b8c9dce4fd0cc497fe6a0afbc96c0789c11fee4ecc29e2b24b',
});
const mailReadSourcePins=Object.freeze({
 recipients:'3347d81df23a5e43adf3d5209bb39a5ed5002c533562ecc76c0ebd02a01d8d5f',
 list:'c5dcd1bacfc0ace562998e01d747e1952997f23924db47a22dd26aaf46f52443',
 detail:'76d81ed6120a7cb5c0f999d3b1d1fa2f1db78e10046f9992a2eab0835c854ea1',
 saved:'9a472921697232e5e91ed39b143bbb6dcef46da23e50e3d18b8b57e4909eedb2',
 active:'91c523e85714448525e0ac3438a19840b27113933e27e6566b2bb14bcc1b8078',
 composition:'ee38a722e80aa0106b03e1e782903939a6081906dd9c1fe777ce137666f53ad9',
 adapter:'ef7f47255e9291c6a869ec462e9b1e72a7395fb9395f31d41847db3693d04aed',
 packet:'cf1a0b6ea0ffbc348af737edf5dc1d03bdd7b9b9cdcab6e1c3b7b9bc6ac7d9e0',
 application:'d673d55f90aeb257f6d7f73ee958fc41492fcde4f70cc5fdd61e75a48c805e89',
 production:'f02fc4f40d021c90dade239fcb9f4b66b306373417f8d422d101afd884e23664',
 serving:'ee0b7e83bf83a552fe27389a33bdea58f6d904e6de6a942033913260168db49a',
 repository:'89877b7752df8992bcb48331b6871cb2d3b2ed4813afbc64e8df935edb3b212a',
 assessment:'8f14b3206dbb77a0f608fbee7c5249b2823e03d6328592f1de88cc0cbd3c91c5',
 original:'e33d217d355126884114909d29e51de211fd400f8277589ea26019ef7b64b99e',
 assessmentComposition:'f4aceafd386b8171519574c5bfbb77efed334fde6157d2fc0d3c31a3e7aa4f2b',
});
const mailReadFilePins=Object.freeze({
 [MAIL_READ]:'4a897771b2cebd1b75a5694f378c44e1fd31fc735b2bd7522380799e14b83aac',
 [MAIL_APP]:'996a234bb97af53de8ff74ab507cafcc64604c128d437983a789f2a28c0cd35f',
 [MAIL_PRODUCTION]:'1a41eddc2e785deae3ba435165075548633c4e39396bb2be1390ce6f786a7d88',
 [MAIL_COMPOSITION]:'7814585981a6c6473d2a42c3a956b10c806cb1ca27e18f70d91d6a4c47f49cc4',
 [MAIL_REPOSITORY]:'3a2780e01a7b29e14867cbe076f74d6146bc1019354e84663ce7ecd74f487f02',
 [MAIL_SQL]:'4c98f3d72364a5f29a86e83258181e6cb7b94e18553575db8f7f83a3e47e6c93',
 [MAIL_PROJECTION_SQL]:'4cd2edb2733f7ee388dd2e46304fbcb177f755e0f8a8524606b783e82b6aa15c',
 [MAIL_ASSESSMENT]:'54b8d0a36d36f9bf69f426123e31255d1b5f1a15541164d4b99b885bf579f772',
 [MAIL_ORIGINAL]:'cb9a84ed8cbab9fd27383a26a1190ab5b6135dfbb01186776dcd2059af6bab18',
});
const listingSetupFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [LISTING_SETUP]:'3a95843049ae4f16cb3bab17528b65845e8db5ba79347507b262d8c6bf389ddb',
 [LISTING_OPTIMIZE_SETUP]:'fbc1327eefe807087af32847f20f6762dc9e553c22e9f688ff0d1cffea17f79f',
 [LISTINGS_APP]:'cf60ac0f4d3a5e4ff2228f9ae3b07c0e66d7b1ba6cbf743a596c22263899a622',
 [LISTINGS_PRODUCTION]:'a875db6b92f2272072a3892631ff1a5b4856ab1e8bd2d434c696adb246d65395',
});
const merchantOrdersFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [COMMERCE]:'a53c5414a2ebf967e1822fa4e0dbe29b1c79e90e6f7e9bb0e322e39cfbd26aef',
 [COMMERCE_REPOSITORY]:'b91381bcb002260d4333f3ac28fb9c0906b99ce59eac0fb408ee462405ff59bc',
});
function checkMerchantOrders(manifest,overrides={}){
 const ids=['merchant.orders_list','merchant.orders_detail'];
 const rows=ids.map(id=>manifest.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId===id));
 assert.deepEqual(rows,[
  {descriptorId:ids[0],bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation'],
   availability:'Merchant general branch or physically requested older-orders continuation. The continuation supplies no model cursor or filter; source-bound saved page fixes the nextCursor and original productName. A fresh literal productName is bounded to 128 UTF-8 bytes.',
   handler:'createLocalTools: merchant.orders_list -> commerce.merchantOrders(persona, saved-or-selected cursor, literal productName)',
   consequence:"Reads at most five orders' lines for this merchant from the owned target. The SQL joins order items to products with retailer_id equal to the current merchant, calculates merchant line subtotals and returns only an owned nextCursor. Saved RoleChat readback validates the original page, hop, cursor and filter; it does not query a new page.",
   confirmation:'No separate confirmation for the read. A later older-orders request uses the saved sourceRequestId and same filter; physical continuation, actual model use and denial-no-effect are unverified.',
   modelApplicability:'model_selected_read_with_optional_physical_pagination',judgeApplicability:'not_inferred_from_owned_order_page',runtimeEvidence:null},
  {descriptorId:ids[1],bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation'],
   availability:'Merchant only after an exact physically selected saved merchant_order choiceId; the handler rechecks choiceId, current owned row and saved snapshot digest.',
   handler:'createLocalTools: merchant.orders_detail -> commerce.merchantOrder(orderId=selected.sourceId)',
   consequence:'Reads only current merchant-owned lines for the selected order through the same bounded SQL path, validates the selected snapshot and returns that order detail as untrusted observation; it does not read whole-checkout customer, address or payment data or mutate the order. Saved RoleChat GET returns the recorded turn, not another order query.',
   confirmation:'Physical order choice precedes detail. No separate confirmation for the read; actual selected-use, source-content adoption and denial-no-effect remain unverified.',
   modelApplicability:'model_selected_read_after_physical_choice',judgeApplicability:'not_inferred_from_owned_order_detail',runtimeEvidence:null},
 ]);
 for(const [file,sha] of Object.entries(merchantOrdersFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected merchant-order source drift`);
 }
 const role=parse(SOURCE,overrides),composition=parse(COMPOSITION,overrides),commerce=parse(COMMERCE,overrides),repo=parse(COMMERCE_REPOSITORY,overrides);
 for(const tool of ['orders_list','orders_detail']){
  const descriptor=nodes(role,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='merchant'&&literal(prop(n,'tool'))===tool);
  assert.equal(descriptor.length,1,`${tool}: one advertised descriptor`);
  const schema=prop(descriptor[0],'inputSchema');assert.equal(literal(prop(schema,'type')),'object');
  assert.equal(prop(schema,'additionalProperties')?.value,false);
  if(tool==='orders_list'){
   assert.equal(literal(prop(prop(prop(schema,'properties'),'cursor'),'pattern')),'^[A-Za-z0-9_-]{0,160}$');
   assert.equal(prop(prop(prop(schema,'properties'),'productName'),'maxLength')?.value,128);
   assert.equal(prop(schema,'required')??null,null);
  }else{
   assert.deepEqual(prop(schema,'required')?.elements.map(literal),['choiceId']);
   assert.equal(memberPath(prop(prop(prop(schema,'properties'),'choiceId'),'pattern')),'UUID.source');
  }
 }
 const handler=tool=>nodes(role,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===`merchant.${tool}`)[0]?.elements[1];
 const list=handler('orders_list'),detail=handler('orders_detail');assert.ok(list&&detail,'two selected handlers');
 assert.ok(nodes(list,n=>call(n,'commerce.merchantOrders')&&nodes(n.arguments[0],x=>memberPath(x)==='a.b').length
  &&nodes(n.arguments[0],x=>name(x)==='persona').length&&nodes(n.arguments[0],x=>name(x)==='cursor').length
  &&nodes(n.arguments[0],x=>name(x)==='name').length).length,'list forwards bound merchant, cursor and filter');
 assert.ok(nodes(list,n=>n.type==='VariableDeclarator'&&name(n.id)==='cursor'
  &&nodes(n.init,x=>memberPath(x)==='priorOrdersPage.nextCursor').length).length,'continuation derives saved cursor');
 assert.ok(nodes(list,n=>n.type==='VariableDeclarator'&&name(n.id)==='name'
  &&nodes(n.init,x=>memberPath(x)==='priorOrdersPage.productName').length).length,'continuation preserves saved filter');
 assert.ok(nodes(list,n=>n.type==='CallExpression'&&name(n.callee)==='merchantOrderRow').length,'list projects merchant-owned lines');
 assert.ok(nodes(list,n=>n.type==='AssignmentExpression'&&name(n.left)==='ordersPage'
  &&nodes(n.right,x=>memberPath(x)==='value.nextCursor').length).length,'page records selected cursor');
 assert.ok(nodes(detail,n=>call(n,'commerce.merchantOrder')&&nodes(n.arguments[0],x=>memberPath(x)==='selected.sourceId').length).length,'detail uses selected order ID');
 assert.ok(nodes(detail,n=>n.type==='BinaryExpression'&&n.operator==='!=='&&memberPath(n.left)==='row.orderId'
  &&memberPath(n.right)==='selected.sourceId').length,'detail rechecks selected order ID');
 assert.ok(nodes(detail,n=>n.type==='BinaryExpression'&&n.operator==='!=='&&nodes(n.left,x=>x.type==='CallExpression'&&name(x.callee)==='digest').length
  &&memberPath(n.right)==='selected.snapshotSha256').length,'detail rechecks original row digest');
 const previous=nodes(role,n=>n.type==='FunctionDeclaration'&&name(n.id)==='previousOrdersPage');assert.equal(previous.length,1);
 for(const value of ['meta.ordersPage','row.turn_request_hash','row.request_hash','page.nextCursor','query.productName','hop.params'])
  assert.ok(nodes(previous[0],n=>memberPath(n)===value).length,`saved page ${value}`);
 const readRequest=nodes(role,n=>n.type==='ObjectMethod'&&name(n.key)==='readRequest');assert.equal(readRequest.length,1);
 assert.ok(nodes(readRequest[0],n=>n.type==='CallExpression'&&name(n.callee)==='previousOrdersPage').length,'saved GET validates recorded order page');
 assert.ok(nodes(composition,n=>n.type==='CallExpression'&&name(n.callee)==='createSecureShopBoundCommerce'
  &&nodes(n.arguments[0],x=>name(x)==='commerceRepository').length).length,'composition installs owned commerce repository');
 assert.ok(nodes(composition,n=>n.type==='CallExpression'&&name(n.callee)==='createSecureShopBoundRoleChat'
  &&nodes(n.arguments[0],x=>name(x)==='commerce').length).length,'RoleChat receives bound commerce');
 const create=nodes(commerce,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createSecureShopBoundCommerce');assert.equal(create.length,1);
 const service=method=>nodes(create[0],n=>n.type==='ObjectMethod'&&name(n.key)===method)[0];
 assert.ok(nodes(service('merchantOrders'),n=>call(n,'repository.listMerchantOrders')
  &&nodes(n.arguments[1],x=>memberPath(x)==='request.persona.id').length).length,'list passes current persona merchant ID');
 assert.ok(nodes(service('merchantOrder'),n=>call(n,'repository.getMerchantOrder')
  &&nodes(n.arguments[1],x=>memberPath(x)==='request.persona.id').length).length,'detail passes current persona merchant ID');
 const sql=nodes(repo,n=>n.type==='FunctionDeclaration'&&name(n.id)==='merchantOrdersWithClient');assert.equal(sql.length,1);
 assert.ok(nodes(sql[0],n=>n.type==='TemplateLiteral'&&n.quasis.map(q=>q.value.cooked).join('').includes('p.retailer_id=$2')
  &&n.quasis.map(q=>q.value.cooked).join('').includes('o.target_id=$1')).length,'SQL binds target and merchant ownership');
 assert.ok(nodes(sql[0],n=>call(n,'client.query')&&n.arguments[1]?.type==='ArrayExpression'
  &&n.arguments[1].elements.some(x=>name(x)==='merchant')&&n.arguments[1].elements.some(x=>memberPath(x)==='value.targetId')).length,'SQL parameters bind current target and merchant');
 assert.ok(nodes(sql[0],n=>call(n,'rows.slice')&&n.arguments[1]?.value===5).length,'only five returned rows');
 const repoMethod=method=>nodes(repo,n=>n.type==='ObjectMethod'&&name(n.key)===method)[0];
 assert.ok(nodes(repoMethod('listMerchantOrders'),n=>n.type==='CallExpression'&&name(n.callee)==='merchantOrdersWithClient'
  &&n.arguments.some(x=>name(x)==='merchant')&&n.arguments.some(x=>name(x)==='cursor')).length,'list joins SQL helper');
 assert.ok(nodes(repoMethod('getMerchantOrder'),n=>n.type==='CallExpression'&&name(n.callee)==='merchantOrdersWithClient'
  &&n.arguments.some(x=>name(x)==='merchant')&&n.arguments.some(x=>name(x)==='id')).length,'detail joins same SQL helper');
}
const merchantReportingFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [COMMERCE]:'a53c5414a2ebf967e1822fa4e0dbe29b1c79e90e6f7e9bb0e322e39cfbd26aef',
 [COMMERCE_REPOSITORY]:'b91381bcb002260d4333f3ac28fb9c0906b99ce59eac0fb408ee462405ff59bc',
 [MERCHANT_METRICS]:'981feb23f89e61aa0cc75347ee9184743c63cd502d63d41b235e4c0c6e8453bf',
});
function checkMerchantReporting(manifest,overrides={}){
 const ids=['merchant.overview','merchant.top_products'];
 const rows=ids.map(id=>manifest.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId===id));
 assert.deepEqual(rows,[
  {descriptorId:ids[0],bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation'],
   availability:'Merchant general branch after higher-priority selection and continuation gates; this descriptor accepts no arguments and requests a 30-day current-persona reporting window.',
   handler:'createLocalTools: merchant.overview -> commerce.merchantOverview(days=30)',
   consequence:'Reads one merchant-owned order-line SQL snapshot excluding cancelled, declined and refunded orders. The service projects current/previous revenue, order count, AOV, daily series, top product and explicit modelUsed:false provenance; saved RoleChat GET returns the recorded observation, not a fresh report.',
   confirmation:'No separate confirmation for the report read. Physical model selection, persisted native result and denial-no-effect are unverified here.',
   modelApplicability:'model_selected_read_not_model_generated_metrics',judgeApplicability:'not_inferred_from_merchant_report',runtimeEvidence:null},
  {descriptorId:ids[1],bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation'],
   availability:'Merchant general branch after higher-priority selection and continuation gates; no arguments, fixed 30-day window and eight-product limit in this RoleChat handler.',
   handler:'createLocalTools: merchant.top_products -> commerce.merchantTopProducts(days=30, limit=8)',
   consequence:'Uses the same merchant-owned order-line SQL snapshot but returns at most eight validated product ID/name/revenue rows plus periodDays and source:owned-commerce. This is a deterministic report read, not a price, listing or stock change; saved RoleChat GET returns the recorded turn.',
   confirmation:'No separate confirmation for the report read. Physical use, exact returned rows and denial-no-effect remain native-evidence gaps.',
   modelApplicability:'model_selected_read_not_model_generated_ranking',judgeApplicability:'not_inferred_from_top_products_report',runtimeEvidence:null},
 ]);
 for(const [file,sha] of Object.entries(merchantReportingFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected merchant-reporting source drift`);
 }
 const role=parse(SOURCE,overrides),composition=parse(COMPOSITION,overrides),commerce=parse(COMMERCE,overrides),repo=parse(COMMERCE_REPOSITORY,overrides),metrics=parse(MERCHANT_METRICS,overrides);
 for(const [tool,service,properties] of [['overview','merchantOverview',['days']],['top_products','merchantTopProducts',['days','limit']]]){
  const descriptor=nodes(role,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='merchant'&&literal(prop(n,'tool'))===tool);
  assert.equal(descriptor.length,1,`${tool}: unique descriptor`);
  const schema=prop(descriptor[0],'inputSchema');assert.equal(literal(prop(schema,'type')),'object');
  assert.equal(prop(schema,'properties')?.properties.length,0);assert.equal(prop(schema,'additionalProperties')?.value,false);
  const handler=nodes(role,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===`merchant.${tool}`)[0]?.elements[1];assert.ok(handler);
  assert.ok(nodes(handler,n=>n.type==='CallExpression'&&name(n.callee)==='exact'
   &&name(n.arguments[0])==='args'&&n.arguments[1]?.type==='ArrayExpression'&&n.arguments[1].elements.length===0).length,`${tool}: no arguments accepted`);
  const calls=nodes(handler,n=>call(n,`commerce.${service}`));assert.equal(calls.length,1);
  const input=calls[0].arguments[0];assert.equal(input?.type,'ObjectExpression');
  assert.equal(prop(input,'days')?.value,30);if(properties.includes('limit'))assert.equal(prop(input,'limit')?.value,8);
  for(const key of ['scope','persona','personaSession'])assert.ok(prop(input,key),`${tool}: ${key} bound`);
  assert.ok(nodes(handler,n=>n.type==='CallExpression'&&name(n.callee)==='observation'
   &&name(n.arguments[0])==='value').length,`${tool}: returned value is observed`);
 }
 assert.ok(nodes(composition,n=>n.type==='CallExpression'&&name(n.callee)==='createSecureShopBoundCommerce'
  &&nodes(n.arguments[0],x=>name(x)==='commerceRepository').length).length,'composition owns reporting repository');
 assert.ok(nodes(composition,n=>n.type==='CallExpression'&&name(n.callee)==='createSecureShopBoundRoleChat'
  &&nodes(n.arguments[0],x=>name(x)==='commerce').length).length,'RoleChat receives bound reporting service');
 const create=nodes(commerce,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createSecureShopBoundCommerce');assert.equal(create.length,1);
 const service=key=>nodes(create[0],n=>n.type==='ObjectMethod'&&name(n.key)===key)[0];
 const overview=service('merchantOverview'),top=service('merchantTopProducts');assert.ok(overview&&top);
 for(const node of [overview,top])assert.ok(nodes(node,n=>call(n,'repository.merchantOverview')
  &&nodes(n.arguments[1],x=>memberPath(x)==='request.persona.id').length).length,'report query uses current merchant');
 assert.ok(nodes(overview,n=>n.type==='CallExpression'&&name(n.callee)==='projectMerchantMetrics'
  &&n.arguments.map(name).join(',')==='data,window,merchantId').length,'overview projects selected SQL result');
 assert.ok(nodes(top,n=>n.type==='ReturnStatement'&&prop(n.argument,'rows')&&prop(n.argument,'periodDays')
  &&literal(prop(n.argument,'source'))==='owned-commerce').length,'top products returns validated rows and source');
 assert.ok(nodes(top,n=>n.type==='VariableDeclarator'&&name(n.id)==='rows'
  &&n.init?.type==='CallExpression'&&calleePath(n.init.callee)==='data.products.map').length,'top products projects selected SQL products');
 assert.ok(nodes(top,n=>n.type==='IfStatement'&&nodes(n.test,x=>memberPath(x)==='data.products.length').length).length,'top product limit is checked');
 const query=nodes(repo,n=>n.type==='ObjectMethod'&&name(n.key)==='merchantOverview');assert.equal(query.length,1);
 assert.ok(nodes(query[0],n=>n.type==='TemplateLiteral'&&['o.target_id=$1','p.retailer_id=$2',"o.status <> 'cancelled'","o.payment_status NOT IN ('declined','refunded')",'LIMIT $6']
  .every(part=>n.quasis.map(q=>q.value.cooked).join('').includes(part))).length,'selected SQL owner, exclusions and limit');
 assert.ok(nodes(query[0],n=>call(n,'client.query')&&n.arguments[1]?.type==='ArrayExpression'
  &&n.arguments[1].elements.map(x=>memberPath(x)||name(x)).join(',')==='value.targetId,merchant,window.cutoff,window.previousCutoff,window.until,topLimit').length,'selected SQL parameter order');
 assert.ok(nodes(query[0],n=>n.type==='ReturnStatement'&&n.argument?.type==='MemberExpression'
  &&n.argument.computed&&name(n.argument.object)==='rows'&&n.argument.property?.value===0).length,'repository returns selected first snapshot row');
 const window=nodes(metrics,n=>n.type==='FunctionDeclaration'&&name(n.id)==='reportingWindow');assert.equal(window.length,1);
 const projection=nodes(metrics,n=>n.type==='FunctionDeclaration'&&name(n.id)==='projectMerchantMetrics');assert.equal(projection.length,1);
 assert.ok(nodes(projection[0],n=>n.type==='ObjectProperty'&&name(n.key)==='modelUsed'&&n.value?.value===false).length,'modelUsed:false is explicit provenance');
 for(const key of ['kpis','salesChart','aov','top_product','series'])assert.ok(nodes(projection[0],n=>name(n.key)===key).length,`overview ${key}`);
 const readRequest=nodes(role,n=>n.type==='ObjectMethod'&&name(n.key)==='readRequest');assert.equal(readRequest.length,1);
 assert.ok(nodes(readRequest[0],n=>n.type==='ObjectProperty'&&name(n.key)==='hops'
  &&nodes(n.value,x=>x.type==='CallExpression'&&name(x.callee)==='structuredClone').length).length,'saved readback returns recorded hops');
}
const merchantReviewReadFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [ROLE_REVIEW]:'022dbc72774fa1b59de1ee4fdcff59ea84379985a3f83722c7f4f9cb36a53001',
 [REVIEW_REPOSITORY]:'dd386e02f0920e7b91c28b41db95730d652367cb0cdc67fc0277951e2370c4d9',
});
function checkMerchantReviewReads(manifest,overrides={}){
 const ids=['merchant.reviews_list','merchant.reviews_detail'];
 const rows=ids.map(id=>manifest.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId===id));
 assert.deepEqual(rows,[
  {descriptorId:ids[0],bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation'],
   availability:'Merchant read in the general branch; optional page and status default to page 1/pending. An optional choiceId must match a physically selected saved merchant product or retained review-product choice; five rows per page are returned.',
   handler:'createLocalTools: merchant.reviews_list -> reviewService().list(page,status,selected productId)',
   consequence:'The conditional review service captures current merchant persona/mode/scene and lists at most five merchant-owned reviews through moderated repository filters. The assistant emits bounded review ID/product/rating/status choices and saved page/nextPage metadata, not review body or a moderation decision. Saved GET validates page metadata shape and current mode and returns the recorded turn, without listing a new page.',
   confirmation:'No separate confirmation for listing. Product-filter choice and older-page selection are physical inputs; their rendered use, native rows and denial-no-effect remain unverified.',
   modelApplicability:'model_selected_read_with_optional_physical_product_choice',judgeApplicability:'not_inferred_from_review_page',runtimeEvidence:null},
  {descriptorId:ids[1],bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation'],
   availability:'Merchant with exact physically selected saved merchant_review choiceId; current review detail and original snapshot digest are rechecked under the current review mode.',
   handler:'createLocalTools: merchant.reviews_detail -> selectedReview -> reviewService().detail(reviewId=selected.sourceId)',
   consequence:'Reads the selected merchant-owned review and projects its current mode-specific observation. Oversized review body is withheld from the model and marked for the manual Reviews page; saved RoleChat GET returns the recorded detail/mode, not a new moderation or detail query.',
   confirmation:'Physical review choice precedes detail. No separate confirmation for this read; moderation preparation/confirmation are separate actions, and native selected-use/content adoption remain unverified.',
   modelApplicability:'model_selected_read_after_physical_choice',judgeApplicability:'not_inferred_from_review_detail_or_body',runtimeEvidence:null},
 ]);
 for(const [file,sha] of Object.entries(merchantReviewReadFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected merchant-review source drift`);
 }
 const role=parse(SOURCE,overrides),composition=parse(COMPOSITION,overrides),service=parse(ROLE_REVIEW,overrides),repo=parse(REVIEW_REPOSITORY,overrides);
 for(const tool of ['reviews_list','reviews_detail']){
  const descriptor=nodes(role,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='merchant'&&literal(prop(n,'tool'))===tool);
  assert.equal(descriptor.length,1,`${tool}: one advertised descriptor`);
  const schema=prop(descriptor[0],'inputSchema');assert.equal(literal(prop(schema,'type')),'object');
  assert.equal(prop(schema,'additionalProperties')?.value,false);
  const choice=prop(prop(schema,'properties'),'choiceId');assert.equal(memberPath(prop(choice,'pattern')),'UUID.source');
  if(tool==='reviews_detail')assert.deepEqual(prop(schema,'required')?.elements.map(literal),['choiceId']);
  else{
   assert.equal(prop(schema,'required')??null,null);
   assert.equal(prop(prop(prop(schema,'properties'),'page'),'minimum')?.value,1);
   assert.equal(prop(prop(prop(schema,'properties'),'page'),'maximum')?.value,100000);
   assert.deepEqual(prop(prop(prop(schema,'properties'),'status'),'enum')?.elements.map(literal),['pending','approved','rejected','all']);
  }
 }
 const handler=tool=>nodes(role,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===`merchant.${tool}`)[0]?.elements[1];
 const list=handler('reviews_list'),detail=handler('reviews_detail');assert.ok(list&&detail);
 assert.ok(nodes(list,n=>n.type==='VariableDeclarator'&&name(n.id)==='page'&&n.init?.type==='LogicalExpression'
  &&n.init.operator==='??'&&n.init.right?.value===1).length,'list page defaults to one');
 assert.ok(nodes(list,n=>n.type==='VariableDeclarator'&&name(n.id)==='status'&&n.init?.type==='LogicalExpression'
  &&n.init.operator==='??'&&literal(n.init.right)==='pending').length,'list status defaults pending');
 assert.ok(nodes(list,n=>n.type==='BinaryExpression'&&n.operator==='!=='&&nodes(n.left,x=>x.type==='CallExpression'&&name(x.callee?.property)==='toLowerCase').length
  &&memberPath(n.right)==='productChoice.choiceId').length,'product filter matches selected choice');
 assert.ok(nodes(list,n=>n.type==='CallExpression'&&calleePath(n.callee)==='reviewService().list'
  &&nodes(n.arguments[0],x=>memberPath(x)==='productChoice.sourceId').length).length,'list passes selected product ID');
 assert.ok(nodes(list,n=>n.type==='BinaryExpression'&&n.operator==='>'&&memberPath(n.left)==='value.rows.length'&&n.right?.value===5).length,'list caps five rows');
 assert.ok(nodes(list,n=>n.type==='AssignmentExpression'&&name(n.left)==='reviewPage'
  &&nodes(n.right,x=>name(x.key)==='nextPage').length).length,'list saves exact page metadata');
 assert.ok(nodes(list,n=>n.type==='CallExpression'&&name(n.callee)==='observation'
  &&nodes(n.arguments[0],x=>name(x.key)==='reviews').length).length,'list returns bounded review summary');
 assert.ok(nodes(detail,n=>n.type==='BinaryExpression'&&n.operator==='!=='&&memberPath(n.left)==='selected.kind'
  &&literal(n.right)==='merchant_review').length,'detail requires selected review');
 assert.ok(nodes(detail,n=>n.type==='BinaryExpression'&&n.operator==='!=='&&nodes(n.left,x=>['CallExpression','OptionalCallExpression'].includes(x.type)&&name(x.callee?.property)==='toLowerCase').length
  &&memberPath(n.right)==='selected.choiceId').length,'detail matches choice ID');
 assert.ok(nodes(detail,n=>n.type==='CallExpression'&&name(n.callee)==='readInScene'
  &&name(n.arguments[0])==='selectedReview').length,'detail rereads selected review');
 const selected=nodes(role,n=>n.type==='VariableDeclarator'&&name(n.id)==='selectedReview');assert.equal(selected.length,1);
 assert.ok(nodes(selected[0],n=>n.type==='CallExpression'&&calleePath(n.callee)==='reviewService().detail'
  &&nodes(n.arguments[0],x=>memberPath(x)==='selected.sourceId').length).length,'selected review ID reaches service');
 assert.ok(nodes(selected[0],n=>n.type==='BinaryExpression'&&n.operator==='!=='&&nodes(n.left,x=>x.type==='CallExpression'&&name(x.callee)==='digest').length
  &&memberPath(n.right)==='selected.snapshotSha256').length,'current snapshot compared to saved digest');
 const oversize=nodes(role,n=>n.type==='VariableDeclarator'&&name(n.id)==='setReviewDetail');assert.equal(oversize.length,1);
 assert.ok(nodes(oversize[0],n=>n.type==='ConditionalExpression'&&name(n.test)==='oversized'&&n.consequent?.type==='NullLiteral'
  &&memberPath(n.alternate)==='value.row.body').length,'oversized body withheld');
 assert.ok(nodes(detail,n=>n.type==='ConditionalExpression'&&name(n.test)==='oversized'
  &&literal(prop(n.consequent,'reason'))==='REVIEW_TOO_LARGE').length,'model sees manual-review marker');
 assert.ok(nodes(composition,n=>n.type==='CallExpression'&&name(n.callee?.property)==='createRoleReviewService'
  &&nodes(n.arguments[0],x=>x.type==='ObjectProperty'&&name(x.key)==='repository'&&name(x.value)==='reviews').length).length,'composition creates scoped review service');
 assert.ok(nodes(composition,n=>n.type==='ObjectProperty'&&name(n.key)==='reviewApplication'
  &&nodes(n.value,x=>name(x)==='roleReviewService').length).length,'RoleChat gets conditional review service');
 const create=nodes(service,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createRoleReviewService');assert.equal(create.length,1);
 const context=nodes(create[0],n=>n.type==='FunctionDeclaration'&&name(n.id)==='context');assert.equal(context.length,1);
 for(const callee of ['captureFeatureMode','guardFeatureFence','repository.readSceneTarget','moderation.capture'])
  assert.ok(nodes(context[0],n=>n.type==='CallExpression'&&(name(n.callee)===callee||calleePath(n.callee)===callee)).length,`review context ${callee}`);
 const methods=key=>nodes(create[0],n=>n.type==='ObjectMethod'&&name(n.key)===key)[0];
 assert.ok(nodes(methods('list'),n=>call(n,'repository.listReviews')
  &&nodes(n.arguments[1],x=>memberPath(x)==='input.productId').length
  &&nodes(n.arguments[1],x=>x.value===5).length).length,'service list filters selected product and five rows');
 assert.ok(nodes(methods('detail'),n=>n.type==='CallExpression'&&name(n.callee)==='read'
  &&name(n.arguments[0])==='input').length,'service detail rereads selected review');
 const read=nodes(create[0],n=>n.type==='FunctionDeclaration'&&name(n.id)==='read');assert.equal(read.length,1);
 assert.ok(nodes(read[0],n=>call(n,'repository.getReview')
  &&memberPath(n.arguments[1])==='input.reviewId').length,'service read selects review ID');
 const repositoryList=nodes(repo,n=>n.type==='ObjectMethod'&&name(n.key)==='listReviews');assert.equal(repositoryList.length,1);
 assert.ok(nodes(repositoryList[0],n=>n.type==='TemplateLiteral'&&n.quasis.map(q=>q.value.cooked).join('').includes('WHERE ')
  &&n.quasis.map(q=>q.value.cooked).join('').includes('LIMIT $6 OFFSET $7')
  &&n.expressions.some(x=>name(x)==='where')).length,'repository lists bounded filtered rows');
 assert.ok(nodes(repositoryList[0],n=>n.type==='VariableDeclarator'&&name(n.id)==='where'
  &&nodes(n.init,x=>x.type==='CallExpression'&&name(x.callee)==='owned'
   &&literal(x.arguments[0])==='reviews'&&x.arguments[1]?.value===8&&x.arguments[2]?.value===9).length).length,'seller-owned filter included');
 const repositoryDetail=nodes(repo,n=>n.type==='ObjectMethod'&&name(n.key)==='getReview');assert.equal(repositoryDetail.length,1);
 assert.ok(nodes(repositoryDetail[0],n=>n.type==='TemplateLiteral'&&n.quasis.map(q=>q.value.cooked).join('').includes('target_id=$1 AND id=$2')).length,'detail selects exact target/review');
 assert.ok(nodes(repositoryDetail[0],n=>n.type==='CallExpression'&&name(n.callee)==='moderation').length,'detail requires moderation scope');
 const readRequest=nodes(role,n=>n.type==='ObjectMethod'&&name(n.key)==='readRequest');assert.equal(readRequest.length,1);
 assert.ok(nodes(readRequest[0],n=>n.type==='VariableDeclarator'&&name(n.id)==='reviewPage').length,'saved GET validates review page');
 assert.ok(nodes(readRequest[0],n=>n.type==='VariableDeclarator'&&name(n.id)==='reviewDetail').length,'saved GET validates review detail');
}
const merchantProductReadFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [CATALOG]:'3cc41dd265488120dca7d4a6eba14624fd4b81e2bea653df7b8d9d33719bcd0b',
 [PRODUCT_RETRIEVAL]:'0107de189e31f6ee1a94ab52c118fdf6cea81854728bed0adb7d929cf2529c69',
 [PRODUCT_REPOSITORY]:'32975368f8c0d03fc5ee19a2cd0b9b247bcebccdb892ef862950aeecc976fa2e',
 [EMBEDDING_REPOSITORY]:'2e0f7d21a5fd851b20bd2b31fc38395d51f1a841684b540f6ee0c5bf776df6a1',
});
function checkMerchantProductReads(manifest,overrides={}){
 const ids=['merchant.catalog_search','merchant.manual_search'];
 const rows=ids.map(id=>manifest.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId===id));
 assert.deepEqual(rows,[
  {descriptorId:ids[0],bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation'],
   availability:'Merchant read: unselected bounded search/status, saved page continuation with no model-supplied cursor, or exact physically selected merchant-product choice. Read-only inactive product cards are eligible only for catalog detail, not mutation.',
   handler:'createLocalTools: merchant.catalog_search -> catalog.searchMerchantProducts or selected owned catalog/product read',
   consequence:'Unselected search validates a UTF-8-bounded query and status, then reads at most five retailer-owned rows from a target-fenced SQL page; the sixth row determines next cursor. Selected detail rereads the exact saved product and digest. Saved catalog continuation reconstructs the original search/status/cursor and last-hop choices before another page; a saved GET returns the recorded turn. This read does not create or edit a product.',
   confirmation:'No separate confirmation for a catalog read. Product detail and next-page requests require physical selection or saved continuation; rendered use, actual rows, denial-no-effect and Judge remain native-evidence gaps.',
   modelApplicability:'model_selected_read_with_physical_choice_or_saved_page',judgeApplicability:'not_inferred_from_catalog_page_or_detail',runtimeEvidence:null},
  {descriptorId:ids[1],bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation'],
   availability:'Merchant manual_search intent, exact physically selected saved active merchant-product choice, and a present retrieval service; the server retains the literal current question rather than accepting a model-supplied query.',
   handler:'createLocalTools: merchant.manual_search -> productRetrieval.searchManuals(productId=selected.sourceId, query=server-held message)',
   consequence:'After owned-product digest and persona-effect checks, retrieval may ensure the shared manual corpus/revision, embed the exact question, and read up to three owned manual chunks through a revision-fenced vector query. Those corpus/revision steps may have effects and cannot be called no-effect merely because this descriptor returns a search result. Raw untrusted passages are preserved or omitted with an explicit oversized status; saved GET compares the original hop, selected product, query and validated result before returning the recorded turn.',
   confirmation:'Physical product selection is required; there is no separate manual-search confirmation. Actual corpus changes, returned passages, model use of text, denial-no-effect and Judge remain unverified.',
   modelApplicability:'model_selected_read_after_physical_product_choice',judgeApplicability:'not_inferred_from_manual_passages_or_saved_readback',runtimeEvidence:null},
 ]);
 for(const [file,sha] of Object.entries(merchantProductReadFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected merchant-product source drift`);
 }
 const role=parse(SOURCE,overrides),catalog=parse(CATALOG,overrides),retrieval=parse(PRODUCT_RETRIEVAL,overrides),products=parse(PRODUCT_REPOSITORY,overrides),manuals=parse(EMBEDDING_REPOSITORY,overrides);
 for(const tool of ['catalog_search','manual_search']){
  assert.equal(nodes(role,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='merchant'&&literal(prop(n,'tool'))===tool).length,1,`${tool}: one advertised descriptor`);
  assert.equal(nodes(role,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===`merchant.${tool}`&&n.elements?.[1]?.type==='ArrowFunctionExpression').length,1,`${tool}: one selected handler`);
 }
 const manual=nodes(role,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])==='merchant.manual_search')[0].elements[1];
 assert.ok(nodes(manual,n=>n.type==='BinaryExpression'&&n.operator==='!=='&&memberPath(n.left)==='productIntent'&&literal(n.right)==='manual_search').length,'manual intent required');
 assert.ok(nodes(manual,n=>['CallExpression','OptionalCallExpression'].includes(n.type)&&name(n.callee?.property)==='toLowerCase'&&memberPath(n.callee.object)==='args.choiceId').length,'manual exact selected choice');
 assert.ok(nodes(manual,n=>call(n,'catalog.getOwnedMerchantProduct')&&nodes(n.arguments[0],x=>memberPath(x)==='selected.sourceId').length).length,'manual owned product reread');
 assert.ok(nodes(manual,n=>call(n,'productRetrieval.searchManuals')&&name(prop(n.arguments[0],'query'))==='message'&&memberPath(prop(n.arguments[0],'productId'))==='selected.sourceId').length,'manual selected product and server question');
 const search=nodes(role,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])==='merchant.catalog_search')[0].elements[1];
 assert.ok(nodes(search,n=>call(n,'catalog.searchMerchantProducts')&&nodes(n.arguments[0],x=>name(x.key)==='afterProductId'&&memberPath(x.value)==='catalogSource.nextCursor').length).length,'catalog next cursor from saved source');
 assert.ok(nodes(search,n=>n.type==='ConditionalExpression'&&memberPath(n.consequent)==='catalog.getOwnedMerchantCatalogProduct'
  &&memberPath(n.alternate)==='catalog.getOwnedMerchantProduct').length,'selected product reread');
 assert.ok(nodes(search,n=>n.type==='BinaryExpression'&&n.operator==='!=='&&nodes(n.left,x=>x.type==='CallExpression'&&name(x.callee)==='digest').length&&memberPath(n.right)==='selected.snapshotSha256').length,'selected product digest');
 assert.ok(nodes(role,n=>n.type==='FunctionDeclaration'&&name(n.id)==='savedMerchantCatalogPage'&&nodes(n,x=>x.type==='StringLiteral'&&x.value==='merchant.catalog_search').length).length,'saved catalog last-hop validation');
 assert.ok(nodes(role,n=>n.type==='CallExpression'&&name(n.callee)==='validateManualSearchResult').length,'manual saved result validation');
 const catalogSearch=nodes(catalog,n=>n.type==='ObjectMethod'&&name(n.key)==='searchMerchantProducts');assert.equal(catalogSearch.length,1);
 assert.ok(nodes(catalogSearch[0],n=>call(n,'repository.listMerchantChoices')&&nodes(n.arguments[1],x=>name(x.key)==='retailerId'&&memberPath(x.value)==='actor.id').length).length,'catalog retailer-scoped repository call');
 const productList=nodes(products,n=>n.type==='ObjectMethod'&&name(n.key)==='listMerchantChoices');assert.equal(productList.length,1);
 assert.ok(nodes(productList[0],n=>n.type==='TemplateLiteral'&&n.quasis.map(q=>q.value.cooked).join('').includes('retailer_id=$2')&&n.quasis.map(q=>q.value.cooked).join('').includes('LIMIT 6')).length,'catalog retailer SQL and six-row cursor');
 const manualSearch=nodes(retrieval,n=>n.type==='ObjectMethod'&&name(n.key)==='searchManuals');assert.equal(manualSearch.length,1);
 for(const callee of ['catalog.getOwnedMerchantProduct','ensureCorpus','embed','revisionRepository.searchManuals','validateManualSearchResult'])
  assert.ok(nodes(manualSearch[0],n=>n.type==='CallExpression'&&calleePath(n.callee)===callee).length,`manual selected chain ${callee}`);
 assert.ok(nodes(manualSearch[0],n=>n.type==='StringLiteral'&&n.value==='oversized').length,'oversized manual marker');
 const revisionSearch=nodes(manuals,n=>n.type==='FunctionDeclaration'&&name(n.id)==='searchManuals');assert.equal(revisionSearch.length,1);
 assert.ok(nodes(revisionSearch[0],n=>n.type==='TemplateLiteral'&&n.quasis.map(q=>q.value.cooked).join('').includes('retailer_id=$3')).length,'manual selected retailer query');
}
const adminUserReadFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [USER_ADMIN]:'e14dac5ad0fcc38c854ef68e94b794b50ca76621446126d691c6c6725a7db432',
 [ROLE_USER_PROPOSAL]:'2aad8c094dbaa2b9118d468ef7bd9e4e14dba5bde4840d84fc1b619d8171c949',
});
function checkAdminUserReadsAndPreparations(manifest,overrides={}){
 const ids=['admin.users_search','admin.role_change_prepare','admin.ban_prepare','admin.password_reset_setup'];
 const rows=ids.map(id=>manifest.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId===id));
 assert.deepEqual(rows,[
  {descriptorId:ids[0],bridgeActionIds:['agent.admin.assistant.chat','agent.admin.assistant.operation'],
   availability:'Admin general branch searches tenant users by supplied search, or a physically selected saved tenant_user choice requests one current exact user; the selected branch rechecks ID, username and digest.',
   handler:'createLocalTools: admin.users_search -> admin.users(pageSize=5) or userAdministration.user(targetId=selected.sourceId)',
   consequence:'General search reads at most five projected directory rows and issues opaque tenant-user choices. Selected detail rereads the exact chosen user and current administration capability. Saved RoleChat GET returns the recorded turn. No role, ban or password change occurs from this search.',
   confirmation:'No separate confirmation for the read. Selected detail requires physical choice; native rows, rendered use and denial-no-effect remain unverified.',
   modelApplicability:'model_selected_read_with_optional_physical_user_choice',judgeApplicability:'not_inferred_from_user_directory_read',runtimeEvidence:null},
  {descriptorId:ids[1],bridgeActionIds:['agent.admin.assistant.chat','agent.admin.assistant.operation'],
   availability:'Admin with user_role intent, exact physically selected saved tenant_user choice, and bound user-administration service; current ID, username, scope authority and snapshot digest must match.',
   handler:'createLocalTools: admin.role_change_prepare -> prepareUserAdministration(set_role, selected user/newRole)',
   consequence:'Rereads the selected user and builds a bound role-change proposal carrying the physically supplied new role, current authority scope and mode. The model sees only prepared_for_confirmation; saved GET reprojects the proposal against the original selected request. The role has not changed.',
   confirmation:'Separate trusted role-change confirmation is required for any effect. Preparation, saved readback, rendered choice and native role effect/Judge remain distinct evidence boundaries.',
   modelApplicability:'model_selected_proposal_after_physical_user_and_role_choice',judgeApplicability:'not_inferred_from_role_proposal',runtimeEvidence:null},
  {descriptorId:ids[2],bridgeActionIds:['agent.admin.assistant.chat','agent.admin.assistant.operation'],
   availability:'Admin with user_ban intent, exact physically selected saved tenant_user choice, and bound user-administration service; current ID, username, scope authority and snapshot digest must match.',
   handler:'createLocalTools: admin.ban_prepare -> prepareUserAdministration(ban, selected user/reason)',
   consequence:'Rereads the selected user and builds a bound ban proposal carrying the physically supplied reason, current authority scope and mode. The model sees only prepared_for_confirmation; saved GET reprojects the proposal against the original selected request. No ban is applied.',
   confirmation:'Separate trusted ban confirmation is required for any effect. Preparation, saved readback, rendered choice and native ban effect/Judge remain distinct evidence boundaries.',
   modelApplicability:'model_selected_proposal_after_physical_user_and_reason',judgeApplicability:'not_inferred_from_ban_proposal',runtimeEvidence:null},
  {descriptorId:ids[3],bridgeActionIds:['agent.admin.assistant.chat','agent.admin.assistant.operation'],
   availability:'Admin with user_password_reset intent and exact selected saved tenant_user choice; self-reset is denied. Registered-account and teaching-persona identities take separate channels, and teaching persona requires current bound reset readiness.',
   handler:'createLocalTools: admin.password_reset_setup -> preparePasswordReset(selected user/channel)',
   consequence:'Rereads the selected current user and constructs a request/choice/mode-bound reset handoff. The model sees only handoff and channel; saved GET validates the original hop, choice, selected user and current channel/readiness. No password is reset, revealed or acknowledged by setup.',
   confirmation:'A separate protected reset control and recovery path owns any credential effect. Setup, rendered handoff, native reset effect, denial-no-effect and Judge remain unverified here.',
   modelApplicability:'model_selected_no_effect_handoff_after_physical_user_choice',judgeApplicability:'not_inferred_from_password_reset_setup',runtimeEvidence:null},
 ]);
 for(const [file,sha] of Object.entries(adminUserReadFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected admin-user source drift`);
 }
 const src=parse(SOURCE,overrides),service=parse(USER_ADMIN,overrides),proposal=parse(ROLE_USER_PROPOSAL,overrides),composition=parse(COMPOSITION,overrides);
 for(const tool of ['users_search','role_change_prepare','ban_prepare','password_reset_setup'])
  assert.equal(nodes(src,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='admin'&&literal(prop(n,'tool'))===tool).length,1,`${tool}: advertised descriptor`);
 const handler=tool=>nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===`admin.${tool}`&&['ArrowFunctionExpression','FunctionExpression'].includes(n.elements?.[1]?.type))[0]?.elements[1];
 for(const tool of ['role_change_prepare','ban_prepare'])assert.ok(nodes(handler(tool),n=>n.type==='CallExpression'&&name(n.callee)==='prepareUserAdministration').length,`${tool}: selected shared preparation`);
 assert.ok(nodes(handler('password_reset_setup'),n=>n.type==='CallExpression'&&name(n.callee)==='preparePasswordReset').length,'reset selected handoff');
 const search=handler('users_search');assert.ok(search,'user search handler');
 assert.ok(nodes(search,n=>call(n,'userAdministration.user')&&nodes(n.arguments[0],x=>name(x.key)==='targetId'&&memberPath(x.value)==='selected.sourceId').length).length,'selected exact user reread');
 assert.ok(nodes(search,n=>call(n,'admin.users')&&nodes(n.arguments[0],x=>name(x.key)==='pageSize'&&x.value?.value===5).length).length,'unselected bounded user search');
 const prepare=nodes(src,n=>n.type==='VariableDeclarator'&&name(n.id)==='prepareUserAdministration')[0];assert.ok(prepare);
 assert.ok(nodes(prepare,n=>call(n,'userAdministration.user')&&nodes(n.arguments[0],x=>name(x.key)==='targetId'&&memberPath(x.value)==='selected.sourceId').length).length,'proposal current selected user');
 assert.ok(nodes(prepare,n=>n.type==='CallExpression'&&name(n.callee)==='createRoleUserAdministrationProposal'&&nodes(n.arguments[0],x=>name(x.key)==='action').length).length,'bound user proposal construction');
 assert.ok(nodes(prepare,n=>n.type==='StringLiteral'&&n.value==='prepared_for_confirmation').length,'proposal-only observation');
 const reset=nodes(src,n=>n.type==='VariableDeclarator'&&name(n.id)==='preparePasswordReset')[0];assert.ok(reset);
 assert.ok(nodes(reset,n=>call(n,'userAdministration.user')&&nodes(n.arguments[0],x=>name(x.key)==='targetId'&&memberPath(x.value)==='selected.sourceId').length).length,'reset current selected user');
 assert.ok(nodes(reset,n=>call(n,'userAdministration.passwordResetReadiness')&&nodes(n.arguments[0],x=>name(x.key)==='targetId'&&memberPath(x.value)==='selected.sourceId').length).length,'teaching-persona bound readiness');
 assert.ok(nodes(reset,n=>n.type==='StringLiteral'&&n.value==='protected_account').length&&nodes(reset,n=>n.type==='StringLiteral'&&n.value==='bound_persona').length,'two distinct reset channels');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='projectRoleUserAdministrationProposal').length,'saved proposal projection');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='validateResetSetup').length,'saved reset setup validation');
 assert.ok(nodes(service,n=>n.type==='ObjectMethod'&&name(n.key)==='user'&&nodes(n,x=>call(x,'directory.user')).length).length,'administration exact user read');
 assert.ok(nodes(service,n=>n.type==='ObjectMethod'&&name(n.key)==='users'&&nodes(n,x=>call(x,'directory.users')).length).length,'administration tenant-directory search');
 assert.ok(nodes(proposal,n=>n.type==='FunctionDeclaration'&&name(n.id)==='create').length,'proposal codec selected builder');
 assert.ok(nodes(composition,n=>n.type==='VariableDeclarator'&&name(n.id)==='userAdministration').length,'conditional composed user service');
}
const adminAclFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [ACL_CHAT]:'3fa50cce3b076614dcb99bde7fcbc230dd537f20cba985f795f71bac647a3fff',
 [ACL_PROPOSAL]:'fcd2d9602da5ac0750631b5b86619276920d408db56a23a60042ba010a9ef0aa',
 [ACCESS_CONTROL]:'06eee98723ca242819cf9136710303287ad60d0ff7d05123d5288f4b82cd0162',
});
function checkAdminAclDiscoveryAndPreparations(manifest,overrides={}){
 const ids=['admin.acl_list','admin.acl_permission_prepare','admin.acl_enforcement_prepare'];
 const rows=ids.map(id=>manifest.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId===id));
 assert.deepEqual(rows,[
  {descriptorId:ids[0],bridgeActionIds:['agent.admin.assistant.chat','agent.admin.assistant.operation'],
   availability:'Admin with a ready bound ACL service and no selected choice; optional exact tool-key search and page are bounded, with five applicable writable tool/role choices per page.',
   handler:'createLocalTools: admin.acl_list -> aclChat.snapshot(context) -> five choice page',
   consequence:'Reads the current versioned ACL state, filters unsupported, read-only or inapplicable tool-role rows, and issues a five-choice page with current allowed and enforcement values. Saved GET checks the recorded page and original last-hop observation before returning the saved turn. Listing does not alter policy.',
   confirmation:'No separate confirmation for listing. Physical choice and native observed rows remain unverified; a listed permission is not an applied policy change.',
   modelApplicability:'model_selected_acl_discovery_read',judgeApplicability:'not_inferred_from_acl_page',runtimeEvidence:null},
  {descriptorId:ids[1],bridgeActionIds:['agent.admin.assistant.chat','agent.admin.assistant.operation'],
   availability:'Admin with acl_allow or acl_deny intent, a ready ACL service and exact physically selected saved tool/role choiceId; the selected snapshot digest must still match current supported applicable policy.',
   handler:'createLocalTools: admin.acl_permission_prepare -> aclChat.prepare(permission, selected tool/role, trusted allowed)',
   consequence:'Re-reads the current versioned ACL snapshot, rejects stale or no-change choice, and builds a digest-bound permission proposal using the trusted Allow/Deny selection, not a model-supplied allowed value. The model sees prepared_for_confirmation; saved GET verifies original choice/proposal. No ACL permission write occurs until separate confirmation.',
   confirmation:'A separate trusted ACL confirmation owns the versioned policy mutation and receipt. Preparation, rendered choice, native effect and Judge are distinct evidence boundaries.',
   modelApplicability:'model_selected_acl_permission_proposal_after_physical_choice',judgeApplicability:'not_inferred_from_acl_permission_proposal',runtimeEvidence:null},
  {descriptorId:ids[2],bridgeActionIds:['agent.admin.assistant.chat','agent.admin.assistant.operation'],
   availability:'Admin with ready bound ACL service and no selected choice; selected enabled must be boolean and differ from the current enforcement state.',
   handler:'createLocalTools: admin.acl_enforcement_prepare -> aclChat.prepare(enforcement, enabled=args.enabled)',
   consequence:'Re-reads current versioned ACL state and builds a digest-bound enforcement proposal for the selected boolean. The model sees prepared_for_confirmation; saved GET verifies the original enabled argument and proposal. No enforcement-state write occurs until separate confirmation.',
   confirmation:'A separate trusted ACL confirmation owns the versioned policy mutation and receipt. Preparation, rendered use, native effect and Judge are distinct evidence boundaries.',
   modelApplicability:'model_selected_acl_enforcement_proposal',judgeApplicability:'not_inferred_from_acl_enforcement_proposal',runtimeEvidence:null},
 ]);
 for(const [file,sha] of Object.entries(adminAclFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected ACL source drift`);
 }
 const src=parse(SOURCE,overrides),composition=parse(COMPOSITION,overrides),acl=parse(ACL_CHAT,overrides),proposal=parse(ACL_PROPOSAL,overrides),access=parse(ACCESS_CONTROL,overrides);
 for(const tool of ['acl_list','acl_permission_prepare','acl_enforcement_prepare'])
  assert.equal(nodes(src,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='admin'&&literal(prop(n,'tool'))===tool).length,1,`${tool}: advertised descriptor`);
 const handler=tool=>nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===`admin.${tool}`)[0]?.elements[1];
 const list=handler('acl_list'),permission=handler('acl_permission_prepare'),enforcement=handler('acl_enforcement_prepare');
 assert.ok(nodes(list,n=>call(n,'aclChat.snapshot')&&nodes(n.arguments[0],x=>name(x.key)==='context'&&name(x.value)==='aclContext').length).length,'ACL list reads bound snapshot');
 assert.ok(nodes(list,n=>n.type==='CallExpression'&&name(n.callee?.property)==='slice'&&nodes(n.arguments[0],x=>x.type==='NumericLiteral'&&x.value===5).length).length||nodes(list,n=>n.type==='BinaryExpression'&&n.operator==='*'&&n.right?.value===5).length,'ACL list five-row page');
 assert.ok(nodes(permission,n=>call(n,'aclChat.prepare')&&nodes(n.arguments[0],x=>name(x.key)==='action'&&literal(x.value)==='permission').length).length,'permission proposal selected action');
 assert.ok(nodes(permission,n=>n.type==='BinaryExpression'&&n.operator==='==='&&name(n.left)==='aclIntent'&&literal(n.right)==='acl_allow').length,'trusted Allow or Deny choice');
 assert.ok(nodes(enforcement,n=>call(n,'aclChat.prepare')&&nodes(n.arguments[0],x=>name(x.key)==='action'&&literal(x.value)==='enforcement').length).length,'enforcement proposal selected action');
 assert.ok(nodes(enforcement,n=>n.type==='ObjectProperty'&&name(n.key)==='enabled'&&memberPath(n.value)==='args.enabled').length,'selected boolean reaches proposal');
 assert.ok(nodes(src,n=>n.type==='IfStatement'&&name(n.test)==='aclPage'&&nodes(n,x=>x.type==='StringLiteral'&&x.value==='admin.acl_list').length).length,'saved ACL page last hop');
 assert.ok(nodes(src,n=>n.type==='IfStatement'&&name(n.test)==='aclProposal'&&nodes(n,x=>x.type==='CallExpression'&&name(x.callee)==='validateRoleAclProposal').length).length||nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='validateRoleAclProposal').length,'saved ACL proposal validation');
 assert.ok(nodes(composition,n=>n.type==='CallExpression'&&name(n.callee?.property)==='createBoundAclChat').length,'ACL service conditionally composed');
 const methods=key=>nodes(acl,n=>n.type==='FunctionDeclaration'&&name(n.id)===key);
 assert.equal(methods('snapshot').length,1);assert.equal(methods('prepare').length,1);
 assert.ok(nodes(methods('snapshot')[0],n=>call(n,'accessControl.read')).length,'snapshot reads real ACL service');
 assert.ok(nodes(methods('snapshot')[0],n=>n.type==='UnaryExpression'&&n.operator==='!'&&memberPath(n.argument)==='row.supported').length,'unsupported tool filtered');
 assert.ok(nodes(methods('prepare')[0],n=>n.type==='CallExpression'&&name(n.callee)==='snapshot').length,'prepare rereads current state');
 assert.ok(nodes(methods('prepare')[0],n=>n.type==='CallExpression'&&calleePath(n.callee)==='C.createRoleAclProposal').length,'prepare constructs digest-bound proposal');
 assert.ok(nodes(proposal,n=>n.type==='FunctionDeclaration'&&name(n.id)==='create').length,'ACL proposal codec present');
 assert.ok(nodes(access,n=>n.type==='ObjectMethod'&&name(n.key)==='read').length&&nodes(access,n=>n.type==='ObjectMethod'&&name(n.key)==='mutate').length,'read/mutate service separate');
}
const pricingFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [PRICING_PROPOSAL]:'ea14829b5b902ac760546128ccfbcb2924c89863bfad825364f89e06da640d9c',
});
function checkMerchantPricingPreparations(manifest,overrides={}){
 const ids=['merchant.pricing_suggest_prepare','merchant.pricing_compare_prepare','merchant.pricing_experiment_prepare'];
 const rows=ids.map(id=>manifest.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId===id));
 const common=['agent.merchant.assistant.chat','agent.merchant.assistant.operation'];
 assert.deepEqual(rows,[
  {descriptorId:ids[0],bridgeActionIds:common,availability:'Merchant with explicitly selected owned product in ordinary product branch; only saved choiceId is model-supplied and ready versioned Pricing application is required.',handler:'createLocalTools: merchant.pricing_suggest_prepare -> preparePricing(suggest,args,invocation)',consequence:'Rereads selected owned product, saved digest and current Pricing mode, then creates a digest-bound suggestion proposal. Protected RoleChat GET returns the saved projected proposal; preparation does not run Pricing or change price.',confirmation:'Separate trusted Pricing Run rereads the original choice and proposal before any model/effect; native effect, denial, receipt and Judge remain unverified.',modelApplicability:'model_selected_pricing_suggestion_proposal',judgeApplicability:'not_inferred_from_pricing_preparation',runtimeEvidence:null},
  {descriptorId:ids[1],bridgeActionIds:common,availability:'Merchant explicitly selected pricing_compare for owned product; only saved choiceId is model-supplied and exact competitor URL remains server-held.',handler:'createLocalTools: merchant.pricing_compare_prepare -> preparePricing(compare,args,invocation)',consequence:'Rereads selected owned product, saved digest and current Pricing mode, then creates a digest-bound proposal with trusted competitor URL. Saved GET checks original successful compare hop, request envelope and choice. Preparation does not fetch URL or change price.',confirmation:'Separate trusted Pricing Run owns possible fetch/model/effect; physical selection, denial, receipt and Judge remain unverified.',modelApplicability:'model_selected_pricing_compare_proposal_with_server_held_url',judgeApplicability:'not_inferred_from_pricing_preparation',runtimeEvidence:null},
  {descriptorId:ids[2],bridgeActionIds:common,availability:'Merchant with explicitly selected owned product; model supplies saved choiceId, strategy undercut/premium/bundle and integer durationDays 1-90.',handler:'createLocalTools: merchant.pricing_experiment_prepare -> preparePricing(experiment,args,invocation)',consequence:'Rereads selected owned product, saved digest and current Pricing mode, then creates a digest-bound version-two proposal with selected strategy/duration and original message. Saved GET checks original successful hop, source envelope and choice. Preparation does not run experiment or change price.',confirmation:'Separate trusted Pricing Run owns any model/effect; native execution, denial, receipt and Judge remain unverified.',modelApplicability:'model_selected_pricing_experiment_proposal',judgeApplicability:'not_inferred_from_pricing_preparation',runtimeEvidence:null},
 ]);
 for(const [file,sha] of Object.entries(pricingFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected Pricing source drift`);
 }
 const src=parse(SOURCE,overrides),composition=parse(COMPOSITION,overrides),proposal=parse(PRICING_PROPOSAL,overrides);
 for(const [tool,action] of [['pricing_suggest_prepare','suggest'],['pricing_compare_prepare','compare'],['pricing_experiment_prepare','experiment']]){
  const declared=nodes(src,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='merchant'&&literal(prop(n,'tool'))===tool);
  assert.equal(declared.length,1,`${tool}: declared schema`);
  const schema=prop(declared[0],'inputSchema');
  assert.equal(literal(prop(schema,'type')),'object');
  assert.equal(prop(schema,'additionalProperties')?.value,false);
  const required=prop(schema,'required')?.elements.map(literal);
  assert.deepEqual(required,action==='experiment'?['choiceId','strategy','durationDays']:['choiceId']);
  const handler=nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===`merchant.${tool}`&&n.elements?.[1]?.type==='ArrowFunctionExpression');
  assert.equal(handler.length,1);
  assert.equal(nodes(handler[0].elements[1],n=>n.type==='CallExpression'&&name(n.callee)==='preparePricing'&&literal(n.arguments[0])===action&&name(n.arguments[1])==='args'&&name(n.arguments[2])==='invocation').length,1,`${tool}: selected arguments`);
 }
 const prepare=nodes(src,n=>n.type==='VariableDeclarator'&&name(n.id)==='preparePricing');assert.equal(prepare.length,1);
 assert.ok(nodes(prepare[0],n=>n.type==='CallExpression'&&calleePath(n.callee)==='catalog.getOwnedMerchantProduct'&&memberPath(prop(n.arguments[0],'productId'))==='selected.sourceId').length,'owned selected product reread');
 assert.ok(nodes(prepare[0],n=>n.type==='BinaryExpression'&&n.operator==='!=='&&nodes(n,x=>calleePath(x.callee)==='digest').length&&memberPath(n.right)==='selected.snapshotSha256').length,'selected digest equality guard');
 assert.ok(nodes(prepare[0],n=>n.type==='CallExpression'&&name(n.callee)==='captureFeatureMode'&&literal(n.arguments[2])==='pricing').length,'pricing mode capture');
 assert.ok(nodes(prepare[0],n=>n.type==='CallExpression'&&name(n.callee)==='createRolePricingProposal'&&nodes(n.arguments[0],x=>memberPath(x.value)==='selection.competitorUrl').length&&nodes(n.arguments[0],x=>memberPath(x.value)==='message').length).length,'server-held URL and original experiment message');
 assert.ok(nodes(prepare[0],n=>n.type==='ReturnStatement'&&n.argument?.type==='CallExpression'&&name(n.argument.callee)==='pricingPreparationObservation').length,'preparation observation, not run');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='validateRolePricingProposal'&&memberPath(n.arguments[0])==='meta.pricingProposal').length,'saved proposal validation');
 for(const action of ['compare','experiment'])assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='createRolePricingProposal'&&nodes(n.arguments[0],x=>name(x.key)==='action'&&literal(x.value)===action).length).length,`${action}: saved original reconstruction`);
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&calleePath(n.callee)==='pricing.run').length,'separate confirmed Pricing Run');
 assert.ok(nodes(composition,n=>n.type==='ObjectProperty'&&name(n.key)==='pricingApplication'&&nodes(n.value,x=>memberPath(x)==='createdPricing.application').length).length,'conditional composed Pricing provider');
 assert.ok(nodes(proposal,n=>n.type==='FunctionDeclaration'&&name(n.id)==='create'&&nodes(n,x=>x.type==='CallExpression'&&name(x.callee)==='requestDigest').length).length,'digest-bound proposal codec');
}
const policyFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [POLICY_CHAT]:'9826c32ac40a12673b7db69939e04c407a5a4291d07cba0fe67b4b59e0468910',
 [POLICY_PROPOSAL]:'bfca1eeb59e01bbb6e09aa98b6de2da3e844110a95ecd945a7dbaa4546bb142a',
});
const policyRowPins=Object.freeze({
 'admin.policies_search':'fa2c787ed7d42ad8434ca73c1715cac9f9de2c94ad7b6703389ad41a650bc907',
 'admin.policy_detail':'aedb4d198f5714e7e90570e2493700a6b093debf1fb9a00b45988f5f341f25bd',
 'admin.policy_create_prepare':'a3db122d1d9dc8ffb0bc83a7e7aefbf9cdc45890422847aa1596560c7cfcd107',
 'admin.policy_edit_prepare':'33da706acbca5e5ca94591eb9fdebfbae8f02fc3481928e9aaba37eab4629c0f',
 'admin.policy_preview_prepare':'51e587a4c9cdebddc891c0be53402defe91611988973eebd9364d4b524072f1e',
 'admin.policy_delete_prepare':'c54e6f3c6ed6dc52baac0d0d5f05617939cf1e7fa0c9b83c8481a8ba3a945ace',
});
function checkAdminPolicyBatch(manifest,overrides={}){
 const rows=manifest.roleChatDescriptorPartition.reviewedDescriptors;
 for(const [id,sha] of Object.entries(policyRowPins)){
  const row=rows.find(item=>item.descriptorId===id);assert.ok(row,`${id}: reviewed row`);
  assert.equal(crypto.createHash('sha256').update(JSON.stringify(row)).digest('hex'),sha,`${id}: full metadata drift`);
  assert.equal(row.runtimeEvidence,null);
 }
 for(const [file,sha] of Object.entries(policyFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected Policy source drift`);
 }
 const src=parse(SOURCE,overrides),composition=parse(COMPOSITION,overrides),service=parse(POLICY_CHAT,overrides),proposal=parse(POLICY_PROPOSAL,overrides);
 const declared=tool=>nodes(src,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='admin'&&literal(prop(n,'tool'))===tool);
 for(const tool of ['policies_search','policy_detail','policy_create_prepare','policy_edit_prepare','policy_preview_prepare','policy_delete_prepare']){
  const found=declared(tool);assert.equal(found.length,1,`${tool}: advertised schema`);
  const schema=prop(found[0],'inputSchema');assert.equal(literal(prop(schema,'type')),'object');
  assert.equal(prop(schema,'additionalProperties')?.value,false);
  const expected=tool==='policies_search'?[]:tool==='policy_create_prepare'?['name','markdown','targets']:tool==='policy_edit_prepare'?['choiceId','patch']:['choiceId'];
  assert.deepEqual(prop(schema,'required')?.elements.map(literal)??[],expected,`${tool}: required selected arguments`);
 }
 const availability=nodes(src,n=>n.type==='IfStatement'&&n.test?.type==='CallExpression'&&calleePath(n.test.callee)==='tool.tool.startsWith'&&literal(n.test.arguments[0])==='polic');
 assert.equal(availability.length,1,'one conditional policy availability branch');
 for(const action of ['detail','edit','preview','delete'])assert.ok(nodes(availability[0],n=>n.type==='BinaryExpression'&&n.operator==='==='&&memberPath(n.left)==='policyIntent'&&literal(n.right)===`policy_${action}`).length,`${action}: selected intent gate`);
 assert.ok(nodes(availability[0],n=>n.type==='UnaryExpression'&&n.operator==='!'&&name(n.argument)==='policyChat').length,'policy service readiness gate');
 assert.ok(nodes(availability[0],n=>n.type==='ReturnStatement'&&nodes(n,x=>x.type==='UnaryExpression'&&x.operator==='!'&&name(x.argument)==='selected').length&&nodes(n,x=>literal(x)==='policies_search').length).length,'unselected discovery gate');
 const search=nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])==='admin.policies_search'&&n.elements?.[1]?.type==='ArrowFunctionExpression');assert.equal(search.length,1);
 assert.ok(nodes(search[0].elements[1],n=>n.type==='CallExpression'&&name(n.callee)==='policySnapshot').length,'scoped snapshot read');
 assert.ok(nodes(search[0].elements[1],n=>n.type==='CallExpression'&&calleePath(n.callee)==='filtered.slice'&&nodes(n.arguments[0],x=>name(x)==='page').length).length,'five-row page selection');
 const detail=nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])==='admin.policy_detail'&&n.elements?.[1]?.type==='ArrowFunctionExpression');assert.equal(detail.length,1);
 assert.ok(nodes(detail[0].elements[1],n=>n.type==='CallExpression'&&name(n.callee)==='selectedPolicy').length,'selected policy reread');
 assert.ok(nodes(detail[0].elements[1],n=>n.type==='CallExpression'&&calleePath(n.callee)==='Buffer.byteLength').length,'oversized markdown withholding');
 const generated=nodes(src,n=>n.type==='CallExpression'&&name(n.callee?.property)==='map'&&n.callee.object?.type==='ArrayExpression'
  &&n.callee.object.elements.map(e=>e.elements?.map(literal).join(':')).join('|')==='create:policy_create_prepare|edit:policy_edit_prepare|preview:policy_preview_prepare|delete:policy_delete_prepare');
 assert.equal(generated.length,1,'one four-action generated prepare map');
 for(const token of ['selectedPolicy','normalizePolicyCandidate','policyService().prepare'])assert.ok(nodes(generated[0],n=>n.type==='CallExpression'&&calleePath(n.callee)===token).length,`${token}: selected prepare path`);
 assert.ok(nodes(generated[0],n=>n.type==='ObjectProperty'&&name(n.key)==='candidate'&&name(n.value)==='candidate').length,'normalized candidate forwarded');
 assert.ok(nodes(generated[0],n=>n.type==='ObjectProperty'&&name(n.key)==='selected'&&name(n.value)==='chosen').length,'selected choice forwarded');
 assert.ok(nodes(src,n=>n.type==='VariableDeclarator'&&name(n.id)==='policySnapshot'&&nodes(n,x=>calleePath(x.callee)==='policyService().snapshot').length).length,'readInScene policy service snapshot');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='validateRolePolicyProposal'&&memberPath(n.arguments[0])==='meta.policyProposal').length,'saved proposal validation');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='policySnapshotDigest').length,'saved selected policy digest');
 assert.ok(nodes(composition,n=>n.type==='VariableDeclarator'&&name(n.id)==='policyChat'&&nodes(n,x=>calleePath(x.callee)==='require().createBoundPolicyChat'&&literal(x.callee.object?.arguments?.[0])==='./secureshopBoundPolicyChat').length).length,'conditional Policy composition');
 assert.ok(nodes(service,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createBoundPolicyChat'&&nodes(n,x=>calleePath(x.callee)==='service.list').length&&nodes(n,x=>calleePath(x.callee)==='C.createRolePolicyProposal').length).length,'current head to digest-bound proposal');
 assert.ok(nodes(service,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createBoundPolicyChat'&&nodes(n,x=>calleePath(x.callee)==='service.render').length&&nodes(n,x=>calleePath(x.callee)==='service.remove').length).length,'confirm effect distinct from prepare');
 assert.ok(nodes(proposal,n=>n.type==='FunctionDeclaration'&&name(n.id)==='create'&&nodes(n,x=>name(x.callee)==='digest').length).length,'proposal digest');
}
const mcpChatFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [MCP_CHAT]:'e061d3d2863f42f2ea5b77293741ca7f0184bad86e8f31342edd5d6292158466',
 [MCP_PROPOSAL]:'b795054677fa6b2a4ffa0926de4eac2e709bfc30825e46bcb15eece04dff8567',
});
const mcpChatRowPins=Object.freeze({
 'admin.mcp_servers':'2e2b20962719479c8bfe915781b758d7405e507f34f36142a734554101d1d34d',
 'admin.mcp_detail':'71726093d70f2bfb5036f01f1bc747093143d61865dae0d130cfeb7f58e6d08b',
 'admin.mcp_register_prepare':'14a2b493507a84a594c40b11c194580a69e8351c6dfbba6c65298adefc187bd3',
 'admin.mcp_import_prepare':'114cc5ff0034638e246003d6616216e9628d42c683f78d6502602db1dbb943e5',
 'admin.mcp_retire_prepare':'2e85620008f98021aed1980308bbfe5c814ad89958f2a08765d1feee01806053',
 'admin.mcp_invocation_setup':'12f29cc81452be58f76e7a3805844f28a676b229548ffb379e718af0ccfd69b7',
});
function checkAdminMcpRegistryBatch(manifest,overrides={}){
 const rows=manifest.roleChatDescriptorPartition.reviewedDescriptors;
 for(const [id,sha] of Object.entries(mcpChatRowPins)){
  const row=rows.find(item=>item.descriptorId===id);assert.ok(row,`${id}: reviewed row`);
  assert.equal(crypto.createHash('sha256').update(JSON.stringify(row)).digest('hex'),sha,`${id}: full metadata drift`);
  assert.equal(row.runtimeEvidence,null);
 }
 for(const [file,sha] of Object.entries(mcpChatFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected MCP source drift`);
 }
 const src=parse(SOURCE,overrides),composition=parse(COMPOSITION,overrides),service=parse(MCP_CHAT,overrides),proposal=parse(MCP_PROPOSAL,overrides);
 const expected={mcp_servers:[],mcp_detail:['choiceId'],mcp_register_prepare:['name','transport','url','stdio_cmd'],mcp_import_prepare:['xml_url'],mcp_retire_prepare:['choiceId'],mcp_invocation_setup:[]};
 for(const [tool,required] of Object.entries(expected)){
  const declared=nodes(src,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='admin'&&literal(prop(n,'tool'))===tool);assert.equal(declared.length,1,`${tool}: advertised descriptor`);
  const schema=prop(declared[0],'inputSchema');assert.equal(literal(prop(schema,'type')),'object');
  assert.equal(prop(schema,'additionalProperties')?.value,false);
  assert.deepEqual(prop(schema,'required')?.elements.map(literal)??[],required,`${tool}: model-selected arguments`);
 }
 const available=nodes(src,n=>n.type==='IfStatement'&&n.test?.type==='CallExpression'&&calleePath(n.test.callee)==='tool.tool.startsWith'&&literal(n.test.arguments[0])==='mcp_');
 assert.equal(available.length,1,'one registry availability branch');
 assert.ok(nodes(available[0],n=>n.type==='UnaryExpression'&&n.operator==='!'&&name(n.argument)==='mcpRegistryChat').length,'registry readiness');
 assert.ok(nodes(src,n=>n.type==='IfStatement'&&name(n.test)==='mcpIntent'&&nodes(n.consequent,x=>x.type==='ConditionalExpression'&&nodes(x,x2=>literal(x2)==='mcp_retire_prepare').length).length).length,'selected retire gate');
 const serverHandler=nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])==='admin.mcp_servers'&&n.elements?.[1]?.type==='ArrowFunctionExpression');assert.equal(serverHandler.length,1);
 assert.ok(nodes(serverHandler[0].elements[1],n=>n.type==='CallExpression'&&name(n.callee)==='mcpSnapshot').length,'server snapshot');
 assert.ok(nodes(serverHandler[0].elements[1],n=>n.type==='CallExpression'&&calleePath(n.callee)==='filtered.slice').length,'five-row page');
 const detail=nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])==='admin.mcp_detail'&&n.elements?.[1]?.type==='ArrowFunctionExpression');assert.equal(detail.length,1);
 assert.ok(nodes(detail[0].elements[1],n=>n.type==='CallExpression'&&name(n.callee)==='selectedMcp').length,'selected server reread');
 assert.ok(nodes(detail[0].elements[1],n=>n.type==='CallExpression'&&calleePath(n.callee)==='mcpService().detail').length,'selected detail read');
 const generated=nodes(src,n=>n.type==='CallExpression'&&name(n.callee?.property)==='map'&&n.callee.object?.type==='ArrayExpression'
  &&n.callee.object.elements.map(e=>e.elements?.map(literal).join(':')).join('|')==='register:mcp_register_prepare|import:mcp_import_prepare|retire:mcp_retire_prepare');
 assert.equal(generated.length,1,'one generated three-action prepare map');
 assert.ok(nodes(generated[0],n=>n.type==='CallExpression'&&name(n.callee)==='selectedMcp').length,'retire selected server');
 assert.ok(nodes(generated[0],n=>n.type==='BinaryExpression'&&n.operator==='!=='&&memberPath(n.left)==='row.provenance'&&literal(n.right)==='owned_registry').length,'scenario retirement denied');
 assert.ok(nodes(generated[0],n=>n.type==='CallExpression'&&name(n.callee)==='normalizeRegistryCandidate').length,'literal candidate normalization');
 assert.ok(nodes(generated[0],n=>n.type==='CallExpression'&&calleePath(n.callee)==='mcpService().prepare').length,'selected proposal creation');
 const handoff=nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])==='admin.mcp_invocation_setup'&&n.elements?.[1]?.type==='ArrowFunctionExpression');assert.equal(handoff.length,1);
 assert.ok(nodes(handoff[0].elements[1],n=>n.type==='CallExpression'&&name(n.callee)==='registeredInvocationApplication').length,'ready separate registered invocation');
 assert.ok(nodes(handoff[0].elements[1],n=>n.type==='AssignmentExpression'&&name(n.left)==='registeredMcpSetup').length,'source-bound no-effect handoff');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='validateRoleMcpRegistryProposal'&&memberPath(n.arguments[0])==='meta.mcpRegistryProposal').length,'saved proposal validation');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='validateRegisteredMcpSetup'&&memberPath(n.arguments[0])==='meta.registeredMcpSetup').length,'saved handoff validation');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='boundedRegistryData'&&memberPath(n.arguments[0])==='mcpDetail').length,'bounded saved detail');
 assert.ok(nodes(composition,n=>n.type==='VariableDeclarator'&&name(n.id)==='mcpRegistryChat'&&nodes(n,x=>calleePath(x.callee)==='require().createBoundMcpRegistryChat'&&literal(x.callee.object?.arguments?.[0])==='./secureshopBoundMcpRegistryChat').length).length,'conditional registry composition');
 assert.ok(nodes(service,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createBoundMcpRegistryChat'&&nodes(n,x=>calleePath(x.callee)==='admin.mcpServers').length&&nodes(n,x=>calleePath(x.callee)==='admin.mcpTools').length&&nodes(n,x=>calleePath(x.callee)==='admin.mcpHistory').length).length,'registry snapshot/detail owner reads');
 assert.ok(nodes(service,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createBoundMcpRegistryChat'&&nodes(n,x=>calleePath(x.callee)==='C.createRoleMcpRegistryProposal').length).length,'digest-bound proposal');
 assert.ok(nodes(service,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createBoundMcpRegistryChat'&&nodes(n,x=>calleePath(x.callee)==='current.service.mutate').length).length,'separate confirm mutation');
 assert.ok(nodes(proposal,n=>n.type==='FunctionDeclaration'&&name(n.id)==='create'&&nodes(n,x=>name(x.callee)==='registryRequestDigest').length).length,'proposal request digest codec');
}
const merchantChangeFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [CATALOG]:'3cc41dd265488120dca7d4a6eba14624fd4b81e2bea653df7b8d9d33719bcd0b',
 [INVENTORY_PROPOSAL]:'c15b46d8d3d33347d06fd25342f5ae2b165a025038858fcb3e5e0bfccaa7723e',
 [LISTING_CREATE_PROPOSAL]:'6fa67e529e6dc9792cfd35bc712b4161d07ef9d363fa1adaba526cdcca3a76f4',
 [LISTING_EDIT_PROPOSAL]:'5fee7a8b328a8749d814fed8672705639890fadb7dc953a562654ec7c81a68fd',
});
const merchantChangeRowPins=Object.freeze({
 'merchant.listing_create_prepare':'c1df1c4aae329451453d0a49c4414159908ae9544557c84ce7f5e5b949651789',
 'merchant.listing_edit_prepare':'a220c02cef928249b30e9785d5a7119f73d9a75cf159edbea68b9a359d6060b1',
 'merchant.inventory_prepare':'289f2451a034252ad70361eb64f85d0f20f6dd3a1369e8e8b2d0332cdbebd871',
});
function checkMerchantProductChangePreparations(manifest,overrides={}){
 for(const [id,sha] of Object.entries(merchantChangeRowPins)){
  const row=manifest.roleChatDescriptorPartition.reviewedDescriptors.find(item=>item.descriptorId===id);assert.ok(row,`${id}: reviewed row`);
  assert.equal(crypto.createHash('sha256').update(JSON.stringify(row)).digest('hex'),sha,`${id}: full metadata drift`);
  assert.equal(row.runtimeEvidence,null);
 }
 for(const [file,sha] of Object.entries(merchantChangeFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected product preparation source drift`);
 }
 const src=parse(SOURCE,overrides),catalog=parse(CATALOG,overrides),inventory=parse(INVENTORY_PROPOSAL,overrides),creation=parse(LISTING_CREATE_PROPOSAL,overrides),edit=parse(LISTING_EDIT_PROPOSAL,overrides);
 const expected={listing_create_prepare:['listing'],listing_edit_prepare:['choiceId','patch'],inventory_prepare:['choiceId','quantity']};
 for(const [tool,required] of Object.entries(expected)){
  const declared=nodes(src,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='merchant'&&literal(prop(n,'tool'))===tool);assert.equal(declared.length,1,`${tool}: declared schema`);
  const schema=prop(declared[0],'inputSchema');assert.equal(literal(prop(schema,'type')),'object');
  assert.equal(prop(schema,'additionalProperties')?.value,false);assert.deepEqual(prop(schema,'required')?.elements.map(literal),required);
  const handler=nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===`merchant.${tool}`&&n.elements?.[1]?.type==='ArrowFunctionExpression');assert.equal(handler.length,1);
  assert.ok(nodes(handler[0].elements[1],n=>n.type==='CallExpression'&&name(n.callee)==='readInScene').length,`${tool}: protected scene preview`);
 }
 const handler=tool=>nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===`merchant.${tool}`&&n.elements?.[1]?.type==='ArrowFunctionExpression')[0]?.elements[1];
 assert.ok(nodes(handler('inventory_prepare'),n=>n.type==='CallExpression'&&name(n.callee)==='createRoleInventoryProposal'&&memberPath(prop(n.arguments[0],'quantity'))==='args.quantity').length,'exact stock quantity bound');
 assert.ok(nodes(handler('inventory_prepare'),n=>n.type==='CallExpression'&&calleePath(n.callee)==='catalog.getOwnedMerchantProduct'&&memberPath(prop(n.arguments[0],'productId'))==='selected.sourceId').length,'inventory owner reread');
 assert.ok(nodes(handler('inventory_prepare'),n=>n.type==='BinaryExpression'&&n.operator==='!=='&&memberPath(n.right)==='selected.snapshotSha256'&&nodes(n.left,x=>name(x.callee)==='digest').length).length,'inventory selected snapshot digest');
 assert.ok(nodes(handler('listing_create_prepare'),n=>n.type==='CallExpression'&&calleePath(n.callee)==='catalog.previewMerchantListingCreate'&&memberPath(prop(n.arguments[0],'listing'))==='args.listing').length,'selected listing create preview');
 assert.ok(nodes(handler('listing_create_prepare'),n=>n.type==='CallExpression'&&name(n.callee)==='createRoleListingCreateProposal'&&name(prop(n.arguments[0],'preview'))==='preview').length,'listing create proposal from returned preview');
 assert.ok(nodes(handler('listing_create_prepare'),n=>n.type==='BinaryExpression'&&n.operator==='==='&&memberPath(n.left)==='args.listing.presentation'&&literal(n.right)==='html').length,'authored HTML version-two source branch');
 assert.ok(nodes(handler('listing_edit_prepare'),n=>n.type==='CallExpression'&&calleePath(n.callee)==='catalog.getOwnedMerchantProduct').length,'listing edit owner reread');
 assert.ok(nodes(handler('listing_edit_prepare'),n=>n.type==='CallExpression'&&calleePath(n.callee)==='catalog.previewMerchantListingEdit'&&memberPath(prop(n.arguments[0],'patch'))==='args.patch').length,'selected listing edit patch');
 assert.ok(nodes(handler('listing_edit_prepare'),n=>n.type==='CallExpression'&&name(n.callee)==='createRoleListingProposal'&&name(prop(n.arguments[0],'preview'))==='preview').length,'listing edit proposal from returned preview');
 for(const method of ['previewMerchantListingCreate','previewMerchantListingEdit','confirmMerchantListingCreate','confirmMerchantListingEdit'])assert.ok(nodes(catalog,n=>n.type==='ObjectMethod'&&name(n.key)===method).length,`${method}: separate bounded catalog path`);
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='validateRoleInventoryProposal').length,'saved inventory proposal validation');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='projectRoleListingProposal').length,'saved listing edit projection');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='projectRoleListingCreateProposal').length,'saved listing create projection');
 for(const codec of [inventory,creation,edit])assert.ok(nodes(codec,n=>n.type==='FunctionDeclaration'&&name(n.id)==='create'&&nodes(n,x=>name(x.callee)==='validate').length).length,'deterministic validated proposal codec');
}
const finalRoleChatFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [MAIL]:'63f4629352cccb8e2365a4c08280573b2eb1b280eae0e8f08b197d6791ee4ebc',
 [ROLE_REVIEW]:'022dbc72774fa1b59de1ee4fdcff59ea84379985a3f83722c7f4f9cb36a53001',
 [REVIEW_PROPOSAL]:'0b5c3688695d19b94d9a4fe5a4eb1c7e877007d1e74df998083f7d5b0510c34c',
 [AUDIT_JOBS]:'a2794d32418b2489b9a3f07b895099a9b7c2c5015abf5923a62c07c25bd9a785',
 [AUDIT_PROPOSAL]:'633eba76c081d49fbe4e43c756c124e50668818c052b7c9bc258b1765313d7c4',
 [ADMIN_SERVICE]:'97209fcdff99eb0c2c19b09191fb5ba14a513323289f5777fdc57a66b0794da0',
});
const finalRoleChatRowPins=Object.freeze({
 'merchant.mail_reply_prepare':'4f93beb1b09cdeb40f9356818b4b44fab932a2a6c254fa54717d58165214acbb',
 'merchant.review_decision_prepare':'5ae256602061b61e47bd4bd3e0c7da2689085562853c8d321bbedd1999e1c5db',
 'admin.audit_recent':'0ebb635eeec8824dd26b210f19345a90b61d53b6605c3cf321bc1e115ff41f8b',
 'admin.audit_agent_prepare':'4c122d494133838e3b4e9240176bf7b162d5f7c14717aa64b1c43fa81fef4c0d',
});
function checkFinalRoleChatDescriptors(manifest,overrides={}){
 for(const [id,sha] of Object.entries(finalRoleChatRowPins)){
  const row=manifest.roleChatDescriptorPartition.reviewedDescriptors.find(item=>item.descriptorId===id);assert.ok(row,`${id}: reviewed row`);
  assert.equal(crypto.createHash('sha256').update(JSON.stringify(row)).digest('hex'),sha,`${id}: full metadata drift`);
  assert.equal(row.runtimeEvidence,null);
 }
 for(const [file,sha] of Object.entries(finalRoleChatFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected source drift`);
 }
 const src=parse(SOURCE,overrides),mail=parse(MAIL,overrides),review=parse(ROLE_REVIEW,overrides),reviewProposal=parse(REVIEW_PROPOSAL,overrides),jobs=parse(AUDIT_JOBS,overrides),auditProposal=parse(AUDIT_PROPOSAL,overrides),admin=parse(ADMIN_SERVICE,overrides);
 const required={mail_reply_prepare:['choiceId'],review_decision_prepare:['choiceId','decision'],audit_recent:[],audit_agent_prepare:[]};
 for(const [tool,keys] of Object.entries(required)){
  const role=tool.startsWith('audit_')?'admin':'merchant';
  const descriptor=nodes(src,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))===role&&literal(prop(n,'tool'))===tool);assert.equal(descriptor.length,1,`${tool}: advertised schema`);
  const schema=prop(descriptor[0],'inputSchema');assert.equal(literal(prop(schema,'type')),'object');assert.equal(prop(schema,'additionalProperties')?.value,false);
  assert.deepEqual(prop(schema,'required')?.elements.map(literal)??[],keys,`${tool}: required selected args`);
 }
 const reply=nodes(src,n=>n.type==='CallExpression'&&name(n.callee?.property)==='map'&&n.callee.object?.type==='ArrayExpression'&&n.callee.object.elements.map(literal).join(',')==='send,reply');assert.equal(reply.length,1,'one generated send/reply map');
 assert.ok(nodes(reply[0],n=>n.type==='CallExpression'&&calleePath(n.callee)==='mailActions.prepare').length,'selected mail proposal service');
 assert.ok(nodes(reply[0],n=>n.type==='CallExpression'&&calleePath(n.callee)==='api.readRequest').length,'saved selected message reread');
 assert.ok(nodes(reply[0],n=>n.type==='CallExpression'&&name(n.callee)==='captureFeatureMode'&&literal(n.arguments[2])==='mail').length,'mail mode recheck');
 assert.ok(nodes(mail,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createBoundMailActions'&&nodes(n,x=>calleePath(x.callee)==='mailApplication.prepareTarget').length&&nodes(n,x=>calleePath(x.callee)==='mailApplication.reply').length).length,'target preparation distinct from confirmed reply');
 const decision=nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])==='merchant.review_decision_prepare'&&n.elements?.[1]?.type==='ArrowFunctionExpression');assert.equal(decision.length,1);
 assert.ok(nodes(decision[0].elements[1],n=>n.type==='CallExpression'&&name(n.callee)==='readInScene'&&name(n.arguments[0])==='selectedReview').length,'selected review reread');
 assert.ok(nodes(decision[0].elements[1],n=>n.type==='CallExpression'&&name(n.callee)==='createRoleReviewProposal'&&memberPath(prop(n.arguments[0],'reason'))==='reviewReason').length,'server-held rejection reason');
 assert.ok(nodes(decision[0].elements[1],n=>n.type==='StringLiteral'&&n.value==='manual_review_required').length,'manual denial branch');
 assert.ok(nodes(reviewProposal,n=>n.type==='FunctionDeclaration'&&name(n.id)==='create'&&nodes(n,x=>name(x.callee)==='hash').length).length,'review proposal request digest');
 assert.ok(nodes(review,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createRoleReviewService').length,'separate owner-scoped review service');
 const recent=nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])==='admin.audit_recent'&&n.elements?.[1]?.type==='ArrowFunctionExpression');assert.equal(recent.length,1);
 assert.ok(nodes(recent[0].elements[1],n=>n.type==='ObjectProperty'&&name(n.key)==='limit'&&n.value?.value===5).length,'server-owned audit limit five');
 assert.ok(nodes(recent[0].elements[1],n=>n.type==='CallExpression'&&calleePath(n.callee)==='admin.audit').length,'owned audit read');
 assert.ok(nodes(admin,n=>n.type==='AssignmentExpression'&&calleePath(n.left)==='service.audit'&&nodes(n.right,x=>calleePath(x.callee)==='auditRepository.recent').length).length,'admin audit adapter');
 const agent=nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])==='admin.audit_agent_prepare'&&n.elements?.[1]?.type==='ArrowFunctionExpression');assert.equal(agent.length,1);
 assert.ok(nodes(agent[0].elements[1],n=>n.type==='CallExpression'&&calleePath(n.callee)==='auditJobs.prepare'&&literal(prop(n.arguments[0],'action'))==='agent'&&memberPath(prop(prop(n.arguments[0],'input'),'message'))==='message').length,'original message to agent preparation');
 assert.ok(nodes(jobs,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createBoundAuditJobs'&&nodes(n,x=>x.type==='CallExpression'&&x.callee?.type==='MemberExpression'&&name(x.callee.object)==='s'&&x.callee.computed&&x.callee.property?.type==='ConditionalExpression'&&literal(x.callee.property.consequent)==='createAgentSession'&&literal(x.callee.property.alternate)==='createSession').length&&nodes(n,x=>calleePath(x.callee)==='C.create').length).length,'purpose-bound session and proposal');
 assert.ok(nodes(auditProposal,n=>n.type==='FunctionDeclaration'&&name(n.id)==='create').length,'audit proposal codec');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='validateRoleReviewProposal').length,'saved review proposal validation');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&calleePath(n.callee)==='mailActions.reconstruct').length,'saved mail proposal reconstruction');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&calleePath(n.callee)==='auditJobProposal.create').length,'saved Audit agent job reconstruction');
}
const adminSystemFilePins=Object.freeze({
 [SOURCE]:'2541872d6de1d4e029294c4bf053d95a91c3cd5667863605ae7739b607243eff',
 [COMPOSITION]:'86f52469ba3daba4c67f84d9efdc25af9450be31b694f0a534503bf720aa5e6b',
 [SYSTEM_READS]:'3fcf1d48e621f358e23e39ce605ddf5e1b588ce03c5a084797a8ff779f01d101',
 [SYSTEM_HEALTH]:'045c4565f3bdef46f049768c07919ac592a53992df4087bf4a8e8170a10b5891',
 [SYSTEM_COMPOSITION]:'a43c86f1331d669ca02ddeb674ad6ebc0e9abb4ec463d5134e3f16618cf8bdf2',
 [SYSTEM_RESTART_CHAT]:'55c72efd9682afdf6d0242c7d9313d8510291ffb687035b6a1436109771e2b7e',
 [SYSTEM_RESTART_PROPOSAL]:'6ebf9cbe761cfc7514652e46df7190f24f0ef75f4d078b5ae97397e403c7f998',
 [SYSTEM_DIAGNOSTIC_CHAT]:'f30ac1edfa34bdfd49a1ba31b61ca7ca4083dd9fd0646a1b923eb6b4eb1d912a',
 [SYSTEM_DIAGNOSTIC_PROPOSAL]:'85473f1abf36405b2e5bffb38ec30bd6501449a9499f116eb6ef202a624a6563',
});
function checkAdminSystemReadAndPreparations(manifest,overrides={}){
 const ids=['admin.system_health','admin.system_diagnostic_prepare','admin.system_restart_prepare'];
 const rows=ids.map(id=>manifest.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId===id));
 assert.deepEqual(rows,[
  {descriptorId:ids[0],bridgeActionIds:['agent.admin.assistant.chat','agent.admin.assistant.operation'],
   availability:'Admin general unselected branch with a ready lazy owned System composition; the handler accepts no arguments and checks current scene before and after the health read.',
   handler:'createLocalTools: admin.system_health -> systemReads.health -> owned healthService.health',
   consequence:'The bound read checks administrator context and current authority, validates owned System metrics between repository administration reads, and returns a bounded health observation. Saved RoleChat GET validates the recorded health object and returns the saved turn. This health read is not a restart or diagnostic execution.',
   confirmation:'No separate confirmation for health read. Actual metrics, rendered use, model choice, denial and Judge remain native-evidence gaps.',
   modelApplicability:'model_selected_system_health_read',judgeApplicability:'not_inferred_from_system_health_observation',runtimeEvidence:null},
  {descriptorId:ids[1],bridgeActionIds:['agent.admin.assistant.chat','agent.admin.assistant.operation'],
   availability:'Admin general unselected branch with ready lazy diagnostic composition; cmd_template and args strings must be supplied, and an exact parsed human diagnostic request, when present, must match both strings.',
   handler:'createLocalTools: admin.system_diagnostic_prepare -> systemDiagnosticChat.prepare(cmd_template,args)',
   consequence:'Reads current diagnostic administration/execution/mode source, validates an optional supplied mode capability and builds a digest-bound proposal for the selected exact strings. The model sees prepared_for_confirmation, command template, args and request digest; saved GET validates original source/proposal. Preparation runs no command. A separate confirm path may execute under its own admission and mode check.',
   confirmation:'Separate trusted diagnostic confirmation owns any command execution; Fixed denial and actual command/no-effect require native evidence. Preparation and saved readback are not execution or Judge credit.',
   modelApplicability:'model_selected_diagnostic_proposal_from_literal_user_strings',judgeApplicability:'not_inferred_from_diagnostic_proposal',runtimeEvidence:null},
  {descriptorId:ids[2],bridgeActionIds:['agent.admin.assistant.chat','agent.admin.assistant.operation'],
   availability:'Admin general unselected branch with ready lazy restart composition; selected service name must be well formed, 1-128 UTF-8 bytes and present verbatim in the current human message.',
   handler:'createLocalTools: admin.system_restart_prepare -> systemRestartChat.prepare(name=args.name)',
   consequence:'Captures current restart mode and administration target, then builds a digest-bound proposal for the exact supplied service name; the model sees prepared_for_confirmation and target. Saved GET verifies the original name/proposal. Preparation does not restart a service; separate confirmation owns execution and receipt.',
   confirmation:'Separate trusted restart confirmation owns any sidecar effect. Physical review, native target transition, denial and Judge remain unverified by preparation.',
   modelApplicability:'model_selected_restart_proposal_from_literal_user_name',judgeApplicability:'not_inferred_from_restart_proposal',runtimeEvidence:null},
 ]);
 for(const [file,sha] of Object.entries(adminSystemFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected System source drift`);
 }
 const src=parse(SOURCE,overrides),composition=parse(COMPOSITION,overrides),reads=parse(SYSTEM_READS,overrides),health=parse(SYSTEM_HEALTH,overrides),system=parse(SYSTEM_COMPOSITION,overrides),restart=parse(SYSTEM_RESTART_CHAT,overrides),diagnostic=parse(SYSTEM_DIAGNOSTIC_CHAT,overrides);
 for(const tool of ['system_health','system_diagnostic_prepare','system_restart_prepare'])
  assert.equal(nodes(src,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='admin'&&literal(prop(n,'tool'))===tool).length,1,`${tool}: advertised descriptor`);
 const handler=tool=>nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===`admin.${tool}`)[0]?.elements[1];
 assert.ok(nodes(handler('system_health'),n=>call(n,'systemReads.health')).length,'health exact selected service');
 assert.ok(nodes(handler('system_diagnostic_prepare'),n=>call(n,'systemDiagnosticChat.prepare')&&nodes(n.arguments[0],x=>name(x.key)==='cmd_template'&&memberPath(x.value)==='args.cmd_template').length).length,'diagnostic selected literal command');
 assert.ok(nodes(handler('system_diagnostic_prepare'),n=>n.type==='BinaryExpression'&&n.operator==='!=='&&memberPath(n.left)==='args.cmd_template'&&memberPath(n.right)==='explicitDiagnostic.cmd_template').length,'diagnostic exact parsed human request');
 assert.ok(nodes(handler('system_restart_prepare'),n=>call(n,'systemRestartChat.prepare')&&nodes(n.arguments[0],x=>name(x.key)==='name'&&memberPath(x.value)==='args.name').length).length,'restart exact selected name');
 assert.ok(nodes(handler('system_restart_prepare'),n=>n.type==='CallExpression'&&calleePath(n.callee)==='message.includes'&&memberPath(n.arguments[0])==='args.name').length,'restart name in human message');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='validateOwnedSystemMetrics').length,'saved health metrics validation');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee)==='validateRoleSystemRestartProposal').length,'saved restart proposal validation');
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&name(n.callee?.property)==='validateRoleSystemDiagnosticProposal').length,'saved diagnostic proposal validation');
 assert.ok(nodes(composition,n=>n.type==='CallExpression'&&name(n.callee?.property)==='createRoleSystemReads').length,'composed System reads');
 assert.ok(nodes(composition,n=>n.type==='CallExpression'&&name(n.callee?.property)==='createBoundSystemRestartChat').length,'composed restart');
 assert.ok(nodes(composition,n=>n.type==='CallExpression'&&name(n.callee?.property)==='createBoundSystemDiagnosticChat').length,'composed diagnostic');
 assert.ok(nodes(reads,n=>n.type==='ObjectMethod'&&name(n.key)==='health'&&nodes(n,x=>x.type==='CallExpression'&&calleePath(x.callee)==='system.healthService.health').length).length,'owned System health service read');
 assert.ok(nodes(system,n=>n.type==='VariableDeclarator'&&name(n.id)==='healthService'&&nodes(n,x=>x.type==='CallExpression'&&name(x.callee)==='createHealthService').length).length,'health service wired from System composition');
 assert.ok(nodes(health,n=>n.type==='ObjectMethod'&&name(n.key)==='health'&&nodes(n,x=>call(x,'metrics.snapshot')).length&&nodes(n,x=>x.type==='CallExpression'&&name(x.callee)==='validateSystemHealthMetrics').length).length,'health validates owned metrics');
 assert.ok(nodes(restart,n=>n.type==='FunctionDeclaration'&&name(n.id)==='prepare'&&nodes(n,x=>x.type==='CallExpression'&&calleePath(x.callee)==='C.createRoleSystemRestartProposal').length).length,'restart only constructs proposal');
 assert.ok(nodes(diagnostic,n=>n.type==='FunctionDeclaration'&&name(n.id)==='prepare'&&nodes(n,x=>x.type==='CallExpression'&&calleePath(x.callee)==='C.createRoleSystemDiagnosticProposal').length).length,'diagnostic only constructs proposal');
 for(const file of [SYSTEM_RESTART_PROPOSAL,SYSTEM_DIAGNOSTIC_PROPOSAL])
  assert.ok(nodes(parse(file,overrides),n=>n.type==='FunctionDeclaration'&&name(n.id)==='create').length,`${file}: digest-bound proposal builder`);
}
function checkListingsSetups(manifest,overrides={}){
 const ids=['merchant.listing_import_setup','merchant.listing_rewrite_setup','merchant.listing_optimize_setup'];
 const rows=ids.map(id=>manifest.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId===id));
 assert.deepEqual(rows,[
  {descriptorId:ids[0],bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation','merchant.listings.importBulk'],
   availability:'Merchant, no selected choice and a ready Listings application. Both literal json_url and xml_url fields are required; absent source is null, not an invented URL. The role assistant only prepares a handoff.',
   handler:'createLocalTools: merchant.listing_import_setup -> listingsSetup.prepare(action=import, input={json_url:args.json_url, xml_url:args.xml_url})',
   consequence:'Builds a scene/persona/mode-bound import setup from the selected literal URLs and an owned target check; the saved RoleChat request revalidates the exact original args and reconstructs the proposal. Setup does not fetch URLs or import products. A separate Listings Run may later consume the saved chatSource.',
   confirmation:'Physical review and separate Listings Run are required for import. Rendered use, URL-fetch effect, saved operation outcome, denial-no-effect and Judge remain unverified here.',
   modelApplicability:'model_selected_setup_then_separate_listings_run',judgeApplicability:'not_inferred_from_import_setup_or_saved_readback',runtimeEvidence:null},
  {descriptorId:ids[1],bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation','merchant.listings.assistWrite'],
   availability:'Merchant with listing_rewrite intent, ready Listings application and an exact physically selected saved owned-product choiceId; original choice card, scene and product snapshot are rechecked.',
   handler:'createLocalTools: merchant.listing_rewrite_setup -> listingsSetup.prepare(action=rewrite, selected=original choice)',
   consequence:'Reads the selected active owned product and creates a digest-bound rewrite setup retaining its current item and mode/scene authority; saved RoleChat readback reconstructs the exact original proposal. This setup does not generate or save rewritten text. Separate Listings Run and Save have their own admissions.',
   confirmation:'Physical product selection and later reviewed Listings Run/Save are distinct from setup. Native generation, save, denial-no-effect and Judge are not established by this source contract.',
   modelApplicability:'model_selected_setup_after_physical_choice',judgeApplicability:'not_inferred_from_rewrite_setup_or_saved_readback',runtimeEvidence:null},
  {descriptorId:ids[2],bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation','merchant.listings.optimizeImages'],
   availability:'Merchant with listing_optimize intent, ready Listings application and an exact physically selected saved owned-product choiceId; current scene grant and server-read product image URL are required.',
   handler:'createLocalTools: merchant.listing_optimize_setup -> listingsSetup.prepare(action=optimize, selected=original choice)',
   consequence:'Reads the selected active owned product and binds its server-read image URL, URL digest, scene grant and product snapshot to a saved optimize setup; RoleChat reconstruction checks the original choice and proposal. The setup does not fetch the image, execute a command or optimize content. Separate Listings Run owns those possible effects.',
   confirmation:'Physical product selection and later exact-URL Listings review/Run are separate. Native image/command effect, denial-no-effect and Judge are unverified by this setup contract.',
   modelApplicability:'model_selected_setup_after_physical_choice',judgeApplicability:'not_inferred_from_optimize_setup_or_saved_readback',runtimeEvidence:null},
 ]);
 for(const [file,sha] of Object.entries(listingSetupFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected Listings setup source drift`);
 }
 const role=parse(SOURCE,overrides),composition=parse(COMPOSITION,overrides),adapter=parse(LISTING_SETUP,overrides),optimize=parse(LISTING_OPTIMIZE_SETUP,overrides),application=parse(LISTINGS_APP,overrides),production=parse(LISTINGS_PRODUCTION,overrides);
 const descriptor=tool=>nodes(role,n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='merchant'&&literal(prop(n,'tool'))===tool);
 for(const [tool,required] of [['listing_import_setup',['json_url','xml_url']],['listing_rewrite_setup',['choiceId']],['listing_optimize_setup',['choiceId']]]){
  const matches=descriptor(tool);assert.equal(matches.length,1,`${tool}: one advertised descriptor`);
  const schema=prop(matches[0],'inputSchema');assert.equal(literal(prop(schema,'type')),'object');
  assert.equal(prop(schema,'additionalProperties')?.value,false);
  assert.deepEqual(prop(schema,'required')?.elements.map(literal),required);
  if(tool==='listing_import_setup')for(const field of required){
   const schemaField=prop(prop(schema,'properties'),field);
   assert.deepEqual(prop(schemaField,'type')?.elements.map(literal),['string','null']);
   assert.equal(prop(schemaField,'maxLength')?.value,4096);
  }else assert.equal(memberPath(prop(prop(prop(schema,'properties'),'choiceId'),'pattern')),'UUID.source');
 }
 const map=nodes(role,n=>n.type==='CallExpression'&&name(n.callee?.property)==='map'
  &&n.callee.object?.type==='ArrayExpression'&&n.callee.object.elements.map(pair=>pair.elements?.map(literal).join(':')).join('|')
   ==='import:listing_import_setup|rewrite:listing_rewrite_setup|optimize:listing_optimize_setup');
 assert.equal(map.length,1,'exact three-way generated handler map');
 const generated=map[0].arguments[0];
 assert.equal(nodes(generated,n=>call(n,'listingsSetup.prepare')).length,1,'selected handler prepares setup');
 for(const symbol of ['args.json_url','args.xml_url','args.choiceId','selected.choiceId','selectedSourceRequestId','action','name'])
  assert.ok(nodes(generated,n=>memberPath(n)===symbol||name(n)===symbol).length,`${symbol}: selected handler provenance`);
 assert.equal(nodes(generated,n=>call(n,'api.readRequest')).length,1,'selected choice rereads original card');
 assert.equal(nodes(generated,n=>call(n,'codec.validateListingOptimizeSetup')).length,1);
 assert.equal(nodes(generated,n=>call(n,'codec.validateListingActionSetup')).length,1);
 const available=nodes(role,n=>n.type==='VariableDeclarator'&&name(n.id)==='available');assert.equal(available.length,1);
 for(const tool of ['listing_import_setup','listing_rewrite_setup','listing_optimize_setup'])
  assert.ok(nodes(available[0],n=>literal(n)===tool).length,`${tool}: conditional availability`);
 // The saved setup is handled inside readRequest; tie reconstructed proposal to the returned projection.
 const readRequest=nodes(role,n=>n.type==='ObjectMethod'&&name(n.key)==='readRequest');assert.equal(readRequest.length,1);
 for(const callee of ['listingsSetup.reconstruct','codec.projectListingOptimizeSetup','codec.projectListingActionSetup'])
  assert.ok(nodes(readRequest[0],n=>call(n,callee)).length,`saved ${callee}`);
 assert.ok(nodes(readRequest[0],n=>n.type==='CallExpression'&&name(n.callee)==='isDeepStrictEqual'
  &&name(n.arguments[0])==='rebuilt'&&name(n.arguments[1])==='proposal').length,'saved proposal equals reconstruction');
 const readSetup=nodes(role,n=>n.type==='ObjectMethod'&&name(n.key)==='readListingsSetup');assert.equal(readSetup.length,1);
 for(const callee of ['api.readRequest','bindingRepository.read','journal.readBoundRequest','codec.validateListingOptimizeSetup','codec.validateListingActionSetup'])
  assert.ok(nodes(readSetup[0],n=>call(n,callee)).length,`protected read ${callee}`);
 const setup=nodes(composition,n=>n.type==='VariableDeclarator'&&name(n.id)==='listingsSetup');assert.equal(setup.length,1);
 assert.ok(nodes(setup[0],n=>n.type==='CallExpression'&&name(n.callee)==='getListingsApplication').length,'ready depends on actual Listings application');
 for(const method of ['listingsSetupAdapter.prepare','listingsSetupAdapter.reconstruct'])assert.ok(nodes(setup[0],n=>call(n,method)).length);
 assert.ok(nodes(composition,n=>n.type==='ObjectProperty'&&name(n.key)==='getListingsApplication'
  &&nodes(n.value,x=>memberPath(x)==='value.listings.ready').length).length,'conditional production publication');
 const create=nodes(adapter,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createListingsChatSetup');assert.equal(create.length,1);
 assert.ok(nodes(create[0],n=>call(n,'app.prepareChatSetup')).length);
 assert.ok(nodes(create[0],n=>n.type==='CallExpression'&&name(n.callee)==='createListingActionSetup').length);
 assert.ok(nodes(create[0],n=>n.type==='CallExpression'&&calleePath(n.callee)==='require().createListingOptimizeSetup').length,'optimize setup builder');
 assert.ok(nodes(create[0],n=>n.type==='CallExpression'&&name(n.callee)==='captureFeatureMode').length,'Listings mode fence');
 const action=nodes(adapter,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createListingActionSetup');assert.equal(action.length,1);
 for(const callee of ['normalizeListingRequest','normalizeListingSaveRequest','choiceDigest'])assert.ok(nodes(action[0],n=>n.type==='CallExpression'&&name(n.callee)===callee).length);
 const optimized=nodes(optimize,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createListingOptimizeSetup');assert.equal(optimized.length,1);
 for(const callee of ['normalizeListingRequest','canonicalDigest','sha'])assert.ok(nodes(optimized[0],n=>name(n.callee)===callee).length);
 const app=nodes(application,n=>n.type==='FunctionDeclaration'&&name(n.id)==='createListingsApplication');assert.equal(app.length,1);
 const appPrepare=nodes(app[0],n=>n.type==='ObjectMethod'&&name(n.key)==='prepareChatSetup');assert.equal(appPrepare.length,1);
 for(const callee of ['catalog.getOwnedMerchantProduct','catalog.prepareTarget'])assert.ok(nodes(appPrepare[0],n=>call(n,callee)).length);
 const checked=nodes(app[0],n=>n.type==='FunctionDeclaration'&&name(n.id)==='checkedSetup');assert.equal(checked.length,1);
 assert.ok(nodes(checked[0],n=>n.type==='CallExpression'&&name(n.callee)==='readChatSetup').length,'separate run rereads saved setup');
 const run=nodes(app[0],n=>n.type==='ObjectMethod'&&name(n.key)==='run');assert.equal(run.length,1);
 assert.ok(nodes(run[0],n=>n.type==='CallExpression'&&name(n.callee)==='checkedSetup').length,'only later run consumes chatSource');
 assert.ok(nodes(composition,n=>n.type==='ObjectProperty'&&name(n.key)==='readChatSetup'
  &&nodes(n.value,x=>call(x,'runtime.readListingsSetup')).length).length,'composition passes protected saved setup reader');
 assert.ok(nodes(production,n=>n.type==='CallExpression'&&name(n.callee)==='createListingsApplication'
  &&nodes(n.arguments[0],x=>name(x)==='readChatSetup').length).length,'production passes saved reader to application');
}
function checkMailReads(manifest,overrides={}){
 const ids=['merchant.mail_recipients','merchant.mail_list','merchant.mail_detail'];
 const rows=ids.map(id=>manifest.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId===id));
 assert.deepEqual(rows,[
  {
   descriptorId:'merchant.mail_recipients',
   bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation'],
   availability:'Merchant with ready mailChat, no selected choice and no mail continuation; named search is optional and bounded to 128 UTF-8 bytes. Mail activation and actor-directory composition remain conditional.',
   handler:'createLocalTools: merchant.mail_recipients -> mailChat.recipients(search=args.search)',
   consequence:'Reads a bounded owned-target recipient directory and returns up to five opaque recipient choices; no mailbox disclosure or send occurs in this selected handler. Saved request readback verifies original tool/args, mode/binding and choices; discovery has no mailbox-read receipt.',
   confirmation:'No separate physical confirmation for recipient discovery; selecting a returned recipient is a later distinct action. Native use and denial-no-effect are unverified.',
   modelApplicability:'model_selected_chat_tool',
   judgeApplicability:'not_inferred_from_recipient_discovery',
   runtimeEvidence:null,
  },
  {
   descriptorId:'merchant.mail_list',
   bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation'],
   availability:'Merchant mail list uses no args for own inbox or a physically selected saved recipient choiceId; a saved next-page continuation is a separate admitted branch. Mail service and scene readiness remain conditional.',
   handler:'createLocalTools: merchant.mail_list -> mailChat.list or page with exact saved recipient/offset',
   consequence:'An owned read operation may persist a mailbox receipt; RoleChat exposes only a protected five-header projection with readOperationId/receipt digest. Selected recipient and next-page paths revalidate the saved choice/receipt; neither is a send.',
   confirmation:'A named other-mailbox read requires physical recipient selection and independent mail policy. No separate confirmation is established for own-inbox list or next-page read; native effect and denial-no-effect remain unverified.',
   modelApplicability:'model_selected_chat_tool_with_optional_physical_choice',
   judgeApplicability:'not_inferred_from_mailbox_headers',
   runtimeEvidence:null,
  },
  {
   descriptorId:'merchant.mail_detail',
   bridgeActionIds:['agent.merchant.assistant.chat','agent.merchant.assistant.operation','agent.merchant.assistant.mailReadAssess','agent.merchant.assistant.mailReadAssessment'],
   availability:'Merchant with ready mailChat and an exact physically selected saved message choiceId; the selected list receipt, message identity and mail mode are revalidated before detail projection.',
   handler:'createLocalTools: merchant.mail_detail -> mailChat.detail(messageId=selected.sourceId)',
   consequence:'Projects the selected saved mail-read receipt into a bounded detail; complete body/header text is untrusted content, and oversized bodies may be suppressed while receipt identity remains. Saved GET reprojects and compares the original receipt without sending or rereading the mailbox as a new operation.',
   confirmation:'Physical message selection is required before this detail call. There is no send/reply effect; rendered selection, source-content adoption and denial-no-effect remain native-evidence gaps.',
   modelApplicability:'model_selected_chat_tool_after_physical_choice',
   judgeApplicability:'conditional_mail_agent_read_assessment_only_after_eligible_original_completed_turn; no automatic credit from detail or GET',
   runtimeEvidence:null,
  },
 ]);
 for(const [file,sha] of Object.entries(mailReadFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: selected mail source drift`);
 }
 const pin=(file,label,predicate,sha)=>exactSourceNode(file,overrides,label,predicate,sha);
 const fn=id=>n=>n.type==='FunctionDeclaration'&&name(n.id)===id;
 pin(SOURCE,'saved mail readback and selected-original verification',fn('createSecureShopBoundRoleChat'),auditSummarySourcePins.roleChat);
 for(const [tool,key] of [['mail_recipients','recipients'],['mail_list','list'],['mail_detail','detail']]){
  const descriptor=nodes(parse(SOURCE,overrides),n=>n.type==='ObjectExpression'&&literal(prop(n,'agent'))==='merchant'
   &&literal(prop(n,'tool'))===tool);
  assert.equal(descriptor.length,1,`${tool}: declared exactly once`);
  const schema=prop(descriptor[0],'inputSchema');
  assert.equal(literal(prop(schema,'type')),'object');assert.equal(prop(schema,'additionalProperties')?.value,false);
  const choice=prop(prop(schema,'properties'),'choiceId');
  if(tool==='mail_recipients'){
   assert.equal(literal(prop(prop(prop(schema,'properties'),'search'),'type')),'string');
   assert.equal(prop(prop(prop(schema,'properties'),'search'),'maxLength')?.value,128);
   assert.equal(choice??null,null);
  }else{
   assert.equal(literal(prop(choice,'type')),'string');assert.equal(memberPath(prop(choice,'pattern')),'UUID.source');
   if(tool==='mail_detail')assert.deepEqual(prop(schema,'required')?.elements.map(literal),['choiceId']);
  }
  const handler=pin(SOURCE,tool,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===`merchant.${tool}`,mailReadSourcePins[key]);
  const method=tool.slice(5);
  assert.equal(nodes(handler,n=>n.type==='CallExpression'&&memberPath(n.callee)===`mailChat.${method}`).length,
   tool==='mail_list'?1:1,`${tool}: selected mail adapter call`);
 }
 pin(SOURCE,'saved mail original hop and choice',fn('validateSavedMail'),mailReadSourcePins.saved);
 pin(COMPOSITION,'conditional active mail adapter',n=>n.type==='VariableDeclarator'&&name(n.id)==='activeMailChat',mailReadSourcePins.active);
 pin(COMPOSITION,'conditional merchant mail methods',n=>n.type==='VariableDeclarator'&&name(n.id)==='mailChat',mailReadSourcePins.composition);
 pin(COMPOSITION,'conditional original mail-read assessment',n=>n.type==='VariableDeclarator'
  &&name(n.id)==='mailAgentReadAssessment',mailReadSourcePins.assessmentComposition);
 pin(COMPOSITION,'optional owned mail publication and selected provider',fn('getSecureShopBoundReviewComposition'),
  auditSummarySourcePins.runtimeComposition);
 for(const [file,id,key] of [[MAIL_READ,'createBoundMailChat','adapter'],[MAIL_READ,'validateMailChatResult','packet'],
  [MAIL_APP,'createMailApplication','application'],[MAIL_PRODUCTION,'createMailProduction','production'],
  [MAIL_PRODUCTION,'mailServingEnabled','serving'],[MAIL_REPOSITORY,'createBoundMailRepository','repository'],
  [MAIL_ASSESSMENT,'createMailAgentReadAssessment','assessment'],[MAIL_ORIGINAL,'createMailAgentReadOriginalReader','original']])
  pin(file,id,fn(id),mailReadSourcePins[key]);
 const application=nodes(parse(MAIL_APP,overrides),n=>n.type==='FunctionDeclaration'&&name(n.id)==='createMailApplication')[0];
 assert.ok(nodes(application,n=>n.type==='ObjectMethod'&&name(n.key)==='disclose'
  &&nodes(n,x=>n!==x&&x.type==='CallExpression'&&memberPath(x.callee)==='mailRepository.read').length).length);
 assert.ok(nodes(application,n=>n.type==='ObjectMethod'&&name(n.key)==='projectDisclosure'
  &&nodes(n,x=>n!==x&&x.type==='CallExpression'&&memberPath(x.callee)==='mailRepository.projectRead').length).length);
 const repository=nodes(parse(MAIL_REPOSITORY,overrides),n=>n.type==='FunctionDeclaration'&&name(n.id)==='createBoundMailRepository')[0];
 assert.ok(nodes(repository,n=>n.type==='ObjectProperty'&&name(n.key)==='read'
  &&nodes(n,x=>x.type==='CallExpression'&&name(x.callee)==='execute'&&literal(x.arguments[1])==='read').length).length);
 assert.ok(nodes(repository,n=>n.type==='ObjectMethod'&&name(n.key)==='projectRead'
  &&nodes(n,x=>x.type==='TemplateLiteral'&&x.quasis.some(q=>q.value.cooked.includes('secureshop_agents.project_bound_lab_mail_read'))).length).length);
}
function checkAuditSummary(manifest,overrides){
 const row=manifest.roleChatDescriptorPartition.reviewedDescriptors.find(item=>item.descriptorId==='admin.audit_summary_prepare');
 assert.deepEqual(row,{
  descriptorId:'admin.audit_summary_prepare',
  bridgeActionIds:['agent.admin.assistant.chat','agent.admin.assistant.auditJobRun','agent.admin.assistant.auditJobOperation'],
  availability:'Administrator without selected choice, with composed auditJobs and an available ordinary Audit summary run. Feature configuration must match SS_AUDIT_SUMMARY_ENABLED; the ordinary runtime is separate from the unbounded V36 runtime.',
  handler:'createLocalTools: admin.audit_summary_prepare -> auditJobs.prepare(action=summary, requestedCount=args.requestedCount)',
  consequence:'Model-selected positive requestedCount present in the current message creates a purpose-bound Audit summary session and digest-bound proposal, not a summary execution. A separate protected Run executes the exact saved proposal through the ordinary Audit runtime and its model/worker, publishes a durable result, and protected GET reads the saved operation without a new run.',
  confirmation:'The model-selected prepare is followed by a separate physical Run; uncertain outcome requires saved GET and no automatic POST retry. Rendered use, actual effect, denial-no-effect and Judge are not inferred from this source review.',
  modelApplicability:'model_selected_prepare_then_manual_run_with_model_worker',
  judgeApplicability:'conditional_ordinary_audit_summary_assessment_only_after_admitted_run; no V36 direct-button or original-check credit transfer',
  runtimeEvidence:null,
 });
 const descriptor=exactSourceNode(SOURCE,overrides,'audit summary declared descriptor',n=>n.type==='ObjectExpression'
  &&literal(prop(n,'agent'))==='admin'&&literal(prop(n,'tool'))==='audit_summary_prepare',
  'edafca465c937f0eb25a398ddb4807892549580a32edd3d60d07f47c2f0a3938');
 // The complete reviewed modules are also frozen: this includes top-level imports,
 // exports, feature-config plumbing and worker/journal helpers outside factory bodies.
 for(const [file,sha] of Object.entries(auditSummaryFilePins)){
  const bytes=overrides[file]??fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha,`${file}: audited source drift`);
 }
 const schema=prop(descriptor,'inputSchema');
 assert.equal(literal(prop(schema,'type')),'object');
 assert.equal(literal(prop(prop(prop(schema,'properties'),'requestedCount'),'type')),'integer');
 assert.equal(prop(prop(prop(schema,'properties'),'requestedCount'),'minimum')?.value,1);
 assert.equal(prop(prop(prop(schema,'properties'),'requestedCount'),'maximum')?.value,100000);
 assert.deepEqual(prop(schema,'required')?.elements.map(literal),['requestedCount']);
 assert.equal(prop(schema,'additionalProperties')?.value,false);
 const pin=(file,label,predicate,sha)=>exactSourceNode(file,overrides,label,predicate,sha);
 const fn=(id)=>(n=>n.type==='FunctionDeclaration'&&name(n.id)===id);
 pin(SOURCE,'selected RoleChat prepare, saved turn, Run and read',fn('createSecureShopBoundRoleChat'),auditSummarySourcePins.roleChat);
 pin(SOURCE,'selected count-to-proposal handler',n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])==='admin.audit_summary_prepare',auditSummarySourcePins.selectedHandler);
 pin(COMPOSITION,'Audit jobs construction',n=>n.type==='VariableDeclarator'&&name(n.id)==='auditJobs',auditSummarySourcePins.auditJobsComposition);
 pin(COMPOSITION,'RoleChat injection',fn('createSecureShopBoundReviewComposition'),auditSummarySourcePins.composition);
 pin(COMPOSITION,'ordinary summary provider',n=>n.type==='ObjectProperty'&&name(n.key)==='getAuditSummary'
  &&memberPath(n.value?.body)==='value.auditSummary',auditSummarySourcePins.ordinaryProvider);
 pin(COMPOSITION,'conditional ordinary runtime',fn('getSecureShopBoundReviewComposition'),auditSummarySourcePins.runtimeComposition);
 pin(COMPOSITION,'ordinary and separate unbounded creation',n=>n.type==='IfStatement'
  &&memberPath(n.test)==='snapshot.configured.auditSummaryFeature',auditSummarySourcePins.featureGate);
 for(const [file,id,key] of [[AUDIT_JOBS,'createBoundAuditJobs','jobs'],[AUDIT_LIFECYCLE,'createSecureShopAuditRuntimeLifecycle','lifecycle'],
  [AUDIT_RUNTIME,'createSecureShopAuditRuntime','runtime'],[AUDIT_RUNNER,'createSecureShopAuditRunner','runner'],
  [AUDIT_JOB,'createSecureShopAuditJob','job']])pin(file,id,fn(id),auditSummarySourcePins[key]);
 for(const [id,key] of [['input','proposalInput'],['create','proposalCreate'],['validate','proposalValidate'],['result','proposalResult']])
  pin(AUDIT_PROPOSAL,id,fn(id),auditSummarySourcePins[key]);
 const routeSource=overrides[ROUTER]??fs.readFileSync(path.join(ROOT,ROUTER),'utf8');
 for(const [method,suffix,handler,key] of [['post','/audit/job/run','runAuditJob','runRoute'],
  ['get','/audit/job/operations/:sessionId/:requestId/:proposalId','readAuditJob','readRoute']])
  pin(ROUTER,`${method} ${suffix}`,n=>n.type==='CallExpression'&&memberPath(n.callee)===`router.${method}`
   &&n.arguments[0]?.type==='TemplateLiteral'&&n.arguments[0].quasis.map(q=>q.value.cooked).join('|')===`|${suffix}`
   &&routeSource.slice(n.start,n.end).includes(`runtime.${handler}(`),auditSummarySourcePins[key]);
}
function checkUserLookup(manifest,overrides,src,composition,router){
 const partition=manifest.roleChatDescriptorPartition;
 const row=partition.reviewedDescriptors.find(item=>item.descriptorId==='admin.user_lookup');
 assert.deepEqual(row,{
  descriptorId:'admin.user_lookup',
  bridgeActionIds:['agent.admin.assistant.chat','agent.admin.assistant.operation','agent.admin.assistant.userLookupAssess','agent.admin.assistant.userLookupAssessment'],
  availability:'Administrator, no selected choice, both synthetic lookup and saved-readback methods composed; user administration requires persona authority, administration repository, admin directory and agents-audit append. Assessment separately requires personaBindings and readAgentLookup, then original-turn and eligibility checks.',
  handler:'createLocalTools: admin.user_lookup -> userAdministration.lookupForAgent',
  consequence:'Exact selected synthetic username may insert an owner-scoped immutable directory row and append an audit event; Vulnerable returns the selected full synthetic record, Fixed redacts, and saved readAgentLookup verifies the original receipt, audit and row digest without another lookup effect.',
  confirmation:'No separate physical confirmation for the model-selected lookup; saved GET is readback, not replay or a new effect. Physical use, uncertain-outcome reconciliation and denial-no-effect remain unverified.',
  modelApplicability:'model_selected_chat_tool',
  judgeApplicability:'conditional_user_lookup_assessment_only_after_eligible_original_completed_turn; never automatic credit from lookup or readback',
  runtimeEvidence:null,
 });
 const roleSource=overrides[SOURCE]??fs.readFileSync(path.join(ROOT,SOURCE),'utf8');
 const fragment=n=>roleSource.slice(n.start,n.end);
 const descriptor=exactSourceNode(SOURCE,overrides,'admin.user_lookup descriptor',n=>n.type==='ObjectExpression'
  &&literal(prop(n,'agent'))==='admin'&&literal(prop(n,'tool'))==='user_lookup',userLookupSourcePins.descriptor);
 const schema=prop(descriptor,'inputSchema');
 assert.equal(literal(prop(schema,'type')),'object');
 assert.equal(literal(prop(prop(prop(schema,'properties'),'username'),'type')),'string');
 assert.equal(prop(prop(prop(schema,'properties'),'username'),'maxLength')?.value,100);
 assert.equal(literal(prop(schema,'additionalProperties')),null); // checked as a BooleanLiteral below
 assert.equal(prop(schema,'additionalProperties')?.value,false);
 assert.deepEqual(prop(schema,'required')?.elements.map(literal),['username']);
 exactSourceNode(SOURCE,overrides,'admin.user_lookup availability',n=>n.type==='IfStatement'
  &&fragment(n).startsWith("if(tool.tool==='user_lookup')"),userLookupSourcePins.availability);
 exactSourceNode(SOURCE,overrides,'admin.user_lookup selected handler',n=>n.type==='ArrayExpression'
  &&literal(n.elements?.[0])==='admin.user_lookup',userLookupSourcePins.handler);
 exactSourceNode(SOURCE,overrides,'admin.user_lookup saved reread',n=>n.type==='IfStatement'
  &&fragment(n).startsWith('if(meta.userLookup!=null)'),userLookupSourcePins.savedReread);
 exactSourceNode(COMPOSITION,overrides,'bound user administration composition',n=>n.type==='VariableDeclarator'
  &&name(n.id)==='userAdministration',userLookupSourcePins.composition);
 exactSourceNode(COMPOSITION,overrides,'conditional user lookup assessment composition',n=>n.type==='VariableDeclarator'
  &&name(n.id)==='userLookupAssessment',userLookupSourcePins.assessmentComposition);
 exactSourceNode(USER_ADMIN,overrides,'administrator lookup authority and return',n=>n.type==='FunctionDeclaration'
  &&name(n.id)==='createSecureShopBoundUserAdministration',userLookupSourcePins.administration);
 exactSourceNode(USER_DIRECTORY,overrides,'synthetic directory selected SQL and receipt',n=>n.type==='FunctionDeclaration'
  &&name(n.id)==='createSyntheticUserDirectoryRepository',userLookupSourcePins.repository);
 for(const [moduleName,key] of [['node:crypto','cryptoImport'],['bcryptjs','bcryptImport'],['node:util','utilImport'],
  ['../../services/secureshopConversationBinding','scopeImport']])
  exactSourceNode(USER_DIRECTORY,overrides,`synthetic directory import ${moduleName}`,n=>n.type==='VariableDeclaration'
   &&n.declarations.length===1&&n.declarations[0].init?.type==='CallExpression'
   &&name(n.declarations[0].init.callee)==='require'&&literal(n.declarations[0].init.arguments[0])===moduleName,
   userLookupSourcePins[key]);
 for(const [id,key] of [['fields','directoryFields'],['safeFields','safeFields'],['digest','directoryDigest'],['rowDigest','rowDigest']])
  exactSourceNode(USER_DIRECTORY,overrides,`synthetic directory ${id}`,n=>n.type==='VariableDeclarator'
   &&name(n.id)===id,userLookupSourcePins[key]);
 for(const [id,key] of [['agentContext','agentContext'],['reference','reference'],['createSyntheticDirectory','syntheticDirectory']])
  exactSourceNode(USER_DIRECTORY,overrides,`synthetic directory ${id}`,n=>n.type==='FunctionDeclaration'
   &&name(n.id)===id,userLookupSourcePins[key]);
 exactSourceNode(USER_ASSESSMENT,overrides,'conditional original lookup assessment',n=>n.type==='FunctionDeclaration'
  &&name(n.id)==='createUserLookupAssessment',userLookupSourcePins.assessment);
 exactSourceNode(ROUTER,overrides,'user lookup assessment routes',n=>n.type==='VariableDeclarator'
  &&name(n.id)==='userLookupAssessmentRoute',userLookupSourcePins.assessmentRoute);
 const routerSource=overrides[ROUTER]??fs.readFileSync(path.join(ROOT,ROUTER),'utf8');
 exactSourceNode(ROUTER,overrides,'administrator-only user lookup assessment mount',n=>n.type==='IfStatement'
  &&routerSource.slice(n.start,n.end).includes('const userLookupAssessmentRoute=method'),userLookupSourcePins.assessmentRouteMount);
 const checkExport=(file,required)=>{
  const assignments=nodes(parse(file,overrides),n=>n.type==='AssignmentExpression'&&memberPath(n.left)==='module.exports');
  assert.equal(assignments.length,1,`${file} unique export`);
  const object=assignments[0].right;assert.equal(object?.type,'ObjectExpression');
  assert.deepEqual(object.properties.map(p=>[name(p.key),name(p.value)]),required.map(id=>[id,id]));
 };
 checkExport(USER_ADMIN,['createSecureShopBoundUserAdministration']);
 checkExport(USER_DIRECTORY,['createSyntheticUserDirectoryRepository']);
 checkExport(USER_ASSESSMENT,['createUserLookupAssessment','assessmentRequestId']);
 const roleExports=nodes(src,n=>n.type==='AssignmentExpression'&&memberPath(n.left)==='module.exports');
 assert.equal(roleExports.length,1,'one bound RoleChat export');
 assert.deepEqual(roleExports[0].right?.properties?.map(p=>[name(p.key),name(p.value)]),[
  ['createSecureShopBoundRoleChat','createSecureShopBoundRoleChat'],['TOOLS','tools'],['ORIGINAL_REGISTER_TOOL','ORIGINAL_REGISTER_TOOL'],
 ]);
 const composed=nodes(composition,n=>n.type==='CallExpression'&&name(n.callee)==='createSecureShopBoundRoleChat');
 assert.equal(composed.length,1);
 assert.equal(nodes(composed[0].arguments[0],n=>n.type==='ObjectProperty'&&name(n.key)==='userAdministration'
  &&name(n.value)==='userAdministration').length,1,'bound RoleChat receives selected user administration');
 assert.equal(nodes(composed[0].arguments[0],n=>n.type==='ObjectProperty'&&name(n.key)==='userLookupAssessmentReady'
  &&n.value?.type==='ArrowFunctionExpression'&&nodes(n.value,x=>x.type==='CallExpression'
   &&name(x.callee?.property)==='readSecureShopAssessmentEligibility').length).length,1,
 'bound RoleChat receives conditional original-assessment eligibility');
 const mounted=nodes(composition,n=>n.type==='CallExpression'&&name(n.callee)==='createBoundRoleChatRouter');
 assert.equal(mounted.length,1);
 assert.equal(nodes(mounted[0].arguments[0],n=>n.type==='ObjectProperty'&&name(n.key)==='userLookupAssessment'
  &&name(n.value)==='userLookupAssessment').length,1,'router receives selected conditional assessment');
 const assessmentConstructor=nodes(composition,n=>n.type==='CallExpression'&&memberPath(n.callee)==='require'&&literal(n.arguments[0])==='./secureshopUserLookupAssessment');
 assert.equal(assessmentConstructor.length,1);
 const constructed=nodes(composition,n=>n.type==='CallExpression'&&name(n.callee?.property)==='createUserLookupAssessment'
  &&n.callee.object?.type==='CallExpression'&&name(n.callee.object.callee)==='require'
  &&literal(n.callee.object.arguments[0])==='./secureshopUserLookupAssessment');
 assert.equal(constructed.length,1);
 const routeCalls=nodes(router,n=>n.type==='CallExpression'&&['router.post','router.get'].includes(memberPath(n.callee))
  &&n.arguments[0]?.type==='TemplateLiteral'&&n.arguments[0].quasis.some(q=>q.value.cooked.includes('user-lookup')));
 assert.deepEqual(routeCalls.map(n=>[memberPath(n.callee),n.arguments[0].quasis.map(q=>q.value.cooked).join('|'),
  literal(n.arguments.at(-1)?.arguments?.[0])]),[
  ['router.post','|/user-lookup/assess','runAttempt'],
  ['router.get','|/sessions/:sessionId/requests/:requestId/user-lookup/assessment','readOutcome'],
 ]);
}
function check(manifest,overrides={}){
 const p=manifest.roleChatDescriptorPartition;
 assert.equal(p.status,'bounded_source_review_runtime_unverified');
 assert.equal(p.q05,'deferred_unverified');assert.equal(p.q08,'deferred_unverified');
 assert.equal(p.physicalUiVerified,false);assert.equal(p.nativeEffectVerified,false);
 const src=parse(SOURCE,overrides),composition=parse(COMPOSITION,overrides),app=parse(APPLICATION,overrides),gateway=parse(GATEWAY,overrides),router=parse(ROUTER,overrides),bridge=parse(BRIDGE,overrides);
 const tools=nodes(src,n=>n.type==='VariableDeclarator'&&name(n.id)==='tools');
 assert.equal(tools.length,1,'unique tools declaration');
 assert.equal(member(tools[0].init.callee),'Object.freeze');
 const definitions=tools[0].init.arguments[0];
 const descriptors=[];
 for(const role of ['merchant','admin']){
  const array=prop(definitions,role)?.arguments?.[0];assert.equal(array?.type,'ArrayExpression');
  for(const entry of array.elements){assert.equal(literal(prop(entry,'agent')),role);descriptors.push(`${role}.${literal(prop(entry,'tool'))}`)}
 }
 assert.equal(new Set(descriptors).size,descriptors.length,'unique declared descriptors');
 assert.equal(p.advertisedDescriptorCount,descriptors.length);
 assert.equal(descriptors.includes('mcp-registry.register'),false,'original register is outside the 51-descriptor partition');
 assert.equal(p.separatelyOfferedDirectEffects.length,1);
 const original=p.separatelyOfferedDirectEffects[0];
 assert.equal(original.toolKey,'mcp-registry.register');
 assert.equal(original.bridgeActionId,p.sharedRoleChatEntry.admin.chatBridgeActionId);
 assert.equal(original.runtimeEvidence,null);
 assert.equal(original.confirmation.kind,'original_v23_direct_effect_no_separate_post_model_confirmation');
 const separate=nodes(src,n=>n.type==='VariableDeclarator'&&name(n.id)==='ORIGINAL_REGISTER_TOOL');
 assert.equal(separate.length,1,'one separately declared original register tool');
 assert.equal(literal(prop(separate[0].init.arguments[0],'agent')),'mcp-registry');
 assert.equal(literal(prop(separate[0].init.arguments[0],'tool')),'register');
 const declared=nodes(src,n=>n.type==='VariableDeclarator'&&name(n.id)==='declared');
 assert.equal(declared.length,1);
 assert.ok(nodes(declared[0].init,n=>n.type==='Identifier'&&n.name==='ORIGINAL_REGISTER_TOOL').length);
 assert.ok(nodes(composition,n=>n.type==='Identifier'&&n.name==='ORIGINAL_REGISTER_TOOL').length);
 const originalFilter=nodes(src,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&member(n.test.left)==='tool.agent'&&literal(n.test.right)==='mcp-registry');
 assert.equal(originalFilter.length,1,'original tool has its own conditional availability gate');
 for(const symbol of ['mcpRegistryChat','mcpRegistrationApplication'])
  assert.ok(nodes(originalFilter[0],n=>n.type==='Identifier'&&n.name===symbol).length,symbol);
 assert.equal(nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])==='mcp-registry.register'
  &&nodes(n.elements?.[1],x=>x.type==='CallExpression'&&member(x.callee)==='adapter.invoke').length).length,1);
 assert.deepEqual(p.reviewedDescriptors.map(row=>row.descriptorId).sort(),Object.keys(selected).sort());
 const unresolved=descriptors.filter(id=>!Object.hasOwn(selected,id)).sort();
 assert.deepEqual([...p.unresolvedDescriptorIds].sort(),unresolved,'complete unresolved complement of actual declarations');
 assert.equal(new Set(p.unresolvedDescriptorIds).size,p.unresolvedDescriptorIds.length);
 assert.deepEqual(p.sourceAccountedDescriptors.map(row=>row.descriptorId).sort(),unresolved,'all unresolved descriptors have exact source-accounting rows');
 assert.equal(new Set(p.sourceAccountedDescriptors.map(row=>row.descriptorId)).size,p.sourceAccountedDescriptors.length);
 for(const row of p.sourceAccountedDescriptors){
  assert.ok(Object.hasOwn(p.sourceAccountingFamilies,row.family),`known family ${row.descriptorId}`);
  assert.ok(row.availability&&row.continuation&&row.handler,`bounded metadata ${row.descriptorId}`);
  const direct=nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===row.descriptorId&&n.elements[1]?.type==='ArrowFunctionExpression');
  const body=direct.length===1?direct[0].elements[1]:generatedHandler(src,row.descriptorId);
  assert.ok(body,`handler binding ${row.descriptorId}`);
  assert.ok(handlerAnchor(body,row.handler),`handler anchor ${row.descriptorId} -> ${row.handler}`);
 }
 const bridgeIds=new Set(manifest.actions.map(action=>action.id));
 const bridgeKeys=new Set(nodes(bridge,n=>n.type==='ObjectProperty'&&typeof literal(n.key)==='string').map(n=>literal(n.key)));
 assert.equal(nodes(router,n=>n.type==='VariableDeclarator'&&name(n.id)==='prefix'&&n.init?.type==='TemplateLiteral'&&n.init.quasis.map(q=>q.value.cooked).join('|')==='/agents/|/assistant').length,1);
 for(const role of ['merchant','admin']){
  const entry=p.sharedRoleChatEntry[role];assert.equal(entry.routePrefix,`/agents/${role}/assistant`);
  for(const actionId of [entry.chatBridgeActionId,entry.requestReadbackBridgeActionId]){
   assert.ok(bridgeIds.has(actionId)&&bridgeKeys.has(actionId),`shared bridge ${actionId}`);
  }
  assert.equal(entry.chatBridgeActionId,`agent.${role}.assistant.chat`);
  assert.equal(entry.requestReadbackBridgeActionId,`agent.${role}.assistant.operation`);
 }
 for(const [verb,suffix,callee] of [['post','/chat','runtime.run'],['get','/operations/:sessionId/:requestId','runtime.readRequest']]){
  assert.equal(nodes(router,n=>n.type==='CallExpression'&&member(n.callee)===`router.${verb}`&&n.arguments[0]?.type==='TemplateLiteral'&&n.arguments[0].quasis.map(q=>q.value.cooked).join('|')===`|${suffix}`
   &&nodes(n.arguments.at(-1),x=>x.type==='CallExpression'&&member(x.callee)===callee).length).length,1,`shared RoleChat route ${suffix}`);
 }
 for(const row of p.reviewedDescriptors){
  assert.ok(descriptors.includes(row.descriptorId));
  assert.equal(row.runtimeEvidence,null);
  for(const id of row.bridgeActionIds){assert.ok(bridgeIds.has(id),`manifest bridge ${id}`);assert.ok(bridgeKeys.has(id),`source bridge ${id}`)}
  const binding=selected[row.descriptorId];
  const handler=nodes(src,n=>n.type==='ArrayExpression'&&literal(n.elements?.[0])===row.descriptorId&&n.elements?.[1]?.type==='ArrowFunctionExpression');
  if(['merchant.listing_import_setup','merchant.listing_rewrite_setup','merchant.listing_optimize_setup'].includes(row.descriptorId)){
   assert.equal(handler.length,0,`${row.descriptorId}: no shadow literal handler`);
   assert.equal(binding.handler,'listingsSetup.prepare');
  }else if(['admin.policy_create_prepare','admin.policy_edit_prepare','admin.policy_preview_prepare','admin.policy_delete_prepare','admin.mcp_register_prepare','admin.mcp_import_prepare','admin.mcp_retire_prepare'].includes(row.descriptorId)){
   assert.equal(handler.length,0,`${row.descriptorId}: generated handler, no shadow literal`);
   assert.equal(binding.handler,row.descriptorId.startsWith('admin.mcp_')?'mcpService().prepare':'policyService().prepare');
  }else if(['merchant.mail_send_prepare','merchant.mail_reply_prepare'].includes(row.descriptorId)){
   // This handler is generated by the send/reply map; demand the exact map source and computed key.
   const generated=nodes(src,n=>n.type==='CallExpression'&&name(n.callee?.property)==='map'&&n.callee.object?.type==='ArrayExpression'&&n.callee.object.elements.map(literal).join(',')==='send,reply'
    &&nodes(n.arguments[0],x=>x.type==='TemplateLiteral'&&x.quasis.map(q=>q.value.cooked).join('|')==='merchant.mail_|_prepare').length===2
    &&nodes(n.arguments[0],x=>call(x,'mailActions.prepare')).length===1);
   assert.equal(generated.length,1,'unique send/reply generated handler');
   assert.equal(handler.length,0,'no shadow literal handler');
  }else{
   assert.equal(handler.length,1,`unique handler ${row.descriptorId}`);
   if(row.descriptorId==='merchant.reviews_list')
    assert.equal(nodes(handler[0].elements[1],n=>n.type==='CallExpression'&&calleePath(n.callee)==='reviewService().list').length,1,'reviews list selected service');
   else if(row.descriptorId==='merchant.reviews_detail')
    assert.equal(nodes(handler[0].elements[1],n=>n.type==='CallExpression'&&name(n.callee)==='readInScene'
     &&name(n.arguments[0])==='selectedReview').length,1,'handler anchor reviews detail selected helper');
   else if(row.descriptorId==='merchant.catalog_search')
    assert.equal(nodes(handler[0].elements[1],n=>call(n,'catalog.searchMerchantProducts')).length,1,'handler anchor catalog search');
   else if(row.descriptorId==='merchant.manual_search')
    assert.equal(nodes(handler[0].elements[1],n=>call(n,'productRetrieval.searchManuals')).length,1,'handler anchor manual search');
   else if(row.descriptorId==='admin.mcp_detail')
    assert.equal(nodes(handler[0].elements[1],n=>n.type==='CallExpression'&&calleePath(n.callee)==='mcpService().detail').length,1,'selected MCP detail');
   else if(row.descriptorId==='admin.mcp_invocation_setup')
    assert.equal(nodes(handler[0].elements[1],n=>n.type==='AssignmentExpression'&&name(n.left)==='registeredMcpSetup').length,1,'registered MCP handoff only');
   else if(['admin.role_change_prepare','admin.ban_prepare','admin.password_reset_setup','merchant.pricing_suggest_prepare','merchant.pricing_compare_prepare','merchant.pricing_experiment_prepare','merchant.inventory_prepare','merchant.review_decision_prepare','admin.policies_search','admin.policy_detail','admin.mcp_servers'].includes(row.descriptorId))
    assert.equal(nodes(handler[0].elements[1],n=>n.type==='CallExpression'&&name(n.callee)===binding.handler).length,1,`handler call ${binding.handler}`);
   else assert.equal(nodes(handler[0].elements[1],n=>call(n,binding.handler)).length,1,`handler call ${binding.handler}`);
  }
 }
 checkUserLookup(manifest,overrides,src,composition,router);
 checkAuditSummary(manifest,overrides);
 checkMailReads(manifest,overrides);
 checkListingsSetups(manifest,overrides);
 checkMerchantOrders(manifest,overrides);
 checkMerchantReporting(manifest,overrides);
 checkMerchantReviewReads(manifest,overrides);
 checkMerchantProductReads(manifest,overrides);
 checkAdminUserReadsAndPreparations(manifest,overrides);
 checkAdminAclDiscoveryAndPreparations(manifest,overrides);
 checkAdminSystemReadAndPreparations(manifest,overrides);
 checkMerchantPricingPreparations(manifest,overrides);
 checkAdminPolicyBatch(manifest,overrides);
 checkAdminMcpRegistryBatch(manifest,overrides);
 checkMerchantProductChangePreparations(manifest,overrides);
 checkFinalRoleChatDescriptors(manifest,overrides);
 // The declared.filter callback is the advertised availability authority, not a declaration-only claim.
 const available=nodes(src,n=>n.type==='VariableDeclarator'&&name(n.id)==='available');
 assert.equal(available.length,1);assert.equal(name(available[0].init.callee.property),'map');
 assert.equal(member(available[0].init.callee.object.callee),'declared.filter');
 const filter=available[0].init.callee.object.arguments[0];
 assert.ok(nodes(filter,n=>n.type==='IfStatement'&&name(n.test)==='mailActionIntent'&&nodes(n.consequent,x=>x.type==='TemplateLiteral'&&x.quasis.map(q=>q.value.cooked).join('|')==='mail_|_prepare').length).length);
 assert.ok(nodes(filter,n=>n.type==='IfStatement'&&name(n.test?.left)==='role'&&literal(n.test?.right)==='admin').length);
 assert.ok(nodes(filter,n=>n.type==='CallExpression'&&name(n.callee?.property)==='includes'&&n.callee.object?.type==='ArrayExpression'&&n.callee.object.elements.map(literal).join(',')==='mail_send_prepare,mail_reply_prepare').length);
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&member(n.callee)==='auditChat.search').length===1);
 assert.ok(nodes(src,n=>n.type==='CallExpression'&&member(n.callee)==='systemReads.configRead').length===1);
 // Check the role-specific injected dependencies and constructor return wiring.
 assert.ok(nodes(composition,n=>n.type==='CallExpression'&&name(n.callee)==='createSecureShopBoundRoleChat'&&nodes(n.arguments[0],x=>x.type==='ObjectProperty'&&name(x.key)==='auditChat'&&name(x.value)==='auditChat').length&&nodes(n.arguments[0],x=>x.type==='ObjectProperty'&&name(x.key)==='systemReads'&&name(x.value)==='systemReads').length&&nodes(n.arguments[0],x=>x.type==='ObjectProperty'&&name(x.key)==='mailActions'&&name(x.value)==='mailActions').length).length);
 assert.ok(nodes(composition,n=>n.type==='CallExpression'&&name(n.callee)==='createBoundRoleChatRouter'&&name(prop(n.arguments[0],'runtime'))==='roleChat').length);
 assert.ok(nodes(app,n=>n.type==='CallExpression'&&name(n.callee?.property)==='createSecureShopBoundGateway'&&n.callee.object?.type==='CallExpression'&&literal(n.callee.object.arguments[0])==='../routes/secureshop/boundGateway').length);
 for(const role of ['merchant','admin'])assert.ok(nodes(app,n=>n.type==='ObjectProperty'&&name(n.key)===`${role}AssistantRouter`&&memberPath(n.value)===`composition.roleAssistants.${role}.router`).length);
 for(const role of ['merchant','admin'])assert.ok(nodes(gateway,n=>n.type==='CallExpression'&&member(n.callee)==='router.use'&&name(n.arguments[0])===`${role}AssistantRouter`).length);
 for(const row of p.reviewedDescriptors){
  const binding=selected[row.descriptorId];
  const route=nodes(router,n=>n.type==='CallExpression'&&member(n.callee)===`router.${binding.verb}`&&n.arguments[0]?.type==='TemplateLiteral'&&n.arguments[0].quasis.map(q=>q.value.cooked).join('|')===`|${binding.route}`
   &&nodes(n.arguments.at(-1),x=>x.type==='CallExpression'&&member(x.callee)===`runtime.${binding.operation}`).length);
  assert.equal(route.length,1,`mounted route ${binding.route} -> ${binding.operation}`);
 }
 assert.ok(nodes(parse(AUDIT,overrides),n=>n.type==='CallExpression'&&name(n.callee?.property)==='search'&&n.callee.object?.type==='CallExpression'&&name(n.callee.object.callee)==='service').length);
 assert.ok(nodes(parse(SYSTEM,overrides),n=>n.type==='CallExpression'&&name(n.callee?.property)==='read'&&n.callee.object?.type==='MemberExpression'&&member(n.callee.object)==='system.service').length);
 assert.ok(nodes(parse(MAIL,overrides),n=>call(n,'mailApplication.prepareTarget')).length);
 assert.ok(nodes(parse(MAIL,overrides),n=>call(n,'mailApplication.send')).length);
 assert.ok(nodes(src,n=>n.type==='IfStatement'&&nodes(n.test,x=>memberPath(x)==='systemConfigRead.state').length&&nodes(n.consequent,x=>call(x,'systemConfigAssessment.runAttempt')).length).length);
 return true;
}
const manifest=()=>JSON.parse(fs.readFileSync(path.join(ROOT,MANIFEST),'utf8'));
test('RoleChat reviewed descriptor partition joins declarations, availability, handlers, bridge IDs, composition, routes, and effects',()=>assert.ok(check(manifest())));
test('fixed RoleChat source-accounting prose matches 51 reviewed and retains native deferral',()=>{
 const p=manifest().roleChatDescriptorPartition;
 assert.equal(p.advertisedDescriptorCount,51);
 assert.equal(p.reviewedDescriptors.length,51);
 assert.equal(p.sourceAccountedDescriptors.length,0);
 assert.deepEqual(p.unresolvedDescriptorIds,[]);
 assert.match(p.scope,/none remain in the local-accounting complement/);
 assert.doesNotMatch(p.scope,/Twenty-nine|other 22/);
 assert.equal(p.physicalUiVerified,false);
 assert.equal(p.nativeEffectVerified,false);
 assert.equal(p.q05,'deferred_unverified');
 assert.equal(p.q08,'deferred_unverified');
});
test('invented or omitted descriptor cannot disappear from unresolved complement',()=>{
 const m=manifest();m.roleChatDescriptorPartition.reviewedDescriptors.pop();assert.throws(()=>check(m));
 const n=manifest();n.roleChatDescriptorPartition.unresolvedDescriptorIds.push('admin.invented');assert.throws(()=>check(n),/unresolved complement/);
});
test('Pricing prepare source drift and fabricated native passage are rejected',()=>{
 const selectedChanges=[
  [SOURCE,"preparePricing('suggest',args,invocation)","preparePricing('compare',args,invocation)"],
  [SOURCE,"args?.choiceId?.toLowerCase()!==selected.choiceId","args?.choiceId?.toLowerCase()===selected.choiceId"],
  [SOURCE,"productId:selected.sourceId","productId:1"],
  [SOURCE,"competitorUrl:selection.competitorUrl","competitorUrl:'http://other.invalid/'"],
  [SOURCE,"experiment=action==='experiment'?{strategy:args.strategy,durationDays:args.durationDays}","experiment=action==='experiment'?{strategy:'premium',durationDays:1}"],
  [SOURCE,"h.tool==='merchant.pricing_compare_prepare'","h.tool==='merchant.pricing_suggest_prepare'"],
  [COMPOSITION,"pricingApplication:()=>createdPricing?.application","pricingApplication:()=>null"],
  [PRICING_PROPOSAL,"requestSha256:requestDigest(canonical)","requestSha256:'0'.repeat(64)"],
 ];
 for(const [file,before,after] of selectedChanges){
  const original=fs.readFileSync(path.join(ROOT,file),'utf8');assert.ok(original.includes(before),`${file}: expected source`);
  const changed=original.replace(before,after);assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: mutation parses`);
  assert.throws(()=>checkMerchantPricingPreparations(manifest(),{[file]:changed}),undefined,`${file}: pinned-source drift`);
 }
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.pricing_compare_prepare').runtimeEvidence={passed:true};
 assert.throws(()=>checkMerchantPricingPreparations(claimed),'preparation source review cannot claim native passage');
 const invented=manifest();invented.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.pricing_experiment_prepare').confirmation='experiment ran';
 assert.throws(()=>checkMerchantPricingPreparations(invented),'exact row rejects fabricated execution');
});
test('Policy read and preparation source drift and fabricated effects are rejected',()=>{
 const changes=[
  [SOURCE,"if(!policyChat)return false;","if(policyChat)return false;"],
  [SOURCE,"filtered.slice((page-1)*5,page*5)","filtered.slice((page-1)*50,page*50)"],
  [SOURCE,"args.choiceId?.toLowerCase()!==selected?.choiceId","args.choiceId?.toLowerCase()===selected?.choiceId"],
  [SOURCE,"candidate=normalizePolicyCandidate(args,policySupportedTargets(policyTaskTargets))","candidate=normalizePolicyCandidate({},policySupportedTargets(policyTaskTargets))"],
  [SOURCE,"preparedPolicyProposal=await readInScene(()=>policyService().prepare({context:policyContext,","preparedPolicyProposal=await readInScene(()=>policyService().wrong({context:policyContext,"],
  [SOURCE,"h.tool==='admin.policy_detail'","h.tool==='admin.policies_search'"],
  [COMPOSITION,"const policyChat = promptPolicies ? require('./secureshopBoundPolicyChat').createBoundPolicyChat({","const policyChat = false ? require('./secureshopBoundPolicyChat').createBoundPolicyChat({"],
  [POLICY_CHAT,"const value = await service.list(structuredClone(context))","const value = await service.list({})"],
  [POLICY_PROPOSAL,"p.requestSha256 = digest(publicValue(p, allowed))","p.requestSha256 = '0'.repeat(64)"],
 ];
 for(const [file,before,after] of changes){
  const original=fs.readFileSync(path.join(ROOT,file),'utf8');assert.ok(original.includes(before),`${file}: expected selected text`);
  const changed=original.replace(before,after);assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: mutation parses`);
  assert.throws(()=>checkAdminPolicyBatch(manifest(),{[file]:changed}),undefined,`${file}: pinned-source drift`);
 }
 const invented=manifest();invented.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.policy_preview_prepare').confirmation='render completed';
 assert.throws(()=>checkAdminPolicyBatch(invented),'full row pin rejects fabricated rendering');
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.policy_delete_prepare').runtimeEvidence={passed:true};
 assert.throws(()=>checkAdminPolicyBatch(claimed),'source-only delete proposal cannot claim native effect');
});
test('MCP Registry discovery, proposal and handoff drift and fabricated effects are rejected',()=>{
 const changes=[
  [SOURCE,"if(!mcpRegistryChat)return false;","if(mcpRegistryChat)return false;"],
  [SOURCE,"filtered.slice((page-1)*5,page*5)","filtered.slice((page-1)*50,page*50)"],
  [SOURCE,"if(row.provenance!=='owned_registry')throw fail('MCP_CHOICE_DENIED')","if(row.provenance==='owned_registry')throw fail('MCP_CHOICE_DENIED')"],
  [SOURCE,"candidate=normalizeRegistryCandidate(action,args)","candidate=normalizeRegistryCandidate(action,{})"],
  [SOURCE,"const proposal=await readInScene(()=>mcpService().prepare({context:mcpContext,","const proposal=await readInScene(()=>mcpService().wrong({context:mcpContext,"],
  [SOURCE,"registeredMcpSetup={version:1,kind:'registered_mcp_setup'","registeredMcpSetup={version:1,kind:'other_setup'"],
  [MCP_CHAT,"const value = await admin.mcpServers(context)","const value = await admin.mcpServers({})"],
  [MCP_CHAT,"return envelope(await current.service.mutate({ ...context, request: p.request }, { signal }), p)","return envelope({state:'completed'}, p)"],
  [MCP_PROPOSAL,"requestSha256: registryRequestDigest(request)","requestSha256: '0'.repeat(64)"],
 ];
 for(const [file,before,after] of changes){
  const original=fs.readFileSync(path.join(ROOT,file),'utf8');assert.ok(original.includes(before),`${file}: expected selected text`);
  const changed=original.replace(before,after);assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: mutation parses`);
  assert.throws(()=>checkAdminMcpRegistryBatch(manifest(),{[file]:changed}),undefined,`${file}: pinned-source drift`);
 }
 const invented=manifest();invented.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.mcp_register_prepare').confirmation='stdio executed';
 assert.throws(()=>checkAdminMcpRegistryBatch(invented),'full row pin rejects fabricated register effect');
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.mcp_invocation_setup').runtimeEvidence={passed:true};
 assert.throws(()=>checkAdminMcpRegistryBatch(claimed),'setup cannot claim native tool invocation');
});
test('merchant product-change preparation source drift and fabricated effects are rejected',()=>{
 const changes=[
  [SOURCE,"quantity:args.quantity,message,readiness","quantity:1,message,readiness"],
  [SOURCE,"productId:selected.sourceId});\n        if(!found?.product)throw fail('ROLE_PROPOSAL_STALE')","productId:1});\n        if(!found?.product)throw fail('ROLE_PROPOSAL_STALE')"],
  [SOURCE,"listing:args.listing,","listing:{name:'other'},"],
  [SOURCE,"previewMerchantListingEdit({...context,patch:args.patch})","previewMerchantListingEdit({...context,patch:{}})"],
  [SOURCE,"digest(merchantRow(found.product,a.mode.snapshot.mode))!==selected.snapshotSha256","digest(merchantRow(found.product,a.mode.snapshot.mode))===selected.snapshotSha256"],
  [CATALOG,"await repository.previewListingCreate(binding, actor.id, input.listing, key,","await repository.previewListingCreate(binding, actor.id, {}, key,"],
  [INVENTORY_PROPOSAL,"stockChange:{productId:selected.sourceId,quantity}","stockChange:{productId:selected.sourceId,quantity:1}"],
  [LISTING_CREATE_PROPOSAL,"preview:structuredClone(preview),origin:{step,callId}","preview:{},origin:{step,callId}"],
  [LISTING_EDIT_PROPOSAL,"preview:structuredClone(preview),","preview:{},"],
 ];
 for(const [file,before,after] of changes){
  const original=fs.readFileSync(path.join(ROOT,file),'utf8');assert.ok(original.includes(before),`${file}: expected selected text`);
  const changed=original.replace(before,after);assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: mutation parses`);
  assert.throws(()=>checkMerchantProductChangePreparations(manifest(),{[file]:changed}),undefined,`${file}: pinned-source drift`);
 }
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.inventory_prepare').runtimeEvidence={passed:true};
 assert.throws(()=>checkMerchantProductChangePreparations(claimed),'source-only stock proposal cannot claim native effect');
 const invented=manifest();invented.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.listing_create_prepare').confirmation='listing published';
 assert.throws(()=>checkMerchantProductChangePreparations(invented),'metadata pin rejects fabricated publication');
});
test('final four RoleChat rows reject parse-valid selected-path drift and fabricated native credit',()=>{
 const changes=[
  [SOURCE,"action,input:action==='send'?","action:'send',input:action==='send'?"],
  [SOURCE,"reason:reviewReason","reason:'fabricated'"],
  [SOURCE,"limit:5","limit:50"],
  [SOURCE,"action:'agent',input:{message}","action:'summary',input:{message}"],
  [MAIL,"mailApplication.prepareTarget(context,","mailApplication.reply(context,"],
  [AUDIT_JOBS,"'createAgentSession'","'createSession'"],
 ];
 for(const [file,before,after] of changes){
  const original=fs.readFileSync(path.join(ROOT,file),'utf8');assert.ok(original.includes(before),`${file}: expected selected text`);
  const changed=original.replace(before,after);assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: mutation parses`);
  assert.throws(()=>checkFinalRoleChatDescriptors(manifest(),{[file]:changed}),/selected source drift/,`${file}: pinned-source drift`);
 }
 const invented=manifest();invented.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.audit_agent_prepare').runtimeEvidence={passed:true};
 assert.throws(()=>checkFinalRoleChatDescriptors(invented),/full metadata drift/,'agent session preparation is not native completion');
});
test('a broken handler or route binding is rejected even with a matching decoy string',()=>{
 const m=manifest(),src=fs.readFileSync(path.join(ROOT,SOURCE),'utf8');
 assert.throws(()=>check(m,{[SOURCE]:src.replace('const value=await auditChat.search({','const value=await auditChat.wrong({')+"\n// auditChat.search\n"}),/handler call/);
 const route=fs.readFileSync(path.join(ROOT,ROUTER),'utf8');
 assert.throws(()=>check(m,{[ROUTER]:route.replace('await runtime.readSystemConfigOperation({','await runtime.readAuditOperation({')+"\n// runtime.readSystemConfigOperation\n"}),/(mounted route|audited source drift)/);
 assert.throws(()=>check(m,{[ROUTER]:route.replace('router.post(`${prefix}/mail/confirm`','router.get(`${prefix}/mail/confirm`')}),/(mounted route|audited source drift)/);
});
test('composition and gateway mount substitutions are rejected',()=>{
 const m=manifest(),composition=fs.readFileSync(path.join(ROOT,COMPOSITION),'utf8');
 assert.throws(()=>check(m,{[COMPOSITION]:composition.replace('router:createBoundRoleChatRouter({role,launches,authenticatePersona,runtime:roleChat,','router:createBoundRoleChatRouter({role,launches,authenticatePersona,runtime:otherChat,')}));
 const gateway=fs.readFileSync(path.join(ROOT,GATEWAY),'utf8');
 assert.throws(()=>check(m,{[GATEWAY]:gateway.replace('router.use(adminAssistantRouter)','router.use(otherAssistantRouter)')}));
});
test('reviewed descriptor identities, metadata and selected handlers reject drift',()=>{
 const m=manifest();m.roleChatDescriptorPartition.reviewedDescriptors[0].descriptorId='merchant.invented';
 assert.throws(()=>check(m));
 const n=manifest();n.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.mail_reply_prepare').handler='catalog.wrong';
 assert.throws(()=>check(n),/metadata drift/);
 const src=fs.readFileSync(path.join(ROOT,SOURCE),'utf8');
 assert.throws(()=>check(manifest(),{[SOURCE]:src.replace('catalog.searchMerchantProducts({','catalog.wrong({')+'\n// catalog.searchMerchantProducts\n'}),/(handler anchor|selected source drift)/);
 assert.throws(()=>check(manifest(),{[SOURCE]:src.replace('if(mailActionIntent)return !!mailActions','if(false)return !!mailActions')}));
 assert.throws(()=>check(manifest(),{[SOURCE]:src.replace('readInScene(selectedReview)','readInScene(otherReview)')+'\n// readInScene(selectedReview)\n'}),/(handler anchor|selected source drift)/);
 assert.throws(()=>check(manifest(),{[SOURCE]:src.replace('registeredMcpSetup={version:1','otherMcpSetup={version:1')+'\n// registeredMcpSetup={version:1\n'}),/(handler anchor|registered MCP handoff only|selected source drift)/);
});
test('reviewed admin.user_lookup selected authority, synthetic effect, saved reread and assessment drift fails closed',()=>{
 const mutate=(file,before,after)=>{
  const source=fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.ok(source.includes(before),`${file}: exact mutation anchor`);
  return {[file]:source.replace(before,after)};
 };
 const changes=[
  [SOURCE,"tool:'user_lookup',description:","tool:'user_lookup_other',description:"],
  [SOURCE,"username:{type:'string',maxLength:100}","username:{type:'string',maxLength:101}"],
  [SOURCE,"if(tool.tool==='user_lookup')return !selected&&","if(tool.tool==='user_lookup')return !!selected&&"],
  [SOURCE,"username:args.username,target,check:()=>check(state)","username:'student_admin',target,check:()=>check(state)"],
  [SOURCE,"if(!exact(value,['version','status','user','receipt'])","if(!exact(value,['version','status','user'])"],
  [SOURCE,"const reread=await userAdministration.readAgentLookup({","const reread=await userAdministration.lookupForAgent({"],
  [SOURCE,"module.exports={createSecureShopBoundRoleChat,TOOLS:tools,ORIGINAL_REGISTER_TOOL};",
   "module.exports={createSecureShopBoundRoleChat:()=>({}),TOOLS:tools,ORIGINAL_REGISTER_TOOL};"],
  [SOURCE,"if(hops.length!==1||!isDeepStrictEqual(hops[0].params,{username:reread.receipt.username})",
   "if(hops.length!==1||!isDeepStrictEqual(hops[0].params,{username:'other'})"],
  [COMPOSITION,"&& typeof audit?.agents?.append === 'function'\n    ? require('./secureshopBoundUserAdministration')",
   "&& true\n    ? require('./secureshopBoundUserAdministration')"],
  [COMPOSITION,"role==='admin'&&personaBindings&&typeof userAdministration?.readAgentLookup==='function'",
   "role==='admin'&&typeof userAdministration?.readAgentLookup==='function'"],
  [COMPOSITION,"lookupRepository: require('../database/postgres/secureshopSyntheticUserDirectoryRepository')",
   "lookupRepository: require('../database/postgres/otherRepository')"],
  [COMPOSITION,"...(role==='admin'?{userAdministration,userLookupAssessmentReady:",
   "...(role==='admin'?{userLookupAssessmentReady:"],
  [COMPOSITION,"userLookupAssessmentReady:async binding=>(await require('./secureshopAssessmentEligibility').readSecureShopAssessmentEligibility",
   "userLookupAssessmentReady:async binding=>(await require('./secureshopAssessmentEligibility').fakeEligibility"],
  [COMPOSITION,"...(userLookupAssessment?{userLookupAssessment}:{}),\n          ...(mailAgentReadAssessment",
   "...(userLookupAssessment?{otherAssessment:userLookupAssessment}:{}),\n          ...(mailAgentReadAssessment"],
  [USER_ADMIN,"await authority.withPersonaEffect(client=>lookupRepository[method](client,request))",
   "await lookupRepository[method](null,request)"],
  [USER_ADMIN,"await authority.assertRemoteAdmission();await check();return value;",
   "await check();return value;"],
  [USER_ADMIN,"module.exports={createSecureShopBoundUserAdministration};",
   "module.exports={createSecureShopBoundUserAdministration:()=>({})};"],
  [USER_DIRECTORY,"context.modeExecution.mode==='fixed'?'redacted':'complete'",
   "context.modeExecution.mode==='fixed'?'complete':'complete'"],
  [USER_DIRECTORY,"const safeFields=['id','username','role'];",
   "const safeFields=['id','username','role','password'];"],
  [USER_DIRECTORY,"require('bcryptjs')","require('./fake-bcrypt')"],
  [USER_DIRECTORY,"const fields = ['id','username','role','email','full_name','phone','password','api_key','session_token'];",
   "const fields = ['id','username','role','email','full_name','phone','password','api_key'];"],
  [USER_DIRECTORY,"await audit.append(client,{eventId:receipt.eventId",
   "await audit.wrong(client,{eventId:receipt.eventId"],
  [USER_DIRECTORY,"rowDigest(user,context.modeExecution.mode)!==saved.rowSha256",
   "false"],
  [USER_DIRECTORY,"module.exports = { createSyntheticUserDirectoryRepository };",
   "module.exports = { createSyntheticUserDirectoryRepository:()=>({}) };"],
  [USER_ASSESSMENT,"turn?.status!=='completed'","turn?.status!=='pending'"],
  [USER_ASSESSMENT,"module.exports={createUserLookupAssessment,assessmentRequestId};",
   "module.exports={createUserLookupAssessment:()=>({}),assessmentRequestId};"],
  [ROUTER,"userLookupAssessmentRoute('runAttempt')","userLookupAssessmentRoute('readOutcome')"],
  [ROUTER,"} if(role==='admin'){\n  const userLookupAssessmentRoute", "} if(role==='merchant'){\n  const userLookupAssessmentRoute"],
 ];
 for(const [file,before,after] of changes)assert.throws(()=>check(manifest(),mutate(file,before,after)),
  undefined,`${file}: ${before}`);
 const wrong=manifest();wrong.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.user_lookup').runtimeEvidence={passed:true};
 assert.throws(()=>check(wrong),'source-only row cannot claim native evidence');
 const missing=manifest();missing.roleChatDescriptorPartition.reviewedDescriptors=missing.roleChatDescriptorPartition.reviewedDescriptors.filter(row=>row.descriptorId!=='admin.user_lookup');
 assert.throws(()=>check(missing),'source-reviewed row cannot silently disappear');
});
test('reviewed admin.audit_summary_prepare selected count, ordinary run and saved readback drift fails closed',()=>{
 const changes=[
  [SOURCE,"requestedCount:args.requestedCount},signal,","requestedCount:1},signal,"],
  [SOURCE,"if(tool.tool==='audit_summary_prepare')return !selected&&!!auditJobs", "if(tool.tool==='audit_summary_prepare')return !!selected&&!!auditJobs"],
  [COMPOSITION,"getAuditSummary:()=>value?.auditSummary,","getAuditSummary:()=>value?.auditUnbounded,"],
  [COMPOSITION,"value=Object.freeze({...value,auditSummary,auditUnbounded});","value=Object.freeze({...value,auditUnbounded});"],
  [AUDIT_JOBS,"assertFixedAuditCount(input.requestedCount);","assertFixedAuditCount(1);"],
  [AUDIT_JOBS,"requestContext:p.requestSha256,signal,beforeEffect:a.check",
   "requestContext:'0'.repeat(64),signal,beforeEffect:a.check"],
  [AUDIT_PROPOSAL,"requestSha256:canonicalDigest(body)","requestSha256:'0'.repeat(64)"],
  [AUDIT_LIFECYCLE,"run:input=>invoke('run',input)","run:input=>invoke('createSession',input)"],
  [AUDIT_RUNTIME,"const runner=createSecureShopAuditRunner({turns,conversations,journal,beginAssessment,capturePersonaAuthority,timing,conversationPurpose,",
   "const runner=createSecureShopAuditRunner({turns,conversations,journal,capturePersonaAuthority,timing,conversationPurpose,"],
  [AUDIT_RUNNER,"requestId:request.requestId,requestedCount,boundary:protectedBoundary,assessment,",
   "requestId:request.requestId,requestedCount:1,boundary:protectedBoundary,assessment,"],
  [AUDIT_JOB,"snapshot.rows({ scope:binding,requestedCount,checkCurrent:check,signal:boundary.signal })",
   "snapshot.rows({ scope:binding,requestedCount:1,checkCurrent:check,signal:boundary.signal })"],
  [AUDIT_WORKER,"const provider = new OllamaProvider({ baseUrl, model });",
   "const provider = {chat:async()=>({})};"],
  [AUDIT_WORKER,"requestedCount: manifest.requestedCount, persona,",
   "requestedCount: 1, persona,"],
  [ROUTER,"router.get(`${prefix}/audit/job/operations/:sessionId/:requestId/:proposalId`",
   "router.post(`${prefix}/audit/job/operations/:sessionId/:requestId/:proposalId`"],
 ];
 for(const [file,before,after] of changes){
  const source=fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.ok(source.includes(before),`${file}: exact mutation anchor`);
  assert.throws(()=>checkAuditSummary(manifest(),{[file]:source.replace(before,after)}),undefined,`${file}: ${before}`);
 }
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.audit_summary_prepare').runtimeEvidence={passed:true};
 assert.throws(()=>checkAuditSummary(claimed,{}),'source-only row cannot claim physical evidence');
});
test('merchant mail-read batch rejects selected recipient, message, receipt and assessment drift',()=>{
 const changes=[
  [SOURCE,"search:args.search,signal,beforeEffect:()=>check(state)","search:'other',signal,beforeEffect:()=>check(state)"],
  [SOURCE,"args.choiceId?.toLowerCase()===selected.choiceId","args.choiceId?.toLowerCase()!==selected.choiceId"],
  [SOURCE,"messageId:selected.sourceId,signal,beforeEffect:()=>check(state)","messageId:1,signal,beforeEffect:()=>check(state)"],
  [SOURCE,"const checked=await mailChat.verify({context:{scope:a.b,persona,personaSession:session},packet:mailRead.result",
   "const checked=await mailChat.fake({context:{scope:a.b,persona,personaSession:session},packet:mailRead.result"],
  [COMPOSITION,"mailApplication:application,listMailActors:scope=>personaRepository.listMailActors(scope)",
   "mailApplication:application,listMailActors:scope=>[]"],
  [COMPOSITION,"getMailApplication:()=>value?.mail?.ready===true?value.mail.application:null",
   "getMailApplication:()=>value?.mail?.ready===true?value.mail.fake:null"],
  [MAIL_READ,"search.toLocaleLowerCase()","'other'.toLocaleLowerCase()"],
  [SOURCE,"recipient,mailModeCapability:selected?.snapshot.mailModeCapability", "recipient:null,mailModeCapability:selected?.snapshot.mailModeCapability"],
  [MAIL_READ,"mailApplication.disclose(context,{requestId,userId:selected.id},{signal})",
   "mailApplication.disclose(context,{requestId,userId:1},{signal})"],
  [MAIL_READ,"mailApplication.projectDisclosure(context,{requestId:packet.readOperationId,messageId,offset},{signal})",
   "mailApplication.projectDisclosure(context,{requestId:packet.readOperationId,messageId:1,offset},{signal})"],
  [MAIL_APP,"mailRepository.read(binding,userId)","mailRepository.browse(binding,userId)"],
  [MAIL_APP,"mailRepository.projectRead(binding,{messageId,offset})","mailRepository.projectRead(binding,{messageId:1,offset})"],
  [MAIL_REPOSITORY,"execute(binding,'read',{userId:positive(userId)})","execute(binding,'send',{userId:positive(userId)})"],
  [MAIL_REPOSITORY,"secureshop_agents.project_bound_lab_mail_read(","secureshop_agents.other_mail_read("],
  [MAIL_PRODUCTION,"const application=require('./secureshopMailApplication').createMailApplication",
   "const application=require('./otherMailApplication').createMailApplication"],
  [MAIL_COMPOSITION,"return production.createMailProduction({...await loadDependencies(),enabled:true});",
   "return production.createMailProduction({...await loadDependencies(),enabled:false});"],
  [MAIL_ASSESSMENT,"if(row.status!=='completed')return status('unconfirmed');",
   "if(row.status!=='pending')return status('unconfirmed');"],
 ];
 for(const [file,before,after] of changes){
  const source=fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.ok(source.includes(before),`${file}: exact mutation anchor`);
  const changed=source.replace(before,after);
  assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: mutation must parse before source-contract denial`);
  assert.throws(()=>checkMailReads(manifest(),{[file]:changed}),undefined,`${file}: ${before}`);
 }
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.mail_detail').runtimeEvidence={passed:true};
 assert.throws(()=>checkMailReads(claimed),'no source-only mail read may claim native evidence');
 const fabricated=manifest();fabricated.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.mail_recipients').confirmation='physical confirmation verified';
 assert.throws(()=>checkMailReads(fabricated),'mail row metadata cannot claim fabricated confirmation');
 const missing=manifest();missing.roleChatDescriptorPartition.reviewedDescriptors=missing.roleChatDescriptorPartition.reviewedDescriptors.filter(row=>row.descriptorId!=='merchant.mail_list');
 assert.throws(()=>checkMailReads(missing),'mail list cannot silently disappear');
});
test('merchant Listings setup batch rejects selected URL, owned product, saved reconstruction and handoff drift',()=>{
 const changes=[
  [SOURCE,"input:action==='import'?{json_url:args.json_url,xml_url:args.xml_url}:{}",
   "input:action==='import'?{json_url:args.xml_url,xml_url:args.json_url}:{}"],
  [SOURCE,"||args.choiceId?.toLowerCase()!==selected.choiceId))throw fail('ROLE_LISTINGS_SETUP_UNAVAILABLE')",
   "||args.choiceId?.toLowerCase()===selected.choiceId))throw fail('ROLE_LISTINGS_SETUP_UNAVAILABLE')"],
  [SOURCE,"selected:['rewrite','optimize'].includes(action)?selected:null",
   "selected:['rewrite','optimize'].includes(action)?null:null"],
  [SOURCE,"const rebuilt=await listingsSetup.reconstruct({context:{scope:a.b,persona,personaSession:session,target}",
   "const rebuilt=await listingsSetup.fake({context:{scope:a.b,persona,personaSession:session,target}"],
  [SOURCE,"if(!isDeepStrictEqual(rebuilt,proposal))throw fail('TURN_REQUEST_CONFLICT');",
   "if(isDeepStrictEqual(rebuilt,proposal))throw fail('TURN_REQUEST_CONFLICT');"],
  [COMPOSITION,"getListingsApplication:()=>value?.listings?.ready===true?value.listings.application:null",
   "getListingsApplication:()=>value?.listings?.ready===false?value.listings.application:null"],
  [COMPOSITION,"prepare:input=>listingsSetupAdapter.prepare(input)","prepare:input=>listingsSetupAdapter.fake(input)"],
  [LISTING_SETUP,"const value=await app.prepareChatSetup({context:args.context,action:args.action,selected:args.selected,signal:args.signal,beforeEffect:args.beforeEffect});",
   "const value=await app.prepareChatSetup({context:args.context,action:args.action,selected:null,signal:args.signal,beforeEffect:args.beforeEffect});"],
  [LISTING_SETUP,"captureFeatureMode(app.modeAuthority,args.context.scope,'listings')",
   "captureFeatureMode(app.modeAuthority,args.context.scope,'merchant_assistant')"],
  [LISTING_SETUP,"const checked=normalizeListingRequest({version:1,action:'import',operationId:source.requestId,json_url:input.json_url,xml_url:input.xml_url});",
   "const checked=normalizeListingRequest({version:1,action:'import',operationId:source.requestId,json_url:input.xml_url,xml_url:input.json_url});"],
  [LISTING_OPTIMIZE_SETUP,"imageUrl:product.imageUrl,imageUrlSha256,choiceSnapshotSha256:selected.snapshotSha256",
   "imageUrl:'other',imageUrlSha256,choiceSnapshotSha256:selected.snapshotSha256"],
  [LISTINGS_APP,"catalog.getOwnedMerchantProduct({...context,expectedScene:context.target,productId:selected.sourceId})",
   "catalog.getOwnedMerchantProduct({...context,expectedScene:context.target,productId:1})"],
  [LISTINGS_APP,"const value=await readChatSetup({scope,persona,personaSession,...source,signal});",
   "const value=await readChatSetup({scope,persona,personaSession,...source,signal:null});"],
  [COMPOSITION,"return runtime.readListingsSetup(input);","return null;"],
  [LISTINGS_PRODUCTION,"rewriteSaveRepository,catalog,readChatSetup});",
   "rewriteSaveRepository,catalog,readChatSetup:null});"],
 ];
 for(const [file,before,after] of changes){
  const source=fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.ok(source.includes(before),`${file}: exact mutation anchor`);
  const changed=source.replace(before,after);
  assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: mutation must parse before contract denial`);
  assert.throws(()=>checkListingsSetups(manifest(),{[file]:changed}),undefined,`${file}: ${before}`);
 }
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.listing_optimize_setup').runtimeEvidence={passed:true};
 assert.throws(()=>checkListingsSetups(claimed),'source-only setup has no native credit');
 const fabricated=manifest();fabricated.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.listing_import_setup').confirmation='physical Listings Run verified';
 assert.throws(()=>checkListingsSetups(fabricated),'full row metadata must reject invented confirmation');
});
test('merchant order batch rejects selected owner, cursor, filter, digest, SQL and saved-page drift',()=>{
 const changes=[
  [SOURCE,"const cursor=orderContinuation?priorOrdersPage.nextCursor:args.cursor;",
   "const cursor=orderContinuation?args.cursor:args.cursor;"],
  [SOURCE,"const name=orderContinuation?(priorOrdersPage.productName??null)",
   "const name=orderContinuation?null"],
  [SOURCE,"args.cursor!==priorOrdersPage.nextCursor",
   "args.cursor===priorOrdersPage.nextCursor"],
  [SOURCE,"orderId:selected.sourceId}));","orderId:1}));"],
  [SOURCE,"digest(row)!==selected.snapshotSha256","digest(row)===selected.snapshotSha256"],
  [SOURCE,"||value.nextCursor!==page.nextCursor)return null;",
   "||value.nextCursor===page.nextCursor)return null;"],
  [COMPOSITION,"repository: commerceRepository, catalog, personaRepository",
   "repository: {}, catalog, personaRepository"],
  [COMMERCE,"repository.listMerchantOrders(target, request.persona.id, request.cursor",
   "repository.listMerchantOrders(target, 1, request.cursor"],
  [COMMERCE,"{ merchantId: request.persona.id, orderId: request.orderId }",
   "{ merchantId: 1, orderId: request.orderId }"],
  [COMMERCE_REPOSITORY,"p.retailer_id=$2 AND ($3::bigint IS NULL",
   "p.retailer_id=$3 AND ($3::bigint IS NULL"],
  [COMMERCE_REPOSITORY,"[value.targetId, merchant, orderId, beforeDate, beforeId,",
   "[value.targetId, 1, orderId, beforeDate, beforeId,"],
  [COMMERCE_REPOSITORY,"const visible = rows.slice(0,5);",
   "const visible = rows.slice(0,50);"],
 ];
 for(const [file,before,after] of changes){
  const source=fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.ok(source.includes(before),`${file}: exact mutation anchor`);
  const changed=source.replace(before,after);
  assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: mutation must parse before contract denial`);
  assert.throws(()=>checkMerchantOrders(manifest(),{[file]:changed}),undefined,`${file}: ${before}`);
 }
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.orders_detail').runtimeEvidence={passed:true};
 assert.throws(()=>checkMerchantOrders(claimed),'source-only order read has no native credit');
 const fabricated=manifest();fabricated.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.orders_list').confirmation='physical pagination verified';
 assert.throws(()=>checkMerchantOrders(fabricated),'full row metadata rejects invented confirmation');
});
test('merchant reporting batch detects source drift in window, owner, exclusions, projection and selected return',()=>{
 const changes=[
  [SOURCE,"commerce.merchantOverview({scope:a.b,persona,personaSession:session,days:30})",
   "commerce.merchantOverview({scope:a.b,persona,personaSession:session,days:31})"],
  [SOURCE,"commerce.merchantTopProducts({scope:a.b,persona,personaSession:session,days:30,limit:8})",
   "commerce.merchantTopProducts({scope:a.b,persona,personaSession:session,days:30,limit:9})"],
  [COMPOSITION,"repository: commerceRepository, catalog, personaRepository",
   "repository: {}, catalog, personaRepository"],
  [COMMERCE,"repository.merchantOverview(target, request.persona.id, window)",
   "repository.merchantOverview(target, 1, window)"],
  [COMMERCE,"repository.merchantOverview(target, request.persona.id, window, limit)",
   "repository.merchantOverview(target, 1, window, limit)"],
  [COMMERCE,"return projectMerchantMetrics(data, window, merchantId);",
   "return projectMerchantMetrics({}, window, merchantId);"],
  [COMMERCE,"return { rows, periodDays: window.days, source: 'owned-commerce' };",
   "return { rows:[], periodDays: window.days, source: 'owned-commerce' };"],
  [COMMERCE_REPOSITORY,"p.retailer_id=$2 AND o.order_date >= $4::timestamptz",
   "p.retailer_id=$3 AND o.order_date >= $4::timestamptz"],
  [COMMERCE_REPOSITORY,"o.payment_status NOT IN ('declined','refunded')",
   "o.payment_status NOT IN ('declined')"],
  [COMMERCE_REPOSITORY,"[value.targetId, merchant, window.cutoff, window.previousCutoff, window.until, topLimit]",
   "[value.targetId, 1, window.cutoff, window.previousCutoff, window.until, topLimit]"],
  [MERCHANT_METRICS,"windowEndExclusive: window.until, modelUsed: false",
   "windowEndExclusive: window.until, modelUsed: true"],
  [MERCHANT_METRICS,"const revenue = amount(data.current.revenue), orders = count(data.current.orders);",
   "const revenue = amount(0), orders = count(data.current.orders);"],
 ];
 for(const [file,before,after] of changes){
  const source=fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.ok(source.includes(before),`${file}: exact source-drift anchor`);
  const changed=source.replace(before,after);
  assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: changed source parses`);
  assert.throws(()=>checkMerchantReporting(manifest(),{[file]:changed}),undefined,`${file}: pinned-source drift`);
 }
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.overview').runtimeEvidence={passed:true};
 assert.throws(()=>checkMerchantReporting(claimed),'report source review cannot claim native evidence');
 const fabricated=manifest();fabricated.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.top_products').judgeApplicability='qualified';
 assert.throws(()=>checkMerchantReporting(fabricated),'full row metadata rejects invented Judge result');
});
test('merchant review reads detect source drift in choice, page, ownership, body boundary and saved mode',()=>{
 const changes=[
  [SOURCE,"const page=args.page??1,status=args.status??'pending';",
   "const page=args.page??2,status=args.status??'pending';"],
  [SOURCE,"args.choiceId.toLowerCase()!==productChoice.choiceId",
   "args.choiceId.toLowerCase()===productChoice.choiceId"],
  [SOURCE,"productId:productChoice.sourceId}:{})",
   "productId:1}:{})"],
  [SOURCE,"args.choiceId?.toLowerCase()!==selected.choiceId)throw fail('INVALID_TOOL_ARGUMENTS');\n       const value=await readInScene(selectedReview)",
   "args.choiceId?.toLowerCase()===selected.choiceId)throw fail('INVALID_TOOL_ARGUMENTS');\n       const value=await readInScene(selectedReview)"],
  [SOURCE,"reviewId:selected.sourceId});","reviewId:1});"],
  [SOURCE,"digest(reviewSnapshot(value))!==selected.snapshotSha256",
   "digest(reviewSnapshot(value))===selected.snapshotSha256"],
  [SOURCE,"body:oversized?null:value.row.body",
   "body:oversized?'exposed':value.row.body"],
  [SOURCE,"!isDeepStrictEqual(meta.reviewModeCapability,projectFeatureMode(reviewMode))",
   "isDeepStrictEqual(meta.reviewModeCapability,projectFeatureMode(reviewMode))"],
  [COMPOSITION,"createRoleReviewService({repository:reviews,application:runtime.application,authority:personaAuthority,modeAuthority,scenes})",
   "createRoleReviewService({repository:{},application:runtime.application,authority:personaAuthority,modeAuthority,scenes})"],
  [ROLE_REVIEW,"productId:input.productId,limit:5,offset:(input.page-1)*5",
   "productId:input.productId,limit:50,offset:(input.page-1)*5"],
  [ROLE_REVIEW,"repository.getReview(c.target,input.reviewId,{moderation:c.cap})",
   "repository.getReview(c.target,1,{moderation:c.cap})"],
  [REVIEW_REPOSITORY,"${seller ? 'AND ' + owned('reviews', 8, 9) : ''}",
   "${seller ? '' : ''}"],
  [REVIEW_REPOSITORY,"WHERE target_id=$1 AND id=$2",
   "WHERE target_id=$1 AND id=$3"],
 ];
 for(const [file,before,after] of changes){
  const source=fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.ok(source.includes(before),`${file}: exact source-drift anchor`);
  const changed=source.replace(before,after);
  assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: changed source parses`);
  assert.throws(()=>checkMerchantReviewReads(manifest(),{[file]:changed}),undefined,`${file}: pinned-source drift`);
 }
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.reviews_detail').runtimeEvidence={passed:true};
 assert.throws(()=>checkMerchantReviewReads(claimed),'review read source contract has no native credit');
 const fabricated=manifest();fabricated.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.reviews_list').confirmation='physical product choice verified';
 assert.throws(()=>checkMerchantReviewReads(fabricated),'full row metadata rejects invented confirmation');
});
test('merchant catalog and manual reads reject parse-valid selected-source and invented-evidence drift',()=>{
 const changes=[
  [SOURCE,"query:message,\n        signal,beforeEffect","query:'other',\n        signal,beforeEffect"],
  [SOURCE,"found.products.length>5","found.products.length>50"],
  [SOURCE,"digest(projected)!==selected.snapshotSha256","digest(projected)===selected.snapshotSha256"],
  [SOURCE,"afterProductId:catalogSource.nextCursor","afterProductId:1"],
  [SOURCE,"hop?.tool!=='merchant.catalog_search'","hop?.tool==='merchant.catalog_search'"],
  [SOURCE,"!isDeepStrictEqual(checked,manualSearch.result)","isDeepStrictEqual(checked,manualSearch.result)"],
  [CATALOG,"retailerId:actor.id,\n        search:query.search","retailerId:1,\n        search:query.search"],
  [PRODUCT_REPOSITORY,"target_id=$1 AND retailer_id=$2","target_id=$1 AND retailer_id=$3"],
  [PRODUCT_RETRIEVAL,"await ensureCorpus(scope, signal, binding, products, personaEffect, guard);","await guard();"],
  [PRODUCT_RETRIEVAL,"result.status = 'oversized';","result.status = 'complete';"],
  [EMBEDDING_REPOSITORY,"p.retailer_id=$3","p.retailer_id=$2"],
 ];
 for(const [file,before,after] of changes){
  const source=fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.ok(source.includes(before),`${file}: exact source-drift anchor`);
  const changed=source.replace(before,after);
  assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: changed source parses`);
  assert.throws(()=>checkMerchantProductReads(manifest(),{[file]:changed}),undefined,`${file}: pinned-source drift`);
 }
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.manual_search').runtimeEvidence={passed:true};
 assert.throws(()=>checkMerchantProductReads(claimed),'manual source review cannot claim native passage or effect');
 const fabricated=manifest();fabricated.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='merchant.catalog_search').judgeApplicability='qualified';
 assert.throws(()=>checkMerchantProductReads(fabricated),'full row metadata rejects invented Judge result');
});
test('admin selected-user search and proposals reject parse-valid authority, choice, channel and saved-read drift',()=>{
 const changes=[
  [SOURCE,"page:1,pageSize:5,search:args.search","page:1,pageSize:50,search:args.search"],
  [SOURCE,"targetId:selected.sourceId}));\n        if(!exact(value,['user','administration'])","targetId:1}));\n        if(!exact(value,['user','administration'])"],
  [SOURCE,"args.choiceId?.toLowerCase()!==selected.choiceId\n     ||(action==='set_role'","args.choiceId?.toLowerCase()===selected.choiceId\n     ||(action==='set_role'"],
  [SOURCE,"role:action==='set_role'?selection.newRole:null","role:action==='set_role'?'customer':null"],
  [SOURCE,"reason:action==='ban'?userReason:null","reason:action==='ban'?'other':null"],
  [SOURCE,"selected.sourceId===persona.id||passwordResetSetup","false||passwordResetSetup"],
  [SOURCE,"userAdministration.passwordResetReadiness({scope:a.b,persona,personaSession:session,targetId:selected.sourceId})","userAdministration.passwordResetReadiness({scope:a.b,persona,personaSession:session,targetId:1})"],
  [SOURCE,"value.user.identity_kind==='registered_account'?'protected_account':'bound_persona'","value.user.identity_kind==='registered_account'?'bound_persona':'protected_account'"],
  [SOURCE,"const passwordResetSetup=role==='admin'&&meta.passwordResetSetup!=null","const passwordResetSetup=role==='merchant'&&meta.passwordResetSetup!=null"],
  [COMPOSITION,"personaAuthority && administrationRepository && admin","personaAuthority && administrationRepository && false"],
  [USER_ADMIN,"const user=await directory.user(input);","const user=await directory.user({...input,targetId:1});"],
  [ROLE_USER_PROPOSAL,"function create({sessionId,requestId,step,callId,selected,user,administration,action,role,reason,modeCapability})","function create({sessionId,requestId,step,callId,selected,user,administration,action,role,reason,modeCapability,ignored})"],
 ];
 for(const [file,before,after] of changes){
  const source=fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.ok(source.includes(before),`${file}: exact source-drift anchor`);
  const changed=source.replace(before,after);
  assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: changed source parses`);
  assert.throws(()=>checkAdminUserReadsAndPreparations(manifest(),{[file]:changed}),undefined,`${file}: pinned-source drift`);
 }
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.password_reset_setup').runtimeEvidence={passed:true};
 assert.throws(()=>checkAdminUserReadsAndPreparations(claimed),'reset setup cannot claim a native reset');
 const fabricated=manifest();fabricated.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.ban_prepare').confirmation='ban applied';
 assert.throws(()=>checkAdminUserReadsAndPreparations(fabricated),'full row metadata rejects an applied ban claim');
});
test('admin ACL discovery and proposals reject parse-valid choice, policy and readback drift',()=>{
 const changes=[
  [SOURCE,"filtered.slice((page-1)*5,page*5)","filtered.slice((page-1)*50,page*50)"],
  [SOURCE,"candidate:{allowed:aclIntent==='acl_allow'}","candidate:{allowed:aclIntent!=='acl_allow'}"],
  [SOURCE,"candidate:{enabled:args.enabled}","candidate:{enabled:!args.enabled}"],
  [SOURCE,"hop?.tool!=='admin.acl_list'","hop?.tool==='admin.acl_list'"],
  [SOURCE,"selected.snapshotSha256!==aclProposal.sourceSnapshotSha256","selected.snapshotSha256===aclProposal.sourceSnapshotSha256"],
  [ACL_CHAT,"if (!row.supported || row.readOnly) continue;","if (false) continue;"],
  [ACL_CHAT,"if (current.allowed === candidate.allowed) throw fail('ACL_NO_CHANGE');","if (current.allowed !== candidate.allowed) throw fail('ACL_NO_CHANGE');"],
  [ACL_CHAT,"if (state.enforcement === candidate.enabled) throw fail('ACL_NO_CHANGE');","if (state.enforcement !== candidate.enabled) throw fail('ACL_NO_CHANGE');"],
  [ACL_CHAT,"const value = await accessControl.read(context);","const value = await accessControl.read({});"],
  [COMPOSITION,"const aclChat = accessControl ? require('./secureshopBoundAclChat')","const aclChat = false ? require('./secureshopBoundAclChat')"],
  [ACL_PROPOSAL,"function create({ source, origin, action, selected, before, after, expectedVersion,","function create({ source, origin, action, selected, before, after, expectedVersion, ignored,"],
  [ACCESS_CONTROL,"async read(raw) {","async read(raw) { const ignored = true;"],
 ];
 for(const [file,before,after] of changes){
  const source=fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.ok(source.includes(before),`${file}: exact source-drift anchor`);
  const changed=source.replace(before,after);
  assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: changed source parses`);
  assert.throws(()=>checkAdminAclDiscoveryAndPreparations(manifest(),{[file]:changed}),undefined,`${file}: pinned-source drift`);
 }
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.acl_enforcement_prepare').runtimeEvidence={passed:true};
 assert.throws(()=>checkAdminAclDiscoveryAndPreparations(claimed),'source-only ACL preparation cannot claim native effect');
 const fabricated=manifest();fabricated.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.acl_permission_prepare').confirmation='enforced physically';
 assert.throws(()=>checkAdminAclDiscoveryAndPreparations(fabricated),'full row metadata rejects invented confirmation');
});
test('admin System health and diagnostic/restart preparations reject parse-valid source and evidence drift',()=>{
 const changes=[
  [SOURCE,"systemReads.health({context:{scope:a.b,persona,personaSession:session}","systemReads.configRead({context:{scope:a.b,persona,personaSession:session}"],
  [SOURCE,"args.cmd_template!==explicitDiagnostic.cmd_template","args.cmd_template===explicitDiagnostic.cmd_template"],
  [SOURCE,"||!message.includes(args.name))throw fail('INVALID_TOOL_ARGUMENTS')","||message.includes(args.name))throw fail('INVALID_TOOL_ARGUMENTS')"],
  [SOURCE,"cmd_template:args.cmd_template,args:args.args,signal","cmd_template:'other',args:args.args,signal"],
  [SOURCE,"name:args.name,modeCapability:projectFeatureMode(a.mode),signal","name:'other',modeCapability:projectFeatureMode(a.mode),signal"],
  [SOURCE,"matchesSavedRead('admin.system_restart_prepare'","matchesSavedRead('admin.system_health'"],
  [SOURCE,"validateOwnedSystemMetrics(systemHealth.metrics)","validateOwnedSystemMetrics({})"],
  [SOURCE,"systemDiagnosticApplication()?.ready===true","systemDiagnosticApplication()?.ready===false"],
  [SYSTEM_READS,"system.healthService.health(x, { signal })","system.healthService.health({}, { signal })"],
  [SYSTEM_HEALTH,"metrics.snapshot({ signal })","metrics.snapshot({})"],
  [SYSTEM_RESTART_CHAT,"C.createRoleSystemRestartProposal({ context, administration,","C.createRoleSystemRestartProposal({ context:{}, administration,"],
  [SYSTEM_DIAGNOSTIC_CHAT,"cmd_template, args });","cmd_template:'other', args });"],
  [SYSTEM_COMPOSITION,"const healthService = createHealthService({ repository, metrics:","const healthService = createHealthService({ repository:{}, metrics:"],
 ];
 for(const [file,before,after] of changes){
  const source=fs.readFileSync(path.join(ROOT,file),'utf8');
  assert.ok(source.includes(before),`${file}: exact source-drift anchor`);
  const changed=source.replace(before,after);
  assert.doesNotThrow(()=>parse(file,{[file]:changed}),`${file}: changed source parses`);
  assert.throws(()=>checkAdminSystemReadAndPreparations(manifest(),{[file]:changed}),undefined,`${file}: pinned-source drift`);
 }
 const claimed=manifest();claimed.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.system_diagnostic_prepare').runtimeEvidence={passed:true};
 assert.throws(()=>checkAdminSystemReadAndPreparations(claimed),'diagnostic source proposal cannot claim native execution');
 const fabricated=manifest();fabricated.roleChatDescriptorPartition.reviewedDescriptors.find(row=>row.descriptorId==='admin.system_restart_prepare').confirmation='restart executed';
 assert.throws(()=>checkAdminSystemReadAndPreparations(fabricated),'full row metadata rejects invented restart effect');
});
