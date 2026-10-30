'use strict';
const {AsyncLocalStorage}=require('node:async_hooks');
const {createPool,withTransaction}=require('./index');
const {initialize,singleton}=require('./workshopSupport');
async function seed(client){
 // An imported empty table is intentional historical state, not a request for demo seeds.
 if((await client.query('SELECT 1 FROM legacy_challenge.import_batches LIMIT 1')).rowCount)return;
 const {products,comments}=require('../../data/legacyChallengeSeeds');
 const bcrypt=require('bcryptjs');
 if(!(await client.query('SELECT 1 FROM legacy_challenge.users LIMIT 1')).rowCount){
  for(const [username,email,password] of [['student','student@owasp-ai-goat.local','student123'],['student123','student123@owasp-ai-goat.local','student123'],['user','user@owasp-ai-goat.local','password'],['Test User','test@owasp-ai-goat.local','test123']])
   await client.query('INSERT INTO legacy_challenge.users(username,email,password,role) VALUES($1,$2,$3,\'student\')',[username,email,await bcrypt.hash(password,10)]);
 }
 if(!(await client.query('SELECT 1 FROM legacy_challenge.products LIMIT 1')).rowCount)
  for(const row of products)await client.query('INSERT INTO legacy_challenge.products(name,description,price,category,image_url) VALUES($1,$2,$3,$4,$5)',row);
 if(!(await client.query('SELECT 1 FROM legacy_challenge.comments LIMIT 1')).rowCount)
  for(const row of comments)await client.query('INSERT INTO legacy_challenge.comments(user_id,content) VALUES($1,$2)',row);
 // Fresh installations use explicit availability rows; imported archives above
 // remain authoritative, including an intentionally empty settings table.
 await require('../../data/legacyVulnerabilitySettings').seedLegacyVulnerabilitySettings(client);
}
function createLegacyChallengeDb(pool){
 const platformMutation=new AsyncLocalStorage();
 const run=async(sql,params=[])=>{const authority=platformMutation.getStore();if(authority){if(!authority.active)throw Object.assign(new Error('Legacy platform mutation authority expired'),{code:'LEGACY_MUTATION_EXPIRED'});return authority.client.query({text:sql,values:params,queryMode:'extended'});}return withTransaction(pool,async client=>{
  await client.query('SET LOCAL search_path TO legacy_challenge,pg_catalog');
  return client.query({text:sql,values:params,queryMode:'extended'});
 });};
 const rows=async(sql,params)=>(await run(sql,params)).rows;
 const mutation=async(sql,params)=>{const r=await run(sql,params);return{lastID:r.rows[0]?.id,changes:r.rowCount};};
 return {
  engine:'postgres',
  async initializeLegacyChallengeDb(migrationPool){const owned=!migrationPool;migrationPool ||= createPool(process.env,'LEGACY_CHALLENGE_MIGRATION_DATABASE_URL');try{await initialize(pool,migrationPool,'legacy_challenge',seed);
    const expectedDatabase=(await migrationPool.query('SELECT current_database() AS database')).rows[0].database;
    await require('../../services/legacyAiTeachingHistoryReadiness').assertLegacyAiTeachingHistoryReadiness({pool,expectedDatabase});
   }finally{if(owned)await migrationPool.end();}},
  getVulnerabilitySetting:async key=>(await rows('SELECT enabled FROM vulnerability_settings WHERE vulnerability_key=$1',[key]))[0],
  listVulnerabilitySettings:()=>rows('SELECT * FROM vulnerability_settings'),
  saveConversation:values=>values.length===5
    ? mutation(`INSERT INTO ai_conversations(user_id,prompt,response,model_used,platform_owner_id) VALUES($1,$2,$3,$4,$5) RETURNING id`,values)
    : mutation('INSERT INTO ai_conversations(user_id,prompt,response,model_used) VALUES($1,$2,$3,$4) RETURNING id',values),
  // Raw SQL is the deliberate challenge input. No dialect rewriting or platform connection is used.
  readConversations:sql=>rows(sql),
  searchProducts:sql=>rows(sql),
  searchCommerceProducts:(sql,params)=>rows(sql,params),
  readDemoUser:async sql=>(await rows(sql))[0],
  readProduct:async sql=>(await rows(sql))[0],
  readReviews:sql=>rows(sql),
  addComment:values=>values.length===3
    ? mutation('INSERT INTO comments(user_id,content,platform_owner_id) VALUES($1,$2,$3) RETURNING id',values)
    : mutation('INSERT INTO comments(user_id,content) VALUES($1,$2) RETURNING id',values),
  listComments:()=>rows('SELECT c.id,c.content,c.created_at,u.username FROM comments c JOIN users u ON c.user_id=u.id ORDER BY c.created_at DESC'),
  addFile:values=>mutation('INSERT INTO files(filename,original_name,file_path,file_size,mime_type,uploaded_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',values),
  addManagedFile:values=>mutation('INSERT INTO files(filename,original_name,file_path,file_size,mime_type,uploaded_by,platform_owner_id,upload_intent_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id',values),
  addReview:sql=>mutation(sql+' RETURNING id'),
  readCart:sql=>rows(sql),
  countCart:async uid=>({count:Number((await rows('SELECT SUM(quantity) AS count FROM cart WHERE user_id=$1',[uid]))[0]?.count)||0}),
  addCart:sql=>mutation(sql),
  createOrder:sql=>mutation(sql+' RETURNING id'),
  moveOrderItems:sql=>mutation(sql),
  clearCart:sql=>mutation(sql),
  readOrders:sql=>rows(sql),
  updateDemoProfile:sql=>mutation(sql),
  executeAiSql:sql=>rows(sql),
  executeNoSqlSimulation:sql=>rows(sql),
  async withPlatformMutationAuthority({identityPool,ownerId,sessionId},work){
   const owner=Number(ownerId),session=Number(sessionId);if(!Number.isSafeInteger(owner)||owner<1||!Number.isSafeInteger(session)||session<1||typeof identityPool?.connect!=='function'||typeof work!=='function')throw new TypeError('Complete legacy platform mutation authority required');
   const legacyClient=await pool.connect();let identityClient,legacyTx=false,identityTx=false;
   const authority={client:legacyClient,active:true,error:null},lost=error=>{authority.active=false;authority.error ||= error||new Error('Legacy mutation authority connection lost');};legacyClient.on?.('error',lost);
   try{await legacyClient.query('BEGIN');legacyTx=true;await legacyClient.query('SET LOCAL search_path TO legacy_challenge,pg_catalog');await legacyClient.query('SELECT pg_advisory_xact_lock($1,$2)',[741902,0]);identityClient=await identityPool.connect();identityClient.on?.('error',lost);await identityClient.query('BEGIN');identityTx=true;await identityClient.query('SELECT identity.assert_legacy_platform_mutation($1,$2)',[owner,session]);const value=await platformMutation.run(authority,work);if(authority.error)throw authority.error;authority.active=false;await legacyClient.query('COMMIT');legacyTx=false;await identityClient.query('COMMIT');identityTx=false;return value;}
   catch(error){if(legacyTx)await legacyClient.query('ROLLBACK').catch(()=>{});if(identityTx)await identityClient?.query('ROLLBACK').catch(()=>{});throw error;}
   finally{authority.active=false;legacyClient.off?.('error',lost);identityClient?.off?.('error',lost);identityClient?.release(authority.error||undefined);legacyClient.release(authority.error||undefined);}
  },
  async destroyOwner(userId,{removeFile,orphanPaths=[],protectedPaths=[],intentIds=[]}={}){
   const id=Number(userId);
   if(!Number.isSafeInteger(id)||id<1||id>2147483647||typeof removeFile!=='function'||!Array.isArray(orphanPaths)
     ||!Array.isArray(intentIds)||orphanPaths.length>1000||protectedPaths.length>1000||intentIds.length>1000
     ||[...orphanPaths,...protectedPaths].some(value=>typeof value!=='string'||!value.length||value.length>4096)
     ||intentIds.some(value=>typeof value!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)))throw new TypeError('Deletion owner and file cleanup required');
   return withTransaction(pool,async client=>{
    await client.query('SET LOCAL search_path TO legacy_challenge,pg_catalog');
    await client.query('SELECT pg_advisory_xact_lock($1,$2)',[741902,0]);
    // The table lock keeps another database writer from gaining a reference to
    // an owned pathname while the corresponding bytes are being removed.
    await client.query('LOCK TABLE legacy_challenge.files IN SHARE ROW EXCLUSIVE MODE');
    const paths=(await client.query(`WITH candidates(file_path) AS (
        SELECT file_path FROM legacy_challenge.files WHERE platform_owner_id=$1 AND upload_intent_id=ANY($4::uuid[])
        UNION SELECT unnest($2::text[])
      ) SELECT DISTINCT candidate.file_path FROM candidates candidate
      WHERE NOT candidate.file_path=ANY($3::text[]) AND NOT EXISTS(SELECT 1 FROM legacy_challenge.files sibling
        WHERE sibling.file_path=candidate.file_path
          AND NOT (sibling.platform_owner_id=$1 AND sibling.upload_intent_id=ANY($4::uuid[])))
      ORDER BY candidate.file_path`,[id,orphanPaths,protectedPaths,intentIds])).rows.map(row=>row.file_path);
    let filesRemoved=0;
    for(const filePath of paths)if(await removeFile(filePath))filesRemoved+=1;
    const result=await client.query('SELECT legacy_challenge.destroy_student_owner($1,$2::uuid[])::integer AS removed',[id,intentIds]);
    return{removed:result.rows[0].removed,filesRemoved};
   });
  }
 };
}
const lazy=singleton(createLegacyChallengeDb,'LEGACY_CHALLENGE_DATABASE_URL');
const names=['initializeLegacyChallengeDb','getVulnerabilitySetting','listVulnerabilitySettings','saveConversation','readConversations','searchProducts','searchCommerceProducts','readDemoUser','readProduct','readReviews','addComment','listComments','addFile','addManagedFile','addReview','readCart','countCart','addCart','createOrder','moveOrderItems','clearCart','readOrders','updateDemoProfile','executeAiSql','executeNoSqlSimulation','withPlatformMutationAuthority','destroyOwner'];
module.exports={engine:'postgres',createLegacyChallengeDb,...Object.fromEntries(names.map(name=>[name,lazy(name)]))};
