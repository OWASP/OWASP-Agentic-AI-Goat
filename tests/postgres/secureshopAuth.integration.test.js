'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const path=require('node:path');
const express=require('express');
const {createPool}=require('../../server/database/postgres');
const {migrate}=require('../../db/postgres/migrate');
const {createSecureShopAccountRepository}=require('../../server/database/postgres/secureshopAccountRepository');
const buildAuthRouter=require('../../server/routes/secureshop/postgres/auth');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_SECURESHOP_TEST_RUNTIME_URL;
test('native SecureShop account routes preserve contracts and atomic owner address changes',{skip:!enabled},async()=>{
  for(const key of ['PG_SECURESHOP_TEST_RUNTIME_URL','PG_SECURESHOP_TEST_MIGRATION_URL'])assert.match(new URL(process.env[key]).pathname,/^\/owasp_ai_goat_test_/);
  const pool=createPool(process.env,'PG_SECURESHOP_TEST_RUNTIME_URL');
  const migration=createPool(process.env,'PG_SECURESHOP_TEST_MIGRATION_URL');
  const previousSecret=process.env.JWT_SECRET;process.env.JWT_SECRET='disposable-secureshop-http-test-secret';
  let server;
  try{
    await migrate(migration,path.join(__dirname,'../../db/postgres/workshop-migrations/secureshop'));
    const repository=createSecureShopAccountRepository(pool);
    const app=express();app.use(express.json());app.use('/auth',buildAuthRouter({repository}));
    server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
    const base=`http://127.0.0.1:${server.address().port}/auth`;
    const request=async(url,method='GET',body,token)=>{
      const response=await fetch(base+url,{method,headers:{'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{})},...(body?{body:JSON.stringify(body)}:{})});
      return{status:response.status,body:await response.json()};
    };
    const a=await request('/register','POST',{username:'native_http_a',email:'native_http_a@example.test',password:'fixture-password'});
    const b=await request('/register','POST',{username:'native_http_b',email:'native_http_b@example.test',password:'fixture-password'});
    assert.equal(a.status,200);assert.equal(b.status,200);assert.equal(typeof a.body.user.id,'number');
    assert.equal((await request('/register','POST',{username:'native_http_a',email:'other@example.test',password:'fixture-password'})).status,409);
    assert.equal((await request('/login','POST',{username:'native_http_a',password:'wrong'})).status,401);
    const login=await request('/login','POST',{username:'native_http_a',password:'fixture-password'});
    assert.equal(login.status,200);const token=login.body.token;
    assert.equal((await request('/whoami','GET',undefined,token)).body.user.username,'native_http_a');
    assert.equal((await request('/users/me/sessions','GET',undefined,token)).body.sessions.length,1);
    const address=await request('/users/me/addresses','POST',{line1:'Original',is_default:true},token);
    assert.equal(address.status,200);
    const denied=await request(`/users/me/addresses/${address.body.id}`,'PUT',{line1:'Other owner',is_default:true},b.body.token);
    assert.equal(denied.status,404);
    assert.equal((await repository.listAddresses(a.body.user.id))[0].line1,'Original');
    // Failing a replacement insert rolls back clearing the original default.
    await assert.rejects(repository.saveAddress(a.body.user.id,null,[null,null,null,null,null,null,null,1]),{code:'23502'});
    assert.equal((await repository.listAddresses(a.body.user.id))[0].is_default,1);
    await Promise.all([repository.saveAddress(a.body.user.id,null,[null,'Second',null,null,null,null,null,1]),repository.saveAddress(a.body.user.id,null,[null,'Third',null,null,null,null,null,1])]);
    assert.equal((await repository.listAddresses(a.body.user.id)).filter(row=>row.is_default).length,1);
    assert.equal((await request('/users/me','PUT',{email:'updated@example.test',full_name:'Updated'},token)).body.user.email,'updated@example.test');
    const changed=await request('/users/me/password','POST',{current_password:'fixture-password',new_password:'new-fixture-password'},token);
    assert.equal(changed.status,200);
    assert.equal((await request('/login','POST',{username:'native_http_a',password:'fixture-password'})).status,401);
    assert.equal((await request('/login','POST',{username:'native_http_a',password:'new-fixture-password'})).status,200);
    assert.match((await request('/users/me/api-keys/rotate','POST',{},token)).body.api_key,/^sk_ss_live_/);
    await assert.rejects(pool.query('CREATE TABLE secureshop.forbidden(id int)'),{code:'42501'});
  }finally{
    if(server)await new Promise(resolve=>server.close(resolve));
    if(previousSecret===undefined)delete process.env.JWT_SECRET;else process.env.JWT_SECRET=previousSecret;
    await Promise.allSettled([pool.end(),migration.end()]);
  }
});
