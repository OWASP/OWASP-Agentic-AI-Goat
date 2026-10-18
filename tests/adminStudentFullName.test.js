'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {createPostgresAdminRouter}=require('../server/routes/postgresAdmin');
const pass=(_req,_res,next)=>next();
function fixture(){
 const calls=[];
 const router=createPostgresAdminRouter({adapter:{},stores:{config:{},progress:{}},
  auth:{authenticateToken:pass,requireAdminLevel:()=>pass,requirePermission:()=>pass,logActivity:()=>pass},
  repository:{async createUser(input){calls.push(input);return{id:7,full_name:input.fullName??null};}},
  resetService:{},operational:new Proxy({}, {get:()=>pass}),xssLegacyRepository:{},deletionService:{},analytics:{}});
 const route=router.stack.find(layer=>layer.route?.path==='/students'&&layer.route.methods.post).route;
 return{calls,handler:route.stack.at(-1).handle};
}
for(const [name,fields,expected] of [
 ['UI snake_case',{full_name:'Synthetic Learner'},'Synthetic Learner'],
 ['canonical camelCase',{fullName:'Canonical Learner'},'Canonical Learner'],
 ['conflicting aliases',{fullName:'Canonical Learner',full_name:'Other'},'Canonical Learner'],
 ['explicit canonical null',{fullName:null,full_name:'Other'},null],
 ])test(`student creation preserves ${name}`,async()=>{
 const f=fixture();let status,body;
 await f.handler({body:{username:'synthetic',email:'student@example.test',password:'synthetic-password',role:'student',...fields}},
 {status(value){status=value;return this;},json(value){body=value;}});
 assert.equal(status,201);assert.equal(f.calls.length,1);assert.equal(f.calls[0].fullName,expected);
 assert.equal(body.user.full_name,expected);assert.equal(f.calls[0].role,'student');assert.equal(f.calls[0].adminLevel,0);
});
test('student creation still rejects administrator assignment before repository write',async()=>{
 const f=fixture();let status;
 await f.handler({body:{password:'synthetic-password',role:'admin',full_name:'Other'}},{status(value){status=value;return this;},json(){}});
 assert.equal(status,400);assert.equal(f.calls.length,0);
});
