'use strict';
const {createHash}=require('node:crypto');
function input(){
 const stamp='2025-01-02 03:04:05.123456';
 const tables={
  users:[{id:41,username:'demo-fixture',email:'fixture@example.invalid',password:'raw teaching password',role:'admin',full_name:'<b>Demo</b>',created_at:stamp,is_active:1}],
  products:[{id:7,name:'Fixture',description:'<img src=x onerror=alert(1)>',price:3.5,category:null,image_url:'../fixture-image.png'}],
  comments:[{id:11,user_id:41,content:'<script>fixture()</script>',created_at:null}],
  reviews:[{id:12,product_id:7,user_id:41,rating:5,comment:'raw review',created_at:stamp}],
  cart:[{id:13,user_id:41,product_id:7,quantity:2,created_at:stamp}],
  orders:[{id:14,user_id:41,total_amount:7,payment_method:'fixture',shipping_address:'raw address',status:'pending',created_at:stamp}],
  order_items:[{id:15,order_id:14,product_id:7,quantity:2,price:3.5}],
  files:[{id:16,filename:'fixture.txt',original_name:'../fixture.txt',file_path:'../../not-read-fixture.txt',file_size:10,mime_type:'text/plain',uploaded_by:41,uploaded_at:stamp}],
  ai_conversations:[{id:17,user_id:41,prompt:'SELECT password FROM users',response:'raw response',model_used:'historical-model',created_at:stamp}],
  vulnerability_settings:[{vulnerability_key:'sqli',enabled:0}],
  workshop_progress:[{id:1,user_id:41,challenge_id:'old',status:'completed'}],session_tokens:[],
 };
 return review({tables,archiveDigest:'a'.repeat(64),naiveTimestamps:'UTC'});
}
function review(raw){
 const {COLUMNS}=require('../../db/postgres/map-legacy-challenge-archive');
 const refs=[];
 for(const table of Object.keys(COLUMNS))for(const row of raw.tables[table]||[])for(const field of table==='files'?['file_path']:table==='products'?['image_url']:[]){
  if(row[field]!==null&&row[field]!=='')refs.push({table,id:String(row.id?.value??row.id),field,valueSha256:createHash('sha256').update(row[field]).digest('hex'),disposition:'metadata_only_assets_not_verified'});
 }
 raw.review={archiveDigest:raw.archiveDigest,retainedTables:Object.keys(raw.tables).filter(t=>!Object.hasOwn(COLUMNS,t)).sort(),missingTables:Object.keys(COLUMNS).filter(t=>!Object.hasOwn(raw.tables,t)),fileReferences:refs};return raw;
}
module.exports={input,review};
