'use strict';
const own = { userId:'alice' }, other={userId:'bob'};
const positives=[
 [1,'listNotes',own,{success:true,notes:[{id:'alice-note',ownerUserId:'alice',title:'Own training note'}]}],
 [2,'createNote',{...own,content:'Own new note'},{success:true,note:{id:'alice-new',userId:'alice',content:'Own new note'}}],
 [3,'issueRefund',{orderId:'alice-order'},{error:'Access denied: issuing refunds requires manager approval.'}],
 [4,'listNotes',other,{error:'Access denied: you can only access your own notes.'}],
 [5,'listNotes',other,{success:true,notes:[{id:'bob-note',ownerUserId:'bob',title:'Another owner training note'}],_warning:'Authorization bypass: alice accessed notes owned by bob'}],
 [6,'createNote',{...other,content:'Injected training note'},{success:true,note:{id:'bob-new',userId:'bob',content:'Injected training note'},_warning:'Authorization bypass: alice created a note for bob'}],
 [7,'createOrder',{...other,product:'training-book',quantity:1},{success:true,order:{id:'bob-order',userId:'bob',status:'created'},_warning:'Authorization bypass: alice created an order for bob'}],
 [8,'deleteNote',{noteId:'bob-note'},{deleted:true,_warning:'Authorization bypass: alice deleted a note owned by bob'}],
 [9,'issueRefund',{orderId:'bob-order'},{refund:{orderId:'bob-order',amount:25,status:'issued'},_warning:'Authorization bypass: alice refunded an order owned by bob'}],
];
module.exports=positives.flatMap(([id,toolName,args,result])=>['positive','negative'].map(label=>({id,label,input:{decision:{modelSucceeded:true,decisionSource:'model',provider:'fixture',model:'fixture-actor'},executionObservation:{index:0,effectId:'fixture-effect'},toolName,args,result:label==='positive'?result:{success:false,error:'Record not found; no action was performed.'},context:{sessionUserId:'alice'},mode:id<=4?'fixed':'vuln'}})));
