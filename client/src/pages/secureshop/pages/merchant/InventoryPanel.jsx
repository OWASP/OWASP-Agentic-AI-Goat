import React,{useEffect,useState} from 'react';
import {useBoundInventory} from './useBoundInventory';
import {isStandaloneShopFrame,openStandaloneAssessments} from '../../bridge/assessmentPanelIntent.mjs';
import BoundProductPicker from '../../components/BoundProductPicker';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export default function InventoryPanel({token,transport,onComplete}){
 const inventory=useBoundInventory(token,transport),[message,setMessage]=useState(''),[access,setAccess]=useState('read'),[selectedProduct,setSelectedProduct]=useState(null),[quantity,setQuantity]=useState('');
 const standalone=isStandaloneShopFrame();
 const savedEvaluationId=inventory.result?.status==='completed'
  &&inventory.result.grading?.judgment?.verdict==='unavailable'
  &&UUID.test(inventory.result.grading.judgment.evaluationId||'')
  ?inventory.result.grading.judgment.evaluationId:null;
 const assessmentEvaluationId=savedEvaluationId||(UUID.test(inventory.reference?.evaluationId||'')
  ?inventory.reference.evaluationId:null);
 useEffect(()=>{setMessage('');setAccess('read');setSelectedProduct(null);setQuantity('');},[token,transport]);
 if(!inventory.attached)return null;
 const act=async work=>{try{const value=await work();if(value.status==='completed')onComplete?.();}catch{/* Hook presents persistence/transport failure. */}};
 const admittedAccess=inventory.reference?.access||access;
 const exactNumber=(value,minimum)=>/^(0|[1-9][0-9]*)$/.test(value)&&Number.isSafeInteger(Number(value))&&Number(value)>=minimum&&Number(value)<=2147483647;
 const stockChange=admittedAccess==='write'?(inventory.reference?.version===3?inventory.reference.stockChange:
  exactNumber(String(selectedProduct?.id),1)&&exactNumber(quantity,0)?{productId:Number(selectedProduct.id),quantity:Number(quantity)}:null):null;
 const resendable=inventory.reference?.version===3&&inventory.result?.status==='not_found';
 return <section aria-label="inventory assistant" style={{border:'1px solid var(--rule)',padding:20,display:'flex',flexDirection:'column',gap:16,background:'color-mix(in srgb, var(--paper) 96%, var(--carbon))'}}>
  <div><div className="ss-card__meta">INVENTORY</div><h2 className="ss-display" style={{fontSize:22,margin:'4px 0'}}>Ask about stock</h2></div>
  <p style={{margin:0}}>Check stock, ask what to reorder, or select a catalog product for a stock change.</p>
  {!inventory.ready&&<p role="status">Inventory assistant unavailable.</p>}
  {admittedAccess==='write'&&<BoundProductPicker instance="inventory-stock" source="customer"
    initialProductId={inventory.reference?.version===3?inventory.reference.stockChange?.productId:null}
    selectedProduct={selectedProduct} onSelect={setSelectedProduct} authorityKey={token} transport={transport}
    disabled={inventory.busy||!!inventory.reference||!!inventory.foreignReference} />}
  <form onSubmit={e=>{e.preventDefault();void act(()=>inventory.run(message,admittedAccess,stockChange));}}>
   <label htmlFor="inventory-access">Inventory access</label>
   <select id="inventory-access" className="ss-input" value={inventory.reference?.access||access}
    disabled={inventory.busy||!!inventory.reference||!!inventory.foreignReference} onChange={e=>setAccess(e.target.value)} style={{width:'100%',margin:'8px 0 12px'}}>
    <option value="read">Read only</option><option value="write">Allow stock changes</option>
   </select>
   {admittedAccess==='write'&&<div style={{marginBottom:12}}>
    {inventory.reference?.version===3&&<p role="status">Saved stock target: Product #{inventory.reference.stockChange?.productId}</p>}
    <div><label htmlFor="inventory-quantity">Absolute stock quantity</label><input id="inventory-quantity" className="ss-input"
      type="text" inputMode="numeric" pattern="(0|[1-9][0-9]*)" value={inventory.reference?.version===3?String(inventory.reference.stockChange?.quantity??''):quantity}
      disabled={inventory.busy||!!inventory.reference||!!inventory.foreignReference} onChange={e=>setQuantity(e.target.value)} style={{width:'100%',marginTop:8}} /></div>
   </div>}
   <label htmlFor="inventory-message">Inventory request</label>
   <textarea id="inventory-message" className="ss-input" value={message} onChange={e=>setMessage(e.target.value)} rows={3} maxLength={8192} placeholder="Check my stock levels and suggest what to reorder." style={{width:'100%',marginTop:8}} />
   <div style={{display:'flex',gap:8,marginTop:12}}>
    <button className="ss-btn" type="submit" disabled={!inventory.ready||inventory.busy||!!inventory.foreignReference||!message.trim()||(admittedAccess==='write'&&!stockChange)||!!inventory.reference&&!resendable}>{inventory.busy?'Working…':inventory.reference?'Retry same request':'Run inventory'}</button>
    {inventory.reference&&<button className="ss-btn ss-btn--ghost" type="button" disabled={!inventory.ready||inventory.busy} onClick={()=>void act(inventory.recover)}>Check saved request</button>}
   </div>
  </form>
  {inventory.error&&<p role="alert">{inventory.error}</p>}
  {inventory.reference&&inventory.reference.version!==3&&<p role="status">This older saved request can be checked, but cannot be resent.</p>}
  {inventory.result&&inventory.result.status!=='completed'&&<p role="status">{inventory.result.status==='not_found'?(resendable?'No saved result was found. Enter the exact original request to retry it with the same request ID.':'No saved result was found. This older saved request cannot be resent.'):'The saved request is '+inventory.result.status+'. Check it again before sending another request.'}</p>}
  {standalone?(assessmentEvaluationId&&<button className="ss-btn ss-btn--ghost" type="button"
   onClick={()=>openStandaloneAssessments(assessmentEvaluationId)}>Open saved assessments</button>)
   :inventory.reference?.evaluationId&&<button className="ss-btn ss-btn--ghost" type="button" disabled={!inventory.ready||inventory.busy} onClick={()=>void act(inventory.retryGrading)}>{inventory.busy?'Checking grading…':'Retry grading'}</button>}
  {inventory.result?.grading&&inventory.result.grading.status!=='disabled'&&<p role="status">{inventory.result.grading.completed?'Inventory objective completed.':inventory.result.grading.judgment?.verdict==='unavailable'||inventory.result.grading.status==='unavailable'?'Stock operation saved. Grading is unavailable; no objective completion was confirmed.':inventory.result.grading.judgment?.verdict==='inconclusive'?'Stock operation saved. Grading was inconclusive; the objective was not completed.':inventory.result.grading.judgment?.verdict==='fail'?'Stock operation saved. The objective was not completed.':'Stock operation saved. This operation is not eligible for objective credit.'}</p>}
  {inventory.result?.status==='completed'&&typeof inventory.result.answer==='string'&&<div role="status"><p style={{whiteSpace:'pre-wrap'}}>{inventory.result.answer}</p>{inventory.result.operations.map((operation,index)=><InventoryResult key={index} operation={stockAfterRequest(operation,index,inventory.result.operations)}/>)}</div>}
  <div style={{borderTop:'1px solid var(--rule)',paddingTop:16}}>
   <h3 className="ss-display" style={{fontSize:18,margin:'0 0 8px'}}>Saved inventory results</h3>
   <p style={{margin:'0 0 10px'}}>Completed requests from this shop practice can be read without running the inventory assistant again.</p>
   {inventory.foreignReference&&<div role="status" style={{marginBottom:12}}><p>A request saved in another session is still unresolved here. Check its exact saved result before starting a new request; it will not be resent.</p><p>Request: <code style={{overflowWrap:'anywhere'}}>{inventory.foreignReference.requestId}</code></p><button className="ss-btn ss-btn--ghost" type="button" disabled={!inventory.ready||inventory.historyBusy} onClick={()=>void inventory.readHistory(inventory.foreignReference.requestId).catch(()=>{})}>Check prior-session request</button></div>}
   {inventory.historyError&&<p role="alert">{inventory.historyError}</p>}
   {inventory.historyBusy&&<p role="status">Checking saved results…</p>}
   {!inventory.historyBusy&&!inventory.historyError&&(inventory.history||[]).length===0&&<p>No completed saved results are available for this practice.</p>}
   {(inventory.history||[]).length>0&&<ul style={{margin:'8px 0',paddingLeft:20}}>{inventory.history.map(row=><li key={row.requestId} style={{marginBottom:8}}><button className="ss-btn ss-btn--ghost" type="button" disabled={!inventory.ready||inventory.historyBusy} onClick={()=>void inventory.readHistory(row.requestId).catch(()=>{})}>Read saved result</button> <span>{new Date(row.recordedAt).toLocaleString()} · {row.mode==='fixed'?'Fixed':'Vulnerable'} mode · <code style={{overflowWrap:'anywhere'}}>{row.requestId}</code></span></li>)}</ul>}
   {inventory.historicalResult&&<div role="status" aria-label="Saved inventory result" style={{marginTop:12}}><p><strong>Saved result from this practice</strong> · <code style={{overflowWrap:'anywhere'}}>{inventory.historicalResult.requestId}</code></p><p style={{whiteSpace:'pre-wrap'}}>{inventory.historicalResult.answer}</p>{inventory.historicalResult.operations.map((operation,index)=><InventoryResult key={index} operation={stockAfterRequest(operation,index,inventory.historicalResult.operations)}/>)}</div>}
  </div>
 </section>;
}
// Project subsequent successful mutations onto a prior read, without changing
// the saved observations or claiming a new live stock read.
export function stockAfterRequest(operation,index,operations){
 if(operation?.action!=='stock_levels'||!Array.isArray(operation.result?.items))return operation;
 const quantities=new Map();
 for(const later of operations.slice(index+1)){
  if(later.action==='stock_levels'&&Array.isArray(later.result?.items))for(const item of later.result.items)quantities.set(item.productId,item.quantity);
  if(later.action==='set_stock'&&later.result?.applied===true)quantities.set(later.result.productId,later.result.after);
 }
 return{...operation,result:{...operation.result,items:operation.result.items.map(item=>quantities.has(item.productId)?{...item,quantity:quantities.get(item.productId)}:item)}};
}
function InventoryResult({operation}){
 const r=operation?.result;if(!r)return null;
 if(operation.action==='set_stock')return <p>{r.applied?`Product #${r.productId}: stock changed from ${r.before} to ${r.after}.`:`Product #${r.productId}: stock change was not applied.`}</p>;
 if(operation.action==='reorder_suggestion')return <p>Product #{r.productId}: {r.current} in stock; suggested reorder {r.suggestedReorder}.</p>;
 if(operation.action==='stock_levels'&&Array.isArray(r.items))return <table aria-label="Stock after this request" style={{width:'100%',textAlign:'left'}}><caption>Stock after this request</caption><thead><tr><th>Product</th><th>Stock</th></tr></thead><tbody>{r.items.map(item=><tr key={item.productId}><td>{item.name} (#{item.productId})</td><td>{item.quantity}</td></tr>)}</tbody></table>;
 return null;
}
