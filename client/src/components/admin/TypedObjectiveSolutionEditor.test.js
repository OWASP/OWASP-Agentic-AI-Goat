import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import Editor,{isEditableSolution,solutionContentPatch} from './TypedObjectiveSolutionEditor';
const change=(el,value)=>{Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el),'value').set.call(el,value);el.dispatchEvent(new Event('input',{bubbles:true}));};
test('typed editor preserves unknown authored fields, owns duplicate saves and retains input on errors',async()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);let reject;const save=jest.fn(()=>new Promise((_,r)=>{reject=r;}));const original={title:'Original',difficulty:'Easy',approach:'Approach',examples:[{prompt:'Prompt',explanation:'Explanation',future:'keep'}],tips:['Tip'],future:{preserved:true}};
 try{await act(async()=>root.render(<Editor objectiveId="mcp_audit_gap" solution={original} onSave={save} onCancel={()=>{}}/>));const title=node.querySelector('input');await act(async()=>change(title,'Typed title'));const button=[...node.querySelectorAll('button')].find(x=>x.textContent==='Save Changes');await act(async()=>{button.click();button.click();});expect(save).toHaveBeenCalledTimes(1);expect(save.mock.calls[0][0]).toEqual({title:'Typed title'});await act(async()=>reject(new Error('Save denied')));expect(node.querySelector('[role="alert"]').textContent).toBe('Save denied');expect(title.value).toBe('Typed title');expect(node.querySelector('[role="dialog"]')).not.toBeNull();}
 finally{await act(async()=>root.unmount());node.remove();}
});
test('null and incompatible authored solutions cannot become fabricated defaults',()=>{expect(isEditableSolution(null)).toBe(false);expect(isEditableSolution({examples:['raw']})).toBe(false);expect(isEditableSolution({title:'Authored',extra:1})).toBe(true);});

test('solution patch excludes unknown top-level fields while nested authored metadata survives',()=>{const original={title:'Before',unknown:'keep',examples:[{prompt:'P',explanation:'E',extension:{retain:true}}]};const draft={...original,title:'After',examples:[{...original.examples[0],prompt:'Changed'}]};const patch=solutionContentPatch(original,draft);expect(patch).toEqual({title:'After',examples:[{prompt:'Changed',explanation:'E',extension:{retain:true}}]});expect({...original,...patch}.unknown).toBe('keep');expect(solutionContentPatch(original,original)).toEqual({});});
test('actual repository validator rejects unknown top-level body but admits typed patches before any store access',async()=>{
 const {createWorkshopConfigRepository}=require('../../../../server/database/postgres/workshopConfigRepository');
 const connect=jest.fn(async()=>{throw new Error('CONTROLLED_STORE_BOUNDARY');});const repo=createWorkshopConfigRepository({connect},{isSecureShopReady:()=>false});
 expect(()=>repo.updateSolutionContent('mcp_workshop','mcp_audit_gap',{title:'Changed',extra:true})).toThrow('Invalid content patch');
 expect(()=>repo.updateHintContent('mcp_workshop','mcp_audit_gap',{title:'Hint',hints:['A'],extra:true})).toThrow('Invalid content patch');expect(connect).not.toHaveBeenCalled();
 await expect(repo.updateSolutionContent('mcp_workshop','mcp_audit_gap',solutionContentPatch({title:'Old',extra:true},{title:'Changed',extra:true}))).rejects.toThrow('CONTROLLED_STORE_BOUNDARY');
 await expect(repo.updateHintContent('mcp_workshop','mcp_audit_gap',{title:'Hint',hints:['A']})).rejects.toThrow('CONTROLLED_STORE_BOUNDARY');expect(connect).toHaveBeenCalledTimes(2);
});
