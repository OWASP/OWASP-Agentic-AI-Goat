import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import MailMessageBody from './MailMessageBody';
let container, root;
beforeEach(() => { global.IS_REACT_ACT_ENVIRONMENT = true;container=document.createElement('div');document.body.appendChild(container);root=createRoot(container); });
afterEach(async()=>{await act(async()=>root.unmount());container.remove();});
test('shared customer and merchant sinks retain raw attributes, inert inserted scripts and existing styles',async()=>{
 const html='<img src="x" onerror="alert(1)"><script>window.__mailScriptExecuted=true</script><b>Ω mail</b>';
 for(const variant of ['customer','merchant']){
  await act(async()=>root.render(<MailMessageBody html={html} variant={variant}/>));
  expect(container.querySelector('img').getAttribute('onerror')).toBe('alert(1)');expect(container.querySelector('b').textContent).toBe('Ω mail');expect(window.__mailScriptExecuted).toBeUndefined();expect(container.firstChild.style.padding).toBe(variant==='merchant'?'18px':'20px');
 }
});
test('fixed escaped persisted content stays text, without synthesizing executable nodes',async()=>{await act(async()=>root.render(<MailMessageBody html={'&lt;img src=x onerror=alert(1)&gt;'}/>));expect(container.querySelector('img')).toBeNull();expect(container.textContent).toBe('<img src=x onerror=alert(1)>');});
