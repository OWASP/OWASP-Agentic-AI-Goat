import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
jest.mock('react-markdown',()=>({__esModule:true,default:({children})=><div data-markdown-dispatch>{children}</div>}));
import CsrfResponseText from './CsrfResponseText';
test('selected-email plain summary renders markup and markdown literally without link or image requests',()=>{
 const content='![x](https://example.invalid/image) [link](https://example.invalid) <img src=x onerror="attack()"> <!--RAG_HTML_START-->literal<!--RAG_HTML_END-->';
 const host=document.createElement('div');host.innerHTML=renderToStaticMarkup(<CsrfResponseText plain content={content}/>);
 expect(host.textContent).toBe(content);expect(host.querySelector('a,img,script,iframe')).toBeNull();expect(host.firstChild.style.whiteSpace).toBe('pre-wrap');
});
test('unrelated existing markdown presentation remains available',()=>{const host=document.createElement('div');host.innerHTML=renderToStaticMarkup(<CsrfResponseText content="**existing**"/>);expect(host.querySelector('[data-markdown-dispatch]').textContent).toBe('**existing**');});
