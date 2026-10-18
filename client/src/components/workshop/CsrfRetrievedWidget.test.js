import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import CsrfRetrievedWidget from './CsrfRetrievedWidget';

for (const managed of [true, false]) {
  test(`widget preserves its appearance and ${managed ? 'cannot replay managed' : 'retains indirect'} execution`, () => {
    const payload = '<img src=x onerror="fetch(\'/api/workshop/csrf/agent-action\')">';
    const host = document.createElement('div');
    host.innerHTML = renderToStaticMarkup(<CsrfRetrievedWidget id="test" html={payload} browserExecuted={managed} />);
    const frame = host.querySelector('iframe');
    expect(frame.getAttribute('sandbox')).toBe(managed ? '' : 'allow-scripts allow-same-origin');
    expect(frame.getAttribute('srcdoc')).toContain(payload);
    expect(frame.title).toBe('rag-widget-test');
    expect(frame.style.height).toBe('54px');
  });
}
test('fixed selected-mail projection remains inert without claiming browser execution',()=>{
 const html='<pre>&lt;img src=x onerror=&quot;attack()&quot;&gt;</pre>';
 const host=document.createElement('div');
 host.innerHTML=renderToStaticMarkup(<CsrfRetrievedWidget id="fixed" html={html} browserExecuted={false} renderPolicy="escaped_inert_text"/>);
 const frame=host.querySelector('iframe');expect(frame.getAttribute('sandbox')).toBe('');expect(frame.getAttribute('srcdoc')).toContain(html);expect(frame.getAttribute('srcdoc')).not.toContain('<img');expect(frame.style.height).toBe('54px');
});
