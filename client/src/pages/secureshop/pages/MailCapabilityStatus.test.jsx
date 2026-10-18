import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import MailCapabilityStatus from './MailCapabilityStatus';
test('configured cloud is explicitly unprobed and no credentials or URLs are rendered',()=>{
 const html=renderToStaticMarkup(<MailCapabilityStatus capabilities={{actor:{status:'configured_unprobed',apiKey:'private-key',baseURL:'http://private.invalid'},judge:{status:'unknown_unprobed'}}}/>);
 expect(html).toContain('cloud provider configured; availability has not been checked');expect(html).toContain('model availability is unverified');expect(html).toContain('Saved messages and requests can still be recovered');expect(html).not.toMatch(/private-key|private.invalid|healthy/);
});
test('unavailable state adds status only and never disables recovery controls',()=>{const html=renderToStaticMarkup(<MailCapabilityStatus capabilities={{judge:{status:'unavailable'}}}/>);expect(html).toContain('role="status"');expect(html).toContain('Grading: model currently unavailable');expect(html).not.toMatch(/button|disabled/);expect(renderToStaticMarkup(<MailCapabilityStatus capabilities={{actor:{status:'available'},judge:{status:'available'}}}/>)).toBe('');});
