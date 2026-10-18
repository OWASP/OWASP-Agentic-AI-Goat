import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { StepReview } from './Checkout';

let root, node;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div');
  root = createRoot(node);
});
afterEach(async () => { await act(async () => root.unmount()); });
const render = async (summary, bound = true) => {
  await act(async () => root.render(<StepReview bound={bound} ship={{}} pay={{number:'4242424242424242'}} summary={summary} summaryLoading={false} onPrev={() => {}} onPlace={() => {}} placing={false} />));
};
test('review renders the bound gateway DTO as currency and count, leaving Place order available', async () => {
  await render({ok:true,items:[{quantity:2}],total:18,coupon:{code:'WELCOME10'},discount:2,summary:{item_count:2,subtotal:20,discount:2}});
  expect(node.querySelector('pre').textContent).toBe('Items: 2\nSubtotal: $20.00\nDiscount: -$2.00\nTotal: $18.00');
  expect(node.textContent).toContain('Order summary');
  expect(node.textContent).not.toContain('AI-generated');
  expect([...node.querySelectorAll('button')].find(button => button.textContent.includes('Place order')).disabled).toBe(false);
});
test('review renders an undiscounted bound summary without inventing fees or a discount', async () => {
  await render({ok:true,items:[],total:20,summary:{item_count:2,subtotal:20}});
  expect(node.querySelector('pre').textContent).toBe('Items: 2\nSubtotal: $20.00\nTotal: $20.00');
});
test('legacy string summary and its label remain unchanged', async () => {
  await render({summary:'Two items ready for delivery.'}, false);
  expect(node.querySelector('pre').textContent).toBe('Two items ready for delivery.');
  expect(node.textContent).toContain('AI-generated order summary · summarizer agent');
});
test('unknown or malformed summary objects never become React children or serialized UI', async () => {
  for (const summary of [{summary:{privateField:'hidden'}},{total:18,summary:{item_count:2,subtotal:Infinity}}, {total:18,summary:{item_count:2,subtotal:20,discount:-2}}]) {
    await render(summary);
    expect(node.querySelector('pre').textContent).toBe('(no summary)');
  }
  await render({summary:{privateField:'hidden'}}, false);
  expect(node.querySelector('pre').textContent).toBe('(no summary)');
});
