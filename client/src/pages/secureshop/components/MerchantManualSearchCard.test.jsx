import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import MerchantManualSearchCard from './MerchantManualSearchCard.jsx';

test('shows exact escaped manual source, honest empty and oversized states', async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const node = document.createElement('div'); document.body.append(node);
  const root = createRoot(node);
  const base = { product: { name: 'Practice laptop' }, query: 'Battery?',
    count: 1, hasMore: true, status: 'complete', sources: [{ sourceId: 1, chunkIndex: 0,
      filename: 'Manual.pdf', completedAt: '2026-10-11T12:00:00.000Z', score: 0.8,
      text: '<img src=x onerror=alert(1)>', textBytes: 28, textSha256: 'a'.repeat(64) }] };
  await act(async () => root.render(<MerchantManualSearchCard read={{ result: base }} />));
  const card = node.querySelector('[aria-label="Merchant manual search result"]');
  expect(card.textContent).toContain('<img src=x onerror=alert(1)>');
  expect(card.querySelector('img')).toBeNull();
  expect(card.textContent).toContain('More matching manual sources exist');
  await act(async () => root.render(<MerchantManualSearchCard read={{ result: { ...base,
    status: 'oversized', sources: [{ ...base.sources[0], text: null }] } }} />));
  expect(card.textContent).toContain('No manual answer is verified');
  expect(card.querySelector('pre')).toBeNull();
  await act(async () => root.render(<MerchantManualSearchCard read={{ result: { ...base,
    count: 0, hasMore: false, sources: [] } }} />));
  expect(card.textContent).toContain('No manual sources found.');
  await act(async () => root.unmount()); node.remove();
});
