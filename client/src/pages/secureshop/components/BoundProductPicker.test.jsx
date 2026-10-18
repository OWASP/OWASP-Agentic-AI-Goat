import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import BoundProductPicker from './BoundProductPicker.jsx';

let root, node;
beforeEach(() => { globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node); });
afterEach(async () => { await act(async () => root.unmount()); node.remove(); });

test('customer picker reads bound catalog rows and selects a named product without manual IDs', async () => {
  const onSelect = jest.fn();
  const transport = jest.fn(async url => {
    if (url === '/api/secureshop/products/7') return { ok: true, json: async () => ({
      product: { id: 7, name: 'Practice laptop', price: 49 },
    }) };
    return { ok: true, json: async () => ({ products: [
      { id: 7, name: '<b>Practice laptop</b>', price: 49, stock_quantity: 3 },
    ] }) };
  });
  await act(async () => root.render(<BoundProductPicker instance="test" source="customer"
    initialProductId={7} selectedProduct={null} onSelect={onSelect}
    authorityKey="shop-1" transport={transport} />));
  expect(transport).toHaveBeenCalledWith('/api/secureshop/products/7', expect.any(Object));
  expect(node.querySelector('input[inputmode="numeric"]')).toBeNull();
  expect(node.querySelector('[aria-label="Catalog product choices"] b')).toBeNull();
  expect(node.textContent).toContain('<b>Practice laptop</b>');
  await act(async () => node.querySelector('[aria-label="Catalog product choices"] button').click());
  expect(onSelect).toHaveBeenLastCalledWith(expect.objectContaining({ id: 7, name: '<b>Practice laptop</b>' }));
});

test('merchant picker uses the owned product list and clears selection on authority change', async () => {
  const onSelect = jest.fn();
  const transport = jest.fn(async () => ({ ok: true, json: async () => ({
    products: [{ id: 9, name: 'Shop chair' }],
  }) }));
  await act(async () => root.render(<BoundProductPicker instance="merchant" source="merchant"
    selectedProduct={{ id: 9, name: 'Shop chair' }} onSelect={onSelect}
    authorityKey="merchant-a" transport={transport} />));
  expect(transport).toHaveBeenCalledWith('/api/secureshop/merchant/products?page=1&per_page=8', expect.any(Object));
  await act(async () => root.render(<BoundProductPicker instance="merchant" source="merchant"
    selectedProduct={{ id: 9, name: 'Shop chair' }} onSelect={onSelect}
    authorityKey="merchant-b" transport={transport} />));
  expect(onSelect).toHaveBeenLastCalledWith(null);
});

test('pending operation disables search and choices without losing the selected row', async () => {
  const onSelect = jest.fn();
  const transport = jest.fn(async () => ({ ok: true, json: async () => ({
    products: [{ id: 9, name: 'Shop chair' }],
  }) }));
  await act(async () => root.render(<BoundProductPicker instance="pending" source="customer"
    selectedProduct={{ id: 9, name: 'Shop chair' }} onSelect={onSelect}
    authorityKey="shop-a" disabled transport={transport} />));
  expect(node.querySelector('#lane-product-search-pending').disabled).toBe(true);
  expect(node.querySelector('button[type="submit"]').disabled).toBe(true);
  expect(node.querySelector('[aria-label="Catalog product choices"] button').disabled).toBe(true);
  expect(node.textContent).toContain('Selected product: Shop chair');
});

test('a late route-product read cannot replace a newer named catalog selection', async () => {
  let finishInitial;
  const initial = new Promise(resolve => { finishInitial = resolve; });
  const onSelect = jest.fn();
  const transport = jest.fn(url => url === '/api/secureshop/products/7' ? initial
    : Promise.resolve({ ok: true, json: async () => ({ products: [
      { id: 8, name: 'Current shop lamp', price: 24, stock_quantity: 4 },
    ] }) }));
  await act(async () => root.render(<BoundProductPicker instance="race" source="customer"
    initialProductId={7} selectedProduct={null} onSelect={onSelect}
    authorityKey="shop-a" transport={transport} />));
  await act(async () => node.querySelector('[aria-label="Catalog product choices"] button').click());
  expect(onSelect).toHaveBeenLastCalledWith(expect.objectContaining({ id: 8 }));
  await act(async () => root.render(<BoundProductPicker instance="race" source="customer"
    initialProductId={7} selectedProduct={{ id: 8, name: 'Current shop lamp' }} onSelect={onSelect}
    authorityKey="shop-a" transport={transport} />));
  const callsAfterChoice = onSelect.mock.calls.length;
  await act(async () => finishInitial({ ok: true, json: async () => ({
    product: { id: 7, name: 'Old route product', price: 49 },
  }) }));
  expect(onSelect).toHaveBeenCalledTimes(callsAfterChoice);
  expect(node.textContent).toContain('Selected product: Current shop lamp');
});
