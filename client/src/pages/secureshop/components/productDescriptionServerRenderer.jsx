import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { isMainThread, parentPort, workerData } from 'node:worker_threads';
import ProductDescription from './ProductDescription.jsx';

export function renderProductDescription(product) {
  return renderToStaticMarkup(React.createElement(ProductDescription, { product }));
}
if (!isMainThread) {
  try { parentPort.postMessage({ ok: true, markup: renderProductDescription(workerData.product) }); }
  catch (error) { parentPort.postMessage({ ok: false, error: String(error?.message || error) }); }
}
