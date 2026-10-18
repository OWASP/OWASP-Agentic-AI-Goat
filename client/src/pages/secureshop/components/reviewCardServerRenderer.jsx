import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { isMainThread, parentPort, workerData } from 'node:worker_threads';
import ReviewCard from './ReviewCard.jsx';

// Build-only server renderer. The rendered tree is the actual ReviewCard
// component, including its intentional stored-XSS sink.
export function renderReviewCard(review) {
  return renderToStaticMarkup(React.createElement(ReviewCard, { review }));
}

if (!isMainThread) {
  try { parentPort.postMessage({ ok: true, markup: renderReviewCard(workerData.review) }); }
  catch (error) { parentPort.postMessage({ ok: false, error: String(error?.message || error) }); }
}
