export async function runAfterTrackedLoad(trackedLoadRef, reconcile) {
  const pendingLoad = trackedLoadRef.current;
  if (pendingLoad) await pendingLoad;
  return reconcile();
}
