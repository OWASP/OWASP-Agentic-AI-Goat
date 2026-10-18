"""Admission for the separate controlled 200-owner cohort; no resource creation."""
BOUNDS={'workSeconds':1200,'childSeconds':1080,'cleanupSeconds':120,'students':200,'postgresMiB':512,'postgresCpu':2,'maxConnections':96,'pids':256}
def validate_capacity(enabled, *, rendered=False, mcp=False, secureshop=False, model_digest=None):
 if not enabled:return None
 if any((rendered,mcp,secureshop,model_digest is not None)):raise ValueError('Capacity cohort excludes rendered, optional sidecar and actual-model modes')
 return dict(BOUNDS)
