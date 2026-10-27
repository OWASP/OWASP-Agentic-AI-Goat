"""Fixed manual ACL evidence, no actor/Judge requirement."""
import re
def verify_deletion_tap(text):
    if not re.search(r'^# fail 0$', text, re.M) or not re.search(r'^# pass 1$', text, re.M) or re.search(r'^not ok', text, re.M):
        raise RuntimeError('Original enabled-index TAP did not pass')
def verify_final_evidence(evidence, journal, browser, **_):
    acl=evidence.get('accessControl',{})
    if not (evidence.get('roleChanged') is True and evidence.get('banned') is True and evidence.get('opaqueFrame') is True and evidence.get('errors')==[] and evidence.get('blocked')==[]
      and acl.get('policyMutations')==4 and acl.get('exactReceiptReadbacks')==4
      and acl.get('acknowledgedReceiptsAndPolicyRefreshes')==3 and acl.get('permissionLostAckRecovered') is True
      and acl.get('unsupportedDisabled') is True and acl.get('defaultsRestored') is True
      and journal.get('resources',{}).get('browser',{}).get('pid')==browser.get('pid')):
        raise RuntimeError('Exact ACL recovery and original lifecycle evidence required')
    return {'passed':True,'manualAclRecovery':True,'actualModelCalls':0,'canonicalCredit':False}
