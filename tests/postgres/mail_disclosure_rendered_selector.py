"""Closed source-only admission for the controlled Inbox rendered cohort."""
import json,re

CATALOG_FILES=(
    "tests/fixtures/secureshopMailDisclosureSeedUpgrade.js",
    "tests/fixtures/secureshopMailDisclosurePriorDefaults.json",
    "tests/fixtures/secureshopMailDisclosureCatalog.js",
    "tests/fixtures/secureshopMailHeaderCatalogBrowser.js",
    "tests/fixtures/secureshopMailHeaderCatalogApp.js",
    "tests/fixtures/secureshopMailDisclosureBrowser.js",
    "tests/fixtures/secureshopMailDisclosureRenderedSupport.js",
    "tests/fixtures/secureshopMailHeaderFullAppBrowser.js",
)

def validate(args):
    if getattr(args,"mail_disclosure_catalog",False) and (args.mail_disclosure_rendered!="vuln" or getattr(args,"mail_disclosure_initialize_only",False)):
        raise ValueError("Disclosure catalog requires exclusive vulnerable rendered candidate")
    if getattr(args,'mail_disclosure_initialize_only',False) and not args.mail_disclosure_rendered:
        raise ValueError('Initializer diagnostic requires disclosure candidate and pins')
    if not args.mail_disclosure_rendered:
        return
    incompatible=('actual8b','saved_evidence','production_assembly','actual_grading','actual_grading_browser','catalog_candidate','rendered_catalog','full_app','full_app_retry','dpi_rendered','dpi_containment_rendered','dpi_containment_visual','inventory_rendered','inventory_catalog','inventory_grading','mail_header_rendered','mail_header_catalog','mail_header_readiness','mail_reply_rendered','mail_reply_seed_only','coupon_rendered','csrf_full_app')
    if any(getattr(args,k,False) for k in incompatible):
        raise ValueError('Disclosure rendered selector must be exclusive')
    if not all((args.node_binary,args.node_sha256,args.node_version,args.dependency_root,args.dependency_hashes)):
        raise ValueError('Disclosure requires explicit runtime and dependency pins')
    if not re.fullmatch('[a-f0-9]{64}',args.mail_disclosure_dependency_byte_sha256 or ''):
        raise ValueError('Disclosure requires full dependency byte digest')
    identities=json.loads(args.dependency_hashes)
    expected={'package.json','package-lock.json','node_modules/.package-lock.json','client/package.json','client/package-lock.json','client/node_modules/.package-lock.json'}
    if set(identities)!=expected or any(not re.fullmatch('[a-f0-9]{64}',v) for v in identities.values()):
        raise ValueError('Disclosure requires exact six dependency identities')
