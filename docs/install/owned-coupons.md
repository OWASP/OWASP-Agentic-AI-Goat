# Owned coupon installation

Coupons use the existing owned Analytics PostgreSQL executor. The SQL injection
teaching query runs inside the learner's isolated target; the application stores
the selected coupon, exact integer-cent discounts, and checkout replay receipts
in the bound review store. Fixed mode parameterizes the coupon input.

Qualified local SecureShop fresh setup prepares this bundle by default. An
additive upgrade of an existing bound installation also prepares it when
Analytics and coupon preferences have not been disabled. The commands below
remain available for an explicit existing-install preview or repair.

For an existing configured bound SecureShop installation:

```bash
npm run setup -- --plan --owned-coupons
./stop_all.sh
npm run setup -- --upgrade --owned-coupons
./start_all.sh
```

The coupon bundle requires enabled bound SecureShop and the canonical PostgreSQL
runtime/migration configuration. It automatically prepares owned Analytics,
applies additive review migrations and checks the coupon tables, permissions,
and reset triggers before activation. It preserves existing application data,
private credentials, and disabled preferences. A disabled Analytics dependency
must be explicitly enabled through its documented `--enable-owned-analytics`
flow before coupon activation can succeed.

Coupon activation is stored privately in
`~/.dvaia/<workspace-id>/coupons-managed.json`; setup creates it with private
permissions. It contains the workspace identity and activation preference, not
provider credentials. Repeated setup preserves an existing disabled coupon
record. Do not reset databases or replace installation credentials to recover
from a readiness error; repair the reported prerequisite and repeat setup.

Qualification includes the real setup upgrade command, all sixteen configured
database URL pairs, four initialized prerequisite stores, repeat installation,
disabled preference preservation, and refusal on missing cleanup triggers or
altered runtime grants. Separate native tests verify actual isolated SQL bypass,
fixed-mode rejection, exact discount allocation, checkout replay and reset with
sibling preservation. These checks do not establish full application startup,
rendered coupon parity, stock accounting, or cold-host Linux compatibility.

The original native review receipts are retained privately and are not part of
the source release.
