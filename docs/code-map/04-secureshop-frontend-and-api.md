# SecureShop Frontend and REST API

## Boundary and boot

SecureShop is a subsystem inside the main React and Express applications. It
is enabled when `SS_ENABLE=true`. `server/services/secureshop/index.js`:

1. refuses to boot without `JWT_SECRET`;
2. forks/waits for Agent Host;
3. connects an MCP client for each native agent;
4. refreshes/persists the tool manifest;
5. builds the SecureShop-specific provider router;
6. constructs customer, merchant, admin, uploads, email, and auth routers;
7. returns those handles to `server/index.js`, which fills pre-mounted router
   placeholders.

The placeholders exist before the global 404 handler so asynchronous boot does
not make later-installed routers unreachable.

## Frontend route model

`App.js` sends `/secureshop` and every `/secureshop/*` path to
`SecureShopStandalone` before the platform `AuthProvider`. That controller
checks the independent shop session, renders `SecureShopGuestLanding` for
public browsing, and mounts the framed `SecureShopApp` through
`SecureShopStandaloneBound` after shop authentication.

| Surface | Paths | Access |
|---|---|---|
| marketing | `/secureshop` | public |
| auth | `/secureshop/login`, `/secureshop/register` | public |
| home | `/secureshop/home` | authenticated |
| shopping | `/secureshop/catalog`, `/secureshop/product/:id`, `/secureshop/cart` | public browsing; writes may require auth |
| customer | `/secureshop/checkout`, `/secureshop/orders`, `/secureshop/account`, `/secureshop/inbox` | authenticated |
| merchant | `/secureshop/merchant/*` | role `merchant` |
| admin | `/secureshop/admin/*` | role `admin` |
| compatibility | `/secureshop/v2/*` | transitional alias for most app routes |

`SecureShopStandalone` redirects protected guest routes to the shop login.
Inside the frame, `components/RequireAuth.jsx` also handles missing or wrong-role
personas. The backend enforces the same boundary.

## Frontend contexts and shell

| File | Owns |
|---|---|
| `SecureShopStandalone.jsx` | independent shop-session hydration, login/register routing, guest or authenticated frame selection |
| `standaloneClient.mjs` | `/api/secureshop/auth/*` session requests and response validation |
| `SecureShopGuestLanding.jsx` | public read-only frame bridge and guest cart persistence |
| `context/AuthContext.jsx` | framed persona token/user hydration and authorized inner-frame requests |
| `context/CartContext.jsx` | local cart plus server synchronization and derived totals/count |
| `context/ToastContext.jsx` | transient notifications |
| `components/Shell.jsx` | nav/footer/outlet plus optional agent lane and context providers |
| `components/TopNav.jsx` | navigation, search, cart/account, role switch, latest trace |
| `hooks/useAgentStream.js` | creates agent session, consumes SSE/chat events, builds turns/hops |
| `components/AgentLane/*` | renders supervisor/task hops and detailed tool payloads |
| `components/AgentAssist.jsx` | embedded role-specific assistant dialog |

The small primitives (`Button`, `Card`, `Dialog`, `Input`, `Tabs`, `Badge`,
`Rating`, `Spinner`, `EmptyState`, `UploadZone`) form the SecureShop UI kit.

## Customer pages and API

| Page | Backend paths | Behavior |
|---|---|---|
| `Landing.jsx` | product category queries | marketing and category feeds |
| `Home.jsx` | products, recommendations, orders | personalized dashboard |
| `Catalog.jsx` | `GET /products` | search/filter/sort/pagination |
| `Product.jsx` | product/reviews/similar/summary | detail, reviews, related items, agent summary |
| `Cart.jsx` | cart context, coupon | quantity/removal/coupon/summary |
| `Checkout.jsx` | `POST /orders`, `/orders/summary` | shipping/payment/review/place order |
| `Orders.jsx` | orders plus customer agent | list/detail/refund-request chat |
| `Account.jsx` | `/v2/auth/users/me/*` | profile, addresses, password, API keys, sessions, uploads |
| `Inbox.jsx` | `/email/*` | threads, send, archive UI, agent auto-reply |

`server/routes/secureshop/customer.js` implements products/categories,
reviews, recommendations/similar/summary, cart/coupon, orders, and customer
agent session/chat/trace. It calls some tool modules directly for deterministic
HTTP features and uses the customer supervisor for conversational work.

## Merchant pages and API

| Page | API domain | Functionality |
|---|---|---|
| `merchant/Overview.jsx` | overview/products/reviews/trace | KPIs, sales chart, quick actions |
| `Listings.jsx` | products/listing assist/import | CRUD, LLM rewrite, images, bulk XML/URL import |
| `Reviews.jsx` | reviews/moderation | filter, approve/reject, AI bulk moderation |
| `Pricing.jsx` | pricing suggest/experiment/compare/history | pricing tools and competitor URL analysis |
| `Analytics.jsx` | analytics query/top-products | natural language query, charts, generated SQL trace |
| `Inbox.jsx` | email APIs | merchant messaging and auto-reply |

`server/routes/secureshop/merchant.js` mounts a role guard under `/merchant`,
queries overview data directly, calls listing/inventory/pricing/review/analytics
tool functions for REST actions, and exposes the merchant supervisor chat and
trace endpoints.

## Admin pages and API

| Page | API domain | Functionality |
|---|---|---|
| `admin/Overview.jsx` | KPIs, DB sizes, provider/agent/MCP/trace/audit | operational summary |
| `Users.jsx` | users and user-management actions | search/lookup, role, ban, password reset |
| `Audit.jsx` | audit search/summarize | filters, detail, anomaly summary, CSV |
| `Policies.jsx` | policy CRUD/render | role policy and injected prompt management |
| `MCP.jsx` | registry/schema history | list/register/remove/import manifests |
| `System.jsx` | health/diagnostics/config/index/restart | operations and vulnerable system tools |
| `AccessControl.jsx` | ACL matrix/enforcement | per-role tool permission and enforcement toggle |

`server/routes/secureshop/admin.js` first exposes a deliberately vulnerable
legacy `whoami`, then guards `/admin` and `/agents/admin`. It mixes direct DB
queries, direct task-tool calls, supervisor chat, and health fetches. It also
provides the ACL configuration APIs that control Layer-B tool enforcement.

## Auth API

The current standalone controller uses `/api/secureshop/auth` for shop-only
`login`, `register`, `session`, `renew`, `logout`, `password`, and `bootstrap`
operations. The server stores the standalone session in an HTTP-only,
same-site `owasp_ai_goat_shop_session` cookie scoped to `/api/secureshop`; it does not
consult a workshop bearer or platform login. Bootstrap supplies the bounded
launch and persona material used inside the authenticated frame.

Retained code also contains two legacy JWT auth surfaces:

- `customer.js` retains handlers historically defined at
  `/api/secureshop/auth/register|login`; the current standalone router owns
  that prefix first.
- `auth.js` remains mounted at `/api/secureshop/v2/auth` and owns register/login,
  logout/whoami, role switching, own-account profile/password, addresses, API
  keys, and sessions.

The framed `AuthContext` still understands the persona JWT supplied by the
standalone bootstrap. That inner-frame token is not the browser's standalone
login authority. Legacy role switching maps to seeded canonical identities for
demonstrations; it is not a production impersonation model.

`_ssAuthMiddleware.js` validates JWTs and supplies `requireRole`. The deliberate
JWT `alg=none` teaching case lives in the admin `whoami` route, not the clean
v2 auth router.

## Upload and email APIs

- `uploads.js` receives base64/multipart-like payloads through the uploads task
  tools, supports download, and serves uploaded files. It intentionally
  preserves several unsafe behaviors for curriculum.
- `email.js` is a thin wrapper around the email task tools for send, inbox,
  thread, and auto-reply.

## Data ownership

| DB | Main tables |
|---|---|
| `secureshop.db` | shop users, products/images/manuals/categories, reviews, cart/coupons, orders/items, policies, email threads/messages, tickets, addresses/sessions |
| `secureshop_agents.db` | sessions/messages, trace, provider state, audit, jobs, MCP registry/cache/history, vectors/index metadata, tool permissions/config |

HTTP route code and Agent Host tools both open these DBs directly using
`better-sqlite3`. Tests redirect them with `SS_SECURESHOP_DB_PATH` and
`SS_AGENTS_DB_PATH`; preserve late environment lookup where possible.

## Security curriculum rule

SecureShop deliberately implements annotated SQLi, XSS, SSRF, path traversal,
file upload, command execution, deserialization/XXE, authorization, LLM, RAG,
and MCP flaws. The vulnerability ID, code annotation, test annotation, and
generated `docs/secureshop/VULNERABILITIES.md` row are a four-way contract.
Never “clean up” an unsafe-looking data flow without checking that contract.
